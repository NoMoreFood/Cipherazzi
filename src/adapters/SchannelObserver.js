function installSchannel(module)
{
    if (schannelModule !== null) return;
    const listeners = [], credentials = new Map(), contexts = new Map(), addresses = new Set();
    let received = [], tokens = [];
    const queryAddress = module.findExportByName('QueryContextAttributesW');
    if (queryAddress === null)
        return;
    const query = new NativeFunction(queryAddress, 'int', ['pointer', 'uint', 'pointer']);
    function identity(handle)
    {
        return handle.isNull() ? '' : handle.readPointer().toString() + ':' + handle.add(pointerSize).readPointer();
    }
    function hook(name, callbacks)
    {
        const address = module.findExportByName(name);
        if (address === null || addresses.has(address.toString()))
            return;
        addresses.add(address.toString());
        listeners.push(Interceptor.attach(address, callbacks));
    }
    function certificate(context, attribute)
    {
        const output = Memory.alloc(pointerSize);
        if (query(context, attribute, output) !== 0 || output.readPointer().isNull())
            return [];
        const value = output.readPointer();
        const release = systemApi('crypt32.dll', 'CertFreeCertificateContext', 'int', ['pointer']);
        try
        {
            const dataOffset = pointerSize === 8 ? 8 : 4;
            const size = value.add(dataOffset + pointerSize).readU32();
            return size > 0 && size <= 262144 ?
                [base64(new Uint8Array(value.add(dataOffset).readPointer().readByteArray(size)))] : [];
        }
        finally { release(value); }
    }
    function buffers(descriptor)
    {
        if (descriptor.isNull()) return [];
        const count = descriptor.add(4).readU32(), pointer = descriptor.add(8).readPointer();
        if (count > 16 || pointer.isNull()) return [];
        const result = [];
        for (let index = 0; index < count; ++index)
        {
            const entry = pointer.add(index * (pointerSize + 8));
            const size = entry.readU32(), type = entry.add(4).readU32() & 0x0fffffff;
            const data = entry.add(8).readPointer();
            if (type === 2 && size > 0 && size <= 1048576 && !data.isNull()) result.push({ data, size });
        }
        return result;
    }
    function overlaps(left, right)
    {
        return left.data.compare(right.data.add(right.size)) < 0 &&
            right.data.compare(left.data.add(left.size)) < 0;
    }
    function associate(current, socket)
    {
        if (current.ambiguous || current.emitted) return;
        if (current.socket && !current.socket.equals(socket))
        {
            current.ambiguous = true;
            delete current.endpoints;
            return;
        }
        current.socket = socket;
        current.endpoints = socketEndpoints(socket);
    }
    function handshakeFields(data, type, current, outbound)
    {
        const word = offset => data[offset] * 256 + data[offset + 1];
        const finish = data.length, fromServer = current.server === outbound;
        if (type === 2 && fromServer && finish >= 38)
        {
            let cursor = 35 + data[34];
            if (cursor + 3 > finish) return;
            current.wireCipher = word(cursor);
            cursor += 3;
            if (cursor + 2 > finish || cursor + 2 + word(cursor) !== finish) return;
            cursor += 2;
            while (cursor + 4 <= finish)
            {
                const extension = word(cursor), length = word(cursor + 2);
                cursor += 4;
                if (cursor + length > finish) return;
                if (extension === 51 && length >= 4 && word(cursor + 2) + 4 === length)
                    current.group = word(cursor);
                cursor += length;
            }
        }
        else if (type === 12 && fromServer && finish >= 8)
        {
            const exchange = adapterOptions.ephemeral_suites[current.wireCipher];
            let cursor = 0, group;
            if (exchange === 'ECDHE' && data[0] === 3)
            {
                group = word(1);
                cursor = 4 + data[3];
            }
            else if (exchange === 'DHE')
            {
                for (let index = 0; index < 3 && cursor + 2 <= finish; ++index)
                    cursor += 2 + word(cursor);
            }
            else return;
            if (cursor + 4 <= finish && cursor + 4 + word(cursor + 2) === finish)
            {
                if (group) current.group = group;
                current[outbound ? 'localSignature' : 'peerSignature'] = word(cursor);
            }
        }
        else if (type === 15 && finish >= 4 && 4 + word(2) === finish)
            current[outbound ? 'localSignature' : 'peerSignature'] = word(0);
    }
    const fragments = new Map();
    let fragmentBytes = 0, contextSequence = 0;
    function streamHandshake(data, current, outbound)
    {
        const key = current.sequence + ':' + outbound + ':tcp';
        let stream = fragments.get(key);
        if (!stream)
        {
            if (fragments.size >= 128) return;
            stream = { current, header: [], data: new Uint8Array(0), count: 0, remaining: 0 };
            fragments.set(key, stream);
        }
        for (let offset = 0; offset < data.length;)
        {
            while (stream.header.length < 4 && offset < data.length) stream.header.push(data[offset++]);
            if (stream.header.length < 4) return;
            if (!stream.remaining)
            {
                const size = stream.header[1] * 65536 + stream.header[2] * 256 + stream.header[3];
                stream.remaining = size;
                if ([2, 12, 15].includes(stream.header[0]) && size <= 65536 &&
                    fragmentBytes + size * 2 <= 2097152)
                {
                    stream.data = new Uint8Array(size);
                    fragmentBytes += size * 2;
                }
            }
            const take = Math.min(stream.remaining, data.length - offset);
            if (stream.data.length) stream.data.set(data.subarray(offset, offset + take), stream.count);
            offset += take;
            stream.count += take;
            stream.remaining -= take;
            if (stream.remaining) return;
            if (stream.data.length) handshakeFields(stream.data, stream.header[0], current, outbound);
            fragmentBytes -= stream.data.length * 2;
            stream.data = new Uint8Array(0);
            stream.header = [];
            stream.count = 0;
        }
    }
    function publicHandshake(buffer, current, outbound)
    {
        // Retain bounded public handshake fragments, excluding certificates, keys, and encrypted records.
        for (const [key, value] of fragments)
            if (value.current.emitted || nowUs() - value.current.started > 120000000)
            {
                fragmentBytes -= value.data.length * 2;
                fragments.delete(key);
            }
        const data = buffer.bytes || new Uint8Array(buffer.data.readByteArray(buffer.size));
        const word = offset => data[offset] * 256 + data[offset + 1];
        const triple = offset => word(offset) * 256 + data[offset + 2];
        for (let record = 0; record + 5 <= data.length;)
        {
            const dtls = data[record + 1] === 254, header = dtls ? 13 : 5;
            if (record + header > data.length) break;
            const end = record + header + word(record + header - 2);
            if (end > data.length) break;
            const protectedField = outbound ? 'localProtected' : 'peerProtected';
            if (data[record] === 20 && current.wireCipher &&
                (current.wireCipher < 0x1301 || current.wireCipher > 0x1305)) current[protectedField] = true;
            if (data[record] === 22 && !current[protectedField] && (!dtls || word(record + 3) === 0))
            {
                if (!dtls)
                {
                    streamHandshake(data.subarray(record + header, end), current, outbound);
                    record = end;
                    continue;
                }
                const handshakeHeader = dtls ? 12 : 4;
                for (let message = record + header; message + handshakeHeader <= end;)
                {
                    const type = data[message], size = triple(message + 1), begin = message + handshakeHeader;
                    const offset = dtls ? triple(message + 6) : 0;
                    const length = dtls ? triple(message + 9) : size, finish = begin + length;
                    if (finish > end || offset + length > size) break;
                    if ([2, 12, 15].includes(type) && size <= 65536)
                    {
                        if (offset === 0 && length === size)
                            handshakeFields(data.subarray(begin, finish), type, current, outbound);
                        else if (dtls)
                        {
                            const key = current.sequence + ':' + outbound + ':' + word(message + 4) + ':' + type;
                            let assembly = fragments.get(key);
                            if (!assembly && fragments.size < 128 && fragmentBytes + size * 2 <= 2097152)
                            {
                                assembly = { current, data: new Uint8Array(size),
                                    mask: new Uint8Array(size), count: 0 };
                                fragments.set(key, assembly);
                                fragmentBytes += size * 2;
                            }
                            if (assembly && assembly.data.length === size && !assembly.invalid)
                            {
                                for (let index = 0; index < length; ++index)
                                {
                                    const position = offset + index, value = data[begin + index];
                                    if (assembly.mask[position] && assembly.data[position] !== value)
                                        assembly.invalid = true;
                                    if (!assembly.mask[position]) ++assembly.count;
                                    assembly.mask[position] = 1;
                                    assembly.data[position] = value;
                                }
                                if (!assembly.invalid && assembly.count === size)
                                    handshakeFields(assembly.data, type, current, outbound);
                            }
                        }
                    }
                    message = finish;
                }
            }
            record = end;
        }
    }
    function emit(context, current, status)
    {
        if (current.emitted || !current.started || nowUs() - current.started > 120000000)
            return;
        const details = Memory.alloc(1024);
        details.writeU32(1);
        const success = status === 0;
        const queried = success && query(context, 0x64, details) === 0;
        const connection = Memory.alloc(28);
        const flags = success && query(context, 0x5a, connection) === 0 ? connection.readU32() : 0;
        const version = flags & 0xc0000 ? 65277 : flags & 0x30000 ? 65279 :
            flags & 0x3000 ? 772 : flags & 0xc00 ? 771 : flags & 0x300 ? 770 :
            flags & 0xc0 ? 769 : flags & 0x30 ? 768 : 0;
        const cipher = queried ? details.add(8).readU32() : 0;
        if (success && (!version || !cipher || cipher > 65535))
            return;
        const report = {
            schema: 'cipherazzi.endpoint/1', provider: 'Schannel', pid: Process.id,
            handshake_started_us: current.started, timestamp_us: nowUs(),
            role: current.server ? 'server' : 'client', transport: current.dtls ? 'DTLS' : 'TCP', success
        };
        if (current.endpoints) Object.assign(report, current.endpoints);
        for (const [field, value] of [['group_id', current.group], ['signature_scheme', current.peerSignature],
            ['local_signature_scheme', current.localSignature]])
            if (value > 0 && value <= 65535) report[field] = value;
        const verification = Memory.alloc(8);
        if (query(context, 0x71, verification) === 0 && (!current.manual || verification.readU32() ||
            verification.add(4).readS32()))
            report.peer_verified = verification.readU32() === 0 && verification.add(4).readS32() === 0;
        else if (!success && [0x80090322, 0x80090325, 0x80090327, 0x80090328].includes(status >>> 0))
            report.peer_verified = false;
        else if (success && !current.server && current.automatic)
            report.peer_verified = true;
        if (success)
        {
            report.tls_version = version;
            report.cipher_id = cipher;
            const session = Memory.alloc(40);
            if (query(context, 0x5d, session) === 0) report.session_resumed = (session.readU32() & 1) !== 0;
            report[current.server ? 'client_certificates_der' : 'server_certificates_der'] = certificate(context, 0x53);
            report[current.server ? 'server_certificates_der' : 'client_certificates_der'] = certificate(context, 0x54);
            const protocol = Memory.alloc(264);
            if (query(context, 35, protocol) === 0 && protocol.readU32() === 1)
            {
                const value = publicProtocol(protocol.add(9), protocol.add(8).readU8());
                if (value) report.selected_alpn = value;
            }
        }
        else
            report.error_code = status;
        if (current.name && current.name.length <= 253 && /^[\x21-\x7e]+$/.test(current.name))
            report.server_name = current.name;
        current.emitted = true;
        send({ kind: 'report', report });
    }

    // Follow public SSPI context handles and policy flags without inspecting credential keys or session secrets.
    for (const suffix of ['W', 'A'])
        hook('AcquireCredentialsHandle' + suffix, {
            onEnter(args)
            {
                this.output = args[7];
                const name = args[1].isNull() ? '' : suffix === 'W' ? publicWideString(args[1], 128) :
                    publicString(args[1], 128);
                this.schannel = /^(Schannel|Microsoft Unified Security Protocol Provider)$/i.test(name);
                this.flags = args[4].isNull() ? 0 : null;
                if (this.schannel && !args[4].isNull())
                {
                    const version = args[4].readU32();
                    const offset = version === 4 ? (pointerSize === 8 ? 72 : 48) :
                        version === 5 ? (pointerSize === 8 ? 52 : 32) : 0;
                    if (offset) this.flags = args[4].add(offset).readU32();
                }
            },
            onLeave(result)
            {
                if (this.schannel && result.toInt32() === 0)
                {
                    if (credentials.size >= 2048)
                        credentials.delete(credentials.keys().next().value);
                    credentials.set(identity(this.output), this.flags);
                }
            }
        });
    for (const name of ['InitializeSecurityContextW', 'InitializeSecurityContextA', 'AcceptSecurityContext'])
        hook(name, {
            onEnter(args)
            {
                this.savedError = this.lastError;
                const old = identity(args[1]);
                const current = contexts.get(old);
                if (!current && !credentials.has(identity(args[0]))) return;
                const server = name === 'AcceptSecurityContext';
                this.sspiContext = args[server ? 5 : 8];
                this.current = current || { started: nowUs(), emitted: false, server, name: '',
                    sequence: ++contextSequence };
                if (credentials.has(identity(args[0])))
                    this.current.credentialFlags = credentials.get(identity(args[0]));
                const flags = this.current.credentialFlags;
                const requested = args[3].toUInt32();
                this.current.dtls = (requested & 0x400) !== 0;
                this.current.manual = !!(flags & 8) || (!server && !!(requested & 0x80000));
                this.current.automatic = flags !== undefined && flags !== null &&
                    !(flags & 0x0400000c) && !this.current.manual;
                this.output = args[server ? 6 : 9];
                this.input = buffers(args[server ? 2 : 6]);
                for (const buffer of this.input)
                {
                    for (const receivedBuffer of received)
                        if (overlaps(buffer, receivedBuffer) && nowUs() - receivedBuffer.started <= 120000000)
                            associate(this.current, receivedBuffer.socket);
                    buffer.bytes = new Uint8Array(buffer.data.readByteArray(buffer.size));
                }
                if (!server && !args[2].isNull())
                    this.current.name = name.endsWith('W') ? publicWideString(args[2], 253) :
                        publicString(args[2], 253);
                this.lastError = this.savedError;
            },
            onLeave(result)
            {
                if (!this.current) return;
                const lastError = this.lastError;
                try
                {
                    const status = result.toInt32();
                    if (status !== -2146893032)
                        for (const buffer of this.input) publicHandshake(buffer, this.current, false);
                    const key = identity(this.sspiContext);
                    if (contexts.size >= 2048 && !contexts.has(key))
                        contexts.delete(contexts.keys().next().value);
                    contexts.set(key, this.current);
                    tokens = tokens.filter(value => !value.current.emitted &&
                        nowUs() - value.current.started <= 120000000);
                    for (const buffer of buffers(this.output))
                    {
                        publicHandshake(buffer, this.current, true);
                        if (tokens.length >= 2048) tokens.shift();
                        tokens.push({ ...buffer, current: this.current });
                    }
                    if (status === 0 || (status < 0 && status !== -2146893032))
                        emit(this.sspiContext, this.current, status);
                }
                catch (_) { warn('schannel-query', 'Schannel public connection metadata could not be queried.'); }
                finally { this.lastError = lastError; }
            }
        });
    hook('DeleteSecurityContext', { onEnter(args) { contexts.delete(identity(args[0])); } });
    hook('FreeCredentialsHandle', { onEnter(args) { credentials.delete(identity(args[0])); } });
    const socketObserver = Process.attachModuleObserver({
        onAdded(loaded)
        {
            if (loaded.name.toLowerCase() !== 'ws2_32.dll') return;
            for (const name of ['send', 'sendto', 'WSASend', 'WSASendTo', 'recv', 'recvfrom', 'WSARecv', 'WSARecvFrom'])
            {
                const target = loaded.findExportByName(name);
                if (target === null) continue;
                listeners.push(Interceptor.attach(target, {
                    onEnter(args)
                    {
                        const error = this.lastError;
                        try
                        {
                            const outgoing = /send/i.test(name), vectors = name.startsWith('WSA');
                            this.outgoing = outgoing;
                            this.buffers = [];
                            const count = vectors ? args[2].toUInt32() : 1;
                            if (count > 64) return;
                            for (let index = 0; index < count; ++index)
                            {
                                const entry = args[1].add(index * pointerSize * 2);
                                const size = vectors ? entry.readU32() : args[2].toUInt32();
                                const data = vectors ? entry.add(pointerSize).readPointer() : args[1];
                                if (!size || size > 1048576 || data.isNull()) continue;
                                const buffer = { data, size, socket: args[0], started: nowUs() };
                                if (outgoing)
                                {
                                    tokens = tokens.filter(token => !token.current.emitted &&
                                        nowUs() - token.current.started <= 120000000);
                                    for (const token of tokens)
                                        if (overlaps(buffer, token)) associate(token.current, args[0]);
                                    tokens = tokens.filter(token => !overlaps(buffer, token));
                                }
                                else
                                {
                                    received = received.filter(value => nowUs() - value.started <= 120000000 &&
                                        !overlaps(buffer, value));
                                    if (received.length >= 2048) received.shift();
                                    received.push(buffer);
                                    this.buffers.push(buffer);
                                }
                            }
                        }
                        catch (_) { warn('schannel-socket', 'Some Schannel socket attribution was unavailable.'); }
                        finally { this.lastError = error; }
                    },
                    onLeave(result)
                    {
                        if (!this.outgoing && this.buffers && result.toInt32() === -1 && this.lastError !== 997)
                            received = received.filter(buffer => !this.buffers.includes(buffer));
                    }
                }));
            }
            listeners.push(Interceptor.attach(loaded.getExportByName('closesocket'), {
                onEnter(args) { received = received.filter(value => !value.socket.equals(args[0])); }
            }));
        }
    });
    listeners.push(socketObserver);
    libraries.set(module.path, listeners);
    schannelModule = module.path;
    send({ kind: 'adapter', provider: 'Schannel', module: module.name });
}

