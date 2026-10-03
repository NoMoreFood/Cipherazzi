function goMetadata(module)
{
    if (Process.arch !== 'x64') return null;
    const sections = module.enumerateRanges('r--').filter(range => !range.protection.includes('x'));
    function inImage(address, length = 1)
    {
        return address.compare(module.base) >= 0 && length >= 0 &&
            address.add(length).compare(module.base.add(module.size)) <= 0;
    }
    function scan(pattern)
    {
        return sections.flatMap(range => Memory.scanSync(range.base, range.size, pattern));
    }
    function unsigned(address, limit)
    {
        const value = address.readU64();
        if (value.compare(uint64(limit)) > 0) throw new Error('Go metadata exceeds its bound.');
        return value.toNumber();
    }
    const headers = scan('f1 ff ff ff 00 00 01 08').filter(value =>
        inImage(value.address, 72) && value.address.add(8).readU64().compare(uint64(1000000)) < 0);
    if (headers.length !== 1) return null;
    const header = headers[0].address;
    const references = scan(header.toMatchPattern()).filter(value =>
        inImage(value.address, 320) && value.address.add(8).readPointer().equals(
            header.add(unsigned(header.add(32), module.size))));
    if (references.length !== 1) return null;
    const data = references[0].address, text = data.add(176).readPointer();
    const types = data.add(296).readPointer();
    let typeEnd = data.add(304).readPointer();
    if (!inImage(typeEnd)) typeEnd = data.add(312).readPointer();
    if (!inImage(text) || !inImage(types) || !inImage(typeEnd) || typeEnd.compare(types) <= 0) return null;
    const typeSize = typeEnd.sub(types).toUInt32();
    function name(address)
    {
        if (!inImage(address, 2)) throw new Error('Go name is outside the image.');
        let length = 0, count = 0, byte;
        do
        {
            byte = address.add(++count).readU8();
            length += (byte & 127) * 2 ** ((count - 1) * 7);
        } while ((byte & 128) && count < 3);
        if (byte & 128 || length > 1024 || !inImage(address, count + 1 + length))
            throw new Error('Go name exceeds its bound.');
        return address.add(count + 1).readUtf8String(length);
    }
    const described = new Map();
    function describe(address)
    {
        const key = address.toString();
        if (described.has(key)) return described.get(key);
        if (address.compare(types) < 0 || address.add(48).compare(typeEnd) > 0)
            throw new Error('Go type is outside the metadata.');
        const kind = address.add(23).readU8() & 31, size = unsigned(address, 1048576);
        const offset = address.add(40).readS32();
        if (offset <= 0 || offset >= typeSize || kind < 1 || kind > 26)
            throw new Error('Go type descriptor is invalid.');
        let text = name(types.add(offset));
        if (address.add(20).readU8() & 2) text = text.slice(1);
        const result = { address, name: text, size, kind };
        described.set(key, result);
        return result;
    }
    function fields(type)
    {
        if (type.fields) return type.fields;
        if (type.kind !== 25) throw new Error('Expected a Go structure.');
        const begin = type.address.add(56).readPointer(), count = unsigned(type.address.add(64), 256);
        if (!inImage(begin, count * 24)) throw new Error('Go fields are outside the image.');
        const values = new Map();
        for (let index = 0; index < count; ++index)
        {
            const field = begin.add(index * 24), child = describe(field.add(8).readPointer());
            const offset = unsigned(field.add(16), type.size);
            if (offset + child.size > type.size) throw new Error('Go field exceeds its structure.');
            values.set(name(field.readPointer()), { offset, type: child });
        }
        type.fields = values;
        return values;
    }
    function field(type, name, kind)
    {
        const value = fields(type).get(name);
        if (!value || (kind !== undefined && value.type.kind !== kind))
            throw new Error('Required Go metadata field is unavailable.');
        return value;
    }
    function element(type)
    {
        if (type.kind !== 22 && type.kind !== 23) throw new Error('Expected a Go pointer or slice.');
        return describe(type.address.add(48).readPointer());
    }
    function findType(wanted, kind)
    {
        const text = wanted.startsWith('*') ? wanted : '*' + wanted;
        const pattern = [...text].map(character => character.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
        const matches = new Map();
        for (const candidate of Memory.scanSync(types, typeSize, pattern))
        {
            const encoded = candidate.address.sub(2);
            if (encoded.add(1).readU8() !== text.length || name(encoded) !== text) continue;
            const offset = encoded.sub(types).toUInt32();
            const bytes = [0, 8, 16, 24].map(shift => ((offset >>> shift) & 255).toString(16).padStart(2, '0'));
            for (const reference of Memory.scanSync(types, typeSize, bytes.join(' ')))
            {
                const address = reference.address.sub(40);
                if (address.and(7).toInt32() || address.compare(types) < 0) continue;
                try
                {
                    const type = describe(address);
                    if (type.name === wanted && type.kind === kind) matches.set(address.toString(), type);
                }
                catch (_) { }
            }
        }
        return matches.size === 1 ? matches.values().next().value : null;
    }
    const functions = new Map(), count = unsigned(header.add(8), 1000000);
    const names = header.add(unsigned(header.add(32), module.size));
    const table = header.add(unsigned(header.add(64), module.size));
    if (!inImage(table, (count + 1) * 8)) throw new Error('Go function table exceeds its image.');
    for (let index = 0; index < count; ++index)
    {
        const entry = table.add(index * 8), metadata = table.add(entry.add(4).readU32());
        if (!inImage(metadata, 8)) throw new Error('Go function metadata is outside its image.');
        const address = names.add(metadata.add(4).readS32());
        if (!inImage(address, 256)) continue;
        const symbol = publicString(address, 256);
        if (!symbol.startsWith('crypto/tls.') && !symbol.startsWith('github.com/quic-go/')) continue;
        const start = text.add(entry.readU32()), end = text.add(entry.add(8).readU32());
        if (inImage(start) && inImage(end) && end.compare(start) > 0)
            functions.set(symbol, { start, end });
    }
    return { describe, fields, field, element, findType, functions };
}

function installGo(module)
{
    const metadata = goMetadata(module);
    if (metadata === null) return false;
    const { field, element, findType, functions } = metadata;
    const type = findType('tls.Conn', 25), handshake = functions.get('crypto/tls.(*Conn).handshakeContext');
    if (!type || !handshake) return false;
    const listeners = [], storage = [];
    libraries.set(module.path, listeners);
    const settings = {};
    for (const [name, member, kind] of [['CLIENT', 'isClient', 1], ['QUIC', 'quic', 22],
        ['ERROR', 'handshakeErr', 20], ['VERSION', 'vers', 9], ['CIPHER', 'cipherSuite', 9],
        ['RESUMED', 'didResume', 1], ['CERTIFICATES', 'peerCertificates', 23],
        ['VERIFIED_CHAINS', 'verifiedChains', 23], ['NAME', 'serverName', 24],
        ['ALPN', 'clientProtocol', 24], ['SOCKET', 'conn', 20]])
        settings['TLS_' + name] = field(type, member, kind).offset;
    const complete = field(type, 'isHandshakeComplete', 25);
    settings.TLS_COMPLETE = complete.offset + field(complete.type, 'v', 10).offset;
    for (const [name, member] of [['GROUP', 'curveID'], ['SIGNATURE', 'peerSigAlg']])
        settings['TLS_' + name] = metadata.fields(type).has(member) ? field(type, member, 9).offset : -1;
    const certificateType = element(element(field(type, 'peerCertificates').type));
    if (certificateType.name !== 'x509.Certificate') throw new Error('Go certificate type is unsupported.');
    settings.CERTIFICATE_RAW = field(certificateType, 'Raw', 23).offset;
    const errorType = findType('*tls.CertificateVerificationError', 22);
    settings.CERTIFICATE_ERROR_TYPE = errorType?.address.toString() + 'ULL';
    settings.CERTIFICATE_ERROR_CHAIN = errorType ? field(element(errorType), 'UnverifiedCertificates', 23).offset : 0;
    if (!errorType) settings.CERTIFICATE_ERROR_TYPE = 0;
    for (const [name, member, key] of [['*fmt.wrapError', 'err', 'WRAP_ERROR'],
        ['*fmt.wrapErrors', 'errs', 'WRAP_ERRORS']])
    {
        const wrapper = findType(name, 22);
        settings[key + '_TYPE'] = wrapper ? wrapper.address + 'ULL' : 0;
        settings[key] = wrapper ? field(element(wrapper), member).offset : 0;
    }
    const tcp = findType('*net.TCPConn', 22), address = findType('*net.TCPAddr', 22);
    settings.TCP_CONNECTION_TYPE = tcp ? tcp.address + 'ULL' : 0;
    settings.TCP_ADDRESS_TYPE = address ? address.address + 'ULL' : 0;
    settings.TCP_FD = settings.FD_LOCAL = settings.FD_REMOTE = settings.TCP_IP = settings.TCP_PORT = 0;
    if (tcp && address)
    {
        const embedded = field(element(tcp), 'conn', 25), fd = field(embedded.type, 'fd', 22);
        settings.TCP_FD = embedded.offset + fd.offset;
        settings.FD_LOCAL = field(element(fd.type), 'laddr', 20).offset;
        settings.FD_REMOTE = field(element(fd.type), 'raddr', 20).offset;
        settings.TCP_IP = field(element(address), 'IP', 23).offset;
        settings.TCP_PORT = field(element(address), 'Port', 2).offset;
    }
    for (const name of ['QUIC_CRYPTO', 'QUIC_SOCKET', 'QUIC_CRYPTO_TYPE', 'QUIC_SOCKET_TYPE', 'QUIC_TLS',
        'QUIC_INNER', 'QUIC_REMOTE', 'QUIC_LOCAL', 'QUIC_REMOTE_ADDRESS', 'UDP_ADDRESS_TYPE', 'UDP_IP', 'UDP_PORT'])
        settings[name] = 0;
    const quicRun = functions.get('github.com/quic-go/quic-go.(*Conn).run');
    const quic = quicRun ? findType('quic.Conn', 25) : null;
    if (quic)
    {
        const crypto = findType('*handshake.cryptoSetup', 22), sender = findType('*quic.sconn', 22);
        const remote = findType('quic.remoteAddrInfo', 25), udp = findType('*net.UDPAddr', 22);
        if (!crypto || !sender || !remote || !udp) throw new Error('Go QUIC address metadata is unavailable.');
        settings.QUIC_CRYPTO = field(quic, 'cryptoStreamHandler', 20).offset;
        settings.QUIC_SOCKET = field(quic, 'conn', 20).offset;
        settings.QUIC_CRYPTO_TYPE = crypto.address + 'ULL';
        settings.QUIC_SOCKET_TYPE = sender.address + 'ULL';
        const tls = field(element(crypto), 'conn', 22);
        settings.QUIC_TLS = tls.offset;
        settings.QUIC_INNER = field(element(tls.type), 'conn', 22).offset;
        settings.QUIC_LOCAL = field(element(sender), 'localAddr', 20).offset;
        const remotePointer = field(element(sender), 'remoteAddrInfo', 25);
        settings.QUIC_REMOTE = remotePointer.offset + field(remotePointer.type, 'v', 26).offset;
        settings.QUIC_REMOTE_ADDRESS = field(remote, 'addr', 20).offset;
        settings.UDP_ADDRESS_TYPE = udp.address + 'ULL';
        settings.UDP_IP = field(element(udp), 'IP', 23).offset;
        settings.UDP_PORT = field(element(udp), 'Port', 2).offset;
    }

    // Native probes copy only bounded public fields; JavaScript runs on the observer's own stack.
    const output = Memory.alloc(68 * 1024 * 1024);
    const source = Object.entries(settings).map(([name, value]) => `#define ${name} ${value}`).join('\n');
    const probe = new CModule(source + '\n' + goProbeSource, { output });
    const packetSize = new NativeFunction(probe.packet_size, 'uint', [])();
    if (packetSize !== 1049320 || new NativeFunction(probe.output_size, 'uint', [])() > 68 * 1024 * 1024)
        throw new Error('Go observation buffer layout is unsupported.');
    const packets = new NativeFunction(probe.packets, 'pointer', [])();
    function ip(address, size)
    {
        let bytes = new Uint8Array(address.readByteArray(size));
        if (size === 16 && bytes.slice(0, 10).every(value => value === 0) && bytes[10] === 255 && bytes[11] === 255)
        {
            bytes = bytes.slice(12);
            size = 4;
        }
        return size === 4 ? Array.from(bytes).join('.') : Array.from({ length: 8 }, (_, index) =>
            ((bytes[index * 2] << 8) | bytes[index * 2 + 1]).toString(16)).join(':');
    }
    function drain()
    {
        for (let index = 0; index < 64; ++index)
        {
            const packet = packets.add(index * packetSize);
            if (packet.readU32() !== 2) continue;
            try
            {
                const value = field => packet.add(8 + field * 8).readU64();
                const scalar = field => value(field).toNumber();
                const time = field => Number((BigInt(value(field).toString()) - 116444736000000000n) / 10n);
                const flags = scalar(3), client = !!(flags & 32), success = !!(flags & 1);
                const report = { schema: 'cipherazzi.endpoint/1', provider: 'Go/crypto/tls', pid: Process.id,
                    timestamp_us: time(2), role: client ? 'client' : 'server',
                    transport: flags & 2 ? 'QUIC' : flags & 16 ? 'TCP' : 'Unknown', success };
                if (packet.add(4).readU32() === 2) report.observation = 'connection';
                else report.handshake_started_us = time(1);
                for (const [field, name] of [[4, 'tls_version'], [5, 'cipher_id'], [6, 'group_id'],
                    [7, 'signature_scheme']]) if (scalar(field)) report[name] = scalar(field);
                if (flags & 4) report.peer_verified = true;
                else if (flags & 8) report.peer_verified = false;
                if (success) report.session_resumed = !!(flags & 64);
                else report.error_name = 'TLS_HANDSHAKE_FAILED';
                if (flags & 16)
                {
                    report.local = { address: ip(packet.add(136), scalar(14)), port: scalar(8) };
                    report.remote = { address: ip(packet.add(152), scalar(15)), port: scalar(9) };
                }
                const name = packet.add(168).readUtf8String(scalar(10));
                if (name && /^[\x21-\x7e]+$/.test(name)) report.server_name = name;
                if (scalar(11)) report.selected_alpn = packet.add(424).readUtf8String(scalar(11));
                const certificates = [];
                let offset = 744;
                for (let item = 0; item < scalar(12); ++item)
                {
                    const size = packet.add(680 + item * 4).readU32();
                    certificates.push(base64(new Uint8Array(packet.add(offset).readByteArray(size))));
                    offset += size;
                }
                report[client ? 'server_certificates_der' : 'client_certificates_der'] = certificates;
                send({ kind: 'report', report });
            }
            catch (_) { warn(module.path + ':go-query', 'Some Go TLS metadata could not be observed.', true); }
            finally { packet.writeU32(0); }
        }
        if (output.readU32()) warn(module.path + ':go-bound', 'Go TLS observation reached its buffer bound.', true);
    }

    // Instruction probes preserve return addresses while goroutines grow, move, and change operating-system threads.
    const returns = [];
    let previous = [];
    for (let address = handshake.start; address.compare(handshake.end) < 0;)
    {
        const instruction = Instruction.parse(address);
        if (instruction.mnemonic === 'ret')
        {
            const [adjust, pop] = previous.slice(-2);
            if (adjust?.mnemonic !== 'add' || adjust.operands[0]?.value !== 'rsp' ||
                adjust.operands[1]?.type !== 'imm' || pop?.mnemonic !== 'pop' || pop.opStr !== 'rbp' ||
                adjust.size + pop.size + instruction.size < 5)
                throw new Error('Go handshake epilogue is unsupported.');
            returns.push({ address: adjust.address, frame: Number(adjust.operands[1].value) + 8 });
        }
        previous = [previous.at(-1), instruction];
        address = instruction.next;
    }
    if (!returns.length || returns.length > 32) throw new Error('Go handshake return sites are unavailable.');
    function attach(address, event, frame)
    {
        const data = Memory.alloc(8);
        data.writeU32(event);
        data.add(4).writeU32(frame);
        storage.push(data);
        listeners.push(Interceptor.attach(address, probe.observe, data));
    }
    attach(handshake.start, 1, 0);
    if (quic) attach(quicRun.start, 4, 0);
    for (const site of returns) attach(site.address, 2, site.frame);
    const close = functions.get('crypto/tls.(*Conn).Close');
    if (close) attach(close.start, 3, 0);
    flushOnExit(listeners, drain);
    const timer = setInterval(drain, 10);
    listeners.push({ detach() { clearInterval(timer); drain(); }, probe, output, storage });
    send({ kind: 'adapter', provider: 'Go/crypto/tls', module: module.name });
    return true;
}
