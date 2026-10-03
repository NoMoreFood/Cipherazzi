'use strict';

const libraries = new Map();
const warnings = new Set();
const pointerSize = Process.pointerSize;
const zero = ptr(0);
const nowUs = () => Date.now() * 1000;

function warn(key, message)
{
    if (warnings.has(key))
        return;
    warnings.add(key);
    send({ kind: 'diagnostic', message });
}

function publicString(address, maximum = 256)
{
    if (address.isNull())
        return '';
    let length = 0;
    while (length < maximum && address.add(length).readU8() !== 0)
        ++length;
    return address.readUtf8String(length);
}

function publicProtocol(address, length)
{
    if (address.isNull() || !length || length > 255)
        return '';
    const bytes = new Uint8Array(address.readByteArray(length));
    if (bytes.some(value => value < 33 || value > 126))
        return '';
    return String.fromCharCode(...bytes);
}

function base64(bytes)
{
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let value = '';
    for (let index = 0; index < bytes.length; index += 3)
    {
        const remaining = bytes.length - index;
        const word = (bytes[index] << 16) | ((bytes[index + 1] || 0) << 8) | (bytes[index + 2] || 0);
        value += alphabet[(word >>> 18) & 63] + alphabet[(word >>> 12) & 63] +
            (remaining > 1 ? alphabet[(word >>> 6) & 63] : '=') + (remaining > 2 ? alphabet[word & 63] : '=');
    }
    return value;
}

const groups = {
    prime256v1: 23, secp256r1: 23, P256: 23, secp384r1: 24, P384: 24, secp521r1: 25, P521: 25,
    X25519: 29, X448: 30, ffdhe2048: 256, ffdhe3072: 257, ffdhe4096: 258, ffdhe6144: 259, ffdhe8192: 260,
    X25519MLKEM768: 4588, SecP256r1MLKEM768: 4587, SecP384r1MLKEM1024: 4589,
    MLKEM512: 512, MLKEM768: 513, MLKEM1024: 514
};
const groupIds = new Map(Object.entries(groups).map(([name, value]) => [name.toLowerCase(), value]));
const signatures = {
    rsa_pkcs1_sha256: 0x0401, rsa_pkcs1_sha384: 0x0501, rsa_pkcs1_sha512: 0x0601,
    ecdsa_secp256r1_sha256: 0x0403, ecdsa_secp384r1_sha384: 0x0503, ecdsa_secp521r1_sha512: 0x0603,
    rsa_pss_rsae_sha256: 0x0804, rsa_pss_rsae_sha384: 0x0805, rsa_pss_rsae_sha512: 0x0806,
    ed25519: 0x0807, ed448: 0x0808, rsa_pss_pss_sha256: 0x0809, rsa_pss_pss_sha384: 0x080a,
    rsa_pss_pss_sha512: 0x080b
};
Object.assign(signatures, {
    mldsa44: 0x0904, mldsa65: 0x0905, mldsa87: 0x0906,
    slhdsa_sha2_128s: 0x0911, slhdsa_sha2_128f: 0x0912, slhdsa_sha2_192s: 0x0913,
    slhdsa_sha2_192f: 0x0914, slhdsa_sha2_256s: 0x0915, slhdsa_sha2_256f: 0x0916,
    slhdsa_shake_128s: 0x0917, slhdsa_shake_128f: 0x0918, slhdsa_shake_192s: 0x0919,
    slhdsa_shake_192f: 0x091a, slhdsa_shake_256s: 0x091b, slhdsa_shake_256f: 0x091c
});

function systemApi(module, name, result, arguments_)
{
    const address = Process.getModuleByName(module).findExportByName(name);
    if (address === null)
        throw new Error(`Required Windows API is unavailable: ${name}`);
    return new NativeFunction(address, result, arguments_, { abi: pointerSize === 8 ? 'win64' : 'stdcall' });
}

let getSocketName = null, getPeerName = null;

function socketEndpoints(descriptor)
{
    if (descriptor < 0)
        return null;
    if (getSocketName === null)
    {
        getSocketName = systemApi('ws2_32.dll', 'getsockname', 'int', ['pointer', 'pointer', 'pointer']);
        getPeerName = systemApi('ws2_32.dll', 'getpeername', 'int', ['pointer', 'pointer', 'pointer']);
    }
    const socket = ptr(descriptor >>> 0);
    function endpoint(query)
    {
        const address = Memory.alloc(128), length = Memory.alloc(4);
        length.writeU32(128);
        if (query(socket, address, length) !== 0)
            return null;
        const family = address.readU16();
        if ((family !== 2 && family !== 23) || length.readU32() < (family === 2 ? 16 : 28))
            return null;
        const port = (address.add(2).readU8() << 8) | address.add(3).readU8();
        if (port === 0)
            return null;
        let text;
        if (family === 2)
            text = Array.from(new Uint8Array(address.add(4).readByteArray(4))).join('.');
        else
        {
            const bytes = new Uint8Array(address.add(8).readByteArray(16));
            text = Array.from({ length: 8 }, (_, index) =>
                ((bytes[index * 2] << 8) | bytes[index * 2 + 1]).toString(16)).join(':');
        }
        return { address: text, port };
    }
    const local = endpoint(getSocketName), remote = endpoint(getPeerName);
    return local !== null && remote !== null ? { local, remote } : null;
}

function publicSymbolApi(module)
{
    // Use the image's CodeView metadata to find symbols shipped beside the loaded module.
    if (module.size < 256 || module.base.readU16() !== 0x5a4d)
        return null;
    const nt = module.base.add(0x3c).readU32();
    if (nt > module.size - 256 || module.base.add(nt).readU32() !== 0x4550)
        return null;
    const optional = module.base.add(nt + 24), magic = optional.readU16();
    if (magic !== 0x10b && magic !== 0x20b)
        return null;
    const directories = magic === 0x20b ? 112 : 96;
    if (module.base.add(nt + 20).readU16() < directories + 56 ||
        optional.add(directories - 4).readU32() < 7)
        return null;
    const table = optional.add(directories + 48);
    const offset = table.readU32(), size = table.add(4).readU32();
    if (!offset || size < 28 || size > 1792 || offset + size > module.size)
        return null;
    const folder = module.path.slice(0, Math.max(module.path.lastIndexOf('\\'), module.path.lastIndexOf('/')) + 1);
    let pdb = null;
    for (let index = 0; index + 28 <= size; index += 28)
    {
        const entry = module.base.add(offset + index);
        const length = entry.add(16).readU32(), address = entry.add(20).readU32();
        if (entry.add(12).readU32() !== 2 || length < 25 || length > 32768)
            continue;
        let data;
        if (address && address + length <= module.size)
            data = module.base.add(address);
        else
        {
            const file = new File(module.path, 'rb');
            try
            {
                file.seek(entry.add(24).readU32(), File.SEEK_SET);
                const bytes = file.readBytes(length);
                if (bytes.byteLength !== length)
                    continue;
                data = Memory.alloc(length);
                data.writeByteArray(bytes);
            }
            finally { file.close(); }
        }
        if (data.readU32() !== 0x53445352)
            continue;
        const name = publicString(data.add(24), length - 24).split(/[\\/]/).pop();
        if (name && name.toLowerCase().endsWith('.pdb'))
        {
            const attributes = systemApi('kernel32.dll', 'GetFileAttributesW', 'uint', ['pointer'])(
                Memory.allocUtf16String(folder + name));
            if (attributes !== 0xffffffff && !(attributes & 16))
            {
                pdb = folder + name;
                break;
            }
        }
    }
    if (pdb === null)
        return null;
    try { DebugSymbol.load(module.path); }
    catch (_) { return null; }

    // Require one executable symbol in this module before calling a public TLS API.
    const scope = module.name.replace(/\.(exe|dll)$/i, '') + '!';
    const cache = new Map();
    function valid(address)
    {
        return address.compare(module.base) >= 0 && address.compare(module.base.add(module.size)) < 0 &&
            Process.findRangeByAddress(address)?.protection.includes('x');
    }
    function find(name)
    {
        if (!cache.has(name))
        {
            const matches = DebugSymbol.findFunctionsNamed(scope + name).filter(valid);
            const unique = [...new Map(matches.map(address => [address.toString(), address])).values()];
            cache.set(name, unique.length === 1 ? unique[0] : null);
        }
        return cache.get(name);
    }
    const entries = DebugSymbol.findFunctionsMatching(scope + '*SSL_do_handshake').filter(valid)
        .map(address => ({ name: DebugSymbol.fromAddress(address).name, address }))
        .filter(entry => /^[A-Za-z_][A-Za-z_0-9]*$/.test(entry.name) && entry.name.endsWith('SSL_do_handshake'));
    return { find, entry: entries.length === 1 ? entries[0] : undefined };
}

function install(module, provider, prefix, symbols = null)
{
    const state = new Map();
    const imports = module.enumerateImports();
    const dependencies = Array.from(new Set(imports.map(value => value.module).filter(Boolean)))
        .map(name => Process.findModuleByName(name)).filter(Boolean);
    const listeners = [];
    libraries.set(module.path, listeners);
    const native = new Map();
    function address(name)
    {
        const exported = module.findExportByName(prefix + name);
        if (exported !== null)
            return exported;
        const symbol = symbols?.find(prefix + name);
        if (symbol !== null && symbol !== undefined)
            return symbol;
        const imported = imports.find(value => value.name === prefix + name || value.name === name);
        if (imported && imported.address)
            return imported.address;
        for (const dependency of dependencies)
        {
            const target = dependency.findExportByName(prefix + name) || dependency.findExportByName(name);
            if (target !== null)
                return target;
        }
        return null;
    }
    function api(name, result, arguments_)
    {
        if (native.has(name))
            return native.get(name);
        const target = address(name);
        const value = target === null ? null : new NativeFunction(target, result, arguments_, { traps: 'none' });
        native.set(name, value);
        return value;
    }
    function hook(name, callbacks)
    {
        const target = address(name);
        if (target === null)
            return false;
        listeners.push(Interceptor.attach(target, callbacks));
        return true;
    }
    function tracked(pointer, create)
    {
        const key = pointer.toString();
        if (!state.has(key) && create)
        {
            if (state.size >= 2048)
            {
                state.delete(state.keys().next().value);
                warn(module.path + ':sessions', 'Endpoint adapter session tracking reached its bound.');
            }
            state.set(key, { started: 0, emitted: false, active: 0, verified: null, serverName: '' });
        }
        return state.get(key);
    }
    function report(pointer, success, details)
    {
        const current = tracked(pointer, true);
        if (current.emitted)
            return;
        if (!current.started || nowUs() - current.started > 120000000)
        {
            warn(module.path + ':timing',
                `${provider}: handshake timing was unavailable or exceeded the report bound.`);
            return;
        }
        const endpoints = socketEndpoints(details.descriptor);
        if (success && (!details.version || !details.cipher))
            return;
        const payload = {
            schema: 'cipherazzi.endpoint/1', provider, pid: Process.id,
            handshake_started_us: current.started, timestamp_us: nowUs(),
            role: details.server ? 'server' : 'client',
            transport: details.dtls ? 'DTLS' : endpoints === null ? 'Unknown' : 'TCP', success
        };
        if (endpoints !== null)
        {
            payload.local = endpoints.local;
            payload.remote = endpoints.remote;
        }
        if (details.version > 0)
            payload.tls_version = details.version;
        if (details.cipher > 0)
            payload.cipher_id = details.cipher;
        for (const [target, source] of [['group_id', 'group'], ['signature_scheme', 'peerSignature'],
            ['local_signature_scheme', 'localSignature']])
            if (Number.isInteger(details[source]) && details[source] > 0 && details[source] <= 65535)
                payload[target] = details[source];
        if (details.verified !== null && details.verified !== undefined)
            payload.peer_verified = details.verified;
        if (details.alpn)
            payload.selected_alpn = details.alpn;
        if (details.resumed !== undefined)
            payload.session_resumed = details.resumed;
        if (details.serverName && details.serverName.length <= 253 && /^[\x21-\x7e]+$/.test(details.serverName))
            payload.server_name = details.serverName;
        let certificateBytes = 0;
        for (const [certificates, field] of [
            [details.peerCertificates, details.server ? 'client_certificates_der' : 'server_certificates_der'],
            [details.localCertificates, details.server ? 'server_certificates_der' : 'client_certificates_der']])
        {
            if (!certificates || !certificates.length)
                continue;
            payload[field] = certificates.filter(encoded => {
                const bytes = encoded.length * 3 / 4 - (encoded.endsWith('==') ? 2 : encoded.endsWith('=') ? 1 : 0);
                if (certificateBytes + bytes > 1048576)
                {
                    warn(module.path + ':certificates', `${provider}: public certificate storage reached its bound.`);
                    return false;
                }
                certificateBytes += bytes;
                return true;
            });
        }
        current.emitted = true;
        send({ kind: 'report', report: payload });
    }
    function guarded(context, callback)
    {
        const lastError = context.lastError;
        try { callback(); }
        catch (_) { warn(module.path + ':query', `${provider}: public handshake metadata could not be queried.`); }
        finally { context.lastError = lastError; }
    }

    if (provider === 'NSS')
    {
        const channel = api('SSL_GetChannelInfo', 'int', ['pointer', 'pointer', 'uint']);
        const option = api('SSL_OptionGet', 'int', ['pointer', 'int', 'pointer']);
        const nativeHandle = api('PR_FileDesc2NativeHandle', 'int', ['pointer']);
        const nextProto = api('SSL_GetNextProto', 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'uint']);
        const peerChain = api('SSL_PeerCertificateChain', 'pointer', ['pointer']);
        const destroyChain = api('CERT_DestroyCertList', 'void', ['pointer']);
        const certificateDer = api('CERT_GetCertificateDer', 'int', ['pointer', 'pointer']);
        const revealName = api('SSL_RevealURL', 'pointer', ['pointer']);
        const freeName = api('PORT_Free', 'void', ['pointer']);
        const getError = api('PR_GetError', 'int', []), getOsError = api('PR_GetOSError', 'int', []);
        const setError = api('PR_SetError', 'void', ['int', 'int']);
        if (channel === null || option === null || nativeHandle === null ||
            getError === null || getOsError === null || setError === null)
            throw new Error('NSS public channel or socket API is unavailable.');
        function query(context, callback)
        {
            guarded(context, () => {
                const error = getError(), osError = getOsError();
                try { callback(); }
                finally { setError(error, osError); }
            });
        }
        function inspect(descriptor, success)
        {
            const current = tracked(descriptor, true);
            if (current.emitted)
                return;
            const infoSize = pointerSize === 8 ? 116 : 112;
            const info = Memory.alloc(infoSize), server = Memory.alloc(4);
            const details = { descriptor: nativeHandle(descriptor), server: false, verified: current.verified,
                version: 0, cipher: 0, dtls: current.dtls, serverName: current.serverName };
            if (option(descriptor, 6, server) !== 0)
                return;
            details.server = server.readS32() !== 0;
            if (channel(descriptor, info, infoSize) !== 0)
            {
                if (success)
                    return;
            }
            else
            {
                const length = info.readU32();
                if (length >= 8)
                {
                    details.version = info.add(4).readU16();
                    if (details.dtls)
                        details.version = { 770: 0xfeff, 771: 0xfefd, 772: 0xfefc }[details.version] || 0;
                    details.cipher = info.add(6).readU16();
                }
                const groupOffset = pointerSize === 8 ? 88 : 84;
                if (length >= groupOffset + 4)
                    details.group = info.add(groupOffset).readU32();
                if (length >= groupOffset + 28)
                {
                    details.resumed = info.add(groupOffset + 24).readU32() !== 0;
                    if (!details.resumed)
                        details.peerSignature = info.add(groupOffset + 16).readU32();
                }
            }
            if (nextProto !== null && success)
            {
                const protocol = Memory.alloc(256), length = Memory.alloc(4), selection = Memory.alloc(4);
                if (nextProto(descriptor, selection, protocol, length, 255) === 0 && length.readU32() <= 255)
                    details.alpn = publicProtocol(protocol, length.readU32());
            }
            if (!details.serverName && revealName !== null && freeName !== null)
            {
                const name = revealName(descriptor);
                try { details.serverName = publicString(name); }
                finally { if (!name.isNull()) freeName(name); }
            }
            if (peerChain !== null && destroyChain !== null && certificateDer !== null && success)
            {
                const chain = peerChain(descriptor);
                if (!chain.isNull())
                {
                    const certificates = [];
                    try
                    {
                        let node = chain.readPointer(), total = 0;
                        while (!node.equals(chain) && !node.isNull() && certificates.length < 16)
                        {
                            const der = Memory.alloc(pointerSize === 8 ? 24 : 12);
                            if (certificateDer(node.add(pointerSize * 2).readPointer(), der) !== 0)
                                break;
                            const data = der.add(pointerSize === 8 ? 8 : 4).readPointer();
                            const length = der.add(pointerSize === 8 ? 16 : 8).readU32();
                            if (!length || length > 262144 || total + length > 1048576)
                                break;
                            certificates.push(base64(new Uint8Array(data.readByteArray(length))));
                            total += length;
                            node = node.readPointer();
                        }
                    }
                    finally { destroyChain(chain); }
                    details.peerCertificates = certificates;
                }
            }
            report(descriptor, success, details);
        }
        for (const [operation, dtls] of [['SSL_ImportFD', false], ['DTLS_ImportFD', true]])
            hook(operation, {
                onLeave(result)
                {
                    if (!result.isNull())
                    {
                        state.delete(result.toString());
                        tracked(result, true).dtls = dtls;
                    }
                }
            });
        hook('SSL_SetURL', {
            onEnter(arguments_)
            {
                query(this, () => tracked(arguments_[0], true).serverName = publicString(arguments_[1]));
            }
        });
        hook('SSL_AuthCertificate', {
            onEnter(arguments_)
            {
                this.descriptor = arguments_[1];
                this.checkSignature = arguments_[2].toInt32() !== 0;
                const current = tracked(this.descriptor, true);
                current.started ||= nowUs();
            },
            onLeave(result)
            {
                tracked(this.descriptor, true).verified = result.toInt32() !== 0 ? false :
                    this.checkSignature ? true : null;
            }
        });
        const verifiers = new Set();
        hook('SSL_AuthCertificateHook', {
            onEnter(arguments_)
            {
                const callback = arguments_[1], key = callback.toString();
                tracked(arguments_[0], true).verifier = key;
                if (callback.isNull() || verifiers.has(key))
                    return;
                if (verifiers.size >= 128)
                {
                    warn(module.path + ':verifiers', 'NSS certificate callback tracking reached its bound.');
                    return;
                }
                verifiers.add(key);
                listeners.push(Interceptor.attach(callback, {
                    onEnter(values)
                    {
                        const current = tracked(values[1], false);
                        if (current && current.verifier === key)
                        {
                            this.current = current;
                            this.checkSignature = values[2].toInt32() !== 0;
                            current.started ||= nowUs();
                        }
                    },
                    onLeave(result)
                    {
                        if (this.current)
                            this.current.verified = result.toInt32() === -1 ? false :
                                result.toInt32() === 0 && this.checkSignature ? true : null;
                    }
                }));
            }
        });
        hook('SSL_AuthCertificateComplete', {
            onEnter(arguments_) { this.descriptor = arguments_[0]; this.error = arguments_[1].toInt32(); },
            onLeave(result)
            {
                if (result.toInt32() === 0)
                    tracked(this.descriptor, true).verified = this.error === 0;
            }
        });
        const callbacks = new Set();
        hook('SSL_HandshakeCallback', {
            onEnter(arguments_)
            {
                const callback = arguments_[1], key = callback.toString();
                tracked(arguments_[0], true).handshakeCallback = key;
                if (callback.isNull() || callbacks.has(key))
                    return;
                if (callbacks.size >= 128)
                {
                    warn(module.path + ':callbacks', 'NSS handshake callback tracking reached its bound.');
                    return;
                }
                callbacks.add(key);
                listeners.push(Interceptor.attach(callback, {
                    onEnter(values)
                    {
                        if (tracked(values[0], false)?.handshakeCallback === key)
                            query(this, () => inspect(values[0], true));
                    }
                }));
            }
        });
        for (const operation of ['SSL_ForceHandshake', 'SSL_ForceHandshakeWithTimeout', 'PR_Read', 'PR_Write',
            'PR_Recv', 'PR_Send'])
            hook(operation, {
                onEnter(arguments_)
                {
                    this.descriptor = arguments_[0];
                    const current = tracked(this.descriptor, operation.startsWith('SSL_ForceHandshake'));
                    if (current)
                    {
                        this.observe = !current.emitted;
                        current.started ||= nowUs();
                    }
                },
                onLeave(result)
                {
                    if (!this.observe)
                        return;
                    query(this, () => {
                        if (result.toInt32() >= 0)
                            inspect(this.descriptor, true);
                        else if (getError() !== -5998)
                            inspect(this.descriptor, false);
                    });
                }
            });
        hook('PR_Close', { onEnter(arguments_) { state.delete(arguments_[0].toString()); } });
    }
    else
    {
        const fd = api('SSL_get_fd', 'int', ['pointer']);
        const version = api('SSL_version', 'int', ['pointer']);
        const server = api('SSL_is_server', 'int', ['pointer']);
        const finished = api('SSL_is_init_finished', 'int', ['pointer']);
        const reused = api('SSL_session_reused', 'int', ['pointer']);
        const cipher = api('SSL_get_current_cipher', 'pointer', ['pointer']);
        const cipherId = api('SSL_CIPHER_get_protocol_id', 'uint16', ['pointer']) ||
            api('SSL_CIPHER_get_id', 'uint', ['pointer']);
        const control = api('SSL_ctrl', 'long', ['pointer', 'int', 'long', 'pointer']);
        const libraryVersion = api('OpenSSL_version_num', 'ulong', []);
        const signatureNames = provider === 'OpenSSL' && libraryVersion !== null &&
            Number(libraryVersion()) >= 0x30500000;
        const group = api('SSL_get_group_id', 'uint16', ['pointer']) || api('SSL_get_curve_id', 'uint16', ['pointer']);
        const groupName = api('SSL_get0_group_name', 'pointer', ['pointer']);
        const peerSignature = api('SSL_get_peer_signature_algorithm', 'uint16', ['pointer']);
        const localSignature = api('SSL_get_signature_algorithm_used', 'uint16', ['pointer']);
        const activeHandshakes = new Map();
        const verifyMode = api('SSL_get_verify_mode', 'int', ['pointer']);
        const verifyResult = api('SSL_get_verify_result', 'long', ['pointer']);
        const alpn = api('SSL_get0_alpn_selected', 'void', ['pointer', 'pointer', 'pointer']);
        const name = api('SSL_get_servername', 'pointer', ['pointer', 'int']);
        const der = api('i2d_X509', 'int', ['pointer', 'pointer']);
        const stackCount = api('OPENSSL_sk_num', 'int', ['pointer']);
        const stackValue = api('OPENSSL_sk_value', 'pointer', ['pointer', 'int']);
        const peerCertificate = api('SSL_get0_peer_certificate', 'pointer', ['pointer']);
        const peerOwned = api('SSL_get1_peer_certificate', 'pointer', ['pointer']) ||
            api('SSL_get_peer_certificate', 'pointer', ['pointer']);
        const freeCertificate = api('X509_free', 'void', ['pointer']);
        const peerChain = api('SSL_get_peer_cert_chain', 'pointer', ['pointer']);
        const localCertificate = api('SSL_get_certificate', 'pointer', ['pointer']);
        const contextOf = api('SSL_get_SSL_CTX', 'pointer', ['pointer']);
        const peerBuffers = api('SSL_get0_peer_certificates', 'pointer', ['pointer']);
        const bufferData = api('CRYPTO_BUFFER_data', 'pointer', ['pointer']);
        const bufferLength = api('CRYPTO_BUFFER_len', 'size_t', ['pointer']);
        const contexts = new Map(), verifiers = new Set();
        if (provider === 'BoringSSL')
        {
            const methods = ['TLS_method', 'TLS_client_method', 'TLS_server_method', 'DTLS_method',
                'DTLS_client_method', 'DTLS_server_method'].map(name => api(name, 'pointer', []))
                .filter(Boolean).map(method => method());
            hook('SSL_CTX_new', {
                onEnter(arguments_) { this.x509 = methods.some(method => method.equals(arguments_[0])); },
                onLeave(result)
                {
                    if (result.isNull())
                        return;
                    if (contexts.size >= 2048)
                        contexts.delete(contexts.keys().next().value);
                    contexts.set(result.toString(), { x509: this.x509 });
                }
            });
            hook('SSL_CTX_free', { onEnter(arguments_) { contexts.delete(arguments_[0].toString()); } });
            for (const operation of ['SSL_CTX_set_custom_verify', 'SSL_set_custom_verify'])
                hook(operation, {
                    onEnter(arguments_)
                    {
                        const callback = arguments_[2], key = callback.toString();
                        const context = operation === 'SSL_CTX_set_custom_verify' ?
                            contexts.get(arguments_[0].toString()) : tracked(arguments_[0], true);
                        if (context)
                            context.verifier = key;
                        if (callback.isNull() || verifiers.has(key))
                            return;
                        if (verifiers.size >= 128)
                        {
                            warn(module.path + ':verifiers',
                                'BoringSSL certificate callback tracking reached its bound.');
                            return;
                        }
                        verifiers.add(key);
                        listeners.push(Interceptor.attach(callback, {
                            onEnter(values)
                            {
                                const current = tracked(values[0], false);
                                const context = contextOf === null ? null :
                                    contexts.get(contextOf(values[0]).toString());
                                if (current && (current.verifier === key || context?.verifier === key))
                                    this.current = current;
                            },
                            onLeave(result)
                            {
                                if (this.current)
                                    this.current.verified = result.toInt32() === 0 ? true :
                                        result.toInt32() === 1 ? false : null;
                            }
                        }));
                    }
                });
        }
        if (fd === null || version === null || server === null ||
            finished === null || cipher === null || cipherId === null)
            throw new Error(`${provider} public session API is unavailable.`);
        function certificates(leaf, chain)
        {
            if (der === null)
                return [];
            const result = [], seen = new Set();
            let total = 0;
            function append(certificate)
            {
                if (certificate.isNull() || result.length >= 16)
                    return;
                const length = der(certificate, zero);
                if (length <= 0 || length > 262144 || total + length > 1048576)
                    return;
                const buffer = Memory.alloc(length), output = Memory.alloc(pointerSize);
                output.writePointer(buffer);
                if (der(certificate, output) !== length)
                    return;
                const encoded = base64(new Uint8Array(buffer.readByteArray(length)));
                if (!seen.has(encoded))
                {
                    seen.add(encoded);
                    result.push(encoded);
                    total += length;
                }
            }
            append(leaf);
            if (!chain.isNull() && stackCount !== null && stackValue !== null)
                for (let index = 0, count = Math.min(16, stackCount(chain)); index < count; ++index)
                    append(stackValue(chain, index));
            return result;
        }
        function inspect(ssl, success)
        {
            const current = tracked(ssl, true);
            if (current.emitted)
                return;
            const selected = cipher(ssl), tlsVersion = version(ssl);
            const details = { descriptor: fd(ssl), version: tlsVersion, dtls: (tlsVersion & 0xff00) === 0xfe00,
                cipher: selected.isNull() ? 0 : cipherId(selected) & 65535, server: server(ssl) !== 0 };
            if (reused !== null)
                details.resumed = reused(ssl) !== 0;
            if (!details.resumed || !details.dtls && tlsVersion >= 772 || tlsVersion === 0xfefc)
            {
                if (group !== null)
                    details.group = group(ssl);
                else if (groupName !== null)
                    details.group = groupIds.get(publicString(groupName(ssl)).toLowerCase());
            }
            if (peerSignature !== null && !details.resumed)
                details.peerSignature = peerSignature(ssl);
            if (localSignature !== null && !details.resumed)
                details.localSignature = localSignature(ssl) || current.localSignature;
            if (control !== null && signatureNames && !details.resumed)
                for (const [command, field] of [[141, 'peerSignature'], [140, 'localSignature']])
                {
                    const result = Memory.alloc(pointerSize);
                    result.writePointer(zero);
                    if (control(ssl, command, 0, result) > 0)
                        details[field] = signatures[publicString(result.readPointer())];
                }
            const boring = provider === 'BoringSSL';
            const context = boring && contextOf !== null ? contexts.get(contextOf(ssl).toString()) : null;
            const owned = !boring && peerCertificate === null && peerOwned !== null && freeCertificate !== null;
            const peer = boring ? zero : peerCertificate !== null ?
                peerCertificate(ssl) : owned ? peerOwned(ssl) : zero;
            if (boring && peerBuffers !== null && bufferData !== null && bufferLength !== null &&
                stackCount !== null && stackValue !== null && success)
            {
                const chain = peerBuffers(ssl), certificates = [];
                let total = 0;
                if (!chain.isNull())
                    for (let index = 0, count = Math.min(16, stackCount(chain)); index < count; ++index)
                    {
                        const certificate = stackValue(chain, index), length = Number(bufferLength(certificate));
                        if (length <= 0 || length > 262144 || total + length > 1048576)
                            break;
                        certificates.push(base64(new Uint8Array(bufferData(certificate).readByteArray(length))));
                        total += length;
                    }
                details.peerCertificates = certificates;
            }
            try
            {
                details.verified = current.verified;
                if (details.verified === null && verifyMode !== null && (verifyMode(ssl) & 1))
                {
                    if (verifyResult !== null && (!boring || current.x509 || context?.x509))
                    {
                        const verification = verifyResult(ssl);
                        if (verification !== 0 || success && (!peer.isNull() || details.peerCertificates?.length))
                            details.verified = verification === 0;
                    }
                    else if (success && details.peerCertificates?.length)
                        details.verified = true;
                }
                if (success && !boring)
                    details.peerCertificates = certificates(peer, peerChain === null ? zero : peerChain(ssl));
            }
            finally { if (owned && !peer.isNull()) freeCertificate(peer); }
            if (alpn !== null && success)
            {
                const data = Memory.alloc(pointerSize), length = Memory.alloc(4);
                alpn(ssl, data, length);
                if (length.readU32() > 0 && length.readU32() <= 255)
                    details.alpn = publicProtocol(data.readPointer(), length.readU32());
            }
            if (name !== null)
                details.serverName = publicString(name(ssl, 0));
            if (success && !boring)
            {
                details.localCertificates = certificates(
                    localCertificate === null ? zero : localCertificate(ssl), zero);
            }
            report(ssl, success, details);
        }
        hook('SSL_new', {
            onEnter(arguments_) { this.configuration = contexts.get(arguments_[0].toString()); },
            onLeave(result)
            {
                if (result.isNull())
                    return;
                state.delete(result.toString());
                const current = tracked(result, true);
                if (this.configuration)
                {
                    current.x509 = this.configuration.x509;
                    current.verifier = this.configuration.verifier;
                }
            }
        });
        hook('SSL_clear', {
            onEnter(arguments_) { this.ssl = arguments_[0]; },
            onLeave(result)
            {
                if (result.toInt32() > 0)
                {
                    const current = tracked(this.ssl, false);
                    if (current && current.active && !current.emitted)
                        return;
                    state.delete(this.ssl.toString());
                    const replacement = tracked(this.ssl, true);
                    replacement.started = current?.active ? nowUs() : 0;
                    replacement.x509 = current?.x509;
                    replacement.verifier = current?.verifier;
                }
            }
        });
        function begin(context, ssl)
        {
            context.ssl = ssl;
            guarded(context, () => {
                const current = tracked(ssl, true);
                context.current = current;
                ++current.active;
                if (localSignature !== null && !current.emitted)
                {
                    const stack = activeHandshakes.get(context.threadId) || [];
                    if (stack.length < 64)
                    {
                        stack.push(context);
                        activeHandshakes.set(context.threadId, stack);
                        context.signing = true;
                    }
                }
                if (!current.started)
                {
                    if (finished(ssl))
                        current.emitted = true;
                    else
                        current.started = nowUs();
                }
            });
        }
        function completed(context)
        {
            if (!context.current)
                return;
            --context.current.active;
            if (context.signing)
            {
                const stack = activeHandshakes.get(context.threadId);
                stack.splice(stack.lastIndexOf(context), 1);
                if (!stack.length)
                    activeHandshakes.delete(context.threadId);
            }
            if (!tracked(context.ssl, false)?.emitted)
                guarded(context, () => { if (finished(context.ssl)) inspect(context.ssl, true); });
        }
        for (const operation of ['SSL_connect', 'SSL_accept', 'SSL_do_handshake', 'SSL_read', 'SSL_write',
            'SSL_read_ex', 'SSL_write_ex', 'SSL_read_ex2', 'SSL_write_ex2', 'SSL_peek', 'SSL_peek_ex',
            'SSL_read_early_data', 'SSL_write_early_data'])
            hook(operation, {
                onEnter(arguments_) { begin(this, arguments_[0]); },
                onLeave() { completed(this); }
            });

        // Query the public local signature scheme while signing still exposes the handshake selection.
        if (localSignature !== null)
            for (const operation of ['EVP_DigestSignInit', 'EVP_DigestSignInit_ex', 'EVP_DigestSign',
                'EVP_DigestSignFinal', 'EVP_PKEY_sign'])
                hook(operation, {
                    onEnter()
                    {
                        const stack = activeHandshakes.get(this.threadId);
                        if (!stack?.length)
                            return;
                        const ssl = stack[stack.length - 1].ssl;
                        guarded(this, () => {
                            const signature = localSignature(ssl);
                            if (signature > 0)
                                tracked(ssl, true).localSignature = signature;
                        });
                    }
                });

        // SSL BIO handlers can drive handshakes without calling the exported SSL entry points.
        const sslBioMethod = api('BIO_f_ssl', 'pointer', []);
        const bioControl = api('BIO_ctrl', 'long', ['pointer', 'int', 'long', 'pointer']);
        const bioFlags = api('BIO_test_flags', 'int', ['pointer', 'int']);
        if (provider === 'OpenSSL' && sslBioMethod !== null && bioControl !== null)
        {
            const method = sslBioMethod(), installed = new Set();
            for (const accessor of ['BIO_meth_get_read', 'BIO_meth_get_read_ex', 'BIO_meth_get_write',
                'BIO_meth_get_write_ex', 'BIO_meth_get_ctrl'])
            {
                const handler = api(accessor, 'pointer', ['pointer']);
                const target = handler === null ? zero : handler(method);
                if (target.isNull() || installed.has(target.toString()))
                    continue;
                installed.add(target.toString());
                listeners.push(Interceptor.attach(target, {
                    onEnter(arguments_)
                    {
                        if (accessor === 'BIO_meth_get_ctrl' && arguments_[1].toInt32() !== 101)
                            return;
                        this.bio = arguments_[0];
                        guarded(this, () => {
                            const ssl = Memory.alloc(pointerSize);
                            ssl.writePointer(zero);
                            if (bioControl(arguments_[0], 110, 0, ssl) > 0 && !ssl.readPointer().isNull())
                                begin(this, ssl.readPointer());
                        });
                    },
                    onLeave(result)
                    {
                        completed(this);
                        if (this.current && !this.current.emitted && result.toInt32() <= 0 && bioFlags !== null)
                            guarded(this, () => {
                                if (!bioFlags(this.bio, 8) && !finished(this.ssl))
                                    inspect(this.ssl, false);
                            });
                    }
                }));
            }
        }
        // Observe the application's error classification after retries without querying its error state early.
        hook('SSL_get_error', {
            onEnter(arguments_) { this.ssl = arguments_[0]; },
            onLeave(result)
            {
                if (this.ssl.isNull())
                    return;
                if ([1, 5, 6].includes(result.toInt32()))
                    guarded(this, () => { if (!finished(this.ssl)) inspect(this.ssl, false); });
            }
        });
        hook('SSL_free', { onEnter(arguments_) { state.delete(arguments_[0].toString()); } });
    }
    libraries.set(module.path, listeners);
    send({ kind: 'adapter', provider, module: module.name });
}

const observer = Process.attachModuleObserver({
    onAdded(module)
    {
        if (libraries.has(module.path))
            return;
        try
        {
            const exports = module.enumerateExports();
            let entry = exports.find(value => value.name.endsWith('SSL_do_handshake'));
            const symbols = entry === undefined && module.findExportByName('SSL_GetChannelInfo') === null ?
                publicSymbolApi(module) : null;
            entry ||= symbols?.entry;
            if (entry !== undefined)
            {
                const prefix = entry.name.slice(0, -'SSL_do_handshake'.length);
                const provider = (module.findExportByName(prefix + 'SSL_get_peer_signature_algorithm') ||
                    symbols?.find(prefix + 'SSL_get_peer_signature_algorithm')) ?
                    'BoringSSL' : 'OpenSSL';
                if (adapterOptions.provider === 'auto' || adapterOptions.provider === provider.toLowerCase())
                    install(module, provider, prefix, symbols);
            }
            else if ((module.findExportByName('SSL_GetChannelInfo') || symbols?.find('SSL_GetChannelInfo')) &&
                (adapterOptions.provider === 'auto' || adapterOptions.provider === 'nss'))
                install(module, 'NSS', '', symbols);
        }
        catch (_)
        {
            const listeners = libraries.get(module.path);
            if (listeners)
                for (const listener of listeners)
                    listener.detach();
            libraries.delete(module.path);
            warn(module.path, 'An endpoint library could not be observed with its public APIs.');
        }
    },
    onRemoved(module)
    {
        const listeners = libraries.get(module.path);
        if (listeners !== undefined)
            for (const listener of listeners)
                listener.detach();
        libraries.delete(module.path);
    }
});
send({ kind: 'ready', adapters: libraries.size });
