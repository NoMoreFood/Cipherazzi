function rustlsImageHash(module)
{
    const file = new File(module.path, 'rb');
    try
    {
        file.seek(0, File.SEEK_END);
        const size = file.tell();
        if (size < 256 || size > 268435456) throw new Error('Rustls image exceeds the profile size bound.');
        file.seek(0, File.SEEK_SET);
        const hash = new Checksum('sha256');
        for (let offset = 0; offset < size; offset += 65536)
        {
            const length = Math.min(65536, size - offset), bytes = file.readBytes(length);
            if (bytes.byteLength !== length) throw new Error('Rustls image could not be read completely.');
            hash.update(bytes);
        }
        return hash.getString();
    }
    finally { file.close(); }
}

function rustlsProfile(module, profile)
{
    function require(condition)
    {
        if (!condition) throw new Error('Rustls observation profile is invalid or exceeds its bounds.');
    }
    function number(value, maximum = 1048576)
    {
        return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
    }
    function name(value)
    {
        return typeof value === 'string' && value.length <= 8192;
    }
    require(profile.schema === 'cipherazzi.rustls-profile/1' && profile.architecture === 'x64' &&
        /^[0-9a-f]{64}$/.test(profile.image_sha256) && number(profile.image_size, 268435456));
    if (profile.image_size !== module.size || profile.image_sha256 !== rustlsImageHash(module))
    {
        warn(module.path + ':rustls-profile', 'Rustls observation profile does not match the executable build.', true);
        return null;
    }
    require(Array.isArray(profile.types) && profile.types.length > 0 && profile.types.length <= 8192 &&
        Array.isArray(profile.names) && profile.names.length <= 8192 &&
        Array.isArray(profile.symbols) && profile.symbols.length <= 8192);

    // Reject incomplete references and out-of-image hook addresses before installing any listener.
    const types = new Map(), names = new Map();
    let fieldCount = 0;
    for (const entry of profile.types)
    {
        require(number(entry.id, 0xffffffff) && !types.has(entry.id) && name(entry.name) &&
            number(entry.tag, 64) && entry.tag > 0 && (entry.size === null || number(entry.size)) &&
            Array.isArray(entry.fields) && entry.fields.length <= 2048);
        fieldCount += entry.fields.length;
        require(fieldCount <= 131072);
        types.set(entry.id, { id: entry.id, name: entry.name, tag: entry.tag, size: entry.size,
            target: entry.target, fields: new Map() });
    }
    function type(id)
    {
        const value = types.get(id);
        require(value !== undefined);
        return value;
    }
    for (const entry of profile.types)
    {
        const value = type(entry.id);
        if (value.tag === 14) type(value.target);
        for (const field of entry.fields)
        {
            require(name(field.name) && !value.fields.has(field.name) && number(field.kind, 9));
            const member = { kind: field.kind, offset: field.offset, type: type(field.type) };
            if (member.kind === 7)
                require(number(member.offset) && member.offset + member.type.size <= value.size);
            if (field.constant !== undefined)
            {
                require(typeof field.constant === 'string' && /^-?\d{1,20}$/.test(field.constant));
                member.constant = BigInt(field.constant);
                require(member.constant >= -9223372036854775808n && member.constant <= 18446744073709551615n);
            }
            value.fields.set(field.name, member);
        }
    }
    for (const entry of profile.names)
    {
        require(Array.isArray(entry) && entry.length === 2 && name(entry[0]) && !names.has(entry[0]));
        names.set(entry[0], entry[1] === null ? null : type(entry[1]));
    }
    const symbols = profile.symbols.map(entry =>
    {
        require(name(entry.name) && number(entry.rva, module.size - 1) &&
            number(entry.type, 0xffffffff) && number(entry.tag, 64));
        const address = module.base.add(entry.rva);
        if (entry.tag === 5) require(Process.findRangeByAddress(address)?.protection.includes('x'));
        return { name: entry.name, address, type: entry.type, tag: entry.tag,
            argument: entry.argument === null ? null : type(entry.argument) };
    });
    const common = type(profile.common);
    require(common.name === 'rustls::common_state::CommonState');
    return { common, type, named: name => names.get(name) ?? null, fields: value => value.fields,
        firstArgument: symbol => symbol.argument, info: (id, request) => request === 4 ? type(id).target : null,
        symbols, close() {} };
}

function rustlsSymbols(module)
{
    if (Process.arch !== 'x64') return null;
    if (adapterOptions.rustls_profile) return rustlsProfile(module, adapterOptions.rustls_profile);
    const identity = {};
    const pdb = publicSymbolFile(module, adapterOptions.rustls_symbols || null, identity);
    if (pdb === null) return null;
    const directory = Memory.alloc(65536);
    const systemDirectory = systemApi('kernel32.dll', 'GetSystemDirectoryW', 'uint', ['pointer', 'uint']);
    if (!systemDirectory(directory, 32768)) return null;
    const library = Module.load(directory.readUtf16String() + '\\dbghelp.dll');
    function api(name, result, arguments_)
    {
        return new NativeFunction(library.getExportByName(name), result, arguments_, { scheduling: 'exclusive' });
    }
    const initialize = api('SymInitializeW', 'int', ['pointer', 'pointer', 'int']);
    const cleanup = api('SymCleanup', 'int', ['pointer']);
    const load = api('SymLoadModuleExW', 'uint64', ['pointer', 'pointer', 'pointer', 'pointer',
        'uint64', 'uint', 'pointer', 'uint']);
    const find = api('SymGetTypeFromName', 'int', ['pointer', 'uint64', 'pointer', 'pointer']);
    const query = api('SymGetTypeInfo', 'int', ['pointer', 'uint64', 'uint', 'int', 'pointer']);
    const enumerate = api('SymEnumSymbols', 'int', ['pointer', 'uint64', 'pointer', 'pointer', 'pointer']);
    const free = systemApi('kernel32.dll', 'LocalFree', 'pointer', ['pointer']);
    const context = Memory.alloc(8), base = uint64(module.base.toString());
    const folder = pdb.slice(0, pdb.lastIndexOf('\\') + 1);
    if (!initialize(context, Memory.allocUtf16String(folder), 0)) return null;
    let alive = true;
    function close()
    {
        if (alive) cleanup(context);
        alive = false;
    }
    try
    {
        if (load(context, zero, Memory.allocUtf16String(pdb), zero, base, module.size, zero, 0)
            .compare(uint64(0)) === 0)
        {
            close();
            return null;
        }
        const types = new Map(), names = new Map(), arguments_ = new Map();
        function info(index, request)
        {
            const output = Memory.alloc(32);
            if (!query(context, base, index, request, output)) return null;
            if (request === 1)
            {
                const value = output.readPointer();
                if (value.isNull()) return '';
                try { return publicWideString(value, 8192); }
                finally { free(value); }
            }
            if (request === 11)
            {
                const kind = output.readU16();
                if ([2, 3, 16, 17, 18, 19, 20, 21, 22, 23].includes(kind))
                {
                    const signed = [2, 3, 16, 20, 22].includes(kind);
                    const size = [16, 17].includes(kind) ? 1 : [2, 18].includes(kind) ? 2 :
                        [20, 21].includes(kind) ? 8 : 4;
                    const value = output.add(8);
                    return BigInt(signed ? size === 8 ? value.readS64().toString() : size === 4 ? value.readS32() :
                        size === 2 ? value.readS16() : value.readS8() : size === 8 ? value.readU64().toString() :
                        size === 4 ? value.readU32() : size === 2 ? value.readU16() : value.readU8());
                }
                return null;
            }
            return request === 2 ? output.readU64().toNumber() : output.readU32();
        }
        function type(index)
        {
            if (!types.has(index))
            {
                if (types.size >= 8192) throw new Error('Rustls symbol types exceed their bound.');
                const result = { id: index, name: info(index, 1) || '', tag: info(index, 0), size: info(index, 2) };
                if (!result.tag || result.size > 1048576) throw new Error('Rustls symbol type is invalid.');
                types.set(index, result);
            }
            return types.get(index);
        }
        function named(name)
        {
            if (!names.has(name))
            {
                const symbol = Memory.alloc(88 + 8192);
                symbol.writeU32(88);
                symbol.add(80).writeU32(8192);
                names.set(name, find(context, base, Memory.allocUtf8String(name), symbol) ?
                    type(symbol.add(4).readU32()) : null);
            }
            return names.get(name);
        }
        function fields(value)
        {
            if (value.fields) return value.fields;
            const count = info(value.id, 13) || 0, result = new Map();
            if (count > 2048) throw new Error('Rustls symbol fields exceed their bound.');
            if (count)
            {
                const children = Memory.alloc(8 + count * 4);
                children.writeU32(count);
                children.add(4).writeU32(0);
                if (!query(context, base, value.id, 7, children))
                    throw new Error('Rustls type fields are unavailable.');
                for (let index = 0; index < count; ++index)
                {
                    const child = children.add(8 + index * 4).readU32();
                    if (info(child, 0) !== 7) continue;
                    const name = info(child, 1), kind = info(child, 8);
                    const field = { id: child, kind, offset: info(child, 10), type: type(info(child, 4)) };
                    if (kind === 7 && (field.offset === null || field.offset + field.type.size > value.size))
                        throw new Error('Rustls symbol field is outside its structure.');
                    if ([8, 9].includes(kind)) field.constant = info(child, 11);
                    result.set(name, field);
                }
            }
            value.fields = result;
            return result;
        }
        function firstArgument(symbol)
        {
            if (arguments_.has(symbol.type)) return arguments_.get(symbol.type);
            const count = info(symbol.type, 13) || 0;
            if (!count || count > 16) return null;
            const children = Memory.alloc(8 + count * 4);
            children.writeU32(count);
            children.add(4).writeU32(0);
            if (!query(context, base, symbol.type, 7, children)) return null;
            const first = children.add(8).readU32();
            const result = info(first, 0) === 20 ? type(info(first, 4)) : null;
            arguments_.set(symbol.type, result);
            return result;
        }
        const common = named('rustls::common_state::CommonState');
        if (!common)
        {
            close();
            return null;
        }
        const moduleInfo = Memory.alloc(3264);
        moduleInfo.writeU32(3264);
        const describe = api('SymGetModuleInfoW64', 'int', ['pointer', 'uint64', 'pointer']);
        if (!describe(context, base, moduleInfo) || !moduleInfo.add(3240).readU32() ||
            moduleInfo.add(3220).readU32() !== identity.age ||
            new Uint8Array(moduleInfo.add(3204).readByteArray(16)).some((value, index) =>
                value !== identity.signature[index]) ||
            publicWideString(moduleInfo.add(1124), 256).toLowerCase() !== pdb.toLowerCase())
            throw new Error('Rustls requires symbols matching the executable build.');
        const symbols = [];
        const callback = new NativeCallback((entry) =>
        {
            const length = entry.add(76).readU32();
            if (length > 8192 || symbols.length >= 8192) return 1;
            const address = entry.add(56).readPointer();
            if (address.compare(module.base) < 0 || address.compare(module.base.add(module.size)) >= 0) return 1;
            symbols.push({ name: entry.add(84).readUtf8String(length), address,
                type: entry.add(4).readU32(), tag: entry.add(72).readU32() });
            return 1;
        }, 'int', ['pointer', 'uint', 'pointer']);
        for (const pattern of ['rustls::*', 'tokio_rustls::common::Stream<*',
            'quinn_proto::crypto::rustls::impl$*', 'quinn::connection::State::terminate',
            'quinn::connection::impl$*::poll', '*SupportedKxGroup*'])
            enumerate(context, base, Memory.allocUtf8String(pattern), callback, zero);
        function profile()
        {
            // Freeze the complete reachable layout graph before any application handshake executes.
            const entries = [], namedTypes = [], foundSymbols = [];
            let fieldCount = 0, encodedBytes = 1024;
            function append(collection, value)
            {
                for (const character of JSON.stringify(value))
                {
                    const point = character.codePointAt(0);
                    encodedBytes += point < 128 ? 1 : point < 2048 ? 2 : point < 65536 ? 3 : 4;
                }
                if (encodedBytes > 16 * 1024 * 1024)
                    throw new Error('Rustls observation profile exceeds its size bound.');
                collection.push(value);
            }
            for (const value of types.values())
            {
                fieldCount += fields(value).size;
                if (fieldCount > 131072) throw new Error('Rustls observation profile fields exceed their bound.');
                const members = [...fields(value)].map(([name, field]) => ({ name, kind: field.kind,
                    offset: field.offset, type: field.type.id,
                    ...(field.constant !== undefined && field.constant !== null ?
                        { constant: field.constant.toString() } : {}) }));
                const target = value.tag === 14 ? type(info(value.id, 4)).id : null;
                append(entries, { id: value.id, name: value.name, tag: value.tag, size: value.size, target,
                    fields: members });
            }
            if (names.size > 8192) throw new Error('Rustls observation profile names exceed their bound.');
            for (const [name, value] of names) append(namedTypes, [name, value?.id ?? null]);
            for (const value of symbols)
                append(foundSymbols, { name: value.name, rva: value.address.sub(module.base).toUInt32(),
                    type: value.type, tag: value.tag, argument: arguments_.get(value.type)?.id ?? null });
            return { schema: 'cipherazzi.rustls-profile/1', architecture: Process.arch,
                image_sha256: rustlsImageHash(module), image_size: module.size, common: common.id,
                types: entries, names: namedTypes, symbols: foundSymbols };
        }
        Script.bindWeak(context, close);
        return { common, type, named, fields, firstArgument, info, symbols, close, profile };
    }
    catch (error)
    {
        close();
        throw error;
    }
}

function installRustls(module)
{
    const symbols = rustlsSymbols(module);
    if (symbols === null) return false;
    const listeners = [], states = new Map(), active = new Map(), socketsByHandle = new Map(), hooked = new Set();
    const quinnSessions = new Map(), quinnDrivers = new Map();
    let boundaries = 0;
    libraries.set(module.path, listeners);
    listeners.push({ detach() { symbols.close(); } });
    function member(value, name)
    {
        const field = symbols.fields(value.type).get(name);
        if (!field || field.kind !== 7) throw new Error('Required rustls metadata field is unavailable.');
        return { type: field.type, address: value.address.add(field.offset) };
    }
    function integer(value)
    {
        const { address, type } = value;
        if (![1, 2, 4, 8].includes(type.size)) throw new Error('Rustls scalar size is unsupported.');
        return BigInt(type.size === 1 ? address.readU8() : type.size === 2 ? address.readU16() :
            type.size === 4 ? address.readU32() : address.readU64().toString());
    }
    function variant(value)
    {
        const fields = symbols.fields(value.type);
        if (value.type.tag === 12)
        {
            const tag = integer(value);
            for (const [name, field] of fields)
                if (field.constant === tag) return { name, value };
            return null;
        }
        if (!value.type.variants)
        {
            value.type.variants = [...fields].filter(([name]) => /^variant\d+$/.test(name)).map(([, field]) =>
            {
                const members = symbols.fields(field.type), data = members.get('value');
                if (!data) throw new Error('Rustls enum value metadata is unavailable.');
                return { exact: members.get('DISCR_EXACT')?.constant,
                    begin: members.get('DISCR_BEGIN')?.constant, end: members.get('DISCR_END')?.constant,
                    name: data.type.name.split('::').at(-1), type: data.type, offset: field.offset + data.offset };
            });
        }
        const tag = integer(member(value, 'tag'));
        const matches = value.type.variants.filter(item => item.exact === tag ||
            (item.begin !== undefined && item.end !== undefined && (item.begin <= item.end ?
                tag >= item.begin && tag <= item.end : tag >= item.begin || tag <= item.end)));
        if (matches.length !== 1) return null;
        const selected = matches[0];
        return { name: selected.name, value: { type: selected.type, address: value.address.add(selected.offset) } };
    }
    function optional(value)
    {
        const selected = variant(value);
        return selected?.name === 'Some' ? member(selected.value, '__0') : null;
    }
    function dereference(value)
    {
        if (value.type.tag !== 14) throw new Error('Rustls metadata pointer is unsupported.');
        const address = value.address.readPointer();
        if (address.isNull()) throw new Error('Rustls metadata pointer is absent.');
        return { type: symbols.type(symbols.info(value.type.id, 4)), address };
    }
    function connectionState(value)
    {
        for (let depth = 0; depth < 8; ++depth)
        {
            if (value.type.name === symbols.common.name) return value.address;
            if (value.type.tag === 14) value = dereference(value);
            else
            {
                const fields = symbols.fields(value.type);
                if (/^enum2\$<rustls::quic::(connection::)?Connection>$/.test(value.type.name))
                {
                    const selected = variant(value);
                    if (!selected || !['Client', 'Server'].includes(selected.name)) break;
                    value = member(selected.value, '__0');
                    continue;
                }
                const name = ['common_state', 'core', 'inner', 'session'].find(name => fields.has(name));
                if (!name) break;
                value = member(value, name);
            }
        }
        throw new Error('Rustls connection layout is unsupported.');
    }
    function quinnConnection(value)
    {
        const connection = member(value, 'inner');
        const crypto = member(connection, 'crypto');
        const current = quinnSessions.get(member(crypto, 'pointer').address.readPointer().toString());
        if (!current || nowUs() - current.touched > 120000000) return null;
        const remote = variant(member(member(connection, 'path'), 'remote'));
        if (!remote || !['V4', 'V6'].includes(remote.name)) return null;
        const address = member(remote.value, '__0'), port = Number(integer(member(address, 'port')));
        const octets = member(member(address, 'ip'), 'octets');
        if (octets.type.size !== (remote.name === 'V4' ? 4 : 16) || !port || port > 65535) return null;
        const data = new Uint8Array(octets.address.readByteArray(octets.type.size));
        const text = remote.name === 'V4' ? Array.from(data).join('.') :
            Array.from({ length: 8 }, (_, index) => (data[index * 2] * 256 + data[index * 2 + 1])
                .toString(16)).join(':');
        current.quicRemote = { address: text, port };
        return current;
    }
    function vector(value, maximum)
    {
        const length = integer(member(value, 'len'));
        if (length > BigInt(maximum)) throw new Error('Rustls public vector exceeds its bound.');
        let buffer = member(value, 'buf');
        for (let depth = 0; depth < 8 && buffer.type.tag !== 14; ++depth)
        {
            const fields = symbols.fields(buffer.type);
            const name = ['inner', 'ptr', 'pointer'].find(name => fields.has(name));
            if (!name) throw new Error('Rustls public vector layout is unsupported.');
            buffer = member(buffer, name);
        }
        if (buffer.type.tag !== 14) throw new Error('Rustls public vector pointer is unavailable.');
        return { address: buffer.address.readPointer(), length: Number(length) };
    }
    function bytes(value, maximum)
    {
        for (let depth = 0; depth < 12; ++depth)
        {
            if (value.type.name.startsWith('alloc::vec::Vec<')) return vector(value, maximum);
            const fields = symbols.fields(value.type);
            if (fields.has('data_ptr') && fields.has('length'))
            {
                const length = integer(member(value, 'length'));
                if (length > BigInt(maximum)) throw new Error('Rustls public byte slice exceeds its bound.');
                return { address: member(value, 'data_ptr').address.readPointer(), length: Number(length) };
            }
            if (fields.has('tag'))
            {
                const selected = variant(value);
                if (!selected || !['Borrowed', 'Owned'].includes(selected.name))
                    throw new Error('Rustls public byte storage is unsupported.');
                value = member(selected.value, '__0');
            }
            else value = member(value, '__0');
        }
        throw new Error('Rustls public byte storage exceeds its nesting bound.');
    }
    const versions = { TLSv1_0: 769, TLSv1_1: 770, TLSv1_2: 771, TLSv1_3: 772,
        DTLSv1_0: 65279, DTLSv1_2: 65277, DTLSv1_3: 65276 };
    const groupsByVtable = new Map();
    for (const symbol of symbols.symbols)
    {
        const match = /^impl\$<(.+), rustls::crypto::SupportedKxGroup>::vtable\$$/.exec(symbol.name);
        if (!match) continue;
        const type = symbols.named(match[1]);
        if (type && symbols.fields(type).has('name')) groupsByVtable.set(symbol.address.toString(), type);
    }
    const certificateType = symbols.named('rustls_pki_types::CertificateDer');
    const createCertificate = systemApi('crypt32.dll', 'CertCreateCertificateContext', 'pointer',
        ['uint', 'pointer', 'uint']);
    const freeCertificate = systemApi('crypt32.dll', 'CertFreeCertificateContext', 'int', ['pointer']);
    function state(address, started = false)
    {
        const key = address.toString();
        let value = states.get(key);
        const view = { type: symbols.common, address };
        const complete = integer(member(view, 'may_send_application_data')) &&
            integer(member(view, 'may_receive_application_data'));
        const reused = value?.emitted && started && !complete;
        if (!value || reused || nowUs() - value.touched > 120000000)
        {
            if (states.size >= 4096) states.delete(states.keys().next().value);
            value = { address, touched: nowUs(), started: started && !complete ? nowUs() : 0, emitted: false };
            states.set(key, value);
        }
        value.touched = nowUs();
        return value;
    }
    function emit(current, success)
    {
        if (current.emitted || (!success && !current.started)) return;
        const connection = { type: symbols.common, address: current.address };
        const role = variant(member(connection, 'side'))?.name;
        if (role !== 'Client' && role !== 'Server') return;
        const report = { schema: 'cipherazzi.endpoint/1', provider: 'Rust/rustls', pid: Process.id,
            timestamp_us: nowUs(), role: role.toLowerCase(), success,
            transport: variant(member(connection, 'protocol'))?.name === 'Quic' ? 'QUIC' : 'TCP' };
        if (current.started) report.handshake_started_us = current.started;
        else report.observation = 'connection';
        if (current.endpoints) Object.assign(report, current.endpoints);
        if (current.verification !== undefined) report.peer_verified = current.verification;
        const version = optional(member(connection, 'negotiated_version'));
        if (version && versions[variant(version)?.name]) report.tls_version = versions[variant(version).name];
        const suite = optional(member(connection, 'suite'));
        if (suite)
        {
            const selected = variant(suite);
            if (selected && ['Tls12', 'Tls13'].includes(selected.name))
            {
                const common = member(dereference(member(selected.value, '__0')), 'common');
                const name = variant(member(common, 'suite'))?.name?.replace(/^TLS13_/, 'TLS_');
                if (adapterOptions.cipher_suites[name]) report.cipher_id = adapterOptions.cipher_suites[name];
            }
        }
        if (success && (!report.tls_version || !report.cipher_id))
            throw new Error('Rustls negotiated parameters could not be resolved.');
        const group = variant(member(connection, 'kx_state'));
        if (group?.name === 'Complete')
        {
            const dynamic = member(group.value, '__0'), fields = symbols.fields(dynamic.type);
            if (fields.has('data_ptr') && fields.has('vtable'))
            {
                const data = member(dynamic, 'data_ptr').address.readPointer();
                const table = member(dynamic, 'vtable').address.readPointer();
                const type = groupsByVtable.get(table.toString());
                if (type)
                {
                    const name = variant(member({ address: data, type }, 'name'))?.name;
                    const identifier = groupIds.get(name?.toLowerCase());
                    if (identifier) report.group_id = identifier;
                }
            }
        }
        const protocol = optional(member(connection, 'alpn_protocol'));
        if (protocol)
        {
            const data = bytes(protocol, 255);
            if (data.length) report.selected_alpn = data.address.readUtf8String(data.length);
        }
        if (success)
        {
            const kind = optional(member(connection, 'handshake_kind'));
            if (kind) report.session_resumed = variant(kind)?.name === 'Resumed';
        }
        else report.error_name = 'TLS_HANDSHAKE_FAILED';
        const chain = optional(member(connection, 'peer_certificates')), certificates = [];
        let total = 0;
        if (chain && certificateType)
        {
            const list = vector(member(chain, '__0'), 16);
            for (let index = 0; index < list.length; ++index)
            {
                const data = bytes({ type: certificateType,
                    address: list.address.add(index * certificateType.size) }, 262144);
                total += data.length;
                if (total > 1048576) throw new Error('Rustls public certificates exceed their bound.');
                const certificate = createCertificate(1, data.address, data.length);
                if (certificate.isNull()) continue;
                freeCertificate(certificate);
                certificates.push(base64(new Uint8Array(data.address.readByteArray(data.length))));
            }
        }
        report[role === 'Client' ? 'server_certificates_der' : 'client_certificates_der'] = certificates;
        current.emitted = true;
        send({ kind: 'report', report });
    }
    function guarded(invocation, operation)
    {
        const error = invocation.lastError;
        try { operation(); }
        catch (_)
        {
            warn(module.path + ':rustls-query',
                'Some rustls metadata could not be read from its observation layout.', true);
        }
        finally { invocation.lastError = error; }
    }
    function hook(symbol, callbacks)
    {
        if (hooked.has(symbol.address.toString())) return;
        hooked.add(symbol.address.toString());
        listeners.push(Interceptor.attach(symbol.address, callbacks));
    }
    for (const symbol of symbols.symbols.filter(value => value.tag === 5))
    {
        const tokio = /^tokio_rustls::common::Stream<.+>::handshake</.test(symbol.name);
        const quic = /^rustls::quic::(connection::)?ConnectionCommon<.+>::(read_hs|write_hs)(<|$)/.test(symbol.name);
        const quinn = /^quinn_proto::crypto::rustls::impl\$\d+::(read_handshake|write_handshake)$/.test(symbol.name);
        if (tokio || quic || quinn ||
            /^rustls::conn::Connection(Common|Core)<.+>::(read_tls|write_tls|complete_io|process_new_packets)(<|$)/
                .test(symbol.name))
        {
            const type = symbols.named(quinn ? 'quinn_proto::crypto::rustls::TlsSession' :
                symbol.name.slice(0, symbol.name.indexOf('>::') + 1));
            if (!type) continue;
            const indirectResult = tokio || quic || quinn ||
                /::(complete_io|process_new_packets)(<|$)/.test(symbol.name);
            ++boundaries;
            hook(symbol, {
                onEnter(args)
                {
                    guarded(this, () =>
                    {
                        this.current = state(connectionState({ type, address: args[indirectResult ? 1 : 0] }), true);
                        if (quinn)
                        {
                            if (quinnSessions.size >= 4096) quinnSessions.delete(quinnSessions.keys().next().value);
                            quinnSessions.set(args[1].toString(), this.current);
                        }
                        const stack = active.get(this.threadId) || [];
                        stack.push(this.current);
                        active.set(this.threadId, stack);
                    });
                },
                onLeave()
                {
                    if (!this.current) return;
                    active.get(this.threadId)?.pop();
                    guarded(this, () =>
                    {
                        const value = { type: symbols.common, address: this.current.address };
                        if ((this.current.started || this.current.endpoints) &&
                            integer(member(value, 'may_send_application_data')) &&
                            integer(member(value, 'may_receive_application_data'))) emit(this.current, true);
                        else if ((quic || quinn) && optional(member(member(value, 'quic'), 'alert')))
                            emit(this.current, false);
                    });
                }
            });
        }
        else if (symbol.name === 'rustls::common_state::CommonState::start_traffic')
            hook(symbol, {
                onEnter(args) { this.current = state(args[0]); },
                onLeave() { guarded(this, () => emit(this.current, true)); }
            });
        else if (symbol.name.startsWith('rustls::common_state::CommonState::send_fatal_alert<') ||
            symbol.name === 'rustls::common_state::CommonState::send_cert_verify_error_alert')
            hook(symbol, {
                onEnter(args)
                {
                    this.current = state(args[1]);
                    if (symbol.name.endsWith('::send_cert_verify_error_alert')) this.current.verification = false;
                },
                onLeave() { guarded(this, () => emit(this.current, false)); }
            });
        else if (/^quinn::connection::impl\$\d+::poll$/.test(symbol.name) &&
            symbols.firstArgument(symbol)?.name ===
                'core::pin::Pin<ref_mut$<quinn::connection::ConnectionDriver> >')
        {
            const type = symbols.named('quinn::connection::ConnectionDriver');
            if (!type) continue;
            hook(symbol, {
                onEnter(args)
                {
                    const stack = quinnDrivers.get(this.threadId) || [];
                    stack.push({ type, address: args[0] });
                    quinnDrivers.set(this.threadId, stack);
                },
                onLeave()
                {
                    const stack = quinnDrivers.get(this.threadId);
                    stack?.pop();
                    if (!stack?.length) quinnDrivers.delete(this.threadId);
                }
            });
        }
        else if (symbol.name === 'quinn::connection::State::terminate')
        {
            const type = symbols.named('quinn::connection::State');
            if (!type) continue;
            hook(symbol, {
                onEnter(args)
                {
                    guarded(this, () =>
                    {
                        this.value = { type, address: args[0] };
                        this.current = quinnConnection(this.value);
                    });
                },
                onLeave()
                {
                    if (!this.current) return;
                    guarded(this, () =>
                    {
                        const error = optional(member(this.value, 'error'));
                        const selected = error && variant(error);
                        if (selected?.name !== 'ConnectionClosed') return;
                        const code = integer(member(member(member(selected.value, '__0'), 'error_code'), '__0'));
                        if (code >= 256n && code <= 511n) emit(this.current, false);
                    });
                }
            });
        }
    }
    if (!boundaries) throw new Error('Rustls handshake symbols are unavailable.');
    if (adapterOptions.rustls_profile_export)
    {
        if (!symbols.profile) throw new Error('Rustls profiles must be generated from matching symbols.');
        send({ kind: 'rustls-profile', profile: symbols.profile() });
    }
    const sockets = Process.attachModuleObserver({ onAdded(loaded)
    {
        if (!['ws2_32.dll', 'mswsock.dll'].includes(loaded.name.toLowerCase())) return;
        for (const name of ['send', 'recv', 'WSASend', 'WSARecv', 'WSASendMsg'])
        {
            const address = loaded.findExportByName(name);
            if (address === null) continue;
            listeners.push(Interceptor.attach(address, { onEnter(args)
            {
                guarded(this, () =>
                {
                    let current = active.get(this.threadId)?.at(-1);
                    let driver = name === 'WSASendMsg' ? quinnDrivers.get(this.threadId)?.at(-1) : null;
                    if (!current && driver)
                    {
                        // Read the connection while Quinn holds its state lock around the socket operation.
                        for (let depth = 0; depth < 16 && driver.type.name !== 'quinn::connection::State'; ++depth)
                        {
                            if (driver.type.tag === 14) driver = dereference(driver);
                            else
                            {
                                const fields = symbols.fields(driver.type);
                                const field = ['conn', '__0', 'ptr', 'pointer', 'data', 'state', 'inner', 'value']
                                    .find(field => fields.has(field));
                                if (!field) throw new Error('Quinn connection metadata is unavailable.');
                                driver = member(driver, field);
                            }
                        }
                        if (driver.type.name === 'quinn::connection::State') current = quinnConnection(driver);
                    }
                    if (!current || current.emitted || current.ambiguous) return;
                    if (current.socket && !current.socket.equals(args[0]))
                    {
                        current.ambiguous = true;
                        delete current.endpoints;
                        return;
                    }
                    current.socket = args[0];
                    current.endpoints = socketEndpoints(args[0], null, current.quicRemote);
                    if (current.quicRemote)
                    {
                        if (current.endpoints &&
                            ['0.0.0.0', '0:0:0:0:0:0:0:0'].includes(current.endpoints.local.address))
                            delete current.endpoints;
                        return;
                    }
                    const key = args[0].toString(), previous = socketsByHandle.get(key);
                    if (previous && previous !== current && nowUs() - previous.touched <= 120000000)
                    {
                        current.started = previous.started;
                        current.emitted = previous.emitted;
                    }
                    if (socketsByHandle.size >= 4096 && !socketsByHandle.has(key))
                        socketsByHandle.delete(socketsByHandle.keys().next().value);
                    socketsByHandle.set(key, current);
                });
            } }));
        }
        const close = loaded.findExportByName('closesocket');
        if (close !== null) listeners.push(Interceptor.attach(close, {
            onEnter(args) { socketsByHandle.delete(args[0].toString()); }
        }));
    } });
    listeners.push(sockets);
    flushOnExit(listeners);
    send({ kind: 'adapter', provider: 'Rust/rustls', module: module.name });
    return true;
}
