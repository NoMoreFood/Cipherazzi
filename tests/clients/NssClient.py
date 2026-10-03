import argparse
import ctypes as c
import os
import socket
import time
from pathlib import Path


class Item(c.Structure):
    _fields_ = [('type', c.c_uint), ('data', c.c_void_p), ('length', c.c_uint)]


class Trust(c.Structure):
    _fields_ = [('ssl', c.c_uint), ('email', c.c_uint), ('signing', c.c_uint)]


class Versions(c.Structure):
    _fields_ = [('minimum', c.c_uint16), ('maximum', c.c_uint16)]


class IoMethods(c.Structure):
    _fields_ = [('file_type', c.c_int)] + [(name, c.c_void_p) for name in (
        'close read write available available64 fsync seek seek64 fileInfo fileInfo64 writev connect accept bind '
        'listen shutdown recv send recvfrom sendto poll acceptread transmitfile getsockname getpeername '
        'reserved_fn_6 reserved_fn_5 getsocketoption setsocketoption sendfile connectcontinue '
        'reserved_fn_3 reserved_fn_2 reserved_fn_1 reserved_fn_0').split()]


class FileDesc(c.Structure):
    _fields_ = [(name, c.c_void_p) for name in ('methods', 'secret', 'lower', 'higher', 'dtor')] + \
        [('identity', c.c_int)]


class SocketOptionValue(c.Union):
    _fields_ = [('non_blocking', c.c_int), ('no_delay', c.c_int), ('size', c.c_size_t), ('storage', c.c_ubyte * 256)]


class SocketOption(c.Structure):
    _fields_ = [('option', c.c_int), ('value', SocketOptionValue)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--certificate', required=True)
    parser.add_argument('--version', type=int, default=772)
    parser.add_argument('--hostname', default='adapter.lab')
    parser.add_argument('--gate')
    parser.add_argument('--custom-io', action='store_true')
    args = parser.parse_args()
    directory = Path(args.library).resolve()
    search = os.add_dll_directory(str(directory))
    nss = c.CDLL(str(directory / 'nss3.dll'))
    nspr = c.CDLL(str(directory / 'nspr4.dll')) if (directory / 'nspr4.dll').exists() else nss
    ssl = c.CDLL(str(directory / 'ssl3.dll')) if (directory / 'ssl3.dll').exists() else nss
    if args.gate:
        gate = Path(args.gate)
        Path(str(gate) + '.ready').write_text('Libraries loaded')
        deadline = time.monotonic() + 25
        while not gate.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert gate.exists(), 'Library client was not released'

    def api(library, name, result, *arguments):
        function = getattr(library, name)
        function.restype, function.argtypes = result, list(arguments)
        return function

    get_error = api(nspr, 'PR_GetError', c.c_int)

    def require(result):
        if result != 0:
            raise RuntimeError(f'NSS operation failed: {get_error()}')

    require(api(nss, 'NSS_NoDB_Init', c.c_int, c.c_char_p)(None))
    database = api(nss, 'CERT_GetDefaultCertDB', c.c_void_p)()
    der = c.create_string_buffer(Path(args.certificate).read_bytes())
    item = Item(0, c.cast(der, c.c_void_p), len(der) - 1)
    certificate = api(nss, 'CERT_NewTempCertificate', c.c_void_p, c.c_void_p, c.POINTER(Item),
        c.c_char_p, c.c_int, c.c_int)(database, c.byref(item), b'adapter fixture', 0, 1)
    assert certificate, 'NSS certificate import failed'
    trust = Trust()
    require(api(nss, 'CERT_DecodeTrustString', c.c_int, c.POINTER(Trust), c.c_char_p)(c.byref(trust), b'CT,,'))
    require(api(nss, 'CERT_ChangeCertTrust', c.c_int, c.c_void_p, c.c_void_p,
        c.POINTER(Trust))(database, certificate, c.byref(trust)))
    transport = None
    if args.custom_io:
        transport = socket.create_connection(('127.0.0.1', args.port), timeout=20)
        methods = IoMethods.from_buffer_copy(api(nspr, 'PR_GetDefaultIOMethods', c.POINTER(IoMethods))().contents)
        set_error = api(nspr, 'PR_SetError', None, c.c_int, c.c_int)

        @c.CFUNCTYPE(c.c_int, c.c_void_p)
        def close(descriptor):
            transport.close()
            destructor = c.cast(descriptor, c.POINTER(FileDesc)).contents.dtor
            c.CFUNCTYPE(None, c.c_void_p)(destructor)(descriptor)
            return 0

        @c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_int, c.c_int, c.c_uint)
        def receive(_, buffer, amount, flags, timeout):
            try:
                assert flags in (0, 2)
                data = transport.recv(amount, socket.MSG_PEEK if flags == 2 else 0)
                c.memmove(buffer, data, len(data))
                return len(data)
            except Exception:
                set_error(-5991, 0)
                return -1

        @c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_int, c.c_int, c.c_uint)
        def send(_, buffer, amount, flags, timeout):
            try:
                assert flags == 0
                transport.sendall(c.string_at(buffer, amount))
                return amount
            except Exception:
                set_error(-5991, 0)
                return -1

        @c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_int)
        def read(descriptor, buffer, amount):
            return receive(descriptor, buffer, amount, 0, 0)

        @c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_int)
        def write(descriptor, buffer, amount):
            return send(descriptor, buffer, amount, 0, 0)

        @c.CFUNCTYPE(c.c_int, c.c_void_p, c.POINTER(SocketOption))
        def get_option(_, option):
            if option.contents.option != 0:
                set_error(-5996, 0)
                return -1
            option.contents.value.non_blocking = 0
            return 0

        @c.CFUNCTYPE(c.c_int, c.c_void_p, c.POINTER(SocketOption))
        def set_option(_, option):
            if option.contents.option == 13:
                transport.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, option.contents.value.no_delay)
                return 0
            set_error(-5996, 0)
            return -1

        @c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p)
        def peer(_, address):
            result = api(nspr, 'PR_StringToNetAddr', c.c_int, c.c_char_p, c.c_void_p)(b'127.0.0.1', address)
            if result == 0:
                c.c_uint16.from_address(address + 2).value = socket.htons(args.port)
            return result

        for name, callback in [('close', close), ('recv', receive), ('send', send), ('read', read),
            ('write', write), ('getsocketoption', get_option), ('setsocketoption', set_option), ('getpeername', peer)]:
            setattr(methods, name, c.cast(callback, c.c_void_p).value)
        identity = api(nspr, 'PR_GetUniqueIdentity', c.c_int, c.c_char_p)(b'Cipherazzi custom I/O fixture')
        raw = api(nspr, 'PR_CreateIOLayerStub', c.c_void_p, c.c_int, c.POINTER(IoMethods))(identity, c.byref(methods))
        assert raw and api(nspr, 'PR_FileDesc2NativeHandle', c.c_int, c.c_void_p)(raw) == -1
    else:
        raw = api(nspr, 'PR_NewTCPSocket', c.c_void_p)()
    descriptor = api(ssl, 'SSL_ImportFD', c.c_void_p, c.c_void_p, c.c_void_p)(None, raw)
    assert descriptor, 'NSS SSL socket import failed'
    try:
        require(api(ssl, 'SSL_OptionSet', c.c_int, c.c_void_p, c.c_int, c.c_int)(descriptor, 5, 1))
        versions = Versions(args.version, args.version)
        require(api(ssl, 'SSL_VersionRangeSet', c.c_int, c.c_void_p, c.POINTER(Versions))(
            descriptor, c.byref(versions)))
        require(api(ssl, 'SSL_SetURL', c.c_int, c.c_void_p, c.c_char_p)(descriptor, args.hostname.encode()))
        peer_certificate = api(ssl, 'SSL_PeerCertificate', c.c_void_p, c.c_void_p)
        destroy_certificate = api(nss, 'CERT_DestroyCertificate', None, c.c_void_p)
        get_der = api(nss, 'CERT_GetCertificateDer', c.c_int, c.c_void_p, c.POINTER(Item))
        set_error = api(nspr, 'PR_SetError', None, c.c_int, c.c_int)

        @c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_int, c.c_int)
        def verifier(_, descriptor, check_signature, is_server):
            peer = peer_certificate(descriptor)
            if not peer:
                return -1
            try:
                # Authenticate the fixture's pinned public certificate and its configured host identity.
                received = Item()
                if get_der(peer, c.byref(received)) == 0 and check_signature and not is_server and \
                    args.hostname == 'adapter.lab' and c.string_at(received.data, received.length) == der.raw[:-1]:
                    return 0
                set_error(-12276, 0)
                return -1
            finally:
                destroy_certificate(peer)

        require(api(ssl, 'SSL_AuthCertificateHook', c.c_int, c.c_void_p, c.c_void_p, c.c_void_p)(
            descriptor, c.cast(verifier, c.c_void_p), database))
        protocols = b'\x02h2\x08http/1.1'
        require(api(ssl, 'SSL_SetNextProtoNego', c.c_int, c.c_void_p, c.c_char_p, c.c_uint)(
            descriptor, protocols, len(protocols)))
        address = c.create_string_buffer(128)
        require(api(nspr, 'PR_StringToNetAddr', c.c_int, c.c_char_p, c.c_void_p)(b'127.0.0.1', address))
        address[2:4] = args.port.to_bytes(2, 'big')
        interval = api(nspr, 'PR_MillisecondsToInterval', c.c_uint, c.c_uint)(20000)
        if not args.custom_io:
            require(api(nspr, 'PR_Connect', c.c_int, c.c_void_p, c.c_void_p, c.c_uint)(descriptor, address, interval))
        require(api(ssl, 'SSL_ResetHandshake', c.c_int, c.c_void_p, c.c_int)(descriptor, 0))
        require(api(ssl, 'SSL_ForceHandshake', c.c_int, c.c_void_p)(descriptor))
        payload = b'cipherazzi-private-application-data-sentinel'
        written = api(nspr, 'PR_Write', c.c_int, c.c_void_p, c.c_char_p, c.c_int)(descriptor, payload, len(payload))
        assert written == len(payload), 'NSS application write failed'
        reply = c.create_string_buffer(2)
        assert api(nspr, 'PR_Read', c.c_int, c.c_void_p, c.c_void_p, c.c_int)(descriptor, reply, 2) == 2
        assert reply.raw == b'ok', 'NSS application response changed'
        print('NSS authenticated handshake and application exchange passed.')
    finally:
        api(nspr, 'PR_Close', c.c_int, c.c_void_p)(descriptor)
        if transport:
            transport.close()
        api(nss, 'CERT_DestroyCertificate', None, c.c_void_p)(certificate)
        api(ssl, 'SSL_ClearSessionCache', None)()
        require(api(nss, 'NSS_Shutdown', c.c_int)())
        search.close()


if __name__ == '__main__':
    main()
