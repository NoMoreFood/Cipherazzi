import argparse
import base64
import ctypes as c
import os
import socket
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--certificate', required=True)
    parser.add_argument('--version', type=int, default=772)
    parser.add_argument('--hostname', default='adapter.lab')
    parser.add_argument('--provider', choices=('openssl', 'boringssl'), default='boringssl')
    parser.add_argument('--gate')
    parser.add_argument('--buffers', action='store_true')
    parser.add_argument('--memory-bio', action='store_true')
    parser.add_argument('--client-certificate')
    parser.add_argument('--client-key')
    args = parser.parse_args()
    directory = Path(args.library).resolve()
    search = os.add_dll_directory(str(directory))
    if args.provider == 'openssl':
        crypto, ssl = [c.CDLL(str(next(directory.glob(pattern)))) for pattern in
            ('libcrypto-*-x64.dll', 'libssl-*-x64.dll')]
    else:
        crypto, ssl = [c.CDLL(str(directory / name)) for name in ('crypto.dll', 'ssl.dll')]
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

    assert not args.buffers or args.provider == 'boringssl', 'Buffer TLS requires BoringSSL'
    method = api(ssl, 'TLS_with_buffers_method' if args.buffers else 'TLS_client_method', c.c_void_p)()
    context = api(ssl, 'SSL_CTX_new', c.c_void_p, c.c_void_p)(method)
    assert context, 'BoringSSL context creation failed'
    connection = None
    try:
        if args.buffers:
            expected = base64.b64decode(b''.join(Path(args.certificate).read_bytes().splitlines()[1:-1]))
            chain_of = api(ssl, 'SSL_get0_peer_certificates', c.c_void_p, c.c_void_p)
            count = api(crypto, 'OPENSSL_sk_num', c.c_size_t, c.c_void_p)
            item = api(crypto, 'OPENSSL_sk_value', c.c_void_p, c.c_void_p, c.c_size_t)
            data = api(crypto, 'CRYPTO_BUFFER_data', c.c_void_p, c.c_void_p)
            length = api(crypto, 'CRYPTO_BUFFER_len', c.c_size_t, c.c_void_p)

            @c.CFUNCTYPE(c.c_int, c.c_void_p, c.POINTER(c.c_uint8))
            def verify(connection, alert):
                chain = chain_of(connection)
                certificate = item(chain, 0) if chain and count(chain) else None
                if certificate and args.hostname == 'adapter.lab' and \
                    c.string_at(data(certificate), length(certificate)) == expected:
                    return 0
                alert[0] = 42
                return 1

            api(ssl, 'SSL_CTX_set_custom_verify', None, c.c_void_p, c.c_int, c.c_void_p)(
                context, 1, c.cast(verify, c.c_void_p))
        else:
            assert api(ssl, 'SSL_CTX_load_verify_locations', c.c_int, c.c_void_p, c.c_char_p, c.c_char_p)(
                context, str(Path(args.certificate).resolve()).encode(), None) == 1
            api(ssl, 'SSL_CTX_set_verify', None, c.c_void_p, c.c_int, c.c_void_p)(context, 1, None)
        for operation, command in (('SSL_CTX_set_min_proto_version', 123), ('SSL_CTX_set_max_proto_version', 124)):
            if hasattr(ssl, operation):
                result = api(ssl, operation, c.c_int, c.c_void_p, c.c_uint16)(context, args.version)
            else:
                result = api(ssl, 'SSL_CTX_ctrl', c.c_long, c.c_void_p, c.c_int, c.c_long, c.c_void_p)(
                    context, command, args.version, None)
            assert result == 1, 'TLS version configuration failed'
        connection = api(ssl, 'SSL_new', c.c_void_p, c.c_void_p)(context)
        assert connection, 'BoringSSL session creation failed'
        if args.client_certificate:
            assert api(ssl, 'SSL_use_certificate_file', c.c_int, c.c_void_p, c.c_char_p, c.c_int)(
                connection, str(Path(args.client_certificate).resolve()).encode(), 1) == 1
            assert api(ssl, 'SSL_use_PrivateKey_file', c.c_int, c.c_void_p, c.c_char_p, c.c_int)(
                connection, str(Path(args.client_key).resolve()).encode(), 1) == 1
        if hasattr(ssl, 'SSL_set_tlsext_host_name'):
            result = api(ssl, 'SSL_set_tlsext_host_name', c.c_int, c.c_void_p, c.c_char_p)(
                connection, args.hostname.encode())
        else:
            hostname = c.create_string_buffer(args.hostname.encode())
            result = api(ssl, 'SSL_ctrl', c.c_long, c.c_void_p, c.c_int, c.c_long, c.c_void_p)(
                connection, 55, 0, hostname)
        assert result == 1, 'Server name configuration failed'
        if not args.buffers:
            parameters = api(ssl, 'SSL_get0_param', c.c_void_p, c.c_void_p)(connection)
            assert api(crypto, 'X509_VERIFY_PARAM_set1_host', c.c_int, c.c_void_p, c.c_char_p, c.c_size_t)(
                parameters, args.hostname.encode(), len(args.hostname.encode())) == 1
        protocols = b'\x02h2\x08http/1.1'
        assert api(ssl, 'SSL_set_alpn_protos', c.c_int, c.c_void_p, c.c_char_p, c.c_uint)(
            connection, protocols, len(protocols)) == 0
        with socket.create_connection(('127.0.0.1', args.port), timeout=20) as transport:
            transport.settimeout(20 if args.memory_bio else None)
            error_of = api(ssl, 'SSL_get_error', c.c_int, c.c_void_p, c.c_int)
            if args.memory_bio:
                method = api(crypto, 'BIO_s_mem', c.c_void_p)()
                incoming = api(crypto, 'BIO_new', c.c_void_p, c.c_void_p)(method)
                outgoing = api(crypto, 'BIO_new', c.c_void_p, c.c_void_p)(method)
                assert incoming and outgoing, 'Memory BIO creation failed'
                api(ssl, 'SSL_set_bio', None, c.c_void_p, c.c_void_p, c.c_void_p)(connection, incoming, outgoing)
                bio_read = api(crypto, 'BIO_read', c.c_int, c.c_void_p, c.c_void_p, c.c_int)
                bio_write = api(crypto, 'BIO_write', c.c_int, c.c_void_p, c.c_char_p, c.c_int)
                bio_control = api(crypto, 'BIO_ctrl', c.c_long, c.c_void_p, c.c_int, c.c_long, c.c_void_p)

                def flush():
                    while bio_control(outgoing, 10, 0, None) > 0:
                        buffer = c.create_string_buffer(4096)
                        count = bio_read(outgoing, buffer, len(buffer))
                        assert count > 0, 'Ciphertext BIO read failed'
                        for offset in range(0, count, 311):
                            transport.sendall(buffer.raw[offset:min(count, offset + 311)])

                def invoke(operation, *arguments, shutdown=False):
                    for _ in range(4096):
                        result = operation(connection, *arguments)
                        error = 0 if result > 0 or shutdown and result == 0 else error_of(connection, result)
                        flush()
                        if result > 0:
                            return result
                        if shutdown and result == 0:
                            continue
                        if error not in (0, 2, 3):
                            raise RuntimeError(f'TLS memory BIO operation failed: {error}')
                        if error == 3:
                            continue
                        encrypted = transport.recv(499)
                        assert encrypted, 'The transport closed before TLS completed'
                        assert bio_write(incoming, encrypted, len(encrypted)) == len(encrypted)
                    raise RuntimeError('TLS memory BIO retry bound exceeded')
            else:
                assert api(ssl, 'SSL_set_fd', c.c_int, c.c_void_p, c.c_int)(connection, transport.fileno()) == 1

                def invoke(operation, *arguments, shutdown=False):
                    result = operation(connection, *arguments)
                    if shutdown and result == 0:
                        result = operation(connection, *arguments)
                    if result <= 0:
                        raise RuntimeError(f'TLS operation failed: {error_of(connection, result)}')
                    return result

            assert invoke(api(ssl, 'SSL_connect', c.c_int, c.c_void_p)) == 1
            payload = b'cipherazzi-private-application-data-sentinel'
            assert invoke(api(ssl, 'SSL_write', c.c_int, c.c_void_p, c.c_char_p, c.c_int),
                payload, len(payload)) == len(payload)
            if args.memory_bio:
                flush()
            reply = c.create_string_buffer(2)
            assert invoke(api(ssl, 'SSL_read', c.c_int, c.c_void_p, c.c_void_p, c.c_int), reply, 2) == 2
            assert reply.raw == b'ok', 'BoringSSL application response changed'
            assert invoke(api(ssl, 'SSL_shutdown', c.c_int, c.c_void_p), shutdown=True) == 1
            print('Authenticated handshake and application exchange passed.')
    finally:
        if connection:
            api(ssl, 'SSL_free', None, c.c_void_p)(connection)
        api(ssl, 'SSL_CTX_free', None, c.c_void_p)(context)
        search.close()


if __name__ == '__main__':
    main()
