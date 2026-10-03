import argparse
import base64
import ctypes as c
import json
import socket
import sqlite3
import ssl
import subprocess
import threading
from pathlib import Path

from FirefoxAdapter import trust_certificate


def socket_owner(local_port, remote_port):
    query = c.WinDLL('iphlpapi').GetExtendedTcpTable
    size = c.c_ulong()
    assert query(None, c.byref(size), 0, 2, 5, 0) == 122 and size.value < 4 * 1024 * 1024
    buffer = c.create_string_buffer(size.value)
    assert query(buffer, c.byref(size), 0, 2, 5, 0) == 0
    words = c.cast(buffer, c.POINTER(c.c_uint32))
    matches = []
    for index in range(words[0]):
        row = 1 + index * 6
        if socket.ntohs(words[row + 2] & 65535) == local_port and \
            socket.ntohs(words[row + 4] & 65535) == remote_port:
            matches.append(words[row + 5])
    assert len(matches) == 1, 'The browser socket owner was ambiguous'
    return matches[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--firefox', required=True, type=Path)
    parser.add_argument('--openssl', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    work = args.output.resolve()
    work.mkdir(parents=True)
    firefox = args.firefox.resolve()
    authority, ca_key, certificate, key = [work / name for name in ('ca.pem', 'ca-key.pem', 'cert.pem', 'key.pem')]
    commands = [
        ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Cipherazzi browser root',
            '-keyout', str(ca_key), '-out', str(authority)],
        ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', str(key),
            '-out', str(work / 'server.csr')],
        ['x509', '-req', '-in', str(work / 'server.csr'), '-CA', str(authority), '-CAkey', str(ca_key),
            '-CAcreateserial', '-days', '1', '-extfile', str(work / 'server.ext'), '-out', str(certificate)]
    ]
    (work / 'server.ext').write_text('basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
        'subjectAltName=DNS:localhost,IP:127.0.0.1\n')
    results = []
    try:
        for command in commands:
            completed = subprocess.run([args.openssl, *command], capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            assert completed.returncode == 0, completed.stderr.decode(errors='replace')
        der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
        for socket_process in (False, True):
            directory = work / ('socket-process' if socket_process else 'browser-process')
            directory.mkdir()
            profile, reports = directory / 'profile', directory / 'reports'
            profile.mkdir()
            reports.mkdir()
            trust_certificate(profile, firefox.parent, ssl.PEM_cert_to_DER_cert(authority.read_text()))
            (profile / 'cipherazzi-profile.json').write_text('{"owner":"Cipherazzi"}')
            preferences = {'network.http.network_access_on_socket_process.enabled': socket_process,
                'browser.startup.page': 0, 'network.proxy.type': 0, 'network.trr.mode': 5,
                'network.captive-portal-service.enabled': False, 'network.connectivity-service.enabled': False,
                'datareporting.policy.dataSubmissionEnabled': False, 'toolkit.telemetry.enabled': False,
                'services.settings.server': 'http://127.0.0.1:1', 'security.OCSP.enabled': 0}
            (profile / 'user.js').write_text(''.join(f'user_pref({json.dumps(name)}, {json.dumps(value)});\n'
                for name, value in preferences.items()))
            listeners, contexts, ports = [], [], []
            observed, errors = [], []
            for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = context.maximum_version = version
                context.set_alpn_protocols(['http/1.1'])
                context.load_cert_chain(certificate, key)
                contexts.append(context)
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0))
                listener.listen(2)
                listener.settimeout(25)
                listeners.append(listener)
                ports.append(listener.getsockname()[1])

            def serve(index):
                listener = listeners[index]
                try:
                    raw, peer = listener.accept()
                    with raw, contexts[index].wrap_socket(raw, server_side=True) as connection:
                        connection.settimeout(15)
                        assert connection.recv(16384).startswith(b'GET /')
                        owner = socket_owner(peer[1], ports[index])
                        if socket_process:
                            kernel = c.WinDLL('kernel32', use_last_error=True)
                            kernel.OpenProcess.argtypes = [c.c_uint, c.c_int, c.c_uint]
                            kernel.OpenProcess.restype = c.c_void_p
                            kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [c.c_void_p], c.c_int
                            kernel.GetProcessMitigationPolicy.argtypes = [c.c_void_p, c.c_int, c.c_void_p, c.c_size_t]
                            kernel.GetProcessMitigationPolicy.restype = c.c_int
                            handle = kernel.OpenProcess(0x1000, 0, owner)
                            assert handle, 'The protected socket process could not be inspected'
                            try:
                                dynamic, signature = c.c_uint(), c.c_uint()
                                assert kernel.GetProcessMitigationPolicy(handle, 2, c.byref(dynamic), 4)
                                assert kernel.GetProcessMitigationPolicy(handle, 8, c.byref(signature), 4)
                                assert dynamic.value & 1 and signature.value & 1, 'Browser process protection changed'
                            finally:
                                kernel.CloseHandle(handle)
                        redirect = f'<script>setTimeout(()=>location.replace("https://localhost:{ports[1]}/"),100)</script>' \
                            if index == 0 else ''
                        body = ('<html><title>Browser adapter fixture</title>'
                            'cipherazzi-private-application-data-sentinel' + redirect + '</html>').encode()
                        connection.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n' +
                            f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
                        observed.append(dict(port=ports[index], local_port=peer[1], pid=owner,
                            version=771 + index, alpn=connection.selected_alpn_protocol()))
                except Exception as error:
                    errors.append(str(error))
                finally:
                    listener.close()

            workers = [threading.Thread(target=serve, args=(index,), daemon=True) for index in range(2)]
            for worker in workers:
                worker.start()
            try:
                result = subprocess.run([str(root / 'build/bin/Release/Cipherazzi.EndpointAdapter.exe'),
                    '--provider', 'firefox', '--spawn', str(firefox), '--output', str(reports),
                    '--browser-profile', str(profile), '--url', f'https://localhost:{ports[0]}/', '--duration', '3',
                    '--', '--headless'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=40)
                (directory / 'adapter.stdout').write_bytes(result.stdout)
                (directory / 'adapter.stderr').write_bytes(result.stderr)
                assert result.returncode == 0, (result.stdout.decode(errors='replace'),
                    result.stderr.decode(errors='replace'))
                for worker in workers:
                    worker.join(3)
                assert not errors and len(observed) == 2, errors
                evidence = [json.loads(path.read_text()) for path in reports.glob('cipherazzi-endpoint-*.json')]
                for exchange in observed:
                    matching = [value for value in evidence if value['remote']['port'] == exchange['port'] and
                        value['local']['port'] == exchange['local_port']]
                    assert len(matching) == 1, (exchange, len(matching))
                    value = matching[0]
                    assert value['pid'] == exchange['pid'] and Path(value['process_path']) == firefox
                    assert value['process_name'] == 'firefox.exe' and value['provider'] == 'Firefox/NSS'
                    assert value['tls_version'] == exchange['version'] and value['success'] and value['peer_verified']
                    assert value['server_name'] == 'localhost' and value['group_id'] == 29
                    assert value['signature_scheme'] == 0x0804 and value['selected_alpn'] == 'http/1.1'
                    assert value['cipher_id'] == (0xc030 if exchange['version'] == 771 else 0x1302)
                    assert base64.b64decode(value['server_certificates_der'][0]) == der
                    assert value['process_started_us'] <= value['handshake_started_us'] <= value['timestamp_us']
                    assert 'cipherazzi-private-application-data-sentinel' not in json.dumps(value)
                imported = directory / 'import'
                imported.mkdir()
                for index, exchange in enumerate(observed):
                    value = next(value for value in evidence if value['remote']['port'] == exchange['port'] and
                        value['local']['port'] == exchange['local_port'])
                    (imported / f'firefox-{index}.json').write_text(json.dumps(value))
                database = directory / 'endpoints.db'
                loaded = subprocess.run([str(root / 'build/bin/Release/Cipherazzi.Tests.exe'), '--import-endpoints',
                    str(imported), str(database)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=30)
                assert loaded.returncode == 0, loaded.stderr.decode(errors='replace')
                with sqlite3.connect(database) as connection:
                    assert connection.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == 2
                results.append(dict(socket_process=socket_process, exchanges=2, native_import=True,
                    exact_socket_owner=True, public_certificates=True, application_data_excluded=True,
                    process_protections_preserved=socket_process))
                print(f'{directory.name}: two public browser TLS reports passed.', flush=True)
            finally:
                for listener in listeners:
                    listener.close()
                for worker in workers:
                    worker.join(1)
        (work / 'results.json').write_text(json.dumps(dict(cases=results), indent=2))
    finally:
        key.unlink(missing_ok=True)
        ca_key.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
