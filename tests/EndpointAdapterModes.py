import argparse
import ctypes as c
import json
import socket
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--openssl', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    adapter = root / 'build/bin/Release/Cipherazzi.EndpointAdapter.exe'
    work = Path(args.output).resolve()
    work.mkdir(parents=True)
    results = []

    def listening(port):
        size = c.c_ulong()
        query = c.WinDLL('iphlpapi').GetExtendedTcpTable
        if query(None, c.byref(size), 0, 2, 5, 0) != 122 or size.value > 4 * 1024 * 1024:
            return False
        buffer = c.create_string_buffer(size.value)
        if query(buffer, c.byref(size), 0, 2, 5, 0):
            return False
        words = c.cast(buffer, c.POINTER(c.c_uint32))
        for index in range(words[0]):
            row = 1 + index * 6
            if words[row] == 2 and socket.ntohs(words[row + 2] & 65535) == port:
                return True
        return False

    for name, algorithm, version, client_auth, reconnect in (
        ('mutual-tls', 'rsa:2048', '-tls1_3', True, False),
        ('resumed-tls', 'rsa:2048', '-tls1_2', False, True),
        ('post-quantum', 'ML-DSA-44', '-tls1_3', False, False)):
        directory = work / name
        directory.mkdir()
        reports = directory / 'reports'
        reports.mkdir()
        certificate, key = directory / 'cert.pem', directory / 'key.pem'
        generated = subprocess.run([args.openssl, 'req', '-x509', '-newkey', algorithm, '-nodes', '-days', '1',
            '-subj', '/CN=adapter.lab', '-keyout', str(key), '-out', str(certificate)],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
        assert generated.returncode == 0, generated.stderr.decode(errors='replace')
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            port = available.getsockname()[1]
        count = 6 if reconnect else 1
        server_arguments = [args.openssl, 's_server', '-accept', f'127.0.0.1:{port}', '-cert', str(certificate),
            '-key', str(key), '-alpn', 'h2', '-rev', '-quiet', '-naccept', str(count), version]
        client_arguments = [args.openssl, 's_client', '-connect', f'127.0.0.1:{port}', '-servername', 'adapter.lab',
            '-CAfile', str(certificate), '-verify_hostname', 'adapter.lab', '-verify_return_error', '-alpn', 'h2',
            '-quiet', '-no_ign_eof', version]
        if client_auth:
            server_arguments += ['-Verify', '1', '-CAfile', str(certificate), '-verify_return_error']
            client_arguments += ['-cert', str(certificate), '-key', str(key)]
        if reconnect:
            client_arguments += ['-reconnect']
        if algorithm == 'ML-DSA-44':
            server_arguments += ['-groups', 'X25519MLKEM768', '-sigalgs', 'mldsa44']
            client_arguments += ['-groups', 'X25519MLKEM768', '-sigalgs', 'mldsa44']
        with (directory / 'server.stdout').open('wb') as stdout, (directory / 'server.stderr').open('wb') as stderr:
            server = subprocess.Popen([str(adapter), '--output', str(reports), '--spawn', server_arguments[0],
                '--', *server_arguments[1:]], stdout=stdout, stderr=stderr, stdin=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                deadline = time.monotonic() + 10
                while not listening(port) and \
                    time.monotonic() < deadline and server.poll() is None:
                    time.sleep(0.01)
                assert listening(port), \
                    (directory / 'server.stderr').read_text(errors='replace')
                client = subprocess.run([str(adapter), '--output', str(reports), '--spawn', client_arguments[0],
                    '--', *client_arguments[1:]], input=b'adapter public test\n', capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=35)
                (directory / 'client.stdout').write_bytes(client.stdout)
                (directory / 'client.stderr').write_bytes(client.stderr)
                assert client.returncode == 0, client.stderr.decode(errors='replace')
                assert server.wait(15) == 0, (directory / 'server.stderr').read_text(errors='replace')
            finally:
                if server.poll() is None:
                    server.kill()
                    server.wait(5)
        evidence = [json.loads(path.read_text()) for path in reports.glob('*.json')]
        clients = sorted((value for value in evidence if value['role'] == 'client'),
            key=lambda value: value['timestamp_us'])
        servers = sorted((value for value in evidence if value['role'] == 'server'),
            key=lambda value: value['timestamp_us'])
        assert len(clients) == len(servers) == count, (name, len(clients), len(servers))
        assert all(value['success'] and value['selected_alpn'] == 'h2' for value in evidence)
        assert all(value['peer_verified'] for value in clients)
        assert all(value['local']['address'] == value['remote']['address'] == '127.0.0.1' for value in evidence)
        for client in clients:
            matches = [value for value in servers if value['local'] == client['remote'] and
                value['remote'] == client['local']]
            assert len(matches) == 1, 'Client/server socket evidence disagreed'
        if client_auth:
            assert servers[0]['peer_verified'] and clients[0]['local_signature_scheme'] > 0
            assert all(value['server_certificates_der'] and value['client_certificates_der'] for value in evidence)
        if reconnect:
            assert clients[0]['session_resumed'] is False and any(value['session_resumed'] for value in clients[1:])
            assert all('signature_scheme' not in value and 'local_signature_scheme' not in value
                for value in evidence if value['session_resumed'])
            assert all('group_id' not in value for value in evidence if value['session_resumed'])
        if algorithm == 'ML-DSA-44':
            assert clients[0]['signature_scheme'] == servers[0]['local_signature_scheme'] == 0x0904
            assert clients[0]['group_id'] == servers[0]['group_id'] == 0x11ec
        results.append(dict(mode=name, client_reports=len(clients), server_reports=len(servers),
            actual_socket_pairs=True, resumed_signatures_not_invented=reconnect))
        key.unlink()
        print(f'{name}: {count} actual client/server pairs passed.', flush=True)
    (work / 'results.json').write_text(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
