import argparse
import ipaddress
import json
import sqlite3
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--provider', choices=['go', 'rustls'], default='go')
    parser.add_argument('--rustls-symbols', type=Path)
    parser.add_argument('--rustls-profile', type=Path)
    parser.add_argument('--rustls-profile-out', type=Path)
    parser.add_argument('--certificate', required=True, type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.output.resolve()
    work.mkdir(parents=True)
    adapter = root / 'tools/artifacts/build/bin/Release/Cipherazzi.EndpointAdapter.exe'
    metadata = []
    for option in ['rustls_symbols', 'rustls_profile']:
        value = getattr(args, option)
        if value:
            metadata.extend(['--' + option.replace('_', '-'), str(value.resolve())])
    results = []
    for address in ['127.0.0.1', '::1']:
        for valid in [True, False]:
            case = work / f'{"ipv4" if address == "127.0.0.1" else "ipv6"}-{valid}'
            case.mkdir()
            server_directory, client_directory = case / 'server', case / 'client'
            endpoint = f'[{address}]' if ':' in address else address
            command = [str(adapter), '--spawn', str(args.client.resolve()), '--provider', args.provider,
                '--output', str(server_directory), *metadata,
                *(['--rustls-profile-out', str(args.rustls_profile_out.resolve())]
                    if args.rustls_profile_out and not args.rustls_profile_out.exists() else []),
                '--', 'server', endpoint + ':0',
                str(args.certificate.resolve()), str(args.key.resolve()), 'ok']
            server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW, text=True)
            prefix = []
            try:
                while True:
                    line = server.stdout.readline()
                    assert line, (prefix, server.stderr.read())
                    prefix.append(line)
                    if line.strip().isdigit():
                        port = int(line.strip())
                        break
                client = subprocess.run([str(adapter), '--spawn', str(args.client.resolve()),
                    '--provider', args.provider, '--output', str(client_directory), *metadata,
                    '--', 'client', f'{endpoint}:{port}',
                    str(args.certificate.resolve()), str(args.key.resolve()), 'ok' if valid else 'reject'],
                    capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=25)
                (case / 'client.stdout').write_bytes(client.stdout)
                (case / 'client.stderr').write_bytes(client.stderr)
                stdout, stderr = server.communicate(timeout=25)
                (case / 'server.stdout').write_text(''.join(prefix) + stdout)
                (case / 'server.stderr').write_text(stderr)
                assert client.returncode == 0, (client.stdout, client.stderr)
                assert server.returncode == (0 if valid else 1), (stdout, stderr)
                client_reports = [json.loads(path.read_text()) for path in client_directory.glob('*.json')]
                server_reports = [json.loads(path.read_text()) for path in server_directory.glob('*.json')]
                assert len(client_reports) == 1, (client_reports, client.stderr)
                assert len(server_reports) == 1, (server_reports, stderr)
                for role, reports in [('client', client_reports), ('server', server_reports)]:
                    report = reports[0]
                    assert report['success'] is valid and report['transport'] == 'QUIC', report
                    provider = 'Go/crypto/tls' if args.provider == 'go' else 'Rust/rustls'
                    assert report['role'] == role and report['provider'] == provider, report
                    assert ipaddress.ip_address(report['local']['address']) == ipaddress.ip_address(address)
                    assert ipaddress.ip_address(report['remote']['address']) == ipaddress.ip_address(address)
                    assert report['process_started_us'] <= report['handshake_started_us'] <= report['timestamp_us']
                    if valid:
                        assert report['tls_version'] == 772 and report['cipher_id'] > 0
                        if args.provider == 'go':
                            assert report['group_id'] > 0
                        assert report['selected_alpn'] == 'coverage'
                    if role == 'client' and args.provider == 'go':
                        assert report['peer_verified'] is valid and report['server_certificates_der'], report
                    assert 'private-application-payload' not in json.dumps(report)
                assert client_reports[0]['local'] == server_reports[0]['remote']
                assert client_reports[0]['remote'] == server_reports[0]['local']
                for directory in [client_directory, server_directory]:
                    imported = subprocess.run([str(root / 'tools/artifacts/build/bin/Release/Cipherazzi.Tests.exe'),
                        '--import-endpoints', str(directory), str(directory / 'events.db')], capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                    assert imported.returncode == 0, imported.stderr
                    with sqlite3.connect(directory / 'events.db') as database:
                        assert database.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == 1
                results.append(dict(address=address, success=valid, roles=['client', 'server'],
                    exact_socket_attribution=True, native_import=True))
            finally:
                if server.poll() is None:
                    subprocess.run(['taskkill', '/F', '/T', '/PID', str(server.pid)], capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
                    server.communicate(timeout=10)
    (work / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
