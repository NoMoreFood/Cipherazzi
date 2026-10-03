import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sqlite3
import ssl
import subprocess
import threading
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--openssl', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.output.resolve()
    work.mkdir(parents=True)
    certificate, key = work / 'cert.pem', work / 'key.pem'
    configuration = work / 'openssl.cnf'
    configuration.write_text('[req]\ndistinguished_name=subject\n[subject]\n')
    issued = subprocess.run([str(args.openssl), 'req', '-config', str(configuration), '-x509',
        '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(certificate), '-days', '1',
        '-subj', '/CN=coverage.test', '-addext', 'subjectAltName=DNS:coverage.test'], capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert issued.returncode == 0, issued.stderr
    results = []
    for family, address in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
        for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
            for valid in [True, False]:
                name = f'{family.name}-{version.name}-{valid}'
                directory = work / name
                directory.mkdir()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certificate, key)
                context.set_alpn_protocols(['h2'])
                context.minimum_version = context.maximum_version = version
                listener = socket.socket(family)
                listener.bind((address, 0))
                listener.listen(64)
                listener.settimeout(25)
                port = listener.getsockname()[1]
                peers, failures = [], []
                count = 32 if valid else 4

                def echo(raw):
                    raw.settimeout(20)
                    try:
                        with raw, context.wrap_socket(raw, server_side=True) as secured:
                            received = bytearray()
                            while len(received) < len(b'private-application-payload'):
                                data = secured.recv(128)
                                assert data
                                received.extend(data)
                            assert received == b'private-application-payload'
                            secured.sendall(received)
                    except ssl.SSLError:
                        if valid:
                            raise

                def serve():
                    try:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
                            futures = []
                            for _ in range(count):
                                raw, peer = listener.accept()
                                peers.append(peer)
                                futures.append(pool.submit(echo, raw))
                            for future in futures:
                                future.result()
                    except Exception as error:
                        failures.append(repr(error))

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                try:
                    result = subprocess.run(
                        [str(root / 'tools/artifacts/build/bin/Release/Cipherazzi.EndpointAdapter.exe'),
                        '--spawn', str(args.client.resolve()), '--provider', 'go', '--output', str(directory),
                        '--', f'[{address}]:{port}' if family == socket.AF_INET6 else f'{address}:{port}',
                        str(certificate), 'ok' if valid else 'reject', str(count),
                        'TLSv1.2' if version == ssl.TLSVersion.TLSv1_2 else 'TLSv1.3'], capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW, timeout=45)
                    worker.join(25)
                finally:
                    listener.close()
                (directory / 'adapter.stdout').write_bytes(result.stdout)
                (directory / 'adapter.stderr').write_bytes(result.stderr)
                assert result.returncode == 0, (name, result.stdout, result.stderr[:2000])
                assert not worker.is_alive() and not failures, (name, failures)
                reports = [json.loads(path.read_text()) for path in directory.glob('cipherazzi-endpoint-*.json')]
                assert len(reports) == count, (name, len(reports), result.stdout, result.stderr)
                assert {report['local']['port'] for report in reports} == {peer[1] for peer in peers}
                for report in reports:
                    assert report['success'] is valid and report['peer_verified'] is valid, report
                    assert report['transport'] == 'TCP' and report['role'] == 'client', report
                    assert report['provider'] == 'Go/crypto/tls', report
                    assert report['process_started_us'] <= report['handshake_started_us'] <= report['timestamp_us']
                    assert ipaddress.ip_address(report['remote']['address']) == ipaddress.ip_address(address)
                    assert report['remote']['port'] == port
                    assert report['server_certificates_der'], report
                    if valid:
                        assert report['tls_version'] == int(version) and report['cipher_id'] > 0, report
                        assert report['group_id'] > 0 and report['signature_scheme'] > 0, report
                        assert report['selected_alpn'] == 'h2' and not report['session_resumed'], report
                assert 'private-application-payload' not in json.dumps(reports)
                imported = subprocess.run([str(root / 'tools/artifacts/build/bin/Release/Cipherazzi.Tests.exe'),
                    '--import-endpoints', str(directory), str(directory / 'events.db')], capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                assert imported.returncode == 0, imported.stderr
                with sqlite3.connect(directory / 'events.db') as database:
                    assert database.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == count
                results.append(dict(case=name, connections=count, concurrent_gc=True,
                    exact_socket_attribution=True, native_import=True))
    (work / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
