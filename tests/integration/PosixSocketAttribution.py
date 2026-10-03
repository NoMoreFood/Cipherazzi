import argparse
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
    parser.add_argument('--openssl', required=True, type=Path, nargs='+')
    parser.add_argument('--issuer', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.output.resolve()
    work.mkdir(parents=True)
    adapter = root / 'tools/artifacts/build/bin/Release/Cipherazzi.EndpointAdapter.exe'
    importer = root / 'tools/artifacts/build/bin/Release/Cipherazzi.Tests.exe'
    certificate, key = work / 'cert.pem', work / 'key.pem'
    configuration = work / 'openssl.cnf'
    configuration.write_text('[req]\ndistinguished_name=subject\n[subject]\n')
    result = subprocess.run([str(args.issuer), 'req', '-config', str(configuration), '-x509', '-newkey',
        'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(certificate), '-days', '1', '-subj', '/CN=adapter.lab'],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert result.returncode == 0, result.stderr
    results = []

    for binary_index, binary in enumerate(args.openssl):
        for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            for version, valid in ((ssl.TLSVersion.TLSv1_2, True), (ssl.TLSVersion.TLSv1_3, True),
                (ssl.TLSVersion.TLSv1_3, False)):
                directory = work / f'{binary_index}-{family.name}-{version.name}-{valid}'
                directory.mkdir()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certificate, key)
                context.minimum_version = context.maximum_version = version
                listener = socket.socket(family)
                listener.bind((address, 0))
                listener.listen(1)
                listener.settimeout(15)
                port = listener.getsockname()[1]
                peers, failures = [], []

                def serve():
                    try:
                        raw, peer = listener.accept()
                        peers.append(peer)
                        with raw, context.wrap_socket(raw, server_side=True) as secured:
                            secured.settimeout(10)
                            assert secured.recv(256) == b'private-application-content\n'
                            secured.sendall(b'ok\n')
                            secured.unwrap().close()
                    except ssl.SSLError as error:
                        if valid:
                            failures.append(str(error))
                    except Exception as error:
                        failures.append(str(error))

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                try:
                    result = subprocess.run([str(adapter), '--spawn', str(binary.resolve()), '--provider', 'openssl',
                        '--output', str(directory), '--', 's_client', '-connect',
                        f'[{address}]:{port}' if family == socket.AF_INET6 else f'{address}:{port}',
                        '-servername', 'adapter.lab', '-CAfile', certificate.as_posix(), '-verify_return_error',
                        '-verify_hostname', 'adapter.lab' if valid else 'wrong.lab',
                        '-tls1_2' if version == ssl.TLSVersion.TLSv1_2 else '-tls1_3', '-quiet', '-no_ign_eof'],
                        input=b'private-application-content\n', capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                    worker.join(20)
                finally:
                    listener.close()
                (directory / 'adapter.stdout').write_bytes(result.stdout)
                (directory / 'adapter.stderr').write_bytes(result.stderr)
                assert not worker.is_alive() and not failures, failures
                assert result.returncode == (0 if valid else 1), result.stderr
                values = [json.loads(path.read_text()) for path in directory.glob('cipherazzi-endpoint-*.json')]
                assert len(values) == 1, (values, result.stdout, result.stderr)
                report = values[0]
                assert report['success'] is valid and report['peer_verified'] is valid, report
                assert report['transport'] == 'TCP', report
                assert ipaddress.ip_address(report['local']['address']) == ipaddress.ip_address(address), report
                assert ipaddress.ip_address(report['remote']['address']) == ipaddress.ip_address(address), report
                assert report['remote']['port'] == port and report['local']['port'] == peers[0][1], report
                assert 'private-application-content' not in json.dumps(values)
                imported = subprocess.run([str(importer), '--import-endpoints', str(directory),
                    str(directory / 'events.db')], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=30)
                assert imported.returncode == 0, imported.stderr
                with sqlite3.connect(directory / 'events.db') as database:
                    assert database.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == 1
                results.append(dict(binary=str(binary), family=family.name, version=version.name, success=valid,
                    exact_socket_attribution=True, native_import=True))
    (work / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
