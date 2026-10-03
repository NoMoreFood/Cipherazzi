import argparse
import base64
import json
import socket
import sqlite3
import ssl
import subprocess
import threading
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--go-client', type=Path)
    parser.add_argument('--rustls-client', type=Path)
    parser.add_argument('--native-rustls-client', type=Path)
    parser.add_argument('--native-async', action='store_true')
    parser.add_argument('--native-provider', choices=['auto', 'rustls'], default='rustls')
    parser.add_argument('--rustls-symbols', type=Path)
    parser.add_argument('--rustls-profile', type=Path)
    parser.add_argument('--rustls-profile-out', type=Path)
    parser.add_argument('--source-async', action='store_true')
    parser.add_argument('--openssl', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.output.resolve()
    work.mkdir(parents=True)

    def command(application, role, version, address, directory, certificate, key, mode):
        if application == args.native_rustls_client:
            metadata = []
            if args.rustls_symbols:
                metadata.extend(['--rustls-symbols', args.rustls_symbols.resolve()])
            if args.rustls_profile:
                metadata.extend(['--rustls-profile', args.rustls_profile.resolve()])
            if args.rustls_profile_out and not args.rustls_profile_out.exists():
                metadata.extend(['--rustls-profile-out', args.rustls_profile_out.resolve()])
            return [root / 'tools/artifacts/build/bin/Release/Cipherazzi.EndpointAdapter.exe',
                    '--spawn', application.resolve(),
                '--provider', args.native_provider, '--output', directory, *metadata,
                '--', role, version, address, certificate, key, mode,
                *(['async'] if args.native_async else [])]
        return [application, role, version, address, directory, certificate, key, mode,
            *(['async'] if args.source_async and application == args.rustls_client else [])]

    def run(command, **options):
        result = subprocess.run([str(value) for value in command], capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW, timeout=40, **options)
        assert result.returncode == 0, (command, result.stdout, result.stderr)
        return result

    # Use a trusted test CA and a distinct end-entity certificate for both mutual TLS roles.
    configuration = work / 'openssl.cnf'
    configuration.write_text('[req]\ndistinguished_name=subject\n[subject]\n')
    ca, ca_key, certificate, key = [work / name for name in ('ca.pem', 'ca.key', 'cert.pem', 'key.pem')]
    run([args.openssl, 'req', '-config', configuration, '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', ca_key, '-out', ca, '-days', '1', '-subj', '/CN=Coverage CA',
        '-addext', 'basicConstraints=critical,CA:TRUE'])
    run([args.openssl, 'req', '-config', configuration, '-new', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', key, '-out', work / 'leaf.csr', '-subj', '/CN=coverage.test'])
    extensions = work / 'extensions.cnf'
    extensions.write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:coverage.test\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n')
    run([args.openssl, 'x509', '-req', '-in', work / 'leaf.csr', '-CA', ca, '-CAkey', ca_key,
        '-set_serial', '1', '-days', '1', '-extfile', extensions, '-out', certificate])
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
    certificate.write_text(certificate.read_text() + ca.read_text())
    results = []
    applications = [('Go/crypto/tls', args.go_client), ('Rust/rustls', args.rustls_client),
        ('Rust/rustls', args.native_rustls_client)]
    assert any(application for _, application in applications), 'Specify at least one client.'
    for provider, application in applications:
        if application is None:
            continue
        native = application == args.native_rustls_client
        no_observations = native or (args.source_async and application == args.rustls_client)
        for version in ('TLSv1.2', 'TLSv1.3'):
            for role, mode in [('client', 'ok'), ('server', 'ok'), ('client', 'reject'),
                *([('client', 'lost-directory')] if version == 'TLSv1.3' and not native else [])]:
                name = f'{application.stem}-{version}-{role}-{mode}'
                directory = work / name
                directory.mkdir()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if role == 'client' else ssl.PROTOCOL_TLS_CLIENT)
                context.load_cert_chain(certificate, key)
                context.load_verify_locations(ca)
                context.verify_mode = ssl.CERT_REQUIRED
                context.set_alpn_protocols(['h2'])
                context.minimum_version = context.maximum_version = (
                    ssl.TLSVersion.TLSv1_2 if version == 'TLSv1.2' else ssl.TLSVersion.TLSv1_3)
                failures = []
                peers = []
                count = 2 if mode == 'ok' else 1
                if role == 'client':
                    listener = socket.socket()
                    listener.bind(('127.0.0.1', 0))
                    listener.listen(2)
                    listener.settimeout(20)

                    def echo():
                        try:
                            for _ in range(count):
                                raw, _ = listener.accept()
                                raw.settimeout(15)
                                try:
                                    with raw, context.wrap_socket(raw, server_side=True) as secured:
                                        peers.append((secured.getpeername(), secured.getsockname()))
                                        assert secured.recv(1) == b'*'
                                        secured.sendall(b'*')
                                except ssl.SSLError:
                                    if mode != 'reject':
                                        raise
                        except Exception as error:
                            failures.append(repr(error))

                    worker = threading.Thread(target=echo, daemon=True)
                    worker.start()
                    try:
                        result = run(command(application, role, version, f'127.0.0.1:{listener.getsockname()[1]}',
                            directory, certificate, key, mode))
                        if directory.exists():
                            (directory / 'client.stdout').write_bytes(result.stdout)
                            (directory / 'client.stderr').write_bytes(result.stderr)
                    finally:
                        worker.join(25)
                        listener.close()
                    assert not worker.is_alive() and not failures, (name, failures)
                else:
                    process = subprocess.Popen([str(value) for value in command(application, role, version,
                        '127.0.0.1:0', directory, certificate, key, mode)], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW, text=True)
                    try:
                        while True:
                            line = process.stdout.readline().strip()
                            assert line, process.stderr.read()
                            if line.isdigit():
                                port = int(line)
                                break
                        session = None
                        for _ in range(count):
                            with socket.create_connection(('127.0.0.1', port), timeout=15) as raw:
                                with context.wrap_socket(raw, server_hostname='coverage.test',
                                    session=session) as secured:
                                    peers.append((secured.getpeername(), secured.getsockname()))
                                    secured.sendall(b'*')
                                    assert secured.recv(1) == b'*'
                                    session = secured.session
                        stdout, stderr = process.communicate(timeout=20)
                        (directory / 'server.stdout').write_text(stdout)
                        (directory / 'server.stderr').write_text(stderr)
                        assert process.returncode == 0, (name, stdout, stderr)
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate()

                if mode == 'lost-directory':
                    assert not directory.exists()
                    results.append(dict(case=name, tls_succeeded=True, report_failure_separate=True))
                    continue
                reports = [json.loads(path.read_text()) for path in directory.glob('*.json')]
                expected = (2 if no_observations else 4) if mode == 'ok' else 1
                assert len(reports) == expected, (name, reports)
                assert not list(directory.glob('*.tmp')), name
                handshakes = sorted([report for report in reports if report.get('observation') != 'connection'],
                    key=lambda report: report['timestamp_us'])
                for report in reports:
                    assert report['provider'] == provider and report['role'] == role
                    assert report['success'] == (mode == 'ok')
                    assert report['process_started_us'] <= report['timestamp_us']
                    assert report['local']['address'] == report['remote']['address'] == '127.0.0.1'
                    assert Path(report['process_path']).resolve() == application.resolve()
                    if report.get('observation') == 'connection':
                        assert 'handshake_started_us' not in report
                    else:
                        assert report['process_started_us'] <= report['handshake_started_us'] <= report['timestamp_us']
                    assert not any(field in report for field in ('signature_scheme', 'local_signature_scheme'))
                    if mode == 'ok':
                        assert report['tls_version'] == (771 if version == 'TLSv1.2' else 772)
                        assert report['cipher_id'] and report['selected_alpn'] == 'h2'
                        field = 'server_certificates_der' if role == 'client' else 'client_certificates_der'
                        assert base64.b64decode(report[field][0]) == der
                        if provider.startswith('Go/'):
                            assert report['peer_verified'] is True
                        else:
                            assert 'peer_verified' not in report
                if mode == 'ok':
                    assert handshakes[0]['session_resumed'] is False and handshakes[1]['session_resumed'] is True, name
                    if not native:
                        assert handshakes[0]['group_id'] > 0, name
                    sockets = {(report['local']['port'], report['remote']['port']) for report in handshakes}
                    assert sockets == {(peer[0][1], peer[1][1]) for peer in peers}, (name, sockets, peers)
                else:
                    assert reports[0]['error_name'] == 'TLS_HANDSHAKE_FAILED'
                imported = directory / 'endpoints.db'
                run([root / 'tools/artifacts/build/bin/Release/Cipherazzi.Tests.exe',
                     '--import-endpoints', directory, imported])
                with sqlite3.connect(imported) as database:
                    assert database.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == len(reports)
                    assert database.execute('SELECT count(*) FROM connections').fetchone()[0] == 0
                    assert database.execute("SELECT count(*) FROM endpoint_events WHERE kind='TLS connection' "
                        "AND json_type(detail_json,'$.handshake_started_us')='null'").fetchone()[0] == (
                        2 if mode == 'ok' and not no_observations else 0)
                results.append(dict(case=name, reports=len(reports), native_import=True))
    (work / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
