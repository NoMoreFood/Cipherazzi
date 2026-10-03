import argparse
import base64
import json
import os
import socket
import shutil
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--openssl', required=True)
    parser.add_argument('--nss')
    parser.add_argument('--boringssl')
    parser.add_argument('--providers', nargs='+', choices=('openssl', 'nss', 'boringssl'),
        default=('openssl', 'nss', 'boringssl'))
    parser.add_argument('--custom-io', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    work = Path(args.output).resolve()
    work.mkdir(parents=True)
    adapter = root / 'build/bin/Release/Cipherazzi.EndpointAdapter.exe'
    collector = root / 'build/bin/Release/Cipherazzi.Tests.exe'
    certificate, key = work / 'cert.pem', work / 'key.pem'
    command = [args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
        '-out', str(certificate), '-days', '1', '-subj', '/CN=adapter.lab']
    subprocess.run(command, check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
    (work / 'cert.der').write_bytes(der)
    expected = []

    def exchange(provider, version, hostname='adapter.lab', report_directory=None, storage_options=(),
        attach=False, buffers=False, detach_before_handshake=False, mutual=False, custom_io=False, console_alias=False):
        directory = report_directory or work / (f'{provider}-{version}-{hostname}' +
            ('-attach' if attach else '') + ('-buffers' if buffers else '') +
            ('-detach' if detach_before_handshake else '') + ('-mutual' if mutual else '') +
            ('-custom-io' if custom_io else '') + ('-console-alias' if console_alias else ''))
        directory.mkdir(exist_ok=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        context.set_alpn_protocols(['h2'])
        if mutual:
            context.load_verify_locations(certificate)
            context.verify_mode = ssl.CERT_REQUIRED
        selected = ssl.TLSVersion.TLSv1_2 if version == 771 else ssl.TLSVersion.TLSv1_3
        context.minimum_version = context.maximum_version = selected
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.settimeout(6)
        port = server.getsockname()[1]
        observed, errors = [], []

        def serve():
            try:
                with server.accept()[0] as raw, context.wrap_socket(raw, server_side=True) as connection:
                    connection.settimeout(20)
                    observed.append(dict(version=connection.version(), cipher=connection.cipher()[0],
                        alpn=connection.selected_alpn_protocol(), peer=connection.getpeername()))
                    connection.recv(256)
                    connection.sendall(b'ok')
                    try:
                        connection.unwrap().close()
                    except (ssl.SSLEOFError, ConnectionResetError):
                        pass
            except Exception as error:
                errors.append(str(error))
            finally:
                server.close()

        worker = threading.Thread(target=serve)
        worker.start()
        before = set(directory.glob('cipherazzi-endpoint-*.json'))
        if detach_before_handshake:
            expired = directory / 'cipherazzi-endpoint-expired.json'
            expired.write_text('{}')
            os.utime(expired, (time.time() - 5, time.time() - 5))
        if provider == 'openssl' and not attach and not custom_io:
            application = [args.openssl, 's_client', '-connect', f'127.0.0.1:{port}', '-servername', hostname,
                '-alpn', 'h2', '-CAfile', str(certificate), '-verify_return_error', '-verify_hostname', hostname,
                '-tls1_2' if version == 771 else '-tls1_3', '-quiet', '-no_ign_eof']
        else:
            application = [sys.executable, str(root / 'tests/clients' /
                ('NssClient.py' if provider == 'nss' else 'ApiTlsClient.py')),
                '--library', args.nss if provider == 'nss' else args.boringssl if provider == 'boringssl' else
                    str(Path(args.openssl).parent), '--port', str(port),
                '--certificate', str(work / 'cert.der' if provider == 'nss' else certificate),
                '--version', str(version), '--hostname', hostname]
            if provider != 'nss':
                application += ['--provider', provider]
            if buffers:
                application += ['--buffers']
            if custom_io:
                application += ['--custom-io' if provider == 'nss' else '--memory-bio']
            if mutual:
                application += ['--client-certificate', str(certificate), '--client-key', str(key)]
        if attach:
            gate = directory / 'release'
            application += ['--gate', str(gate)]
            with (directory / 'application.stdout').open('wb') as stdout, \
                (directory / 'application.stderr').open('wb') as stderr, \
                (directory / 'adapter.stdout').open('wb') as adapter_stdout, \
                (directory / 'adapter.stderr').open('wb') as adapter_stderr:
                target = subprocess.Popen(application, stdout=stdout, stderr=stderr,
                    creationflags=subprocess.CREATE_NO_WINDOW)
                observer = None
                try:
                    deadline = time.monotonic() + 10
                    ready = Path(str(gate) + '.ready')
                    while not ready.exists() and time.monotonic() < deadline and target.poll() is None:
                        time.sleep(0.01)
                    assert ready.exists(), 'Target library startup failed'
                    observer = subprocess.Popen([str(adapter), '--pid', str(target.pid), '--output', str(directory),
                        '--provider', provider, '--duration', '1' if detach_before_handshake else '25',
                        *(['--max-age', '1'] if detach_before_handshake else [])],
                        stdout=adapter_stdout, stderr=adapter_stderr,
                        creationflags=subprocess.CREATE_NO_WINDOW)
                    deadline = time.monotonic() + 10
                    while 'Observing PID' not in (directory / 'adapter.stdout').read_text() and \
                        time.monotonic() < deadline and observer.poll() is None:
                        time.sleep(0.01)
                    assert 'Observing PID' in (directory / 'adapter.stdout').read_text(), 'Target attachment failed'
                    if detach_before_handshake:
                        assert observer.wait(10) == 0 and target.poll() is None, 'Timed detach stopped the application'
                        assert not expired.exists(), 'Idle retention did not expire an old report'
                    gate.write_text('Handshake may start')
                    assert target.wait(25) == 0, 'The attached application failed'
                    status = observer.wait(10)
                finally:
                    for process in (observer, target):
                        if process is not None and process.poll() is None:
                            process.kill()
                            process.wait(5)
            result = subprocess.CompletedProcess([], status, (directory / 'adapter.stdout').read_bytes(),
                (directory / 'adapter.stderr').read_bytes())
        else:
            if console_alias:
                binary = directory / 'conhost.exe'
                shutil.copyfile(args.openssl, binary)
                for dependency in Path(args.openssl).parent.glob('lib*-*-x64.dll'):
                    shutil.copyfile(dependency, directory / dependency.name)
                application[0] = str(binary)
                configuration = directory / 'launcher.json'
                configuration.write_text(json.dumps(dict(commands=[application], pids=str(directory / 'pids.json'),
                    input='cipherazzi-private-application-data-sentinel\n')))
                application = [sys.executable, str(root / 'tests/clients/TlsChildLauncher.py'),
                    '--configuration', str(configuration)]
            invocation = [str(adapter), '--output', str(directory), '--provider', provider,
                '--spawn', application[0], *storage_options, '--', *application[1:]]
            result = subprocess.run(invocation, input=b'cipherazzi-private-application-data-sentinel\n',
                capture_output=True, timeout=35, creationflags=subprocess.CREATE_NO_WINDOW)
        (directory / 'adapter.stdout').write_bytes(result.stdout)
        (directory / 'adapter.stderr').write_bytes(result.stderr)
        worker.join(7)
        assert not worker.is_alive(), (provider, 'TLS server did not stop', result.stdout.decode(errors='replace'),
            result.stderr.decode(errors='replace'))
        success = hostname == 'adapter.lab'
        assert result.returncode == (0 if success else 1), (provider, result.stdout.decode(errors='replace'),
            result.stderr.decode(errors='replace'), errors)
        generated = set(directory.glob('cipherazzi-endpoint-*.json')) - before
        if detach_before_handshake:
            assert not generated and observed and not errors, 'Observation continued after timed detach'
            print(f'{provider} idle retention and timed detach passed.', flush=True)
            return directory, None
        assert len(generated) == 1, (provider, result.stdout.decode(errors='replace'),
            result.stderr.decode(errors='replace'), errors)
        report_path = generated.pop()
        report = json.loads(report_path.read_text())
        assert report['success'] is success, report
        assert report['provider'].lower() == provider
        assert report['process_started_us'] <= report['handshake_started_us'] <= report['timestamp_us']
        assert report['process_name'] and report['process_path']
        if console_alias:
            assert report['process_name'] == 'conhost.exe' and Path(report['process_path']) == binary
        assert report['server_name'] == hostname
        if custom_io:
            assert 'local' not in report and 'remote' not in report and report['transport'] == 'Unknown'
        else:
            assert report['local']['address'] == report['remote']['address'] == '127.0.0.1'
            assert report['remote']['port'] == port
        assert report['peer_verified'] is success, report
        if success:
            assert observed and not errors, errors
            assert report['tls_version'] == version and report['cipher_id'] > 0
            if not custom_io:
                assert report['local']['port'] == observed[0]['peer'][1]
            assert report['selected_alpn'] == 'h2' and report['group_id'] == 29
            assert report['signature_scheme'] in (0x0401, 0x0804, 0x0805, 0x0806)
            assert report['session_resumed'] is False
            assert base64.b64decode(report['server_certificates_der'][0]) == der
            if mutual:
                assert report['local_signature_scheme'] in (0x0804, 0x0805, 0x0806)
        assert 'cipherazzi-private-application-data-sentinel' not in report_path.read_text()
        assert 'PRIVATE KEY' not in report_path.read_text()
        assert not list(directory.glob('*.tmp'))
        expected.append(dict(provider=provider, version=version, success=success, attached=attach, buffers=buffers,
            mutual=mutual, console_alias=console_alias,
            process_identity=True, socket_identity=not custom_io, custom_io=custom_io, public_certificate=success))
        print(f'{provider} TLS {version} {"success" if success else "verification failure"} passed.', flush=True)
        return directory, report

    for provider in args.providers:
        if provider != 'openssl' and not getattr(args, provider):
            continue
        if args.custom_io:
            for version in (771, 772):
                exchange(provider, version, custom_io=True)
            exchange(provider, 772, 'wrong-host.lab', custom_io=True)
            exchange(provider, 772, attach=True, custom_io=True)
            if provider == 'boringssl':
                exchange(provider, 772, buffers=True, custom_io=True)
                exchange(provider, 772, 'wrong-host.lab', buffers=True, custom_io=True)
        for version in (771, 772):
            exchange(provider, version)
        exchange(provider, 772, 'wrong-host.lab')
        exchange(provider, 772, attach=True)
        if provider == 'boringssl':
            exchange(provider, 772, buffers=True)
            exchange(provider, 772, 'wrong-host.lab', buffers=True)
            exchange(provider, 772, mutual=True)
    exchange('openssl', 772, attach=True, detach_before_handshake=True)
    if args.custom_io:
        exchange('openssl', 772, console_alias=True)

    # Test report retention during actual launches without deleting another provider's files.
    retained = work / 'retention'
    retained.mkdir()
    foreign = retained / 'another-provider.json'
    foreign.write_text('{"preserve":true}')
    expired = retained / 'cipherazzi-endpoint-expired.json'
    expired.write_text('{}')
    os.utime(expired, (time.time() - 7200, time.time() - 7200))
    exchange('openssl', 772, report_directory=retained, storage_options=['--max-files', '1', '--max-age', '3600'])
    exchange('openssl', 772, report_directory=retained, storage_options=['--max-files', '1', '--max-age', '3600'])
    assert len(list(retained.glob('cipherazzi-endpoint-*.json'))) == 1 and not expired.exists()
    assert foreign.read_text() == '{"preserve":true}'

    # Import the emitted files through the native collector and inspect durable public evidence.
    combined = work / 'all-reports'
    combined.mkdir()
    for directory in work.iterdir():
        if directory.is_dir() and directory not in (retained, combined):
            for report in directory.glob('cipherazzi-endpoint-*.json'):
                (combined / report.name).write_bytes(report.read_bytes())
    database = work / 'endpoints.db'
    result = subprocess.run([str(collector), '--import-endpoints', str(combined), str(database)],
        capture_output=True, timeout=40, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    with sqlite3.connect(database) as connection:
        events = connection.execute('SELECT detail_json FROM endpoint_events').fetchall()
        assert len(events) == len(expected) - 2, (len(events), len(expected))
        details = [json.loads(value[0]) for value in events]
        assert all(value['peer_name'] in ('adapter.lab', 'wrong-host.lab') for value in details)
        assert all(value['assessment']['server_name'] == value['peer_name'] for value in details)
        for value in details:
            if value['transport'] == 'Unknown':
                assert value['local_address'] == value['remote_address'] == '' and not value['local_port']
                assert not value['remote_port'] and 'no packet association asserted' in value['correlation']
                assert value['assessment']['crypto']['transport'] == 'Unknown'
                assert 'matched_flow_id' not in value and value['process_scope'] == 'endpoint'
            else:
                assert value['local_address'] == value['remote_address'] == '127.0.0.1'
                assert value['correlation'].startswith('Unmatched socket')
        certificates = connection.execute('SELECT der FROM certificates').fetchall()
        assert len(certificates) == 1 and certificates[0][0] == der
    (work / 'results.json').write_text(json.dumps(dict(cases=expected, native_report_import=True,
        bounded_atomic_files=True, unrelated_reports_preserved=True, application_data_excluded=True,
        private_keys_excluded=True, idle_expiration=True, timed_detach_keeps_application_running=True,
        packet_associations_not_invented=True), indent=2))
    key.unlink()
    print(f'{len(expected)} actual library-adapter exchanges and native import passed.')


if __name__ == '__main__':
    main()
