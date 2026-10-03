import argparse
import base64
import ctypes as c
import hashlib
import json
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--chrome', required=True, type=Path)
    parser.add_argument('--edge', type=Path)
    parser.add_argument('--openssl', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--adapter', type=Path)
    parser.add_argument('--recovery', action='store_true')
    parser.add_argument('--tabs', action='store_true')
    parser.add_argument('--url', default='https://example.com/')
    parser.add_argument('--tab-url', default='https://www.cloudflare.com/')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    work = args.output.resolve()
    work.mkdir(parents=True)
    adapter = (args.adapter or root / 'build/bin/Release/Cipherazzi.EndpointAdapter.exe').resolve()
    importer = root / 'build/bin/Release/Cipherazzi.Tests.exe'
    json.loads((root / 'collector/EndpointReport.schema.json').read_text())
    cases = []
    recovery = None
    tab_cases = []
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [c.c_uint, c.c_int, c.c_uint], c.c_void_p
    kernel.WaitForSingleObject.argtypes = [c.c_void_p, c.c_uint]
    kernel.CloseHandle.argtypes = [c.c_void_p]

    def run(browser, name, url, extra=(), failure=''):
        directory = work / name
        directory.mkdir()
        started = time.time_ns() // 1000
        clock = time.monotonic()
        result = subprocess.run([str(adapter), '--provider', 'chromium', '--spawn', str(browser),
            '--output', str(directory), '--url', url, '--duration', '3', '--', '--headless',
            '--disable-background-networking', '--disable-sync', *extra], capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW, timeout=45)
        elapsed = time.monotonic() - clock
        finished = time.time_ns() // 1000
        (directory / 'adapter.stdout').write_bytes(result.stdout)
        (directory / 'adapter.stderr').write_bytes(result.stderr)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        reports = [json.loads(path.read_text()) for path in directory.glob('cipherazzi-endpoint-*.json')]
        assert len(reports) == 1, f'{name}: expected one report, got {len(reports)}'
        report = reports[0]
        assert report['provider'] == 'Chromium/BoringSSL' and report['success'] == (not failure)
        assert report['process_scope'] == 'application' and report['role'] == 'client'
        assert Path(report['process_path']).resolve() == browser.resolve()
        assert report['process_name'] == browser.name and report['process_started_us'] <= \
            report['handshake_started_us'] <= report['timestamp_us'] <= finished
        assert report['process_started_us'] >= started
        assert not any(key in report for key in ('local', 'remote', 'quic_original_dcid', 'signature_scheme',
            'local_signature_scheme', 'session_resumed'))
        handle = kernel.OpenProcess(0x100000, False, report['pid'])
        if handle:
            try:
                assert kernel.WaitForSingleObject(handle, 5000) == 0, 'The owned browser remained running'
            finally:
                kernel.CloseHandle(handle)
        chain = [base64.b64decode(value, validate=True) for value in report['server_certificates_der']]
        if failure:
            assert report['error_name'] == failure and report['transport'] == 'Unknown'
            if failure.startswith('ERR_CERT_'):
                assert report['peer_verified'] is False and chain
                assert report['tls_version'] == (771 if name.endswith('tls12') else 772) and report['cipher_id']
                assert len(chain) == 1 and chain[0] == ssl.PEM_cert_to_DER_cert(certificate.read_text()), \
                    'The observed certificate is not the real fixture peer certificate'
            else:
                assert not chain and not any(key in report for key in ('peer_verified', 'cipher_id', 'tls_version'))
        else:
            assert report['peer_verified'] is True and len(chain) > 1
            assert report['cipher_id'] and report['group_id']
            if '--disable-quic' in extra:
                assert report['transport'] == 'TCP' and report['tls_version'] == 772
            else:
                assert report['transport'] == 'QUIC' and report['selected_alpn'].startswith('h3')
                assert 'tls_version' not in report, 'An unspecified QUIC wire version was fabricated'
        for der in chain:
            checked = subprocess.run([args.openssl, 'x509', '-inform', 'DER', '-noout'], input=der,
                capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
            assert checked.returncode == 0, 'A public certificate did not round trip'
        database = directory / 'endpoints.db'
        loaded = subprocess.run([str(importer), '--import-endpoints', str(directory), str(database)],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
        assert loaded.returncode == 0, loaded.stderr.decode(errors='replace')
        with sqlite3.connect(database) as connection:
            assert connection.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == 1
            stored = json.loads(connection.execute('SELECT detail_json FROM endpoint_events').fetchone()[0])
            assert stored['process_role'] == 'unknown' and stored['local_address'] == stored['remote_address'] == ''
            assert 'matched_flow_id' not in stored and 'no packet association asserted' in stored['correlation']
            assessment = stored['assessment']
            assert assessment['local_role'] == 'Unknown' and Path(assessment['path']).resolve() == browser.resolve()
            assert assessment['crypto']['endpoint_confirmations'][0]['success'] == (not failure)
            assert assessment['tls_version'] == report.get('tls_version', 0)
            if report['transport'] == 'QUIC':
                assert connection.execute('SELECT protocol FROM endpoint_events').fetchone()[0] == 'QUIC'
        cases.append(dict(case=name, success=not failure, transport=report['transport'],
            tls_version=report.get('tls_version', 0), certificate_count=len(chain), native_import=True,
            application_identity=True, exact_socket_not_invented=True, own_browser_stopped=True,
            elapsed_seconds=round(elapsed, 2)))
        return report

    def recover(browser, url):
        from websockets.sync.client import connect

        directory = work / 'navigation-recovery'
        directory.mkdir()
        with (directory / 'adapter.stdout').open('wb') as output, (directory / 'adapter.stderr').open('wb') as error:
            process = subprocess.Popen([str(adapter), '--provider', 'chromium', '--spawn', str(browser),
                '--output', str(directory), '--url', url, '--duration', '10', '--', '--headless',
                '--disable-background-networking', '--disable-sync', '--disable-quic'],
                stdout=output, stderr=error, creationflags=subprocess.CREATE_NO_WINDOW)
            control = None
            try:
                deadline = time.monotonic() + 15
                while not list(directory.glob('cipherazzi-endpoint-*.json')):
                    assert process.poll() is None and time.monotonic() < deadline
                    time.sleep(.05)
                first = json.loads(next(directory.glob('cipherazzi-endpoint-*.json')).read_text())
                assert first['success'] is False and first['error_name'] == 'ERR_CERT_AUTHORITY_INVALID'
                endpoint = (directory / 'chromium-profile/DevToolsActivePort').read_text().splitlines()
                control = connect(f'ws://127.0.0.1:{endpoint[0]}{endpoint[1]}',
                    open_timeout=5, close_timeout=2, max_size=4 * 1024 * 1024)
                sequence = 0

                def command(method, parameters=None, session=None):
                    nonlocal sequence
                    sequence += 1
                    request = dict(id=sequence, method=method, params=parameters or {})
                    if session:
                        request['sessionId'] = session
                    control.send(json.dumps(request))
                    while True:
                        message = json.loads(control.recv(timeout=10))
                        if message.get('id') == sequence:
                            assert 'error' not in message, message
                            return message['result']

                targets = command('Target.getTargets')['targetInfos']
                target = next(target['targetId'] for target in targets
                    if target['type'] == 'page' and target['url'] != 'about:blank')
                session = command('Target.attachToTarget', dict(targetId=target, flatten=True))['sessionId']
                command('Page.navigate', dict(url=args.url), session)
                process.wait(20)
                assert process.returncode == 0, (directory / 'adapter.stderr').read_text(errors='replace')
                reports = [json.loads(path.read_text()) for path in directory.glob('cipherazzi-endpoint-*.json')]
                assert len(reports) == 2 and sum(report['success'] for report in reports) == 1, \
                    'The adapter did not resume observing successful navigation after certificate rejection'
                assert len({(report['pid'], report['process_started_us']) for report in reports}) == 1
                completed = next(report for report in reports if report['success'])
                assert completed['peer_verified'] is True and completed['handshake_started_us'] > first['timestamp_us']
                loaded = subprocess.run([str(importer), '--import-endpoints', str(directory),
                    str(directory / 'endpoints.db')], capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                assert loaded.returncode == 0, loaded.stderr.decode(errors='replace')
                return dict(real_exchanges=2, failure_then_success=True, same_browser_lifetime=True, native_import=True)
            finally:
                if control:
                    control.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(5)

    def tabs(browser, name):
        from websockets.sync.client import connect

        directory = work / (name + '-tabs')
        directory.mkdir()
        with (directory / 'adapter.stdout').open('wb') as output, (directory / 'adapter.stderr').open('wb') as error:
            process = subprocess.Popen([str(adapter), '--provider', 'chromium', '--spawn', str(browser),
                '--output', str(directory), '--url', args.url, '--duration', '20', '--', '--headless',
                '--disable-background-networking', '--disable-sync', '--disable-quic'],
                stdout=output, stderr=error, creationflags=subprocess.CREATE_NO_WINDOW)
            control = None
            try:
                deadline = time.monotonic() + 15

                def reports():
                    return [json.loads(path.read_text()) for path in directory.glob('cipherazzi-endpoint-*.json')]

                while not reports():
                    assert process.poll() is None and time.monotonic() < deadline
                    time.sleep(.05)
                first = reports()[0]
                assert first['success'] and first['server_name'] == urlsplit(args.url).hostname
                endpoint = (directory / 'chromium-profile/DevToolsActivePort').read_text().splitlines()
                control = connect(f'ws://127.0.0.1:{endpoint[0]}{endpoint[1]}',
                    open_timeout=5, close_timeout=2, max_size=4 * 1024 * 1024)
                sequence = 0
                states = {}

                def command(method, parameters=None, session=None):
                    nonlocal sequence
                    sequence += 1
                    request = dict(id=sequence, method=method, params=parameters or {})
                    if session:
                        request['sessionId'] = session
                    control.send(json.dumps(request))
                    while True:
                        message = json.loads(control.recv(timeout=10))
                        if message.get('method') == 'Security.visibleSecurityStateChanged':
                            states[message['sessionId']] = message['params']['visibleSecurityState']
                        if message.get('id') == sequence:
                            assert 'error' not in message, message
                            return message['result']

                targets = command('Target.getTargets')['targetInfos']
                primary = next(target['targetId'] for target in targets
                    if target['type'] == 'page' and target['url'] == args.url)
                peers = []

                def open_peer(url):
                    # Separate browser contexts require independent real handshakes without changing certificate trust.
                    context = command('Target.createBrowserContext')['browserContextId']
                    target = command('Target.createTarget',
                        dict(url='about:blank', browserContextId=context))['targetId']
                    session = command('Target.attachToTarget', dict(targetId=target, flatten=True))['sessionId']
                    command('Security.enable', session=session)
                    started = time.time_ns() // 1000
                    command('Page.navigate', dict(url=url), session)
                    peers.append(dict(target=target, session=session, started=started, url=url))

                open_peer(args.url)
                open_peer(args.tab_url)
                deadline = time.monotonic() + 8
                while len(reports()) < 3:
                    assert process.poll() is None and time.monotonic() < deadline, \
                        'Additional Chromium tabs were not observed'
                    time.sleep(.05)

                # Closing the original observed page and short-lived tabs must leave other pages observable.
                assert command('Target.closeTarget', dict(targetId=primary))['success']
                for _ in range(12):
                    target = command('Target.createTarget', dict(url='about:blank'))['targetId']
                    assert command('Target.closeTarget', dict(targetId=target))['success']
                open_peer(args.url)
                deadline = time.monotonic() + 8
                while len(reports()) < 4:
                    assert process.poll() is None and time.monotonic() < deadline, \
                        'Closing tabs stopped observation of subsequent navigations'
                    time.sleep(.05)
                finished = time.time_ns() // 1000

                # Compare every added tab with that tab's independently read public certificate state.
                observed = reports()
                assert len(observed) == 4 and len({(report['pid'], report['process_started_us'])
                    for report in observed}) == 1, 'Tab reports were duplicated or assigned another browser lifetime'
                available = sorted((report for report in observed if report != first),
                    key=lambda report: report['handshake_started_us'])
                for peer in peers:
                    command('Security.disable', session=peer['session'])
                    states.pop(peer['session'], None)
                    command('Security.enable', session=peer['session'])
                    security = states[peer['session']]['certificateSecurityState']
                    matched = next(report for report in available
                        if report['server_name'] == urlsplit(peer['url']).hostname and
                        report['handshake_started_us'] >= peer['started'])
                    available.remove(matched)
                    assert matched['success'] and matched['peer_verified'] is True and matched['transport'] == 'TCP'
                    assert matched['tls_version'] == (772 if security['protocol'] == 'TLS 1.3' else 771)
                    assert matched['server_certificates_der'] == security['certificate'], \
                        'A certificate from one tab was paired with another tab'
                    assert matched['process_scope'] == 'application' and matched['role'] == 'client'
                    assert peer['started'] <= matched['handshake_started_us'] <= matched['timestamp_us'] <= finished
                    assert not any(key in matched for key in ('local', 'remote', 'quic_original_dcid',
                        'signature_scheme', 'local_signature_scheme', 'session_resumed'))
                assert not available
                process.wait(20)
                assert process.returncode == 0, (directory / 'adapter.stderr').read_text(errors='replace')
                loaded = subprocess.run([str(importer), '--import-endpoints', str(directory),
                    str(directory / 'endpoints.db')], capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                assert loaded.returncode == 0, loaded.stderr.decode(errors='replace')
                with sqlite3.connect(directory / 'endpoints.db') as connection:
                    assert connection.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == 4
                    for (value,) in connection.execute('SELECT detail_json FROM endpoint_events'):
                        stored = json.loads(value)
                        assert 'matched_flow_id' not in stored and stored['process_role'] == 'unknown'
                return dict(browser=name, real_exchanges=4, certificate_pairing=True,
                    original_tab_closed=True, short_lived_tabs=12, continued_observation=True, native_import=True)
            finally:
                if control:
                    control.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(5)

    browsers = [('chrome', args.chrome.resolve())]
    if args.edge:
        browsers.append(('edge', args.edge.resolve()))
    quic = None
    for name, browser in browsers:
        quic = run(browser, name + '-quic', args.url)
        run(browser, name + '-tcp', args.url, ['--disable-quic'])
        if args.tabs:
            tab_cases.append(tabs(browser, name))

    # A contradictory QUIC version must be rejected by the real importer.
    invalid = work / 'invalid-quic-version'
    invalid.mkdir()
    quic['tls_version'] = 771
    (invalid / 'cipherazzi-endpoint-invalid.json').write_text(json.dumps(quic))
    rejected = subprocess.run([str(importer), '--import-endpoints', str(invalid), str(invalid / 'endpoints.db')],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert rejected.returncode == 1 and b'QUIC reports cannot select TLS versions older than TLS 1.3' in \
        rejected.stdout + rejected.stderr

    certificate, key = work / 'cert.pem', work / 'key.pem'
    generated = subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
        '-out', str(certificate), '-keyout', str(key)], capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert generated.returncode == 0, generated.stderr.decode(errors='replace')
    try:
        for version, label in [(ssl.TLSVersion.TLSv1_2, 'tls12'), (ssl.TLSVersion.TLSv1_3, 'tls13'),
            (ssl.TLSVersion.TLSv1_1, 'protocol')]:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = version
            context.set_ciphers('ALL:@SECLEVEL=0')
            context.load_cert_chain(certificate, key)
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(8)
            listener.settimeout(.2)
            stopped = threading.Event()
            errors = []
            rejections = []

            def serve():
                while not stopped.is_set():
                    try:
                        connection, _ = listener.accept()
                    except TimeoutError:
                        continue
                    try:
                        with connection:
                            connection.settimeout(5)
                            with context.wrap_socket(connection, server_side=True) as secure:
                                secure.recv(4096)
                                secure.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
                    except ssl.SSLError as error:
                        rejections.append(error.reason)
                    except Exception as error:
                        errors.append(str(error))

            worker = threading.Thread(target=serve)
            worker.start()
            try:
                for name, browser in browsers:
                    run(browser, name + '-' + label, f'https://localhost:{listener.getsockname()[1]}/',
                        ['--disable-quic'], 'ERR_SSL_VERSION_OR_CIPHER_MISMATCH' if label == 'protocol' else
                        'ERR_CERT_AUTHORITY_INVALID')
                if version == ssl.TLSVersion.TLSv1_3 and args.recovery:
                    recovery = recover(args.chrome.resolve(), f'https://localhost:{listener.getsockname()[1]}/')
                assert rejections and not errors, f'The real TLS server did not reject the exchanges: {errors}'
            finally:
                stopped.set()
                worker.join(6)
                listener.close()
                assert not worker.is_alive(), 'The owned fixture did not stop'
    finally:
        key.unlink(missing_ok=True)

    # Profiles and browser control arguments cannot redirect the adapter to another user's session.
    unowned = work / 'unowned-profile'
    unowned.mkdir()
    sentinel = unowned / 'sentinel.txt'
    sentinel.write_text('Unrelated profile content')
    guards = []
    for label, arguments, expected in [
        ('unowned-profile', ['--browser-profile', str(unowned)], 'Choose an empty browser profile'),
        ('control-override', ['--', '--remote-debugging-port=9222'], 'owns its profile and browser control options')]:
        directory = work / (label + '-reports')
        failed = subprocess.run([str(adapter), '--provider', 'chromium', '--spawn', str(args.chrome.resolve()),
            '--output', str(directory), '--duration', '1', *arguments], capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
        assert failed.returncode == 1 and expected in failed.stderr.decode(errors='replace')
        assert not list(directory.glob('cipherazzi-endpoint-*.json'))
        guards.append(label)
    assert sentinel.read_text() == 'Unrelated profile content'
    (work / 'results.json').write_text(json.dumps(dict(cases=cases, guards=guards,
        adapter_sha256=hashlib.sha256(adapter.read_bytes()).hexdigest(),
        invalid_quic_version_rejected=True, public_certificates_only=True,
        private_fixture_keys_deleted=True, navigation_recovery=recovery, multi_tab=tab_cases), indent=2))
    exchanges = len(cases) + (recovery['real_exchanges'] if recovery else 0) + \
        sum(case['real_exchanges'] for case in tab_cases)
    print(f'{exchanges} real Chromium exchanges passed native import, lifecycle, and profile-boundary checks.')


if __name__ == '__main__':
    main()
