import argparse
import base64
import ctypes as c
import json
import os
import re
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from pathlib import Path


class Item(c.Structure):
    _fields_ = [('type', c.c_uint), ('data', c.c_void_p), ('length', c.c_uint)]


class Trust(c.Structure):
    _fields_ = [('ssl', c.c_uint), ('email', c.c_uint), ('signing', c.c_uint)]


def trust_certificate(profile, library, der):
    with os.add_dll_directory(str(library)):
        nss = c.CDLL(str(library / 'nss3.dll'))

        def api(name, result, *arguments):
            function = getattr(nss, name)
            function.restype, function.argtypes = result, list(arguments)
            return function

        def require(result):
            assert result == 0, f'NSS profile initialization failed: {api("PR_GetError", c.c_int)()}'

        require(api('NSS_InitReadWrite', c.c_int, c.c_char_p)(('sql:' + str(profile)).encode()))
        database = api('CERT_GetDefaultCertDB', c.c_void_p)()
        encoded = c.create_string_buffer(der)
        item = Item(0, c.cast(encoded, c.c_void_p), len(der))
        certificate = api('CERT_NewTempCertificate', c.c_void_p, c.c_void_p, c.POINTER(Item),
            c.c_char_p, c.c_int, c.c_int)(database, c.byref(item), b'Cipherazzi browser fixture', 0, 1)
        assert certificate, 'Public fixture certificate import failed'
        try:
            trust = Trust()
            require(api('CERT_DecodeTrustString', c.c_int, c.POINTER(Trust), c.c_char_p)(c.byref(trust), b'CT,,'))
            slot = api('PK11_GetInternalKeySlot', c.c_void_p)()
            assert slot, 'NSS profile certificate slot unavailable'
            try:
                if api('PK11_NeedUserInit', c.c_int, c.c_void_p)(slot):
                    require(api('PK11_InitPin', c.c_int, c.c_void_p, c.c_char_p, c.c_char_p)(slot, None, b''))
                require(api('PK11_ImportCert', c.c_int, c.c_void_p, c.c_void_p, c.c_ulong,
                    c.c_char_p, c.c_int)(slot, certificate, 0, b'Cipherazzi browser fixture', 0))
                require(api('CERT_ChangeCertTrust', c.c_int, c.c_void_p, c.c_void_p,
                    c.POINTER(Trust))(database, certificate, c.byref(trust)))
            finally:
                api('PK11_FreeSlot', None, c.c_void_p)(slot)
        finally:
            api('CERT_DestroyCertificate', None, c.c_void_p)(certificate)
            require(api('NSS_Shutdown', c.c_int)())


class Marionette:
    def __init__(self, port, observer):
        deadline = time.monotonic() + 30
        while True:
            try:
                self.connection = socket.create_connection(('127.0.0.1', port), 1)
                break
            except OSError:
                assert time.monotonic() < deadline and observer.poll() is None, 'Browser startup failed'
                time.sleep(0.05)
        self.connection.settimeout(30)
        self.sequence = 0
        hello = self.receive()
        assert hello['applicationType'] == 'gecko' and hello['marionetteProtocol'] >= 3

    def receive(self):
        prefix = b''
        while not prefix.endswith(b':'):
            value = self.connection.recv(1)
            assert value and len(prefix) < 10, 'Invalid browser automation response'
            prefix += value
        remaining, body = int(prefix[:-1]), b''
        while remaining:
            value = self.connection.recv(remaining)
            assert value, 'Browser automation connection closed'
            body += value
            remaining -= len(value)
        return json.loads(body)

    def command(self, name, arguments=None, expected_error=None):
        self.sequence += 1
        body = json.dumps([0, self.sequence, name, arguments or {}]).encode()
        self.connection.sendall(str(len(body)).encode() + b':' + body)
        response = self.receive()
        assert response[:2] == [1, self.sequence], response
        if expected_error:
            assert response[2], response
        else:
            assert response[2] is None, response
        return response[3]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--firefox', required=True)
    parser.add_argument('--openssl', required=True)
    root = Path(__file__).resolve().parent.parent
    parser.add_argument('--adapter', default=str(root / 'build/bin/Release/Cipherazzi.EndpointAdapter.exe'))
    parser.add_argument('--output', required=True)
    parser.add_argument('--single-process', action='store_true')
    parser.add_argument('--allow-unobserved-socket', action='store_true')
    parser.add_argument('--socket-process', action='store_true')
    parser.add_argument('--browser-api-script', type=Path)
    args = parser.parse_args()
    firefox = Path(args.firefox).resolve()
    work = Path(args.output).resolve()
    work.mkdir(parents=True)
    profile, reports = work / 'profile', work / 'reports'
    profile.mkdir()
    reports.mkdir()
    certificate, key = work / 'cert.pem', work / 'key.pem'
    authority, authority_key = work / 'ca.pem', work / 'ca-key.pem'
    generated = subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=Cipherazzi browser root', '-keyout', str(authority_key), '-out', str(authority)],
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert generated.returncode == 0, generated.stderr.decode(errors='replace')
    generated = subprocess.run([args.openssl, 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
        '-keyout', str(key), '-out', str(work / 'server.csr')], capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert generated.returncode == 0, generated.stderr.decode(errors='replace')
    extensions = 'basicConstraints=critical,CA:FALSE\n' \
        'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
    (work / 'server.ext').write_text(extensions +
        'subjectAltName=DNS:localhost,IP:127.0.0.1\n')
    generated = subprocess.run([args.openssl, 'x509', '-req', '-in', str(work / 'server.csr'), '-CA',
        str(authority), '-CAkey', str(authority_key), '-CAcreateserial', '-days', '1', '-extfile',
        str(work / 'server.ext'), '-out', str(certificate)], capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert generated.returncode == 0, generated.stderr.decode(errors='replace')
    (work / 'wrong-server.ext').write_text(extensions + 'subjectAltName=DNS:wrong-host.invalid\n')
    wrong_certificate = work / 'wrong-cert.pem'
    generated = subprocess.run([args.openssl, 'x509', '-req', '-in', str(work / 'server.csr'), '-CA',
        str(authority), '-CAkey', str(authority_key), '-days', '1', '-extfile',
        str(work / 'wrong-server.ext'), '-out', str(wrong_certificate)], capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert generated.returncode == 0, generated.stderr.decode(errors='replace')
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
    trust_certificate(profile, firefox.parent, ssl.PEM_cert_to_DER_cert(authority.read_text()))
    with socket.socket() as available:
        available.bind(('127.0.0.1', 0))
        control_port = available.getsockname()[1]
    preferences = {
        'marionette.port': control_port, 'browser.startup.page': 0,
        'browser.shell.checkDefaultBrowser': False, 'browser.aboutwelcome.enabled': False,
        'browser.newtabpage.enabled': False, 'app.update.enabled': False,
        'app.normandy.enabled': False, 'app.shield.optoutstudies.enabled': False,
        'datareporting.healthreport.uploadEnabled': False, 'datareporting.policy.dataSubmissionEnabled': False,
        'toolkit.telemetry.enabled': False, 'toolkit.telemetry.server': '',
        'network.captive-portal-service.enabled': False, 'network.connectivity-service.enabled': False,
        'network.dns.disablePrefetch': True, 'network.prefetch-next': False,
        'network.proxy.type': 0, 'network.trr.mode': 5, 'extensions.blocklist.enabled': False,
        'browser.safebrowsing.phishing.enabled': False, 'browser.safebrowsing.malware.enabled': False,
        'security.OCSP.enabled': 0, 'security.remote_settings.intermediates.enabled': False,
        'services.settings.server': 'http://127.0.0.1:1',
    }
    if args.socket_process:
        preferences['network.http.network_access_on_socket_process.enabled'] = True
    (profile / 'user.js').write_text(''.join(f'user_pref({json.dumps(name)}, {json.dumps(value)});\n'
        for name, value in preferences.items()))
    observations, workers, listeners, cases = [], [], [], []

    def serve(listener, context, version, port):
        peer = None
        try:
            raw, peer = listener.accept()
            with raw, context.wrap_socket(raw, server_side=True) as connection:
                request = connection.recv(16384)
                body = b'<html><title>Cipherazzi browser fixture</title><body>' \
                    b'cipherazzi-private-application-data-sentinel</body></html>'
                connection.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n'
                    + f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
                observations.append(dict(version=version, port=port, peer=peer, success=True,
                    tls=connection.version(), cipher=connection.cipher()[0], alpn=connection.selected_alpn_protocol(),
                    request_received=request.startswith(b'GET /')))
        except Exception as error:
            observations.append(dict(version=version, port=port, peer=peer, success=False, error=str(error)))
        finally:
            listener.close()

    for version, success in ((ssl.TLSVersion.TLSv1_2, True), (ssl.TLSVersion.TLSv1_3, True),
        (ssl.TLSVersion.TLSv1_3, False)):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = version
        context.load_cert_chain(certificate if success else wrong_certificate, key)
        context.set_alpn_protocols(['http/1.1'])
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        listener.settimeout(40)
        listeners.append(listener)
        port = listener.getsockname()[1]
        cases.append(dict(version=int(version), success=success, port=port))
        worker = threading.Thread(target=serve, args=(listener, context, int(version), port), daemon=True)
        workers.append(worker)
        worker.start()

    browser = None
    with (work / 'adapter.stdout').open('wb') as stdout, (work / 'adapter.stderr').open('wb') as stderr:
        observer = subprocess.Popen([args.adapter, '--provider', 'nss', '--output', str(reports),
            '--duration', '60', *(['--no-children'] if args.single_process else []),
            '--spawn', str(firefox), '--', '--headless', '--no-remote', '--profile',
            str(profile), '--marionette', *(['--remote-allow-system-access'] if args.browser_api_script else []),
            'about:blank'], stdout=stdout, stderr=stderr,
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            browser = Marionette(control_port, observer)
            capabilities = browser.command('WebDriver:NewSession', {'capabilities': {'alwaysMatch': {
                'acceptInsecureCerts': False}}})
            (work / 'browser.json').write_text(json.dumps(capabilities, indent=2))
            if args.browser_api_script:
                browser.command('Marionette:SetContext', {'value': 'chrome'})
                browser.command('WebDriver:ExecuteScript', {'script': args.browser_api_script.read_text(),
                    'args': [], 'sandbox': 'cipherazzi', 'newSandbox': False})
                browser.command('Marionette:SetContext', {'value': 'content'})
            for case in cases:
                browser.command('WebDriver:Navigate', {'url': f'https://localhost:{case["port"]}/'},
                    expected_error=not case['success'])
                if case['success']:
                    title = browser.command('WebDriver:GetTitle')
                    assert title['value'] == 'Cipherazzi browser fixture', title
            if args.browser_api_script:
                browser.command('Marionette:SetContext', {'value': 'chrome'})
                captured = browser.command('WebDriver:ExecuteScript', {'script':
                    'return globalThis.cipherazziCapture.stop();', 'args': [], 'sandbox': 'cipherazzi',
                    'newSandbox': False})
                (work / 'browser-api.json').write_text(json.dumps(captured, indent=2))
                browser.command('Marionette:SetContext', {'value': 'content'})
            unobserved = []
            kernel = c.WinDLL('kernel32', use_last_error=True)
            kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [c.c_uint, c.c_int, c.c_uint], c.c_void_p
            kernel.WaitForSingleObject.argtypes, kernel.WaitForSingleObject.restype = [c.c_void_p, c.c_uint], c.c_uint
            kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [c.c_void_p], c.c_int
            diagnostics = (work / 'adapter.stderr').read_text(errors='replace')
            protections = []
            kernel.GetProcessMitigationPolicy.argtypes = [c.c_void_p, c.c_int, c.c_void_p, c.c_size_t]
            kernel.GetProcessMitigationPolicy.restype = c.c_int
            for identifier in re.findall(r'PID (\d+) could not be observed:', diagnostics):
                handle = kernel.OpenProcess(0x101000, 0, int(identifier))
                assert handle, 'The unobserved browser child could not be checked'
                try:
                    assert kernel.WaitForSingleObject(handle, 0) == 258, 'The observation attempt stopped a browser child'
                    policies = {}
                    for policy, name in ((2, 'dynamic_code'), (8, 'binary_signature'), (10, 'image_load')):
                        flags = c.c_uint()
                        assert kernel.GetProcessMitigationPolicy(handle, policy, c.byref(flags), c.sizeof(flags)), \
                            'The browser child protection policy could not be read'
                        policies[name] = flags.value
                    protections.append(dict(pid=int(identifier), policies=policies))
                    unobserved.append(int(identifier))
                finally:
                    kernel.CloseHandle(handle)
            (work / 'protections.json').write_text(json.dumps(protections, indent=2))
            browser.command('Marionette:Quit', {'flags': ['eForceQuit']})
            status = observer.wait(20)
            assert status == 0 or status == 2 and args.allow_unobserved_socket, \
                (status, (work / 'adapter.stderr').read_text(errors='replace'))
        finally:
            if browser:
                try:
                    browser.command('Marionette:Quit', {'flags': ['eForceQuit']})
                except (OSError, AssertionError):
                    pass
                browser.connection.close()
            if observer.poll() is None:
                observer.kill()
                observer.wait(5)
            for listener in listeners:
                listener.close()
            for worker in workers:
                worker.join(3)
            (work / 'server.json').write_text(json.dumps(observations, indent=2))
            key.unlink(missing_ok=True)
            authority_key.unlink(missing_ok=True)
    (work / 'server.json').write_text(json.dumps(observations, indent=2))
    evidence = [json.loads(path.read_text()) for path in reports.glob('*.json')]
    print(json.dumps({'server': observations, 'reports': len(evidence),
        'report_pids': sorted({value['pid'] for value in evidence})}, indent=2))
    assert len(observations) == 3
    assert all(value.get('request_received') for value in observations if value['success']), observations
    verified = []
    for observed in observations:
        expected = next(case for case in cases if case['port'] == observed['port'])
        assert observed['success'] == expected['success'], observed
        if not observed['success']:
            assert 'CERTIFICATE' in observed['error'], observed
        matches = [value for value in evidence if value['remote']['port'] == observed['port'] and
            value['local']['port'] == observed['peer'][1]]
        assert len(matches) == 1, f'Browser TLS {observed["version"]} evidence missing or duplicated: {len(matches)}'
        value = matches[0]
        assert value['provider'] == 'NSS' and value['process_name'] == 'firefox.exe'
        assert value['pid'] == capabilities['capabilities']['moz:processID']
        assert Path(value['process_path']) == firefox
        assert value['success'] == observed['success'] and value['peer_verified'] == observed['success']
        assert value['server_name'] == 'localhost'
        assert value['process_started_us'] <= value['handshake_started_us'] <= value['timestamp_us']
        if observed['success']:
            assert value['tls_version'] == observed['version'] and value['group_id'] == 29
            assert value['selected_alpn'] == observed['alpn'] == 'http/1.1'
            assert value['signature_scheme'] == 0x0804
            assert base64.b64decode(value['server_certificates_der'][0]) == der
        assert 'cipherazzi-private-application-data-sentinel' not in json.dumps(value)
        assert 'PRIVATE KEY' not in json.dumps(value)
        verified.append(dict(version=observed['version'], success=observed['success'],
            process_identity=True, socket_identity=True, certificate=observed['success'], application_data_excluded=True))
    imported = work / 'import'
    imported.mkdir()
    for index, observed in enumerate(observations):
        value = next(value for value in evidence if value['remote']['port'] == observed['port'] and
            value['local']['port'] == observed['peer'][1])
        (imported / f'firefox-{index}.json').write_text(json.dumps(value))
    database = work / 'firefox.db'
    imported_result = subprocess.run([str(root / 'build/bin/Release/Cipherazzi.Tests.exe'), '--import-endpoints',
        str(imported), str(database)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert imported_result.returncode == 0, imported_result.stderr.decode(errors='replace')
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == 3
        stored = [json.loads(row[0]) for row in connection.execute('SELECT detail_json FROM endpoint_events')]
        assert all(value['assessment']['server_name'] == 'localhost' for value in stored)
        assert all(value['correlation'].startswith('Unmatched socket') for value in stored)
        assert connection.execute('SELECT der FROM certificates').fetchone()[0] == der
    (work / 'results.json').write_text(json.dumps(dict(browser=capabilities['capabilities']['browserVersion'],
        cases=verified, reports=len(evidence), native_import=True, status=status,
        unobserved_socket_process=status == 2, unobserved_children_alive=unobserved), indent=2))


if __name__ == '__main__':
    main()
