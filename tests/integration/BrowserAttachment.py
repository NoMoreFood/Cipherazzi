import argparse
import ctypes as c
import http.server
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from pathlib import Path

from FirefoxBrowserAdapter import socket_owner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--chrome', required=True, type=Path)
    parser.add_argument('--firefox', required=True, type=Path)
    parser.add_argument('--openssl', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.output.resolve()
    work.mkdir(parents=True)
    adapter = root / 'tools/artifacts/build/bin/Release/Cipherazzi.EndpointAdapter.exe'
    importer = root / 'tools/artifacts/build/bin/Release/Cipherazzi.Tests.exe'
    configuration = work / 'openssl.cnf'
    configuration.write_text('[req]\ndistinguished_name=subject\n[subject]\n')
    certificate, key = work / 'cert.pem', work / 'key.pem'
    result = subprocess.run([str(args.openssl), 'req', '-config', str(configuration), '-x509', '-newkey',
        'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(certificate), '-days', '1', '-subj', '/CN=localhost'],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert result.returncode == 0, result.stderr
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    cases = []
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [c.c_uint, c.c_int, c.c_uint], c.c_void_p
    kernel.WaitForSingleObject.argtypes = [c.c_void_p, c.c_uint]
    kernel.QueryFullProcessImageNameW.argtypes = [c.c_void_p, c.c_uint, c.c_wchar_p, c.POINTER(c.c_uint)]
    kernel.GetProcessTimes.argtypes = [c.c_void_p] + [c.POINTER(c.c_uint64)] * 4
    kernel.CloseHandle.argtypes = [c.c_void_p]

    for provider, browser in (('chromium', args.chrome), ('firefox', args.firefox)):
        directory = work / provider
        profile, reports = directory / 'profile', directory / 'reports'
        profile.mkdir(parents=True)
        reports.mkdir()
        fired = threading.Event()
        loaded = threading.Event()
        requested = threading.Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/trigger':
                    body = b'true' if fired.is_set() else b'false'
                else:
                    loaded.set()
                    body = f'''<title>Existing session</title><script>
                        const timer = setInterval(async () => {{
                            if (await (await fetch('/trigger')).json()) {{clearInterval(timer);
                                fetch('https://127.0.0.1:{secure.server_port}/private-resource').catch(() => {{}});
                            }}
                        }}, 100);</script>'''.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        class SecureServer(http.server.ThreadingHTTPServer):
            def get_request(self):
                transport, address = super().get_request()
                requested.set()
                try:
                    transport.settimeout(5)
                    return context.wrap_socket(transport, server_side=True), address
                except Exception:
                    transport.close()
                    raise

        secure = SecureServer(('127.0.0.1', 0), Handler)
        page = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        for server in (page, secure):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        url = f'http://127.0.0.1:{page.server_port}/'
        if provider == 'chromium':
            arguments = ['--headless', '--no-first-run', '--no-default-browser-check', '--disable-sync',
                '--disable-background-networking', '--disable-quic', '--no-proxy-server',
                f'--user-data-dir={profile}', f'--remote-debugging-port={port}', url]
        else:
            preferences = {'marionette.port': port, 'network.proxy.type': 0, 'network.trr.mode': 5,
                'network.captive-portal-service.enabled': False, 'network.connectivity-service.enabled': False,
                'browser.shell.checkDefaultBrowser': False, 'browser.aboutwelcome.enabled': False,
                'services.settings.server': 'http://127.0.0.1:1'}
            (profile / 'user.js').write_text(''.join(f'user_pref({json.dumps(k)}, {json.dumps(v)});\n'
                for k, v in preferences.items()))
            arguments = ['--headless', '--no-remote', '--profile', str(profile), '--marionette',
                '--remote-allow-system-access', url]
        stdout = (directory / 'browser.stdout').open('wb')
        stderr = (directory / 'browser.stderr').open('wb')
        launched_us = time.time_ns() // 1000
        browser_process = subprocess.Popen([str(browser), *arguments], stdout=stdout, stderr=stderr,
            creationflags=subprocess.CREATE_NO_WINDOW)
        browser_handle = None
        owned_pid = browser_process.pid
        try:
            assert loaded.wait(30), 'The existing browser page did not load'
            deadline = time.monotonic() + 15
            while True:
                try:
                    pid = socket_owner(port, 0)
                    break
                except AssertionError:
                    assert time.monotonic() < deadline, 'The existing browser control listener did not start'
                    time.sleep(.1)
            handle = kernel.OpenProcess(0x101000, False, pid)
            assert handle, 'The browser process could not be inspected'
            name, size = c.create_unicode_buffer(32768), c.c_uint(32768)
            created, exited, system, user = (c.c_uint64() for _ in range(4))
            try:
                assert kernel.QueryFullProcessImageNameW(handle, 0, name, c.byref(size))
                assert Path(name.value).resolve() == browser.resolve(), 'Unexpected browser listener owner'
                assert kernel.GetProcessTimes(handle, c.byref(created), c.byref(exited), c.byref(system), c.byref(user))
                assert created.value // 10 - 11644473600000000 >= launched_us, 'The listener predates this fixture'
            except Exception:
                kernel.CloseHandle(handle)
                raise
            browser_handle, owned_pid = handle, pid
            mismatch = subprocess.run([str(adapter), '--provider', provider, '--pid', str(os.getpid()),
                '--browser-port', str(port), '--output', str(directory / 'mismatch'), '--duration', '1'],
                capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=20)
            assert mismatch.returncode != 0 and b'listener' in mismatch.stderr, mismatch.stderr
            command = [str(adapter), '--provider', provider, '--pid', str(pid), '--browser-port', str(port),
                '--output', str(reports), '--duration', '4']
            observer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                ready = threading.Event()
                output = []

                def consume():
                    for line in iter(observer.stdout.readline, b''):
                        output.append(line)
                        if b'Observing' in line:
                            ready.set()

                reader = threading.Thread(target=consume, daemon=True)
                reader.start()
                assert ready.wait(20), 'The observer did not attach'
                fired.set()
                observer.wait(25)
                reader.join(5)
                errors = observer.stderr.read()
                (directory / 'adapter.stdout').write_bytes(b''.join(output))
                (directory / 'adapter.stderr').write_bytes(errors)
                assert observer.returncode == 0, errors
            finally:
                if observer.poll() is None:
                    observer.kill()
                    observer.wait(10)
            assert requested.is_set(), 'The existing page did not make its TLS request'
            assert kernel.WaitForSingleObject(browser_handle, 0) == 258, 'Detaching closed the existing browser'
            values = [json.loads(path.read_text()) for path in reports.glob('cipherazzi-endpoint-*.json')]
            selected = [value for value in values if value.get('server_name') == '127.0.0.1']
            assert len(selected) == 1 and selected[0]['success'] is False, values
            assert selected[0]['peer_verified'] is False and 'private-' not in json.dumps(values), values
            imported = subprocess.run([str(importer), '--import-endpoints', str(reports), str(directory / 'events.db')],
                capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            assert imported.returncode == 0, imported.stderr
            with sqlite3.connect(directory / 'events.db') as database:
                assert database.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == len(values)
            cases.append(dict(provider=provider, reports=len(values),
                browser_survived=True, pid_mismatch_rejected=True))
        finally:
            if ((browser_handle and kernel.WaitForSingleObject(browser_handle, 0) == 258) or
                (not browser_handle and browser_process.poll() is None)):
                subprocess.run(['taskkill', '/pid', str(owned_pid), '/t', '/f'], capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=20)
            if browser_handle:
                kernel.CloseHandle(browser_handle)
            stdout.close()
            stderr.close()
            for server in (page, secure):
                server.shutdown()
                server.server_close()
    (work / 'results.json').write_text(json.dumps(cases, indent=2))
    print(json.dumps(cases, indent=2))


if __name__ == '__main__':
    main()
