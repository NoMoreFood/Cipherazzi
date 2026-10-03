import argparse
import asyncio
import base64
import hashlib
import http.server
import ipaddress
import json
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--openssl', required=True, type=Path)
    parser.add_argument('--schannel', required=True, type=Path)
    parser.add_argument('--chrome', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--require-preconnect', action='store_true')
    parser.add_argument('--http3', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.output.resolve()
    work.mkdir(parents=True)
    adapter = root / 'tools/artifacts/build/bin/Release/Cipherazzi.EndpointAdapter.exe'
    importer = root / 'tools/artifacts/build/bin/Release/Cipherazzi.Tests.exe'
    certificate, key = work / 'cert.pem', work / 'key.pem'
    configuration = work / 'openssl.cnf'
    configuration.write_text('[req]\ndistinguished_name=subject\n[subject]\n')

    def run(command, **options):
        return subprocess.run([str(value) for value in command], capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW, timeout=60, **options)

    generated = run([args.openssl, 'req', '-config', configuration, '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', key, '-out', certificate, '-days', '1', '-subj', '/CN=coverage.test'])
    assert generated.returncode == 0, generated.stderr
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
    public = run([args.openssl, 'x509', '-in', certificate, '-pubkey', '-noout']).stdout
    spki = run([args.openssl, 'pkey', '-pubin', '-outform', 'DER'], input=public).stdout
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    results = []

    def observe(name, provider, application, extra=()):
        directory = work / name
        directory.mkdir()
        observed = run([adapter, '--provider', provider, '--spawn', application[0], '--output', directory,
            *extra, '--', *application[1:]])
        (directory / 'adapter.stdout').write_bytes(observed.stdout)
        (directory / 'adapter.stderr').write_bytes(observed.stderr)
        assert observed.returncode == 0, (name, observed.stdout, observed.stderr)
        reports = [json.loads(path.read_text()) for path in directory.glob('cipherazzi-endpoint-*.json')]
        assert reports, (name, observed.stdout, observed.stderr)
        imported = run([importer, '--import-endpoints', directory, directory / 'endpoints.db'])
        assert imported.returncode == 0, imported.stderr
        with sqlite3.connect(directory / 'endpoints.db') as connection:
            assert connection.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == len(reports)
        return reports

    # The application exports no reports: all evidence must come from public SSPI instrumentation.
    for version in ('TLSv1.2', 'TLSv1.3'):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        context.set_alpn_protocols(['h2'])
        selected = ssl.TLSVersion.TLSv1_2 if version == 'TLSv1.2' else ssl.TLSVersion.TLSv1_3
        context.minimum_version = context.maximum_version = selected
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.settimeout(30)
        port = server.getsockname()[1]
        failures = []
        peer_ports = []

        def echo():
            try:
                raw, peer = server.accept()
                peer_ports.append(peer[1])
                with raw, context.wrap_socket(raw, server_side=True) as secured:
                    secured.settimeout(15)
                    assert secured.recv(1) == b'*'
                    secured.sendall(b'*')
            except Exception as error:
                failures.append(str(error))

        worker = threading.Thread(target=echo, daemon=True)
        worker.start()
        try:
            reports = observe('schannel-' + version, 'schannel', [args.schannel,
                str(port), version, 'coverage.test', '127.0.0.1'])
        finally:
            worker.join(30)
            server.close()
        assert not worker.is_alive() and not failures, failures
        assert len(reports) == 1, reports
        report = reports[0]
        assert report['provider'] == 'Schannel' and report['success']
        assert report['tls_version'] == (771 if version == 'TLSv1.2' else 772) and report['cipher_id']
        assert report['selected_alpn'] == 'h2' and report['server_name'] == 'coverage.test'
        assert base64.b64decode(report['server_certificates_der'][0]) == der
        assert report['remote']['port'] == port, report
        assert report['local']['port'] == peer_ports[0] and report['group_id'] == 29, report
        for field in ('local', 'remote'):
            address = ipaddress.ip_address(report[field]['address'])
            assert (getattr(address, 'ipv4_mapped', None) or address) == ipaddress.ip_address('127.0.0.1')
        assert 'peer_verified' not in report, 'The permissive application callback has no observable trust result'
        if version == 'TLSv1.2':
            assert report['signature_scheme'] == 0x0804, report
        results.append(dict(case='Schannel ' + version, reports=len(reports), native_import=True))

    # Separate origins expose image, fetch, worker, and iframe handshakes with public connection timing.
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            body = self.server.body
            if hasattr(self.server, 'requested'):
                self.server.requested.add(self.path)
            self.send_response(404 if self.path == '/private-not-found' else 200)
            self.send_header('Content-Type', self.server.content_type)
            if self.path != '/private-cors':
                self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    context.set_alpn_protocols(['http/1.1'])

    class SecureServer(http.server.ThreadingHTTPServer):
        def get_request(self):
            transport, address = super().get_request()
            try:
                transport.settimeout(10)
                # Keep TLS in progress while the browser assigns speculative sockets to requests.
                time.sleep(self.delay)
                return getattr(self, 'context', context).wrap_socket(transport, server_side=True), address
            except Exception:
                transport.close()
                raise

    servers = []
    for index in range(6):
        server = SecureServer(('127.0.0.1', 0), Handler)
        server.delay = .25 if index < 5 else 0
        server.body, server.content_type = b'private-response-body', 'text/plain'
        servers.append(server)
    urls = [f'https://127.0.0.1:{server.server_port}/' for server in servers]
    servers[0].content_type = 'text/html'
    servers[0].body = f'''<!doctype html><title>Coverage fixture</title>
        <link rel="preconnect" href="{urls[5]}" crossorigin>
        <img src="{urls[1]}private-image-path">
        <script>fetch('{urls[2]}private-fetch-path');
        setTimeout(async () => {{await fetch('{urls[5]}private-preconnect-path');
            await fetch('{urls[5]}private-reused-path');}}, 2000);
        setTimeout(() => {{const frame = document.createElement('iframe');
            frame.src = atob('{base64.b64encode((urls[4] + 'private-frame-path').encode()).decode()}');
            document.body.appendChild(frame);}}, 500);
        new Worker(URL.createObjectURL(new Blob(["fetch('{urls[3]}private-worker-path')"],
            {{type:'text/javascript'}})));</script>'''.encode()
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        reports = observe('chromium-resources', 'chromium', [args.chrome, '--headless', '--disable-quic',
            '--disable-background-networking', '--disable-sync', '--ignore-certificate-errors-spki-list=' + pin],
            ['--duration', '6', '--url', urls[0]])
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    ports = {report.get('remote', {}).get('port') for report in reports}
    assert {server.server_port for server in servers[1:]} <= ports, (urls, ports, reports)
    for report in reports:
        assert report['success'] and report['process_scope'] == 'application' and 'local' not in report
        assert report['cipher_id'] and report['tls_version'] == 772
        assert 'private-' not in json.dumps(report), 'Application content was retained'
    preconnected = [report for report in reports if report.get('remote', {}).get('port') == servers[5].server_port]
    assert len(preconnected) == 1, preconnected
    if args.require_preconnect:
        assert preconnected[0].get('observation') == 'connection', preconnected
    for report in reports:
        if report.get('observation') == 'connection':
            assert 'handshake_started_us' not in report, report
    assert len(reports) == len(servers), reports
    results.append(dict(case='Chromium image, fetch, worker, iframe', reports=len(reports), native_import=True))

    # Untrusted subresources fail independently; successful HTTP errors must not become TLS failures.
    rejected_certificate, rejected_key = work / 'rejected.pem', work / 'rejected-key.pem'
    generated = run([args.openssl, 'req', '-config', configuration, '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', rejected_key, '-out', rejected_certificate, '-days', '1', '-subj', '/CN=rejected.test'])
    assert generated.returncode == 0, generated.stderr
    rejected_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    rejected_context.load_cert_chain(rejected_certificate, rejected_key)
    rejected = SecureServer(('127.0.0.1', 0), Handler)
    rejected.context, rejected.delay = rejected_context, 0
    incompatible_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    incompatible_context.load_cert_chain(certificate, key)
    incompatible_context.minimum_version = incompatible_context.maximum_version = ssl.TLSVersion.TLSv1_2
    incompatible_context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256')
    incompatible = SecureServer(('127.0.0.1', 0), Handler)
    incompatible.context, incompatible.delay = incompatible_context, 0
    page = SecureServer(('127.0.0.1', 0), Handler)
    page.delay, page.content_type = .25, 'text/html'
    page.requested = set()
    failed_urls = {kind: f'https://{kind}.coverage.test:{rejected.server_port}/private-{kind}-path'
        for kind in ('image', 'fetch', 'iframe', 'worker')}
    page.body = f'''<!doctype html><title>Failure fixture</title>
        <img src="{failed_urls['image']}"><iframe src="{failed_urls['iframe']}"></iframe>
        <script>fetch('{failed_urls['fetch']}').catch(() => {{}});
        fetch('https://tls.coverage.test:{incompatible.server_port}/private-tls-path').catch(() => {{}});
        fetch('/private-not-found').catch(() => {{}});
        fetch('https://negative.coverage.test:{page.server_port}/private-cors').catch(() => {{}});
        new Worker(URL.createObjectURL(new Blob(["fetch('{failed_urls['worker']}').catch(() => {{}})"],
            {{type:'text/javascript'}})));</script>'''.encode()
    for server in (page, rejected, incompatible):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        reports = observe('chromium-resource-failures', 'chromium', [args.chrome, '--headless', '--disable-quic',
            '--disable-background-networking', '--disable-sync', '--no-proxy-server',
            '--host-resolver-rules=MAP *.coverage.test 127.0.0.1', '--ignore-certificate-errors-spki-list=' + pin],
            ['--duration', '6', '--url', f'https://127.0.0.1:{page.server_port}/'])
        failures = [report for report in reports if not report['success']]
        assert len(failures) == len(failed_urls) + 1, reports
        assert {'/private-not-found', '/private-cors'} <= page.requested, page.requested
        assert {report['server_name'] for report in failures} == {
            'tls.coverage.test', *(kind + '.coverage.test' for kind in failed_urls)}
        for report in failures:
            if report['server_name'] == 'tls.coverage.test':
                assert report['error_name'].startswith('ERR_SSL_') and 'peer_verified' not in report, report
            else:
                assert report['error_name'].startswith('ERR_CERT_') and report['peer_verified'] is False, report
            assert report['timestamp_us'] >= report['handshake_started_us'] > report['process_started_us'], report
            assert 'private-' not in json.dumps(report) and 'remote' not in report and 'local' not in report
        navigation = observe('chromium-navigation-failure', 'chromium', [args.chrome, '--headless', '--disable-quic',
            '--disable-background-networking', '--disable-sync', '--no-proxy-server',
            '--host-resolver-rules=MAP *.coverage.test 127.0.0.1'],
            ['--duration', '3', '--url', failed_urls['fetch']])
        assert len(navigation) == 1 and not navigation[0]['success'], navigation
        results.append(dict(case='Chromium image, fetch, worker, iframe failures', reports=len(failures),
            navigation_failures=len(navigation), native_import=True))
    finally:
        for server in (page, rejected, incompatible):
            server.shutdown()
            server.server_close()

    if args.http3:
        from aioquic.asyncio import QuicConnectionProtocol, serve
        from aioquic.h3.connection import H3Connection
        from aioquic.h3.events import HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration

        class Protocol(QuicConnectionProtocol):
            def __init__(self, *values, **options):
                super().__init__(*values, **options)
                self.http = H3Connection(self._quic)

            def quic_event_received(self, event):
                for item in self.http.handle_event(event):
                    if isinstance(item, HeadersReceived):
                        self.http.send_headers(item.stream_id, [(b':status', b'200'),
                            (b'access-control-allow-origin', b'*')])
                        self.http.send_data(item.stream_id, b'private-http3-body', end_stream=True)
                        self.transmit()

        async def http3():
            configuration = QuicConfiguration(is_client=False, alpn_protocols=['h3'])
            configuration.load_cert_chain(certificate, key)
            quic = await serve('127.0.0.1', 0, configuration=configuration, create_protocol=Protocol)
            port = quic._transport.get_extra_info('sockname')[1]
            page = SecureServer(('127.0.0.1', 0), Handler)
            page.delay, page.content_type = .25, 'text/html'
            page.body = f"<script>fetch('https://127.0.0.1:{port}/private-http3-path')</script>".encode()
            threading.Thread(target=page.serve_forever, daemon=True).start()
            try:
                reports = await asyncio.to_thread(observe, 'chromium-http3', 'chromium',
                    [args.chrome, '--headless', '--enable-quic', '--disable-background-networking', '--disable-sync',
                        f'--origin-to-force-quic-on=127.0.0.1:{port}', '--ignore-certificate-errors-spki-list=' + pin],
                    ['--duration', '6', '--url', f'https://127.0.0.1:{page.server_port}/'])
            finally:
                page.shutdown()
                page.server_close()
                quic.close()
            selected = [report for report in reports if report.get('remote', {}).get('port') == port]
            assert len(selected) == 1, reports
            report = selected[0]
            assert report['transport'] == 'QUIC' and report['selected_alpn'] == 'h3' and report['success'], report
            assert report.get('tls_version', 0) in (0, 772) and report['cipher_id']
            assert 'local' not in report and 'quic_original_dcid' not in report
            assert 'private-' not in json.dumps(reports)
            results.append(dict(case='Chromium HTTP/3 resource', reports=len(reports), native_import=True))

        asyncio.run(http3())
    (work / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
