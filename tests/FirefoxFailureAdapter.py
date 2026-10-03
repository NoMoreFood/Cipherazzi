import argparse
import base64
import ctypes as c
import json
import socket
import sqlite3
import ssl
import subprocess
import threading
from pathlib import Path

from FirefoxAdapter import trust_certificate
from FirefoxBrowserAdapter import socket_owner


def publish_failure(publisher, database, directory, completed=False):
    directory.mkdir(parents=True)
    policies = directory / 'policies.xml'
    policies.write_text('<cipherazzi><policies>'
        '<policy name="Completed TLS" process="firefox.exe" requirePostQuantumKeyExchange="False" />'
        '<policy name="Peer verification" process="firefox.exe" requirePostQuantumKeyExchange="False" '
        'requireEndpointCompletion="False" requirePeerVerification="True" />'
        '<policy name="Post-quantum keys" process="firefox.exe" requireEndpointCompletion="False" />'
        '</policies></cipherazzi>')
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(2)
    listener.settimeout(0.2)
    received, errors = [], []
    stopped, delivered = threading.Event(), threading.Event()

    def receive():
        try:
            while not stopped.is_set():
                messages = []
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(25)
                    while True:
                        prefix = b''
                        while not prefix.endswith(b' '):
                            byte = connection.recv(1)
                            if not byte:
                                assert not prefix, 'The publisher left an incomplete syslog frame'
                                break
                            assert byte.isdigit() or byte == b' ' and prefix, 'Invalid syslog length'
                            assert len(prefix) < 8, 'The syslog length exceeded its bound'
                            prefix += byte
                        if not prefix:
                            break
                        length = int(prefix[:-1])
                        assert 0 < length <= 32768, 'The syslog event exceeded its bound'
                        message = b''
                        while len(message) < length:
                            part = connection.recv(length - len(message))
                            assert part, 'The publisher truncated a syslog event'
                            message += part
                        messages.append(json.loads(message[message.index(b'{'):]))
                received.append(messages)
                delivered.set()
        except Exception as error:
            errors.append(str(error))

    worker = threading.Thread(target=receive, daemon=True)
    worker.start()
    try:
        for attempt in range(2):
            result = subprocess.run([str(publisher), '--source', str(database), '--policies', str(policies),
                '--events', 'policies', '--syslog', f'tcp://127.0.0.1:{listener.getsockname()[1]}',
                '--allow-plaintext-syslog', '--once'], capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            (directory / f'publisher-{attempt}.stdout').write_bytes(result.stdout)
            (directory / f'publisher-{attempt}.stderr').write_bytes(result.stderr)
            assert result.returncode == 0, result.stderr.decode(errors='replace')
            if attempt == 0:
                assert delivered.wait(5), 'The initial policy results were not received'
        stopped.set()
        worker.join(5)
        assert not worker.is_alive() and not errors, errors
        assert len(received[0]) == 3 and not any(received[1:]), 'Policy delivery omitted results or replayed results'
        rows = {value['payload']['policy']: value['payload'] for value in received[0]}
        assert rows['Completed TLS']['status'] == rows['Peer verification']['status'] == \
            ('Pass' if completed else 'Violation')
        assert rows['Post-quantum keys']['status'] == ('Violation' if completed else 'Insufficient evidence')
        if not completed:
            assert any('unverified' in issue['message'] for issue in rows['Peer verification']['issues'])
        assert all(value['type'] == 'policy' and value['payload']['evidence_source'] == 'Endpoint'
            and value['payload']['endpoint_event_id'] and not value['payload']['flow_id'] for value in received[0])
        assert all(not row['emitting_process'] and
            Path(row['client_process']).name == 'firefox.exe' and not row['server_process'] for row in rows.values())
        (directory / 'events.json').write_text(json.dumps(received[0], indent=2))
        result = dict(actual_policy_delivery=True, emitting_application_retained=True, socket_process_role_retained=True,
            peer_verification_evaluated=True, reported_algorithms_evaluated=True,
            acknowledged_results_not_replayed=True)
        (directory / 'results.json').write_text(json.dumps(result, indent=2))
        return result
    finally:
        stopped.set()
        listener.close()
        worker.join(2)


def protections(pid):
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [c.c_uint, c.c_int, c.c_uint], c.c_void_p
    kernel.CloseHandle.argtypes = [c.c_void_p]
    kernel.GetProcessMitigationPolicy.argtypes = [c.c_void_p, c.c_int, c.c_void_p, c.c_size_t]
    handle = kernel.OpenProcess(0x1000, 0, pid)
    assert handle, 'The protected socket process could not be inspected'
    try:
        dynamic, signature = c.c_uint(), c.c_uint()
        assert kernel.GetProcessMitigationPolicy(handle, 2, c.byref(dynamic), 4)
        assert kernel.GetProcessMitigationPolicy(handle, 8, c.byref(signature), 4)
        assert dynamic.value & 1 and signature.value & 1, 'Browser process protection changed'
        return dict(dynamic_code=dynamic.value, signature=signature.value)
    finally:
        kernel.CloseHandle(handle)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--firefox', required=True, type=Path)
    parser.add_argument('--openssl', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--publisher', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    work = args.output.resolve()
    work.mkdir(parents=True)
    firefox = args.firefox.resolve()
    authority, ca_key, certificate, key = [work / name for name in ('ca.pem', 'ca-key.pem', 'cert.pem', 'key.pem')]
    (work / 'server.ext').write_text('basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
        'subjectAltName=DNS:wrong-host.invalid\n')
    (work / 'valid.ext').write_text((work / 'server.ext').read_text().replace('wrong-host.invalid', 'localhost'))
    valid_certificate = work / 'valid-cert.pem'
    results = []
    try:
        commands = [
            ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Cipherazzi failure root',
                '-keyout', str(ca_key), '-out', str(authority)],
            ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=wrong-host.invalid', '-keyout', str(key),
                '-out', str(work / 'server.csr')],
            ['x509', '-req', '-in', str(work / 'server.csr'), '-CA', str(authority), '-CAkey', str(ca_key),
                '-CAcreateserial', '-days', '1', '-extfile', str(work / 'server.ext'), '-out', str(certificate)],
            ['x509', '-req', '-in', str(work / 'server.csr'), '-CA', str(authority), '-CAkey', str(ca_key),
                '-CAcreateserial', '-days', '1', '-extfile', str(work / 'valid.ext'), '-out', str(valid_certificate)]
        ]
        for command in commands:
            completed = subprocess.run([args.openssl, *command], capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            assert completed.returncode == 0, completed.stderr.decode(errors='replace')
        der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
        cases = [('hostname-tls12', ssl.TLSVersion.TLSv1_2, True, False, 'SSL_ERROR_BAD_CERT_DOMAIN'),
            ('hostname-tls13', ssl.TLSVersion.TLSv1_3, True, False, 'SSL_ERROR_BAD_CERT_DOMAIN'),
            ('untrusted-root', ssl.TLSVersion.TLSv1_3, False, False, 'SEC_ERROR_UNKNOWN_ISSUER'),
            ('protocol-version', ssl.TLSVersion.TLSv1_2, True, True, 'SSL_ERROR_PROTOCOL_VERSION_ALERT'),
            ('frame-failures', ssl.TLSVersion.TLSv1_3, True, False, 'SSL_ERROR_BAD_CERT_DOMAIN'),
            ('no-response-tls12', ssl.TLSVersion.TLSv1_2, True, False, None),
            ('no-response-tls13', ssl.TLSVersion.TLSv1_3, True, False, None),
            ('fetch-hostname-tls12', ssl.TLSVersion.TLSv1_2, True, False, 'SSL_ERROR_BAD_CERT_DOMAIN'),
            ('fetch-hostname-tls13', ssl.TLSVersion.TLSv1_3, True, False, 'SSL_ERROR_BAD_CERT_DOMAIN'),
            ('fetch-untrusted-root', ssl.TLSVersion.TLSv1_3, False, False, 'SEC_ERROR_UNKNOWN_ISSUER'),
            ('fetch-no-response-tls12', ssl.TLSVersion.TLSv1_2, True, False, None),
            ('fetch-no-response-tls13', ssl.TLSVersion.TLSv1_3, True, False, None)]
        for name, version, trusted, tls13_only, expected in cases:
            completed_tls = expected is None
            background = name.startswith('fetch-')
            directory = work / name
            directory.mkdir()
            profile, reports = directory / 'profile', directory / 'reports'
            profile.mkdir()
            reports.mkdir()
            if trusted:
                trust_certificate(profile, firefox.parent, ssl.PEM_cert_to_DER_cert(authority.read_text()))
            (profile / 'cipherazzi-profile.json').write_text('{"owner":"Cipherazzi"}')
            preferences = {'network.http.network_access_on_socket_process.enabled': True,
                'browser.startup.page': 0, 'network.proxy.type': 0, 'network.trr.mode': 5,
                'network.captive-portal-service.enabled': False, 'network.connectivity-service.enabled': False,
                'datareporting.policy.dataSubmissionEnabled': False, 'toolkit.telemetry.enabled': False,
                'services.settings.server': 'http://127.0.0.1:1', 'security.OCSP.enabled': 0}
            if tls13_only:
                preferences['security.tls.version.min'] = 4
            (profile / 'user.js').write_text(''.join(f'user_pref({json.dumps(key)}, {json.dumps(value)});\n'
                for key, value in preferences.items()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = version
            context.load_cert_chain(valid_certificate if completed_tls else certificate, key)
            context.set_alpn_protocols(['http/1.1'])
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(8)
            listener.settimeout(0.2)
            port = listener.getsockname()[1]
            stopped = threading.Event()
            exchanges, errors = [], []

            def serve():
                while not stopped.is_set():
                    try:
                        raw, peer = listener.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        return
                    with raw:
                        raw.settimeout(5)
                        try:
                            owner = socket_owner(peer[1], port)
                            mitigation = protections(owner)
                            try:
                                with context.wrap_socket(raw, server_side=True) as connection:
                                    if completed_tls:
                                        assert connection.recv(4096).startswith(b'GET /')
                                        exchanges.append(dict(pid=owner, protections=mitigation, local_port=peer[1],
                                            tls=connection.version(), cipher=connection.cipher()[0],
                                            alpn=connection.selected_alpn_protocol(), http_response_sent=False))
                                        connection.unwrap().close()
                                    else:
                                        assert not connection.recv(1), 'The rejected peer sent application data'
                                        exchanges.append(dict(pid=owner, protections=mitigation, local_port=peer[1],
                                            error='Peer closed without application data'))
                            except ssl.SSLError as error:
                                exchanges.append(dict(pid=owner, protections=mitigation, local_port=peer[1],
                                    error=str(error)))
                        except Exception as error:
                            errors.append(str(error))

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            page_worker = None
            page_listener = None
            page_served = threading.Event()
            page_port = port
            if name == 'frame-failures' or background:
                page_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                page_context.load_cert_chain(valid_certificate, key)
                page_listener = socket.socket()
                page_listener.bind(('127.0.0.1', 0))
                page_listener.listen(2)
                page_listener.settimeout(20)
                page_port = page_listener.getsockname()[1]

                def serve_page():
                    try:
                        raw, _ = page_listener.accept()
                        with raw, (raw if background else
                            page_context.wrap_socket(raw, server_side=True)) as connection:
                            connection.settimeout(10)
                            assert connection.recv(16384).startswith(b'GET /')
                            body = ('<html>cipherazzi-private-application-data-sentinel' +
                                (f'<script>fetch("https://localhost:{port}/background", {{mode:"no-cors"}})'
                                    '.catch(() => {});</script>' if background else
                                    f'<iframe src="https://localhost:{port}/first"></iframe>'
                                    f'<iframe src="https://localhost:{port}/second"></iframe>') + '</html>').encode()
                            connection.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n' +
                                f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
                            page_served.set()
                    except Exception as error:
                        errors.append(str(error))
                    finally:
                        page_listener.close()

                page_worker = threading.Thread(target=serve_page, daemon=True)
                page_worker.start()
            try:
                result = subprocess.run([str(root / 'build/bin/Release/Cipherazzi.EndpointAdapter.exe'),
                    '--provider', 'firefox', '--spawn', str(firefox), '--output', str(reports),
                    '--browser-profile', str(profile), '--url',
                    f'{"http" if background else "https"}://localhost:{page_port}/', '--duration', '3',
                    '--', '--headless'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=40)
                (directory / 'adapter.stdout').write_bytes(result.stdout)
                (directory / 'adapter.stderr').write_bytes(result.stderr)
                assert result.returncode == 0, (result.stdout.decode(errors='replace'),
                    result.stderr.decode(errors='replace'))
                assert exchanges and not errors, errors
                evidence = [json.loads(path.read_text()) for path in reports.glob('cipherazzi-endpoint-*.json')]
                matching = [value for value in evidence
                    if value.get('server_name') == 'localhost' and value['success'] == completed_tls and
                    (not completed_tls or value.get('remote', {}).get('port') == port)]
                assert matching and (name == 'frame-failures' or len(matching) == 1), matching
                if name == 'frame-failures' or background:
                    assert page_served.is_set()
                    if not background:
                        assert any(value['success'] and value.get('remote', {}).get('port') == page_port
                            for value in evidence)
                    assert b'The initial navigation failed' not in result.stderr
                assert not (profile / 'chrome/cipherazzi/FirefoxFailureActor.sys.mjs').exists()
                assert 'cipherazzi-private-application-data-sentinel' not in json.dumps(evidence)
                value = matching[0]
                assert value['success'] == completed_tls
                if completed_tls:
                    exchange = next(item for item in exchanges if item.get('local_port') == value['local']['port'])
                    assert not exchange['http_response_sent'] and value['remote']['port'] == port
                    assert value['local']['address'] == value['remote']['address'] == '127.0.0.1'
                    assert value['tls_version'] == (771 if version == ssl.TLSVersion.TLSv1_2 else 772)
                    assert value['cipher_id'] == (0xc030 if version == ssl.TLSVersion.TLSv1_2 else 0x1302)
                    assert value['group_id'] == 29 and value['signature_scheme'] == 0x0804
                    assert value['peer_verified'] and value['selected_alpn'] == 'http/1.1'
                    assert 'error_name' not in value and 'error_code' not in value
                    assert base64.b64decode(value['server_certificates_der'][0]) == \
                        ssl.PEM_cert_to_DER_cert(valid_certificate.read_text())
                else:
                    assert value['error_name'] == expected and value['error_code'] != 0
                assert value['provider'] == 'Firefox/NSS' and Path(value['process_path']) == firefox
                assert value['process_scope'] == 'endpoint' and value['role'] == 'client'
                assert value['transport'] == ('TCP' if completed_tls else 'Unknown')
                if not completed_tls:
                    assert ('local' in value) == ('remote' in value)
                    if 'local' in value:
                        assert value['local']['port'] in {exchange['local_port'] for exchange in exchanges}
                        assert value['local']['address'] == value['remote']['address'] == '127.0.0.1'
                        assert value['remote']['port'] == port
                assert value['pid'] in {exchange['pid'] for exchange in exchanges}
                assert value['process_started_us'] <= value['handshake_started_us'] <= value['timestamp_us']
                if not completed_tls:
                    assert not set(value).intersection({'tls_version', 'cipher_id', 'group_id', 'signature_scheme',
                        'selected_alpn', 'session_resumed'})
                if not completed_tls and not tls13_only:
                    assert not value['peer_verified'] and base64.b64decode(value['server_certificates_der'][0]) == der
                elif tls13_only:
                    assert not value['server_certificates_der'] and 'peer_verified' not in value
                imported = directory / 'import'
                imported.mkdir()
                for index, failure in enumerate(matching):
                    assert failure['process_scope'] == 'endpoint' and failure['role'] == 'client'
                    assert failure['transport'] == ('TCP' if completed_tls else 'Unknown')
                    if not completed_tls:
                        assert failure['error_name'] == expected
                    (imported / f'failure-{index}.json').write_text(json.dumps(failure))
                database = directory / 'endpoints.db'
                loaded = subprocess.run([str(root / 'build/bin/Release/Cipherazzi.Tests.exe'), '--import-endpoints',
                    str(imported), str(database)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=30)
                assert loaded.returncode == 0, loaded.stderr.decode(errors='replace')
                with sqlite3.connect(database) as connection:
                    assert connection.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == len(matching)
                    if not completed_tls:
                        assert connection.execute("SELECT count(*) FROM endpoint_events "
                            "WHERE cipher='' AND protocol='TLS'") \
                            .fetchone()[0] == len(matching)
                    stored = json.loads(connection.execute('SELECT detail_json FROM endpoint_events').fetchone()[0])
                    assert 'matched_flow_id' not in stored and stored['correlation'] == \
                        ('Unmatched socket, process lifetime, timing, or parameters' if completed_tls else
                            'Socket, transport, or socket-process identity unavailable; no packet association asserted')
                    assert stored['process_role'] == 'client'
                    if not completed_tls:
                        assert stored['local_address'] == stored['remote_address'] == \
                            ('127.0.0.1' if 'local' in value else '')
                    assert stored['assessment']['crypto']['transport'] == ('TCP' if completed_tls else 'Unknown')
                    assert stored['assessment']['local_role'] == 'Client'
                    assert stored['assessment']['crypto']['endpoint_confirmations'][0]['success'] == completed_tls
                results.append(dict(case=name, native_import=True, failure=expected,
                    tls_completed_without_http_response=completed_tls,
                    reports=len(matching), subframe_capture=name == 'frame-failures', application_data_excluded=True,
                    background_request=background, exact_socket_owner=True,
                    public_certificate=not tls13_only, socket_identity_not_invented=True,
                    process_protections_preserved=True, listener_retained_during_retries=True))
                print(f'{name}: public browser TLS evidence passed.', flush=True)
            finally:
                stopped.set()
                listener.close()
                worker.join(6)
                if page_listener:
                    page_listener.close()
                if page_worker:
                    page_worker.join(6)
        (work / 'results.json').write_text(json.dumps(dict(cases=results), indent=2))
        publication = publish_failure(args.publisher.resolve(), work / 'hostname-tls13/endpoints.db',
            work / 'publishing') if args.publisher else None
        completed_publication = publish_failure(args.publisher.resolve(), work / 'no-response-tls13/endpoints.db',
            work / 'publishing-completed', completed=True) if args.publisher else None
        (work / 'results.json').write_text(json.dumps(dict(cases=results, publication=publication,
            completed_publication=completed_publication), indent=2))
    finally:
        key.unlink(missing_ok=True)
        ca_key.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
