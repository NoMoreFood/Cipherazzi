import argparse
import asyncio
import base64
import ctypes as c
import json
import socket
import ssl
import sqlite3
import subprocess
from pathlib import Path

from FirefoxAdapter import trust_certificate
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted


def inspect_socket(port):
    table = c.WinDLL('iphlpapi').GetExtendedUdpTable
    table.argtypes = [c.c_void_p, c.POINTER(c.c_uint32), c.c_int, c.c_uint32, c.c_int, c.c_uint32]
    table.restype = c.c_uint32
    size = c.c_uint32()
    assert table(None, c.byref(size), 0, 2, 1, 0) == 122
    buffer = c.create_string_buffer(size.value)
    assert table(buffer, c.byref(size), 0, 2, 1, 0) == 0
    owners = set()
    for index in range(c.c_uint32.from_buffer_copy(buffer).value):
        row = (c.c_uint32 * 3).from_buffer_copy(buffer, 4 + index * 12)
        if socket.ntohs(row[1] & 0xffff) == port:
            owners.add(row[2])
    assert len(owners) == 1, 'The QUIC socket has no unique Windows owner'
    owner = owners.pop()
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [c.c_uint32, c.c_int, c.c_uint32], c.c_void_p
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [c.c_void_p], c.c_int
    kernel.GetProcessMitigationPolicy.argtypes = [c.c_void_p, c.c_int, c.c_void_p, c.c_size_t]
    kernel.GetProcessMitigationPolicy.restype = c.c_int
    handle = kernel.OpenProcess(0x1000, 0, owner)
    assert handle, 'The QUIC socket process could not be inspected'
    try:
        dynamic, signature = c.c_uint32(), c.c_uint32()
        assert kernel.GetProcessMitigationPolicy(handle, 2, c.byref(dynamic), 4)
        assert kernel.GetProcessMitigationPolicy(handle, 8, c.byref(signature), 4)
        assert dynamic.value & 1 and signature.value & 1, 'Browser process protection changed'
        return dict(pid=owner, dynamic_code=dynamic.value, binary_signature=signature.value)
    finally:
        kernel.CloseHandle(handle)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--openssl', default=r'C:\Program Files\OpenSSL-Win64\bin\openssl.exe')
    parser.add_argument('--firefox', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    work = args.output.resolve()
    work.mkdir(parents=True)
    profile = work / 'profile'
    profile.mkdir()
    openssl = args.openssl
    firefox = (args.firefox or root / '.work/nss-runtime/core/firefox.exe').resolve()
    authority, ca_key, certificate, key = [work / name for name in ('ca.pem', 'ca-key.pem', 'cert.pem', 'key.pem')]
    (work / 'server.ext').write_text('basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
        'subjectAltName=DNS:localhost,IP:127.0.0.1\n')
    commands = [
        ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Cipherazzi H3 root',
            '-keyout', str(ca_key), '-out', str(authority)],
        ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', str(key),
            '-out', str(work / 'server.csr')],
        ['x509', '-req', '-in', str(work / 'server.csr'), '-CA', str(authority), '-CAkey', str(ca_key),
            '-CAcreateserial', '-days', '1', '-extfile', str(work / 'server.ext'), '-out', str(certificate)]
    ]
    for command in commands:
        subprocess.run([openssl, *command], check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    trust_certificate(profile, firefox.parent, ssl.PEM_cert_to_DER_cert(authority.read_text()))
    observed = []

    class Protocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = H3Connection(self._quic)

        def quic_event_received(self, event):
            if isinstance(event, HandshakeCompleted):
                observed.append(dict(alpn=event.alpn_protocol, peer=self._quic._network_paths[0].addr,
                    original_dcid=self._quic.original_destination_connection_id.hex(),
                    **inspect_socket(self._quic._network_paths[0].addr[1])))
            for item in self.http.handle_event(event):
                if isinstance(item, HeadersReceived):
                    self.http.send_headers(item.stream_id, [(b':status', b'200'), (b'content-type', b'text/html')])
                    self.http.send_data(item.stream_id, b'<html><title>Public HTTP3 fixture</title>'
                        b'cipherazzi-private-application-data-sentinel</html>', end_stream=True)
                    self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=['h3'])
    configuration.load_cert_chain(str(certificate), str(key))
    server = await serve('127.0.0.1', 0, configuration=configuration, create_protocol=Protocol)
    port = server._transport.get_extra_info('sockname')[1]
    preferences = {'browser.startup.page': 0,
        'network.proxy.type': 0, 'network.trr.mode': 5, 'security.OCSP.enabled': 0,
        'network.http.network_access_on_socket_process.enabled': True,
        'network.http.http3.alt-svc-mapping-for-testing': f'localhost;h3=":{port}"',
        'network.http.http3.force-use-alt-svc-mapping-for-testing': True,
        'network.http.http3.disable_when_third_party_roots_found': False,
        'network.captive-portal-service.enabled': False, 'network.connectivity-service.enabled': False,
        'services.settings.server': 'http://127.0.0.1:1', 'browser.shell.checkDefaultBrowser': False}
    (profile / 'user.js').write_text(''.join(f'user_pref({json.dumps(name)}, {json.dumps(value)});\n'
        for name, value in preferences.items()))
    (profile / 'cipherazzi-profile.json').write_text('{"owner":"Cipherazzi"}')
    reports = work / 'reports'
    reports.mkdir()
    with (work / 'browser.stdout').open('wb') as stdout, (work / 'browser.stderr').open('wb') as stderr:
        process = subprocess.Popen([str(root / 'build/bin/Release/Cipherazzi.EndpointAdapter.exe'), '--provider',
            'firefox', '--spawn', str(firefox), '--output', str(reports), '--browser-profile', str(profile),
            '--url', f'https://localhost:{port}/', '--duration', '3', '--', '--headless'], stdout=stdout, stderr=stderr,
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            assert await asyncio.to_thread(process.wait, 30) == 0, (work / 'browser.stderr').read_text(errors='replace')
            (work / 'server.json').write_text(json.dumps(observed, indent=2))
            evidence = [json.loads(path.read_text()) for path in reports.glob('cipherazzi-endpoint-*.json')]
            matching = [value for value in evidence if value['remote']['port'] == port]
            assert len(matching) == 1 and len(observed) == 1, (len(matching), observed)
            report = matching[0]
            assert report['transport'] == 'QUIC' and report['selected_alpn'] == 'h3'
            assert report['tls_version'] == 772 and report['cipher_id'] == 0x1302 and report['group_id'] == 29
            assert report['signature_scheme'] == 0x0804 and report['success'] and report['peer_verified']
            assert report['pid'] == observed[0]['pid'] and Path(report['process_path']) == firefox
            assert report['process_started_us'] <= report['handshake_started_us'] <= report['timestamp_us']
            assert report['local']['port'] == observed[0]['peer'][1] and report['local']['address'] == '0.0.0.0'
            assert report['remote']['address'] == observed[0]['peer'][0] == '127.0.0.1'
            assert 'quic_original_dcid' not in report, 'An unreported connection ID was invented'
            assert base64.b64decode(report['server_certificates_der'][0]) == ssl.PEM_cert_to_DER_cert(certificate.read_text())
            assert 'cipherazzi-private-application-data-sentinel' not in json.dumps(report)
            imported = work / 'import'
            imported.mkdir()
            (imported / 'http3.json').write_text(json.dumps(report))
            database = work / 'endpoints.db'
            loaded = await asyncio.to_thread(subprocess.run, [str(root / 'build/bin/Release/Cipherazzi.Tests.exe'),
                '--import-endpoints', str(imported), str(database)], capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            assert loaded.returncode == 0, loaded.stderr.decode(errors='replace')
            with sqlite3.connect(database) as connection:
                detail = json.loads(connection.execute('SELECT detail_json FROM endpoint_events').fetchone()[0])
                assert 'matched_flow_id' not in detail and 'no packet association asserted' in detail['correlation']
                assert detail['local_address'] == '' and detail['local_binding_address'] == '0.0.0.0'
                assert detail['assessment']['server_name'] == 'localhost'
                assert connection.execute('SELECT count(*) FROM certificates').fetchone()[0] == 1
            results = dict(actual_http3=True, tls_metadata=True, public_certificate=True, wildcard_binding_explicit=True,
                packet_association_not_invented=True, application_data_excluded=True, native_import=True,
                exact_windows_socket_owner=True, process_protections_preserved=True)
            (work / 'results.json').write_text(json.dumps(results, indent=2))
            print('Real Firefox HTTP/3 endpoint evidence and native import passed.')
        finally:
            if process.poll() is None:
                try:
                    await asyncio.to_thread(process.wait, 10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(5)
            server.close()
            key.unlink(missing_ok=True)
            ca_key.unlink(missing_ok=True)


if __name__ == '__main__':
    asyncio.run(main())
