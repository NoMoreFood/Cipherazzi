import argparse
import base64
import ctypes as c
import ipaddress
import json
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--openssl', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.output.resolve()
    work.mkdir(parents=True)
    adapter = root / 'tools/artifacts/build/bin/Release/Cipherazzi.EndpointAdapter.exe'
    client = root / 'tools/artifacts/build/bin/Release/Cipherazzi.SchannelClient.exe'
    importer = root / 'tools/artifacts/build/bin/Release/Cipherazzi.Tests.exe'

    def run(command, **options):
        return subprocess.run([str(value) for value in command], capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW, timeout=30, **options)

    configuration = work / 'openssl.cnf'
    configuration.write_text('[req]\ndistinguished_name=subject\n[subject]\n')
    ca, ca_key, certificate, key = [work / name for name in ('ca.pem', 'ca.key', 'cert.pem', 'key.pem')]
    commands = [
        ['req', '-config', configuration, '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', ca_key, '-out', ca,
            '-days', '1', '-subj', '/CN=Cipherazzi fixture ' + str(uuid.uuid4()),
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign'],
        ['req', '-config', configuration, '-new', '-newkey', 'rsa:4096', '-nodes', '-keyout', key, '-out',
            work / 'leaf.csr', '-subj', '/CN=coverage.test'],
        ['x509', '-req', '-in', work / 'leaf.csr', '-CA', ca, '-CAkey', ca_key, '-set_serial', '1', '-days', '1',
            '-extfile', work / 'extensions.cnf', '-out', certificate]
    ]
    (work / 'extensions.cnf').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:coverage.test\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    for command in commands:
        result = run([args.openssl, *command])
        assert result.returncode == 0, result.stderr
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
    results = []

    def exchange(protocol, mode, address='127.0.0.1', fragmented=False):
        directory = work / (protocol + '-' + mode + ('-ipv6' if ':' in address else '') +
            ('-fragmented' if fragmented else ''))
        directory.mkdir()
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        datagram = protocol.startswith('DTLS')
        server = socket.socket(family, socket.SOCK_DGRAM if datagram else socket.SOCK_STREAM)
        server.bind((address, 0))
        port = server.getsockname()[1]
        expected_success = mode in ('manual', 'trusted')
        peers, outcomes, failures = [], [], []
        server_process = worker = None
        if datagram or fragmented:
            server.close()
            server_process = subprocess.Popen([str(args.openssl), 's_server',
                *(['-dtls1_2'] if datagram else ['-tls1_2', '-max_send_frag', '512']), '-accept',
                f'[{address}]:{port}' if ':' in address else f'{address}:{port}', '-cert', str(certificate),
                '-key', str(key), '-groups', 'P-256', '-brief'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(.3)
            assert server_process.poll() is None, 'The DTLS server did not start'
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            context.num_tickets = 0
            context.set_ecdh_curve('prime256v1')
            context.minimum_version = context.maximum_version = (
                ssl.TLSVersion.TLSv1_2 if protocol == 'TLSv1.2' else ssl.TLSVersion.TLSv1_3)
            server.listen(1)
            server.settimeout(15)

            def serve():
                try:
                    raw, peer = server.accept()
                    peers.append(peer)
                    with raw, context.wrap_socket(raw, server_side=True) as secured:
                        outcomes.append(secured.version())
                except ssl.SSLError as error:
                    if expected_success:
                        failures.append(str(error))
                except Exception as error:
                    failures.append(str(error))

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
        try:
            result = run([adapter, '--provider', 'schannel', '--spawn', client, '--output', directory, '--',
                str(port), protocol, 'wrong.test' if mode == 'wrong-name' else 'coverage.test', address,
                'manual' if mode == 'manual' else 'automatic'])
            if worker:
                worker.join(20)
        finally:
            server.close()
            if server_process:
                server_process.kill()
                server_output, server_error = server_process.communicate(timeout=10)
                (directory / 'server.stdout').write_bytes(server_output)
                (directory / 'server.stderr').write_bytes(server_error)
        (directory / 'adapter.stdout').write_bytes(result.stdout)
        (directory / 'adapter.stderr').write_bytes(result.stderr)
        assert not failures and (not worker or not worker.is_alive()), failures
        assert result.returncode == (0 if expected_success else 1), (result.stdout, result.stderr)
        values = [json.loads(path.read_text()) for path in directory.glob('cipherazzi-endpoint-*.json')]
        assert len(values) == 1, (values, result.stdout, result.stderr)
        report = values[0]
        assert report['success'] is expected_success, report
        assert report['transport'] == ('DTLS' if datagram else 'TCP'), report
        assert report['remote']['port'] == port, report
        for field in ('local', 'remote'):
            observed = ipaddress.ip_address(report[field]['address'])
            assert (getattr(observed, 'ipv4_mapped', None) or observed) == ipaddress.ip_address(address)
        if expected_success:
            own = next(json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith('{'))
            assert report['local']['port'] == own['local_port'] and report['cipher_id'] == own['cipher'], report
            assert report['tls_version'] == (0xfefd if datagram else 771 if protocol == 'TLSv1.2' else 772), report
            assert report['group_id'] == 23 and report['session_resumed'] is False, report
            assert base64.b64decode(report['server_certificates_der'][0]) == der
            if protocol != 'TLSv1.3':
                assert report['signature_scheme'] in (0x0401, 0x0804), report
            if mode == 'trusted':
                assert report['peer_verified'] is True, report
            else:
                assert 'peer_verified' not in report, report
            if datagram:
                assert b'Protocol version: DTLSv1.2' in server_error and b'Ciphersuite:' in server_error, server_error
            elif fragmented:
                assert b'Protocol version: TLSv1.2' in server_error and b'Ciphersuite:' in server_error, server_error
            else:
                assert outcomes == [protocol] and report['local']['port'] == peers[0][1]
        else:
            assert report['peer_verified'] is False, report
        imported = run([importer, '--import-endpoints', directory, directory / 'events.db'])
        assert imported.returncode == 0, imported.stderr
        with sqlite3.connect(directory / 'events.db') as database:
            assert database.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == 1
        results.append(dict(protocol=protocol, mode=mode, address=address, fragmented=fragmented,
            exact_socket=True, native_import=True))
        print(protocol, mode, address, 'passed', flush=True)

    for protocol in ('TLSv1.2', 'TLSv1.3', 'DTLSv1.2'):
        exchange(protocol, 'manual')
        exchange(protocol, 'untrusted')

    # Trust only this fixture's unique public CA and remove it even when a verification assertion fails.
    crypt = c.WinDLL('crypt32', use_last_error=True)
    crypt.CertOpenStore.argtypes = [c.c_void_p, c.c_uint, c.c_void_p, c.c_uint, c.c_void_p]
    crypt.CertOpenStore.restype = c.c_void_p
    crypt.CertAddEncodedCertificateToStore.argtypes = [c.c_void_p, c.c_uint, c.c_void_p, c.c_uint, c.c_uint,
        c.POINTER(c.c_void_p)]
    crypt.CertDeleteCertificateFromStore.argtypes = [c.c_void_p]
    crypt.CertCloseStore.argtypes = [c.c_void_p, c.c_uint]
    store = crypt.CertOpenStore(c.c_void_p(10), 0, None, 0x24000, c.c_wchar_p('ROOT'))
    assert store, 'Run this certificate-store integration test with administrator rights.'
    owned = c.c_void_p()
    try:
        root_der = ssl.PEM_cert_to_DER_cert(ca.read_text())
        assert crypt.CertAddEncodedCertificateToStore(store, 1, root_der, len(root_der), 1, c.byref(owned))
        for protocol in ('TLSv1.2', 'TLSv1.3', 'DTLSv1.2'):
            exchange(protocol, 'trusted')
            exchange(protocol, 'wrong-name')
        exchange('DTLSv1.2', 'trusted', '::1')
        exchange('TLSv1.2', 'trusted', fragmented=True)
    finally:
        if owned:
            assert crypt.CertDeleteCertificateFromStore(owned), 'Fixture CA removal failed'
        crypt.CertCloseStore(store, 0)
    (work / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
