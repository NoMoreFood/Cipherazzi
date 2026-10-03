import argparse
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--collector', required=True)
    parser.add_argument('--certificate', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--with-service', action='store_true')
    args = parser.parse_args()
    work = Path(args.output).resolve()
    work.mkdir(parents=True)
    results = []

    def service_state():
        query = subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'),
            '-NoProfile', '-Command', "$cipherService=Get-CimInstance Win32_Service -Filter \"Name='Cipherazzi'\"; "
            "$cipherService | Select-Object Started,StartName,ProcessId,PathName | ConvertTo-Json -Compress"],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=15)
        assert query.returncode == 0, query.stderr
        return json.loads(query.stdout) if query.stdout.strip() else None
    addresses = ['127.0.0.1', '::1']
    for address in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        value = address[4][0]
        if value not in addresses and not ipaddress.ip_address(value).is_loopback:
            addresses.append(value)
            break
    assert len(addresses) == 3, 'A local network-interface IPv4 address is needed for coverage verification'
    for mode in ('loopback', 'combined', *(['service'] if args.with_service else [])):
        directory = work / mode
        directory.mkdir()
        database = directory / 'capture.db'
        expected = []
        with (directory / 'collector.stdout').open('wb') as stdout, \
            (directory / 'collector.stderr').open('wb') as stderr:
            command = [args.collector, '--db', str(database)]
            if mode == 'service':
                assert service_state() is None, 'A collector service already exists; it was left intact'
                system = Path(os.environ['SystemRoot']) / 'System32'
                assert not (system / 'Cipherazzi.Collector.exe').exists() and \
                    not (system / 'CipherazziLoopback').exists(), 'Existing service payloads were left intact'
                command.append('--install')
            else:
                command.extend(['--duration', '10'])
            if mode != 'combined':
                command.append('--loopback-only')
            collector = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                creationflags=subprocess.CREATE_NO_WINDOW)
            started = time.monotonic()
            try:
                if mode == 'service':
                    assert collector.wait(70) == 0, (directory / 'collector.stderr').read_text(errors='replace')
                    service = service_state()
                    assert service and service['Started'] and service['StartName'] == 'LocalSystem'
                    assert service['ProcessId'] and str(database).lower() in service['PathName'].lower()
                else:
                    deadline = started + 15
                    while 'Capturing TLS' not in (directory / 'collector.stdout').read_text(errors='replace') and \
                        time.monotonic() < deadline and collector.poll() is None:
                        time.sleep(0.01)
                    assert 'Capturing TLS' in (directory / 'collector.stdout').read_text(errors='replace'), \
                        (directory / 'collector.stderr').read_text(errors='replace')
                startup = time.monotonic() - started
                for address in addresses:
                    family = socket.AF_INET6 if ':' in address else socket.AF_INET
                    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        server_context.load_cert_chain(args.certificate, args.key)
                        server_context.minimum_version = server_context.maximum_version = version
                        server_context.set_alpn_protocols(['h2'])
                        client_context = ssl.create_default_context(cafile=args.certificate)
                        client_context.minimum_version = client_context.maximum_version = version
                        client_context.set_alpn_protocols(['h2'])
                        listener = socket.socket(family)
                        listener.bind((address, 0))
                        listener.listen(1)
                        listener.settimeout(15)
                        port = listener.getsockname()[1]
                        errors = []
                        payload = b'loopback-private-application-data' * 2048

                        def serve():
                            try:
                                with listener.accept()[0] as raw, \
                                    server_context.wrap_socket(raw, server_side=True) as tls:
                                    tls.settimeout(15)
                                    received = bytearray()
                                    while len(received) < len(payload):
                                        part = tls.recv(len(payload) - len(received))
                                        assert part, 'TLS application stream ended early'
                                        received.extend(part)
                                    assert received == payload, 'Sniffing changed application traffic'
                                    tls.sendall(b'ok')
                                    tls.unwrap().close()
                            except Exception as error:
                                errors.append(str(error))
                            finally:
                                listener.close()

                        worker = threading.Thread(target=serve)
                        worker.start()
                        with socket.socket(family) as raw:
                            raw.settimeout(15)
                            raw.connect((address, port))
                            local = raw.getsockname()
                            with client_context.wrap_socket(raw, server_hostname='loopback.lab') as tls:
                                tls.sendall(payload)
                                assert tls.recv(2) == b'ok', 'TLS responder failed'
                                assert tls.selected_alpn_protocol() == 'h2'
                                tls.unwrap().close()
                        worker.join(5)
                        assert not worker.is_alive() and not errors, errors
                        expected.append(dict(address=address, source_port=local[1], destination_port=port,
                            protocol='TLS', tls=771 if version == ssl.TLSVersion.TLSv1_2 else 772))
                    with socket.socket(family, socket.SOCK_DGRAM) as sender, \
                        socket.socket(family, socket.SOCK_DGRAM) as receiver:
                        receiver.bind((address, 0))
                        receiver.settimeout(10)
                        sender.bind((address, 0))
                        sender.settimeout(10)
                        target = receiver.getsockname()
                        initiation = bytearray(148)
                        struct.pack_into('<II', initiation, 0, 1, 100)
                        sender.sendto(initiation, target)
                        data, peer = receiver.recvfrom(512)
                        assert data == initiation
                        response = bytearray(92)
                        struct.pack_into('<III', response, 0, 2, 200, 100)
                        receiver.sendto(response, peer)
                        assert sender.recvfrom(512)[0] == response, 'UDP traffic changed during capture'
                        expected.append(dict(address=address, source_port=sender.getsockname()[1],
                            destination_port=target[1], protocol='WireGuard'))
                if mode == 'service':
                    removed = subprocess.run([args.collector, '--uninstall'], stdout=stdout, stderr=stderr,
                        creationflags=subprocess.CREATE_NO_WINDOW, timeout=70)
                    assert removed.returncode == 0 and service_state() is None, \
                        (directory / 'collector.stderr').read_text(errors='replace')
                else:
                    assert collector.wait(20) == 0, (directory / 'collector.stderr').read_text(errors='replace')
            finally:
                if collector.poll() is None:
                    collector.kill()
                    collector.wait(5)
                if mode == 'service':
                    service = service_state()
                    if service and str(database).lower() in service['PathName'].lower():
                        removed = subprocess.run([args.collector, '--uninstall'], stdout=stdout, stderr=stderr,
                            creationflags=subprocess.CREATE_NO_WINDOW, timeout=70)
                        assert removed.returncode == 0, 'The owned lab service could not be removed'
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute('SELECT * FROM connections').fetchall()
            for item in expected:
                matches = [row for row in rows if row['source_port'] == item['source_port'] and
                    row['destination_port'] == item['destination_port'] and row['source_address'] == item['address']]
                assert len(matches) == 1, (mode, item, len(matches))
                row = matches[0]
                assert row['destination_address'] == item['address']
                if item['protocol'] == 'TLS':
                    assert row['tls_version'] == item['tls'] and row['cipher_id'] > 0
                    crypto = json.loads(row['crypto_json'])
                    assert row['sni'] == 'loopback.lab' and crypto['client_hello_us'] and crypto['server_hello_us']
                else:
                    assert json.loads(row['crypto_json'])['protocol'] == 'WireGuard'
            run = dict(connection.execute('SELECT * FROM capture_sessions').fetchone())
            assert run['status'] == 'stopped', 'The collector did not finish its journal cleanly'
            assert run['capture_lost'] == run['queue_lost'] == run['storage_lost'] == 0, run
            assert run['truncated'] == run['malformed'] == run['reassembly_limit'] == 0, run
        assert 'loopback-private-application-data' not in json.dumps([dict(row) for row in rows])
        results.append(dict(mode=mode, cases=expected, startup_seconds=startup,
            no_known_loss=True, application_traffic_unchanged=True, plaintext_not_persisted=True,
            local_system_service=mode == 'service'))
        print(f'{mode}: {len(expected)} real IPv4/IPv6/local-interface TCP and UDP exchanges passed.', flush=True)
    (work / 'results.json').write_text(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
