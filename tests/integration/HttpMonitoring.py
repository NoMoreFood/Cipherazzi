import argparse
import ipaddress
import json
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
    parser.add_argument('--output', required=True)
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    collector = str(Path(args.collector).resolve())

    def read(database):
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute('SELECT * FROM connections')]

    def run_config(name, settings):
        path = output / (name + '.json')
        path.write_text(json.dumps(settings, indent=2), encoding='utf-8')
        result = subprocess.run([collector, '--config', str(path)], capture_output=True, text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
        (output / (name + '.stdout')).write_text(result.stdout, encoding='utf-8')
        (output / (name + '.stderr')).write_text(result.stderr, encoding='utf-8')
        assert result.returncode == 0, result.stdout + result.stderr

    # Replay real TLS hello bytes alongside ordinary HTTP, authentication, and protocol upgrades.
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname='tls.http-monitor.test')
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outgoing.read()
    packets = []
    timestamp = time.time_ns() // 1000

    def exchange(index, client_ip, server_ip, messages):
        sequence = [1, 1]
        client_port, server_port = 45000 + index, 3000 + index
        for client, payload in messages:
            side = 0 if client else 1
            source, destination = (client_ip, server_ip) if client else (server_ip, client_ip)
            ports = (client_port, server_port) if client else (server_port, client_port)
            tcp = struct.pack('!HHIIBBHHH', *ports, sequence[side], 0, 0x50, 0x18, 65535, 0, 0)
            sequence[side] += len(payload)
            source, destination = ipaddress.ip_address(source), ipaddress.ip_address(destination)
            if source.version == 4:
                ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40 + len(payload), index, 0, 64, 6, 0,
                                 source.packed, destination.packed)
            else:
                ip = struct.pack('!IHBB16s16s', 6 << 28, 20 + len(payload), 6, 64,
                                 source.packed, destination.packed)
            packets.append(ip + tcp + payload)

    request = b'GET /private?token=not-retained HTTP/1.1\r\nHost: ordinary.http-monitor.test:3000\r\n' \
              b'Cookie: secret=not-retained\r\n\r\n'
    response = b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nnot-retained'
    ordinary = [(True, request[:9]), (True, request[9:]), (False, response)]
    exchange(1, '10.20.0.1', '10.20.0.2', ordinary * 100)
    exchange(2, '127.0.0.1', '127.0.0.1', ordinary)
    exchange(3, '::1', '::1', ordinary)
    exchange(4, '::ffff:127.0.0.1', '::ffff:127.0.0.1', ordinary)
    exchange(5, '10.20.0.1', '10.20.0.2', [(True,
        b'GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n')])
    exchange(6, '10.20.0.1', '10.20.0.2', [(True,
        b'GET /ws HTTP/1.1\r\nHost: websocket.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'),
        (False, b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x02hi'),
        (True, b'\x81\x82xxxxxx')])
    exchange(7, '10.20.0.1', '10.20.0.2', [(True,
        b'CONNECT tls.http-monitor.test:443 HTTP/1.1\r\nHost: tls.http-monitor.test:443\r\n\r\n'),
        (False, b'HTTP/1.1 200 Connection Established\r\n\r\n'), (True, hello)])
    exchange(8, '127.0.0.1', '127.0.0.1', [(True, hello)])
    exchange(9, '10.20.0.1', '10.20.0.2', [(True, hello)])
    capture = output / 'http.pcap'
    with capture.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for index, packet in enumerate(packets):
            seconds, micros = divmod(timestamp + index * 1000, 1000000)
            stream.write(struct.pack('<IIII', seconds, micros, len(packet), len(packet)))
            stream.write(packet)
    for disabled in (False, True):
        name = 'disabled' if disabled else 'enabled'
        run_config(name, {'db': name + '.db', 'replay': 'http.pcap', 'no-process': True, 'no-http': disabled})
        rows = read(output / (name + '.db'))
        assert len(rows) == (4 if disabled else 9), [(r['destination_port'], r['state']) for r in rows]
        assert sum(row['tls_name'] == 'HTTP' for row in rows) == (1 if disabled else 6)
        for row in rows:
            assert 'not-retained' not in row['crypto_json'] and '/private' not in row['crypto_json']
            if row['tls_name'] == 'HTTP':
                assert row['encryption'] == 'Unencrypted'
        tunnel = next(row for row in rows if row['destination_port'] == 3007)
        tunnel_facts = json.loads(tunnel['crypto_json'])
        assert tunnel_facts['protocol'] == 'TLS' and tunnel_facts['http_tunnel_established']
        if not disabled:
            ordinary_row = next(row for row in rows if row['destination_port'] == 3001)
            facts = json.loads(ordinary_row['crypto_json'])
            assert facts['http_methods'] == ['GET'] and facts['http_status_codes'] == [200]
            assert facts['http_host'] == 'ordinary.http-monitor.test:3000'
        with sqlite3.connect(output / (name + '.db')) as connection:
            assert connection.execute('SELECT sum(malformed) FROM capture_sessions').fetchone()[0] == 0

    live_checks = []
    if args.live:
        # Independent sniff handles exercise localhost and same-host LAN addresses without modifying traffic.
        addresses = ['127.0.0.1', '::1']
        addresses.extend(next(([entry[4][0]] for entry in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
                               if not ipaddress.ip_address(entry[4][0]).is_loopback), []))
        for disabled in (False, True):
            name = 'live-disabled' if disabled else 'live-enabled'
            configuration = output / (name + '.json')
            configuration.write_text(json.dumps({'db': name + '.db', 'loopback-only': True,
                'duration': 8, 'no-http': disabled, 'no-process': True}), encoding='utf-8')
            expected = []
            with (output / (name + '.stdout')).open('wb') as stdout, \
                    (output / (name + '.stderr')).open('wb') as stderr:
                process = subprocess.Popen([collector, '--config', str(configuration)], stdout=stdout, stderr=stderr,
                                           creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    deadline = time.monotonic() + 10
                    while 'Capturing TLS' not in (output / (name + '.stdout')).read_text(errors='replace'):
                        assert process.poll() is None and time.monotonic() < deadline, 'Live capture did not start'
                        time.sleep(0.05)
                    for address in addresses:
                        with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET) as listener:
                            listener.bind((address, 0))
                            listener.listen(1)
                            listener.settimeout(5)
                            port = listener.getsockname()[1]
                            errors = []

                            def serve():
                                try:
                                    with listener.accept()[0] as client:
                                        client.settimeout(5)
                                        received = b''
                                        while b'\r\n\r\n' not in received:
                                            part = client.recv(4096)
                                            assert part, 'HTTP request ended before its headers'
                                            received += part
                                        assert received == request
                                        client.sendall(response)
                                except Exception as error:
                                    errors.append(str(error))

                            worker = threading.Thread(target=serve)
                            worker.start()
                            with socket.create_connection((address, port), timeout=5) as client:
                                client.sendall(request)
                                received = b''
                                while data := client.recv(4096):
                                    received += data
                                assert received == response, 'HTTP traffic changed during capture'
                            worker.join(5)
                            assert not worker.is_alive() and not errors, errors
                            expected.append(port)
                    assert process.wait(15) == 0, (output / (name + '.stderr')).read_text(errors='replace')
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(5)
            rows = [row for row in read(output / (name + '.db')) if row['destination_port'] in expected]
            assert len(rows) == (0 if disabled else len(expected)), rows
            assert all(json.loads(row['crypto_json'])['loopback'] for row in rows)
            live_checks.append({'disabled': disabled, 'addresses': addresses, 'connections': len(rows)})
    (output / 'results.json').write_text(json.dumps({'result': 'passed', 'replay': True,
        'configuration': True, 'private_data_excluded': True, 'live': live_checks}, indent=2), encoding='utf-8')
    print('HTTP replay, configuration, and requested live capture checks passed.')


if __name__ == '__main__':
    main()
