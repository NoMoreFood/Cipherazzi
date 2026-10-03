import argparse
import base64
import ipaddress
import json
import sqlite3
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import hpack


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--collector', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True)
    packets = []
    timestamp = time.time_ns() // 1000
    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

    def frame(kind, stream=0, payload=b'', flags=0):
        return len(payload).to_bytes(3, 'big') + bytes([kind, flags]) + stream.to_bytes(4, 'big') + payload

    def headers(encoder, host='first.test', method='GET', extra=()):
        return encoder.encode([(':method', method), (':scheme', 'http'), (':path', '/not-retained?secret=hidden'),
                               (':authority', host), *extra])

    def exchange(port, messages, fragment=False):
        sequences = [1, 1]
        for when, client, payload in messages:
            side = 0 if client else 1
            source, destination = ('10.55.0.1', '10.55.0.2') if client else ('10.55.0.2', '10.55.0.1')
            ports = (45000 + port - 4300, port) if client else (port, 45000 + port - 4300)
            stride = 1 if fragment else 1300
            for offset in range(0, len(payload), stride):
                part = payload[offset:offset + stride]
                tcp = struct.pack('!HHIIBBHHH', *ports, sequences[side], 0, 0x50, 0x18, 65535, 0, 0)
                sequences[side] += len(part)
                ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40 + len(part), port, 0, 64, 6, 0,
                                 ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed)
                packets.append((timestamp + round(when * 1000000) + offset, ip + tcp + part))

    # Huffman fields, dynamic-table reuse, continuations, DATA skipping, and late request/response metadata.
    encoder = hpack.Encoder()
    first = headers(encoder, extra=[('cookie', 'not-retained'),
                    ('authorization', 'Basic dXNlcjpub3QtcmV0YWluZWQ=')])
    second = headers(encoder, 'second.test', 'POST')
    exchange(4301, [(0, True, preface + frame(4)), (.1, False, frame(4)),
        (.2, True, frame(1, 1, first[:7]) + frame(9, 1, first[7:], 4)),
        (.3, True, b''.join(frame(0, 1, b'x' * 16384, int(index == 63)) for index in range(64))),
        (31, False, frame(1, 1, b'\x88', 5)), (61, True, frame(1, 3, second, 5)),
        (62, False, frame(1, 3, b'\x8d', 5))])

    # The preface and frame headers may be split across individual TCP payloads.
    exchange(4302, [(1, True, preface + frame(4) + frame(1, 1, headers(hpack.Encoder()), 5)),
        (2, False, frame(4) + frame(1, 1, b'\x88', 5))], True)

    # A server's SETTINGS can precede the client preface in capture order.
    exchange(4303, [(1, False, frame(4)), (2, True, preface + frame(4) +
        frame(1, 1, headers(hpack.Encoder(), 'response-first.test'), 5))])

    # h2c upgrades preserve the HTTP/1.x request and continue through binary response headers.
    exchange(4304, [(1, True, b'GET / HTTP/1.1\r\nHost: upgrade.test\r\nConnection: Upgrade, HTTP2-Settings\r\n'
        b'Upgrade: h2c\r\nHTTP2-Settings: AAMAAABk\r\n\r\n'),
        (2, False, b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n' + frame(4)),
        (3, True, preface + frame(4)), (4, False, frame(1, 1, b'\x88', 5))])

    # Invalid compression, interleaved continuations, and hostile table sizes cannot publish invented headers.
    exchange(4305, [(1, True, preface + frame(4) + frame(1, 1, b'\xff' * 10, 5))])
    exchange(4306, [(1, True, preface + frame(4) + frame(1, 1, b'\x82')),
        (2, True, frame(6, payload=b'12345678') + frame(9, 1, first, 4))])
    exchange(4307, [(1, True, preface + frame(4)),
        (2, False, frame(4, payload=b'\x00\x01\x7f\xff\xff\xff'))])
    exchange(4308, [(1, True, preface + frame(4) + frame(1, 1, b'\x88', 5))])

    # A table-size change is sent by the opposite peer and applies before the next compressed block.
    encoder = hpack.Encoder()
    one = headers(encoder, 'table.test')
    encoder.header_table_size = 0
    two = headers(encoder, 'new-table.test')
    exchange(4309, [(1, True, preface + frame(4) + frame(1, 1, one, 5)),
        (2, False, frame(4, payload=b'\x00\x01\x00\x00\x00\x00')),
        (3, True, frame(4, flags=1) + frame(1, 3, two, 5))])

    # In-flight headers keep the old compression table until the peer acknowledges a smaller limit.
    encoder = hpack.Encoder()
    one = headers(encoder, 'before-settings.test')
    two = headers(encoder, 'in-flight.test')
    encoder.header_table_size = 0
    three = headers(encoder, 'after-settings.test')
    exchange(4310, [(1, True, preface + frame(4) + frame(1, 1, one, 5)), (2, False, frame(4)),
        (2.5, True, frame(4, flags=1)), (3, False, frame(4, payload=b'\x00\x01\x00\x00\x00\x00')),
        (4, True, frame(1, 3, two, 5)), (5, True, frame(4, flags=1) + frame(1, 5, three, 5))])

    # Upgrade settings apply before the server sends its first compressed response or larger DATA frame.
    settings = struct.pack('!HIHI', 1, 8192, 5, 32768)
    encoder = hpack.Encoder()
    encoder.header_table_size = 8192
    response = encoder.encode([(':status', '200')])
    exchange(4311, [(1, True, b'GET / HTTP/1.1\r\nHost: upgrade-settings.test\r\n'
        b'Connection: Upgrade, HTTP2-Settings\r\n'
        b'Upgrade: h2c\r\nHTTP2-Settings: ' + base64.urlsafe_b64encode(settings).rstrip(b'=') + b'\r\n\r\n'),
        (2, False, b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n' +
            frame(4) + frame(1, 1, response, 4) + frame(0, 1, b'x' * 20000, 1)),
        (3, True, preface + frame(4))])
    capture = output / 'http2.pcap'
    with capture.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for stamp, packet in sorted(packets):
            seconds, micros = divmod(stamp, 1000000)
            stream.write(struct.pack('<IIII', seconds, micros, len(packet), len(packet)))
            stream.write(packet)
    results = []
    for disabled in (False, True):
        database = output / ('disabled.db' if disabled else 'enabled.db')
        command = [str(args.collector.resolve()), '--db', str(database), '--replay', str(capture), '--no-process']
        if disabled:
            command.append('--no-http')
        result = subprocess.run(command, capture_output=True, text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        (output / (database.stem + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        with sqlite3.connect(database) as connection:
            rows = {port: json.loads(detail) for port, detail in connection.execute(
                'SELECT destination_port,crypto_json FROM connections')}
        assert all('not-retained' not in json.dumps(value) and '/private' not in json.dumps(value)
                   for value in rows.values()), rows
        if disabled:
            assert set(rows) == {4301} and rows[4301]['http_basic_auth_observed'], rows
            assert not any(key in rows[4301] for key in ('http_hosts', 'http_methods', 'http_request_versions'))
        else:
            assert set(rows) == set(range(4301, 4312)), rows.keys()
            assert rows[4301]['http_methods'] == ['GET', 'POST'] and rows[4301]['http_status_codes'] == [200, 404]
            assert rows[4301]['http_hosts'] == ['first.test', 'second.test']
            assert rows[4302]['http_request_versions'] == ['HTTP/2'] and rows[4302]['http_status_codes'] == [200]
            assert rows[4303]['http_host'] == 'response-first.test'
            assert rows[4304]['http_status_codes'] == [101, 200] and rows[4304]['http_upgrade_protocol'] == 'h2c'
            assert all('http_hosts' not in rows[port] for port in range(4305, 4309))
            assert rows[4309]['http_hosts'] == ['table.test', 'new-table.test']
            assert rows[4310]['http_hosts'] == ['before-settings.test', 'in-flight.test', 'after-settings.test']
            assert rows[4311]['http_status_codes'] == [101, 200]
        results.append({'disabled': disabled, 'connections': len(rows), 'passed': True})
    if args.live:
        import h2.config
        import h2.connection
        import h2.events
        for disabled in (False, True):
            database = output / ('live-disabled.db' if disabled else 'live-enabled.db')
            command = [str(args.collector.resolve()), '--db', str(database), '--loopback-only',
                       '--no-process', '--duration', '7']
            if disabled:
                command.append('--no-http')
            collector = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
            failures = []
            try:
                time.sleep(1.5)
                for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                    with socket.socket(family) as listener:
                        listener.bind((address, 0))
                        listener.listen()
                        listener.settimeout(4)

                        def serve():
                            try:
                                with listener.accept()[0] as stream:
                                    stream.settimeout(4)
                                    server = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
                                    server.initiate_connection()
                                    stream.sendall(server.data_to_send())
                                    remaining = 3
                                    while remaining:
                                        received = stream.recv(65536)
                                        assert received
                                        for event in server.receive_data(received):
                                            if isinstance(event, h2.events.RequestReceived):
                                                server.send_headers(event.stream_id, [(':status', '200')],
                                                                    end_stream=True)
                                                remaining -= 1
                                        stream.sendall(server.data_to_send())
                            except Exception as error:
                                failures.append(str(error))

                        worker = threading.Thread(target=serve)
                        worker.start()
                        with socket.socket(family) as stream:
                            stream.settimeout(4)
                            stream.connect((address, listener.getsockname()[1]))
                            client = h2.connection.H2Connection()
                            client.initiate_connection()
                            for index in range(3):
                                client.send_headers(2 * index + 1, [(':method', 'GET'), (':scheme', 'http'),
                                    (':authority', 'h2-live.test'), (':path', '/not-retained')], end_stream=True)
                            stream.sendall(client.data_to_send())
                            complete = 0
                            while complete < 3:
                                received = stream.recv(65536)
                                assert received
                                complete += sum(isinstance(event, h2.events.StreamEnded)
                                                for event in client.receive_data(received))
                        worker.join(5)
                        assert not worker.is_alive() and not failures, failures
                stdout, stderr = collector.communicate(timeout=15)
                assert collector.returncode == 0, stdout + stderr
                (output / (database.stem + '.log')).write_text(stdout + stderr, encoding='utf-8')
                with sqlite3.connect(database) as connection:
                    rows = [json.loads(row[0]) for row in connection.execute('SELECT crypto_json FROM connections')]
                assert len(rows) == (0 if disabled else 2), rows
                assert all(row['http_request_versions'] == ['HTTP/2'] and row['http_status_codes'] == [200]
                           and row['loopback'] for row in rows), rows
                results.append({'live': True, 'disabled': disabled, 'connections': len(rows), 'passed': True})
            finally:
                if collector.poll() is None:
                    collector.kill()
                    collector.wait()
    (output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print('HTTP/2 framing, compression, upgrades, bounds, persistence, and privacy checks passed.')


if __name__ == '__main__':
    main()
