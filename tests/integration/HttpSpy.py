import argparse
import ipaddress
import json
import sqlite3
import ssl
import struct
import subprocess
import time
from pathlib import Path

IDENTITY = Path(__file__).resolve().parents[1] / 'fixtures' / 'HttpSpyServer.pem'
CLIENT = '10.66.0.1'
SERVER = '10.66.0.2'
PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


class Wire:
    """Writes the packets of one TCP connection, optionally losing or damaging one server segment."""

    def __init__(self, packets, clock, port, drop=None, corrupt=None):
        self.packets, self.clock, self.port = packets, clock, port
        self.seq = [1000 + port, 900000 + port]
        self.endpoints = [(CLIENT, 50000 + port % 1000), (SERVER, port)]
        self.drop, self.corrupt, self.server_segments = drop, corrupt, 0

    def emit(self, side, flags, payload=b''):
        source, destination = self.endpoints[side], self.endpoints[1 - side]
        ack = self.seq[1 - side] if flags & 0x10 else 0
        tcp = struct.pack('!HHIIBBHHH', source[1], destination[1], self.seq[side] & 0xffffffff, ack, 0x50, flags,
                          65535, 0, 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40 + len(payload), self.port, 0, 64, 6, 0,
                         ipaddress.ip_address(source[0]).packed, ipaddress.ip_address(destination[0]).packed)
        lost = False
        if side == 1 and payload:
            self.server_segments += 1
            lost = self.drop == self.server_segments
            if self.corrupt == self.server_segments:
                payload = payload[:-8] + bytes([payload[-8] ^ 0x55]) + payload[-7:]
                ip = ip[:2] + struct.pack('!H', 40 + len(payload)) + ip[4:]
        if not lost:
            self.packets.append((self.clock[0], ip + tcp + payload))
        self.clock[0] += 1000
        self.seq[side] += len(payload) + (1 if flags & 3 else 0)

    def open(self):
        self.emit(0, 0x02)
        self.emit(1, 0x12)
        self.emit(0, 0x10)

    def send(self, side, data):
        for offset in range(0, len(data), 1400):
            self.emit(side, 0x18, data[offset:offset + 1400])

    def close(self):
        self.emit(0, 0x11)
        self.emit(1, 0x11)
        self.emit(0, 0x10)


class Session:
    """One TLS connection between two in-memory endpoints, recorded as it would cross the network."""

    def __init__(self, wire, keylog, version=None, ciphers=None, alpn=None, host='httpspy.test'):
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.check_hostname = False
        client.verify_mode = ssl.CERT_NONE
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(IDENTITY)
        for context in (client, server):
            if version == 12:
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            if version == 13:
                context.minimum_version = ssl.TLSVersion.TLSv1_3
            if ciphers:
                context.set_ciphers(ciphers)
            if alpn:
                context.set_alpn_protocols(alpn)
            if keylog:
                context.keylog_filename = str(keylog)
        self.wire = wire
        self.bio = [ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()]
        self.client = client.wrap_bio(self.bio[0], self.bio[1], server_hostname=host)
        self.server = server.wrap_bio(self.bio[2], self.bio[3], server_side=True)

    def pump(self):
        moved = True
        while moved:
            moved = False
            data = self.bio[1].read()
            if data:
                self.wire.send(0, data)
                self.bio[2].write(data)
                moved = True
            data = self.bio[3].read()
            if data:
                self.wire.send(1, data)
                self.bio[0].write(data)
                moved = True

    def handshake(self):
        done = [False, False]
        for _ in range(20):
            for index, endpoint in enumerate((self.client, self.server)):
                if not done[index]:
                    try:
                        endpoint.do_handshake()
                        done[index] = True
                    except ssl.SSLWantReadError:
                        pass
            self.pump()
            if all(done):
                break
        assert all(done), 'The TLS handshake did not complete.'
        return self

    def write(self, side, data):
        (self.client if side == 0 else self.server).write(data)
        self.pump()

    def read(self, side):
        endpoint = self.client if side == 0 else self.server
        received = b''
        while True:
            try:
                received += endpoint.read(65536)
            except ssl.SSLWantReadError:
                return received


def literal(name, value):
    return b'\x00' + bytes([len(name)]) + name.encode() + bytes([len(value)]) + value.encode()


def frame(kind, stream=0, payload=b'', flags=0):
    return len(payload).to_bytes(3, 'big') + bytes([kind, flags]) + stream.to_bytes(4, 'big') + payload


def pcap(path, packets):
    with path.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for stamp, packet in sorted(packets, key=lambda item: item[0]):
            seconds, micros = divmod(stamp, 1000000)
            stream.write(struct.pack('<IIII', seconds, micros, len(packet), len(packet)))
            stream.write(packet)


def http1(session, secure_name):
    """Pipelined requests, a fixed-length and a chunked response, a request body, and credential headers."""
    session.write(0, b'GET /first?q=1 HTTP/1.1\r\nHost: ' + secure_name + b'\r\nAuthorization: Bearer hunter2\r\n'
                  b'Cookie: sid=secret\r\nX-Csrf-Token: csrfvalue\r\nAccept: */*\r\n\r\n'
                  b'POST /submit HTTP/1.1\r\nHost: ' + secure_name + b'\r\nContent-Type: text/plain\r\n'
                  b'Content-Length: 11\r\n\r\nhello=world')
    requests = session.read(1)
    assert requests.startswith(b'GET /first') and requests.endswith(b'hello=world'), requests
    session.write(1, b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: track=abc\r\n'
                  b'Content-Length: 5\r\n\r\nhello'
                  b'HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n'
                  b'6\r\n{"a":1\r\n2\r\n}\n\r\n0\r\n\r\n')
    session.read(0)


def http2(session):
    """Two concurrent streams with a request body, split header and data frames, and a response trailer."""
    client = PREFACE + frame(4) + frame(4, flags=1)
    get = (literal(':method', 'GET') + literal(':scheme', 'https') + literal(':authority', 'httpspy.test') +
           literal(':path', '/h2?x=1') + literal('authorization', 'Bearer hunter2') + literal('accept', '*/*'))
    post = (literal(':method', 'POST') + literal(':scheme', 'https') + literal(':authority', 'httpspy.test') +
            literal(':path', '/upload') + literal('content-type', 'application/octet-stream'))
    client += frame(1, 1, get, 5) + frame(1, 3, post, 4) + frame(0, 3, b'part-one,', 0) + frame(0, 3, b'part-two', 1)
    session.write(0, client)
    session.read(1)
    ok = literal(':status', '200') + literal('content-type', 'text/plain') + literal('set-cookie', 'a=b')
    created = literal(':status', '201') + literal('content-type', 'text/plain')
    server = frame(4) + frame(4, flags=1) + frame(1, 1, ok, 4) + frame(1, 3, created[:9], 0)
    server += frame(9, 3, created[9:], 4) + frame(0, 1, b'hello h2', 1) + frame(0, 3, b'done', 1)
    session.write(1, server)
    session.read(0)


def database(output, name):
    with sqlite3.connect(output / 'HttpSpy' / name) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute('SELECT * FROM exchanges ORDER BY server_port,flow_id,sequence').fetchall()
        session = connection.execute('SELECT * FROM sessions').fetchone()
    by_port = {}
    for row in rows:
        by_port.setdefault(row['server_port'], []).append(dict(row))
    return by_port, dict(session)


def run(collector, output, name, capture, keylog):
    command = [str(collector), '--db', str(output / name), '--replay', str(capture), '--no-process', '--httpspy']
    if keylog:
        command += ['--keylog', str(keylog)]
    result = subprocess.run(command, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW,
                            timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    (output / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--collector', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True)
    keylog = output / 'secrets.log'
    packets, clock = [], [time.time_ns() // 1000]

    def wire(port, **options):
        value = Wire(packets, clock, port, **options)
        value.open()
        return value

    # TLS 1.3 with AES-256-GCM, TLS 1.2 with each supported AEAD suite, and a hostile reordering of both.
    for port, version, ciphers in ((9001, 13, None), (9002, 12, 'ECDHE-RSA-AES128-GCM-SHA256'),
                                   (9003, 12, 'ECDHE-RSA-AES256-GCM-SHA384'), (9004, 12, 'ECDHE-RSA-CHACHA20-POLY1305')):
        link = wire(port)
        session = Session(link, keylog, version, ciphers, ['http/1.1']).handshake()
        http1(session, b'httpspy.test')
        link.close()

    # HTTP/2 over TLS 1.3 and TLS 1.2.
    for port, version in ((9005, 13), (9006, 12)):
        link = wire(port)
        http2(Session(link, keylog, version, None, ['h2']).handshake())
        link.close()

    # A TLS connection whose secrets were never exported.
    link = wire(9007)
    session = Session(link, None, 13, None, ['http/1.1']).handshake()
    session.write(0, b'GET /hidden HTTP/1.1\r\nHost: httpspy.test\r\n\r\n')
    session.read(1)
    session.write(1, b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno')
    link.close()

    # A server segment that capture missed, and one that was damaged.
    link = wire(9008)
    session = Session(link, keylog, 13, None, ['http/1.1']).handshake()
    session.write(0, b'GET /lost HTTP/1.1\r\nHost: httpspy.test\r\n\r\n')
    session.read(1)
    link.drop = link.server_segments + 3
    session.write(1, b'HTTP/1.1 200 OK\r\nContent-Length: 6000\r\n\r\n' + b'x' * 6000)
    link.close()
    link = wire(9009)
    session = Session(link, keylog, 13, None, ['http/1.1']).handshake()
    session.write(0, b'GET /damaged HTTP/1.1\r\nHost: httpspy.test\r\n\r\n')
    session.read(1)
    link.corrupt = link.server_segments + 1
    session.write(1, b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc')
    link.close()

    # Cleartext HTTP needs no secrets, and a CONNECT tunnel carries TLS that does.
    link = wire(9010)
    link.send(0, b'GET /plain HTTP/1.1\r\nHost: cleartext.test\r\n\r\n')
    link.send(1, b'HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnone')
    link.close()
    link = wire(9011)
    link.send(0, b'CONNECT httpspy.test:443 HTTP/1.1\r\nHost: httpspy.test:443\r\n\r\n')
    link.send(1, b'HTTP/1.1 200 Connection established\r\n\r\n')
    session = Session(link, keylog, 13, None, ['http/1.1']).handshake()
    session.write(0, b'GET /tunnelled HTTP/1.1\r\nHost: httpspy.test\r\n\r\n')
    session.read(1)
    session.write(1, b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
    link.close()
    capture = output / 'httpspy.pcap'
    pcap(capture, packets)

    stdout = run(args.collector, output, 'secrets.db', capture, keylog)
    rows, stats = database(output, 'secrets.db')
    for port in (9001, 9002, 9003, 9004):
        first, second = rows[port]
        assert (first['method'], first['target'], first['host'], first['status']) == \
            ('GET', '/first?q=1', 'httpspy.test', 200), first
        assert first['state'] == 'complete' and first['scheme'] == 'https', first
        assert first['transport'] == ('TLS 1.3' if port == 9001 else 'TLS 1.2'), first
        assert bytes(first['response_body']) == b'hello' and first['content_type'] == 'text/html', first
        assert 'Bearer' not in first['request_headers'] and 'hunter2' not in first['request_headers'], first
        assert 'Authorization: [redacted' in first['request_headers'] and 'Accept: */*' in first['request_headers']
        assert 'secret' not in first['request_headers'] and 'track=abc' not in first['response_headers'], first
        assert 'csrfvalue' not in first['request_headers'] and 'X-Csrf-Token: [redacted' in first['request_headers']
        assert (second['method'], second['target'], second['status']) == ('POST', '/submit', 201), second
        assert bytes(second['request_body']) == b'hello=world', second
        assert bytes(second['response_body']) == b'{"a":1}\n' and second['response_bytes'] == 8, second
    for port in (9005, 9006):
        get, post = rows[port]
        assert (get['method'], get['target'], get['host'], get['status'], get['version']) == \
            ('GET', '/h2?x=1', 'httpspy.test', 200, 'HTTP/2'), get
        assert bytes(get['response_body']) == b'hello h2' and 'redacted' in get['request_headers'], get
        assert (post['method'], post['target'], post['status']) == ('POST', '/upload', 201), post
        assert bytes(post['request_body']) == b'part-one,part-two' and bytes(post['response_body']) == b'done', post
        assert post['state'] == 'complete' and get['state'] == 'complete'
    missing = rows[9007]
    assert len(missing) == 1 and missing[0]['state'] == 'encrypted' and 'No TLS secrets' in missing[0]['note'], missing
    assert missing[0]['host'] == 'httpspy.test' and missing[0]['transport'] == 'TLS 1.3', missing
    lost = rows[9008][-1]
    assert lost['state'] == 'partial' and lost['target'] == '/lost', rows[9008]
    damaged = rows[9009]
    assert damaged[0]['state'] == 'partial' and 'authentication' in damaged[0]['note'], damaged
    plain = rows[9010][0]
    assert (plain['scheme'], plain['host'], plain['status'], bytes(plain['response_body'])) == \
        ('http', 'cleartext.test', 404, b'none'), plain
    connect, inner = rows[9011]
    assert connect['method'] == 'CONNECT' and 'Tunnel established' in connect['note'], connect
    assert (inner['scheme'], inner['target'], inner['status'], bytes(inner['response_body'])) == \
        ('https', '/tunnelled', 200, b'ok'), inner
    assert stats['exchanges'] == sum(len(group) for group in rows.values()) and stats['missing_secrets'] == 1
    assert stats['failed'] == 1 and stats['decoded_flows'] == 9 and stats['tls_flows'] == 10 and stats['secrets'] > 0

    # Without the key log only cleartext HTTP is readable, and every TLS connection says why.
    run(args.collector, output, 'nosecrets.db', capture, None)
    rows, stats = database(output, 'nosecrets.db')
    assert all(row['state'] == 'encrypted' for port in (9001, 9002, 9005) for row in rows[port]), rows
    assert rows[9010][0]['status'] == 404 and stats['missing_secrets'] >= 8, stats

    # Header-only capture keeps no bodies and masks nothing the operator asked to keep.
    command = [str(args.collector), '--db', str(output / 'headers.db'), '--replay', str(capture), '--no-process',
               '--httpspy', '--keylog', str(keylog), '--httpspy-body-kb', '0', '--httpspy-credentials']
    result = subprocess.run(command, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW,
                            timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    rows, _ = database(output, 'headers.db')
    first = rows[9001][0]
    assert first['response_body'] is None and first['response_bytes'] == 5, first
    assert 'Bearer hunter2' in first['request_headers'] and 'sid=secret' in first['request_headers'], first
    assert 'csrfvalue' in first['request_headers'], first

    # Upgrade an existing message store without losing its earlier captures.
    upgraded = output / 'HttpSpy' / 'upgrade.db'
    with sqlite3.connect(output / 'HttpSpy' / 'secrets.db') as source, sqlite3.connect(upgraded) as target:
        source.backup(target)
    with sqlite3.connect(upgraded) as connection:
        previous = connection.execute('SELECT count(*) FROM exchanges').fetchone()[0]
        connection.execute('ALTER TABLE exchanges DROP COLUMN flow_started_us')
        connection.execute('ALTER TABLE exchanges DROP COLUMN connection_client_port')
        connection.execute('PRAGMA user_version=1')
    run(args.collector, output, 'upgrade.db', capture, keylog)
    with sqlite3.connect(upgraded) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2
        assert connection.execute('SELECT count(*) FROM exchanges').fetchone()[0] == 2 * previous
        assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'

    # Target validation finishes before any live interception can change this computer's traffic.
    for ports in ('0', '65536', '443,', '443,,8443', 'https'):
        result = subprocess.run([str(args.collector), '--httpspy', '--httpspy-port', ports],
                                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
        assert result.returncode != 0 and 'port' in result.stderr.lower(), result.stderr
    (output / 'results.json').write_text(json.dumps({'statistics': stats, 'output': stdout}, indent=2),
                                         encoding='utf-8')
    print('HTTP Spy decryption, protocols, redaction, loss, and failure checks passed.')


if __name__ == '__main__':
    main()
