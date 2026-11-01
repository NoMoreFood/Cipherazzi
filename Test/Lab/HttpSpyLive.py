"""Real loopback TLS traffic for scoped interception and passive live HTTP Spy capture."""
import argparse
import ctypes
import hashlib
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path


def exact(stream, length):
    data = bytearray()
    while len(data) < length:
        part = stream.recv(length - len(data))
        if not part:
            raise EOFError('The TLS peer closed before its message was complete')
        data.extend(part)
    return bytes(data)


def frame(kind, flags=0, stream=0, body=b''):
    return len(body).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + body


def literal(name, value):
    name, value = name.encode(), value.encode()
    assert len(name) < 127 and len(value) < 127
    return b'\0' + bytes((len(name),)) + name + bytes((len(value),)) + value


class Fixture:
    def __init__(self, address, certificate, key, mutual=False):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate, key)
        self.context.set_alpn_protocols(['h2', 'http/1.1'])
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.mutual = mutual
        self.authenticated = 0
        if mutual:
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_verify_locations(certificate)
        self.listener = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((address, 0))
        self.listener.listen()
        self.address, self.port = self.listener.getsockname()[:2]
        self.stopping = False
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.stopping:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(client,), daemon=True).start()

    def serve(self, client):
        try:
            client.settimeout(4)
            with self.context.wrap_socket(client, server_side=True) as stream:
                if self.mutual:
                    assert stream.getpeercert(), 'The server received no client certificate'
                    self.authenticated += 1
                body = b'live fixture reply'
                if stream.selected_alpn_protocol() == 'h2':
                    assert exact(stream, 24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                    stream.sendall(frame(4))
                    while True:
                        head = exact(stream, 9)
                        payload = exact(stream, int.from_bytes(head[:3], 'big'))
                        kind, flags, identity = head[3], head[4], int.from_bytes(head[5:], 'big')
                        if kind == 4 and not flags & 1:
                            stream.sendall(frame(4, 1))
                        if kind == 1:
                            headers = b'\x88' + literal('content-type', 'text/plain')
                            headers += literal('content-length', str(len(body)))
                            stream.sendall(frame(1, 4, identity, headers) + frame(0, 1, identity, body))
                            # Drain SETTINGS acknowledgements so closing cannot reset the unread reply.
                            while stream.recv(16384):
                                pass
                            return
                else:
                    head = bytearray()
                    while not head.endswith(b'\r\n\r\n') and len(head) <= 65536:
                        head.extend(exact(stream, 1))
                    stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ' +
                                   str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
        except (OSError, EOFError):
            pass
        finally:
            client.close()

    def close(self):
        self.stopping = True
        self.listener.close()


def roots():
    return sorted(hashlib.sha256(der).hexdigest() for der, _, _ in ssl.enum_certificates('ROOT')
                  if b'Cipherazzi HTTP Spy CA' in der)


class Capture:
    def __init__(self, collector, output, name, options):
        self.path = output / (name + '.db')
        self.store = output / 'HttpSpy' / self.path.name
        self.stdout = open(output / (name + '.stdout'), 'wb')
        self.stderr = open(output / (name + '.stderr'), 'wb')
        self.before = roots()
        self.process = subprocess.Popen([str(collector), '--db', str(self.path), '--httpspy', '--loopback-only',
                                         '--duration', '9', *options], stdout=self.stdout, stderr=self.stderr,
                                        creationflags=subprocess.CREATE_NO_WINDOW)

    def __enter__(self):
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenEventW.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_wchar_p)
        kernel.OpenEventW.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint)
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and self.process.poll() is None:
            event = kernel.OpenEventW(0x100000, False, 'Local\\Cipherazzi-Ready-' + str(self.process.pid))
            if event:
                try:
                    if kernel.WaitForSingleObject(event, 0) == 0:
                        return self
                finally:
                    kernel.CloseHandle(event)
            time.sleep(0.02)
        self.__exit__(None, None, None)
        raise AssertionError('The collector did not become ready: ' + str(self.path))

    def __exit__(self, *_):
        try:
            self.process.wait(timeout=35)
        finally:
            if self.process.poll() is None:
                self.process.kill()
            self.stdout.close()
            self.stderr.close()
        assert self.process.returncode == 0, 'Collector failed; inspect ' + str(self.path.with_suffix('.stderr'))
        assert roots() == self.before, 'Capture left a temporary root certificate installed'

    def rows(self):
        with sqlite3.connect('file:' + self.store.as_posix() + '?mode=ro', uri=True) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute('SELECT * FROM exchanges ORDER BY id')]


def request(fixture, certificate, key, target, intercepted=False, host='httpspy.test', version=13, h2=False,
            keylog=None, mutual=False):
    context = ssl.create_default_context() if intercepted else ssl.create_default_context(cafile=certificate)
    if intercepted:
        context.load_verify_locations(certificate)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3 if version == 13 else ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['h2' if h2 else 'http/1.1'])
    if keylog:
        context.keylog_filename = str(keylog)
    if mutual:
        context.load_cert_chain(certificate, key)
    expected = ssl.PEM_cert_to_DER_cert(Path(certificate).read_text())
    with socket.create_connection((fixture.address, fixture.port), timeout=4) as tcp:
        with context.wrap_socket(tcp, server_hostname=host) as stream:
            same = stream.getpeercert(binary_form=True) == expected
            assert same != intercepted, 'The certificate did not match the requested interception scope'
            if not intercepted:
                assert stream.version() == ('TLSv1.3' if version == 13 else 'TLSv1.2'), 'TLS version changed'
            if h2:
                assert stream.selected_alpn_protocol() == 'h2', 'HTTP/2 ALPN was not preserved'
                headers = b'\x82\x87' + literal(':authority', 'httpspy.test:' + str(fixture.port))
                headers += literal(':path', target)
                stream.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4) + frame(1, 5, 1, headers))
                body = bytearray()
                while True:
                    head = exact(stream, 9)
                    payload = exact(stream, int.from_bytes(head[:3], 'big'))
                    if head[3] == 4 and not head[4] & 1:
                        stream.sendall(frame(4, 1))
                    if head[3] == 0:
                        body.extend(payload)
                    if int.from_bytes(head[5:], 'big') == 1 and head[4] & 1:
                        break
                assert body == b'live fixture reply', body
            else:
                authority = host if ':' not in host else '[' + host + ']'
                stream.sendall(('GET ' + target + ' HTTP/1.1\r\nHost: ' + authority + ':' + str(fixture.port) +
                                '\r\nConnection: close\r\n\r\n').encode())
                body = bytearray()
                while part := stream.recv(16384):
                    body.extend(part)
                assert b'200 OK' in body and body.endswith(b'live fixture reply'), body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--collector', type=Path, required=True)
    parser.add_argument('--certificate', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    fixtures = [Fixture('127.0.0.1', args.certificate, args.key), Fixture('::1', args.certificate, args.key),
                Fixture('127.0.0.1', args.certificate, args.key, mutual=True)]
    ports = ','.join(str(fixture.port) for fixture in fixtures)
    checks = []
    try:
        with Capture(args.collector, args.output, 'intercept', ['--httpspy-port', ports,
                     '--httpspy-process', 'python.exe', '--httpspy-host', '*.test']) as capture:
            for fixture, path in zip(fixtures, ('/ipv4', '/ipv6')):
                request(fixture, args.certificate, args.key, path, intercepted=True, version=12)
            try:
                request(fixtures[0], args.certificate, args.key, '/wrong', intercepted=True,
                        host='wrong.test', version=12)
                raise AssertionError('An invalid server certificate name was accepted')
            except ssl.SSLError:
                pass
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not any(row['state'] == 'encrypted' for row in capture.rows()):
                time.sleep(0.05)
            assert any('SEC_E_WRONG_PRINCIPAL (0x80090322)' in row['note'] for row in capture.rows()), \
                'The interception failure was not persisted while capture was still running'
        rows = capture.rows()
        assert {row['target'] for row in rows if row['state'] == 'complete'} == {'/ipv4', '/ipv6'}, rows
        assert all(row['client_pid'] == os.getpid() and row['client_path'] and row['client_account'] for row in rows), rows
        checks.append('IPv4/IPv6 custom ports, process-name and wildcard-host filters, live failure rows, CA cleanup')

        for name, filters in [('host-mismatch', ['--httpspy-host', 'selected.test']),
                              ('process-mismatch', ['--httpspy-process', 'not-the-target.exe'])]:
            with Capture(args.collector, args.output, name, ['--httpspy-port', ports, *filters]) as capture:
                request(fixtures[0], args.certificate, args.key, '/original', h2=True)
                request(fixtures[1], args.certificate, args.key, '/original-v6', h2=True)
            assert not capture.rows(), 'Unmatched traffic appeared in HTTP Spy: ' + name
            checks.append(name + ': original certificate, TLS 1.3, HTTP/2, and an empty capture list')

        with Capture(args.collector, args.output, 'pid-filter', ['--httpspy-port', ports,
                     '--httpspy-process', str(os.getpid())]) as capture:
            request(fixtures[0], args.certificate, args.key, '/pid', intercepted=True, version=12)
        assert [row['target'] for row in capture.rows()] == ['/pid']
        checks.append('PID filtering intercepts the selected application')

        keylog = args.output / 'growing-keys.log'
        before = roots()
        with Capture(args.collector, args.output, 'passive', ['--keylog', str(keylog)]) as capture:
            assert not keylog.exists() and roots() == before, 'Passive startup changed trust or created a key log'
            request(fixtures[0], args.certificate, args.key, '/passive-13', h2=True, keylog=keylog)
            request(fixtures[1], args.certificate, args.key, '/passive-12', h2=True, version=12, keylog=keylog)
            request(fixtures[2], args.certificate, args.key, '/passive-mtls', h2=True, mutual=True, keylog=keylog)
        rows = capture.rows()
        assert {row['target'] for row in rows} == {'/passive-13', '/passive-12', '/passive-mtls'}, rows
        assert all(row['state'] == 'complete' and row['version'] == 'HTTP/2' and
                   bytes(row['response_body']) == b'live fixture reply' for row in rows), rows
        assert {row['transport'] for row in rows} == {'TLS 1.2', 'TLS 1.3'}, rows
        assert fixtures[2].authenticated == 1, 'Mutual TLS did not authenticate the original client'
        checks.append('Growing key log decrypts TLS 1.2/1.3, HTTP/2, IPv6, and pinned mutual TLS without changing trust')
        result = {'result': 'passed', 'checks': checks, 'ports': ports}
    except Exception as error:
        result = {'result': 'failed', 'checks': checks, 'error': repr(error), 'ports': ports}
        raise
    finally:
        for fixture in fixtures:
            fixture.close()
        if 'result' in locals():
            (args.output / 'results.json').write_text(json.dumps(result, indent=2))
            print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--permission-probe':
        assert not ctypes.windll.shell32.IsUserAnAdmin(), 'The permission probe has an administrator token'
        user = ctypes.create_unicode_buffer(256)
        size = ctypes.c_uint(len(user))
        assert ctypes.windll.advapi32.GetUserNameW(user, ctypes.byref(size)), 'Could not identify the test user'
        store_path = Path(sys.argv[2])
        with open(store_path.parent.parent / store_path.name, 'rb') as journal:
            assert journal.read(16) == b'SQLite format 3\0', 'The metadata journal is not readable'
        try:
            with open(store_path, 'rb') as store:
                store.read(1)
        except PermissionError:
            pass
        else:
            raise AssertionError('The ordinary user could read the private HTTP Spy store')
        result = subprocess.run([sys.argv[3], '--httpspy', '--duration', '1'], capture_output=True, text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
        assert result.returncode != 0 and 'administrator privileges' in result.stderr, result
        Path(sys.argv[4]).write_text(json.dumps({'result': 'passed', 'account': user.value,
                                               'journal_read': 'allowed', 'store_read': 'denied',
                                               'live_capture': 'denied'}))
    else:
        main()
