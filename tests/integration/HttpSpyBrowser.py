import argparse
import http.server
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from HttpSpy import IDENTITY, Wire, pcap

BROWSERS = (r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
            r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
            r'C:\Program Files\Google\Chrome\Application\chrome.exe')
PAGE = b'''<!doctype html><title>HTTP Spy</title><body>ready<script>
fetch('/api?x=1',{headers:{'X-Test':'browser'}}).then(r=>r.text()).then(t=>
fetch('/post',{method:'POST',body:'name=value&token='+t}).then(r=>r.text()).then(
t=>{document.body.append(' done ' + t)}));
</script></body>'''


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def reply(self, body, kind='text/plain'):
        self.send_response(200)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Set-Cookie', 'session=server-secret')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(PAGE if self.path == '/' else b'api-result', 'text/html' if self.path == '/' else 'text/plain')

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.reply(b'posted')

    def log_message(self, *arguments):
        pass


def relay(listener, backend, wires, packets, clock, lock):
    """Forwards each browser connection to the server while recording both directions as network traffic."""
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        with lock:
            wire = Wire(packets, clock, 9100 + len(wires))
            wire.open()
            wires.append(wire)
        server = socket.create_connection(backend)

        def pipe(source, target, side, recorder):
            try:
                while data := source.recv(65536):
                    with lock:
                        recorder.send(side, data)
                    target.sendall(data)
            except OSError:
                pass
            finally:
                for value in (source, target):
                    try:
                        value.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        threading.Thread(target=pipe, args=(client, server, 0, wire), daemon=True).start()
        threading.Thread(target=pipe, args=(server, client, 1, wire), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--collector', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--browser', type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True)
    browser = args.browser or next((Path(path) for path in BROWSERS if Path(path).exists()), None)
    assert browser, 'Install Microsoft Edge or Google Chrome to run this check.'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(IDENTITY)
    context.set_alpn_protocols(['http/1.1'])
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    packets, wires, lock, clock = [], [], threading.Lock(), [time.time_ns() // 1000]
    threading.Thread(target=relay, args=(listener, server.server_address, wires, packets, clock, lock),
                     daemon=True).start()

    # The browser exports its secrets because the environment asks it to; no proxy is configured.
    keylog = output / 'browser-secrets.log'
    profile = Path(tempfile.mkdtemp(prefix='httpspy-profile-'))
    try:
        environment = dict(__import__('os').environ, SSLKEYLOGFILE=str(keylog))
        result = subprocess.run([str(browser), '--headless=new', '--disable-gpu', '--no-first-run',
            '--disable-quic', '--ignore-certificate-errors', '--user-data-dir=' + str(profile),
            '--virtual-time-budget=8000', '--dump-dom', f'https://127.0.0.1:{listener.getsockname()[1]}/'],
            capture_output=True, text=True, env=environment, timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
    finally:
        time.sleep(1)
        shutil.rmtree(profile, ignore_errors=True)
    assert 'done posted' in result.stdout, result.stdout + result.stderr
    with lock:
        for wire in wires:
            wire.close()
    capture = output / 'browser.pcap'
    pcap(capture, packets)
    assert keylog.exists() and keylog.stat().st_size > 0, 'The browser exported no TLS secrets.'
    command = [str(args.collector.resolve()), '--db', str(output / 'browser.db'), '--replay', str(capture),
               '--no-process', '--httpspy', '--keylog', str(keylog)]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=60,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    (output / 'browser.log').write_text(completed.stdout + completed.stderr, encoding='utf-8')
    with sqlite3.connect(output / 'HttpSpy' / 'browser.db') as connection:
        rows = connection.execute('SELECT method,target,status,state,request_headers,request_body,response_body '
                                  'FROM exchanges WHERE state="complete" ORDER BY started_us').fetchall()
    targets = {(row[0], row[1]): row for row in rows}
    assert ('GET', '/') in targets and ('GET', '/api?x=1') in targets and ('POST', '/post') in targets, rows
    assert bytes(targets[('GET', '/')][6]) == PAGE and targets[('GET', '/api?x=1')][2] == 200, rows
    assert 'X-Test: browser' in targets[('GET', '/api?x=1')][4].replace('x-test', 'X-Test'), rows
    assert bytes(targets[('POST', '/post')][5]) == b'name=value&token=api-result', rows
    print('A real browser was decoded without a proxy: ' + str(len(rows)) + ' messages.')


if __name__ == '__main__':
    main()
