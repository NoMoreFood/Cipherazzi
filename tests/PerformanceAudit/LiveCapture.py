import argparse
import concurrent.futures
import json
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from pathlib import Path


def exchange(context, host, port, sni, bulk):
    with socket.create_connection((host, port), timeout=30) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            local = tls.getsockname()
            tls.sendall(b'B' if bulk else b'H')
            received = 0
            while data := tls.recv(65536):
                received += len(data)
                if not bulk:
                    break
            expected = 32 * 1048576 if bulk else 1
            if received != expected:
                raise RuntimeError(f'Expected {expected} bytes, received {received}')
            return dict(local_address=local[0], local_port=local[1], received_bytes=received)


def workload(args, label, bulk=False):
    # Use real completed TLS exchanges and retain each socket tuple as independent detection evidence.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sni = label + '.performance.cipherazzi.test'
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: exchange(context, args.host, args.port, sni, bulk),
                                range(8 if bulk else 1000)))
    elapsed = time.perf_counter() - started
    result = dict(sni=sni, expected=len(results), seconds=elapsed, sockets=results,
                  mib_per_second=sum(row['received_bytes'] for row in results) / 1048576 / elapsed)
    (args.output / (label + '.json')).write_text(json.dumps(result, indent=2))


def verify(output):
    expected = [json.loads(path.read_text()) for path in sorted(output.glob('capture-*.json'))]
    if len(expected) != 6:
        raise RuntimeError('Expected three TLS batches and three bulk transfers')
    with sqlite3.connect(f'{(output / "capture.db").as_uri()}?mode=ro', uri=True) as connection:
        connection.row_factory = sqlite3.Row
        health = dict(connection.execute('SELECT * FROM capture_sessions').fetchone())
        integrity = connection.execute('PRAGMA integrity_check').fetchone()[0]
        batches = []
        for batch in expected:
            rows = list(connection.execute('''
                SELECT source_address, source_port, state FROM connections WHERE sni=?''', (batch['sni'],)))
            observed = {(row['source_address'], row['source_port']) for row in rows
                        if row['state'] == 'hellos_observed'}
            sockets = {(row['local_address'], row['local_port']) for row in batch['sockets']}
            batches.append(dict(sni=batch['sni'], expected=batch['expected'], observed=len(rows),
                both_hellos=len(observed), missing=sorted(sockets - observed), unexpected=sorted(observed - sockets),
                passed=len(rows) == batch['expected'] and observed == sockets and len(sockets) == batch['expected']))
    losses = {key: health[key] for key in ('capture_lost', 'queue_lost', 'storage_lost', 'process_events_lost',
                                         'flow_limit', 'reassembly_limit')}
    result = dict(passed=integrity == 'ok' and all(batch['passed'] for batch in batches) and not any(losses.values()),
                  batches=batches, integrity=integrity, health=health)
    (output / 'verification.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(passed=result['passed'], batches=[{key: row[key] for key in
                     ('sni', 'expected', 'observed', 'both_hellos', 'passed')} for row in batches], losses=losses),
                     indent=2))
    return result['passed']


def capture(args):
    args.output.mkdir(parents=True)
    workload(args, 'warmup')
    command = [str(args.collector), '--db', str(args.output / 'capture.db'), '--duration', str(args.duration)]
    if args.classify_raw:
        command.append('--classify-raw')
    (args.output / 'settings.json').write_text(json.dumps(dict(classify_raw=args.classify_raw,
                                                             duration=args.duration), indent=2))
    stdout = args.output / 'collector.stdout'
    with stdout.open('w') as log, (args.output / 'collector.stderr').open('w') as errors:
        process = subprocess.Popen(command, stdout=log, stderr=errors)
        try:
            deadline = time.monotonic() + 15
            while 'Capturing TLS' not in stdout.read_text():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('The live collector did not start')
                time.sleep(.05)
            time.sleep(5)
            for iteration in range(3):
                workload(args, f'capture-handshakes-{iteration}')
                workload(args, f'capture-bulk-{iteration}', bulk=True)
                if process.poll() is not None:
                    raise RuntimeError('The live collector stopped during the workload')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                for _ in range(50000):
                    udp.sendto(b'\xfa' + bytes(range(256)) * 4, (args.host, args.port + 1))
            if process.wait(timeout=args.duration + 15):
                raise RuntimeError('The live collector failed')
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
    return verify(args.output)


def serve(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    block = bytes(range(256)) * 256
    pacing = threading.Lock()
    next_send = time.perf_counter()

    def accept(raw):
        nonlocal next_send
        try:
            with raw, context.wrap_socket(raw, server_side=True) as tls:
                bulk = tls.recv(1) == b'B'
                for _ in range(512 if bulk else 1):
                    # An optional aggregate payload ceiling makes link-capacity comparisons reproducible.
                    if bulk and args.bulk_mib_per_second:
                        with pacing:
                            send_at = max(next_send, time.perf_counter())
                            next_send = send_at + len(block) / (args.bulk_mib_per_second * 1048576)
                        time.sleep(max(0, send_at - time.perf_counter()))
                    tls.sendall(block if bulk else b'H')
        except (OSError, ssl.SSLError) as error:
            print(str(error), flush=True)

    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        listener.bind((args.host, args.port))
        listener.listen(256)
        args.output.mkdir(parents=True)
        (args.output / 'settings.json').write_text(json.dumps(dict(bulk_mib_per_second=args.bulk_mib_per_second)))
        (args.output / 'ready').write_text('ready')
        while True:
            raw, _ = listener.accept()
            raw.settimeout(30)
            pool.submit(accept, raw)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('server', 'capture', 'verify'))
    parser.add_argument('--host')
    parser.add_argument('--port', type=int, default=24449)
    parser.add_argument('--output', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--collector', type=lambda value: Path(value).resolve())
    parser.add_argument('--duration', type=int, default=90)
    parser.add_argument('--classify-raw', action='store_true')
    parser.add_argument('--bulk-mib-per-second', type=float, default=0)
    arguments = parser.parse_args()
    if not 0 <= arguments.bulk_mib_per_second < float('inf'):
        parser.error('--bulk-mib-per-second must be finite and nonnegative')
    if arguments.mode != 'verify' and not arguments.host:
        parser.error('--host is required for server and capture')
    if arguments.mode == 'server':
        if not arguments.cert or not arguments.key:
            parser.error('--cert and --key are required for server')
        serve(arguments)
    else:
        if arguments.mode == 'capture' and not arguments.collector:
            parser.error('--collector is required for capture')
        raise SystemExit(0 if (capture(arguments) if arguments.mode == 'capture' else verify(arguments.output)) else 1)
