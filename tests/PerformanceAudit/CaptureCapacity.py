import argparse
import concurrent.futures
import ctypes
from ctypes import wintypes
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import struct
import subprocess
import threading
import time


BLOCK = bytes(range(256)) * 256


def pacer(rate):
    lock = threading.Lock()
    next_send = time.perf_counter()

    def wait(size):
        nonlocal next_send
        if not rate:
            return
        with lock:
            send_at = max(next_send, time.perf_counter())
            next_send = send_at + size / (rate * 1048576)
        time.sleep(max(0, send_at - time.perf_counter()))
    return wait


def receive(tls, size):
    result = bytearray()
    while len(result) < size:
        data = tls.recv(size - len(result))
        if not data:
            raise RuntimeError('The TLS peer closed before completing the transfer')
        result.extend(data)
    return bytes(result)


def server(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    pace = pacer(args.bulk_mib_per_second)

    def accept(raw):
        try:
            with raw, context.wrap_socket(raw, server_side=True) as tls:
                command = receive(tls, 1)
                if command == b'H':
                    tls.sendall(b'H')
                    return
                remaining = total = struct.unpack('!Q', receive(tls, 8))[0]
                if command not in (b'D', b'U') or not 0 < total <= 16 * 1024 ** 3:
                    raise ValueError('Invalid capacity-test transfer')
                while remaining:
                    size = min(remaining, len(BLOCK))
                    if command == b'D':
                        pace(size)
                        tls.sendall(BLOCK[:size])
                    else:
                        receive(tls, size)
                    remaining -= size
                if command == b'U':
                    tls.sendall(struct.pack('!Q', total))
        except (OSError, ValueError, RuntimeError) as error:
            print(str(error), flush=True)

    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        listener.bind((args.host, args.port))
        listener.listen(256)
        args.output.mkdir(parents=True)
        (args.output / 'ready').write_text('ready')
        while True:
            raw, _ = listener.accept()
            raw.settimeout(90)
            pool.submit(accept, raw)


def sample_resources(pid, database, output, phase, stopped):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)

    class Memory(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ('peak_ws', 'ws', 'peak_paged', 'paged',
                                                'peak_nonpaged', 'nonpaged', 'pagefile', 'peak_pagefile', 'private')]

    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetSystemTimes.argtypes = [ctypes.POINTER(wintypes.FILETIME)] * 3
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
    handle = kernel.OpenProcess(0x1010, False, pid) if pid else None
    if pid and not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    def seconds(value):
        return ((value.dwHighDateTime << 32) | value.dwLowDateTime) / 10000000

    try:
        with output.open('w') as log:
            while not stopped.is_set():
                system = [wintypes.FILETIME() for _ in range(3)]
                if not kernel.GetSystemTimes(*(ctypes.byref(value) for value in system)):
                    raise ctypes.WinError(ctypes.get_last_error())
                row = dict(time=time.perf_counter(), phase=phase[0], cpu_count=os.cpu_count(),
                           system_idle_seconds=seconds(system[0]),
                           system_total_seconds=seconds(system[1]) + seconds(system[2]))
                if handle:
                    memory, times = Memory(), [wintypes.FILETIME() for _ in range(4)]
                    memory.cb = ctypes.sizeof(memory)
                    if (kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)) and
                            psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb)):
                        row.update(cpu_seconds=sum(seconds(value) for value in times[2:]),
                                   private_bytes=memory.private, working_set_bytes=memory.ws)
                    try:
                        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=.1) as connection:
                            connection.row_factory = sqlite3.Row
                            health = connection.execute('SELECT * FROM capture_sessions').fetchone()
                            if health:
                                row['health'] = dict(health)
                    except sqlite3.Error:
                        pass
                log.write(json.dumps(row) + '\n')
                log.flush()
                stopped.wait(.25)
    finally:
        if handle:
            kernel.CloseHandle(handle)


def verify(output):
    with sqlite3.connect((output / 'capture.db').as_uri() + '?mode=ro', uri=True) as connection:
        connection.row_factory = sqlite3.Row
        health = dict(connection.execute('SELECT * FROM capture_sessions').fetchone())
        integrity = connection.execute('PRAGMA integrity_check').fetchone()[0]
        batches = []
        for name in ('before', 'during', 'after', 'bulk'):
            expected = json.loads((output / (name + '.json')).read_text())
            sockets = {(row['local_address'], row['local_port']) for row in expected['sockets']}
            rows = list(connection.execute('SELECT source_address,source_port,state FROM connections WHERE sni=?',
                                           (expected['sni'],)))
            observed = {(row['source_address'], row['source_port']) for row in rows
                        if row['state'] == 'hellos_observed'}
            batches.append(dict(name=name, expected=len(sockets), observed=len(rows), both_hellos=len(observed),
                                missing=sorted(sockets - observed), unexpected=sorted(observed - sockets),
                                passed=len(rows) == len(expected['sockets']) == len(sockets) and observed == sockets))
    losses = {key: health[key] for key in ('capture_lost', 'queue_lost', 'storage_lost', 'process_events_lost',
                                         'telemetry_lost', 'malformed', 'flow_limit', 'reassembly_limit')}
    result = dict(passed=integrity == 'ok' and all(row['passed'] for row in batches) and not any(losses.values()),
                  all_handshakes_detected=all(row['passed'] for row in batches), batches=batches,
                  integrity=integrity, health=health)
    (output / 'verification.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(passed=result['passed'], all_handshakes_detected=result['all_handshakes_detected'],
                         losses=losses, batches=[{key: row[key] for key in ('name', 'expected', 'both_hellos')}
                                                for row in batches]), indent=2))
    return result['passed']


def summarize(output):
    bulk = json.loads((output / 'bulk.json').read_text())['sockets']
    during = json.loads((output / 'during.json').read_text())['sockets']
    resources = [json.loads(line) for line in (output / 'resources.jsonl').read_text().splitlines()]
    rates = {}
    for upload, label in ((False, 'download'), (True, 'upload')):
        transfers = [row for row in bulk if row['upload'] == upload]
        if transfers:
            elapsed = max(row['finished'] for row in transfers) - min(row['handshake_finished'] for row in transfers)
            rates[label] = sum(row['transferred_bytes'] for row in transfers) * 8 / 1e9 / elapsed
    start = min(row['handshake_finished'] for row in bulk)
    end = max(row['finished'] for row in bulk)
    phases = {}
    for phase in ('idle', 'concurrent', 'after', 'cooldown'):
        samples = [row for row in resources if row['phase'] == phase]
        if len(samples) < 2:
            continue
        first, last = samples[0], samples[-1]
        elapsed = last['time'] - first['time']
        total = last['system_total_seconds'] - first['system_total_seconds']
        idle = last['system_idle_seconds'] - first['system_idle_seconds']
        phases[phase] = dict(seconds=elapsed, guest_cpu_percent=100 * (1 - idle / total) if total else None)
        if 'cpu_seconds' in first and 'cpu_seconds' in last:
            cpu = 100 * (last['cpu_seconds'] - first['cpu_seconds']) / elapsed
            phases[phase]['collector_cpu_one_core_percent'] = cpu
    latencies = sorted((row['handshake_finished'] - row['started']) * 1000 for row in during)
    result = dict(rates_gbps=rates, bulk_seconds=end-start, during_expected=len(during),
                  overlapping_handshakes=sum(row['started'] < end and row['handshake_finished'] > start
                                            for row in during),
                  handshake_latency_ms={key: latencies[round((len(latencies) - 1) * fraction)]
                                        for key, fraction in (('p50', .5), ('p95', .95), ('p99', .99))},
                  resource_phases=phases,
                  peak_private_mib=max((row.get('private_bytes', 0) for row in resources), default=0) / 1048576)
    (output / 'performance.json').write_text(json.dumps(result, indent=2))


def capture(args):
    args.output.mkdir(parents=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    pace = pacer(args.bulk_mib_per_second)
    rate = args.bulk_mib_per_second or 1120
    per_direction = 4 if args.direction == 'both' else 8
    target = math.ceil(rate * args.seconds * 1048576 / per_direction / len(BLOCK)) * len(BLOCK)
    database = args.output / 'capture.db'
    stopped, phase = threading.Event(), ['startup']

    def exchange(sni, bulk=False, upload=False):
        started = time.perf_counter()
        with socket.create_connection((args.host, args.port), timeout=90) as raw:
            with context.wrap_socket(raw, server_hostname=sni) as tls:
                local = tls.getsockname()
                handshake_finished = time.perf_counter()
                transferred = 0
                if bulk:
                    tls.sendall((b'U' if upload else b'D') + struct.pack('!Q', target))
                    while transferred < target:
                        size = min(target - transferred, len(BLOCK))
                        if upload:
                            pace(size)
                            tls.sendall(BLOCK[:size])
                            transferred += size
                        else:
                            data = tls.recv(size)
                            if not data:
                                raise RuntimeError('The bulk transfer ended early')
                            transferred += len(data)
                    if upload and struct.unpack('!Q', receive(tls, 8))[0] != target:
                        raise RuntimeError('The server did not acknowledge the complete upload')
                else:
                    tls.sendall(b'H')
                    if receive(tls, 1) != b'H':
                        raise RuntimeError('The handshake probe failed')
                return dict(local_address=local[0], local_port=local[1], started=started,
                            handshake_finished=handshake_finished, finished=time.perf_counter(),
                            transferred_bytes=transferred, upload=upload)

    def batch(label, count, frequency=0):
        sni = label + '.capacity.cipherazzi.test'
        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futures = []
            for index in range(count):
                if frequency:
                    time.sleep(max(0, started + index / frequency - time.perf_counter()))
                futures.append(pool.submit(exchange, sni))
            rows = [future.result() for future in futures]
        (args.output / (label + '.json')).write_text(json.dumps(dict(sni=sni, sockets=rows), indent=2))

    settings = {key: value for key, value in vars(args).items() if key not in ('cert', 'key')}
    (args.output / 'settings.json').write_text(json.dumps(settings, default=str, indent=2))
    with (args.output / 'collector.stdout').open('w') as log, (args.output / 'collector.stderr').open('w') as errors:
        process = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
            monitor = None
            try:
                startup = time.perf_counter()
                if not args.without_collector:
                    command = [str(args.collector), '--db', str(database), '--duration', str(args.duration)]
                    if args.classify_raw:
                        command.append('--classify-raw')
                    process = subprocess.Popen(command, stdout=log, stderr=errors)
                monitor = pool.submit(sample_resources, process.pid if process else None, database,
                                      args.output / 'resources.jsonl', phase, stopped)
                if process:
                    deadline = time.monotonic() + 15
                    while 'Capturing TLS' not in (args.output / 'collector.stdout').read_text():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError('The collector did not start')
                        time.sleep(.05)
                    (args.output / 'startup.json').write_text(json.dumps(dict(seconds=time.perf_counter() - startup)))
                phase[0] = 'idle'
                time.sleep(5)
                phase[0] = 'before'
                batch('before', 100)
                phase[0] = 'concurrent'
                bulk_sni = 'bulk.capacity.cipherazzi.test'
                bulk = [pool.submit(exchange, bulk_sni, True,
                                    args.direction == 'upload' or (args.direction == 'both' and index >= 4))
                        for index in range(8)]
                time.sleep(.2)
                batch('during', round(args.seconds * args.handshakes_per_second), args.handshakes_per_second)
                rows = [future.result() for future in bulk]
                (args.output / 'bulk.json').write_text(json.dumps(dict(sni=bulk_sni, sockets=rows), indent=2))
                phase[0] = 'after'
                batch('after', 1000)
                phase[0] = 'cooldown'
                if process:
                    if process.poll() is not None:
                        raise RuntimeError('Capture stopped before the workload finished')
                    if process.wait(timeout=args.duration + 15):
                        raise RuntimeError('The collector failed')
                else:
                    time.sleep(5)
            finally:
                stopped.set()
                if process and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                if monitor:
                    monitor.result()
    summarize(args.output)
    return True if args.without_collector else verify(args.output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('server', 'capture', 'verify'))
    parser.add_argument('--host')
    parser.add_argument('--port', type=int, default=24449)
    parser.add_argument('--output', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--collector', type=lambda value: Path(value).resolve())
    parser.add_argument('--duration', type=int, default=55)
    parser.add_argument('--seconds', type=float, default=20)
    parser.add_argument('--handshakes-per-second', type=int, default=50)
    parser.add_argument('--bulk-mib-per-second', type=float, default=112)
    parser.add_argument('--direction', choices=('download', 'upload', 'both'), default='download')
    parser.add_argument('--classify-raw', action='store_true')
    parser.add_argument('--without-collector', action='store_true')
    arguments = parser.parse_args()
    if (not 0 <= arguments.bulk_mib_per_second <= 2000 or not 1 <= arguments.seconds <= 60 or
            not 1 <= arguments.handshakes_per_second <= 1000):
        parser.error('Capacity settings exceed the supported test bounds')
    if arguments.mode != 'verify' and not arguments.host:
        parser.error('--host is required')
    if arguments.mode == 'server':
        if not arguments.cert or not arguments.key:
            parser.error('--cert and --key are required')
        server(arguments)
    elif arguments.mode == 'verify':
        raise SystemExit(0 if verify(arguments.output) else 1)
    else:
        if not arguments.without_collector and not arguments.collector:
            parser.error('--collector is required')
        raise SystemExit(0 if capture(arguments) else 1)
