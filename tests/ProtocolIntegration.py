import argparse
import gzip
import json
import os
import socket
import sqlite3
import subprocess
import threading
import time
import zlib
from pathlib import Path


SSH_CASES = [
    ('ssh-ctr', 'curve25519-sha256', 'aes128-ctr', 'hmac-sha2-256', 'ssh-ed25519'),
    ('ssh-gcm', 'ecdh-sha2-nistp256', 'aes256-gcm@openssh.com', 'AEAD', 'rsa-sha2-512'),
    ('ssh-chacha', 'curve25519-sha256', 'chacha20-poly1305@openssh.com', 'AEAD', 'ssh-ed25519'),
    ('ssh-legacy', 'diffie-hellman-group1-sha1', '3des-cbc', 'hmac-sha1', 'ssh-rsa'),
]


def serve(host, output):
    stop = threading.Event()
    tcp = socket.socket()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp.bind((host, 24446))
    udp.bind((host, 24446))
    tcp.listen(16)
    tcp.settimeout(0.5)
    udp.settimeout(0.5)

    def drain(client):
        with client:
            client.settimeout(10)
            try:
                while client.recv(65536):
                    pass
            except OSError:
                pass

    def accept():
        while not stop.is_set():
            try:
                client = tcp.accept()[0]
                threading.Thread(target=drain, args=(client,), daemon=True).start()
            except socket.timeout:
                continue

    def datagrams():
        while not stop.is_set():
            try:
                udp.recvfrom(65536)
            except socket.timeout:
                continue

    threads = [threading.Thread(target=accept), threading.Thread(target=datagrams)]
    for thread in threads:
        thread.start()
    (output / 'ready.json').write_text(json.dumps({'host': host, 'port': 24446}), encoding='utf-8')
    try:
        while not (output / 'stop').exists():
            time.sleep(0.2)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=2)
        tcp.close()
        udp.close()


def execute(host, ssh, output):
    cases = []
    for name, kex, cipher, mac, host_key in SSH_CASES:
        # Complete real initial key exchange; the lab deliberately has no authorized login account.
        command = [str(ssh), '-F', 'NUL', '-vv', '-p', '24422', '-o', 'BatchMode=yes',
                   '-o', 'PreferredAuthentications=none', '-o', 'StrictHostKeyChecking=no',
                   '-o', 'UserKnownHostsFile=NUL', '-o', 'ConnectTimeout=10',
                   '-o', f'KexAlgorithms={kex}', '-o', f'Ciphers={cipher}',
                   '-o', f'HostKeyAlgorithms={host_key}', '-o',
                   'MACs=hmac-sha2-256' if mac == 'AEAD' else f'MACs={mac}',
                   f'CipherazziProbeUserDoesNotExist@{host}']
        started = time.time_ns() // 1000
        result = subprocess.run(command, capture_output=True, text=True, timeout=20,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        completed = time.time_ns() // 1000
        (output / (name + '.stdout')).write_text(result.stdout, encoding='utf-8')
        (output / (name + '.stderr')).write_text(result.stderr, encoding='utf-8')
        evidence = result.stderr
        assert 'SSH2_MSG_NEWKEYS received' in evidence and 'SSH2_MSG_NEWKEYS sent' in evidence, evidence
        assert f'kex: algorithm: {kex}' in evidence and f'kex: host key algorithm: {host_key}' in evidence, evidence
        assert f'cipher: {cipher}' in evidence, evidence
        cases.append(dict(name=name, protocol='SSH', started_us=started, completed_us=completed,
                          destination_port=24422, kex=kex, cipher=cipher, mac=mac, host_key=host_key,
                          exit_code=result.returncode, authentication='Login deliberately unavailable'))
    controls = [
        ('tcp-random', 'TCP', os.urandom(8192), True),
        ('tcp-plaintext', 'TCP', b'Cipherazzi plaintext control.\n' * 400, False),
        ('tcp-short', 'TCP', os.urandom(128), False),
        ('tcp-gzip', 'TCP', gzip.compress(os.urandom(6000)), False),
        ('tcp-zlib', 'TCP', zlib.compress(os.urandom(6000)), False),
        ('udp-random', 'UDP', os.urandom(8192), True),
        ('udp-short', 'UDP', os.urandom(128), False),
        ('udp-gzip', 'UDP', gzip.compress(os.urandom(6000)), False),
    ]
    for name, transport, payload, expected in controls:
        started = time.time_ns() // 1000
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == 'TCP' else socket.SOCK_DGRAM) as sender:
            sender.settimeout(10)
            sender.connect((host, 24446))
            source_port = sender.getsockname()[1]
            if transport == 'TCP':
                for offset in range(0, len(payload), 997):
                    sender.sendall(payload[offset:offset + 997])
            else:
                for offset in range(0, len(payload), 997):
                    sender.send(payload[offset:offset + 997])
            time.sleep(0.15)
        cases.append(dict(name=name, protocol='Unknown', transport=transport, started_us=started,
                          completed_us=time.time_ns() // 1000, source_port=source_port, destination_port=24446,
                          expected=expected, payload_bytes=len(payload), pid=os.getpid()))
    (output / 'executions.json').write_text(json.dumps(cases, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'executed': len(cases), 'ssh_newkeys_confirmed': len(SSH_CASES)}))


def verify(database_path, output, raw_enabled):
    cases = json.loads((output / 'executions.json').read_text(encoding='utf-8'))
    with sqlite3.connect(database_path.resolve().as_uri() + '?mode=ro', uri=True) as database:
        database.row_factory = sqlite3.Row
        assert database.execute('pragma integrity_check').fetchone()[0] == 'ok'
        rows = [dict(row) for row in database.execute('select * from connections')]
        sessions = [dict(row) for row in database.execute('select * from capture_sessions')]
    for row in rows:
        row['crypto'] = json.loads(row['crypto_json'])
    checked = []
    for case in cases:
        candidates = [row for row in rows if row['destination_port'] == case['destination_port'] and
                      case['started_us'] - 10000 <= row['first_us'] <= case['completed_us'] + 10000 and
                      ('source_port' not in case or row['source_port'] == case['source_port'])]
        if case['protocol'] == 'SSH':
            assert len(candidates) == 1, (case, candidates)
            row = candidates[0]
            crypto = row['crypto']
            selected = crypto['ssh_selection']
            assert crypto['protocol'] == 'SSH' and row['tls_version'] is None and row['cipher_id'] is None, row
            assert row['state'] == 'ssh_newkeys_observed', row
            assert selected['key_exchange'] == case['kex'] and selected['host_key'] == case['host_key'], selected
            assert selected['cipher_c2s'] == selected['cipher_s2c'] == case['cipher'], selected
            assert selected['mac_c2s'] == selected['mac_s2c'] == case['mac'], selected
            assert 'authentication outcome unknown' in crypto['handshake_confirmation'], crypto
            checked.append(dict(name=case['name'], result='Passed', connection_id=row['id'], selection=selected))
        else:
            expected = case['expected'] and raw_enabled
            assert len(candidates) == (1 if expected else 0), (case, candidates)
            if expected:
                row = candidates[0]
                crypto = row['crypto']
                assert row['state'] == 'possible_encryption' and row['tls_version'] is None, row
                assert row['cipher_id'] is None and not row['cipher_name'] and not row['encryption'], row
                assert crypto['protocol'] == 'Unknown' and crypto['transport'] == case['transport'], crypto
                assert 4096 <= crypto['sample_bytes'] <= 8192 and crypto['sample_entropy'] >= 7.8, crypto
            checked.append(dict(name=case['name'], result='Passed', classification_present=bool(candidates)))
    losses = ('capture_lost', 'queue_lost', 'storage_lost', 'process_events_lost', 'telemetry_lost',
              'truncated', 'malformed', 'flow_limit', 'reassembly_limit')
    assert sessions and all(session['status'] == 'stopped' for session in sessions), sessions
    assert all(session[field] == 0 for session in sessions for field in losses), sessions
    report = dict(verified=True, raw_enabled=raw_enabled, database=str(database_path),
                  cases=checked, health={field: sum(session[field] for session in sessions) for field in losses})
    (output / 'verified-results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serve')
    parser.add_argument('--host')
    parser.add_argument('--ssh', type=Path)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--raw-enabled', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.serve:
        serve(args.serve, args.output)
    elif args.verify:
        verify(args.verify, args.output, args.raw_enabled)
    else:
        execute(args.host, args.ssh, args.output)


if __name__ == '__main__':
    main()
