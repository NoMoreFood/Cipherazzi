import argparse
import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--collector', required=True, type=Path)
    parser.add_argument('--tshark', required=True, type=Path)
    parser.add_argument('--roce', required=True, type=Path)
    parser.add_argument('--iwarp', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True)
    results = []
    fields = ['frame.number', 'smb2.flags.response', 'smb2.dialect', 'smb2.flags.signature',
        'smb2.negotiate_context.cipher_id', 'smb_direct.version.negotiated']
    reference = [str(args.tshark.resolve()), '-2', '-n', '-r', str(args.roce.resolve()), '-Y', 'smb2 || smb_direct',
        '-T', 'fields']
    for field in fields:
        reference.extend(['-e', field])
    checked = subprocess.run(reference, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=120)
    assert checked.returncode == 0, checked.stderr.decode(errors='replace')
    (output / 'reference.tsv').write_bytes(checked.stdout)
    rows = [line.split('\t') for line in checked.stdout.decode().splitlines()]
    responses = [row for row in rows if row[1].lower() == 'true' and row[2]]
    assert len(responses) == 1 and responses[0][2] == '0x0311'
    assert any(row[3].lower() == 'true' for row in rows), 'The reference did not observe signed SMB messages'
    captures = [('roce', args.roce.resolve(), 'SMB Direct / RoCEv2')]
    if args.iwarp:
        captures.append(('iwarp', args.iwarp.resolve(), 'SMB Direct / iWARP'))
    for name, capture, framing in captures:
        database = output / (name + '.db')
        assert not database.exists(), 'Choose a fresh output directory'
        collected = subprocess.run([str(args.collector.resolve()), '--no-process', '--db', str(database),
            '--replay', str(capture)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
        (output / (name + '.stdout')).write_bytes(collected.stdout)
        (output / (name + '.stderr')).write_bytes(collected.stderr)
        assert collected.returncode == 0, collected.stderr.decode(errors='replace')
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            records = [json.loads(row[0]) for row in connection.execute('SELECT crypto_json FROM connections')]
            assert len(records) == 1, 'A single captured RDMA session was omitted or split into unrelated flows'
            evidence = records[0]
            health = dict(connection.execute('SELECT packets,observations,malformed,unsupported,reassembly_limit,'
                'capture_lost,queue_lost,storage_lost,buffered_bytes,active_flows FROM capture_sessions').fetchone())
            assert not any(health[key] for key in ('malformed', 'capture_lost', 'queue_lost', 'storage_lost',
                'buffered_bytes', 'active_flows'))
            assert evidence['smb_transport_framing'] == framing and evidence['smb_signed_message_observed']
            assert 'smb_encrypted_transform_observed' not in evidence, 'Signing was mistaken for encryption'
            if name == 'roce':
                assert evidence['smb_selected_dialect'] == responses[0][2]
                assert evidence['smb_selected_cipher'] == responses[0][4].split(',')
                assert evidence['smb_direct_server_negotiation']['selected_version'] == \
                    next(row[5] for row in rows if row[5])
                assert evidence['roce_client_queue_pair'] == 25 and evidence['roce_server_queue_pair'] == 88
                assert evidence['roce_connection_management_observed'] and evidence['roce_ready_observed']
                assert health['packets'] == 75659 and health['reassembly_limit'] == 1
            else:
                assert evidence['smb_offered_dialects'] == ['0x0202', '0x0210', '0x0300']
                assert evidence['smb_iwarp_crc_checked'] and not evidence['smb_iwarp_markers']
                assert 'smb_selected_dialect' not in evidence and 'smb_direct_server_negotiation' not in evidence
                assert health['packets'] == 37 and health['reassembly_limit'] == 0
            results.append(dict(name=name, capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
                framing=framing, reference_compared=name == 'roce', health=health))
    (output / 'results.json').write_text(json.dumps(dict(cases=results,
        collector_sha256=hashlib.sha256(args.collector.read_bytes()).hexdigest(),
        peer_receive_sequence_preserved=True, protection_not_inferred_from_negotiation=True), indent=2))
    print(f'{len(results)} published RDMA captures passed metadata, integrity, and inspection-boundary checks.')


if __name__ == '__main__':
    main()
