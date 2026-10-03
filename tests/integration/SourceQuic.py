import argparse
import json
import sqlite3
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--certificate', required=True, type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.output.resolve()
    work.mkdir(parents=True)
    results = []
    for address in ['127.0.0.1:0', '[::1]:0']:
        for mode in ['ok', 'reject', 'lost-directory']:
            directory = work / f'{"ipv6" if address.startswith("[") else "ipv4"}-{mode}'
            directory.mkdir()
            result = subprocess.run([str(value) for value in [args.client, directory, args.certificate,
                args.key, mode, address]], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=20)
            assert result.returncode == 0, (result.stdout, result.stderr)
            if mode == 'lost-directory':
                assert not directory.exists()
                results.append(dict(address=address, mode=mode, report_failure_separate=True))
                continue
            reports = [json.loads(path.read_text()) for path in directory.glob('*.json')]
            assert len(reports) == (4 if mode == 'ok' else 1)
            for report in reports:
                assert report['provider'] == 'Rust/rustls' and report['transport'] == 'QUIC'
                assert report['success'] == (mode == 'ok')
                assert report['local']['port'] and report['remote']['port']
                assert 'peer_verified' not in report
                if report.get('observation') == 'connection':
                    assert 'handshake_started_us' not in report
                else:
                    assert report['process_started_us'] <= report['handshake_started_us'] <= report['timestamp_us']
                if mode == 'ok':
                    assert report['tls_version'] == 772 and report['cipher_id'] and report['group_id']
                    assert report['selected_alpn'] == 'coverage' and not report['session_resumed']
                    if report['role'] == 'client':
                        assert report['server_certificates_der']
            imported = subprocess.run([str(root / 'tools/artifacts/build/bin/Release/Cipherazzi.Tests.exe'),
                '--import-endpoints', str(directory), str(directory / 'events.db')], capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=20)
            assert imported.returncode == 0, imported.stderr
            with sqlite3.connect(directory / 'events.db') as database:
                assert database.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == len(reports)
            results.append(dict(address=address, mode=mode, reports=len(reports), native_import=True))
    (work / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
