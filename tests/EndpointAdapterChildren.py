import argparse
import json
import socket
import ssl
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--openssl', required=True)
    parser.add_argument('--nss', required=True)
    parser.add_argument('--boringssl', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    work = Path(args.output).resolve()
    work.mkdir(parents=True)
    adapter = root / 'build/bin/Release/Cipherazzi.EndpointAdapter.exe'
    certificate, key = work / 'cert.pem', work / 'key.pem'
    generated = subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=adapter.lab', '-keyout', str(key), '-out', str(certificate)], capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    assert generated.returncode == 0, generated.stderr.decode(errors='replace')
    (work / 'cert.der').write_bytes(ssl.PEM_cert_to_DER_cert(certificate.read_text()))
    results = []

    def wait_for(predicate, description, timeout=15):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert predicate(), description

    try:
        for mode in ('launcher-exit', 'detach', 'attach-existing', 'attach-existing-no-children',
            'attach-existing-detach'):
            existing = mode.startswith('attach-existing')
            detached = mode in ('detach', 'attach-existing-detach')
            root_only = mode == 'attach-existing-no-children'
            directory = work / mode
            directory.mkdir()
            reports = directory / 'reports'
            reports.mkdir()
            observed, errors, commands, gates, listeners, workers = [], [], [], [], [], []
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(certificate, key)
            context.set_alpn_protocols(['h2'])

            def serve(listener, provider, port):
                try:
                    raw, peer = listener.accept()
                    with raw, context.wrap_socket(raw, server_side=True) as connection:
                        connection.settimeout(10)
                        payload = connection.recv(256)
                        assert payload == b'cipherazzi-private-application-data-sentinel', payload
                        connection.sendall(b'ok')
                        observed.append(dict(provider=provider, port=port, peer=peer,
                            version=connection.version(), alpn=connection.selected_alpn_protocol()))
                        try:
                            connection.unwrap().close()
                        except (ssl.SSLEOFError, ConnectionResetError):
                            pass
                except Exception as error:
                    errors.append(str(error))
                finally:
                    listener.close()

            providers = ['openssl', 'nss', 'boringssl', *(['openssl'] if detached or existing else [])]
            for index, provider in enumerate(providers):
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(25)
                listeners.append(listener)
                port = listener.getsockname()[1]
                worker = threading.Thread(target=serve, args=(listener, provider, port), daemon=True)
                workers.append(worker)
                worker.start()
                gate = directory / f'release-{index}'
                gates.append(gate)
                command = [sys.executable, str(root / 'tests/clients' /
                    ('NssClient.py' if provider == 'nss' else 'ApiTlsClient.py')), '--library',
                    args.nss if provider == 'nss' else args.boringssl if provider == 'boringssl' else
                    str(Path(args.openssl).parent), '--port', str(port), '--certificate',
                    str(work / 'cert.der' if provider == 'nss' else certificate), '--version', '772',
                    '--hostname', 'adapter.lab']
                if provider != 'nss':
                    command += ['--provider', provider]
                if index < 3:
                    command += ['--gate', str(gate)]
                commands.append(command)
            pids, release, finished = directory / 'pids.json', directory / 'parent-release', directory / 'finished'
            configuration = directory / 'configuration.json'
            nested_pids = directory / 'nested-pids.json'
            values = dict(commands=commands[:3], pids=str(pids), release=str(release),
                finished=str(finished), late=commands[-1])
            if existing:
                nested = directory / 'nested.json'
                nested.write_text(json.dumps(dict(commands=commands[2:3], pids=str(nested_pids),
                    release=str(release), finished=str(directory / 'nested-finished'))))
                values.update(commands=commands[:2], nested=str(nested), observe_late=True)
            configuration.write_text(json.dumps(values))
            launcher = None
            if existing:
                with (directory / 'launcher.stdout').open('wb') as stdout, \
                    (directory / 'launcher.stderr').open('wb') as stderr:
                    launcher = subprocess.Popen([sys.executable, str(root / 'tests/clients/TlsChildLauncher.py'),
                        '--configuration', str(configuration), '--hold'], stdout=stdout, stderr=stderr,
                        creationflags=subprocess.CREATE_NO_WINDOW)
                wait_for(lambda: pids.exists() and nested_pids.exists() and all(
                    Path(str(gate) + '.ready').exists() for gate in gates[:3]),
                    'Existing descendants did not reach their handshake gates')
            with (directory / 'adapter.stdout').open('wb') as stdout, \
                (directory / 'adapter.stderr').open('wb') as stderr:
                observer = subprocess.Popen([str(adapter), '--output', str(reports),
                    *(['--duration', '3'] if detached else []), *(['--no-children'] if root_only else []),
                    *(['--pid', str(launcher.pid)] if existing else ['--spawn', sys.executable, '--',
                        str(root / 'tests/clients/TlsChildLauncher.py'), '--configuration', str(configuration),
                        *(['--detach'] if detached else [])])], stdout=stdout, stderr=stderr,
                    creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    wait_for(lambda: pids.exists() and all(Path(str(gate) + '.ready').exists()
                        for gate in gates[:3]), 'TLS descendants did not reach their handshake gates')
                    identities = json.loads(pids.read_text())
                    if existing:
                        assert launcher.poll() is None, 'The existing parent exited before attachment'
                        identities = identities[:2] + json.loads(nested_pids.read_text())
                    targets = [launcher.pid] if root_only else identities
                    wait_for(lambda: all(f'Observing PID {pid};' in (directory / 'adapter.stdout').read_text()
                        for pid in targets),
                        'TLS descendants were not attached')
                    if detached:
                        assert observer.wait(10) == 0, (directory / 'adapter.stderr').read_text()
                    for gate in gates[:3]:
                        gate.write_text('Handshake released')
                    if detached or existing:
                        release.write_text('Parent remains usable')
                        wait_for(finished.exists, 'The parent or children did not survive timed detach')
                    if not detached:
                        assert observer.wait(20) == (2 if root_only else 0), (directory / 'adapter.stderr').read_text()
                    if launcher:
                        assert launcher.wait(10) == 0, (directory / 'launcher.stderr').read_text()
                    for worker in workers:
                        worker.join(5)
                    assert not errors and all(not worker.is_alive() for worker in workers), errors
                    assert len(observed) == len(providers), observed
                    evidence = [json.loads(path.read_text()) for path in reports.glob('*.json')]
                    if detached or root_only:
                        assert not evidence, 'Child observation continued after timed detach'
                        if root_only:
                            assert all(f'Observing PID {pid};' not in (directory / 'adapter.stdout').read_text()
                                for pid in identities), 'The explicit child opt-out was ignored'
                    else:
                        if existing:
                            identities.append(json.loads(pids.read_text())[-1])
                        assert len(evidence) == len(identities) == (4 if existing else 3)
                        assert {value['pid'] for value in evidence} == set(identities)
                        for value in evidence:
                            matches = [item for item in observed if item['port'] == value['remote']['port'] and
                                item['peer'][1] == value['local']['port']]
                            assert len(matches) == 1 and value['provider'].lower() == matches[0]['provider']
                            assert value['tls_version'] == 772 and value['success'] and value['peer_verified']
                            assert value['process_started_us'] <= value['handshake_started_us'] <= value['timestamp_us']
                            assert value['group_id'] == 29 and value['selected_alpn'] == 'h2'
                            assert 'cipherazzi-private-application-data-sentinel' not in json.dumps(value)
                    results.append(dict(mode=directory.name, observed_exchanges=len(observed),
                        reports=len(evidence), exact_child_identity=True, application_data_excluded=True,
                        existing_nested_workers=existing, child_opt_out=root_only))
                    print(f'{directory.name}: {len(observed)} child TLS exchanges passed.', flush=True)
                finally:
                    release.write_text('Cleanup release')
                    for gate in gates[:3]:
                        gate.write_text('Cleanup release')
                    if observer.poll() is None:
                        observer.kill()
                        observer.wait(5)
                    if launcher and launcher.poll() is None:
                        launcher.wait(20)
                    for listener in listeners:
                        listener.close()
                    for worker in workers:
                        worker.join(1)
        # Import actual worker reports and retain their independent endpoint provenance.
        combined = work / 'all-reports'
        combined.mkdir()
        for report in work.glob('*/reports/*.json'):
            (combined / report.name).write_bytes(report.read_bytes())
        database = work / 'endpoints.db'
        imported = subprocess.run([str(root / 'build/bin/Release/Cipherazzi.Tests.exe'), '--import-endpoints',
            str(combined), str(database)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
        assert imported.returncode == 0, imported.stderr.decode(errors='replace')
        with sqlite3.connect(database) as connection:
            assert connection.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == 7
            details = [json.loads(value[0]) for value in connection.execute('SELECT detail_json FROM endpoint_events')]
            assert all(value['correlation'].startswith('Unmatched socket') and
                'matched_flow_id' not in value for value in details)
        (work / 'results.json').write_text(json.dumps(dict(cases=results, launcher_exit_keeps_child_capture=True,
            timed_detach_preserves_parent_and_children=True, post_detach_child_launch=True,
            existing_nested_workers=True, explicit_child_opt_out=True, native_import=True), indent=2))
    finally:
        key.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
