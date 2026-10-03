import argparse
import hashlib
import json
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--quic-client', required=True, type=Path)
    parser.add_argument('--openssl', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.output.resolve()
    work.mkdir(parents=True)
    adapter = root / 'tools/artifacts/build/bin/Release/Cipherazzi.EndpointAdapter.exe'
    deployed, symbols = work / 'deployed', work / 'symbols'
    deployed.mkdir()
    symbols.mkdir()
    binaries = []
    for source in [args.client.resolve(), args.quic_client.resolve()]:
        target = deployed / source.name
        shutil.copyfile(source, target)
        shutil.copyfile(source.with_suffix('.pdb'), symbols / source.with_suffix('.pdb').name)
        assert hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(source.read_bytes()).digest()
        binaries.append(target)
    client, quic_client = binaries
    assert not list(deployed.glob('*.pdb'))
    tls_profile, quic_profile = work / 'tls-profile.json', work / 'quic-profile.json'
    results = []

    def suite(name, script, arguments):
        directory = work / name
        result = subprocess.run([sys.executable, str(root / 'tests/integration' / script),
            *[str(value) for value in arguments], '--output', str(directory)],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=240)
        (work / f'{name}.stdout').write_bytes(result.stdout)
        (work / f'{name}.stderr').write_bytes(result.stderr)
        assert result.returncode == 0, (name, result.stdout, result.stderr)
        evidence = json.loads((directory / 'results.json').read_text())
        results.append(dict(case=name, exchanges=len(evidence), passed=True))
        print(f'{name}: {len(evidence)} capture cases passed.', flush=True)

    tls_arguments = ['--native-rustls-client', client, '--openssl', args.openssl.resolve()]
    suite('external-tls', 'SourceAdapters.py', [*tls_arguments,
        '--rustls-symbols', symbols, '--rustls-profile-out', tls_profile])
    for name, extra in [('profile-sync', ['--native-provider', 'auto']), ('profile-async', ['--native-async'])]:
        suite(name, 'SourceAdapters.py', [*tls_arguments, '--rustls-profile', tls_profile, *extra])
    certificate, key = work / 'external-tls/cert.pem', work / 'external-tls/key.pem'
    quic_arguments = ['--client', quic_client, '--provider', 'rustls', '--certificate', certificate, '--key', key]
    suite('external-quic', 'QuicObservation.py', [*quic_arguments,
        '--rustls-symbols', symbols, '--rustls-profile-out', quic_profile])
    suite('profile-quic', 'QuicObservation.py', [*quic_arguments, '--rustls-profile', quic_profile])
    for profile, binary in [(tls_profile, client), (quic_profile, quic_client)]:
        value = json.loads(profile.read_text())
        assert value['image_sha256'] == hashlib.sha256(binary.read_bytes()).hexdigest()
        assert value['schema'] == 'cipherazzi.rustls-profile/1' and value['architecture'] == 'x64'
        assert value['types'] and value['symbols']
        assert 'PRIVATE KEY-----' not in profile.read_text()

    def rejected(name, extra, application=client, provider='rustls'):
        directory = work / name
        directory.mkdir()
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(2)
        listener.settimeout(20)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2'])
        errors, exchanges = [], []

        def serve():
            try:
                for _ in range(2):
                    raw, _ = listener.accept()
                    raw.settimeout(10)
                    with raw, context.wrap_socket(raw, server_side=True) as secured:
                        assert secured.recv(1) == b'*'
                        secured.sendall(b'*')
                        exchanges.append(True)
            except Exception as error:
                errors.append(repr(error))

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            result = subprocess.run([str(adapter), '--provider', provider, '--spawn', str(application),
                '--output', str(directory / 'reports'), *[str(value) for value in extra], '--',
                'client', 'TLSv1.3', f'127.0.0.1:{listener.getsockname()[1]}', str(certificate), str(key), 'ok'],
                capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=40)
            worker.join(22)
            (directory / 'adapter.stdout').write_bytes(result.stdout)
            (directory / 'adapter.stderr').write_bytes(result.stderr)
            assert not worker.is_alive() and not errors and len(exchanges) == 2, (name, errors)
            assert result.returncode == 2, (name, result.stdout, result.stderr)
            assert not list((directory / 'reports').glob('*.json'))
            results.append(dict(case=name, no_guessed_reports=True, application_tls_unaffected=True))
            print(f'{name}: unsupported metadata rejected; application TLS succeeded.', flush=True)
        finally:
            listener.close()

    rejected('no-metadata', [])
    wrong_symbols = work / 'wrong-symbols'
    wrong_symbols.mkdir()
    shutil.copyfile(args.quic_client.resolve().with_suffix('.pdb'), wrong_symbols / client.with_suffix('.pdb').name)
    rejected('mismatched-symbols', ['--rustls-symbols', wrong_symbols])
    altered = deployed / 'altered.exe'
    altered.write_bytes(client.read_bytes() + b'profile identity mismatch')
    rejected('mismatched-image', ['--rustls-profile', tls_profile], altered)
    for name, edit in [
        ('out-of-image-hook', lambda profile: profile['symbols'][0].update(rva=profile['image_size'])),
        ('missing-type', lambda profile: profile.update(common=0xffffffff)),
        ('too-many-types', lambda profile: profile.update(types=[profile['types'][0]] * 8193)),
    ]:
        value = json.loads(tls_profile.read_text())
        edit(value)
        target = work / f'{name}.json'
        target.write_text(json.dumps(value))
        rejected(name, ['--rustls-profile', target])
        if name == 'missing-type':
            rejected('missing-type-auto', ['--rustls-profile', target], provider='auto')

    # File limits and accidental overwrite attempts fail before spawning the application.
    oversized, nested = work / 'oversized.json', work / 'nested.json'
    with oversized.open('wb') as file:
        file.truncate(16 * 1024 * 1024 + 1)
    nested.write_text('{"schema":"cipherazzi.rustls-profile/1","data":' + '[' * 40 + '0' + ']' * 40 + '}')
    for name, extra in [('oversized', ['--rustls-profile', oversized]),
        ('nested', ['--rustls-profile', nested]), ('existing-output', ['--rustls-profile-out', tls_profile])]:
        before = tls_profile.read_bytes()
        result = subprocess.run([str(adapter), '--provider', 'rustls', '--spawn', str(client),
            '--output', str(work / name), *[str(value) for value in extra]], capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW, timeout=20)
        assert result.returncode == 1 and b'Starting endpoint observation' not in result.stdout
        assert tls_profile.read_bytes() == before
        results.append(dict(case=name, rejected_before_launch=True))
    assert not list(deployed.glob('*.pdb'))
    (work / 'results.json').write_text(json.dumps(results, indent=2))
    print('Rustls matching-symbol and PDB-free profile checks passed.', flush=True)


if __name__ == '__main__':
    main()
