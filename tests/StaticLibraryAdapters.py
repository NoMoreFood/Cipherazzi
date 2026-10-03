import argparse
import base64
import ctypes as c
import json
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path

from FirefoxBrowserAdapter import socket_owner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--openssl', required=True)
    parser.add_argument('--openssl-client', required=True, type=Path)
    parser.add_argument('--boringssl-client', required=True, type=Path)
    parser.add_argument('--boringssl-library', required=True, type=Path)
    parser.add_argument('--loader', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    work = args.output.resolve()
    work.mkdir(parents=True)
    certificate, key = work / 'cert.pem', work / 'key.pem'
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.LoadLibraryExW.argtypes, kernel.LoadLibraryExW.restype = [c.c_wchar_p, c.c_void_p, c.c_uint], c.c_void_p
    kernel.GetProcAddress.argtypes, kernel.GetProcAddress.restype = [c.c_void_p, c.c_char_p], c.c_void_p
    kernel.FreeLibrary.argtypes = [c.c_void_p]
    results = []

    def exchange(name, binary, provider, version, hostname='adapter.lab', symbols='matching', library=None):
        directory = work / name
        directory.mkdir()
        reports = directory / 'reports'
        reports.mkdir()
        module = (library or binary).resolve()
        loaded = kernel.LoadLibraryExW(str(module), None, 1)
        assert loaded, 'The fixture image could not be inspected'
        try:
            assert not kernel.GetProcAddress(loaded, b'SSL_do_handshake'), 'The fixture exports its TLS implementation'
            assert not kernel.GetProcAddress(loaded, b'SSL_GetChannelInfo')
        finally:
            kernel.FreeLibrary(loaded)
        pdb = next(path for path in module.parent.glob('*.pdb')
            if path.name not in ('StaticTlsLoader.pdb', 'StaticTlsSymbols.pdb.disabled'))
        hidden = pdb.with_suffix('.pdb.disabled')
        if symbols != 'matching':
            assert not hidden.exists()
            pdb.rename(hidden)
            if symbols == 'mismatched':
                other = next(args.openssl_client.resolve().parent.glob('*.pdb'))
                shutil.copyfile(other, pdb)
        count = 2 if library else 1
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = \
            ssl.TLSVersion.TLSv1_2 if version == 771 else ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certificate, key)
        context.set_alpn_protocols(['h2'])
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(2)
        listener.settimeout(15)
        port = listener.getsockname()[1]
        observations, errors = [], []
        success = hostname == 'adapter.lab'

        def serve():
            try:
                for _ in range(count):
                    raw, peer = listener.accept()
                    with raw:
                        raw.settimeout(10)
                        owner = socket_owner(peer[1], port)
                        try:
                            with context.wrap_socket(raw, server_side=True) as connection:
                                assert success, 'The client accepted the wrong hostname'
                                assert connection.recv(4096) == b'cipherazzi-private-application-data-sentinel'
                                observations.append(dict(pid=owner, local_port=peer[1],
                                    version=connection.version(), cipher=connection.cipher()[0],
                                    alpn=connection.selected_alpn_protocol()))
                                connection.sendall(b'ok')
                                connection.unwrap().close()
                        except ssl.SSLError as error:
                            assert not success, str(error)
                            observations.append(dict(pid=owner, local_port=peer[1], rejected=True))
            except Exception as error:
                errors.append(str(error))

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            application = [str(binary.resolve())]
            if library:
                application.append(str(library.resolve()))
            application.extend([str(port), str(certificate), str(version), hostname])
            started = time.perf_counter()
            result = subprocess.run([str(root / 'build/bin/Release/Cipherazzi.EndpointAdapter.exe'),
                '--provider', 'auto',
                '--spawn', application[0], '--output', str(reports), '--', *application[1:]], capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=45)
            elapsed = time.perf_counter() - started
            (directory / 'adapter.stdout').write_bytes(result.stdout)
            (directory / 'adapter.stderr').write_bytes(result.stderr)
            worker.join(16)
            assert not worker.is_alive() and not errors and len(observations) == count, errors
            expected_status = 2 if symbols != 'matching' else 0 if success else 1
            assert result.returncode == expected_status, result.stderr.decode(errors='replace')
            evidence = [json.loads(path.read_text()) for path in reports.glob('cipherazzi-endpoint-*.json')]
            assert len(evidence) == (0 if symbols != 'matching' else count), evidence
            assert 'cipherazzi-private-application-data-sentinel' not in json.dumps(evidence)
            for report in evidence:
                observation = next(row for row in observations if row['local_port'] == report['local']['port'])
                assert report['pid'] == observation['pid'] and report['role'] == 'client'
                assert Path(report['process_path']) == binary.resolve()
                assert report['provider'] == provider and report['success'] == success
                assert report['local']['address'] == report['remote']['address'] == '127.0.0.1'
                assert report['remote']['port'] == port and report['transport'] == 'TCP'
                assert report['process_started_us'] <= report['handshake_started_us'] <= report['timestamp_us']
                assert report['peer_verified'] == success
                if success:
                    assert report['tls_version'] == version
                    assert report['cipher_id'] == (0xc030 if version == 771 else 0x1302)
                    assert report['group_id'] == 29 and report['signature_scheme'] == 0x0804
                    assert report['selected_alpn'] == 'h2' and not report['session_resumed']
                    assert report['server_name'] == hostname
                    assert base64.b64decode(report['server_certificates_der'][0]) == \
                        ssl.PEM_cert_to_DER_cert(certificate.read_text())
            imported = subprocess.run([str(root / 'build/bin/Release/Cipherazzi.Tests.exe'), '--import-endpoints',
                str(reports), str(directory / 'endpoints.db')], capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            if evidence:
                assert imported.returncode == 0, imported.stderr.decode(errors='replace')
                with sqlite3.connect(directory / 'endpoints.db') as database:
                    assert database.execute('SELECT count(*) FROM endpoint_events').fetchone()[0] == len(evidence)
            else:
                assert imported.returncode == 1 and b'No endpoint adapter reports were imported' in imported.stderr
            results.append(dict(case=name, provider=provider, version=version, success=success,
                symbols=symbols, exchanges=count, reports=len(evidence), public_tls_exports=False,
                exact_socket_owner=True, native_import=bool(evidence), empty_reports_rejected=not evidence,
                application_data_excluded=True,
                dll_reload=library is not None, elapsed_seconds=elapsed))
            print(f'{name}: static TLS capture passed.', flush=True)
        finally:
            listener.close()
            worker.join(16)
            if symbols != 'matching':
                pdb.unlink(missing_ok=True)
                hidden.rename(pdb)

    try:
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=adapter.lab', '-addext', 'subjectAltName=DNS:adapter.lab', '-keyout', str(key),
            '-out', str(certificate)], check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        for provider, binary in (('OpenSSL', args.openssl_client), ('BoringSSL', args.boringssl_client)):
            for version in (771, 772):
                for hostname in ('adapter.lab', 'wrong.invalid'):
                    exchange(f'{provider}-{version}-{hostname}', binary, provider, version, hostname)
        for symbols in ('missing', 'mismatched'):
            exchange(f'BoringSSL-{symbols}', args.boringssl_client, 'BoringSSL', 772, symbols=symbols)

        # Exercise CodeView metadata stored only in the image file, outside the loaded address space.
        image_directory = work / 'unmapped-image'
        image_directory.mkdir()
        source = args.boringssl_client.resolve()
        image = image_directory / source.name
        shutil.copyfile(source, image)
        for pdb in source.parent.glob('*.pdb'):
            shutil.copyfile(pdb, image_directory / pdb.name)
        data = bytearray(image.read_bytes())
        nt = struct.unpack_from('<I', data, 0x3c)[0]
        optional = nt + 24
        directory = optional + (112 if struct.unpack_from('<H', data, optional)[0] == 0x20b else 96) + 48
        rva, size = struct.unpack_from('<II', data, directory)
        sections = optional + struct.unpack_from('<H', data, nt + 20)[0]
        modified = 0
        for index in range(struct.unpack_from('<H', data, nt + 6)[0]):
            section = sections + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from('<IIII', data, section + 8)
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                for entry in range(raw_offset + rva - virtual_address,
                    raw_offset + rva - virtual_address + size, 28):
                    if struct.unpack_from('<I', data, entry + 12)[0] == 2:
                        struct.pack_into('<I', data, entry + 20, 0)
                        modified += 1
        assert modified == 1
        image.write_bytes(data)
        exchange('BoringSSL-unmapped-CodeView', image, 'BoringSSL', 772)
        exchange('BoringSSL-dll-reload', args.loader, 'BoringSSL', 772, library=args.boringssl_library)
        (work / 'results.json').write_text(json.dumps(dict(cases=results), indent=2))
    finally:
        key.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
