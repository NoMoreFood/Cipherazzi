import argparse
import asyncio
import base64
import ctypes
import hashlib
import json
import re
import socket
import sqlite3
import subprocess
import threading
import time
from contextlib import ExitStack
from pathlib import Path


def execute(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=40,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError(result.stderr + result.stdout)
    return result.stdout


def process_start(pid):
    # Get the Windows process creation timestamp before a short-lived endpoint exits.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.c_void_p] * 4
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, False, pid)
    values = [ctypes.c_uint64() for _ in range(4)]
    try:
        assert handle and kernel.GetProcessTimes(handle, *[ctypes.byref(value) for value in values])
        return values[0].value // 10 - 11644473600000000
    finally:
        if handle:
            kernel.CloseHandle(handle)


def certificate(openssl, work, name, algorithm, issuer=None):
    key, cert, request = (work / (name + suffix) for suffix in [".key", ".pem", ".csr"])
    execute([openssl, "genpkey", "-algorithm", algorithm, "-out", str(key)])
    execute([openssl, "req", "-new", "-key", str(key), "-out", str(request), "-subj", "/CN=auth.lab",
             "-config", str(work / "openssl.cnf")])
    command = [openssl, "x509", "-req", "-in", str(request), "-out", str(cert), "-days", "2",
               "-extfile", str(work / "extensions.cnf"), "-extensions", "leaf" if issuer else "root"]
    if issuer:
        command += ["-CA", str(issuer[1]), "-CAkey", str(issuer[0]), "-CAcreateserial"]
    else:
        command += ["-signkey", str(key)]
    execute(command)
    return key, cert


class TlsServer:
    def __init__(self, openssl, work, name, host, key, cert, chain=None, client_ca=None):
        listener = socket.socket()
        listener.bind((host, 0))
        self.port = listener.getsockname()[1]
        listener.close()
        self.log = (work / (name + ".server.log")).open("w")
        command = [openssl, "s_server", "-accept", f"{host}:{self.port}", "-key", str(key), "-cert", str(cert),
                   "-tls1_3", "-groups", "X25519MLKEM768", "-www", "-quiet"]
        if chain:
            command += ["-cert_chain", str(chain)]
        if client_ca:
            command += ["-Verify", "1", "-verify_return_error", "-CAfile", str(client_ca)]
        self.process = subprocess.Popen(command, stdout=self.log, stderr=self.log,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(0.15)
        if self.process.poll() is not None:
            raise RuntimeError(f"TLS server {name} failed: " + (work / (name + ".server.log")).read_text())

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=10)
        self.log.close()


def pem_der(text):
    return [base64.b64decode(value) for value in re.findall(
        r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", text, re.S)]


async def serve(args, work):
    from aioquic.asyncio import QuicConnectionProtocol, serve as quic_serve
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import HandshakeCompleted
    openssl = str(Path(args.openssl).resolve())
    (work / "openssl.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n")
    (work / "extensions.cnf").write_text(
        "[root]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\n"
        "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:auth.lab,DNS:quic.lab\n")
    manifest = dict(host=args.serve, ports={}, cases=[], openssl=execute([openssl, "version"]).strip())
    servers, quic_servers = [], []
    try:
        roots = {name: certificate(openssl, work, "root-" + name, algorithm) for name, algorithm in
                 [("pq", "ML-DSA-65"), ("classical", "RSA"), ("slh", "SLH-DSA-SHA2-128f")]}
        client_key, client_cert = certificate(openssl, work, "client-pq", "ML-DSA-65", roots["pq"])
        client_chain = work / "client-chain.pem"
        client_chain.write_text(client_cert.read_text() + roots["pq"][1].read_text())
        for name, algorithm, root, mutual in [("mldsa44", "ML-DSA-44", "pq", False),
            ("mldsa65", "ML-DSA-65", "pq", False), ("mldsa87", "ML-DSA-87", "pq", False),
            ("mixed-chain", "ML-DSA-65", "classical", False),
            ("slh-chain", "ML-DSA-87", "slh", False), ("mutual-pq", "ML-DSA-44", "pq", True)]:
            key, cert = certificate(openssl, work, name, algorithm, roots[root])
            server = TlsServer(openssl, work, name, args.serve, key, cert, roots[root][1],
                               roots["pq"][1] if mutual else None)
            servers.append(server)
            manifest["ports"][name] = server.port
            manifest["cases"].append(dict(name=name, port=server.port, transport="TCP", success=True,
                signature={"ML-DSA-44": 0x0904, "ML-DSA-65": 0x0905, "ML-DSA-87": 0x0906}[algorithm],
                trust=roots[root][1].read_text(), certificates=cert.read_text() + roots[root][1].read_text(),
                root_class="Classical" if root == "classical" else "Post-quantum", mutual=mutual,
                client_key=client_key.read_text() if mutual else "", client_cert=client_chain.read_text() if mutual else ""))
        for name, verify_name in [("hostname-rejected", "wrong.lab"), ("untrusted-root", "auth.lab")]:
            case = dict(manifest["cases"][0], name=name, success=False, signature=-1, verify_name=verify_name)
            if name == "untrusted-root":
                case["trust"] = roots["classical"][1].read_text()
            manifest["cases"].append(case)

        # QUIC endpoints run real UDP sockets; application payload and TLS secrets are never exported.
        ec_key = work / "quic.key"
        ec_cert = work / "quic.pem"
        execute([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                 "-keyout", str(ec_key), "-out", str(ec_cert), "-days", "2", "-subj", "/CN=quic.lab",
                 "-addext", "subjectAltName=DNS:quic.lab", "-config", str(work / "openssl.cnf")])

        class Protocol(QuicConnectionProtocol):
            def quic_event_received(self, event):
                if isinstance(event, HandshakeCompleted):
                    asyncio.get_running_loop().call_later(1.5, self.close)

        for name, retry in [("quic-v1", False), ("quic-retry", True)]:
            config = QuicConfiguration(is_client=False, alpn_protocols=["h3"], supported_versions=[1])
            config.load_cert_chain(str(ec_cert), str(ec_key))
            server = await quic_serve(args.serve, 0, configuration=config, create_protocol=Protocol, retry=retry)
            quic_servers.append(server)
            port = server._transport.get_extra_info("sockname")[1]
            manifest["ports"][name] = port
            manifest["cases"].append(dict(name=name, port=port, transport="QUIC", success=True,
                signature=0x0403, trust=ec_cert.read_text(), certificates=ec_cert.read_text(), retry=retry))
        (work / "servers.json").write_text(json.dumps(manifest, indent=2))
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline and not (work / "stop").exists():
            await asyncio.sleep(0.2)
    finally:
        for server in quic_servers:
            server.close()
        for server in servers:
            server.close()


def clients(args, work):
    manifest = json.loads(Path(args.servers).read_text())
    host = manifest["host"]
    endpoint_directory = Path(args.endpoint_directory or work / "endpoint")
    endpoint_directory.mkdir(parents=True, exist_ok=True)
    outcomes = []
    for index, case in enumerate(manifest["cases"]):
        transport = case["transport"]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "QUIC" else socket.SOCK_STREAM) as probe:
            probe.connect((host, case["port"]))
            local_address = probe.getsockname()[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "QUIC" else socket.SOCK_STREAM) as probe:
            probe.bind((local_address, 0))
            port = probe.getsockname()[1]
        trust = work / (case["name"] + ".trust.pem")
        trust.write_text(case["trust"])
        command = [args.openssl, "s_client", "-connect", f"{host}:{case['port']}", "-bind", f"{local_address}:{port}",
            "-servername", "quic.lab" if transport == "QUIC" else "auth.lab", "-CAfile", str(trust),
            "-verify_return_error", "-verify_hostname", case.get("verify_name", "quic.lab" if transport == "QUIC" else "auth.lab"),
            "-trace", "-msgfile", str(work / (case["name"] + ".trace")), "-brief"]
        if transport == "QUIC":
            command += ["-quic", "-alpn", "h3"]
        else:
            command += ["-tls1_3", "-groups", "X25519MLKEM768"]
        if case.get("mutual"):
            key, cert = work / "client.key", work / "client.pem"
            key.write_text(case["client_key"])
            cert.write_text(case["client_cert"])
            command += ["-key", str(key), "-cert", str(cert), "-cert_chain", str(cert)]
        started_us = time.time_ns() // 1000
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        process_started = process_start(process.pid)
        started_us = max(started_us, process_started)
        try:
            if transport == "QUIC":
                # Keep stdin open while the server completes and closes the connection.
                time.sleep(2)
                output, errors = process.communicate(timeout=15)
            else:
                time.sleep(1)
                output, errors = process.communicate(b"GET / HTTP/1.0\r\nHost: auth.lab\r\n\r\n", timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            output, errors = process.communicate()
            raise AssertionError(f"Endpoint {case['name']} did not terminate")
        ended_us = time.time_ns() // 1000
        text = (work / (case["name"] + ".trace")).read_text(errors="replace") + errors.decode(errors="replace")
        (work / (case["name"] + ".endpoint.log")).write_text(text)
        success = "CONNECTION ESTABLISHED" in text and "Verification: OK" in text and process.returncode == 0
        assert success == case["success"], f"Unexpected {case['name']} result: {text[-4000:]}"
        signatures = re.findall(r"Signature Algorithm:\s*[^\r\n]*\(0x([0-9a-fA-F]+)\)", text)
        actual_signature = int(signatures[0], 16) if signatures and success else -1
        if success:
            assert actual_signature == case["signature"], f"Missing/wrong CertificateVerify: {signatures}"
        report = dict(schema="cipherazzi.endpoint/1", provider="OpenSSL public-result adapter", pid=process.pid,
            process_started_us=process_started, handshake_started_us=started_us, timestamp_us=ended_us,
            local=dict(address=local_address, port=port), remote=dict(address=host, port=case["port"]),
            role="client", transport=transport, success=success, peer_verified=success,
            tls_version=772 if success else 0, cipher_id=4866 if success else 0)
        if success:
            report["signature_scheme"] = actual_signature
            # Match the certificates actually printed by the endpoint rather than the server manifest.
            actual_certificates = pem_der(text)
            assert actual_certificates, "Endpoint did not print its presented chain"
            expected = pem_der(case["certificates"])
            assert actual_certificates[:len(expected)] == expected
            report["server_certificates_der"] = [base64.b64encode(der).decode() for der in actual_certificates[:len(expected)]]
        if transport == "QUIC":
            initial_ids = re.findall(r"Sent Packet\s+Packet Type: Initial\s+Version: [^\n]+\n\s+Destination Conn Id: 0x([0-9a-fA-F]+)", text)
            assert initial_ids, "Endpoint trace did not provide its original QUIC connection ID"
            report["quic_original_dcid"] = initial_ids[0].lower()
            report["selected_alpn"] = "h3"
        else:
            if success:
                report["group_id"] = 4588
        if case.get("mutual") and success:
            assert len(signatures) == 2 and int(signatures[1], 16) == 2309, signatures
            report["local_signature_scheme"] = int(signatures[1], 16)
            assert all(der in actual_certificates for der in pem_der(case["client_cert"]))
            report["client_certificates_der"] = [base64.b64encode(der).decode() for der in pem_der(case["client_cert"])]
        temporary = endpoint_directory / (case["name"] + ".tmp")
        temporary.write_text(json.dumps(report))
        temporary.replace(temporary.with_suffix(".json"))
        outcomes.append(dict(name=case["name"], report=report, expected={key: value for key, value in case.items() if key != "client_key"}, exit_code=process.returncode))
    results = dict(openssl=manifest["openssl"], cases=outcomes, endpoint_directory=str(endpoint_directory))
    (work / "results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(dict(cases=[dict(name=item["name"], success=item["report"]["success"],
        pid=item["report"]["pid"], port=item["report"]["local"]["port"]) for item in outcomes]), indent=2))


def verify(args):
    reference = json.loads(Path(args.reference).read_text())
    database = sqlite3.connect(args.verify_live)
    database.row_factory = sqlite3.Row
    rows = list(database.execute("SELECT * FROM connections"))
    outcomes = []
    for case in reference["cases"]:
        report = case["report"]
        candidates = [row for row in rows if row["source_address"] == report["local"]["address"] and
                      row["source_port"] == report["local"]["port"] and row["destination_address"] == report["remote"]["address"] and
                      row["destination_port"] == report["remote"]["port"] and
                      json.loads(row["crypto_json"]).get("transport", "TCP") == report["transport"]]
        assert len(candidates) == 1, f"{case['name']}: captured {len(candidates)} connections"
        row = candidates[0]
        crypto = json.loads(row["crypto_json"])
        assert row["source_pid"] == report["pid"], f"{case['name']}: wrong process owner {row['source_pid']}"
        if report["transport"] == "TCP":
            expected = "Endpoint confirmed completion" if report["success"] else "Endpoint confirmed failure"
            assert crypto["handshake_confirmation"] == expected, (case["name"], crypto["handshake_confirmation"])
            evidence = crypto["endpoint_confirmations"][0]
            assert evidence["success"] == report["success"]
            if report["success"]:
                assert evidence["handshake_signature_id"] == report["signature_scheme"]
                assert evidence["authentication_class"] == "Post-quantum"
                certs = [database.execute("SELECT metadata_json,der FROM certificates WHERE sha256=?", (value,)).fetchone()
                         for value in evidence["server_certificates"]]
                assert certs and all(value is not None for value in certs)
                assert json.loads(certs[0]["metadata_json"])["public_key_class"] == "Post-quantum"
                assert json.loads(certs[-1]["metadata_json"])["public_key_class"] == case["expected"]["root_class"]
                if case["expected"].get("mutual"):
                    assert evidence["local_handshake_signature_id"] == report["local_signature_scheme"] == 2309
                    assert evidence["local_authentication_class"] == "Post-quantum"
                    assert evidence["client_certificates"]
        else:
            assert row["state"] == "hellos_observed" and row["tls_version"] == 772
            assert crypto["quic_retry"] == case["expected"]["retry"]
            assert crypto["handshake_confirmation"] == "Endpoint confirmed completion"
            assert crypto["endpoint_confirmations"][0]["handshake_signature_id"] == report["signature_scheme"]
        outcomes.append(dict(name=case["name"], flow_id=row["flow_id"], process=row["source_process"],
                             owner=row["source_account"], confirmation=crypto["handshake_confirmation"]))
    health = dict(database.execute("SELECT capture_lost,truncated,queue_lost,storage_lost,malformed,reassembly_limit,flow_limit,telemetry_lost FROM capture_sessions").fetchone())
    oversized = []
    if args.allow_capture_truncation:
        log = Path(args.capture_log).read_text()
        warnings = re.findall(r"Packet Monitor processing warning: (\d+); reported length (\d+)", log)
        assert all(int(reason) == 122 and int(length) > 9000 for reason, length in warnings), warnings
        oversized = [int(length) for _, length in warnings]
        assert health["capture_lost"] == health["truncated"] == len(oversized), health
        assert not any(value for key, value in health.items() if key not in ("capture_lost", "truncated")), health
    else:
        assert not any(health.values()), health
    result = dict(cases=outcomes, health=health, oversized_offload_packets=oversized)
    Path(args.reference).with_name("live-results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl", default="C:/msys64/usr/bin/openssl.exe")
    parser.add_argument("--serve")
    parser.add_argument("--servers")
    parser.add_argument("--collector")
    parser.add_argument("--output", default=".work/advanced")
    parser.add_argument("--endpoint-directory")
    parser.add_argument("--verify-live")
    parser.add_argument("--reference")
    parser.add_argument("--allow-capture-truncation", action="store_true")
    parser.add_argument("--capture-log")
    args = parser.parse_args()
    if args.allow_capture_truncation and (not args.verify_live or not args.capture_log):
        parser.error("Capture truncation validation requires --verify-live and --capture-log")
    if args.verify_live:
        verify(args)
        return
    work = Path(args.output).resolve()
    work.mkdir(parents=True, exist_ok=True)
    if args.serve:
        asyncio.run(serve(args, work))
    elif args.servers:
        clients(args, work)
    else:
        parser.error("Choose --serve, --servers, or --verify-live")


if __name__ == "__main__":
    main()
