import argparse
from contextlib import ExitStack, nullcontext
import json
import re
import socket
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from Integration import ip_packet, write_pcap


def execute(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=45,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited with {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(15)
    return server


class Server:
    def __init__(self, openssl, work, name, groups, host="127.0.0.1"):
        self.work = work
        self.name = name
        self.host = host
        with listener() as available:
            self.port = available.getsockname()[1]
        self.output = (work / f"{name}.server.log").open("w")
        self.process = subprocess.Popen(
            [openssl, "s_server", "-accept", f"{self.host}:{self.port}", "-cert", "cert.pem", "-key", "key.pem",
             "-tls1_3", "-groups", groups, "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-www", "-num_tickets", "2"],
            cwd=work, stdin=subprocess.PIPE, stdout=self.output, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def __enter__(self):
        try:
            for _ in range(150):
                if self.process.poll() is not None:
                    raise RuntimeError(f"OpenSSL server exited: {self.work / (self.name + '.server.log')}")
                try:
                    with socket.create_connection((self.host, self.port), timeout=0.1):
                        return self
                except OSError:
                    time.sleep(0.02)
            raise RuntimeError("OpenSSL server did not listen in time")
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=10)
        self.process.stdin.close()
        self.output.close()


def exchange(openssl, work, server, case, source_port, packets):
    # Relay unmodified TLS bytes and record their arrival order; IP/TCP framing is generated for replay.
    proxy = listener()
    streams = []
    errors = []
    lock = threading.Lock()
    byte_counts = [0, 0]
    network = {}
    sequences = [1001, 9001]
    timestamp = time.time_ns() // 1000
    packets.extend([(timestamp, ip_packet(b"", source_port, 1000, True, 2)),
                    (timestamp, ip_packet(b"", source_port, 9000, False, 0x12))])

    def pump(source, destination, direction):
        try:
            while data := source.recv(65536):
                with lock:
                    observed = time.time_ns() // 1000
                    byte_counts[direction] += len(data)
                    for offset in range(0, len(data), 137):
                        part = data[offset:offset + 137]
                        packet = ip_packet(part, source_port, sequences[direction], direction == 0)
                        packets.append((observed, packet))
                        sequences[direction] += len(part)
                destination.sendall(data)
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def relay():
        try:
            with proxy.accept()[0] as client, socket.create_connection((server.host, server.port), timeout=15) as remote:
                streams.extend([client, remote])
                network.update(source_address=remote.getsockname()[0], source_port=remote.getsockname()[1],
                               destination_address=remote.getpeername()[0], destination_port=remote.getpeername()[1])
                receiver = threading.Thread(target=pump, args=(remote, client, 1), daemon=True)
                receiver.start()
                pump(client, remote, 0)
                receiver.join(timeout=20)
                if receiver.is_alive():
                    raise RuntimeError("TLS response relay timed out")
        except Exception as error:
            errors.append(str(error))

    thread = threading.Thread(target=relay, daemon=True)
    thread.start()
    command = [openssl, "s_client", "-connect", f"127.0.0.1:{proxy.getsockname()[1]}",
               "-servername", case.get("hostname", case["name"] + ".pqc.test"), "-CAfile", "cert.pem",
               "-verify_return_error", "-tls1_3", "-groups", case["client_groups"],
               "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-ign_eof", "-brief"]
    if case.get("save_session"):
        command.extend(["-sess_out", "session.pem"])
    if case.get("resumed"):
        command.extend(["-sess_in", "session.pem"])
    started = time.perf_counter()
    try:
        result = subprocess.run(command, input="GET / HTTP/1.0\r\n\r\n", text=True, capture_output=True,
                                timeout=30, cwd=work, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    finally:
        proxy.close()
        for stream in streams:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        thread.join(timeout=25)
    elapsed = (time.perf_counter() - started) * 1000
    if thread.is_alive() or errors:
        raise RuntimeError(f"TLS relay failed: {errors}")
    (work / f"{case['name']}.client.stdout").write_text(result.stdout)
    (work / f"{case['name']}.client.stderr").write_text(result.stderr)
    packets.append((time.time_ns() // 1000, ip_packet(b"", source_port, sequences[0], True, 4)))
    output = result.stdout + result.stderr
    success = result.returncode == 0 and "HTTP/1.0 200 ok" in output and "TLSv1.3" in output
    assert success == (not case.get("failure", False)), (case["name"], result.returncode, output)
    if not success:
        assert "handshake failure" in output.lower(), (case["name"], output)
    group = re.search(r"(?:Negotiated TLS1\.3 group|Server Temp Key|Peer Temp Key):\s*([^,\r\n]+)", output)
    negotiated = group.group(1) if group else ""
    if success:
        assert negotiated.lower() == case["expected_group"].lower(), (case["name"], negotiated, output)
        assert ("Reused, TLSv1.3" in output) == case.get("resumed", False), (case["name"], output)
    return dict(name=case["name"], source_port=source_port, endpoint_handshake_complete=success,
                sni=case.get("hostname", case["name"] + ".pqc.test"), network=network,
                endpoint_application_roundtrip=success, endpoint_selected_group=negotiated,
                endpoint_session_reused=case.get("resumed", False), client_exit_code=result.returncode,
                client_process_and_application_roundtrip_ms=round(elapsed, 3),
                relay_client_tls_bytes=byte_counts[0], relay_server_tls_bytes=byte_counts[1])


def verify(database, cases, outcomes):
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        rows = {row["source_port"]: row for row in connection.execute("SELECT * FROM connections")}
        assert len(rows) == len(cases), (len(rows), len(cases))
        for case, outcome in zip(cases, outcomes):
            row = rows[outcome["source_port"]]
            crypto = json.loads(row["crypto_json"])
            stages = crypto["negotiation_stages"]
            expected = ["ClientHello", "HelloRetryRequest", "ClientHello", "ServerHello"] if case.get("hrr") else \
                ["ClientHello"] if case.get("failure") else ["ClientHello", "ServerHello"]
            assert [stage["type"] for stage in stages] == expected, (case["name"], stages)
            assert not crypto["negotiation_history_truncated"] and crypto["negotiation_stages_dropped"] == 0
            assert crypto["handshake_confirmation"] == "Not confirmed by endpoint", crypto
            assert crypto["classification_rule_version"] >= 1, crypto
            assert all(stage["handshake_bytes"] > 4 for stage in stages), stages
            assert [stage["timestamp_us"] for stage in stages] == sorted(stage["timestamp_us"] for stage in stages)
            if case.get("failure"):
                assert row["alert"] == "handshake_failure", dict(row)
            else:
                assert row["group_name"].lower() == case["expected_group"].lower(), dict(row)
                assert crypto["group_class"] == case["group_class"], crypto
                assert stages[-1]["selected_group_id"] == case["group_id"], stages
                assert "Encrypted" in crypto["certificate_visibility"], crypto
                if case.get("resumed"):
                    assert crypto["selected_psk_index"] == 0, crypto
                elif not case.get("failure"):
                    assert crypto["selected_psk_index"] is None, crypto
            if not case.get("failure"):
                lengths = {29: (32, 32), 513: (1184, 1088), 514: (1568, 1568),
                           4587: (1249, 1153), 4588: (1216, 1120), 4589: (1665, 1665)}
                client_bytes, server_bytes = lengths[case["group_id"]]
                assert {"group_id": case["group_id"], "bytes": client_bytes} in stages[-2]["key_shares"], stages[-2]
                assert {"group_id": case["group_id"], "bytes": server_bytes} in stages[-1]["key_shares"], stages[-1]
            if case.get("hrr"):
                assert stages[0]["group_ids"] == stages[2]["group_ids"], stages
                assert stages[0]["key_shares"] == [{"group_id": 29, "bytes": 32}], stages
                assert stages[1]["selected_group_id"] == 4588 and not stages[1]["key_shares"], stages
                assert stages[2]["key_shares"] != stages[0]["key_shares"], stages
            if case["name"] == "offered-pq-classical-selected":
                assert 4588 in stages[0]["group_ids"] and stages[-1]["selected_group_id"] == 29, stages
            outcome.update(collector_group_class=crypto["group_class"],
                           collector_handshake_confirmation=crypto["handshake_confirmation"],
                           negotiation_stages=[stage["type"] for stage in stages],
                           negotiation_key_shares=[stage["key_shares"] for stage in stages],
                           plaintext_hello_handshake_bytes=sum(stage["handshake_bytes"] for stage in stages),
                           observed_hello_interval_ms=(stages[-1]["timestamp_us"] - stages[0]["timestamp_us"]) / 1000
                           if stages[-1]["type"] == "ServerHello" else None)
        assert not list(connection.execute("PRAGMA foreign_key_check"))
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def verify_live(database, reference):
    # Compare the kernel capture with endpoint outcomes and the independently replayed byte transcript.
    report = json.loads(reference.read_text())
    matched = []
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        rows = list(connection.execute("SELECT * FROM connections"))
        sessions = [dict(row) for row in connection.execute("SELECT * FROM capture_sessions")]
        for outcome in report["cases"]:
            network = outcome["network"]
            candidates = [row for row in rows if all(row[key] == value for key, value in network.items())]
            assert len(candidates) == 1, (outcome["name"], "Live flow missing or duplicated", network, len(candidates))
            row = candidates[0]
            crypto = json.loads(row["crypto_json"])
            assert row["sni"] == outcome["sni"], dict(row)
            assert row["group_name"].lower() == outcome["endpoint_selected_group"].lower(), dict(row)
            assert crypto["group_class"] == outcome["collector_group_class"], crypto
            assert [stage["type"] for stage in crypto["negotiation_stages"]] == outcome["negotiation_stages"], crypto
            shares = [stage["key_shares"] for stage in crypto["negotiation_stages"]]
            assert shares == outcome["negotiation_key_shares"], crypto
            assert crypto["handshake_confirmation"] == "Not confirmed by endpoint", crypto
            assert not crypto["negotiation_history_truncated"], crypto
            if not outcome["endpoint_handshake_complete"]:
                assert row["alert"] == "handshake_failure", dict(row)
            assert row["source_pid"] and row["source_process"].lower() == "python.exe", dict(row)
            assert row["source_account"] and row["source_account_sid"], dict(row)
            matched.append(dict(name=outcome["name"], connection_id=row["id"], group=row["group_name"],
                                process=row["source_process"], owner=row["source_account"],
                                negotiation_stages=outcome["negotiation_stages"]))
        for session in sessions:
            assert session["stopped_us"] and session["computer_name"], session
            for key in ["capture_lost", "queue_lost", "storage_lost", "process_events_lost", "telemetry_lost",
                        "truncated", "malformed", "flow_limit", "reassembly_limit"]:
                assert session[key] == 0, (key, session[key])
        assert not list(connection.execute("PRAGMA foreign_key_check"))
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    output = dict(verified=True, database=str(database), matched=matched, sessions=sessions,
                  process_attribution="Python relay owns the guest-to-host TCP socket")
    (reference.parent / "live-results.json").write_text(json.dumps(output, indent=2))
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl")
    parser.add_argument("--collector", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--configuration", default="Release")
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--serve", metavar="ADDRESS")
    parser.add_argument("--servers", type=Path)
    parser.add_argument("--verify-live", type=Path)
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    if args.verify_live:
        if not args.reference:
            parser.error("--verify-live requires --reference results.json")
        verify_live(args.verify_live, args.reference)
        return
    if not args.openssl:
        parser.error("--openssl is required for endpoint operations")
    root = Path(__file__).resolve().parent.parent
    work = args.output.resolve() if args.output else root / ".work" / ("pqc-" + str(time.time_ns()))
    work.mkdir(parents=True, exist_ok=False)
    openssl = str(Path(args.openssl).resolve())
    version = execute([openssl, "version", "-a"])
    available = execute([openssl, "list", "-tls-groups"])
    if "X25519MLKEM768" not in available:
        raise RuntimeError("This suite requires an OpenSSL build supporting X25519MLKEM768 and key-share selection")
    (work / "openssl-version.txt").write_text(version)
    (work / "openssl-groups.txt").write_text(available)
    remote = json.loads(args.servers.read_text(encoding="utf-8-sig")) if args.servers else None
    if remote:
        (work / "cert.pem").write_text(remote["certificate_pem"])
    else:
        (work / "openssl.cnf").write_text("[req]\ndistinguished_name = subject\n[subject]\n")
        execute([openssl, "req", "-config", "openssl.cnf", "-x509", "-newkey", "rsa:2048", "-noenc",
                 "-keyout", "key.pem", "-out", "cert.pem",
                 "-days", "1", "-subj", "/CN=Cipherazzi PQC lab"], cwd=work)
    if args.serve:
        with ExitStack() as stack:
            servers = {}
            for group in ["X25519", "X25519MLKEM768", "SecP256r1MLKEM768", "MLKEM768", "MLKEM1024",
                          "SecP384r1MLKEM1024"]:
                if group.lower() not in available.lower().split(":"):
                    continue
                server = stack.enter_context(Server(openssl, work, group, group, args.serve))
                servers[group] = server.port
            manifest = dict(host=args.serve, ports=servers, certificate_pem=(work / "cert.pem").read_text(),
                            openssl=version.splitlines()[0])
            (work / "servers.json").write_text(json.dumps(manifest, indent=2))
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline and not (work / "stop").exists():
                time.sleep(0.2)
        return
    cases = [
        dict(name="classical", client_groups="X25519", server_groups="X25519", expected_group="X25519",
             group_id=29, group_class="Classical"),
        dict(name="hybrid", client_groups="X25519MLKEM768", server_groups="X25519MLKEM768",
             expected_group="X25519MLKEM768", group_id=4588, group_class="Hybrid post-quantum"),
        dict(name="hybrid-hrr", client_groups="*X25519:X25519MLKEM768", server_groups="X25519MLKEM768",
             expected_group="X25519MLKEM768", group_id=4588, group_class="Hybrid post-quantum", hrr=True),
        dict(name="offered-pq-classical-selected", client_groups="*X25519:X25519MLKEM768", server_groups="X25519",
             expected_group="X25519", group_id=29, group_class="Classical"),
        dict(name="no-common-group", client_groups="X25519", server_groups="X25519MLKEM768",
             expected_group="", failure=True),
        dict(name="resumption-seed", client_groups="X25519MLKEM768", server_groups="X25519MLKEM768",
             expected_group="X25519MLKEM768", group_id=4588, group_class="Hybrid post-quantum",
             hostname="resumed.pqc.test", save_session=True),
        dict(name="resumed", client_groups="X25519MLKEM768", server_groups="X25519MLKEM768",
             expected_group="X25519MLKEM768", group_id=4588, group_class="Hybrid post-quantum",
             hostname="resumed.pqc.test", resumed=True)]
    skipped = []
    optional = [("hybrid-p256", "SecP256r1MLKEM768", 4587, "Hybrid post-quantum"),
                ("pure-mlkem", "MLKEM768", 513, "Post-quantum"),
                ("pure-mlkem1024", "MLKEM1024", 514, "Post-quantum"),
                ("hybrid-mlkem1024", "SecP384r1MLKEM1024", 4589, "Hybrid post-quantum")]
    additions = []
    for name, group, group_id, group_class in optional:
        if group in available.split(":") and (not remote or group in remote["ports"]):
            additions.append(dict(name=name, client_groups=group, server_groups=group, expected_group=group,
                                  group_id=group_id, group_class=group_class))
        else:
            skipped.append(dict(name=name, reason=group + " is not provided by an endpoint OpenSSL build"))
    cases[2:2] = additions
    packets, outcomes = [], []
    for index, case in enumerate(cases):
        if case.get("resumed"):
            continue
        context = nullcontext(SimpleNamespace(host=remote["host"], port=remote["ports"][case["server_groups"]])) \
            if remote else Server(openssl, work, case["name"], case["server_groups"])
        with context as server:
            outcomes.append(exchange(openssl, work, server, case, 52000 + index, packets))
            if case.get("save_session"):
                assert (work / "session.pem").exists(), "No TLS 1.3 resumption ticket was received"
                outcomes.append(exchange(openssl, work, server, cases[index + 1], 52001 + index, packets))
    capture = work / "negotiations.pcap"
    write_pcap(capture, packets)
    database = work / "negotiations.db"
    report = dict(openssl=version.splitlines()[0], openssl_path=openssl, database=str(database), capture=str(capture),
                  capture_source="Unmodified OpenSSL TLS bytes through TCP relay; generated IP/TCP replay framing",
                  metrics_scope="Relay bytes and hello interval; process timing includes startup and HTTP roundtrip",
                  endpoint_authentication="Self-signed lab RSA certificate; TLS 1.3 authentication is encrypted",
                  collector_verified=False, cases=outcomes, skipped=skipped)
    if remote:
        report["server_openssl"] = remote["openssl"]
    (work / "endpoint-results.json").write_text(json.dumps(report, indent=2))
    if not args.capture_only:
        collector = args.collector or root / "build/bin" / args.configuration / "Cipherazzi.Collector.exe"
        started = time.perf_counter()
        replay = execute([str(collector), "--replay", str(capture), "--db", str(database)])
        (work / "collector.stdout").write_text(replay)
        report["collector_replay_process_ms"] = round((time.perf_counter() - started) * 1000, 3)
        verify(database, cases, outcomes)
        report["collector_verified"] = True
    (work / "results.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
