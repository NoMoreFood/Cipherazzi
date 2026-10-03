import argparse
import json
import sqlite3
import statistics
from pathlib import Path


def verify(directory):
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8-sig"))
    server = [json.loads(line) for line in (directory / "server.jsonl").read_text().splitlines()]
    expected = {(row["client"][0], row["client"][1], row["sni"]): row for row in server if "sni" in row}
    with sqlite3.connect(directory / "capture.db") as database:
        database.row_factory = sqlite3.Row
        assert database.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        session = dict(database.execute("SELECT * FROM capture_sessions").fetchone())
        rows = [dict(row) for row in database.execute("SELECT * FROM connections WHERE sni LIKE '%cipherazzi.test'")]
    assert session["computer_name"] == summary["computer_name"]
    assert len(rows) == len(expected), (len(rows), len(expected))
    ciphers = {"ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}
    for row in rows:
        peer = expected[(row["source_address"], row["source_port"], row["sni"])]
        assert row["destination_address"] == peer["server"][0]
        assert row["destination_port"] == peer["server"][1]
        assert row["tls_version"] == (772 if peer["version"] == "TLSv1.3" else 771)
        assert row["cipher_name"] == ciphers.get(peer["cipher"], peer["cipher"])
        assert row["state"] == "hellos_observed"
        assert session["started_us"] <= row["first_us"] <= row["last_us"] <= session["stopped_us"]
        process = "java.exe" if row["sni"].startswith("java") else (
            "SchannelClient.exe" if row["sni"].startswith("schannel") else "python.exe")
        assert row["source_process"] == process and row["source_pid"], (row["sni"], row["source_process"])
        assert row["source_process_started_us"] <= row["first_us"]
        assert row["source_account_domain"] + "\\" + row["source_account"] == summary["process_account"]
        assert row["source_account_sid"] == summary["process_account_sid"]
        assert row["destination_pid"] is None
        assert row["destination_account"] == row["destination_account_domain"] == row["destination_account_sid"] == ""
    arrivals = {}
    transport_arrivals = {}
    hello_times = {row["id"]: json.loads(row["crypto_json"])["client_hello_us"] for row in rows}
    for line in (directory / "arrivals.jsonl").read_text().splitlines():
        row = json.loads(line)
        # Measure publication after TLS evidence exists; socket setup can precede the hello by seconds.
        assert hello_times[row["id"]] >= row["first_us"]
        arrivals.setdefault(row["id"], (row["arrival_us"] - hello_times[row["id"]]) / 1000)
        transport_arrivals.setdefault(row["id"], (row["arrival_us"] - row["first_us"]) / 1000)
    latencies = sorted(arrivals.values())
    assert len(latencies) == len(rows)
    assert min(latencies) >= 0 and max(latencies) < 2000, (min(latencies), max(latencies))
    assert session["queue_lost"] == session["storage_lost"] == session["process_events_lost"] == 0
    assert session["flow_limit"] == session["reassembly_limit"] == 0
    assert session["status"] == "stopped"
    assert summary["viewer_exit"] == 0, summary
    report = dict(handshakes=len(rows), complete_metadata=True, process_names=len(rows), process_accounts=len(rows),
                  collector_computer=session["computer_name"], remote_accounts_unknown=True,
                  capture_losses=session["capture_lost"], queue_losses=session["queue_lost"],
                  storage_losses=session["storage_lost"], process_event_losses=session["process_events_lost"],
                  median_arrival_ms=statistics.median(latencies), p95_arrival_ms=latencies[int(len(latencies) * .95)],
                  maximum_arrival_ms=max(latencies), os=summary["os"],
                  peak_memory=summary["peak_memory"], cpu_seconds=summary["cpu_seconds"], viewer_exit=summary["viewer_exit"],
                  arrival_reference="Complete observed ClientHello",
                  maximum_connection_start_to_arrival_ms=max(transport_arrivals.values()))
    (directory / "verified.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    verify(parser.parse_args().directory)
