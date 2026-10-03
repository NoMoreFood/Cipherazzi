import argparse
import ctypes
import datetime
import json
import sqlite3
import struct
import subprocess
import time
from pathlib import Path

from NegotiationFixture import Capture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("collector", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    collector = args.collector.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True)
    results = []

    def run(name, *options, failed=False, events=0, connections=0, database=None, sessions=1):
        database = database or output / (name + ".db")
        started = time.perf_counter()
        process = subprocess.run([str(collector), "--db", str(database), "--no-process",
                                  "--retention-days", "0", "--retention-mb", "0", *map(str, options)],
                                 capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        (output / (name + ".stdout")).write_bytes(process.stdout)
        (output / (name + ".stderr")).write_bytes(process.stderr)
        assert process.returncode == int(failed), (name, process.returncode, process.stderr)
        if failed:
            assert process.stderr, (name, "The failure did not explain its cause")
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
            status, stopped, first, updated = connection.execute(
                "SELECT status,stopped_us,started_us,updated_us FROM capture_sessions "
                "ORDER BY started_us DESC LIMIT 1").fetchone()
            assert (status.startswith("failed:") if failed else status == "stopped"), (name, status)
            assert stopped is not None and first <= updated <= stopped, (name, first, stopped, updated)
            assert connection.execute("SELECT count(*) FROM capture_sessions").fetchone()[0] == sessions, name
            event_count = connection.execute("SELECT count(*) FROM endpoint_events").fetchone()[0]
            assert events is None or event_count == events, (name, event_count, events)
            assert connection.execute("SELECT count(*) FROM connections").fetchone()[0] == connections, name
            assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)], name
            assert not connection.execute("PRAGMA foreign_key_check").fetchall(), name
        results.append(dict(case=name, status=status, endpoint_events=event_count, connections=connections,
                            elapsed_ms=round((time.perf_counter() - started) * 1000, 1)))

    # Startup failures must publish a failed session even before the telemetry worker exists.
    run("missing-endpoint", "--endpoint-only", "--endpoint-directory", output / "missing-endpoint", failed=True)
    run("missing-java", "--endpoint-only", "--jfr-directory", output / "missing-java", failed=True)
    ordinary_file = output / "ordinary-file"
    ordinary_file.write_text("This is a file, not a telemetry directory.", encoding="utf-8")
    run("file-as-directory", "--endpoint-only", "--endpoint-directory", ordinary_file, failed=True)
    malformed = output / "malformed.json"
    malformed.write_text('{"recording":', encoding="utf-8")
    run("malformed-import", "--import-jfr", malformed, failed=True)
    run("missing-import", "--import-jfr", output / "missing.json", failed=True)

    # A later invalid event must preserve accepted events across more than one writer batch.
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    events = [dict(type="jdk.TLSHandshake", values=dict(startTime=timestamp, peerHost=f"peer-{index}.test",
                  peerPort=443, protocolVersion="TLSv1.3", cipherSuite="TLS_AES_128_GCM_SHA256"))
              for index in range(300)]
    partial = output / "partial.json"
    partial.write_text(json.dumps(dict(recording=dict(events=[*events, dict(type="jdk.TLSHandshake", values={})]))),
                       encoding="utf-8")
    run("partial-import", "--import-jfr", partial, failed=True, events=len(events))
    valid = output / "valid.json"
    valid.write_text(json.dumps(dict(recording=dict(events=events))), encoding="utf-8")
    run("successful-import", "--import-jfr", valid, events=len(events))
    run("restart-after-failure", "--import-jfr", valid, events=len(events),
        database=output / "partial-import.db", sessions=2)

    # Runtime replay errors retain decoded observations and the explicit diagnostic shutdown status.
    capture = Capture()
    capture.tcp([192, 0, 2, 1], [192, 0, 2, 2], 45000, 80,
                [(True, b"GET / HTTP/1.1\r\nHost: lifecycle.test\r\n\r\n"),
                 (False, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")])
    pcap = output / "truncated.pcap"
    capture.write(pcap)
    with pcap.open("ab") as stream:
        stream.write(struct.pack("<IIII", int(time.time()), 0, 100, 100) + b"incomplete")
    run("truncated-replay", "--replay", pcap, failed=True, connections=1)

    # Normal duration-based shutdown remains successful with no packet or administrative privileges.
    reports = output / "reports"
    reports.mkdir()
    run("endpoint-duration", "--endpoint-only", "--endpoint-directory", reports, "--duration", "1", events=1)

    # Event channels can have different access rights; report actual subscriptions and count source errors.
    run("windows-events", "--endpoint-only", "--schannel", "--duration", "1", events=None)
    with sqlite3.connect((output / "windows-events.db").as_uri() + "?mode=ro", uri=True) as connection:
        statuses = [row[0] for row in connection.execute(
            "SELECT result FROM endpoint_events WHERE kind='Source status'")]
        for channel in ["System", "Microsoft-Windows-CAPI2/Operational"]:
            assert sum(status.startswith(("Subscribed: " + channel + ";",
                                          "Subscription unavailable: " + channel + " ("))
                       for status in statuses) == 1, (channel, statuses)
        unavailable = sum(status.startswith("Subscription unavailable:") for status in statuses)
        assert connection.execute("SELECT telemetry_lost FROM capture_sessions").fetchone()[0] >= unavailable
        results[-1]["subscriptions"] = statuses

    # A standard token must reject packet capture before creating a misleading empty capture session.
    if not ctypes.windll.shell32.IsUserAnAdmin():
        database = output / "denied-live.db"
        process = subprocess.run([str(collector), "--db", str(database), "--no-loopback", "--duration", "1"],
                                 capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        (output / "denied-live.stderr").write_bytes(process.stderr)
        assert process.returncode == 1 and b"administrator privileges" in process.stderr, process.stderr
        assert not database.exists(), "A denied capture created a journal"
        results.append(dict(case="denied-live", exit_code=process.returncode, journal_created=False))
    (output / "results.json").write_text(json.dumps(dict(result="passed", checks=results), indent=2) + "\n",
                                         encoding="utf-8")
    print(f"All {len(results)} collector lifecycle checks passed.")


if __name__ == "__main__":
    main()
