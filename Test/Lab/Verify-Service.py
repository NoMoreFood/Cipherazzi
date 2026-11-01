import argparse
import json
import sqlite3
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("database", type=Path)
parser.add_argument("suffix")
parser.add_argument("count", type=int)
parser.add_argument("output", type=Path)
args = parser.parse_args()
with sqlite3.connect(args.database) as database:
    database.row_factory = sqlite3.Row
    assert database.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    rows = list(database.execute("SELECT * FROM connections WHERE sni LIKE ?", ("%." + args.suffix,)))
    assert len(rows) == args.count, (len(rows), args.count)
    sessions = list(database.execute("SELECT * FROM capture_sessions WHERE id IN "
                                    "(SELECT run_id FROM connections WHERE sni LIKE ?)", ("%." + args.suffix,)))
    assert len(sessions) == 1 and sessions[0]["status"] == "stopped"
    session = sessions[0]
    for row in rows:
        label = row["sni"].split(".")[0]
        expected = "java.exe" if label.startswith("java") else (
            "SchannelClient.exe" if label.startswith("schannel") else "python.exe")
        assert row["source_process"] == expected and row["source_pid"], dict(row)
        assert row["source_process_started_us"] <= row["first_us"]
        assert row["state"] == "hellos_observed" and row["destination_port"] == 24443
        assert row["tls_version"] == (771 if label.endswith("-2") else 772)
        assert row["cipher_name"] == ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" if label.endswith("-2")
                                      else "TLS_AES_256_GCM_SHA384")
    assert session["capture_lost"] == session["queue_lost"] == session["storage_lost"] == 0
    assert session["process_events_lost"] == 0
    report = dict(handshakes=len(rows), process_names=len(rows), metadata_correct=True, graceful_stop=True,
                  capture_losses=0, queue_losses=0, storage_losses=0, process_event_losses=0,
                  packets=session["packets"])
    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
