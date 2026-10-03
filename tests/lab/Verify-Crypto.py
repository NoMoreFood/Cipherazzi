import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from Verify import verify


directory = Path(sys.argv[1])
verify(directory)
with sqlite3.connect(directory / "capture.db") as database:
    database.row_factory = sqlite3.Row
    legacy = list(database.execute("SELECT * FROM connections WHERE tls_version=771 AND sni LIKE '%cipherazzi.test'"))
    assert len(legacy) >= 3
    for row in legacy:
        evidence = json.loads(row["crypto_json"])
        assert row["group_name"] == "x25519" and row["certificate_sha256"], dict(row)
        assert evidence["handshake_signature"] and evidence["ems_selected"] == 1, evidence
        assert database.execute("SELECT count(*) FROM connection_certificates WHERE run_id=? AND flow_id=?",
                                (row["run_id"], row["flow_id"])).fetchone()[0] > 0
    certificates = list(database.execute("SELECT sha256,der FROM certificates"))
    assert certificates
    for row in certificates:
        assert hashlib.sha256(row["der"]).hexdigest() == row["sha256"]
    assert not list(database.execute("PRAGMA foreign_key_check"))
    events = list(database.execute("SELECT * FROM endpoint_events WHERE kind='jdk.TLSHandshake'"))
    assert len(events) == 8, len(events)
    assert all(row["pid"] and row["protocol"] == "TLSv1.3" for row in events)
    windows = database.execute("SELECT count(*) FROM endpoint_events WHERE provider='Microsoft-Windows-CAPI2'").fetchone()[0]
    assert windows > 0, "CAPI2 did not emit certificate telemetry"
    assert database.execute("SELECT sum(telemetry_lost) FROM capture_sessions").fetchone()[0] == 0
report = dict(legacy_handshakes=len(legacy), certificates=len(certificates), original_der_verified=True,
              certificate_links_verified=True, jfr_handshakes=len(events), capi2_events=windows,
              service_mode=True, telemetry_losses=0)
(directory / "crypto-verified.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
