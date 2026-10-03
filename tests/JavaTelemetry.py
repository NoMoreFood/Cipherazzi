import json
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from Integration import listener, run
import ssl


def main():
    root = Path(__file__).resolve().parent.parent
    fixture = Path(json.loads((root / ".work/latest-integration.json").read_text())["database"]).parent
    work = root / ".work" / ("jfr " + str(time.time_ns()))
    work.mkdir()
    java_home = Path(r"C:\Program Files\Java\jdk-25.0.2")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(fixture / "cert.pem", fixture / "key.pem")
    server = listener()
    server.settimeout(1)
    port = server.getsockname()[1]
    stopping = threading.Event()

    def accept():
        while not stopping.is_set():
            try:
                raw, _ = server.accept()
                with raw, context.wrap_socket(raw, server_side=True) as tls:
                    tls.sendall(tls.recv(1))
            except TimeoutError:
                continue
            except OSError:
                break

    thread = threading.Thread(target=accept)
    thread.start()
    java = subprocess.Popen([str(java_home / "bin/java.exe"), str(root / "tests/clients/JavaTelemetry.java"),
                             "127.0.0.1", str(port), str(fixture / "cert.pem")], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        assert java.stdout.readline().strip() == "ready", "Java TLS client did not start"
        result = run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                      str(root / "Watch-Java.ps1"), "-ProcessId", str(java.pid), "-JavaHome", str(java_home),
                      "-OutputDirectory", str(work), "-IntervalSeconds", "2", "-DurationSeconds", "12"])
        exported = work / f"jfr-{java.pid}.json"
        payload = json.loads(exported.read_text(encoding="utf-8-sig"))
        events = payload["recording"]["events"]
        handshakes = [event for event in events if event["type"] == "jdk.TLSHandshake"]
        assert len(handshakes) == 8, (len(handshakes), result)
        assert all(event["values"]["protocolVersion"] == "TLSv1.3" for event in handshakes)
        database = work / "endpoint.db"
        collector = root / "build/bin/Release/Cipherazzi.Collector.exe"
        for _ in range(2):
            run([str(collector), "--import-jfr", str(exported), "--db", str(database)])
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT count(*) FROM endpoint_events").fetchone()[0] == len(events)
            assert connection.execute("SELECT count(*) FROM endpoint_events WHERE kind='jdk.TLSHandshake' "
                                      "AND protocol='TLS 1.3' AND pid=?", (java.pid,)).fetchone()[0] == 8
            assert connection.execute("SELECT count(*) FROM endpoint_events WHERE kind='jdk.TLSHandshake' "
                                      "AND json_extract(detail_json,'$.assessment.crypto.evidence_source')='Endpoint' "
                                      "AND json_extract(detail_json,'$.process_started_us')=?",
                                      (payload["process_started_us"],)).fetchone()[0] == 8
            assert connection.execute("SELECT sum(telemetry_lost) FROM capture_sessions").fetchone()[0] == 0
        # A malformed exporter must not expand the bounded event queue through an oversized summary field.
        oversized = json.loads(json.dumps(payload))
        oversized["recording"]["events"] = [handshakes[0]]
        oversized["recording"]["events"][0]["values"]["peerHost"] = "x" * 100000
        oversized_file = work / "oversized.json"
        oversized_file.write_text(json.dumps(oversized))
        oversized_database = work / "oversized.db"
        run([str(collector), "--import-jfr", str(oversized_file), "--db", str(oversized_database)])
        with sqlite3.connect(oversized_database) as connection:
            assert connection.execute("SELECT sum(telemetry_lost) FROM capture_sessions").fetchone()[0] == 1
            peer, detail = connection.execute("SELECT peer,detail_json FROM endpoint_events").fetchone()
            assert len(peer) < 4096 and "error" in json.loads(detail)
        report = dict(database=str(database), exported=str(exported), jfr_events=len(events),
                      endpoint_handshakes=8, deduplicated_reimport=True, path_with_spaces=True,
                      oversized_metadata_bounded_and_reported=True)
        (root / ".work/latest-jfr.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
    finally:
        if java.poll() is None:
            java.terminate()
        java.communicate(timeout=10)
        stopping.set()
        server.close()
        thread.join(timeout=3)


if __name__ == "__main__":
    main()
