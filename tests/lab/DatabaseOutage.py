import json
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / ".work" / ("outage-" + str(time.time_ns()))
WORK.mkdir(parents=True)
FLAGS = subprocess.CREATE_NO_WINDOW


def run(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=90, creationflags=FLAGS)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout.strip()


def scalar(sql):
    return int(run(["docker", "exec", "cipherazzi-lab-postgres", "psql", "-U", "cipherazzi", "-d", "cipherazzi",
                    "-Atc", sql]).splitlines()[-1])


def main():
    labels = json.loads(run(["docker", "inspect", "cipherazzi-lab-postgres"]))[0]["Config"]["Labels"]
    assert labels.get("purpose") == "cipherazzi-lab"
    integration = json.loads((ROOT / ".work/latest-integration.json").read_text())
    pcap = Path(integration["database"]).with_name("crypto-stacks.pcap")
    database = WORK / "capture.db"
    collector = ROOT / "dist/Cipherazzi.Collector.exe"
    run([str(collector), "--db", str(database), "--replay", str(pcap)])
    environment = os.environ.copy()
    arguments = [str(ROOT / "dist/Cipherazzi.Relay.exe"), "--source", str(database), "--provider", "postgresql",
                 "--connection-file", str(ROOT / ".work/databases/PostgreSql.credential")]
    with sqlite3.connect(database) as local:
        database_id, initial_revision = local.execute("SELECT database_id,revision FROM metadata").fetchone()
    assert re.fullmatch("[0-9a-f]{32}", database_id)

    def cursor():
        return scalar("SELECT COALESCE((SELECT revision FROM cipherazzi.replication_sources " +
                      f"WHERE source_id='{database_id}'),0)")

    def await_cursor(revision):
        deadline = time.monotonic() + 30
        while cursor() != revision:
            if time.monotonic() > deadline:
                raise TimeoutError("The relay did not recover its destination cursor.")
            time.sleep(0.2)

    stopped = False
    with (WORK / "relay.log").open("w") as log:
        relay = subprocess.Popen(arguments, env=environment, stdout=log, stderr=log, creationflags=FLAGS)
        try:
            await_cursor(initial_revision)
            run(["docker", "stop", "--time", "1", "cipherazzi-lab-postgres"])
            stopped = True
            run([str(collector), "--db", str(database), "--replay", str(pcap)])
            time.sleep(4)
            assert relay.poll() is None, "A server outage stopped the continuous relay."
            with sqlite3.connect(database) as local:
                revision = local.execute("SELECT revision FROM metadata").fetchone()[0]
                expected = local.execute("SELECT count(*) FROM connections").fetchone()[0]
                runs = [r[0] for r in local.execute("SELECT id FROM capture_sessions")]
                assert local.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert expected == 12 and revision > initial_revision
            run(["docker", "start", "cipherazzi-lab-postgres"])
            stopped = False
            for _ in range(100):
                try:
                    scalar("SELECT 1")
                    break
                except RuntimeError:
                    time.sleep(0.1)
            await_cursor(revision)
        finally:
            if stopped:
                run(["docker", "start", "cipherazzi-lab-postgres"])
            relay.terminate()
            relay.wait(timeout=10)
    for run_id in runs:
        assert re.fullmatch("[0-9-]+", run_id)
    query = "SELECT count(*) FROM cipherazzi.connections WHERE run_id IN(" + ",".join(f"'{r}'" for r in runs) + ")"
    assert scalar(query) == expected
    restarted = subprocess.run(arguments + ["--once"], env=environment, capture_output=True, text=True,
                               timeout=30, creationflags=FLAGS)
    assert restarted.returncode == 0 and scalar(query) == expected
    report = dict(source_rows=expected, recovered_rows=expected, journal_preserved=True,
                  automatic_reconnect=True, restart_idempotent=True, provider="PostgreSQL")
    (WORK / "results.json").write_text(json.dumps(report, indent=2))
    (ROOT / ".work/latest-outage.json").write_text(json.dumps(dict(directory=str(WORK), **report), indent=2))
    print(json.dumps(report))


if __name__ == "__main__":
    main()
