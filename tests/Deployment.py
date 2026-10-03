import argparse
import json
import socket
import sqlite3
import struct
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Verify configured collector and publisher processes.")
    parser.add_argument("payload", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    payload = args.payload.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    collector = payload / "Cipherazzi.Collector.exe"
    publisher = payload / "Cipherazzi.Publisher.exe"
    relay = payload / "Cipherazzi.Relay.exe"

    def run(executable, *arguments, success=True):
        result = subprocess.run([str(executable), *map(str, arguments)], capture_output=True,
                                text=True, timeout=20)
        assert (result.returncode == 0) == success, result.stdout + result.stderr
        return result.stdout + result.stderr

    # Resolve configured paths beside a file containing spaces, independently of the working directory.
    pcap = output / "empty.pcap"
    pcap.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    configuration = output / "collector config.json"
    configuration.write_text(json.dumps({"db": "journal.db", "replay": "empty.pcap", "no-process": True}))
    run(collector, "--config", configuration)
    journal = output / "journal.db"
    with sqlite3.connect(journal) as database:
        assert database.execute("SELECT count(*) FROM capture_sessions").fetchone()[0] == 1
    run(collector, "--config", configuration, "--db", output / "override.db")
    assert (output / "override.db").exists()

    # Exercise actual configured delivery through a local receiver with octet-counted framing.
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(10)
        publishing = output / "publisher config.json"
        publishing.write_text(json.dumps({"source": "journal.db",
            "syslog": f"tcp://127.0.0.1:{server.getsockname()[1]}", "allow-plaintext-syslog": True}))
        process = subprocess.Popen([str(publisher), "--config", str(publishing), "--once"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with server.accept()[0] as connection:
                connection.settimeout(10)
                data = bytearray()
                while True:
                    block = connection.recv(65536)
                    if not block:
                        break
                    data.extend(block)
            stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stdout + stderr
            length, body = bytes(data).split(b" ", 1)
            assert len(body) == int(length)
            event = json.loads(body[body.index(b'{'):])
            assert event["type"] == "health"
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    # Configured endpoint-only collection runs without a capture driver or administrator privileges.
    reports = output / "reports"
    reports.mkdir()
    endpoint = json.loads((Path(__file__).resolve().parents[1] / "tests/fixtures/endpoint-pq.json").read_text())
    (reports / "report.json").write_text(json.dumps(endpoint))
    configuration.write_text(json.dumps({"db": "endpoint.db", "endpoint-only": True,
                                        "endpoint-directory": "reports", "no-process": True, "duration": 1}))
    run(collector, "--config", configuration)
    with sqlite3.connect(output / "endpoint.db") as database:
        assert database.execute("SELECT count(*) FROM endpoint_events WHERE "
            "json_extract(detail_json,'$.assessment') IS NOT NULL").fetchone()[0] == 1

    for content in ['{"db":"first.db","db":"second.db"}', '{"install":true}',
                    '{"max-flows":{}}', '{"db":"' + "x" * (256 * 1024) + '"}']:
        configuration.write_text(content)
        run(collector, "--config", configuration, success=False)
    for executable in (collector, publisher, relay):
        configuration.write_text('{"source":"first.db","source":"second.db"}')
        run(executable, "--config", configuration, success=False)
        result = run(executable, "--service", "--config", output / "missing.json", success=False)
        assert "Windows Services" in result or "Service Control Manager" in result
    (output / "results.json").write_text(json.dumps({"result": "passed", "configured_delivery": True,
        "relative_paths": True, "command_overrides": True, "endpoint_only": True,
        "invalid_configuration": True, "service_entry_guard": True}, indent=2))
    print("Configured collector/publisher delivery and service-entry checks passed.")


if __name__ == "__main__":
    main()
