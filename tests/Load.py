import argparse
import json
import sqlite3
import struct
import time
from pathlib import Path
from Integration import ip_packet, run, write_pcap


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=20000)
    args = parser.parse_args()
    if not 1 <= args.count <= 30000:
        raise ValueError("Count must be between 1 and 30000")
    root = Path(__file__).resolve().parent.parent
    integration = json.loads((root / ".work/latest-integration.json").read_text())
    work = Path(integration["database"]).parent
    captured = work / "crypto-stacks.pcap"
    streams = [{}, {}]
    with captured.open("rb") as file:
        file.read(24)
        while header := file.read(16):
            _, _, captured_size, _ = struct.unpack("<IIII", header)
            data = file.read(captured_size)
            source, destination, sequence = struct.unpack("!HHI", data[20:28])
            if len(data) > 40 and (source == 50001 or destination == 50001):
                streams[0 if source == 50001 else 1][sequence] = data[40:]
    hellos = []
    for stream in streams:
        data = b"".join(payload for _, payload in sorted(stream.items()))
        hellos.append(data[:5 + struct.unpack("!H", data[3:5])[0]])
    timestamp = time.time_ns() // 1000

    def packets():
        for index in range(args.count):
            port = 10000 + index
            yield timestamp + index, ip_packet(b"", port, 1000, True, 2)
            yield timestamp + index, ip_packet(hellos[0], port, 1001, True)
            yield timestamp + index, ip_packet(hellos[1], port, 9001, False)

    pcap = work / "load.pcap"
    database = work / ("load-" + str(time.time_ns()) + ".db")
    write_pcap(pcap, packets())
    started = time.perf_counter()
    output = run([str(root / "build/bin/Release/Cipherazzi.Collector.exe"), "--db", str(database),
                  "--replay", str(pcap)])
    elapsed = time.perf_counter() - started
    with sqlite3.connect(database) as connection:
        count = connection.execute("SELECT count(*) FROM connections WHERE tls_version=772 "
                                   "AND state='hellos_observed'").fetchone()[0]
        health = connection.execute("SELECT storage_lost,flow_limit,reassembly_limit FROM capture_sessions").fetchone()
        assert count == args.count and health == (0, 0, 0), (count, health)
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    viewer = str(root / "viewer/bin/Release/net10.0-windows/Cipherazzi.Viewer.exe")
    run([viewer, "--verify-ui", str(database), str(work / "load-viewer.png")])
    report = {"connections": count, "elapsed_seconds": elapsed, "connections_per_second": count / elapsed,
              "database_bytes": database.stat().st_size, "database": str(database), "collector_output": output}
    (root / ".work/latest-load.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
