import argparse
import json
import random
import sqlite3
import struct
import subprocess
import time
from pathlib import Path


def read_packets(path):
    packets = []
    with path.open("rb") as stream:
        header = stream.read(24)
        if header[:4] != bytes.fromhex("d4c3b2a1"):
            raise ValueError("The mutation corpus requires little-endian microsecond PCAP.")
        link = struct.unpack_from("<I", header, 20)[0]
        while record := stream.read(16):
            _, _, size, _ = struct.unpack("<IIII", record)
            packet = stream.read(size)
            if len(packet) != size:
                raise ValueError("The seed capture is truncated.")
            if link == 1:
                if packet[12:14] != bytes.fromhex("0800"):
                    continue
                packet = packet[14:]
            if packet and packet[0] >> 4 == 4:
                packets.append(packet)
    return packets


def write_pcap(path, packets):
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 1048576, 101))
        now = time.time_ns() // 1000
        for index, packet in enumerate(packets):
            timestamp = now + index
            stream.write(struct.pack("<IIII", timestamp // 1000000, timestamp % 1000000,
                                     len(packet), len(packet)))
            stream.write(packet)


def mutated_packets(seeds, count):
    generator = random.Random(0xC1F3A221)
    for index in range(count):
        packet = bytearray(generator.choice(seeds))
        operation = index % 10
        if operation == 0:
            packet = packet[:generator.randrange(len(packet) + 1)]
        elif operation == 1:
            packet.extend(generator.randbytes(generator.randrange(2048)))
        elif operation == 2:
            packet = bytearray(generator.randbytes(generator.randrange(4096)))
        else:
            # Preserve some envelope lengths to reach parsers beyond IP and TCP admission checks.
            start = 40 if operation >= 6 and len(packet) > 40 else 0
            for _ in range(generator.randrange(1, 20)):
                if len(packet) > start:
                    at = generator.randrange(start, len(packet))
                    packet[at] ^= generator.randrange(1, 256)
            if operation >= 8 and len(packet) >= 40:
                packet[12:16] = struct.pack("!I", 0x0A000001 + index // 50000)
                packet[20:22] = struct.pack("!H", 10000 + index % 50000)
                packet[2:4] = struct.pack("!H", len(packet))
        yield bytes(packet)
        if index % 1000 == 0:
            yield from seeds[:32]


def invoke(executable, database, capture, timeout=120):
    started = time.perf_counter()
    process = subprocess.Popen([str(executable), "--db", str(database), "--no-process",
                                "--max-flows", "4096", "--buffer-mb", "8", "--replay", str(capture)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise RuntimeError(f"Collector did not terminate within {timeout} seconds.\n{stdout}\n{stderr}")
    return {"exit_code": process.returncode, "seconds": time.perf_counter() - started,
            "stdout": stdout, "stderr": stderr}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--seed", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=250000)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    seeds = [packet for path in args.seed for packet in read_packets(path)]
    if not seeds:
        raise ValueError("No IP packets were found in the mutation corpus.")
    capture = args.output / "mutations.pcap"
    write_pcap(capture, mutated_packets(seeds, args.count))
    database = args.output / "mutations.db"
    result = invoke(args.collector.resolve(), database, capture)
    if result["exit_code"] != 0:
        (args.output / "failure.json").write_text(json.dumps(result, indent=2))
        raise RuntimeError("Mutated packets stopped the collector: " + result["stderr"])
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        columns = [item[1] for item in connection.execute("PRAGMA table_info(capture_sessions)")]
        result["health"] = dict(zip(columns, connection.execute("SELECT * FROM capture_sessions").fetchone()))
        result["observations"] = connection.execute("SELECT count(*) FROM connections").fetchone()[0]
        (args.output / "replay.json").write_text(json.dumps(result, indent=2))
        assert result["health"]["active_flows"] == 0, "Flow cleanup retained active connections."
        assert result["health"]["buffered_bytes"] == 0, "Flow cleanup corrupted the reassembly budget."
        assert result["observations"] > 0, "Seed observations did not survive the mutation stream."
    # Container corruption must be rejected with an error, without hanging or corrupting the journal.
    failures = []
    with capture.open("rb") as stream:
        short_header = stream.read(19)
    for name, content in {
        "short_header": short_header,
        "partial_record": struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101) + bytes(7),
        "oversized_record": struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101) +
                            struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF),
        "invalid_timestamp": struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101) +
                             struct.pack("<IIII", 1, 1000000, 0, 0),
    }.items():
        path = args.output / (name + ".pcap")
        path.write_bytes(content)
        rejection = invoke(args.collector.resolve(), args.output / (name + ".db"), path, 15)
        assert rejection["exit_code"] == 1 and rejection["stderr"], rejection
        failures.append({"case": name, **rejection})
    report = {"result": "passed", "mutations": args.count, "seed_packets": len(seeds),
              "replay": result, "corrupt_container_rejections": failures}
    (args.output / "results.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"result": report["result"], "mutations": args.count,
                      "seconds": result["seconds"], "observations": result["observations"]}))


if __name__ == "__main__":
    main()
