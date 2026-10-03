import argparse
import json
import socket
import sqlite3
import ssl
import struct
import subprocess
import time
from pathlib import Path

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.packet import encode_quic_retry, pull_quic_header


def packet(data, client, port, ipv6=False):
    source = "fd00::1" if ipv6 and client else "fd00::2" if ipv6 else "10.20.0.1" if client else "10.20.0.2"
    destination = "fd00::2" if ipv6 and client else "fd00::1" if ipv6 else "10.20.0.2" if client else "10.20.0.1"
    udp = struct.pack("!HHHH", port if client else 443, 443 if client else port, len(data) + 8, 0) + data
    if ipv6:
        return struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 64,
                           socket.inet_pton(socket.AF_INET6, source), socket.inet_pton(socket.AF_INET6, destination)) + udp
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(udp) + 20, 0, 0x4000, 64, 17, 0,
                       socket.inet_aton(source), socket.inet_aton(destination)) + udp


def write_pcap(path, packets):
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        for timestamp, data in packets:
            output.write(struct.pack("<IIII", timestamp // 1000000, timestamp % 1000000, len(data), len(data)))
            output.write(data)


def transcript(cert, key, version, retry=False, fragmented=False):
    # Drive unmodified aioquic TLS and packet protection through both endpoints.
    client_config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name="quic.lab",
                                      verify_mode=ssl.CERT_NONE, supported_versions=[version],
                                      original_version=version, quantum_readiness_test=fragmented)
    client = QuicConnection(configuration=client_config)
    server_config = QuicConfiguration(is_client=False, alpn_protocols=["h3"], supported_versions=[version])
    server_config.load_cert_chain(str(cert), str(key))
    now = time.monotonic()
    client.connect(("10.20.0.2", 443), now=now)
    first = client.datagrams_to_send(now=now)
    header = pull_quic_header(Buffer(data=first[0][0]), host_cid_length=8)
    records = [(True, data) for data, _ in first]
    token, retry_id = b"cipherazzi-test-address-token", b"retrycid"
    if retry:
        retry_packet = encode_quic_retry(version=version, source_cid=retry_id,
            destination_cid=header.source_cid, original_destination_cid=header.destination_cid, retry_token=token)
        records.append((False, retry_packet))
        client.receive_datagram(retry_packet, ("10.20.0.2", 443), now=now + 0.001)
        first = client.datagrams_to_send(now=now + 0.002)
        records.extend((True, data) for data, _ in first)
    server = QuicConnection(configuration=server_config, original_destination_connection_id=header.destination_cid,
                            retry_source_connection_id=retry_id if retry else None)
    for data, _ in first:
        server.receive_datagram(data, ("10.20.0.1", 52000), now=now + 0.003)
    completed = [False, False]
    for step in range(500):
        now += 0.01
        for source, target, client_side, address in [(server, client, False, ("10.20.0.2", 443)),
                                                     (client, server, True, ("10.20.0.1", 52000))]:
            for data, _ in source.datagrams_to_send(now=now):
                records.append((client_side, data))
                target.receive_datagram(data, address, now=now)
            while (event := source.next_event()) is not None:
                if isinstance(event, HandshakeCompleted):
                    completed[0 if client_side else 1] = True
        if all(completed):
            break
        for connection in [client, server]:
            timer = connection.get_timer()
            if timer is not None and now >= timer:
                connection.handle_timer(now=now)
    assert all(completed), "Actual QUIC endpoints did not complete the handshake"
    return records


def grease_server_initial(records, version):
    # Reprotect one authentic Initial with the QUIC bit cleared, including its authenticated header.
    original = pull_quic_header(Buffer(data=records[0][1]), host_cid_length=8).destination_cid
    crypto = CryptoPair()
    crypto.setup_initial(original, is_client=True, version=version)
    for index, (client, data) in enumerate(records):
        if client:
            continue
        buffer = Buffer(data=data)
        header = pull_quic_header(buffer, host_cid_length=8)
        plain, payload, number, _ = crypto.recv.decrypt_packet(data[:header.packet_length], buffer.tell(), 0)
        plain = bytes([plain[0] & ~0x40]) + plain[1:]
        records[index] = (False, crypto.recv.encrypt_packet(plain, payload, number) + data[header.packet_length:])
        return records
    raise AssertionError("Missing server Initial")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl", default="C:/msys64/usr/bin/openssl.exe")
    parser.add_argument("--collector", default="build/bin/Release/Cipherazzi.Collector.exe")
    parser.add_argument("--output", default=".work/quic")
    parser.add_argument("--fixtures", action="store_true")
    args = parser.parse_args()
    work = Path(args.output).resolve()
    work.mkdir(parents=True, exist_ok=True)
    config = work / "openssl.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n")
    cert, key = work / "cert.pem", work / "key.pem"
    result = subprocess.run([args.openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=quic.lab", "-config", str(config)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    records, fixtures, cases = [], [], []
    scenarios = [(1, False, False, False), (0x6b3343cf, False, False, False),
        (1, True, False, False), (0x6b3343cf, True, False, False),
        (1, False, True, False), (0x6b3343cf, False, True, False), (1, False, False, True)]
    for index, (version, retry, fragmented, greased) in enumerate(scenarios):
        packets = transcript(cert, key, version, retry, fragmented)
        if greased:
            packets = grease_server_initial(packets, version)
        if fragmented:
            initial = []
            while packets and packets[0][0]:
                initial.append(packets.pop(0))
            assert len(initial) > 1, "Fragmentation case must contain multiple client Initial datagrams"
            packets = list(reversed(initial)) + initial + packets
        port = 52000 + index
        encoded = []
        for offset, (client, data) in enumerate(packets):
            wire = packet(data, client, port, ipv6=index % 2 == 1)
            timestamp = 1700000000000000 + index * 1000000 + offset * 1000
            records.append((timestamp, wire))
            encoded.append(wire.hex())
        fixtures.append(dict(version=version, retry=retry, fragmented=fragmented, greased=greased, packets=encoded))
        cases.append(dict(version=version, retry=retry, fragmented=fragmented, greased=greased, port=port))
    capture = work / "quic.pcap"
    write_pcap(capture, records)
    database = work / "quic.db"
    subprocess.run([args.collector, "--replay", str(capture), "--db", str(database)], check=True, timeout=30)
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    rows = list(connection.execute("SELECT * FROM connections WHERE sni='quic.lab' ORDER BY source_port"))
    assert len(rows) == len(cases), f"Expected {len(cases)} QUIC flows, got {len(rows)}"
    for row, case in zip(rows, cases):
        crypto = json.loads(row["crypto_json"])
        assert row["state"] == "hellos_observed" and row["tls_version"] == 772
        assert row["source_port"] == case["port"] and crypto["transport"] == "QUIC"
        assert crypto["quic_version"] == case["version"] and crypto["quic_retry"] == case["retry"]
        assert row["offered_alpn"] == "h3" and row["selected_alpn"] == ""
        assert crypto["handshake_confirmation"] == "Not confirmed by endpoint"
        assert crypto["group_class"] == "Classical"
        assert len(crypto["negotiation_stages"]) == (3 if case["retry"] else 2)
    health = dict(connection.execute("SELECT malformed,reassembly_limit,flow_limit,queue_lost,capture_lost,storage_lost FROM capture_sessions").fetchone())
    assert not any(health.values()), health
    if args.fixtures:
        directory = Path(__file__).resolve().parent / "fixtures"
        directory.mkdir(exist_ok=True)
        (directory / "quic.json").write_text(json.dumps(fixtures, indent=2))
    report = dict(cases=cases, health=health, packets=len(records), database=str(database), capture=str(capture))
    (work / "results.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
