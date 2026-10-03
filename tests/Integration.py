import argparse
import json
import socket
import sqlite3
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=90,
                            creationflags=subprocess.CREATE_NO_WINDOW, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited with {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(30)
    return server


def ip_packet(data, port, sequence, client, flags=0x18):
    source = bytes([10, 20, 0, 1 if client else 2])
    destination = bytes([10, 20, 0, 2 if client else 1])
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(data), 1, 0x4000, 64, 6, 0,
                         source, destination)
    tcp = struct.pack("!HHIIBBHHH", port if client else 443, 443 if client else port,
                      sequence, 0, 0x50, flags, 65535, 0, 0)
    return header + tcp + data


def exchange(context, client_command, source_port):
    # Record actual TLS stream bytes in a loopback relay, then packetize them for collector replay.
    upstream = listener()
    proxy = listener()
    captured = []
    errors = []
    transcript_lock = threading.Lock()

    def server():
        try:
            with upstream.accept()[0] as raw, context.wrap_socket(raw, server_side=True) as tls:
                data = tls.recv(1)
                tls.sendall(data)
        except Exception as error:
            errors.append(error)
        finally:
            upstream.close()

    def pump(source, destination, client):
        sequence = 1001 if client else 9001
        try:
            while data := source.recv(65536):
                with transcript_lock:
                    timestamp = time.time_ns() // 1000
                    offset = 0
                    sizes = [1, 2, 7, 31, 257, 511]
                    count = 0
                    while offset < len(data):
                        part = data[offset:offset + sizes[count % len(sizes)]]
                        captured.append((timestamp, ip_packet(part, source_port, sequence, client)))
                        sequence += len(part)
                        offset += len(part)
                        count += 1
                destination.sendall(data)
            destination.shutdown(socket.SHUT_WR)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    def relay():
        try:
            with proxy.accept()[0] as client, socket.create_connection(upstream.getsockname(), timeout=30) as remote:
                received = threading.Thread(target=pump, args=(remote, client, False))
                received.start()
                pump(client, remote, True)
                received.join(timeout=35)
        except Exception as error:
            errors.append(error)
        finally:
            proxy.close()

    timestamp = time.time_ns() // 1000
    captured.extend([(timestamp, ip_packet(b"", source_port, 1000, True, 2)),
                     (timestamp, ip_packet(b"", source_port, 9000, False, 0x12))])
    port = proxy.getsockname()[1]
    server_thread = threading.Thread(target=server)
    relay_thread = threading.Thread(target=relay)
    server_thread.start()
    relay_thread.start()
    result = run(client_command(port))
    relay_thread.join(timeout=40)
    server_thread.join(timeout=40)
    if relay_thread.is_alive() or server_thread.is_alive():
        raise RuntimeError("Loopback TLS exchange timed out")
    if errors:
        raise errors[0]
    return captured, result


def write_pcap(path, packets):
    with path.open("wb") as file:
        file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for timestamp, data in packets:
            seconds, fraction = divmod(timestamp, 1_000_000)
            file.write(struct.pack("<IIII", seconds, fraction, len(data), len(data)))
            file.write(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--java", required=True)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--configuration", default="Release")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    work = root / ".work" / ("integration-" + str(time.time_ns()))
    work.mkdir(parents=True)
    run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(work / "key.pem"),
         "-out", str(work / "cert.pem"), "-days", "1", "-subj", "/CN=localhost"])
    run(["dotnet", "build", str(root / "tests/clients/SchannelClient.csproj"), "-c", args.configuration])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(work / "cert.pem", work / "key.pem")
    context.set_alpn_protocols(["h2", "http/1.1"])
    packets = []
    expected = []
    schannel = root / "tests/clients/bin" / args.configuration / "net10.0-windows/SchannelClient.dll"
    for stack in ["java", "schannel", "openssl"]:
        for version in ["TLSv1.2", "TLSv1.3"]:
            source_port = 50000 + len(expected)
            hostname = f"{stack}-{version[-1]}.example.test"
            if stack == "java":
                command = lambda port: [args.java, str(root / "tests/clients/JavaClient.java"),
                                        str(port), version, hostname]
            elif stack == "schannel":
                command = lambda port: ["dotnet", str(schannel), str(port), version, hostname]
            else:
                # Python's ssl module uses OpenSSL and sends a real TLS exchange through the same relay.
                script = (
                    "import socket,ssl,sys; c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); "
                    "c.check_hostname=False; c.verify_mode=ssl.CERT_NONE; "
                    f"c.minimum_version=c.maximum_version=ssl.TLSVersion.TLSv1_{version[-1]}; "
                    "c.set_alpn_protocols(['h2','http/1.1']); "
                    "raw=socket.create_connection(('127.0.0.1',int(sys.argv[1]))); "
                    f"s=c.wrap_socket(raw,server_hostname='{hostname}'); "
                    "print(s.version(),s.cipher()); s.sendall(b'*'); assert s.recv(1)==b'*'; s.close()"
                )
                import sys
                command = lambda port: [sys.executable, "-c", script, str(port)]
            exchange_packets, negotiated = exchange(context, command, source_port)
            packets.extend(exchange_packets)
            expected.append((hostname, 0x0303 if version == "TLSv1.2" else 0x0304, negotiated))
            print(f"{stack}: {negotiated}", flush=True)

    # Introduce real capture duplication and reordering without changing the TLS byte streams.
    for start in range(2, len(packets) - 3, 11):
        packets[start], packets[start + 1] = packets[start + 1], packets[start]
    packets += packets[2:12]
    capture = work / "crypto-stacks.pcap"
    write_pcap(capture, packets)
    database = work / "observations.db"
    collector = root / "build/bin" / args.configuration / "Cipherazzi.Collector.exe"
    started = time.perf_counter()
    result = run([str(collector), "--replay", str(capture), "--db", str(database)])
    elapsed = time.perf_counter() - started
    print(result)
    with sqlite3.connect(database) as connection:
        rows = connection.execute("SELECT sni,tls_version,cipher_name,offered_alpn,selected_alpn,state,"
                                  "source_pid,destination_pid FROM connections ORDER BY source_port").fetchall()
        assert len(rows) == len(expected), rows
        for row, (hostname, version, negotiated) in zip(rows, expected):
            assert row[0] == hostname and row[1] == version and row[2], row
            assert "h2" in row[3] and row[4] == ("h2" if version == 0x0303 else ""), row
            assert row[5] == "hellos_observed" and row[6:] == (None, None), row
            if hostname.startswith(("java", "schannel")):
                assert row[2] in negotiated, (row, negotiated)
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT storage_lost FROM capture_sessions").fetchone()[0] == 0
    viewer = root / "viewer/bin" / args.configuration / "net10.0-windows/Cipherazzi.Viewer.exe"
    run([str(viewer), "--verify", str(database)])
    run([str(viewer), "--verify-ui", str(database), str(work / "viewer.png")])
    report = {"database": str(database), "screenshot": str(work / "viewer.png"), "rows": len(rows),
              "replay_seconds": elapsed, "exchanges": expected, "packets": len(packets)}
    (root / ".work/latest-integration.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
