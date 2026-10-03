import argparse
import concurrent.futures
import json
import os
import socket
import sqlite3
import ssl
import threading
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["server", "client", "observe"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=24443)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--log", required=True)
    parser.add_argument("--database")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--parallel", type=int, default=1)
    parser.add_argument("--tls", default="TLSv1.3")
    parser.add_argument("--sni", default="openssl-3.cipherazzi.test")
    args = parser.parse_args()
    lock = threading.Lock()
    deadline = time.monotonic() + args.duration

    def log(value):
        with lock, open(args.log, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(value) + "\n")
            stream.flush()

    if args.mode == "observe":
        seen = {}
        revision = 0
        with open(args.log, "a", encoding="utf-8") as output:
            while time.monotonic() < deadline:
                try:
                    with sqlite3.connect(f"file:{args.database}?mode=ro", uri=True, timeout=1) as database:
                        database.execute("BEGIN")
                        current = database.execute("SELECT revision FROM metadata WHERE id=1").fetchone()[0]
                        rows = database.execute("SELECT id,first_us,sni,tls_version,source_pid,source_process "
                                                "FROM connections WHERE change_revision>? "
                                                "AND sni LIKE '%cipherazzi.test'", (revision,)).fetchall()
                        database.commit()
                    arrival = time.time_ns() // 1000
                    for row in rows:
                        key = (row[3], row[4], row[5])
                        if seen.get(row[0]) != key:
                            seen[row[0]] = key
                            output.write(json.dumps(dict(id=row[0], first_us=row[1], sni=row[2], tls=row[3],
                                                        pid=row[4], process=row[5], arrival_us=arrival)) + "\n")
                    output.flush()
                    revision = current
                except sqlite3.OperationalError:
                    pass
                time.sleep(0.01)
        return

    if args.mode == "server":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.cert, args.key)
        context.set_alpn_protocols(["h2", "http/1.1"])
        context.set_servername_callback(lambda tls, name, _: setattr(tls, "lab_sni", name))

        def accept(raw, address):
            try:
                with raw, context.wrap_socket(raw, server_side=True) as tls:
                    data = tls.recv(1)
                    tls.sendall(data)
                    log(dict(sni=tls.lab_sni, version=tls.version(), cipher=tls.cipher()[0],
                             client=address, server=tls.getsockname(), time_us=time.time_ns() // 1000))
            except Exception as error:
                log(dict(error=str(error)))

        with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=64) as workers:
            listener.bind((args.host, args.port))
            listener.listen(256)
            listener.settimeout(1)
            Path(args.log + ".ready").write_text(str(os.getpid()))
            while time.monotonic() < deadline:
                try:
                    client, address = listener.accept()
                    client.settimeout(10)
                    workers.submit(accept, client, address)
                except socket.timeout:
                    pass
        return

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = context.maximum_version = (
        ssl.TLSVersion.TLSv1_3 if args.tls == "TLSv1.3" else ssl.TLSVersion.TLSv1_2)
    context.set_alpn_protocols(["h2", "http/1.1"])

    def exchange(index):
        with socket.create_connection((args.host, args.port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=args.sni) as tls:
                tls.sendall(b"*")
                if tls.recv(1) != b"*":
                    raise RuntimeError("TLS echo failed")
                log(dict(index=index, pid=os.getpid(), sni=args.sni, version=tls.version(),
                         cipher=tls.cipher()[0], local=tls.getsockname(), remote=tls.getpeername()))

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as workers:
        list(workers.map(exchange, range(args.count)))
    print(json.dumps(dict(count=args.count, seconds=time.perf_counter() - started, pid=os.getpid())))


if __name__ == "__main__":
    main()
