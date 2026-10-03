import hashlib
import json
import sqlite3
import ssl
import shutil
import sys
import time
from pathlib import Path
from Integration import ip_packet, run, write_pcap


def main():
    root = Path(__file__).resolve().parent.parent
    fixture = Path(json.loads((root / ".work/latest-integration.json").read_text())["database"]).parent
    work = root / ".work" / ("crypto-" + str(time.time_ns()))
    work.mkdir()
    certificate = ssl.PEM_cert_to_DER_cert((fixture / "cert.pem").read_text())
    fingerprint = hashlib.sha256(certificate).hexdigest()
    packets = []
    expectations = []

    def contexts(version, mutual=False):
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.minimum_version = server.maximum_version = version
        server.load_cert_chain(fixture / "cert.pem", fixture / "key.pem")
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.minimum_version = client.maximum_version = version
        client.check_hostname = False
        client.load_verify_locations(fixture / "cert.pem")
        if mutual:
            server.load_verify_locations(fixture / "cert.pem")
            server.verify_mode = ssl.CERT_REQUIRED
            client.load_cert_chain(fixture / "cert.pem", fixture / "key.pem")
        return client, server

    def exchange(client_context, server_context, name, session=None, failure=False):
        # Memory BIOs expose the exact TLS bytes without substituting a handcrafted handshake.
        port = 51000 + len(expectations)
        incoming = [ssl.MemoryBIO(), ssl.MemoryBIO()]
        outgoing = [ssl.MemoryBIO(), ssl.MemoryBIO()]
        sockets = [client_context.wrap_bio(incoming[0], outgoing[0], server_hostname=name, session=session),
                   server_context.wrap_bio(incoming[1], outgoing[1], server_side=True)]
        sequence = [1001, 9001]
        packets.append((time.time_ns() // 1000, ip_packet(b"", port, 1000, True, 2)))
        completed = [False, False]
        failed = False

        def pump():
            for direction in range(2):
                data = outgoing[direction].read()
                incoming[1 - direction].write(data)
                for offset in range(0, len(data), 137):
                    part = data[offset:offset + 137]
                    packets.append((time.time_ns() // 1000,
                                    ip_packet(part, port, sequence[direction], direction == 0)))
                    sequence[direction] += len(part)

        for _ in range(100):
            for direction in range(2):
                if completed[direction]:
                    continue
                try:
                    sockets[direction].do_handshake()
                    completed[direction] = True
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLError:
                    failed = True
                pump()
            if all(completed) or failed:
                break
        assert failed == failure, (name, failed)
        if not failed:
            assert all(completed), name
            sockets[0].write(b"test")
            pump()
            assert sockets[1].read(4) == b"test"
            sockets[1].write(b"pass")
            pump()
            assert sockets[0].read(4) == b"pass"
            assert sockets[0].getpeercert(binary_form=True) == certificate
        packets.append((time.time_ns() // 1000, ip_packet(b"", port, sequence[0], True, 4)))
        expectations.append(dict(name=name, resumed=not failed and sockets[0].session_reused, failure=failed))
        return sockets[0].session if not failed else None

    client12, server12 = contexts(ssl.TLSVersion.TLSv1_2, mutual=True)
    session12 = exchange(client12, server12, "mutual.test")
    exchange(client12, server12, "resumed12.test", session12)
    client13, server13 = contexts(ssl.TLSVersion.TLSv1_3)
    session13 = exchange(client13, server13, "full13.test")
    assert session13.has_ticket, "The server did not supply a resumption ticket"
    exchange(client13, server13, "resumed13.test", session13)
    client_bad, server_bad = contexts(ssl.TLSVersion.TLSv1_2)
    client_bad.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    server_bad.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")
    exchange(client_bad, server_bad, "fatal.test", failure=True)
    client_dh, server_dh = contexts(ssl.TLSVersion.TLSv1_2)
    parameters = work / "dh.pem"
    run([shutil.which("openssl"), "genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt", "group:ffdhe2048",
         "-out", str(parameters)])
    server_dh.load_dh_params(str(parameters))
    client_dh.set_ciphers("DHE-RSA-AES128-GCM-SHA256")
    server_dh.set_ciphers("DHE-RSA-AES128-GCM-SHA256")
    exchange(client_dh, server_dh, "finite-field.test")
    assert expectations[1]["resumed"] and expectations[3]["resumed"], expectations
    capture = work / "operations.pcap"
    write_pcap(capture, packets)
    database = work / "operations.db"
    collector = root / "build/bin/Release/Cipherazzi.Collector.exe"
    run([str(collector), "--replay", str(capture), "--db", str(database)])
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        rows = {row["sni"]: row for row in connection.execute("SELECT * FROM connections")}
        assert len(rows) == 6, list(rows)
        mutual = rows["mutual.test"]
        crypto = json.loads(mutual["crypto_json"])
        assert crypto["client_authentication"] == "Certificate presented; not confirmed", crypto
        assert crypto["handshake_signature"] and crypto["client_handshake_signature"], crypto
        assert mutual["group_name"] == "x25519" and crypto["ems_selected"] == 1, crypto
        assert crypto["server_certificates"] == crypto["client_certificates"] == [fingerprint], crypto
        resumed12 = json.loads(rows["resumed12.test"]["crypto_json"])
        assert "resumption selected" in resumed12["resumption"], resumed12
        resumed13 = json.loads(rows["resumed13.test"]["crypto_json"])
        assert resumed13["selected_psk_index"] == 0 and "PSK" in rows["resumed13.test"]["psk_mode"], resumed13
        assert resumed13["ems_selected"] is None, resumed13
        assert "Encrypted" in resumed13["certificate_visibility"], resumed13
        finite_field = json.loads(rows["finite-field.test"]["crypto_json"])
        assert finite_field["dh_parameter_bits"] == 2048 and finite_field["group_class"] == "Classical", finite_field
        assert rows["fatal.test"]["alert"] == "handshake_failure", dict(rows["fatal.test"])
        for row in rows.values():
            assert row["ended_us"] and row["close_reason"] == "TCP reset observed", dict(row)
        stored = list(connection.execute("SELECT sha256,der,metadata_json FROM certificates"))
        assert len(stored) == 1 and stored[0][0] == fingerprint and stored[0][1] == certificate
        metadata = json.loads(stored[0][2])
        assert metadata["public_key_bits"] == 2048 and "localhost" in metadata["subject"], metadata
        references = list(connection.execute("SELECT role,chain_index,sha256 FROM connection_certificates ORDER BY role"))
        assert [tuple(row) for row in references] == [("client", 0, fingerprint), ("server", 0, fingerprint),
                                                    ("server", 0, fingerprint)]
        assert not list(connection.execute("PRAGMA foreign_key_check"))
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    # Reopening the journal must accumulate negotiations while retaining one certificate object.
    run([str(collector), "--replay", str(capture), "--db", str(database)])
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM certificates").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM connection_certificates").fetchone()[0] == 6
        assert connection.execute("SELECT count(*) FROM connections").fetchone()[0] == 12
    report = dict(database=str(database), handshakes=expectations, certificate_sha256=fingerprint,
                  original_der_roundtrip=True, deduplication_across_restarts=True, certificate_links=6)
    (root / ".work/latest-crypto.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
