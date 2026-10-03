import argparse
import copy
import json
import sqlite3
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--cohorts", type=int, default=10)
    args = parser.parse_args()
    destination = Path(args.destination).resolve()
    if destination.exists() or not 10 <= args.count <= 1000000 or args.count % 10 or \
            not 10 <= args.cohorts <= 20000 or args.cohorts % 10 or args.count < args.cohorts:
        raise ValueError("Use a new destination and a count divisible by ten, from 10 to 1,000,000")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect(args.source)
    source.row_factory = sqlite3.Row
    connection = sqlite3.connect(destination)
    source.backup(connection)
    template = dict(source.execute("SELECT * FROM connections LIMIT 1").fetchone())
    certificates = [(row[0], json.loads(row[1])) for row in source.execute("SELECT sha256,metadata_json FROM certificates")]
    pq = next(value[0] for value in certificates if value[1].get("public_key_class") == "Post-quantum"
              and value[1].get("certificate_signature_class") == "Post-quantum")
    classical = next(value[0] for value in certificates if value[1].get("public_key_class") == "Classical")
    connection.executescript("PRAGMA foreign_keys=OFF; BEGIN; DELETE FROM connection_certificates; "
                             "DELETE FROM endpoint_events; DELETE FROM connections; DELETE FROM capture_sessions;")
    timestamp = time.time_ns() // 1000
    run = "migration-fixture"
    session = dict(source.execute("SELECT * FROM capture_sessions LIMIT 1").fetchone())
    session.update(id=run, started_us=timestamp - 1000000, updated_us=timestamp, stopped_us=timestamp,
                   computer_name="LAB-COLLECTOR", source="Synthetic migration/performance fixture", status="stopped",
                   packets=args.count * 3, observations=args.count, change_revision=1)
    columns = list(session)
    connection.execute(f"INSERT INTO capture_sessions ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                       [session[column] for column in columns])
    rows, links = [], []
    columns = list(template)
    for index in range(args.count):
        case = index % 10
        revision = index // 256 + 1
        crypto = copy.deepcopy(json.loads(template["crypto_json"]))
        crypto.update(transport="QUIC" if case == 7 else "TCP", classification_rule_version=1,
                      selected_group_id=4588, selected_group="X25519MLKEM768", group_class="Hybrid post-quantum",
                      group_standardization="Standardized", endpoint_confirmations=[], selected_psk_index=None,
                      server_certificates=[], client_certificates=[], handshake_signature="", client_handshake_signature="")
        crypto.update(client_hello_us=timestamp + index, server_hello_us=timestamp + index + 500)
        for stage in crypto.get("negotiation_stages", []):
            stage["observed_us"] = timestamp + index
        report = dict(provider="Synthetic public-session fixture", event_id=f"fixture-{index}",
                      timestamp_us=timestamp + index + 700, pid=100, local_role="Client", success=True,
                      handshake_signature_id=2308, authentication_class="Post-quantum", peer_verified=1,
                      local_handshake_signature_id=None, local_authentication_class="Not reported")
        chain = []
        if case == 0:
            crypto.update(selected_group_id=29, group_class="Classical", group_standardization="Assigned")
        elif case == 1:
            crypto["endpoint_confirmations"] = [report]
            chain = [pq]
        elif case == 2:
            report.update(handshake_signature_id=2052, authentication_class="Classical")
            crypto["endpoint_confirmations"] = [report]
            chain = [classical]
        elif case == 3:
            crypto.update(selected_group_id=512, group_class="Post-quantum", group_standardization="Draft")
            report["success"] = False
            crypto["endpoint_confirmations"] = [report]
        elif case == 4:
            crypto.update(selected_group_id=65025, group_class="Unknown", group_standardization="Private use")
            report.update(handshake_signature_id=65001, authentication_class="Unknown", peer_verified=-1)
            crypto["endpoint_confirmations"] = [report]
        elif case == 5:
            crypto.update(selected_group_id=None, group_class="Not observed", selected_psk_index=0)
            report.update(handshake_signature_id=None, authentication_class="Not reported")
            crypto["endpoint_confirmations"] = [report]
        elif case == 6:
            crypto["endpoint_confirmations"] = [report, dict(report, success=False)]
            chain = [pq]
        elif case == 7:
            report.update(local_role="Server", handshake_signature_id=2309, local_handshake_signature_id=2308,
                          local_authentication_class="Post-quantum")
            crypto["endpoint_confirmations"] = [report]
            chain = [pq, classical]
        elif case == 8:
            crypto.update(selected_group_id=23, group_class="Classical", group_standardization="Assigned",
                          handshake_signature="rsa_pss_rsae_sha256")
            chain = [classical]
        elif case == 9:
            crypto.update(selected_group_id=None, group_class="Not observed")
        crypto["server_certificates"] = chain
        row = template.copy()
        row.update(id=index + 1, run_id=run, flow_id=index + 1, first_us=timestamp + index, last_us=timestamp + index + 500,
                   sni=f"case-{case}.migration.test", source_process="client.exe",
                   source_path="C:/Lab/client.exe" if args.cohorts == 10 else f"C:/Lab/client-{index % args.cohorts // 10}.exe",
                   source_pid=100, destination_process="server.exe", destination_path="C:/Lab/server.exe", destination_pid=200,
                   source_process_started_us=timestamp - 5000000, destination_process_started_us=timestamp - 5000000,
                   source_account="analyst", source_account_domain="LAB", destination_account="service",
                   destination_account_domain="LAB", destination_port=443, tls_version=None if case == 9 else 771 if case == 8 else 772,
                   tls_name="" if case == 9 else "TLS 1.2" if case == 8 else "TLS 1.3",
                   state="client_hello_only" if case == 9 else "hellos_observed", group_name="X25519" if case == 0 else "X25519MLKEM768",
                   key_exchange="PSK only" if case == 5 else "X25519" if case == 0 else "X25519MLKEM768",
                   authentication="RSA" if case == 8 else "Encrypted; unknown", certificate_sha256=chain[0] if chain else "",
                   crypto_json=json.dumps(crypto, separators=(",", ":")), change_revision=revision,
                   detail="Synthetic evidence fixture; endpoint reports are simulated", ech_offered=int(case == 9))
        rows.append([row[column] for column in columns])
        links.extend((run, index + 1, "server", position, value, revision) for position, value in enumerate(chain))
        if len(rows) >= 1000:
            connection.executemany(f"INSERT INTO connections ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", rows)
            connection.executemany("INSERT INTO connection_certificates VALUES (?,?,?,?,?,?)", links)
            rows, links = [], []
    if rows:
        connection.executemany(f"INSERT INTO connections ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", rows)
        connection.executemany("INSERT INTO connection_certificates VALUES (?,?,?,?,?,?)", links)
    connection.execute("UPDATE certificates SET change_revision=1")
    connection.execute("UPDATE metadata SET database_id=lower(hex(randomblob(16))),revision=?", ((args.count + 255) // 256,))
    connection.commit()
    assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    connection.close()
    print(json.dumps(dict(database=str(destination), observations=args.count, cases=10, cohorts=args.cohorts,
                          bytes=destination.stat().st_size, pq_certificate=pq, classical_certificate=classical)))


if __name__ == "__main__":
    main()
