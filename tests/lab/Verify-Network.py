import argparse
import json
import sqlite3
from pathlib import Path


def verify(directory):
    with sqlite3.connect(directory / "capture.db") as database:
        rows = database.execute("SELECT sni,tls_name,cipher_name,group_name,state,"
                                "json_extract(crypto_json,'$.dtls_cookie_exchange') FROM connections").fetchall()
        sessions = database.execute("SELECT packets,observations,capture_lost,queue_lost,malformed,fragments,"
                                    "reassembly_limit,storage_lost FROM capture_sessions").fetchall()
        assert database.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    by_name = {row[0]: row for row in rows}
    assert set(by_name) == {"dtls1.network.lab", "dtls1_2.network.lab", "fragmented.ipv4.network.lab"}, by_name
    for name, version in [("dtls1.network.lab", "DTLS 1.0"), ("dtls1_2.network.lab", "DTLS 1.2")]:
        row = by_name[name]
        assert row[1] == version and row[2] and row[4] == "hellos_observed" and row[5], row
        assert "CONNECTION ESTABLISHED" in (directory / (name.split(".")[0] + ".client.err")).read_text()
    assert by_name["fragmented.ipv4.network.lab"][4] == "client_hello_only"
    assert all(session[index] == 0 for session in sessions for index in [2, 3, 4, 6, 7]), sessions
    assert sessions[0][5] >= 4, sessions
    result = {"real_dtls10": True, "real_dtls12": True, "ipv4_fragments_live": True,
              "zero_losses": True, "rows": rows, "sessions": sessions}
    (directory / "results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    verify(parser.parse_args().directory)
