import argparse
import base64
import json
import ipaddress
import sqlite3
import ssl
from pathlib import Path

from Integration import exchange, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--java", required=True)
    parser.add_argument("--openssl", default="C:/msys64/usr/bin/openssl.exe")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    work = Path(args.output).resolve()
    directory = work / "reports"
    directory.mkdir(parents=True)
    run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(work / "key.pem"),
         "-out", str(work / "cert.pem"), "-days", "1", "-subj", "/CN=adapter.lab"])
    run(["dotnet", "build", str(root / "tests/clients/SchannelClient.csproj"), "-c", "Release"])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(work / "cert.pem", work / "key.pem")
    context.set_alpn_protocols(["h2", "http/1.1"])
    der = ssl.PEM_cert_to_DER_cert((work / "cert.pem").read_text())
    expected = []

    # Export results from live Schannel and Java handshakes using each stack's public session API.
    for stack in ("schannel", "java"):
        for version in ("TLSv1.2", "TLSv1.3"):
            client = ["dotnet", str(root / "tests/clients/bin/Release/net10.0-windows/SchannelClient.dll")] \
                if stack == "schannel" else [args.java, str(root / "tests/clients/JavaClient.java")]
            before = set(directory.glob("*.json"))
            _, negotiated = exchange(context, lambda port: client +
                [str(port), version, "adapter.lab", "127.0.0.1", str(directory)], 54000 + len(expected))
            generated = set(directory.glob("*.json")) - before
            assert len(generated) == 1, (stack, version)
            report = json.loads(generated.pop().read_text())
            assert report["success"] and report["peer_verified"] is False
            assert report["tls_version"] == (771 if version == "TLSv1.2" else 772)
            assert report["selected_alpn"] == "h2"
            assert report["process_started_us"] <= report["handshake_started_us"] <= report["timestamp_us"]
            for endpoint in (report["local"], report["remote"]):
                address = ipaddress.ip_address(endpoint["address"])
                assert str(getattr(address, "ipv4_mapped", None) or address) == "127.0.0.1"
            assert base64.b64decode(report["server_certificates_der"][0]) == der
            expected.append(dict(stack=stack, version=version, provider=report["provider"],
                                 pid=report["pid"], negotiated=negotiated))
    tool = root / "build/bin/Release/Cipherazzi.Tests.exe"
    database = work / "endpoint.db"
    run([str(tool), "--import-endpoints", str(directory), str(database)])
    connection = sqlite3.connect(database)
    events = connection.execute("SELECT detail_json FROM endpoint_events").fetchall()
    assert len(events) == 4 and connection.execute("SELECT count(*) FROM certificates").fetchone()[0] == 1
    assert connection.execute("SELECT der FROM certificates").fetchone()[0] == der
    assert all(json.loads(value[0])["correlation"].startswith("Unmatched socket") for value in events)
    assert all(json.loads(value[0])["local_address"] == "127.0.0.1" for value in events)
    (work / "results.json").write_text(json.dumps(dict(cases=expected, public_der_roundtrip=True,
        native_report_import=True, unobserved_sockets_not_confirmed=True), indent=2))
    print("Schannel and Java endpoint adapters passed TLS 1.2/1.3 public-result and native import checks.")


if __name__ == "__main__":
    main()
