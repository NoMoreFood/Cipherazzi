#include "Telemetry.h"
#include <filesystem>
#include <fstream>
#include <sqlite3.h>
#include <windows.h>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);
int scalar(sqlite3* database, const char* sql);

void endpointIntegration(const std::filesystem::path& output)
{
    const auto path = output.empty() ? std::filesystem::temp_directory_path() /
        ("cipherazzi-provider-" + std::to_string(GetCurrentProcessId()) + ".db") : output;
    require(!std::filesystem::exists(path), "Endpoint integration requires a new journal");
    const auto fixture = path.parent_path() / (path.filename().string() + ".json");
    Counters counters;
    {
        Storage storage(path, counters, "Endpoint integration", "fixture ownership");
        Observation observation;
        observation.flowId = 1;
        observation.firstUs = 1700000000000000;
        observation.lastUs = 1700000000100000;
        observation.source = {{10,20,0,1},52000,4};
        observation.destination = {{10,20,0,2},443,4};
        observation.sourceOwner = {4242,1699999000000000,"java.exe","C:\\Java\\java.exe","fixture identity"};
        observation.sni = "endpoint.cipherazzi.test";
        observation.clientHello = observation.serverHello = true;
        observation.version = 772;
        observation.cipher = 4866;
        observation.crypto.groupId = 4588;
        storage.enqueue(observation, true);

        // Exercise the actual JFR importer, including exported process identity and named cipher conversion.
        {
            std::ofstream file(fixture);
            file << nlohmann::json{
                {"pid",4242}, {"process_started_us",1699999000000000}, {"process_name","java.exe"},
                {"process_path","C:\\Java\\java.exe"}, {"recording",{{"events",nlohmann::json::array({
                    {{"type","jdk.TLSHandshake"}, {"values",{
                        {"startTime","2023-11-14T22:13:20.100000Z"}, {"peerHost","endpoint.cipherazzi.test"},
                        {"peerPort",443}, {"protocolVersion","TLSv1.3"}, {"cipherSuite","TLS_AES_256_GCM_SHA384"}}}}
                })}}}
            }.dump();
        }
        require(Telemetry::importJava(fixture, storage) == 1, "JFR handshake did not import");
        EndpointEvent windows;
        windows.id = "provider-windows";
        windows.pid = 4242;
        windows.timestampUs = 1700000000100000;
        windows.provider = "Schannel";
        windows.kind = "Event 36880";
        windows.result = "Endpoint confirmed handshake completion";
        windows.detail = R"({"fields":{"Type":"client","Protocol":"TLS 1.3","CipherSuite":4866,
            "TargetName":"endpoint.cipherazzi.test"}})";
        Telemetry::normalizeProvider(windows, observation.sourceOwner);
        storage.enqueue(windows, true);
        sqlite3* raw = nullptr;
        require(sqlite3_open_v2(utf8(path.wstring()).c_str(), &raw, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Could not open endpoint integration reader");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> reader(raw, sqlite3_close);
        auto await = [&](const char* sql)
        {
            const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!scalar(reader.get(), sql) && std::chrono::steady_clock::now() < until)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            require(scalar(reader.get(), sql) != 0, "Provider integration did not publish the expected evidence");
        };
        await("SELECT count(*) FROM connections WHERE json_array_length(crypto_json,'$.endpoint_confirmations')=2");
        require(scalar(reader.get(), "SELECT count(*) FROM connections WHERE "
            "json_extract(crypto_json,'$.endpoint_confirmations[0].peer_verified')=-1") == 1,
            "Provider completion was incorrectly treated as peer verification");

        // A second compatible exchange retracts provider associations instead of guessing a socket.
        observation.flowId = 2;
        storage.enqueue(observation, true);
        await("SELECT count(*)=2 FROM endpoint_events WHERE "
            "json_extract(detail_json,'$.correlation') LIKE 'Ambiguous%'");
        require(scalar(reader.get(), "SELECT count(*) FROM connections WHERE "
            "json_extract(crypto_json,'$.handshake_confirmation')='Endpoint confirmed completion'") == 0,
            "An ambiguous provider event continued confirming a packet connection");

        // A DTLS application report matches UDP evidence using the normalized TLS policy level.
        std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "endpoint-pq.json");
        auto report = nlohmann::json::parse(input);
        report["transport"] = "DTLS";
        report["tls_version"] = 0xfefd;
        report["group_id"] = 23;
        report["process_name"] = "java.exe";
        report["process_path"] = "C:\\Java\\java.exe";
        { std::ofstream file(fixture); file << report.dump(); }
        observation.flowId = 3;
        observation.version = 771;
        observation.dtlsVersion = 0xfefd;
        observation.udp = true;
        observation.crypto.groupId = 23;
        storage.enqueue(observation, true);
        require(Telemetry::importEndpoint(fixture, storage) == 1, "DTLS endpoint report did not import");
        await("SELECT count(*) FROM connections WHERE tls_name='DTLS 1.2' AND "
            "json_extract(crypto_json,'$.handshake_confirmation')='Endpoint confirmed completion'");
        report["success"] = false;
        report["tls_version"] = 0;
        report["cipher_id"] = 0;
        report["group_id"] = -1;
        { std::ofstream file(fixture); file << report.dump(); }
        require(Telemetry::importEndpoint(fixture, storage) == 1, "DTLS failure report did not import");
        await("SELECT count(*) FROM connections WHERE tls_name='DTLS 1.2' AND "
            "json_extract(crypto_json,'$.handshake_confirmation')='Conflicting endpoint outcomes'");

        // Same-host and identity-poor provider evidence remains independently assessable.
        report["transport"] = "TCP";
        report["success"] = true;
        report["tls_version"] = 772;
        report["cipher_id"] = 4866;
        report["group_id"] = 4588;
        report["local"]["address"] = "127.0.0.1";
        report["remote"]["address"] = "127.0.0.1";
        { std::ofstream file(fixture); file << report.dump(); }
        require(Telemetry::importEndpoint(fixture, storage) == 1, "Loopback report did not import");

        // Missing QUIC identity remains independent even beside one otherwise-compatible packet connection.
        report["transport"] = "QUIC";
        report["local"]["address"] = "10.20.0.1";
        report["remote"]["address"] = "10.20.0.2";
        report.erase("quic_original_dcid");
        observation.flowId = 4;
        observation.quic = true;
        observation.udp = false;
        observation.dtlsVersion = 0;
        observation.version = 772;
        observation.cipher = 4866;
        observation.crypto.groupId = 4588;
        storage.enqueue(observation, true);
        { std::ofstream file(fixture); file << report.dump(); }
        require(Telemetry::importEndpoint(fixture, storage) == 1, "QUIC evidence without a connection ID was lost");
        report["local"]["address"] = "0.0.0.0";
        report["quic_original_dcid"] = "0102030405060708";
        { std::ofstream file(fixture); file << report.dump(); }
        require(Telemetry::importEndpoint(fixture, storage) == 1, "Wildcard QUIC binding evidence was lost");

        // Failed application evidence and TLS over an unidentified transport retain independent assessments.
        report.erase("local");
        report.erase("remote");
        report.erase("quic_original_dcid");
        report["transport"] = "Unknown";
        report["role"] = "unknown";
        report["process_scope"] = "application";
        report["success"] = false;
        report["peer_verified"] = false;
        report["error_code"] = -12276;
        report["error_name"] = "SSL_ERROR_BAD_CERT_DOMAIN";
        for (const auto* field : {"tls_version", "cipher_id", "group_id", "signature_scheme"}) report.erase(field);
        { std::ofstream file(fixture); file << report.dump(); }
        require(Telemetry::importEndpoint(fixture, storage) == 1, "Failed application evidence was lost");
        report["process_scope"] = "endpoint";
        report["role"] = "client";
        report["success"] = true;
        report["peer_verified"] = true;
        report["tls_version"] = 772;
        report["cipher_id"] = 4866;
        report["group_id"] = 4588;
        report.erase("error_code");
        report.erase("error_name");
        { std::ofstream file(fixture); file << report.dump(); }
        require(Telemetry::importEndpoint(fixture, storage) == 1, "TLS evidence without socket identity was lost");

        // A reported connection role does not identify the application's TLS socket process.
        report["process_scope"] = "application";
        report["transport"] = "TCP";
        report["local"] = {{"address", "10.20.0.1"}, {"port", 52000}};
        report["remote"] = {{"address", "10.20.0.2"}, {"port", 443}};
        { std::ofstream file(fixture); file << report.dump(); }
        require(Telemetry::importEndpoint(fixture, storage) == 1, "Application-reported TLS completion was lost");
        windows.id = "provider-no-peer";
        windows.detail = "{}";
        Telemetry::normalizeProvider(windows, observation.sourceOwner);
        storage.enqueue(windows, true);
        EndpointEvent diagnostic;
        diagnostic.id = "capi-diagnostic";
        diagnostic.provider = "Microsoft-Windows-CAPI2";
        diagnostic.kind = "Event 11";
        diagnostic.detail = "{}";
        Telemetry::normalizeProvider(diagnostic, observation.sourceOwner);
        storage.enqueue(diagnostic, true);
        storage.finish();
        require(scalar(reader.get(), "SELECT count(*) FROM endpoint_events WHERE "
            "json_extract(detail_json,'$.assessment') IS NOT NULL") == 11,
            "Normalized endpoint evidence or its independent assessment was lost");
        require(scalar(reader.get(), "SELECT count(*) FROM endpoint_events WHERE "
            "json_extract(detail_json,'$.matched_flow_id') IS NOT NULL") == 2,
            "Missing socket evidence acquired a packet association");
        require(scalar(reader.get(), "SELECT count(*) FROM endpoint_events WHERE "
            "json_extract(detail_json,'$.correlation') LIKE 'QUIC source address%' AND "
            "json_extract(detail_json,'$.matched_flow_id') IS NULL") == 2,
            "QUIC evidence without complete identity acquired a packet association");
        require(scalar(reader.get(), "SELECT count(*) FROM endpoint_events WHERE "
            "json_extract(detail_json,'$.local_address')='' AND "
            "json_extract(detail_json,'$.local_binding_address')='0.0.0.0'") == 1,
            "A wildcard QUIC binding was presented as a concrete source address");
        require(scalar(reader.get(), "SELECT count(*) FROM endpoint_events WHERE "
            "json_extract(detail_json,'$.transport')='Unknown' AND "
            "json_extract(detail_json,'$.assessment.crypto.transport')='Unknown' AND "
            "json_extract(detail_json,'$.remote_address')='' AND "
            "json_extract(detail_json,'$.local_address')='' AND "
            "json_extract(detail_json,'$.matched_flow_id') IS NULL") == 2,
            "Unknown socket evidence acquired a transport, address, or packet association");
        require(scalar(reader.get(), "SELECT count(*) FROM endpoint_events WHERE "
            "json_extract(detail_json,'$.error_name')='SSL_ERROR_BAD_CERT_DOMAIN' AND "
            "cipher='' AND protocol='TLS' AND "
            "json_extract(detail_json,'$.assessment.local_role')='Unknown' AND "
            "json_extract(detail_json,'$.assessment.crypto.endpoint_confirmations[0].success')=0") == 1,
            "Application-level failure acquired a socket process role or lost its public error");
        require(scalar(reader.get(), "SELECT count(*) FROM endpoint_events WHERE "
            "json_extract(detail_json,'$.process_scope')='application' AND "
            "json_extract(detail_json,'$.role')='client' AND "
            "json_extract(detail_json,'$.process_role')='unknown' AND "
            "json_extract(detail_json,'$.assessment.local_role')='Unknown' AND "
            "json_extract(detail_json,'$.assessment.crypto.endpoint_confirmations[0].local_role')='Client' AND "
            "json_extract(detail_json,'$.matched_flow_id') IS NULL") == 1,
            "A TLS connection role became an asserted socket process role or packet match");
    }
    require(counters.telemetryLost == 0 && counters.storageLost == 0, "Provider integration lost evidence");
    std::filesystem::remove(fixture);
    if (output.empty())
        std::filesystem::remove(path);
}
}
