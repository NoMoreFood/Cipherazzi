#include "Engine.h"
#include "Telemetry.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <sqlite3.h>
#include <windows.h>
#include <wincrypt.h>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);
int scalar(sqlite3* database, const char* sql);

void protocolCoverage()
{
    using Buffer = std::vector<uint8_t>;
    auto packet = [](Bytes bytes, uint32_t sequence, bool client, uint8_t flags = 0x18)
    {
        TcpPacket value;
        value.source.address[0] = value.destination.address[0] = 10;
        value.source.address[3] = client ? 1 : 2;
        value.destination.address[3] = client ? 2 : 1;
        value.source.port = client ? 42000 : 2222;
        value.destination.port = client ? 2222 : 42000;
        value.sequence = sequence;
        value.flags = flags;
        value.payload = bytes;
        return value;
    };
    auto framed = [](Buffer body)
    {
        size_t padding = 8 - (body.size() + 5) % 8;
        if (padding < 4)
            padding += 8;
        const auto length = static_cast<uint32_t>(body.size() + padding + 1);
        Buffer result{static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
            static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length), static_cast<uint8_t>(padding)};
        result.insert(result.end(), body.begin(), body.end());
        result.resize(result.size() + padding, 0x42);
        return result;
    };
    auto kex = [&](bool client, std::string cipher = "", std::string hostAlgorithm = "ssh-ed25519")
    {
        Buffer body(17, 0x42);
        body[0] = 20;
        const std::array<std::string, 10> names{"curve25519-sha256,ecdh-sha2-nistp256", hostAlgorithm,
            cipher.empty() ? client ? "aes128-ctr,aes256-ctr" : "aes256-ctr,aes128-ctr" : cipher,
            cipher.empty() ? client ? "aes128-ctr,aes256-ctr" : "aes256-ctr,aes128-ctr" : cipher,
            "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""};
        for (const auto& value : names)
        {
            const auto length = static_cast<uint32_t>(value.size());
            body.insert(body.end(), {static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
                static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)});
            body.insert(body.end(), value.begin(), value.end());
        }
        body.resize(body.size() + 5, 0);
        return framed(std::move(body));
    };
    const std::string banner = "SSH-2.0-TestEndpoint\r\n";
    auto sshString = [](Buffer& target, Bytes value)
    {
        const auto size = static_cast<uint32_t>(value.size());
        target.insert(target.end(), {static_cast<uint8_t>(size >> 24), static_cast<uint8_t>(size >> 16),
            static_cast<uint8_t>(size >> 8), static_cast<uint8_t>(size)});
        target.insert(target.end(), value.begin(), value.end());
    };
    const std::string hostType = "ssh-ed25519";
    const Bytes hostName(reinterpret_cast<const uint8_t*>(hostType.data()), hostType.size());
    Buffer hostKey;
    sshString(hostKey, hostName);
    sshString(hostKey, Buffer(32, 0x42));
    Buffer signature;
    sshString(signature, hostName);
    sshString(signature, Buffer(64, 0x24));
    Buffer reply{31};
    sshString(reply, hostKey);
    sshString(reply, Buffer(32, 0x18));
    sshString(reply, signature);
    const auto hostReply = framed(reply);
    auto transcript = [&](bool client)
    {
        Buffer bytes(banner.begin(), banner.end());
        const auto offers = kex(client);
        bytes.insert(bytes.end(), offers.begin(), offers.end());
        if (!client)
            bytes.insert(bytes.end(), hostReply.begin(), hostReply.end());
        const auto newKeys = framed({21});
        bytes.insert(bytes.end(), newKeys.begin(), newKeys.end());
        bytes.insert(bytes.end(), 64, 0xff);
        return bytes;
    };
    Counters counters;
    std::vector<Observation> observations;
    Engine engine(counters, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            observations.push_back(std::move(observation));
    });

    // Split banners and packets, reorder segments, and replay overlap before both directions activate keys.
    engine.tcp(packet({}, 1000, true, 2), 1);
    engine.tcp(packet({}, 9000, false, 0x12), 2);
    const auto client = transcript(true), server = transcript(false);
    engine.tcp(packet(Bytes(client).subspan(17), 1018, true), 3);
    engine.tcp(packet(Bytes(client).first(17), 1001, true), 4);
    engine.tcp(packet(client, 1001, true), 5);
    for (size_t offset = 0; offset < server.size(); ++offset)
        engine.tcp(packet(Bytes(server).subspan(offset, 1), static_cast<uint32_t>(9001 + offset), false),
            6 + static_cast<int64_t>(offset));
    engine.expire(1000000, true);
    require(!observations.empty() && observations.back().state == "ssh_newkeys_observed" &&
        observations.back().ssh->selected[2] == "aes128-ctr" && counters.malformed == 0 &&
        counters.bufferedBytes == 0, "SSH selection, reassembly, or encrypted-data boundary failed");
    require(!observations.front().ssh->peers[1].kexInit,
        "A queued SSH observation changed after its later negotiation was received");
    CryptoCatalog catalog;
    const auto summary = catalog.summarize(observations.back(), [](const auto&, const auto&, Bytes) {});
    require(summary.encryption == "AES_128" && summary.keyBits == 128 &&
        summary.exchange == "curve25519-sha256", "SSH selections were not summarized independently of TLS");
    const auto sshEvidence = nlohmann::json::parse(summary.json);
    require(sshEvidence.value("ssh_host_key_sha256", "") == sha256(hostKey) &&
        sshEvidence.value("ssh_host_key_type", "") == "ssh-ed25519" &&
        sshEvidence.value("ssh_host_key_bits", 0) == 256 &&
        sshEvidence.value("ssh_exchange_signature", "") == "ssh-ed25519" &&
        sshEvidence.value("ssh_host_key_trust", "") == "Not verified",
        "Visible SSH host key evidence was missing or implied trust");

    // OpenSSH-generated certificates retain the certified key fingerprint across certificate serialization.
    std::ifstream certificateInput(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "ssh-certificates.json");
    const auto certificateFixtures = nlohmann::json::parse(certificateInput);
    auto decode = [](const std::string& encoded)
    {
        DWORD size = 0;
        require(CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()), CRYPT_STRING_BASE64,
            nullptr, &size, nullptr, nullptr) != FALSE, "SSH certificate fixture encoding is invalid");
        Buffer result(size);
        require(CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()), CRYPT_STRING_BASE64,
            result.data(), &size, nullptr, nullptr) != FALSE, "SSH certificate fixture could not decode");
        result.resize(size);
        return result;
    };
    for (const auto& certificateFixture : certificateFixtures)
    {
        const auto certificate = decode(certificateFixture["certificate"]);
        const auto publicKey = decode(certificateFixture["public_key"]);
        const std::string negotiated = certificateFixture["negotiated"],
            signatureName = certificateFixture["signature"];
        auto inspectKey = [&](Bytes key, const std::string& signatureType, bool fragmented)
        {
            Observation result;
            result.ssh = std::make_shared<Observation::Ssh>();
            result.ssh->rolesKnown = true;
            SshStream clientParser, serverParser;
            Buffer clientOffer(banner.begin(), banner.end()), serverOffer = clientOffer;
            const auto algorithms = kex(true, "", negotiated);
            clientOffer.insert(clientOffer.end(), algorithms.begin(), algorithms.end());
            serverOffer.insert(serverOffer.end(), algorithms.begin(), algorithms.end());
            require(clientParser.feed(clientOffer, [&](const SshMessage& message) { applySsh(result, 0, message); }) &&
                serverParser.feed(serverOffer, [&](const SshMessage& message) { applySsh(result, 1, message); }),
                "SSH certificate algorithm offers were rejected");
            Buffer signedExchange;
            sshString(signedExchange, Bytes(reinterpret_cast<const uint8_t*>(signatureType.data()),
                signatureType.size()));
            sshString(signedExchange, Buffer(64, 0x24));
            Buffer exchange{31};
            sshString(exchange, key);
            sshString(exchange, Buffer(32, 0x18));
            sshString(exchange, signedExchange);
            const auto frame = framed(exchange);
            for (size_t offset = 0; offset < frame.size();)
            {
                const auto count = fragmented ? size_t{1} : frame.size();
                require(serverParser.feed(Bytes(frame).subspan(offset, count),
                    [&](const SshMessage& message) { applySsh(result, 1, message); }),
                    "A fragmented SSH certificate reply was rejected");
                offset += count;
            }
            return result;
        };
        const auto certified = inspectKey(certificate, signatureName, true);
        const auto evidence = nlohmann::json::parse(catalog.summarize(certified,
            [](const auto&, const auto&, Bytes) {}).json);
        require(certified.ssh->hostKeyType == certificateFixture["key_type"].get<std::string>() &&
            certified.ssh->hostKeyBits == certificateFixture["bits"].get<int>() &&
            certified.ssh->hostKeySha256 == certificateFixture["key_sha256"].get<std::string>() &&
            certified.ssh->hostKeySha256 == sha256(publicKey) && evidence.contains("ssh_host_certificate"),
            "An OpenSSH certificate lost its certified key, size, or OpenSSH fingerprint");
        const auto& details = evidence["ssh_host_certificate"];
        require(details["serial"] == 42 && details["type"] == "Host" &&
            details["key_id"] == "cipherazzi-test-host" && details["principals"] ==
            nlohmann::json::array({"service.example.test", "alias.example.test"}) &&
            details["valid_after"] == 1577836800ULL && details["valid_before"] == 1893456000ULL &&
            details["authority_key_type"] == "ssh-ed25519" && details["signature_algorithm"] == "ssh-ed25519" &&
            details["sha256"] == sha256(certificate) && details["trust"] == "Not verified",
            "SSH certificate identity or CA evidence was lost or implied trust");
        require(inspectKey(certificate, negotiated, false).ssh->hostKeySha256.empty(),
            "A certificate algorithm name was accepted as an exchange signature algorithm");
        for (size_t length = 0; length < certificate.size(); ++length)
            require(inspectKey(Bytes(certificate).first(length), signatureName, false).ssh->hostKeySha256.empty(),
                "A truncated SSH certificate established host-key evidence");
    }

    // Client-only fixtures preserve offers without asserting a selected cipher or completed exchange.
    SshStream partial;
    Observation offered;
    const auto fixture = transcript(true);
    partial.feed(fixture, [&](const SshMessage& message) { applySsh(offered, 0, message); });
    require(offered.ssh->peers[0].kexInit && offered.ssh->selected[0].empty(),
        "One-sided SSH offers were reported as a negotiation");
    SshStream malformed;
    bool accepted = malformed.feed(Bytes(reinterpret_cast<const uint8_t*>(banner.data()), banner.size()),
        [](const SshMessage&) {});
    accepted &= malformed.feed(Buffer{0xff, 0xff, 0xff, 0xff, 8}, [](const SshMessage&) {});
    require(!accepted, "An oversized SSH packet length was accepted");

    // A midstream capture can retain both offers without establishing which peer was the client.
    Counters midstreamHealth;
    std::vector<Observation> midstream;
    Engine midstreamEngine(midstreamHealth, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            midstream.push_back(std::move(observation));
    });
    midstreamEngine.tcp(packet(client, 1001, true), 1);
    midstreamEngine.tcp(packet(server, 9001, false), 2);
    midstreamEngine.expire(1000000, true);
    require(!midstream.empty() && !midstream.back().ssh->rolesKnown &&
        midstream.back().ssh->selected[0].empty(), "Midstream SSH offers established an unsupported selection");
    require(midstream.back().ssh->hostKeySha256.empty(), "Unknown SSH roles established a server host key");

    // Unknown payload classification requires enough unique reassembled bytes and stays explicitly uncertain.
    Buffer binary(8192), plaintext(8192, 'A'), gzip(8192);
    for (size_t index = 0; index < binary.size(); ++index)
        binary[index] = gzip[index] = static_cast<uint8_t>(index);
    gzip[0] = 0x1f;
    gzip[1] = 0x8b;
    auto classify = [&](const Buffer& payload, bool enabled, bool retransmit = false)
    {
        Counters health;
        std::vector<Observation> output;
        Engine sample(health, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                output.push_back(std::move(observation));
        }, {.raw = enabled});
        sample.tcp(packet({}, 1000, true, 2), 1);
        sample.tcp(packet(payload, 1001, true), 2);
        if (retransmit)
            for (int repeat = 0; repeat < 20; ++repeat)
                sample.tcp(packet(payload, 1001, true), repeat + 3);
        sample.expire(1000000, true);
        require(health.bufferedBytes == 0, "Unknown TCP sample memory was retained after expiration");
        return output;
    };
    require(classify(binary, false).empty() && classify(plaintext, true).empty() &&
        classify(gzip, true).empty() && classify(Buffer(binary.begin(), binary.begin() + 512), true, true).empty(),
        "Disabled, plaintext, compressed, or retransmitted short samples produced an encryption claim");
    const auto raw = classify(binary, true);
    require(raw.size() == 1 && raw[0].state == "possible_encryption" && raw[0].raw.sampleBytes == 8192 &&
        raw[0].version == 0 && raw[0].cipher == 0 &&
        catalog.summarize(raw[0], [](const auto&, const auto&, Bytes) {}).encryption.empty(),
        "Unknown traffic was assigned a cipher or omitted its bounded statistical evidence");

    // UDP uses the same sample bounds without being mistaken for a TLS or QUIC handshake.
    Buffer udp(28, 0);
    udp[0] = 0x45;
    udp[2] = 0x20;
    udp[3] = 28;
    udp[9] = 17;
    udp[12] = udp[16] = 10;
    udp[15] = 1;
    udp[19] = 2;
    udp[20] = 0xa4;
    udp[21] = 0x10;
    udp[22] = 0x56;
    udp[23] = 0xce;
    udp[24] = 0x20;
    udp[25] = 8;
    udp.insert(udp.end(), binary.begin(), binary.end());
    Counters udpHealth;
    std::vector<Observation> datagrams;
    Engine datagram(udpHealth, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            datagrams.push_back(std::move(observation));
    }, {.raw = true});
    datagram.packet(udp, PacketKind::Ip, 1);
    datagram.expire(1000000, true);
    require(datagrams.size() == 1 && datagrams[0].udp && datagrams[0].raw.sampleBytes == 8192 &&
        udpHealth.bufferedBytes == 0 && udpHealth.activeFlows == 0, "Unknown UDP sampling or expiration failed");
    Counters limitedHealth;
    Engine limited(limitedHealth, [](Observation) {}, {.bytes = 1, .raw = true});
    limited.packet(udp, PacketKind::Ip, 1);
    require(limitedHealth.reassemblyLimit == 1 && limitedHealth.flowLimit == 0 &&
        limitedHealth.bufferedBytes == 0, "UDP samples escaped their memory budget or misreported the limit");

    // Raw endpoint evidence must match a captured socket and process instance without supplying private material.
    const auto base = std::filesystem::temp_directory_path() /
        ("cipherazzi-raw-report-" + std::to_string(GetCurrentProcessId()));
    const auto database = base.string() + ".db", reportPath = base.string() + ".json";
    std::filesystem::remove(database);
    const auto timestamp = nowUs();
    auto captured = raw[0];
    captured.firstUs = captured.lastUs = timestamp;
    nlohmann::json report{{"schema", "cipherazzi.raw/1"}, {"provider", "Raw operation control"},
        {"pid", 4242}, {"process_started_us", timestamp - 1000000}, {"operation_started_us", timestamp},
        {"timestamp_us", timestamp + 1000}, {"role", "client"}, {"transport", "TCP"}, {"success", true},
        {"algorithm", "AES"}, {"mode", "GCM"}, {"key_bits", 256},
        {"local", {{"address", captured.source.text()}, {"port", captured.source.port}}},
        {"remote", {{"address", captured.destination.text()}, {"port", captured.destination.port}}}};
    Counters storageHealth;
    {
        Storage storage(database, storageHealth, "Raw endpoint controls", "Controlled process lifetime",
            [&](Observation& observation)
        {
            observation.sourceOwner.pid = 4242;
            observation.sourceOwner.startedUs = timestamp - 1000000;
        });
        storage.enqueue(captured);
        for (int control = 0; control < 4; ++control)
        {
            auto value = report;
            if (control == 1)
                value["pid"] = 4343;
            else if (control == 2)
                value["process_started_us"] = timestamp - 500000;
            else if (control == 3)
                value["role"] = "server";
            { std::ofstream output(reportPath); output << value; }
            require(Telemetry::importEndpoint(reportPath, storage) == 1, "A public raw report was not ingested");
        }
        report["key"] = "private-material-must-be-rejected";
        { std::ofstream output(reportPath); output << report; }
        bool rejected = false;
        try { Telemetry::importEndpoint(reportPath, storage); }
        catch (const std::exception&) { rejected = true; }
        require(rejected, "A raw encryption report accepted nonpublic key material");
        storage.finish();
        sqlite3* reader = nullptr;
        require(sqlite3_open_v2(database.c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "The raw endpoint reader could not open");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE cipher_id IS NULL AND encryption='' AND "
            "json_extract(crypto_json,'$.endpoint_confirmations[0].algorithm')='AES' AND "
            "json_array_length(crypto_json,'$.endpoint_confirmations')=2 AND "
            "json_extract(crypto_json,'$.handshake_confirmation')='Endpoint reported encryption'") == 1 &&
            scalar(reader, "SELECT count(*) FROM endpoint_events WHERE "
                "json_extract(detail_json,'$.correlation') LIKE 'Unmatched%'") == 2,
            "Raw endpoint evidence was inferred from packets or crossed process identities");
        sqlite3_close(reader);
    }
    std::filesystem::remove(reportPath);
    std::filesystem::remove(database);
}
}
