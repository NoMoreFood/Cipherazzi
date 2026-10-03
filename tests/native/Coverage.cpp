#include "Engine.h"
#include "Storage.h"
#include <sqlite3.h>
#include <string_view>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);
int scalar(sqlite3* database, const char* sql);
std::vector<uint8_t> hello(bool client, uint16_t version, bool retry, bool ech, Bytes extensions);
std::vector<uint8_t> record(Bytes payload, uint8_t type);

void coverageExtensions()
{
    using Buffer = std::vector<uint8_t>;
    auto bytes = [](std::string_view text)
    {
        return Buffer(text.begin(), text.end());
    };
    auto word = [](Buffer& value, uint32_t number)
    {
        for (int shift : {24, 16, 8, 0}) value.push_back(static_cast<uint8_t>(number >> shift));
    };
    auto pg = [&](uint32_t code, Buffer payload = {})
    {
        Buffer value;
        word(value, static_cast<uint32_t>(payload.size() + 8));
        word(value, code);
        value.insert(value.end(), payload.begin(), payload.end());
        return value;
    };
    auto pgMessage = [&](char type, Buffer payload)
    {
        Buffer value{static_cast<uint8_t>(type)};
        word(value, static_cast<uint32_t>(payload.size() + 4));
        value.insert(value.end(), payload.begin(), payload.end());
        return value;
    };
    auto mysql = [](Buffer payload, uint8_t sequence)
    {
        Buffer value{static_cast<uint8_t>(payload.size()), static_cast<uint8_t>(payload.size() >> 8),
            static_cast<uint8_t>(payload.size() >> 16), sequence};
        value.insert(value.end(), payload.begin(), payload.end());
        return value;
    };
    auto mysqlHello = [&](size_t padding = 0)
    {
        auto value = bytes("\x0a" "8.4.0");
        value.insert(value.end(), padding, '0');
        value.push_back(0);
        value.insert(value.end(), 4 + 8 + 1, 0);
        value.insert(value.end(), {0, 0x8a, 0x21, 2, 0, 8, 0, 21});
        value.insert(value.end(), 10 + 13, 0);
        const auto plugin = bytes(std::string_view("caching_sha2_password\0", 22));
        value.insert(value.end(), plugin.begin(), plugin.end());
        return mysql(value, 0);
    };
    const auto clientHello = record(hello(true, 0x0304, false, false, {}), 22);
    const auto serverHello = record(hello(false, 0x0304, false, false, {}), 22);
    using Flight = std::pair<bool, Buffer>;
    auto exchange = [&](const std::vector<Flight>& flights, size_t chunk)
    {
        Counters counters;
        std::vector<Observation> observed;
        Engine engine(counters, [&](Observation row)
        {
            if (!row.lifecycleOnly) observed.push_back(std::move(row));
        });
        Endpoint client, server;
        client.address[0] = server.address[0] = 10;
        client.address[3] = 1;
        server.address[3] = 2;
        client.port = 41000;
        server.port = 8443;
        uint32_t sequences[]{1, 1001};
        engine.tcp({client, server, 0, 2, {}}, 1000);
        engine.tcp({server, client, 1000, 0x12, {}}, 1001);
        int64_t time = 1002;
        for (const auto& [outbound, payload] : flights)
            for (size_t offset = 0; offset < payload.size(); offset += chunk)
            {
                const auto part = Bytes(payload).subspan(offset, std::min(chunk, payload.size() - offset));
                auto& sequence = sequences[outbound ? 0 : 1];
                engine.tcp({outbound ? client : server, outbound ? server : client, sequence, 0x18, part}, time++);
                require(counters.malformed == 0 && counters.reassemblyLimit == 0,
                    ("Startup rejected packet: offset=" + std::to_string(offset) + "; client=" +
                        std::to_string(outbound) + "; bytes=" + std::to_string(part.size()) + "; prefix=" +
                        std::to_string(payload.front())).c_str());
                sequence += static_cast<uint32_t>(part.size());
            }
        engine.expire(time, true);
        require(counters.malformed == 0 && counters.reassemblyLimit == 0 && counters.bufferedBytes == 0,
            ("Startup exchange failed: malformed=" + std::to_string(counters.malformed.load()) +
                "; limited=" + std::to_string(counters.reassemblyLimit.load()) + "; bytes=" +
                std::to_string(counters.bufferedBytes.load()) + "; chunk=" + std::to_string(chunk) +
                "; first=" + std::to_string(flights.front().second.front())).c_str());
        require(!observed.empty(), "Startup exchange emitted no evidence");
        return observed.back();
    };

    // Proxy and database upgrades must preserve both TLS directions under arbitrary TCP segmentation.
    for (const auto chunk : {size_t{1}, size_t{7}, size_t{65536}})
    {
        for (const auto status : {"200 Connection Established", "201 Created"})
        {
            auto response = bytes(std::string("HTTP/1.1 ") + status + "\r\n\r\n");
            response.insert(response.end(), serverHello.begin(), serverHello.end());
            const auto row = exchange({{true, bytes("CONNECT target.test:443 HTTP/1.1\r\n\r\n")},
                {true, clientHello}, {false, response}}, chunk);
            require(row.clientHello && row.serverHello && row.cipher == 0x1301 && row.application &&
                row.application->fields.value("http_tunnel_established", false),
                "CONNECT discarded the tunnel's server hello");
        }
        const auto tls = exchange({{true, pg(80877103)}, {false, bytes("S")},
            {true, clientHello}, {false, serverHello}}, chunk);
        require(tls.serverHello && tls.application->fields.value("postgresql_tls_accepted", false),
            "PostgreSQL TLS upgrade lost negotiation evidence");
        const auto gss = exchange({{true, pg(80877104)}, {false, bytes("G")}}, chunk);
        require(gss.protocol == Observation::Protocol::PostgreSql &&
            gss.application->fields.value("postgresql_gss_encryption_accepted", false),
            "PostgreSQL GSSAPI acceptance was missed");
        auto request = Buffer(32, 0);
        request[1] = 0x0a;
        for (const size_t padding : {size_t{0}, size_t{57}})
        {
            const auto myTls = exchange({{false, mysqlHello(padding)}, {true, mysql(request, 1)},
                {true, clientHello}, {false, serverHello}}, chunk);
            require(myTls.serverHello && myTls.application->fields.value("mysql_tls_requested", false),
                "MySQL TLS upgrade lost negotiation evidence");
        }
    }

    // Authentication evidence contains the mechanism and outcome, never credentials or database names.
    Buffer cleartext;
    word(cleartext, 3);
    const auto plain = exchange({{true, pg(80877103)}, {false, bytes("N")},
        {true, pg(196608, bytes(std::string_view("user\0private-user\0\0", 19)))},
        {false, pgMessage('R', cleartext)}, {true, pgMessage('p', bytes(std::string_view("secret\0", 7)))},
        {false, pgMessage('R', Buffer(4, 0))}}, 1);
    const auto& fields = plain.application->fields;
    require(fields.value("postgresql_cleartext_password_observed", false) &&
        fields.value("postgresql_server_authentication_result", "") == "Accepted" &&
        fields.dump().find("secret") == std::string::npos && fields.dump().find("private-user") == std::string::npos,
        "PostgreSQL authentication was missed or retained credentials");

    Buffer mechanisms;
    word(mechanisms, 10);
    const auto scram = bytes(std::string_view("SCRAM-SHA-256\0\0", 15));
    mechanisms.insert(mechanisms.end(), scram.begin(), scram.end());
    auto initial = bytes(std::string_view("SCRAM-SHA-256\0", 14));
    word(initial, 6);
    const auto proof = bytes("secret");
    initial.insert(initial.end(), proof.begin(), proof.end());
    const auto sasl = exchange({{true, pg(196608, Buffer{0})}, {false, pgMessage('R', mechanisms)},
        {true, pgMessage('p', initial)}, {false, pgMessage('E', Buffer{0})}}, 1);
    require(sasl.application->fields.value("postgresql_sasl_selected", "") == "SCRAM-SHA-256" &&
        sasl.application->fields.value("postgresql_server_authentication_result", "") == "Rejected" &&
        sasl.application->fields.dump().find("secret") == std::string::npos,
        "PostgreSQL SASL negotiation retained proof bytes or lost the server outcome");
    const auto startupError = exchange({{true, pg(80877103)}, {false, pgMessage('E', Buffer{0})}}, 1);
    require(startupError.application->fields.value("postgresql_startup_rejected", false),
        "PostgreSQL rejected SSL startup was missed");

    // An ordinary 200 response and a rejected CONNECT must not turn HTTP response bodies into TLS evidence.
    auto body = bytes("HTTP/1.1 200 OK\r\n\r\n");
    body.insert(body.end(), serverHello.begin(), serverHello.end());
    const auto ordinary = exchange({{true, bytes("GET / HTTP/1.1\r\nAuthorization: Basic YTpi\r\n\r\n")},
        {false, body}}, 7);
    require(!ordinary.serverHello, "An HTTP body was interpreted as a tunnel");
    const auto rejected = exchange({{true, bytes("CONNECT target.test:443 HTTP/1.1\r\n\r\n")},
        {false, bytes("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")},
        {false, serverHello}}, 1);
    require(!rejected.serverHello && !rejected.application->fields.contains("http_tunnel_established"),
        "A rejected CONNECT response was interpreted as a tunnel");

    // HEAD responses can advertise a body length without consuming bytes from the following response.
    const auto head = exchange({{true, bytes("HEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n")},
        {false, bytes("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nHTTP/1.1 401 Unauthorized\r\n"
            "Content-Length: 0\r\nWWW-Authenticate: Basic\r\n\r\n")}}, 1);
    require(head.application->fields.value("http_basic_challenge_observed", false),
        "HEAD response framing swallowed the following authentication challenge");

    // MySQL authentication switches expose the mechanism without retaining the response or query text.
    auto login = Buffer(32, 0);
    login[1] = 0x82;
    login[2] = 8;
    const auto identity = bytes(std::string_view("private-user\0\x06secretcaching_sha2_password\0", 42));
    login.insert(login.end(), identity.begin(), identity.end());
    auto change = bytes(std::string_view("\xfe" "mysql_clear_password\0", 22));
    change.push_back(0);
    const auto mysqlPlain = exchange({{false, mysqlHello()}, {true, mysql(login, 1)},
        {false, mysql(change, 2)}, {true, mysql(bytes(std::string_view("secret\0", 7)), 3)},
        {false, mysql(Buffer{0, 0, 0, 2, 0, 0, 0}, 4)}, {true, mysql(bytes("\x03private-query"), 0)}}, 1);
    const auto mysqlFields = mysqlPlain.application->fields.dump();
    require(mysqlPlain.application->fields.value("mysql_cleartext_password_observed", false) &&
        mysqlPlain.application->fields.value("mysql_server_authentication_result", "") == "Accepted" &&
        mysqlFields.find("secret") == std::string::npos && mysqlFields.find("private-") == std::string::npos,
        "MySQL authentication was missed or retained application data");

    // Declared lengths must fail within the startup bound without allocating the declared payload.
    DatabaseNegotiation negotiation;
    negotiation.kind = DatabaseNegotiation::Kind::PostgreSql;
    negotiation.client = 0;
    DatabaseStream bounded(negotiation, 0);
    Buffer oversized;
    word(oversized, 0xffffffff);
    word(oversized, 196608);
    require(!bounded.feed(oversized, [](Bytes, const nlohmann::json&, bool) { return true; }) && bounded.limited() &&
        bounded.memory() < 1024, "Database startup trusted an oversized frame");

    // IPsec directions and SPIs remain distinct, while opaque payloads never imply known algorithms.
    auto ip = [](bool ipv6, uint8_t protocol, const Buffer& payload)
    {
        Buffer value(ipv6 ? 40 : 20, 0);
        value[0] = ipv6 ? 0x60 : 0x45;
        const auto length = payload.size() + (ipv6 ? 0 : 20);
        value[ipv6 ? 4 : 2] = static_cast<uint8_t>(length >> 8);
        value[ipv6 ? 5 : 3] = static_cast<uint8_t>(length);
        value[ipv6 ? 6 : 9] = protocol;
        value[ipv6 ? 7 : 8] = 64;
        value[ipv6 ? 23 : 15] = 1;
        value[ipv6 ? 39 : 19] = 2;
        value.insert(value.end(), payload.begin(), payload.end());
        return value;
    };
    Buffer esp;
    word(esp, 0x12345678);
    word(esp, 1);
    esp.insert(esp.end(), 32, 0xee);
    Buffer ah{59, 4, 0, 0};
    word(ah, 0x12345678);
    word(ah, 1);
    ah.insert(ah.end(), 12, 0xee);
    for (const bool ipv6 : {false, true})
    {
        Counters counters;
        std::vector<Observation> observed;
        Engine engine(counters, [&](Observation row)
        {
            if (!row.lifecycleOnly) observed.push_back(std::move(row));
        });
        for (const auto protocol : {uint8_t{50}, uint8_t{51}})
            engine.packet(ip(ipv6, protocol, protocol == 50 ? esp : ah), PacketKind::Ip, 1000);
        auto other = esp;
        other[3]++;
        engine.packet(ip(ipv6, 50, other), PacketKind::Ip, 1001);
        require(observed.size() == 3 && observed[0].flowId != observed[1].flowId &&
            observed[0].flowId != observed[2].flowId, "IPsec merged different protocols or SPIs");
        auto udp = Buffer{0x11, 0x94, 0x11, 0x94, 0, 48, 0, 0};
        udp.insert(udp.end(), esp.begin(), esp.end());
        engine.packet(ip(ipv6, 17, udp), PacketKind::Ip, 1002);
        require(observed.size() == 4 && observed.back().udp && observed.back().source.port == 4500,
            "NAT-T ESP was missed or merged with native ESP");
        udp.resize(9);
        udp[5] = 9;
        udp[8] = 0xff;
        engine.packet(ip(ipv6, 17, udp), PacketKind::Ip, 1003);
        require(observed.size() == 4, "A NAT keepalive became an ESP association");
        engine.expire(200000000, true);
        require(counters.malformed == 0 && counters.bufferedBytes == 0, "IPsec inspection leaked retained state");
        for (const auto& row : observed)
            require(row.protocol == Observation::Protocol::Ipsec && row.application &&
                !row.application->fields.contains("ipsec_cipher") && !row.clientHello && !row.serverHello,
                "An opaque IPsec header implied algorithms or TLS evidence");
        const auto before = counters.malformed.load();
        ah[1] = 255;
        require(!decodePacket(ip(ipv6, 51, ah), PacketKind::Ip, counters) && counters.malformed == before + 1,
            "Truncated AH was accepted");
        ah[1] = 4;
    }
    Counters limited;
    Engine capped(limited, [](Observation) {}, {1, 4096, 1000000});
    capped.packet(ip(false, 50, esp), PacketKind::Ip, 1000);
    esp[3]++;
    capped.packet(ip(false, 50, esp), PacketKind::Ip, 1001);
    require(limited.flowLimit == 1 && limited.bufferedBytes <= 4096, "IPsec bypassed shared flow limits");
    capped.expire(2000000, true);
    require(limited.bufferedBytes == 0, "IPsec expiration did not release memory");

    // Storage must not turn an IPsec association into a TCP socket during delayed process attribution.
    const auto path = std::filesystem::temp_directory_path() /
        ("cipherazzi-ipsec-" + std::to_string(nowUs()) + ".db");
    unsigned enriched{};
    {
        Storage storage(path, limited, "IPsec controls", "Packet evidence", [&](Observation&) { ++enriched; });
        Observation row;
        row.protocol = Observation::Protocol::Ipsec;
        row.flowId = 1;
        row.firstUs = row.lastUs = 1000000;
        auto evidence = std::make_shared<ProtocolEvidence>();
        evidence->fields = {{"ipsec_protocol", "ESP"}, {"ipsec_spi", 0x12345678}};
        row.application = evidence;
        storage.enqueue(row, true);
        storage.finish();
        require(enriched == 1, "IPsec entered delayed socket attribution");
        sqlite3* reader{};
        require(sqlite3_open_v2(utf8(path.wstring()).c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Could not read IPsec control storage");
        const auto count = scalar(reader, "SELECT count(*) FROM connections WHERE tls_name='IPsec' "
            "AND tls_version IS NULL AND cipher_id IS NULL AND json_extract(crypto_json,'$.transport')='ESP'");
        sqlite3_close(reader);
        require(count == 1, "Stored IPsec headers implied TLS selections or lost their transport");
    }
    std::filesystem::remove(path);
}
}
