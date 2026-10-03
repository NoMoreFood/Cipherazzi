#include "Engine.h"

#include <string_view>
#include <string>
#include <tuple>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);
std::vector<uint8_t> hello(bool client, uint16_t version, bool retry, bool ech, Bytes extensions);
std::vector<uint8_t> record(Bytes payload, uint8_t type);

void cleartextCoverage()
{
    auto bytes = [](std::string_view text)
    {
        return Bytes(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    };
    auto feed = [&](FramedStream& parser, std::string_view text, nlohmann::json& fields)
    {
        return parser.feed(bytes(text), [&](const FramedMessage& message)
        {
            fields.update(message.fields);
            return true;
        });
    };

    // HTTP credentials can appear after an unauthenticated request on the same connection.
    FramedStream http;
    nlohmann::json fields = nlohmann::json::object();
    require(feed(http, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\nGET / HTTP/1.1\r\n", fields) &&
        feed(http, "Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n", fields) &&
        fields.value("http_basic_auth_observed", false) &&
        fields.dump().find("alice") == std::string::npos && fields.dump().find("secret") == std::string::npos,
        "HTTP Basic authentication was missed or retained credentials");
    require(feed(http, "GET / HTTP/1.1\r\nAuthorization: NTLM VG9rZW4=\r\n"
        "Proxy-Authorization: Negotiate VG9rZW4=\r\n\r\n", fields) &&
        fields.value("http_ntlm_auth_observed", false) &&
        fields.value("http_negotiate_auth_observed", false) && fields.value("http_proxy_auth_observed", false),
        "HTTP NTLM or Negotiate authorization was missed");
    FramedStream unpadded;
    nlohmann::json unpaddedFields = nlohmann::json::object();
    require(feed(unpadded, "GET / HTTP/1.1\r\nAuthorization: Basic YWxpY2U6cA\r\n\r\n",
        unpaddedFields) && unpaddedFields.value("http_basic_auth_observed", false),
        "HTTP Basic authentication with an unpadded token was missed");

    // Authentication fields must appear on the side of the exchange defined by HTTP.
    FramedStream wrongRequest, wrongResponse;
    nlohmann::json wrongRequestFields = nlohmann::json::object();
    nlohmann::json wrongResponseFields = nlohmann::json::object();
    require(feed(wrongRequest, "GET / HTTP/1.1\r\nWWW-Authenticate: Basic realm=\"test\"\r\n"
        "Proxy-Authenticate: Negotiate\r\n\r\n", wrongRequestFields) &&
        !wrongRequestFields.contains("http_basic_challenge_observed") &&
        !wrongRequestFields.contains("http_negotiate_challenge_observed") &&
        !wrongRequestFields.contains("http_proxy_auth_observed"),
        "HTTP request headers were treated as server challenges");
    require(feed(wrongResponse, "HTTP/1.1 204 No Content\r\n"
        "Authorization: Basic YWxpY2U6c2VjcmV0\r\n"
        "Proxy-Authorization: NTLM VG9rZW4=\r\n\r\n", wrongResponseFields) &&
        !wrongResponseFields.contains("http_basic_auth_observed") &&
        !wrongResponseFields.contains("http_ntlm_auth_observed") &&
        !wrongResponseFields.contains("http_proxy_auth_observed"),
        "HTTP response headers were treated as client credentials");

    // Large request bodies are discarded incrementally so later authentication remains visible.
    FramedStream largeBody;
    nlohmann::json largeBodyFields = nlohmann::json::object();
    require(feed(largeBody, "POST /upload HTTP/1.1\r\nContent-Length: 262145\r\n\r\n", largeBodyFields),
        "HTTP rejected a valid large content length");
    const std::string body(262145, 'x');
    for (size_t offset = 0; offset < body.size(); offset += 4096)
        require(feed(largeBody, std::string_view(body).substr(offset, 4096), largeBodyFields),
            "HTTP stopped while skipping a large body");
    require(feed(largeBody, "GET / HTTP/1.1\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n",
        largeBodyFields) && largeBodyFields.value("http_basic_auth_observed", false),
        "HTTP missed authentication after a large body");

    // Chunked responses must not swallow a later authentication header on a persistent stream.
    FramedStream response;
    nlohmann::json responseFields = nlohmann::json::object();
    require(feed(response, "HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n"
        "WWW-Authenticate: Basic realm=\"test\"\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n",
        responseFields) && responseFields.value("http_basic_challenge_observed", false) &&
        responseFields.value("http_negotiate_challenge_observed", false),
        "HTTP challenge parsing lost a message after chunked framing");

    // Login commands are classified by protocol; account names and passwords never enter JSON evidence.
    for (const auto [port, command, expected] :
        {std::tuple<uint16_t, std::string_view, const char*>{uint16_t{21}, "USER alice\r\nPASS secret\r\n",
            "ftp_plaintext_password_observed"},
        {uint16_t{110}, "USER alice\r\nPASS secret\r\n", "pop3_plaintext_password_observed"},
        {uint16_t{143}, "A1 LOGIN \"Alice Smith\" \"secret\"\r\n", "imap_plaintext_login_observed"},
        {uint16_t{25}, "EHLO client\r\nAUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n", "smtp_auth_plain_observed"}})
    {
        FramedStream parser;
        parser.configurePort(port);
        nlohmann::json result = nlohmann::json::object();
        require(feed(parser, command, result) && result.value(expected, false) &&
            result.dump().find("alice") == std::string::npos &&
            result.dump().find("secret") == std::string::npos,
            ("A cleartext mail or FTP login was missed or retained credentials on port " +
                std::to_string(port)).c_str());
    }
    FramedStream smtp;
    smtp.configurePort(587);
    nlohmann::json smtpFields = nlohmann::json::object();
    require(feed(smtp, "AUTH LOGIN\r\nYWxpY2U=\r\nc2VjcmV0\r\n", smtpFields) &&
        smtpFields.value("smtp_auth_login_observed", false), "SMTP AUTH LOGIN challenge sequence was missed");

    // Framing evidence reaches the observation with its protocol and state.
    Counters counters;
    std::vector<Observation> observations;
    Engine engine(counters, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            observations.push_back(std::move(observation));
    });
    TransportPacket packet;
    packet.source.address[0] = packet.destination.address[0] = 10;
    packet.source.address[3] = 1;
    packet.destination.address[3] = 2;
    packet.source.port = 41000;
    packet.destination.port = 80;
    const auto request = bytes("GET / HTTP/1.1\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n");
    packet.payload = request;
    packet.sequence = 1;
    packet.flags = 0x18;
    engine.tcp(packet, 1);
    require(!observations.empty() && observations.back().protocol == Observation::Protocol::Http &&
        observations.back().state == "http_authentication", "HTTP authentication did not reach the engine");

    const std::string_view tunnel = "CONNECT target.test:443 HTTP/1.1\r\n"
        "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n";
    packet.sequence += static_cast<uint32_t>(request.size());
    packet.payload = bytes(tunnel);
    engine.tcp(packet, 2);
    const auto tls = record(hello(true, 0x0303, false, false, {}), 22);
    packet.sequence += static_cast<uint32_t>(tunnel.size());
    packet.payload = tls;
    engine.tcp(packet, 3);
    CryptoCatalog catalog;
    const auto summary = catalog.summarize(observations.back(), [](const auto&, const auto&, Bytes) {});
    require(observations.back().protocol == Observation::Protocol::Tls &&
        nlohmann::json::parse(summary.json).value("http_proxy_auth_observed", false),
        "HTTP proxy authentication was lost after a TLS tunnel upgrade");

    // Fragmented extension methods and body framing retain only public HTTP facts.
    FramedStream general;
    nlohmann::json generalFields = nlohmann::json::object();
    const std::string_view fragmented = "PROPFIND /private?token=hidden HTTP/1.1\r\nHost: localhost:3000\r\n"
        "Cookie: session=hidden\r\nContent-Length: 6\r\n\r\nhidden";
    for (const auto ch : fragmented)
        require(feed(general, std::string_view(&ch, 1), generalFields), "Fragmented HTTP request was rejected");
    require(generalFields["http_methods"] == nlohmann::json::array({"PROPFIND"}) &&
        generalFields["http_hosts"] == nlohmann::json::array({"localhost:3000"}) &&
        generalFields.dump().find("hidden") == std::string::npos &&
        generalFields.dump().find("private") == std::string::npos, "HTTP metadata leaked private request data");
    require(feed(general, "GET / HTTP/1.0\r\n\r\n", generalFields) &&
        generalFields["http_request_versions"] == nlohmann::json::array({"HTTP/1.0"}),
        "HTTP body framing swallowed a persistent request");
    for (const auto* malformed : {"GET nonsense\r\n\r\n", "GET / HTTP/2.0\r\n\r\n",
        "GET /bad target HTTP/1.1\r\n\r\n", "GET / HTTP/1.1\r\nBad Header: value\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n",
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"})
    {
        FramedStream parser;
        nlohmann::json parsed = nlohmann::json::object();
        require(!feed(parser, malformed, parsed) && parsed.empty(), "Malformed text produced HTTP evidence");
    }

    // HEAD and interim responses preserve the request queue; chunked and close-delimited bodies are skipped.
    FramedConnection exchange;
    auto feedPeer = [&](FramedConnection& connection, int direction, std::string_view text, nlohmann::json& fields)
    {
        return connection.feed(direction, bytes(text), [&](int, const FramedMessage& message)
        {
            fields.update(message.fields);
            return true;
        });
    };
    nlohmann::json exchangeFields = nlohmann::json::object();
    require(feedPeer(exchange, 0, "HEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n", exchangeFields) &&
        feedPeer(exchange, 1, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n",
            exchangeFields), "HTTP HEAD, interim, or chunked framing lost pairing");
    require(feedPeer(exchange, 1, "HTTP/1.0 200 OK\r\n\r\nhidden GET /fake HTTP/1.1\r\n\r\n", exchangeFields) &&
        exchangeFields.dump().find("hidden") == std::string::npos,
        "Close-delimited HTTP response body was inspected as another message");

    // Switching protocols ends HTTP parsing in both directions before WebSocket payload bytes arrive.
    FramedConnection upgraded;
    nlohmann::json upgradeFields = nlohmann::json::object();
    require(feedPeer(upgraded, 0, "GET /ws HTTP/1.1\r\nHost: localhost:3000\r\n"
        "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n", upgradeFields) &&
        feedPeer(upgraded, 1, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
            "Upgrade: websocket\r\n\r\n\x81\x02hi", upgradeFields) &&
        upgraded.finished() &&
        feedPeer(upgraded, 0, "\x81\x82xxxxxx", upgradeFields) &&
        upgradeFields.value("http_upgrade_protocol", "") == "websocket",
        "WebSocket upgrade was treated as malformed HTTP or TLS");

    // General monitoring is bounded and optional without losing existing authentication or TLS tunnel evidence.
    for (const auto enabled : {true, false})
    {
        Counters stats;
        std::vector<Observation> seen;
        Engine observer(stats, [&](Observation value)
        {
            if (!value.lifecycleOnly)
                seen.push_back(std::move(value));
        }, {.http = enabled});
        TransportPacket client = packet;
        client.sequence = 1;
        client.destination.port = 3000;
        client.loopback = true;
        auto send = [&](std::string_view text)
        {
            client.payload = bytes(text);
            observer.tcp(client, 10);
            client.sequence += static_cast<uint32_t>(text.size());
        };
        for (int index = 0; index < 100; ++index)
        {
            send("GET /private HTTP/1.1\r\nHost: localhost:3000\r\n\r\n");
            TransportPacket server = client;
            std::swap(server.source, server.destination);
            server.sequence = 1 + index * 38;
            server.payload = bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            observer.tcp(server, 11);
        }
        require(
            seen.size() == (enabled ? 2u : 0u), "Repeated HTTP requests caused observation churn or ignored disable");
        if (enabled)
        {
            const auto info = catalog.summarize(seen.back(), [](const auto&, const auto&, Bytes) {});
            require(seen.back().state == "http_observed" && info.encryption == "Unencrypted" &&
                nlohmann::json::parse(info.json).value("loopback", false),
                "HTTP protection or loopback classification was lost");
        }
        for (int index = 0; index < 40; ++index)
            send("GET / HTTP/1.1\r\nHost: host-" + std::to_string(index) + ".test\r\n\r\n");
        if (enabled)
            require(seen.back().application->fields["http_hosts"].size() == 16 &&
                seen.back().application->fields["http_host"] == "localhost:3000",
                "HTTP host aggregation exceeded its bound or changed the primary peer");
        send("GET / HTTP/1.1\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n");
        require(!seen.empty() && seen.back().state == "http_authentication" &&
            seen.back().application->fields.contains("http_hosts") == enabled,
            "Disabling general HTTP lost authentication evidence or retained general metadata");
    }

    // A response observed before TCP setup still places the server and client in the correct columns.
    Counters responseStats;
    std::vector<Observation> responseSeen;
    Engine responseObserver(responseStats, [&](Observation value) { responseSeen.push_back(std::move(value)); });
    packet.source.port = 3000;
    packet.destination.port = 42000;
    packet.sequence = 1;
    packet.payload = bytes("HTTP/1.1 204 No Content\r\n\r\n");
    responseObserver.tcp(packet, 1);
    require(!responseSeen.empty() && responseSeen.back().destination.port == 3000 &&
        responseSeen.back().source.port == 42000, "Response-first HTTP capture reversed process roles");

    // Persistent HTTP retains late responses and new request metadata beyond the handshake window.
    Counters persistentStats;
    std::vector<Observation> persistent;
    Engine persistentObserver(persistentStats, [&](Observation value)
    {
        if (!value.lifecycleOnly)
            persistent.push_back(std::move(value));
    });
    packet.source.port = 42000;
    packet.destination.port = 3000;
    packet.sequence = 1;
    packet.payload = bytes("GET / HTTP/1.1\r\nHost: first.test\r\n\r\n");
    persistentObserver.tcp(packet, 1);
    packet.sequence += static_cast<uint32_t>(packet.payload.size());
    auto reply = packet;
    std::swap(reply.source, reply.destination);
    reply.sequence = 1;
    reply.payload = bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    persistentObserver.tcp(reply, 31000001);
    packet.payload = bytes("POST / HTTP/1.1\r\nHost: second.test\r\nContent-Length: 0\r\n\r\n");
    persistentObserver.tcp(packet, 61000001);
    require(persistent.size() == 3 && persistent.back().application->fields["http_methods"].size() == 2 &&
        persistent.back().application->fields["http_status_codes"] == nlohmann::json::array({200}) &&
        persistent.back().application->fields["http_hosts"].size() == 2 && !persistentStats.reassemblyLimit,
        "Persistent HTTP lost a slow response or a late request");
    require(persistent.front().application->fields["http_hosts"] == nlohmann::json::array({"first.test"}) &&
        !persistent.front().application->fields.contains("http_status_codes"),
        "Updating HTTP evidence mutated a previously emitted snapshot");

    // A late CONNECT starts a fresh TLS inspection window after the persistent HTTP exchange.
    reply.sequence += static_cast<uint32_t>(reply.payload.size());
    persistentObserver.tcp(reply, 62000001);
    packet.sequence += static_cast<uint32_t>(packet.payload.size());
    packet.payload = bytes("CONNECT target.test:443 HTTP/1.1\r\nHost: target.test:443\r\n\r\n");
    persistentObserver.tcp(packet, 91000001);
    reply.sequence += static_cast<uint32_t>(reply.payload.size());
    reply.payload = bytes("HTTP/1.1 200 Connection established\r\n\r\n");
    persistentObserver.tcp(reply, 92000001);
    packet.sequence += static_cast<uint32_t>(packet.payload.size());
    packet.payload = tls;
    persistentObserver.tcp(packet, 93000001);
    reply.sequence += static_cast<uint32_t>(reply.payload.size());
    const auto serverTls = record(hello(false, 0x0303, false, false, {}), 22);
    reply.payload = serverTls;
    persistentObserver.tcp(reply, 94000001);
    require(persistent.back().protocol == Observation::Protocol::Tls && persistent.back().serverHello &&
        !persistentStats.reassemblyLimit, "A late CONNECT lost the tunneled TLS handshake");
}
}
