#include "NetworkFixtures.h"

namespace Cipherazzi::Tests
{
using namespace NetworkFixtures;
void smbLegacyCoverage();
void rdpStandardCoverage();
void kerberosCoverage();
void smbAuthenticationCoverage();
void kerberosUdpCoverage();
void kerberosPasswordCoverage();
void authenticationEngineCoverage();
void legacyHelloCoverage();
void ldapCoverage();

Buffer dtlsHello(bool client, bool tls13 = false)
{
    Buffer extensions;
    if (tls13)
    {
        extensions = client ? Buffer{0, 43, 0, 5, 4, 0xfe, 0xfc, 0xfe, 0xfd} :
            Buffer{0, 43, 0, 2, 0xfe, 0xfc};
    }
    auto body = hello(client, 0x0303, false, false, extensions);
    body.erase(body.begin(), body.begin() + 4);
    body[0] = 0xfe;
    body[1] = 0xfd;
    if (client)
        body.insert(body.begin() + 35, 0);
    return body;
}

Buffer dtlsFragment(Bytes body, uint8_t type, uint16_t sequence, size_t offset, size_t length)
{
    auto triple = [](Buffer& bytes, size_t value)
    {
        bytes.push_back(static_cast<uint8_t>(value >> 16));
        word(bytes, static_cast<uint16_t>(value));
    };
    Buffer handshake{type};
    triple(handshake, body.size());
    word(handshake, sequence);
    triple(handshake, offset);
    triple(handshake, length);
    append(handshake, body.subspan(offset, length));
    Buffer result{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, static_cast<uint8_t>(offset)};
    word(result, static_cast<uint16_t>(handshake.size()));
    append(result, handshake);
    return result;
}

Buffer ipTransport(Bytes payload, bool ipv6, bool udp, bool client)
{
    Buffer transport;
    word(transport, client ? 42000 : 443);
    word(transport, client ? 443 : 42000);
    if (udp)
    {
        word(transport, static_cast<uint16_t>(payload.size() + 8));
        word(transport, 0);
    }
    else
    {
        append(transport, Buffer{0, 0, 0, 100, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0});
    }
    append(transport, payload);
    Buffer ip(ipv6 ? 40 : 20);
    ip[0] = ipv6 ? 0x60 : 0x45;
    const auto size = transport.size() + (ipv6 ? 0 : 20);
    ip[ipv6 ? 4 : 2] = static_cast<uint8_t>(size >> 8);
    ip[ipv6 ? 5 : 3] = static_cast<uint8_t>(size);
    ip[ipv6 ? 6 : 9] = udp ? 17 : 6;
    ip[ipv6 ? 7 : 8] = 64;
    ip[ipv6 ? 23 : 15] = client ? 1 : 2;
    ip[ipv6 ? 39 : 19] = client ? 2 : 1;
    append(ip, transport);
    return ip;
}

Buffer ipFragment(Bytes datagram, bool ipv6, size_t offset, size_t length, bool more, uint16_t id)
{
    const auto header = ipv6 ? 40 : 20;
    Buffer result(datagram.begin(), datagram.begin() + header);
    const auto total = length + (ipv6 ? 8 : 20);
    result[ipv6 ? 4 : 2] = static_cast<uint8_t>(total >> 8);
    result[ipv6 ? 5 : 3] = static_cast<uint8_t>(total);
    const auto flags = static_cast<uint16_t>(ipv6 ? offset | (more ? 1 : 0) :
        offset / 8 | (more ? 0x2000 : 0));
    if (ipv6)
    {
        result[6] = 44;
        result.push_back(datagram[6]);
        result.push_back(0);
        word(result, flags);
        append(result, Buffer{0, 0});
        word(result, id);
    }
    else
    {
        result[4] = static_cast<uint8_t>(id >> 8);
        result[5] = static_cast<uint8_t>(id);
        result[6] = static_cast<uint8_t>(flags >> 8);
        result[7] = static_cast<uint8_t>(flags);
    }
    append(result, datagram.subspan(header + offset, length));
    return result;
}

void networkCoverage()
{
    smbLegacyCoverage();
    legacyHelloCoverage();
    ldapCoverage();
    rdpStandardCoverage();
    kerberosCoverage();
    kerberosUdpCoverage();
    kerberosPasswordCoverage();
    smbAuthenticationCoverage();
    authenticationEngineCoverage();
    const auto tlsRecord = record(hello(true, 0x0304, false, false, {}), 22);
    auto tdsFrame = [](Bytes payload)
    {
        Buffer bytes{0x12, 1};
        word(bytes, static_cast<uint16_t>(payload.size() + 8));
        append(bytes, Buffer{0, 0, 1, 0});
        append(bytes, payload);
        return bytes;
    };
    FramedStream tdsFraming;
    TlsStream tdsTls;
    int tdsHellos = 0;
    auto tdsSink = [&](const FramedMessage& message)
    {
        return tdsTls.feed(message.payload, [&](const Hello& parsed)
        {
            require(parsed.client && parsed.sni == "service.example.test", "TDS changed TLS hello content");
            ++tdsHellos;
        });
    };
    Buffer tds = tdsFrame(Bytes(tlsRecord).first(11));
    append(tds, tdsFrame(Bytes(tlsRecord).subspan(11)));
    for (size_t offset = 0; offset < tds.size(); ++offset)
        require(tdsFraming.feed(Bytes(tds).subspan(offset, 1), tdsSink), "Split TDS framing failed");
    require(tdsHellos == 1, "TDS wrappers interrupted a TLS record");
    require(tdsFraming.feed(tlsRecord, tdsSink) && tdsHellos == 2,
        "TDS did not transition from encapsulated to direct TLS records");

    // PRELOGIN options span TDS packets and must finish before encapsulated TLS is inspected.
    const Buffer prelogin{0, 0, 16, 0, 6, 1, 0, 22, 0, 1, 4, 0, 23, 0, 1, 0xff,
        16, 0, 0x18, 0x42, 0, 0, 3, 1};
    auto preloginFirst = tdsFrame(Bytes(prelogin).first(11));
    preloginFirst[1] = 0;
    auto preloginLast = tdsFrame(Bytes(prelogin).subspan(11));
    preloginLast[6] = 2;
    Buffer preloginTranscript = preloginFirst;
    append(preloginTranscript, preloginLast);
    append(preloginTranscript, tdsFrame(tlsRecord));
    FramedStream preloginFraming;
    TlsStream preloginTls;
    int preloginMessages = 0, preloginHellos = 0;
    for (size_t offset = 0; offset < preloginTranscript.size(); ++offset)
        require(preloginFraming.feed(Bytes(preloginTranscript).subspan(offset, 1), [&](const FramedMessage& message)
        {
            if (message.fields.contains("tds_prelogin"))
            {
                const auto& options = message.fields["tds_prelogin"];
                require(options["product_version"] == "16.0.6210.0" && options["encryption"] == 3 &&
                    options["mars_enabled"] == true && options["client_certificate_requested"] == false,
                    "TDS PRELOGIN options were lost or mistaken for TLS");
                ++preloginMessages;
            }
            return preloginTls.feed(message.payload, [&](const Hello&) { ++preloginHellos; });
        }), "A fragmented PRELOGIN and TLS exchange was rejected");
    require(preloginMessages == 1 && preloginHellos == 1,
        "Fragmented TDS options interrupted TLS or emitted duplicate negotiation evidence");
    for (int invalid = 0; invalid < 4; ++invalid)
    {
        auto options = prelogin;
        if (invalid == 0) options[7] = 0xff;
        else if (invalid == 1) options[7] = 19;
        else if (invalid == 2) options[5] = 0;
        else options[15] = 0;
        FramedStream rejected;
        int reports = 0;
        require(!rejected.feed(tdsFrame(options), [&](const FramedMessage&) { ++reports; return true; }) && !reports,
            "Malformed TDS offsets, overlapping data, duplicate tokens, or missing terminator produced evidence");
    }
    FramedStream missedPrelogin;
    require(missedPrelogin.feed(preloginFirst, [](const FramedMessage&) { return true; }),
        "An incomplete PRELOGIN message was prematurely rejected");
    preloginLast[6] = 3;
    require(!missedPrelogin.feed(preloginLast, [](const FramedMessage&) { return true; }),
        "TDS PRELOGIN fragments were combined across a missing packet");
    FramedStream unencryptedTds;
    int unencryptedLogins = 0;
    auto login7 = [&](Bytes security)
    {
        Buffer body(94 + security.size(), 'Q');
        const auto size = static_cast<uint32_t>(body.size());
        for (int index = 0; index < 4; ++index)
            body[index] = static_cast<uint8_t>(size >> (index * 8));
        body[25] = 0x80;
        body[78] = 94;
        body[79] = 0;
        body[80] = static_cast<uint8_t>(security.size());
        body[81] = static_cast<uint8_t>(security.size() >> 8);
        std::copy(security.begin(), security.end(), body.begin() + 94);
        auto frame = tdsFrame(body);
        frame[0] = 0x10;
        return frame;
    };
    const auto login = login7(ntlmType1(0x02088215));
    auto sspiFrame = [&](uint8_t type, Bytes token)
    {
        auto frame = tdsFrame(token);
        frame[0] = type;
        return frame;
    };
    const auto challenge = ntlmType2(0x00008205, {}, false);
    const auto authenticate = ntlmType3(0x200, Buffer(24, 0x66), Buffer(24, 0x77), "privateuser");
    Buffer sspiResponse{0xed, static_cast<uint8_t>(challenge.size()),
        static_cast<uint8_t>(challenge.size() >> 8)};
    append(sspiResponse, challenge);
    require(unencryptedTds.feed(tdsFrame(prelogin), [](const FramedMessage&) { return true; }) &&
        unencryptedTds.feed(login, [&](const FramedMessage& message)
        {
            if (!message.payload.empty() || message.kind != FramedMessage::Kind::Tds ||
                message.fields.value("tds_unencrypted_login_observed", false) != true ||
                message.fields.value("tds_login_integrated_security", false) != true ||
                !message.fields.contains("ntlm_negotiate") || message.fields.dump().find("QQQQ") != std::string::npos)
                throw std::runtime_error("LOGIN7 payload reached TLS inspection");
            ++unencryptedLogins;
            return true;
        }) && unencryptedLogins == 1 && !unencryptedTds.finished() && unencryptedTds.memory() == 0,
        "Plain LOGIN7 traffic was counted as a malformed handshake or retained its private payload");
    require(unencryptedTds.feed(sspiFrame(0x11, authenticate),
                [&](const FramedMessage& message)
                {
                    require(message.kind == FramedMessage::Kind::Tds && message.payload.empty() &&
                            message.fields.value("tds_sspi_continuation_observed", false) &&
                            message.fields["ntlm_authenticate"]["nt_response"] == "NTLMv1" &&
                            message.fields.dump().find("privateuser") == std::string::npos,
                        "A clear TDS SSPI continuation lost NTLM metadata or retained an identity");
                    return true;
                }),
        "A clear TDS SSPI continuation was rejected");
    auto sql = tdsFrame(Buffer{0x42});
    sql[0] = 1;
    require(unencryptedTds.feed(sql, [](const FramedMessage&) -> bool
        { throw std::runtime_error("Post-login SQL payload reached authentication inspection"); }) &&
        unencryptedTds.finished() && unencryptedTds.memory() == 0,
        "TDS inspection did not stop after the authentication exchange");
    for (const size_t segment : {size_t{4096}, size_t{1}})
    {
        FramedStream midstream;
        int reports = 0;
        for (size_t offset = 0; offset < login.size(); offset += segment)
            require(midstream.feed(Bytes(login).subspan(offset, std::min(segment, login.size() - offset)),
                [&](const FramedMessage& message)
                {
                    require(message.fields.value("tds_unencrypted_login_observed", false) &&
                        message.fields.contains("ntlm_negotiate"), "Standalone LOGIN7 lost its SSPI token");
                    ++reports;
                    return true;
                }), "A standalone LOGIN7 packet was rejected");
        require(reports == 1 && !midstream.finished() && midstream.memory() == 0,
            "A capture starting at LOGIN7 was not recognized");
    }
    {
        Counters health;
        const auto output = replayConnection(login, {}, 1433, health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Tds &&
            output.back().application->fields.contains("ntlm_negotiate") &&
            output.back().application->fields.value("tds_unencrypted_login_observed", false) &&
            !output.back().application->fields.contains("tds_client_prelogin") && health.malformed == 0,
            "A midstream LOGIN7 was not retained as unencrypted TDS evidence");
    }
    {
        FramedStream fragmented;
        const auto body = Bytes(login).subspan(8);
        auto first = tdsFrame(body.first(50)), last = tdsFrame(body.subspan(50));
        first[0] = last[0] = 0x10;
        first[1] = 0;
        last[6] = 2;
        int reports = 0;
        require(fragmented.feed(tdsFrame(prelogin), [](const FramedMessage&) { return true; }) &&
                fragmented.feed(first,
                    [&](const FramedMessage&)
                    {
                        ++reports;
                        return true;
                    }) &&
                !reports &&
                fragmented.feed(last,
                    [&](const FramedMessage& message)
                    {
                        ++reports;
                        return message.fields.contains("ntlm_negotiate");
                    }) &&
                reports == 1,
            "Fragmented LOGIN7 SSPI token was not reassembled");
    }

    // Server 0xED tokens and client 0x11 continuations can each span TDS packets and TCP segments.
    for (const size_t segment : {size_t{1}, size_t{7}, size_t{4096}})
    {
        auto serverPrelogin = tdsFrame(prelogin);
        serverPrelogin[0] = 4;
        const auto clientAuth = sspiFrame(0x11, authenticate);
        auto challengeFirst = sspiFrame(4, Bytes(sspiResponse).first(10));
        challengeFirst[1] = 0;
        auto challengeLast = sspiFrame(4, Bytes(sspiResponse).subspan(10));
        challengeLast[6] = 2;
        FramedStream directClient;
        int directAuthentications = 0;
        int directFrames = 0;
        for (const auto& frame : {tdsFrame(prelogin), login, clientAuth})
        {
            for (size_t offset = 0; offset < frame.size(); offset += segment)
                require(directClient.feed(Bytes(frame).subspan(offset, std::min(segment, frame.size() - offset)),
                    [&](const FramedMessage& message)
                    {
                        directAuthentications += message.fields.contains("ntlm_authenticate");
                        return true;
                    }), "Segmented TDS client SSPI framing failed");
            ++directFrames;
            if (directFrames == 2)
                require(!directClient.finished(), "Segmented LOGIN7 ended TDS inspection before SSPI continuation");
        }
        require(directAuthentications == 1, "Segmented TDS client authentication was missed");
        Counters health;
        const auto output = replayExchange({{false, tdsFrame(prelogin)}, {true, serverPrelogin},
            {false, login}, {true, challengeFirst}, {true, challengeLast}, {false, clientAuth}},
            1433, segment, health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Tds &&
            health.malformed == 0 && health.reassemblyLimit == 0,
            "A segmented TDS SSPI exchange was not retained");
        const auto evidence = summarized(output.back());
        require(evidence.contains("ntlm_negotiate"), "TDS SSPI negotiate metadata was lost");
        require(evidence.contains("ntlm_challenge"), "TDS SSPI challenge metadata was lost");
        require(evidence.contains("ntlm_authenticate"), "TDS SSPI authenticate metadata was lost");
        require(evidence.value("tds_sspi_response_observed", false) &&
            evidence.value("tds_sspi_continuation_observed", false),
            "TDS SSPI response or continuation framing was lost");
        require(evidence.dump().find("privateuser") == std::string::npos,
            "TDS SSPI retained private identity bytes");
    }
    {
        FramedStream malformedSspi;
        auto invalid = sspiResponse;
        invalid[1] = 0xff;
        int reports = 0;
        require(!malformedSspi.feed(sspiFrame(4, invalid),
                    [&](const FramedMessage&)
                    {
                        ++reports;
                        return true;
                    }) &&
                reports == 0,
            "A truncated server SSPI token produced TDS evidence");
    }

    // Known length-prefixed login tokens can precede SSPI; their payloads are skipped without being retained.
    {
        Buffer prefixed{0xe3, 3, 0, 'A', 'B', 'C', 0xab, 2, 0, 'D', 'E'};
        append(prefixed, sspiResponse);
        FramedStream server;
        int challenges = 0;
        require(server.feed(sspiFrame(4, prelogin), [](const FramedMessage&) { return true; }) &&
            server.feed(sspiFrame(4, prefixed), [&](const FramedMessage& message)
            {
                challenges += message.fields.contains("ntlm_challenge");
                require(message.fields.value("tds_sspi_response_observed", false) &&
                    message.fields.dump().find("ABC") == std::string::npos,
                    "A prefixed TDS response exposed private token contents");
                return true;
            }) && challenges == 1 && server.memory() == 0,
            "A prefixed server SSPI token was missed");
        auto malformed = prefixed;
        malformed[1] = 0xff;
        FramedStream invalid;
        require(!invalid.feed(sspiFrame(4, malformed), [](const FramedMessage&) -> bool
            { throw std::runtime_error("Malformed server login token produced evidence"); }),
            "A malformed TDS response prefix was accepted");
        FramedStream unknown;
        prefixed[0] = 0x81;
        int guessed = 0;
        require(unknown.feed(sspiFrame(4, prelogin), [](const FramedMessage&) { return true; }) &&
            unknown.feed(sspiFrame(4, prefixed), [&](const FramedMessage& message)
            { guessed += message.fields.contains("ntlm_challenge"); return true; }) &&
            guessed == 0 && unknown.finished(),
            "An unknown TDS login response prefix yielded guessed SSPI evidence");
    }
    FramedStream implausibleLogin;
    require(implausibleLogin.feed(tdsFrame(prelogin), [](const FramedMessage&) { return true; }) &&
        !implausibleLogin.feed(Buffer{0x10, 0x40, 0, 20, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            [](const FramedMessage&) -> bool
            { throw std::runtime_error("An implausible LOGIN7 header produced evidence"); }),
        "An implausible LOGIN7 header produced evidence");

    // Both PRELOGIN encryption settings determine the negotiated protection (MS-TDS 2.2.6.5).
    const char* const tdsOutcomes[4][4] = {
        {"Login only", "Entire session", "None", "Entire session"},
        {"Entire session", "Entire session", "Incompatible settings", "Entire session"},
        {"None", "Incompatible settings", "None", "Incompatible settings"},
        {"Entire session", "Entire session", "Incompatible settings", "Entire session"}};
    for (unsigned client = 0; client < 4; ++client)
        for (unsigned server = 0; server < 4; ++server)
        {
            // The client-certificate bit accompanies the setting without changing it.
            nlohmann::json fields{{"tds_client_prelogin", {{"encryption", client | 0x80}}},
                {"tds_server_prelogin", {{"encryption", server}}}};
            resolveNegotiation(fields);
            require(fields["tds_negotiated_encryption"] == tdsOutcomes[client][server],
                "PRELOGIN encryption settings were resolved to the wrong session protection");
        }
    for (auto fields : {nlohmann::json{{"tds_client_prelogin", {{"encryption", 0}}}},
        nlohmann::json{{"tds_client_prelogin", {{"encryption", 4}}}, {"tds_server_prelogin", {{"encryption", 0}}}},
        nlohmann::json{{"tds_client_prelogin", {{"mars_enabled", true}}}, {"tds_server_prelogin", {{"encryption", 0}}}},
        nlohmann::json{{"tds_peer_a_prelogin", {{"encryption", 0}}}, {"tds_peer_b_prelogin", {{"encryption", 0}}}}})
    {
        fields["tds_negotiated_encryption"] = "Entire session";
        resolveNegotiation(fields);
        require(!fields.contains("tds_negotiated_encryption"),
            "Session protection was resolved from one peer, an unknown setting, or unknown roles");
    }

    // The outcome joins both directions of one connection; a login outside TLS is observed rather than inferred.
    {
        auto options = [&](uint8_t encryption, bool response)
        {
            auto bytes = prelogin;
            bytes[22] = encryption;
            auto frame = tdsFrame(bytes);
            frame[0] = response ? 4 : 0x12;
            return frame;
        };
        Counters health;
        auto output = replayConnection(concat({options(2, false), login}), options(2, true), 1433, health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Tds &&
            output.back().state == "tds_authentication" && health.malformed == 0 && health.reassemblyLimit == 0 &&
            health.bufferedBytes == 0, "An unencrypted TDS login was not retained as TDS evidence");
        auto evidence = summarized(output.back());
        require(evidence["tds_negotiated_encryption"] == "None" && evidence["tds_unencrypted_login_observed"] == true &&
            evidence["tds_client_prelogin"]["encryption"] == 2 && evidence.dump().find("QQQQ") == std::string::npos,
            "An unencrypted TDS login was not reported or retained login contents");

        // Login-only encryption wraps the TLS handshake in TDS packets and reports no cleartext login.
        Counters loginOnlyHealth;
        output = replayConnection(concat({options(0, false), tdsFrame(tlsRecord)}), options(0, true), 1433,
            loginOnlyHealth);
        require(!output.empty() && output.back().clientHello && loginOnlyHealth.malformed == 0,
            "A TLS handshake following PRELOGIN was not inspected");
        evidence = summarized(output.back());
        require(evidence["tds_negotiated_encryption"] == "Login only" &&
            !evidence.contains("tds_unencrypted_login_observed"),
            "Login-only TDS encryption was misreported or implied a cleartext login");
        Counters requiredHealth;
        output = replayConnection(options(0x80, false), options(3, true), 1433, requiredHealth);
        require(!output.empty() && summarized(output.back())["tds_negotiated_encryption"] == "Entire session",
            "A server encryption requirement was not resolved to an encrypted session");
    }

    // A midstream server-first exchange keeps PRELOGIN socket provenance when TLS reveals TCP roles later.
    for (const bool knownRoles : {false, true})
    {
        Counters health;
        std::vector<Observation> output;
        Engine engine(health, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                output.push_back(std::move(observation));
        });
        auto packet = [](Bytes payload, bool server, uint32_t sequence, uint8_t flags = 0x18)
        {
            TransportPacket value;
            value.source.address[0] = value.destination.address[0] = 10;
            value.source.address[3] = server ? 2 : 1;
            value.destination.address[3] = server ? 1 : 2;
            value.source.port = server ? 1433 : 50123;
            value.destination.port = server ? 50123 : 1433;
            value.sequence = sequence;
            value.flags = flags;
            value.payload = payload;
            return value;
        };
        if (knownRoles)
        {
            engine.tcp(packet({}, false, 1000, 2), 1);
            engine.tcp(packet({}, true, 9000, 0x12), 2);
        }
        const auto options = tdsFrame(prelogin);
        engine.tcp(packet(options, true, 9001), 3);
        engine.tcp(packet(options, false, 1001), 4);
        const auto serverHello = tdsFrame(record(hello(false, 0x0304, false, false, {}), 22));
        engine.tcp(packet(serverHello, true, static_cast<uint32_t>(9001 + options.size())), 5);
        engine.tcp(packet(tdsFrame(tlsRecord), false, static_cast<uint32_t>(1001 + options.size())), 6);
        engine.expire(1000000, true);
        require(!output.empty() && output.back().clientHello && output.back().serverHello &&
            output.back().source.address[3] == 1 && health.malformed == 0 && health.bufferedBytes == 0,
            "TDS PRELOGIN role handling interrupted TLS or retained inspection storage");
        CryptoCatalog catalog;
        const auto evidence = nlohmann::json::parse(catalog.summarize(output.back(), [](auto&, auto&, Bytes) {}).json);
        require(evidence["tds_roles_known"] == knownRoles && (knownRoles ?
            evidence.contains("tds_client_prelogin") && evidence.contains("tds_server_prelogin") :
            !evidence.contains("tds_client_prelogin") && !evidence.contains("tds_server_prelogin") &&
            evidence["tds_peer_a_prelogin"]["socket_address"] == "10.0.0.1" &&
            evidence["tds_peer_b_prelogin"]["socket_address"] == "10.0.0.2"),
            "PRELOGIN options fabricated client roles or changed peer identity after a TLS hello");
        require(knownRoles ? evidence["tds_negotiated_encryption"] == "Entire session" :
            !evidence.contains("tds_negotiated_encryption"),
            "Negotiated TDS encryption was lost with known roles or resolved without them");
    }
    FramedStream rdpFraming;
    Buffer rdp{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0};
    append(rdp, tlsRecord);
    int rdpRequests = 0, rdpHellos = 0;
    TlsStream rdpTls;
    require(rdpFraming.feed(rdp, [&](const FramedMessage& message)
    {
        if (message.kind == FramedMessage::Kind::Rdp)
        {
            require(message.fields["rdp_requested_protocols"] == 3, "RDP negotiation flags were lost");
            ++rdpRequests;
            return true;
        }
        return rdpTls.feed(message.payload, [&](const Hello&) { ++rdpHellos; });
    }) && rdpRequests == 1 && rdpHellos == 1, "Coalesced RDP negotiation and TLS were not separated");

    // Cookies and correlation information bracket the request's negotiation structure.
    Buffer correlated(rdp.begin(), rdp.begin() + 19);
    const std::string cookie = "Cookie: mstshash=test-identity\r\n";
    correlated.insert(correlated.begin() + 11, cookie.begin(), cookie.end());
    correlated[12 + cookie.size()] = 9;
    append(correlated, Buffer{6, 0, 36, 0});
    for (uint8_t value = 1; value <= 16; ++value)
        correlated.push_back(value);
    correlated.resize(correlated.size() + 16, 0);
    correlated[3] = static_cast<uint8_t>(correlated.size());
    correlated[4] = correlated[3] - 5;
    FramedStream correlatedFraming;
    int correlatedReports = 0;
    for (size_t offset = 0; offset < correlated.size(); ++offset)
        require(correlatedFraming.feed(Bytes(correlated).subspan(offset, 1), [&](const FramedMessage& message)
        {
            require(message.fields["rdp_requested_protocols"] == 3 && message.fields["rdp_request_flags"] == 9 &&
                message.fields["rdp_restricted_admin_required"] == true &&
                message.fields["rdp_credential_guard_required"] == false &&
                message.fields["rdp_routing_cookie_observed"] == true &&
                message.fields["rdp_correlation_id"] == "0102030405060708090a0b0c0d0e0f10" &&
                message.fields.dump().find("test-identity") == std::string::npos,
                "RDP correlation displaced security negotiation or persisted the routing cookie");
            ++correlatedReports;
            return true;
        }), "A split RDP correlation-info request was rejected");
    require(correlatedReports == 1, "RDP correlation request emitted duplicate evidence");
    for (int invalid = 0; invalid < 3; ++invalid)
    {
        auto malformed = correlated;
        if (invalid == 0) malformed[malformed.size() - 34] = 8;
        else if (invalid == 1) malformed.back() = 1;
        else malformed[12 + cookie.size()] = 0;
        FramedStream rejected;
        require(!rejected.feed(malformed, [](const FramedMessage&) { return true; }),
            "Malformed RDP correlation information was accepted");
    }
    FramedStream legacyRdp;
    require(legacyRdp.feed(Buffer{3, 0, 0, 11, 6, 0xd0, 0, 0, 0, 0, 0}, [](const FramedMessage& message)
    {
        return message.fields["rdp_response_negotiation_observed"] == false &&
            !message.fields.contains("rdp_selected_protocol");
    }), "An X.224 response without negotiation implied a selected security protocol");
    require(!legacyRdp.finished(), "An X.224 response without negotiation ended inspection before the MCS PDU");
    FramedStream direct;
    const Buffer shortAlert{21, 3, 3, 0, 2, 2, 40};
    size_t directBytes = 0;
    require(direct.feed(shortAlert, [&](const FramedMessage& message)
    {
        directBytes += message.payload.size();
        return true;
    }) && directBytes == shortAlert.size(), "Protocol probing withheld a short direct TLS record");
    auto smbFrame = [](bool response)
    {
        Buffer bytes(response ? 128 : 104, 0);
        bytes[0] = 0xfe;
        bytes[1] = 'S'; bytes[2] = 'M'; bytes[3] = 'B';
        bytes[4] = 64;
        bytes[16] = response ? 1 : 0;
        bytes[64] = response ? 65 : 36;
        if (response)
        {
            bytes[66] = 3;
            bytes[68] = 2; bytes[69] = 3;
        }
        else
        {
            bytes[66] = 2;
            bytes[68] = 1;
            bytes[100] = 2; bytes[101] = 2;
            bytes[102] = 2; bytes[103] = 3;
        }
        Buffer result{0, 0};
        word(result, static_cast<uint16_t>(bytes.size()));
        append(result, bytes);
        return result;
    };
    for (bool response : {false, true})
    {
        FramedStream framing;
        const auto bytes = smbFrame(response);
        int messages = 0;
        for (size_t offset = 0; offset < bytes.size(); ++offset)
            require(framing.feed(Bytes(bytes).subspan(offset, 1), [&](const FramedMessage& message)
            {
                require(message.kind == FramedMessage::Kind::Smb &&
                    message.fields.contains(response ? "smb_selected_dialect" : "smb_offered_dialects") &&
                    !message.fields.contains("smb_encrypted_transform_observed"),
                    "SMB negotiation implied encrypted traffic or lost dialect evidence");
                ++messages;
                return true;
            }), "SMB split-frame parsing failed");
        require(messages == 1, "SMB split frame emitted duplicate evidence");
    }
    FramedStream invalidSmb;
    auto smb311 = smbFrame(true);
    smb311[72] = 0x11;
    smb311[74] = 1;
    smb311[128] = 128;
    append(smb311, Buffer{2, 0, 4, 0, 0, 0, 0, 0, 1, 0, 2, 0});
    smb311[3] = static_cast<uint8_t>(smb311.size() - 4);
    FramedStream smbContexts;
    require(smbContexts.feed(smb311, [](const FramedMessage& message)
    {
        return message.fields["smb_selected_dialect"] == "0x0311" &&
            message.fields["smb_selected_cipher"] == nlohmann::json::array({"0x0002"});
    }), "SMB 3.1.1 encryption selection was lost");

    // A fragmented operational response can establish signing independently of negotiation capabilities.
    auto signedSmb = smbFrame(true);
    signedSmb[16] = 5;
    signedSmb[20] = 9;
    FramedStream signedFraming;
    int signedReports = 0;
    require(signedFraming.feed(smbFrame(false), [&](const FramedMessage& message)
    {
        require(!message.fields.contains("smb_signed_message_observed"),
            "SMB signing negotiation implied signed traffic");
        return true;
    }), "SMB signing transcript negotiation failed");
    for (size_t offset = 0; offset < signedSmb.size(); ++offset)
        require(signedFraming.feed(Bytes(signedSmb).subspan(offset, 1), [&](const FramedMessage& message)
        {
            require(message.fields["smb_signed_message_observed"] == true &&
                !message.fields.contains("smb_encrypted_transform_observed"), "Signed SMB framing implied encryption");
            ++signedReports;
            return true;
        }), "Fragmented signed SMB response was rejected");
    require(signedReports == 1, "Signed SMB response emitted duplicate evidence");

    // NetBIOS setup and four-byte control packets preserve subsequent SMB negotiation framing.
    Buffer netbiosRequest{0x81, 0, 0, 68};
    for (int name = 0; name < 2; ++name)
    {
        netbiosRequest.push_back(32);
        netbiosRequest.insert(netbiosRequest.end(), 32, 'A');
        netbiosRequest.push_back(0);
    }
    for (const bool client : {false, true})
    {
        Buffer transcript = client ? netbiosRequest : Buffer{0x82, 0, 0, 0};
        append(transcript, Buffer{0x85, 0, 0, 0});
        append(transcript, smbFrame(!client));
        FramedStream framed;
        int reports = 0;
        for (size_t offset = 0; offset < transcript.size(); ++offset)
            require(framed.feed(Bytes(transcript).subspan(offset, 1), [&](const FramedMessage& message)
            {
                require(message.fields["smb_transport_framing"] == "NetBIOS over TCP" &&
                    message.fields.contains(client ? "smb_offered_dialects" : "smb_selected_dialect"),
                    "NetBIOS setup displaced SMB dialect negotiation");
                ++reports;
                return true;
            }), "Fragmented NetBIOS session setup was rejected");
        require(reports == 1, "NetBIOS session setup emitted duplicate or unsupported SMB observations");
    }
    auto badNetbios = netbiosRequest;
    badNetbios[5] = 'Q';
    FramedStream netbiosBounds;
    require(!netbiosBounds.feed(badNetbios, [](const FramedMessage&) { return true; }),
        "A malformed NetBIOS session name was accepted");

    // Native Windows compression produces independent LZNT1, XPRESS, and Huffman wire fixtures.
    auto littleDword = [](Buffer& bytes, uint32_t value)
    {
        for (int shift = 0; shift < 32; shift += 8)
            bytes.push_back(static_cast<uint8_t>(value >> shift));
    };
    auto envelope = [](Bytes payload)
    {
        Buffer frame{0, static_cast<uint8_t>(payload.size() >> 16), static_cast<uint8_t>(payload.size() >> 8),
            static_cast<uint8_t>(payload.size())};
        append(frame, payload);
        return frame;
    };
    using WorkspaceSize = LONG(WINAPI*)(USHORT, PULONG, PULONG);
    using Compress = LONG(WINAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto workspaceSize = reinterpret_cast<WorkspaceSize>(
        GetProcAddress(module, "RtlGetCompressionWorkSpaceSize"));
    const auto compress = reinterpret_cast<Compress>(GetProcAddress(module, "RtlCompressBuffer"));
    require(workspaceSize && compress, "Windows SMB compression codecs are unavailable");
    auto compressed = [&](Bytes payload, uint16_t algorithm)
    {
        if (algorithm == 5)
        {
            Buffer result{0xf0};
            size_t remaining = payload.size() - 15;
            while (remaining >= 255)
            {
                result.push_back(255);
                remaining -= 255;
            }
            result.push_back(static_cast<uint8_t>(remaining));
            append(result, payload);
            return result;
        }
        ULONG workSize{}, fragmentSize{}, actual{};
        const USHORT format = algorithm + 1;
        require(workspaceSize(format, &workSize, &fragmentSize) >= 0,
            "Windows compression workspace could not be sized");
        Buffer workspace(workSize), result(payload.size() * 2 + 512);
        require(compress(format, const_cast<PUCHAR>(payload.data()), static_cast<ULONG>(payload.size()),
            result.data(), static_cast<ULONG>(result.size()), 4096, &actual, workspace.data()) >= 0,
            "Windows could not produce an SMB compression fixture");
        result.resize(actual);
        return result;
    };
    Buffer plain(signedSmb.begin() + 4, signedSmb.end());
    plain.resize(4096, 0);
    for (const auto algorithm : std::array<uint16_t, 4>{1, 2, 3, 5})
        for (const bool chained : {false, true})
        {
            const size_t prefix = chained || algorithm == 2 ? 64 : 0;
            Buffer transform{0xfc, 'S', 'M', 'B'};
            littleDword(transform, static_cast<uint32_t>(chained ? plain.size() : plain.size() - prefix));
            if (chained)
            {
                append(transform, Buffer{0, 0, 1, 0});
                littleDword(transform, static_cast<uint32_t>(prefix));
                append(transform, Bytes(plain).first(prefix));
                const auto payload = compressed(Bytes(plain).subspan(prefix), algorithm);
                append(transform, Buffer{static_cast<uint8_t>(algorithm), 0, 0, 0});
                littleDword(transform, static_cast<uint32_t>(payload.size() + 4));
                littleDword(transform, static_cast<uint32_t>(plain.size() - prefix));
                append(transform, payload);
            }
            else
            {
                append(transform, Buffer{static_cast<uint8_t>(algorithm), 0, 0, 0});
                littleDword(transform, static_cast<uint32_t>(prefix));
                append(transform, Bytes(plain).first(prefix));
                append(transform, compressed(Bytes(plain).subspan(prefix), algorithm));
            }
            const auto frame = envelope(transform);
            FramedStream framed;
            int reports = 0;
            for (size_t offset = 0; offset < frame.size();)
            {
                const auto count = std::min(size_t{17}, frame.size() - offset);
                require(framed.feed(Bytes(frame).subspan(offset, count), [&](const FramedMessage& message)
                {
                    require(message.fields["smb_compressed_transform_observed"] == true &&
                        message.fields["smb_compression_chained"] == chained &&
                        message.fields["smb_compression_decoded"] == true &&
                        message.fields["smb_signed_message_observed"] == true &&
                        !message.fields.contains("smb_encrypted_transform_observed"),
                        "SMB compressed framing lost signing evidence or implied encryption");
                    ++reports;
                    return true;
                }), "An independently encoded SMB compressed message was rejected");
                offset += count;
            }
            require(reports == 1, "SMB compressed message emitted duplicate evidence");
        }
    Buffer pattern{0xfc, 'S', 'M', 'B'};
    littleDword(pattern, 4096);
    append(pattern, Buffer{0, 0, 1, 0});
    littleDword(pattern, 64);
    append(pattern, Bytes(plain).first(64));
    append(pattern, Buffer{4, 0, 0, 0});
    littleDword(pattern, 8);
    append(pattern, Buffer{0, 0, 0, 0});
    littleDword(pattern, 4032);
    FramedStream patternFraming;
    require(patternFraming.feed(envelope(pattern), [](const FramedMessage& message)
    {
        return message.fields["smb_compression_decoded"] == true &&
            message.fields["smb_signed_message_observed"] == true;
    }), "SMB pattern compression was not decoded");
    Buffer unknownCompression{0xfc, 'S', 'M', 'B'};
    littleDword(unknownCompression, 4096);
    append(unknownCompression, Buffer{0x42, 0, 0, 0});
    littleDword(unknownCompression, 0);
    append(unknownCompression, Buffer{1, 2, 3, 4});
    FramedStream futureCompression;
    require(futureCompression.feed(envelope(unknownCompression), [](const FramedMessage& message)
    {
        return message.fields["smb_compressed_transform_observed"] == true &&
            message.fields["smb_compression_decoded"] == false &&
            message.fields["smb_compression_algorithms"] == nlohmann::json::array({"0x0042"}) &&
            !message.fields.contains("smb_signed_message_observed");
    }), "An unknown SMB compression algorithm fabricated decoded signing evidence");
    for (const bool oversized : {false, true})
    {
        auto malformed = pattern;
        if (oversized)
            std::fill_n(malformed.begin() + 4, 4, uint8_t{0xff});
        else
            std::fill_n(malformed.end() - 4, 4, uint8_t{0xff});
        FramedStream rejected;
        require(!rejected.feed(envelope(malformed), [](const FramedMessage&) { return true; }) &&
            rejected.limited() == oversized, "SMB compression exceeded its bounds or misclassified a length error");
    }

    // Mutate complete framed exchanges and vary their delivery boundaries to exercise the new length paths.
    std::mt19937 framingMutations(74183);
    for (const auto& original : {netbiosRequest, correlated, tdsFrame(prelogin), envelope(pattern),
        envelope(unknownCompression)})
        for (int trial = 0; trial < 200; ++trial)
        {
            auto mutated = original;
            for (int change = 0; change < 4; ++change)
                mutated[framingMutations() % mutated.size()] ^= static_cast<uint8_t>(framingMutations());
            FramedStream parser;
            for (size_t offset = 0; offset < mutated.size();)
            {
                const auto count = std::min(size_t{1 + framingMutations() % 31}, mutated.size() - offset);
                if (!parser.feed(Bytes(mutated).subspan(offset, count), [](const FramedMessage&) { return true; }))
                    break;
                offset += count;
            }
            require(parser.memory() <= 2 * 262144, "Malformed framing bypassed the retained inspection bound");
        }
    auto invalidContext = smb311;
    invalidContext[134] = 255;
    FramedStream contextBounds;
    require(!contextBounds.feed(invalidContext, [](const FramedMessage&) { return true; }),
        "SMB negotiation context escaped its frame");
    for (size_t length = 0; length < smb311.size(); ++length)
    {
        FramedStream truncated;
        int emitted = 0;
        require(truncated.feed(Bytes(smb311).first(length), [&](const FramedMessage&)
        {
            ++emitted;
            return true;
        }) && emitted == 0, "Truncated SMB negotiation produced evidence");
    }
    Buffer encryptedSmb(4 + 52 + 16, 0);
    encryptedSmb[3] = 68;
    encryptedSmb[4] = 0xfd;
    encryptedSmb[5] = 'S'; encryptedSmb[6] = 'M'; encryptedSmb[7] = 'B';
    encryptedSmb[40] = 16;
    encryptedSmb[46] = 1;
    FramedStream encryptedFraming;
    int encryptedReports = 0;
    auto encryptedSink = [&](const FramedMessage& message)
    {
        require(message.fields["smb_encrypted_transform_observed"] == true,
            "SMB encrypted transform evidence missing");
        ++encryptedReports;
        return true;
    };
    require(encryptedFraming.feed(encryptedSmb, encryptedSink) &&
        encryptedFraming.feed(encryptedSmb, encryptedSink) && encryptedReports == 1 && encryptedFraming.memory() == 0,
        "SMB encrypted bulk traffic retained inspection storage or repeated observations");
    auto malformedSmb = smbFrame(false);
    malformedSmb[70] = 255;
    require(!invalidSmb.feed(malformedSmb, [](const FramedMessage&) { return true; }),
        "Truncated SMB dialect list accepted");
    auto srtpHello = [](bool client, Bytes extension)
    {
        auto bytes = hello(client, 0x0303, false, false, extension);
        bytes.erase(bytes.begin(), bytes.begin() + 4);
        bytes[0] = 0xfe;
        bytes[1] = 0xfd;
        if (client)
            bytes.insert(bytes.begin() + 35, 0);
        return bytes;
    };
    Hello srtpClient, srtpServer;
    srtpClient.client = true;
    require(parseHello(srtpHello(true, Buffer{0, 14, 0, 9, 0, 6, 0, 1, 0, 7, 0xfe, 0x42, 0}),
        srtpClient, true) && srtpClient.crypto.srtpProfiles == std::vector<uint16_t>{1, 7, 0xfe42},
        "DTLS SRTP offers lost known or unknown profile IDs");
    require(parseHello(srtpHello(false, Buffer{0, 14, 0, 5, 0, 2, 0, 7, 0}), srtpServer, true) &&
        srtpServer.crypto.selectedSrtpProfile == 7, "DTLS SRTP server selection was not parsed");
    Observation srtpObservation;
    applyHello(srtpObservation, srtpClient, 1);
    require(srtpObservation.crypto.selectedSrtpProfile == -1, "SRTP offers established a selection");
    applyHello(srtpObservation, srtpServer, 2);
    CryptoCatalog srtpCatalog;
    const auto srtpSummary = nlohmann::json::parse(
        srtpCatalog.summarize(srtpObservation, [](const auto&, const auto&, Bytes) {}).json);
    require(srtpSummary["srtp_selected_profile"] == 7 && srtpSummary["srtp_offered_profiles"].size() == 3,
        "SRTP evidence was not retained in the public summary");
    srtpServer.version = 0x0304;
    srtpServer.dtlsVersion = 0xfefc;
    applyHello(srtpObservation, srtpServer, 3);
    require(srtpObservation.crypto.selectedSrtpProfile == -1,
        "DTLS 1.3 ServerHello established an encrypted SRTP selection");
    Hello duplicateProfiles;
    duplicateProfiles.client = true;
    require(!parseHello(srtpHello(true, Buffer{0, 14, 0, 7, 0, 4, 0, 7, 0, 7, 0}),
        duplicateProfiles, true), "Duplicate SRTP offers accepted");
    for (const auto& extension : {Buffer{0, 14, 0, 3, 0, 0, 0}, Buffer{0, 14, 0, 4, 0, 1, 7, 0},
        Buffer{0, 14, 0, 5, 0, 2, 0, 7, 1}, Buffer{0, 14, 0, 7, 0, 4, 0, 1, 0, 7, 0}})
    {
        Hello invalid;
        require(!parseHello(srtpHello(false, extension), invalid, true), "Malformed SRTP selection accepted");
    }
    for (const bool ipv6 : {false, true})
    {
        for (unsigned seed = 0; seed < 30; ++seed)
        {
            Counters counters;
            std::vector<Observation> observations;
            Engine engine(counters,
                [&](Observation row)
                {
                    if (!row.lifecycleOnly) observations.push_back(std::move(row));
                });
            const auto message = hello(true, 0x0304, false, false, {});
            const auto datagram = ipTransport(record(message, 22), ipv6, false);
            std::vector<Buffer> pieces;
            const auto payload = datagram.size() - (ipv6 ? 40 : 20);
            for (size_t offset = 0; offset < payload; offset += 24)
                pieces.push_back(ipFragment(datagram, ipv6, offset, std::min(size_t{24}, payload - offset),
                    offset + 24 < payload));
            std::shuffle(pieces.begin(), pieces.end(), std::mt19937(seed));
            for (const auto& piece : pieces)
                engine.packet(piece, PacketKind::Ip, 1000000);
            require(!observations.empty() && observations.back().clientHello && counters.malformed == 0,
                "Out-of-order IP fragments lost the TLS hello");
            engine.expire(40000000, true);
            require(counters.bufferedBytes == 0 && counters.reassemblyLimit == 0,
                "Completed IP fragments leaked their reassembly budget");
        }

        // Overlap is rejected before any transport evidence can be emitted.
        Counters counters;
        Engine engine(counters, [](Observation) { throw std::runtime_error("Overlapping fragments were inspected"); });
        const auto datagram = ipTransport(record(hello(true, 0x0304, false, false, {}), 22), ipv6, false);
        engine.packet(ipFragment(datagram, ipv6, 0, 48, true), PacketKind::Ip, 1000000);
        engine.packet(ipFragment(datagram, ipv6, 24, 48, true), PacketKind::Ip, 1000001);
        engine.expire(40000000, true);
        require(counters.malformed == 1 && counters.bufferedBytes == 0, "Overlap rejection leaked fragment state");
        Counters missing;
        Engine incomplete(missing, [](Observation) {});
        incomplete.packet(ipFragment(datagram, ipv6, 24, 48, true), PacketKind::Ip, 1000000);
        incomplete.expire(32000000);
        require(missing.reassemblyLimit == 1 && missing.bufferedBytes == 0, "Incomplete IP fragments did not expire");

        // Distinct fragment IDs cannot bypass the configured context budget.
        Counters bounded;
        Engine constrained(bounded, [](Observation) {}, {1, 65536, 120000000});
        constrained.packet(ipFragment(datagram, ipv6, 24, 48, true, 100), PacketKind::Ip, 1000000);
        constrained.packet(ipFragment(datagram, ipv6, 24, 48, true, 101), PacketKind::Ip, 1000001);
        require(bounded.reassemblyLimit == 1 && bounded.bufferedBytes <= 65536,
            "IP fragments bypassed their bounded context admission");
        constrained.expire(40000000, true);
        require(bounded.bufferedBytes == 0, "Fragment admission retained memory after shutdown");
    }

    // Protocol framing takes precedence over a conventional service port when another protocol uses that port.
    {
        Counters counters;
        std::vector<Observation> observations;
        Engine engine(counters, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                observations.push_back(std::move(observation));
        });
        const auto client = dtlsHello(true);
        auto packet = ipTransport(dtlsFragment(client, 1, 0, 0, client.size()), false);
        packet[22] = 0x12;
        packet[23] = 0xb7;
        engine.packet(packet, PacketKind::Ip, 1000000);
        require(observations.size() == 1 && observations[0].dtlsVersion == 0xfefd && counters.malformed == 0,
            "RoCE port recognition suppressed a DTLS handshake on a nonstandard service port");
        engine.expire(2000000, true);
        require(counters.bufferedBytes == 0 && counters.activeFlows == 0,
            "DTLS on the RoCE service port retained inspection state");
    }

    // UDP DTLS shares the same connection ceiling as the existing protocol inspectors.
    Counters admission;
    Engine constrained(admission, [](Observation) {}, {1, 65536, 120000000});
    const auto firstHello = dtlsHello(true);
    auto firstPacket = ipTransport(dtlsFragment(firstHello, 1, 0, 0, firstHello.size()), false);
    constrained.packet(firstPacket, PacketKind::Ip, 1000000);
    ++firstPacket[21];
    constrained.packet(firstPacket, PacketKind::Ip, 1000001);
    require(admission.flowLimit == 1 && admission.activeFlows == 1 && admission.reassemblyLimit == 0,
        "DTLS bypassed the shared connection admission limit");
    constrained.expire(40000000, true);
    require(admission.bufferedBytes == 0, "DTLS admission retained memory after shutdown");

    for (const bool tls13 : {false, true})
    {
        Counters counters;
        std::vector<Observation> observations;
        Engine engine(counters,
            [&](Observation row)
            {
                if (!row.lifecycleOnly) observations.push_back(std::move(row));
            });
        const auto client = dtlsHello(true, tls13);
        engine.packet(ipTransport(dtlsFragment(client, 1, 0, 30, client.size() - 30), false),
            PacketKind::Ip, 1000000);
        engine.packet(ipTransport(dtlsFragment(client, 1, 0, 0, 40), false), PacketKind::Ip, 1000001);
        engine.packet(ipTransport(dtlsFragment(client, 1, 0, 0, client.size()), false), PacketKind::Ip, 1000002);
        require(observations.size() == 1, "DTLS overlap or retransmission duplicated a hello");
        const auto server = dtlsHello(false, tls13);
        engine.packet(ipTransport(dtlsFragment(server, 2, 0, 0, server.size()), false, true, false),
            PacketKind::Ip, 1000003);
        require(observations.back().clientHello && observations.back().serverHello &&
            observations.back().dtlsVersion == (tls13 ? 0xfefc : 0xfefd) &&
            observations.back().version == (tls13 ? 0x0304 : 0x0303), "DTLS version or TLS policy mapping was wrong");
        CryptoCatalog catalog;
        const auto detail = nlohmann::json::parse(
            catalog.summarize(observations.back(), [](auto&, auto&, Bytes) {}).json);
        require(detail["protocol"] == "DTLS" && detail["transport"] == "UDP", "DTLS was presented as TCP TLS");
        engine.expire(40000000, true);
        require(counters.malformed == 0 && counters.bufferedBytes == 0, "DTLS retained budget after shutdown");
    }

    // STUN and media share a DTLS-SRTP socket; a datagram of another protocol leaves the handshake untouched.
    {
        Counters counters;
        std::vector<Observation> observations;
        Engine engine(counters,
            [&](Observation row)
            {
                if (!row.lifecycleOnly) observations.push_back(std::move(row));
            });
        const auto client = dtlsHello(true), server = dtlsHello(false);
        const Buffer binding{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        const Buffer media{0x80, 96, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1};
        engine.packet(ipTransport(dtlsFragment(client, 1, 0, 0, client.size()), false), PacketKind::Ip, 1000000);
        engine.packet(ipTransport(binding, false), PacketKind::Ip, 1000001);
        engine.packet(ipTransport(media, false, true, false), PacketKind::Ip, 1000002);
        engine.packet(ipTransport(dtlsFragment(server, 2, 0, 0, server.size()), false, true, false),
            PacketKind::Ip, 1000003);
        require(observations.back().clientHello && observations.back().serverHello &&
            observations.back().detail.empty() && counters.malformed == 0,
            "A datagram of another protocol ended DTLS inspection");
        engine.expire(40000000, true);
        require(counters.bufferedBytes == 0, "DTLS shared with other protocols retained budget after shutdown");
    }
    const auto body = dtlsHello(true);
    DtlsStream malformed;
    require(malformed.feed(dtlsFragment(body, 1, 0, 0, 40), [](const Hello&) {}),
        "Initial DTLS fragment rejected");
    auto conflict = dtlsFragment(body, 1, 0, 30, body.size() - 30);
    conflict[25] ^= 1;
    require(!malformed.feed(conflict, [](const Hello&) {}), "Conflicting DTLS retransmission was accepted");

    // A reordered certificate flight waits for the server hello before entering the shared TLS parser.
    DtlsStream reordered;
    std::vector<Hello> flight;
    const Buffer certificate{0, 0, 4, 0, 0, 1, 42};
    auto collect = [&](const Hello& value) { flight.push_back(value); };
    require(reordered.feed(dtlsFragment(certificate, 11, 2, 0, certificate.size()), collect) && flight.empty(),
        "A reordered DTLS certificate was inspected before its hello");
    const auto server = dtlsHello(false);
    require(reordered.feed(dtlsFragment(server, 2, 1, 0, server.size()), collect) &&
        flight.size() == 2 && flight[0].type == 2 && flight[1].crypto.serverCertificates.size() == 1,
        "DTLS reordering lost the cleartext certificate flight");
    const Buffer oversized{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12,
        11, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    DtlsStream limited;
    require(!limited.feed(oversized, collect) && limited.limited(),
        "An oversized DTLS handshake bypassed the memory limit");

    // A certificate list that does not parse is malformed; only its size and count bounds are limits.
    TlsStream truncatedChain;
    const Buffer truncatedList{11, 0, 0, 7, 0, 0, 4, 0, 0, 9, 42};
    require(!truncatedChain.feedHandshake(truncatedList, collect) && truncatedChain.malformed() &&
        !truncatedChain.limited(), "A truncated certificate list was reported as an inspection limit");

    // A known CID links rebinding even after Initial inspection has released its decryption state.
    std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "quic.json");
    const auto fixtures = nlohmann::json::parse(input);
    Counters counters;
    std::vector<Observation> observations;
    Engine engine(counters,
        [&](Observation row)
        {
            if (!row.lifecycleOnly) observations.push_back(std::move(row));
        });
    for (const auto& encoded : fixtures[0]["packets"])
        engine.packet(fromHex(encoded.get<std::string>()), PacketKind::Ip, 1000000);
    const auto original = observations.back();
    auto id = fromHex(original.quicServerId);
    Buffer shortPacket{0x40};
    append(shortPacket, id);
    shortPacket.resize(shortPacket.size() + 20);
    TransportPacket migrated;
    migrated.source = original.source;
    ++migrated.source.port;
    migrated.destination = original.destination;
    migrated.protocol = 17;
    migrated.payload = shortPacket;
    auto migratedIp = ipTransport(shortPacket, false);
    std::copy_n(migrated.source.address.begin(), 4, migratedIp.begin() + 12);
    std::copy_n(migrated.destination.address.begin(), 4, migratedIp.begin() + 16);
    migratedIp[20] = static_cast<uint8_t>(migrated.source.port >> 8);
    migratedIp[21] = static_cast<uint8_t>(migrated.source.port);
    migratedIp[22] = static_cast<uint8_t>(migrated.destination.port >> 8);
    migratedIp[23] = static_cast<uint8_t>(migrated.destination.port);
    engine.packet(migratedIp, PacketKind::Ip, 2000000);
    require(observations.back().flowId == original.flowId && observations.back().quicPaths.size() == 2,
        "A visible QUIC CID failed to link a changed UDP tuple");
    engine.expire(40000000, true);
    require(counters.bufferedBytes == 0, "QUIC path tracking leaked its budget");
}
}
