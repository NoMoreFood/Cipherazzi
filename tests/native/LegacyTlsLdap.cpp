#include "NetworkFixtures.h"

namespace Cipherazzi::Tests
{
using namespace NetworkFixtures;

// SSL 2.0 hellos, the client's cipher choice, and hellos in SSL 2.0 format that lead to TLS.
void legacyHelloCoverage()
{
    // Selected TLS export, RC2, and IDEA suites retain their encryption and effective key size.
    for (const auto [cipher, encryption, bits] : {
        std::tuple{0x0003u, "RC4_40", 40}, {0x0006u, "RC2_CBC_40", 40},
        {0x0007u, "IDEA_CBC", 128}, {0x0021u, "IDEA_CBC", 128},
        {0x0008u, "DES40", 40}, {0x0026u, "DES40", 40},
        {0x0027u, "RC2_CBC_40", 40}, {0x0028u, "RC4_40", 40},
        {0x0009u, "DES_CBC", 56}})
    {
        Observation selected;
        selected.serverHello = true;
        selected.version = 0x0301;
        selected.cipher = cipher;
        const auto evidence = summarized(selected);
        require(evidence["encryption"] == encryption && evidence["symmetric_key_bits"] == bits,
            "A selected legacy TLS cipher lacked its encryption summary");
    }

    auto sized = [](const Buffer& message)
    {
        Buffer result{static_cast<uint8_t>(0x80 | message.size() >> 8), static_cast<uint8_t>(message.size())};
        append(result, message);
        return result;
    };
    auto clientHello = [&](uint16_t version, const Buffer& specs, size_t session = 0)
    {
        Buffer message{1};
        for (const auto value : {size_t{version}, specs.size(), session, size_t{16}})
            word(message, static_cast<uint16_t>(value));
        append(message, specs);
        message.resize(message.size() + session, 0x51);
        message.resize(message.size() + 16, 0x43);
        return sized(message);
    };

    // A session-ID hit resumes a session, so the server sends neither a certificate nor a cipher list.
    auto serverHello = [&](size_t certificate, const Buffer& specs)
    {
        Buffer message{4, static_cast<uint8_t>(certificate ? 0 : 1), static_cast<uint8_t>(certificate ? 1 : 0)};
        for (const auto value : {size_t{2}, certificate, specs.size(), size_t{16}})
            word(message, static_cast<uint16_t>(value));
        message.resize(message.size() + certificate, 0x30);
        append(message, specs);
        message.resize(message.size() + 16, 0x53);
        return sized(message);
    };
    auto masterKey = [&](const Buffer& kind, size_t clear, size_t encrypted, size_t argument)
    {
        Buffer message{2};
        append(message, kind);
        for (const auto value : {clear, encrypted, argument})
            word(message, static_cast<uint16_t>(value));
        message.resize(message.size() + clear + encrypted + argument, 0x4b);
        return sized(message);
    };
    const Buffer rc4{1, 0, 0x80}, exportRc4{2, 0, 0x80}, tripleDes{7, 0, 0xc0};
    const auto offer = clientHello(0x0002, concat({rc4, exportRc4, tripleDes}));
    const auto protectedRecord = sized(Buffer(64, 0x9d));

    // The exchange is read whole or a byte at a time. The server hello is sized so that its length reads as a
    // NetBIOS session packet, and the export cipher's name also contains that of the full-strength one.
    const auto answer = serverHello(735, concat({tripleDes, exportRc4}));
    require(answer[0] == 0x83 && answer[1] == 0, "The SSL 2.0 server hello fixture lost its NetBIOS-like length");
    for (const size_t segment : {size_t{4096}, size_t{1}, size_t{7}})
    {
        Counters health;
        const auto output = replayExchange({{false, offer}, {true, answer}, {false, masterKey(exportRc4, 11, 64, 0)},
            {false, protectedRecord}, {true, protectedRecord}}, 443, segment, health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Tls &&
            output.back().state == "hellos_observed" && output.back().version == 0x0002 &&
            output.back().cipher == 0x020080 && output.back().source.address[3] == 1 &&
            output.back().offeredVersions == "SSL 2.0" &&
            output.back().offeredCiphers == "0x010080, 0x020080, 0x0700C0" &&
            output.back().crypto.serverCertificates.size() == 1 &&
            output.back().crypto.serverCertificates[0]->size() == 735 && health.malformed == 0 &&
            health.reassemblyLimit == 0 && health.bufferedBytes == 0, "An SSL 2.0 exchange was not observed");
        const auto evidence = summarized(output.back());
        require(evidence["key_exchange"] == "RSA" && evidence["authentication"] == "RSA" &&
            evidence["encryption"] == "RC4_40" && evidence["symmetric_key_bits"] == 40 &&
            evidence["record_mac"] == "MD5" && evidence["ssl2_server_ciphers"] ==
                "SSL_CK_DES_192_EDE3_CBC_WITH_MD5, SSL_CK_RC4_128_EXPORT40_WITH_MD5" &&
            evidence["client_hello_visibility"].get<std::string>().starts_with("SSL 2.0-format") &&
            evidence["negotiation_stages"][0]["cipher_ids"] == std::array<uint32_t, 3>{0x010080, 0x020080, 0x0700c0},
            "SSL 2.0 selections were not summarized");
    }

    // STARTTLS can leave plaintext in both directions before the SSL 2.0 records begin.
    for (const size_t segment : {size_t{4096}, size_t{1}})
    {
        Counters health;
        const auto output = replayExchange({{false, concat({ascii("STARTTLS\r\n"), offer})},
            {true, concat({ascii("220 Ready\r\n"), answer})}, {false, masterKey(exportRc4, 11, 64, 0)}},
            25, segment, health);
        require(!output.empty() && output.back().version == 0x0002 && output.back().cipher == 0x020080 &&
            output.back().clientHello && output.back().serverHello && health.malformed == 0,
            "SSL 2.0 negotiation after a STARTTLS plaintext preface was missed");
    }

    // SSL 2.0 error codes are separate from TLS alerts and can end a connection before ServerHello.
    {
        Counters health;
        const auto error = sized(Buffer{0, 0, 1});
        const auto output = replayExchange({{false, concat({ascii("STARTTLS\r\n"), offer})},
            {true, concat({ascii("220 Ready\r\n"), error})}}, 25, 1, health);
        require(!output.empty() && output.back().state == "ssl2_error" &&
            output.back().crypto.ssl2ErrorCode == 1 && health.malformed == 0 &&
            summarized(output.back())["ssl2_error_name"] == "NO_CIPHER_ERROR" &&
            summarized(output.back())["ssl2_error_sender"] == "Server",
            "An SSL 2.0 error after STARTTLS was not reported");
    }

    // The server hello selects nothing: without the client's choice, or with one whose lengths disagree, the
    // cipher stays unknown rather than being reported as the null suite.
    for (const bool disagreeing : {false, true})
    {
        auto chosen = masterKey(rc4, 0, 128, 0);
        ++chosen[9];
        std::vector<Message> messages{{false, offer}, {true, answer}};
        if (disagreeing)
            messages.push_back({false, chosen});
        Counters health;
        const auto output = replayExchange(messages, 443, 4096, health);
        const auto evidence = summarized(output.back());
        require(output.back().version == 0x0002 && !output.back().cipherSelected() && health.malformed == 0 &&
            evidence["encryption"] == "" && evidence["key_exchange"] == "",
            "An SSL 2.0 cipher was reported without the client's choice");
    }

    // A resumed session sends no certificate, cipher list, or cipher choice; its padded records are encrypted
    // and end inspection instead of being searched for TLS up to the scan limit.
    {
        std::vector<Message> messages{{false, clientHello(0x0002, rc4, 16)}, {true, serverHello(0, {})},
            {false, Buffer{0, 0x18, 5}}};
        for (int index = 0; index < 18; ++index)
            messages.push_back({false, Buffer(60000, 0x78)});
        Counters health;
        const auto output = replayExchange(messages, 443, SIZE_MAX, health);
        const auto evidence = summarized(output.back());
        require(output.back().version == 0x0002 && !output.back().cipherSelected() &&
            output.back().crypto.serverCertificates.empty() && !evidence.contains("ssl2_server_ciphers") &&
            evidence["resumption"].get<std::string>().starts_with("Server reported a session-ID hit") &&
            health.malformed == 0 && health.reassemblyLimit == 0, "A resumed SSL 2.0 session was not recognized");
    }

    // A hello in SSL 2.0 format that offers TLS 1.0 is answered with TLS records, which are then read in step: an
    // encrypted handshake record that happens to begin like a hello is not parsed as one.
    for (const size_t segment : {size_t{4096}, size_t{1}})
    {
        Counters health;
        const auto output = replayExchange({{false, clientHello(0x0301, concat({Buffer{0, 0, 4, 0, 0, 10}, rc4}))},
            {true, record(hello(false, 0x0301, false, false, {}), 22)}, {false, record(Buffer{16, 0, 0, 2, 0, 0}, 22)},
            {false, Buffer{20, 3, 1, 0, 1, 1}}, {false, record(Buffer{1, 0x77, 0x77, 0x77, 0x77, 0x77}, 22)}},
            443, segment, health);
        require(!output.empty() && output.back().version == 0x0301 && output.back().cipher == 0xc02f &&
            output.back().clientHello && output.back().offeredVersions == "TLS 1.0, SSL 2.0" &&
            output.back().offeredCiphers == "0x0004, 0x000A, 0x010080" && output.back().crypto.legacyHello &&
            output.back().crypto.stages[0].legacyVersion == 0x0301 &&
            output.back().crypto.stages[0].ciphers == std::vector<uint32_t>{4, 10, 0x010080} &&
            summarized(output.back())["encryption"] == "AES_128" && health.malformed == 0 &&
            health.reassemblyLimit == 0, "An SSL 2.0-format hello that led to TLS lost its offers or its framing");
    }

    // Bytes that only resemble an SSL 2.0 hello are passed over, and a TLS hello behind them is still found.
    for (const size_t segment : {size_t{4096}, size_t{1}})
    {
        auto resembling = Buffer(offer.begin(), offer.begin() + 13);
        ++resembling[1];
        append(resembling, record(hello(true, 0x0303, false, false, {}), 22));
        Counters health;
        const auto output = replayExchange({{false, resembling}}, 443, segment, health);
        require(!output.empty() && output.back().clientHello && output.back().sni == "service.example.test" &&
            !output.back().crypto.legacyHello && health.malformed == 0,
            "A TLS hello behind bytes resembling SSL 2.0 was missed");
    }

    // Every single-byte change to the start of each message is read within its record, and a cipher is reported
    // for SSL 2.0 only when it is the one the client sent or the change was to that field.
    const std::vector<Message> exchange{{false, offer}, {true, answer}, {false, masterKey(tripleDes, 0, 128, 8)}};
    for (size_t message = 0; message < exchange.size(); ++message)
        for (size_t offset = 0; offset < std::min(exchange[message].bytes.size(), size_t{64}); ++offset)
            for (const uint8_t change : {uint8_t{1}, uint8_t{0x80}, uint8_t{0xff}})
            {
                auto changed = exchange;
                changed[message].bytes[offset] ^= change;
                Counters health;
                const auto output = replayExchange(changed, 443, 4096, health);
                require(output.empty() || output.back().version != 0x0002 || !output.back().cipherSelected() ||
                    output.back().cipher == 0x0700c0 || (message == 2 && offset >= 3 && offset <= 5),
                    "A changed SSL 2.0 exchange reported a cipher that was not sent");
            }
}

// LDAP binds, the SASL security layer or its absence afterwards, and StartTLS.
void ldapCoverage()
{
    // LDAP is BER, whose lengths need not be minimal; Windows writes four length bytes whatever the length.
    auto wide = [](uint8_t tag, const Buffer& content)
    {
        Buffer result{tag, 0x84, 0, static_cast<uint8_t>(content.size() >> 16)};
        word(result, static_cast<uint16_t>(content.size()));
        append(result, content);
        return result;
    };
    auto ldap = [&](int id, const Buffer& operation, bool windows = false)
    {
        const auto content = concat({derInt(id), operation});
        return windows ? wide(0x30, content) : der(0x30, content);
    };
    auto bindRequest = [](std::string_view name, const Buffer& authentication)
    {
        return der(0x60, concat({derInt(3), der(4, ascii(name)), authentication}));
    };
    auto sasl = [](std::string_view mechanism, const Buffer& credentials)
    {
        return der(0xa3, concat({der(4, ascii(mechanism)), der(4, credentials)}));
    };

    // A result is a code, a matched name, and diagnostic text, here the text a domain controller returns.
    auto result = [](uint8_t tag, uint8_t code, const Buffer& extra = {}, const Buffer& matched = {})
    {
        return der(tag, concat({der(0x0a, Buffer{code}), der(4, matched),
            der(4, ascii(code == 49 ? "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error" : "")),
            extra}));
    };
    auto buffer = [](const Buffer& content)
    {
        Buffer result{0, 0};
        word(result, static_cast<uint16_t>(content.size()));
        append(result, content);
        return result;
    };
    const auto search = der(0x63, concat({der(4, {}), der(0x0a, Buffer{0}), der(0x0a, Buffer{0}), derInt(0), derInt(0),
        der(1, Buffer{0}), der(0x87, ascii("objectClass")), der(0x30, {})}));
    const auto done = result(0x65, 0);
    const std::string name = "cn=backup service,dc=example,dc=test", password = "correct horse";
    auto run = [](const std::vector<Message>& messages, size_t segment = 4096, uint64_t malformed = 0)
    {
        Counters health;
        const auto output = replayExchange(messages, 389, segment, health);
        require(!output.empty() && health.malformed == malformed && health.reassemblyLimit == 0 &&
            health.bufferedBytes == 0, "An LDAP exchange was not observed or was miscounted");
        return std::pair{output.back(), summarized(output.back())};
    };

    // A simple bind sends the password as is and leaves the session unprotected. A search of the root entry before
    // the bind is ordinary and yields nothing; neither the bind name nor the password is kept.
    for (const size_t segment : {size_t{4096}, size_t{1}})
        for (const bool windows : {false, true})
        {
            const auto [observation, evidence] = run({{false, ldap(1, search, windows)}, {true, ldap(1, done, windows)},
                {false, ldap(2, bindRequest(name, der(0x80, ascii(password))), windows)},
                {true, ldap(2, result(0x61, 0), windows)}, {false, ldap(3, search, windows)},
                {true, ldap(3, done, windows)}}, segment);
            require(observation.protocol == Observation::Protocol::Ldap && observation.state == "ldap_bind_response" &&
                observation.source.address[3] == 1 && evidence["protocol"] == "LDAP" &&
                evidence["ldap_bind_request"] == nlohmann::json{{"version", 3}, {"method", "Simple"},
                    {"form", "Password"}} && evidence["ldap_plaintext_password"] == true &&
                evidence["ldap_bind_response"] == nlohmann::json{{"result_code", 0}, {"result", "success"}} &&
                evidence["ldap_messages_after_bind"] == "Plain" && evidence["ldap_session_protection"] == "None" &&
                evidence.dump().find("horse") == std::string::npos &&
                evidence.dump().find("backup") == std::string::npos, "A simple bind was not observed as sent");
        }

    // An anonymous bind and a refused one establish no session to assess, though the refused password was sent.
    {
        auto evidence = run({{false, ldap(1, bindRequest("", der(0x80, {})))}, {true, ldap(1, result(0x61, 0))},
            {false, ldap(2, search)}}).second;
        require(evidence["ldap_bind_request"]["form"] == "Anonymous" && !evidence.contains("ldap_plaintext_password") &&
            evidence["ldap_messages_after_bind"] == "Plain" && !evidence.contains("ldap_session_protection"),
            "An anonymous bind was reported as an unprotected session");
        evidence = run({{false, ldap(1, bindRequest(name, der(0x80, {})))}}).second;
        require(evidence["ldap_bind_request"]["form"] == "Unauthenticated",
            "A bind name without a password was missed");
        evidence = run({{false, ldap(1, bindRequest(name, der(0x80, ascii(password))))},
            {true, ldap(1, result(0x61, 49))}, {false, ldap(2, Buffer{0x42, 0})}}).second;
        require(evidence["ldap_bind_response"]["result"] == "invalidCredentials" &&
            evidence["ldap_plaintext_password"] == true && !evidence.contains("ldap_session_protection") &&
            evidence.dump().find("DSID") == std::string::npos, "A refused bind was reported as a session");
        evidence = run({{false, ldap(1, bindRequest("", sasl("PLAIN", ascii(password))))}}).second;
        require(evidence["ldap_bind_request"]["mechanism"] == "PLAIN" && evidence["ldap_plaintext_password"] == true &&
            !evidence.contains("spnego_token_undecoded") && evidence.dump().find("horse") == std::string::npos,
            "A PLAIN bind was not reported as a sent password, or was read as a security token");
    }

    // A recorded NTLM exchange inside GSS-SPNEGO binds: what follows the accepted bind shows whether a security
    // layer was negotiated. Kerberos wrap tokens state sealing; NTLM and DIGEST-MD5 leave a signed message in clear.
    const auto& vectors = recordedVectors();
    const auto signedSearch = ldap(3, search);
    const Buffer signature{1, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0};
    const auto oldWrap = [](uint8_t sealing)
    {
        return concat({Buffer{0x60, 0x2b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 2, 1, 0x11,
            0, sealing, sealing == 0xff ? uint8_t{0xff} : uint8_t{0}, 0xff, 0xff}, Buffer(24, 0x9d)});
    };
    for (const auto& [first, expected] : std::vector<std::pair<Buffer, const char*>>{
        {signedSearch, "None"}, {buffer(concat({signature, signedSearch})), "Signed"},
        {buffer(concat({signature, Buffer(signedSearch.size(), 0x9d)})), "Sealed"},
        {buffer(concat({Buffer{5, 4, 6, 0xff}, Buffer(40, 0x9d)})), "Sealed"},
        {buffer(concat({Buffer{5, 4, 4, 0xff}, Buffer(40, 0x9d)})), "Signed"}, {buffer(oldWrap(0x10)), "Sealed"},
        {buffer(oldWrap(0xff)), "Signed"}, {buffer(concat({signedSearch, Buffer(16, 0x9d)})), "Signed"},
        {buffer(Buffer(48, 0x9d)), "SASL security layer"}})
        for (const size_t segment : {size_t{4096}, size_t{1}})
        {
            const auto [observation, evidence] = run({
                {false, ldap(1, bindRequest("", sasl("GSS-SPNEGO", vectors.ntlmNegotiate)), true)},
                {true, ldap(1, result(0x61, 14, der(0x87, vectors.ntlmChallenge)), true)},
                {false, ldap(2, bindRequest("", sasl("GSS-SPNEGO", vectors.ntlmAuthenticate)), true)},
                {true, ldap(2, result(0x61, 0, der(0x87, vectors.sessionFinal)), true)}, {false, first}}, segment);
            require(evidence["ldap_bind_request"] == nlohmann::json{{"version", 3}, {"method", "SASL"},
                    {"mechanism", "GSS-SPNEGO"}} && evidence["ntlm_authenticate"]["nt_response"] == "NTLMv2" &&
                evidence.contains("ntlm_challenge") && evidence["spnego_server_state"] == "accept-completed" &&
                evidence["ldap_session_protection"] == expected && !evidence.contains("ldap_plaintext_password") &&
                evidence.dump().find("smbuser") == std::string::npos,
                "A SASL bind or the protection that followed it was not observed");
        }

    // Active Directory's Sicily binds carry bare NTLMSSP messages, with the challenge in the matched-name field.
    {
        const auto evidence = run({{false, ldap(1, bindRequest("", der(0x8a, ntlmType1(0x02088215))))},
            {true, ldap(1, result(0x61, 0, {}, ntlmType2(0x00008205, {}, false)))},
            {false, ldap(2, bindRequest("", der(0x8b, ntlmType3(0x200, Buffer(24, 0x66), Buffer(24, 0x77)))))},
            {true, ldap(2, result(0x61, 0))}, {false, ldap(3, search)}}).second;
        require(evidence["ldap_bind_request"]["method"] == "Sicily" && evidence.contains("ntlm_challenge") &&
            evidence["ntlm_authenticate"]["nt_response"] == "NTLMv1" &&
            evidence["ldap_session_protection"] == "None", "A Sicily bind's NTLM messages were not read");
    }

    // DIGEST-MD5 choices are useful evidence, while its identity and digest material remain private.
    {
        const auto challenge = ascii("realm=\"example.test\",nonce=\"server-secret\",qop=\"auth,auth-int,auth-conf\","
            "cipher=\"3des,des,rc4\"");
        const auto response = ascii("username=\"alice\",nonce=\"server-secret\",cnonce=\"client-secret\","
            "nc=00000001,qop=auth-conf,digest-uri=\"ldap/example.test\",response=0123456789abcdef,cipher=3des");
        const auto evidence = run({{false, ldap(1, bindRequest("", sasl("DIGEST-MD5", {})))},
            {true, ldap(1, result(0x61, 14, der(0x87, challenge)))},
            {false, ldap(2, bindRequest("", sasl("DIGEST-MD5", response)))},
            {true, ldap(2, result(0x61, 0, der(0x87, ascii("rspauth=0123456789abcdef"))))}}).second;
        require(evidence["ldap_digest_md5_challenge"]["qop"] == "auth,auth-int,auth-conf" &&
            evidence["ldap_digest_md5_response"]["qop"] == "auth-conf" &&
            evidence["ldap_digest_md5_response"]["cipher"] == "3des" &&
            evidence["ldap_digest_md5_server_proof_observed"] == true &&
            evidence.dump().find("alice") == std::string::npos &&
            evidence.dump().find("server-secret") == std::string::npos,
            "DIGEST-MD5 protection details were lost or credentials were retained");
    }

    // Connectionless LDAP is one complete BER message per UDP datagram, including ordinary search operations.
    for (const bool ipv6 : {false, true})
    {
        Counters health;
        std::vector<Observation> output;
        Engine engine(health, [&](Observation observation) { output.push_back(std::move(observation)); });
        engine.packet(ipTransport(ldap(1, bindRequest(name, der(0x80, ascii(password)))), ipv6), PacketKind::Ip, 1);
        engine.packet(ipTransport(ldap(2, search), ipv6), PacketKind::Ip, 2);
        require(output.size() == 2 && output[0].protocol == Observation::Protocol::Ldap && output[0].udp &&
            output[0].application->fields["ldap_plaintext_password"] == true &&
            output[1].application->fields["ldap_datagram_observed"] == true &&
            output[0].flowId != output[1].flowId && health.malformed == 0 && health.activeFlows == 0,
            "UDP LDAP datagrams were not inspected independently");
    }

    // SPNEGO's NegoEx and IAKerb mechanisms carry structured payloads beyond their offered OIDs.
    {
        Buffer negoex(108);
        std::copy_n("NEGOEXTS", 8, negoex.begin());
        negoex[16] = 92;
        negoex[20] = 108;
        negoex[80] = 92;
        negoex[84] = 1;
        std::fill(negoex.begin() + 92, negoex.end(), uint8_t{0x42});
        nlohmann::json evidence;
        parseSecurityBuffer(negotiationInit({NegoExOid}, negoex), false, evidence);
        require(evidence["negoex_messages"][0]["type"] == "Initiator negotiation" &&
            evidence["negoex_messages"][0]["authentication_schemes"].size() == 1 &&
            !evidence.contains("spnego_token_undecoded"), "NegoEx payload details were not decoded");
        evidence = nlohmann::json::object();
        const auto header = der(0x30, context(1, der(0x0c, ascii("EXAMPLE.TEST"))));
        parseSecurityBuffer(negotiationInit({"2b0601050205"},
            kerberosGss(0x0501, header, "2b0601050205")), false, evidence);
        require(evidence["iakerb_proxy"]["target_realm"] == "EXAMPLE.TEST" &&
            evidence["iakerb_proxy"]["cookie_present"] == false &&
            !evidence.contains("spnego_token_undecoded"), "IAKerb proxy header was not decoded");
    }

    // StartTLS hands the connection to TLS, whose hellos then describe it; the LDAP evidence stays with them.
    for (const size_t segment : {size_t{4096}, size_t{1}})
    {
        const auto oid = ascii("1.3.6.1.4.1.1466.20037");
        const auto [observation, evidence] = run({{false, ldap(1, der(0x77, der(0x80, oid)), true)},
            {true, ldap(1, result(0x78, 0, der(0x8a, oid)), true)},
            {false, record(hello(true, 0x0303, false, false, {}), 22)},
            {true, record(hello(false, 0x0303, false, false, {}), 22)}}, segment);
        require(observation.protocol == Observation::Protocol::Tls && observation.version == 0x0303 &&
            observation.clientHello && observation.sni == "service.example.test" &&
            evidence["ldap_starttls_requested"] == true && evidence["ldap_starttls_result"] == "success" &&
            !evidence.contains("ldap_bind_request"), "TLS after StartTLS was not observed");
    }

    // A successful StartTLS response can omit its response name; the request's message ID identifies it.
    for (const size_t segment : {size_t{4096}, size_t{1}})
        for (const bool namedResponse : {false, true})
        {
            const auto oid = ascii("1.3.6.1.4.1.1466.20037");
            const auto [observation, evidence] = run({
                {false, ldap(1, bindRequest(name, der(0x80, ascii(password))), true)},
                {true, ldap(1, result(0x61, 0), true)},
                {false, ldap(2, der(0x77, der(0x80, oid)), true)},
                {true, ldap(2, result(0x78, 0, namedResponse ? der(0x8a, oid) : Buffer{}), true)},
                {false, record(hello(true, 0x0303, false, false, {}), 22)},
                {true, record(hello(false, 0x0303, false, false, {}), 22)}}, segment);
            require(observation.protocol == Observation::Protocol::Tls && observation.clientHello &&
                observation.serverHello && evidence["ldap_starttls_requested"] == true &&
                evidence["ldap_starttls_result"] == "success" && !evidence.contains("ldap_session_protection"),
                "A bind hid the following LDAP StartTLS handshake");
        }
    {
        nlohmann::json evidence;
        const auto unnamed = ldap(2, result(0x78, 0));
        require(parseLdap(unnamed, evidence) && !evidence.contains("ldap_starttls_result") &&
            parseLdap(unnamed, evidence, nullptr, 3) && !evidence.contains("ldap_starttls_result"),
            "An unrelated nameless LDAP extension was labeled StartTLS");
        require(parseLdap(ldap(2, result(0x78, 49)), evidence, nullptr, 2) &&
            !evidence.contains("ldap_starttls_result") &&
            parseLdap(ldap(2, result(0x78, 0, der(0x8a, ascii("1.2.3")))), evidence, nullptr, 2) &&
            !evidence.contains("ldap_starttls_result"),
            "A failed or differently named LDAP extension was labeled StartTLS");
    }

    // A bind response whose fields overrun it is counted as malformed, and text that merely begins like an LDAP
    // message is left to the search for TLS.
    {
        auto overrun = ldap(1, result(0x61, 0));
        overrun[8] = 9;
        const auto evidence = run({{false, ldap(1, bindRequest(name, der(0x80, ascii(password))))}, {true, overrun}},
            4096, 1).second;
        require(!evidence.contains("ldap_bind_response"), "A malformed bind response produced a result");
        Counters health;
        const auto output = replayExchange({{false, concat({ascii("0\r\n\r\n01234567"),
            record(hello(true, 0x0303, false, false, {}), 22)})}}, 389, 4096, health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Tls && output.back().clientHello &&
            health.malformed == 0, "Text beginning like an LDAP message hid a TLS hello");
    }

    // No single-byte change to a bind exchange exposes the password or the bind name in what is kept.
    const std::vector<Message> exchange{{false, ldap(1, bindRequest(name, der(0x80, ascii(password))), true)},
        {true, ldap(1, result(0x61, 0), true)}, {false, ldap(2, search, true)}};
    for (size_t message = 0; message < exchange.size(); ++message)
        for (size_t offset = 0; offset < std::min(exchange[message].bytes.size(), size_t{24}); ++offset)
            for (const uint8_t change : {uint8_t{1}, uint8_t{0x80}, uint8_t{0xff}})
            {
                auto changed = exchange;
                changed[message].bytes[offset] ^= change;
                Counters health;
                for (const auto& observation : replayExchange(changed, 389, 4096, health))
                    require(summarized(observation).dump().find("horse") == std::string::npos &&
                        summarized(observation).dump().find("backup") == std::string::npos,
                        "A changed LDAP exchange kept the password or the bind name");
            }
}
}
