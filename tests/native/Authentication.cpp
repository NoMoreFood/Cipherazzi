#include "NetworkFixtures.h"

namespace Cipherazzi::Tests
{
using namespace NetworkFixtures;
void kerberosCoverage()
{
    // Recorded MIT Kerberos KDC messages, including their TCP length prefixes.
    const auto& vectors = recordedVectors();
    const auto& asRequest = vectors.asRequest;
    const auto& preauthRequired = vectors.preauthRequired;
    const auto& tgsRequest = vectors.tgsRequest;
    const auto& kerberoastReply = vectors.kerberoastReply;
    auto names = [](std::initializer_list<const char*> values)
    {
        return nlohmann::json(std::vector<std::string>(values.begin(), values.end()));
    };
    const auto offered = names({"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha384-192",
        "aes128-cts-hmac-sha256-128", "des3-cbc-sha1-kd", "rc4-hmac", "camellia128-cts-cmac", "camellia256-cts-cmac"});
    const nlohmann::json expectedAsRequest{{"krb_as_request", {{"offered_encryption_types", offered},
        {"preauthentication", names({"PA-AS-FRESHNESS", "PA-REQ-ENC-PA-REP"})},
        {"service_principal", "krbtgt/EXAMPLE.TEST"}}}};
    const nlohmann::json expectedError{{"krb_error", {{"code", 25}, {"name", "KDC_ERR_PREAUTH_REQUIRED"},
        {"preauthentication", names({"PA-FX-FAST", "PA-ETYPE-INFO2", "PA-ENC-TIMESTAMP", "PA-FX-COOKIE"})},
        {"service_principal", "krbtgt/EXAMPLE.TEST"},
        {"supported_encryption_types", names({"aes256-cts-hmac-sha1-96"})}}}};
    const nlohmann::json expectedTgsRequest{{"krb_tgs_request",
        {{"authenticator_encryption", "aes256-cts-hmac-sha1-96"}, {"offered_encryption_types", offered},
            {"preauthentication", names({"PA-TGS-REQ", "PA-FX-FAST"})}, {"service_principal", "cifs/localhost"},
            {"ticket_granting_ticket_encryption", "aes256-cts-hmac-sha1-96"}}}};
    const nlohmann::json expectedKerberoast{{"krb_tgs_reply", {{"preauthentication", names({"PA-FX-FAST"})},
        {"reply_encryption", "aes256-cts-hmac-sha1-96"}, {"service_principal", "host/rc4svc.example.test"},
        {"ticket_encryption", "rc4-hmac"}}}};

    // Evidence is identical whole or split, names only the service, and leaves the TCP stream open for later messages.
    const std::tuple<Buffer, nlohmann::json> recorded[] = {{asRequest, expectedAsRequest},
        {preauthRequired, expectedError}, {tgsRequest, expectedTgsRequest}, {kerberoastReply, expectedKerberoast}};
    for (const bool split : {false, true})
    {
        for (const auto& [bytes, expected] : recorded)
        {
            const auto outcome = observe(bytes, split);
            require(outcome.valid && !outcome.finished && outcome.reports.size() == 1 && outcome.passthrough == 0 &&
                outcome.kinds[0] == FramedMessage::Kind::Kerberos && outcome.reports[0] == expected,
                "A recorded Kerberos message was rejected, split, or mis-decoded");
            require(outcome.reports[0].dump().find("alice") == std::string::npos,
                "Kerberos evidence retained a client principal or salt");
        }
        const auto exchange = observe(concat({asRequest, tgsRequest}), split);
        require(exchange.valid && exchange.reports.size() == 2 && exchange.reports[0] == expectedAsRequest &&
            exchange.reports[1] == expectedTgsRequest, "Consecutive Kerberos messages were merged or lost");
    }

    // Constructed messages cover encryption types and options absent from the recorded set.
    auto single = [](const Buffer& message)
    {
        const auto outcome = observe(kdcFrame(message), false);
        require(outcome.valid && outcome.reports.size() == 1 && outcome.kinds[0] == FramedMessage::Kind::Kerberos,
            "A well-formed Kerberos message was not reported");
        return outcome.reports[0];
    };
    require(single(kdcReply(false, 18, 23)) == nlohmann::json{{"krb_as_reply", {
        {"ticket_encryption", "aes256-cts-hmac-sha1-96"}, {"reply_encryption", "rc4-hmac"},
        {"service_principal", "krbtgt/EXAMPLE.TEST"}}}}, "An RC4 AS reply was not reported");
    require(single(kdcReply(true, 23, 18, {preauthData(136, {})})) == nlohmann::json{{"krb_tgs_reply", {
        {"ticket_encryption", "rc4-hmac"}, {"reply_encryption", "aes256-cts-hmac-sha1-96"},
        {"service_principal", "cifs/server.example.test"}, {"preauthentication", names({"PA-FX-FAST"})}}}},
        "An RC4 service ticket was not reported");
    require(single(kdcReply(true, 99, -133)) == nlohmann::json{{"krb_tgs_reply", {
        {"ticket_encryption", "etype 99"}, {"reply_encryption", "rc4-hmac-old"},
        {"service_principal", "cifs/server.example.test"}}}}, "Unlisted encryption types were not reported by number");
    require(single(kdcRequest(
                true, {18, 17}, {preauthData(1, apRequest(18, 17, 0x20))}, kerberosTicket(23, FileService))) ==
            nlohmann::json{{"krb_tgs_request",
                {{"offered_encryption_types", names({"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"})},
                    {"preauthentication", names({"PA-TGS-REQ"})}, {"service_principal", "cifs/server.example.test"},
                    {"ticket_granting_ticket_encryption", "aes256-cts-hmac-sha1-96"},
                    {"authenticator_encryption", "aes128-cts-hmac-sha1-96"},
                    {"additional_ticket_encryption", "rc4-hmac"}}}},
        "TGS ticket, authenticator, or additional-ticket encryption was lost");
    require(single(kdcRequest(false, {23}, {preauthData(2, kerberosEncrypted(23))})) ==
            nlohmann::json{{"krb_as_request",
                {{"offered_encryption_types", names({"rc4-hmac"})}, {"preauthentication", names({"PA-ENC-TIMESTAMP"})},
                    {"preauthentication_encryption", "rc4-hmac"}, {"service_principal", "krbtgt/EXAMPLE.TEST"}}}},
        "Pre-authentication encryption was lost");
    require(single(kdcRequest(false, {18}, {}, {}, Names{"krbtgt", "\xc3\xa9"})) == nlohmann::json{{"krb_as_request", {
        {"offered_encryption_types", names({"aes256-cts-hmac-sha1-96"})}}}},
        "A non-ASCII service name was retained");

    // Error codes, optional data, and encodings that vary with the code.
    require(single(kerberosError(14)) == nlohmann::json{{"krb_error", {{"code", 14}, {"name", "KDC_ERR_ETYPE_NOSUPP"},
        {"service_principal", "krbtgt/EXAMPLE.TEST"}}}}, "An unsupported-encryption error was not reported");
    require(single(kerberosError(99, {}, false)) == nlohmann::json{{"krb_error", {{"code", 99}}}},
        "An unlisted error code was named or given a service");
    const auto salted = sequence({context(0, derInt(23)), context(1, der(0x1b, ascii("saltvalue")))});
    const auto methods = sequenceOf({preauthData(19, sequenceOf({sequence({context(0, derInt(18))}), salted,
        sequence({context(0, derInt(18))})})), preauthData(2, {})});
    const auto described = single(kerberosError(25, methods));
    require(described["krb_error"]["supported_encryption_types"] == names({"aes256-cts-hmac-sha1-96", "rc4-hmac"}) &&
            described["krb_error"]["preauthentication"] == names({"PA-ETYPE-INFO2", "PA-ENC-TIMESTAMP"}) &&
            described.dump().find("saltvalue") == std::string::npos,
        "Error pre-authentication data was lost or kept a salt");
    for (const auto& data : {sequence({context(1, derInt(2)), context(2, der(4, ascii("x")))}),
        sequenceOf({preauthData(19, ascii("zz"))}), ascii("not DER")})
        require(single(kerberosError(25, data)) == nlohmann::json{{"krb_error", {{"code", 25},
            {"name", "KDC_ERR_PREAUTH_REQUIRED"}, {"service_principal", "krbtgt/EXAMPLE.TEST"}}}},
            "Error data with another encoding changed the error report");

    // Structure errors reject the message and publish nothing, including when a stream is already established.
    auto rejected = [](const Buffer& message, const char* fault)
    {
        nlohmann::json fields = nlohmann::json::object();
        require(!parseKerberos(message, fields) && fields.empty(), fault);
        FramedStream framing;
        auto ignore = [](const FramedMessage&) { return true; };
        require(framing.feed(kdcFrame(kdcRequest(false, {18})), ignore) && !framing.feed(kdcFrame(message), ignore),
            fault);
    };
    const auto request = kdcRequest(false, {18});
    rejected(patched(request, "a103020105", "a103020104"), "A Kerberos version other than 5 was accepted");
    rejected(patched(request, "a20302010a", "a20302010c"), "A message type that disagrees with its tag was accepted");
    rejected(patched(kdcReply(false, 18, 18), "a10302010b", "a10302010d"),
        "A reply with the wrong message type was accepted");
    rejected(
        patched(kerberosError(25), "a10302011e", "a10302011f"), "An error with the wrong message type was accepted");
    rejected(kdcRequest(false, {}), "A request without encryption types was accepted");
    rejected(concat({request, Buffer{0}}), "Trailing bytes after a Kerberos message were accepted");
    rejected(der(0x6a, der(0x30, concat({context(1, derInt(5)), context(1, derInt(5))}))),
        "Repeated or unordered members were accepted");
    rejected(Buffer{0x6a, 0x81, 0x02, 0x30, 0x00}, "A non-minimal DER length was accepted");
    rejected(Buffer{0x6a, 0x80, 0x30, 0x80, 0, 0, 0, 0}, "An indefinite DER length was accepted");
    rejected(der(0x6e, Buffer{0x30, 0}), "An unexpected Kerberos tag was accepted");

    // A truncated recorded message never produces evidence.
    for (const auto* bytes : {&asRequest, &preauthRequired, &tgsRequest, &kerberoastReply})
        for (size_t size = 0; size + 4 < bytes->size(); ++size)
        {
            nlohmann::json fields = nlohmann::json::object();
            require(!parseKerberos(Bytes(*bytes).subspan(4, size), fields) && fields.empty(),
                "A truncated Kerberos message produced evidence");
        }

    // A length that disagrees with the DER message is not Kerberos; an oversized later frame stops inspection.
    auto nearMiss = asRequest;
    nearMiss[3] += 1;
    nearMiss.push_back(0);
    for (const bool split : {false, true})
    {
        const auto passthrough = observe(nearMiss, split);
        require(passthrough.valid && passthrough.reports.empty() && passthrough.passthrough == nearMiss.size(),
            "A length that disagrees with its DER message was treated as Kerberos");
        const auto oversized = observe(concat({asRequest, Buffer{0, 0x10, 0, 0, 0x6a, 0x82}}), split);
        require(!oversized.valid && oversized.limited && oversized.reports.size() == 1,
            "An oversized Kerberos frame was not bounded");
    }

    // A reply beyond 64 KiB needs a three-byte DER length and stays within the stream framing bound.
    auto largeReply = [](size_t cipher)
    {
        const auto encrypted = sequence({context(0, derInt(18)), context(2, der(4, Buffer(cipher, 0x5a)))});
        return kdcFrame(der(0x6b, der(0x30, concat({context(0, derInt(5)), context(1, derInt(11)),
            context(3, der(0x1b, ascii("EXAMPLE.TEST"))), context(4, kerberosName({"alice"})),
            context(5, kerberosTicket(23, KdcService)), context(6, encrypted)}))));
    };
    for (const bool split : {false, true})
    {
        const auto large = observe(largeReply(70000), split);
        require(large.valid && large.reports.size() == 1 && large.passthrough == 0 &&
            large.kinds[0] == FramedMessage::Kind::Kerberos && large.reports[0] == nlohmann::json{{"krb_as_reply", {
            {"ticket_encryption", "rc4-hmac"}, {"reply_encryption", "aes256-cts-hmac-sha1-96"},
            {"service_principal", "krbtgt/EXAMPLE.TEST"}}}}, "A Kerberos reply beyond 64 KiB was not reported");
    }
    auto shortened = largeReply(70000);
    shortened[7] = 0;
    const auto misdeclared = observe(shortened, true);
    require(misdeclared.valid && misdeclared.reports.empty() && misdeclared.passthrough == shortened.size(),
        "A three-byte DER length that disagrees with its frame was treated as Kerberos");
    FramedStream excessive;
    require(!excessive.feed(Bytes(largeReply(270000)).first(64), [](const FramedMessage&) { return true; }) &&
        excessive.limited(), "A Kerberos frame beyond the inspection bound was buffered");
}

void kerberosUdpCoverage()
{
    // Replay KDC messages on standard and alternate ports in both IP families.
    const auto& vectors = recordedVectors();
    const auto asReply = kdcFrame(kdcReply(false, 18, 23));
    const std::array frames{vectors.asRequest, vectors.preauthRequired, vectors.tgsRequest,
        vectors.kerberoastReply, asReply};
    const std::array<const char*, 5> fields{"krb_as_request", "krb_error", "krb_tgs_request",
        "krb_tgs_reply", "krb_as_reply"};
    for (const bool ipv6 : {false, true})
        for (const uint16_t port : {uint16_t{88}, uint16_t{19088}, uint16_t{443}})
        {
            Counters health;
            std::vector<Observation> output;
            Engine engine(health, [&](Observation observation)
            {
                if (!observation.lifecycleOnly)
                    output.push_back(std::move(observation));
            });
            auto datagram = [&](Bytes payload, bool client)
            {
                auto packet = ipTransport(payload, ipv6, true, client);
                const size_t offset = (ipv6 ? 40 : 20) + (client ? 2 : 0);
                packet[offset] = static_cast<uint8_t>(port >> 8);
                packet[offset + 1] = static_cast<uint8_t>(port);
                return packet;
            };
            int64_t timestamp = 1;
            for (size_t index = 0; index < frames.size(); ++index)
            {
                const bool client = index == 0 || index == 2;
                engine.packet(datagram(Bytes(frames[index]).subspan(4), client), PacketKind::Ip, timestamp++);
                const bool paired = index == 1 || index == 3;
                require(output.size() == index + 1 && output.back().protocol == Observation::Protocol::Kerberos &&
                    output.back().udp && output.back().application->fields.size() == (paired ? 2u : 1u) &&
                    output.back().application->fields.contains(fields[index]) &&
                    output.back().source.port == 42000 && output.back().destination.port == port &&
                    output.back().source.family == (ipv6 ? 6 : 4) &&
                    (paired ? output.back().firstUs < output.back().lastUs &&
                        output.back().flowId == output[index - 1].flowId :
                        output.back().firstUs == output.back().lastUs &&
                        (index == 0 || output.back().flowId != output[index - 1].flowId)) &&
                    output.back().endedUs == (client ? 0 : output.back().lastUs),
                    "UDP KDC messages were lost, paired ambiguously, or assigned to the wrong endpoint");
            }
            CryptoCatalog catalog;
            auto summary = nlohmann::json::parse(catalog.summarize(output[3], [](auto&, auto&, Bytes) {}).json);
            require(summary["transport"] == "UDP" && summary["krb_tgs_reply"]["ticket_encryption"] == "rc4-hmac" &&
                summary["handshake_confirmation"].get<std::string>().find("unverified") != std::string::npos &&
                summary.dump().find("alice") == std::string::npos && summary.contains("krb_tgs_request"),
                "UDP Kerberos lost weak-encryption evidence, retained an account, or failed to pair a reply");

            // Reassemble an out-of-order fragmented datagram before publishing any evidence.
            const auto fragmented = datagram(Bytes(vectors.tgsRequest).subspan(4), true);
            const auto header = ipv6 ? 40 : 20;
            std::vector<Buffer> pieces;
            for (size_t offset = 0; offset < fragmented.size() - header; offset += 64)
                pieces.push_back(ipFragment(fragmented, ipv6, offset,
                    std::min(size_t{64}, fragmented.size() - header - offset),
                    offset + 64 < fragmented.size() - header));
            for (auto piece = pieces.rbegin(); piece != pieces.rend(); ++piece)
            {
                engine.packet(*piece, PacketKind::Ip, timestamp++);
                require(output.size() == frames.size() + (piece + 1 == pieces.rend() ? 1 : 0),
                    "An incomplete fragmented Kerberos datagram produced evidence");
            }
            require(output.back().application->fields.contains("krb_tgs_request") && health.malformed == 0 &&
                health.bufferedBytes > 0 && health.activeFlows == 1,
                "UDP Kerberos fragmentation lost bounded pairing state or corrupted evidence");

            // Reject truncation, TCP prefixes, multiple messages, and invalid DER without retaining partial fields.
            const Buffer request(vectors.asRequest.begin() + 4, vectors.asRequest.end());
            for (const auto& invalid : {Buffer(request.begin(), request.end() - 1), vectors.asRequest,
                concat({request, request}), patched(Buffer(request.begin(), request.end()),
                    "a103020105", "a103020104"), ascii("unrelated UDP traffic")})
                engine.packet(datagram(invalid, true), PacketKind::Ip, timestamp++);
            auto truncated = datagram(request, true);
            truncated.pop_back();
            engine.packet(truncated, PacketKind::Ip, timestamp++);
            require(output.size() == frames.size() + 1 && health.malformed == 1 && health.truncated == 1,
                "Invalid UDP Kerberos framing produced evidence or bypassed capture-health accounting");
            engine.expire(timestamp, true);
            require(output.size() == frames.size() + 1 && health.bufferedBytes == 0 && health.activeFlows == 0,
                "Completed UDP Kerberos datagrams were emitted again during expiry");
        }

    // A retransmitted request remains one outstanding exchange and can pair with its reply.
    for (const bool ipv6 : {false, true})
    {
        Counters health;
        std::vector<Observation> output;
        Engine engine(health, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                output.push_back(std::move(observation));
        });
        const auto request = ipTransport(Bytes(vectors.asRequest).subspan(4), ipv6, true, true);
        const auto reply = ipTransport(Bytes(asReply).subspan(4), ipv6, true, false);
        engine.packet(request, PacketKind::Ip, 1);
        engine.packet(request, PacketKind::Ip, 2);
        require(output.size() == 1 && health.activeFlows == 1,
            "A retransmitted Kerberos request became a second outstanding exchange");
        engine.packet(reply, PacketKind::Ip, 3);
        require(output.size() == 2 && output.back().flowId == output.front().flowId &&
            output.back().firstUs == 1 && output.back().lastUs == 3 &&
            output.back().application->fields.contains("krb_as_request") &&
            output.back().application->fields.contains("krb_as_reply") && health.activeFlows == 0,
            "A Kerberos reply did not pair with a retransmitted request");
    }

    // Without a visible transaction identifier, distinct outstanding AS requests make an AS reply ambiguous.
    {
        Counters health;
        std::vector<Observation> output;
        Engine engine(health, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                output.push_back(std::move(observation));
        });
        const auto request = ipTransport(kdcRequest(false, {18}), false, true, true);
        const auto other = ipTransport(kdcRequest(false, {17}), false, true, true);
        const auto reply = ipTransport(Bytes(asReply).subspan(4), false, true, false);
        engine.packet(request, PacketKind::Ip, 1);
        engine.packet(other, PacketKind::Ip, 2);
        engine.packet(reply, PacketKind::Ip, 3);
        require(output.size() == 3 && output.back().application->fields.contains("krb_as_reply") &&
            !output.back().application->fields.contains("krb_as_request") &&
            output.back().flowId != output[0].flowId && output.back().flowId != output[1].flowId,
            "Concurrent Kerberos UDP requests were paired with an ambiguous reply");
        engine.expire(40000000, true);
        require(health.activeFlows == 0 && health.bufferedBytes == 0,
            "Unmatched Kerberos UDP requests were retained after expiry");
    }

    // Datagram evidence respects the shared flow-admission and metadata-memory limits.
    for (const bool flowLimit : {false, true})
    {
        EngineLimits limits;
        if (flowLimit) limits.flows = 0;
        else limits.bytes = 1;
        Counters health;
        Engine engine(health, [](Observation) { throw std::runtime_error("UDP Kerberos bypassed admission limits"); },
            limits);
        engine.packet(ipTransport(Bytes(vectors.asRequest).subspan(4), false), PacketKind::Ip, 1);
        require(flowLimit ? health.flowLimit == 1 : health.reassemblyLimit == 1,
            "UDP Kerberos did not account for its admission limit");
    }
}

void kerberosPasswordCoverage()
{
    // The AP-REQ is the recorded MIT one carried by the TGS request; the remaining parts follow RFC 3244.
    const auto& vectors = recordedVectors();
    const auto marker = fromHex("6e820273");
    const auto recorded = std::search(vectors.tgsRequest.begin(), vectors.tgsRequest.end(), marker.begin(),
        marker.end());
    require(recorded != vectors.tgsRequest.end(), "The recorded AP-REQ was missing from its TGS request");
    const Buffer recordedRequest(recorded, recorded + 4 + 0x273);
    const Names passwordService{"kadmin", "changepw"};
    const std::string text = "Failed reading application request";
    const auto change = passwordMessage(1, recordedRequest, privateMessage(18));
    const auto set = passwordMessage(0xff80, apRequest(23, 17, 0, passwordService), privateMessage(23));
    const auto reply = passwordMessage(1, apReply(17), privateMessage(17));
    const auto failure = passwordMessage(1, {}, kerberosError(60, concat({Buffer{0, 3}, ascii(text)})));
    const nlohmann::json expectedChange{{"krb_password_request", {{"operation", "Change password"},
        {"ticket_encryption", "aes256-cts-hmac-sha1-96"}, {"authenticator_encryption", "aes256-cts-hmac-sha1-96"},
        {"private_message_encryption", "aes256-cts-hmac-sha1-96"}, {"service_principal", "krbtgt/EXAMPLE.TEST"}}}};
    const nlohmann::json expectedSet{{"krb_password_request", {{"operation", "Set or change password"},
        {"ticket_encryption", "rc4-hmac"}, {"authenticator_encryption", "aes128-cts-hmac-sha1-96"},
        {"private_message_encryption", "rc4-hmac"}, {"service_principal", "kadmin/changepw"}}}};
    const nlohmann::json expectedReply{{"krb_password_reply", {{"reply_encryption", "aes128-cts-hmac-sha1-96"},
        {"private_message_encryption", "aes128-cts-hmac-sha1-96"}}}};
    const nlohmann::json expectedFailure{{"krb_error", {{"code", 60}, {"name", "KRB_ERR_GENERIC"},
        {"service_principal", "krbtgt/EXAMPLE.TEST"}}},
        {"krb_password_reply", {{"result_code", 3}, {"result", "KRB5_KPASSWD_AUTHERROR"}}}};

    // TCP evidence is identical whole or split, and a stream can carry several messages of either kind.
    const std::tuple<Buffer, nlohmann::json> messages[] = {{change, expectedChange}, {set, expectedSet},
        {reply, expectedReply}, {failure, expectedFailure}};
    for (const bool split : {false, true})
    {
        for (const auto& [message, expected] : messages)
        {
            const auto outcome = observe(kdcFrame(message), split);
            require(outcome.valid && !outcome.finished && outcome.reports.size() == 1 && outcome.passthrough == 0 &&
                outcome.kinds[0] == FramedMessage::Kind::Kerberos && outcome.reports[0] == expected,
                "A change-password message was rejected, split, or mis-decoded");
            require(outcome.reports[0].dump().find(text) == std::string::npos &&
                outcome.reports[0].dump().find("alice") == std::string::npos,
                "Change-password evidence retained result text or a client principal");
        }
        const auto stream = observe(concat({kdcFrame(change), vectors.asRequest, kdcFrame(set)}), split);
        require(stream.valid && stream.reports.size() == 3 && stream.reports[0] == expectedChange &&
            stream.reports[1].contains("krb_as_request") && stream.reports[2] == expectedSet,
            "Consecutive change-password and KDC messages were merged or lost");
    }

    // Result codes are reported as sent; an error without data states no result.
    auto failed = [](const Buffer& data)
    {
        nlohmann::json fields = nlohmann::json::object();
        require(parsePasswordChange(passwordMessage(1, {}, kerberosError(41, data)), fields) &&
            fields["krb_error"]["name"] == "KRB_AP_ERR_MODIFIED", "A change-password error reply was rejected");
        return fields["krb_password_reply"];
    };
    require(failed(Buffer{0, 9}) == nlohmann::json{{"result_code", 9}} && failed({}) == nlohmann::json::object() &&
        failed(Buffer{0, 4, 'x'}) == nlohmann::json{{"result_code", 4}, {"result", "KRB5_KPASSWD_SOFTERROR"}} &&
        failed(Buffer{5}) == nlohmann::json::object(), "A change-password result code was invented or lost");

    // Structure errors publish nothing, including after a stream has been established.
    auto rejected = [&](const Buffer& message, const char* fault)
    {
        nlohmann::json fields = nlohmann::json::object();
        require(!parsePasswordChange(message, fields) && fields.empty(), fault);
        FramedStream framing;
        auto ignore = [](const FramedMessage&) { return true; };
        require(framing.feed(kdcFrame(change), ignore) && !framing.feed(kdcFrame(message), ignore), fault);
    };
    auto resized = [](Buffer message, size_t offset)
    {
        ++message[offset + 1];
        return message;
    };
    rejected(passwordMessage(2, recordedRequest, privateMessage(18)),
        "An unknown change-password version was accepted");
    rejected(passwordMessage(1, recordedRequest, privateMessage(18, 20)),
        "A KRB-PRIV with the wrong message type was accepted");
    rejected(passwordMessage(1, recordedRequest, kerberosError(60)), "A request carrying an error was accepted");
    rejected(passwordMessage(1, recordedRequest, concat({privateMessage(18), Buffer{0}})),
        "Trailing bytes after a change-password message were accepted");
    rejected(passwordMessage(1, {}, privateMessage(18)), "A reply without an AP-REP or an error was accepted");
    rejected(passwordMessage(1, apReply(18), kerberosError(60)),
        "An authenticated reply carrying an error was accepted");
    rejected(patched(change, "a10302010e", "a10302010f"), "An AP-REQ with the wrong message type was accepted");
    rejected(resized(change, 0), "A change-password length beyond its message was accepted");
    rejected(resized(change, 4), "An AP-REQ length that overlaps the KRB-PRIV was accepted");
    rejected(resized(change, 3), "An AP-REQ length beyond its message was accepted");
    rejected(passwordMessage(1, recordedRequest, {}), "A change-password request without a KRB-PRIV was accepted");
    rejected(concat({change, Buffer{0}}), "Bytes after the declared change-password length were accepted");
    for (const auto* message : {&change, &reply, &failure})
        for (size_t size = 0; size < message->size(); ++size)
        {
            nlohmann::json fields = nlohmann::json::object();
            require(!parsePasswordChange(Bytes(*message).first(size), fields) && fields.empty(),
                "A truncated change-password message produced evidence");
        }

    // A header that disagrees with the TCP length, or one followed by another protocol, is not change-password.
    auto nearMiss = kdcFrame(change);
    nearMiss[3] += 1;
    nearMiss.push_back(0);
    const auto unrelated = concat({Buffer{0, 0, 0, 18, 0, 18, 0, 1, 0, 0, 0, 7, 0, 8}, ascii("producer")});
    for (const bool split : {false, true})
        for (const auto* bytes : std::initializer_list<const Buffer*>{&nearMiss, &unrelated})
        {
            const auto passthrough = observe(*bytes, split);
            require(passthrough.valid && passthrough.reports.empty() && passthrough.passthrough == bytes->size(),
                "A stream that only resembles a change-password header was treated as Kerberos");
        }

    // Datagrams are oriented by message kind on any port and classified by the latest evidence.
    for (const bool ipv6 : {false, true})
    {
        Counters health;
        std::vector<Observation> output;
        Engine engine(health, [&](Observation observation) { output.push_back(std::move(observation)); });
        const std::tuple<const Buffer*, bool, const char*, const char*> datagrams[] = {
            {&change, true, "krb_password_request", "kerberos_request"},
            {&reply, false, "krb_password_reply", "kerberos_reply"},
            {&failure, false, "krb_password_reply", "kerberos_error"}};
        int64_t timestamp = 1;
        for (const auto& [message, client, field, state] : datagrams)
        {
            engine.packet(ipTransport(*message, ipv6, true, client), PacketKind::Ip, timestamp++);
            require(output.size() == static_cast<size_t>(timestamp - 1) &&
                output.back().protocol == Observation::Protocol::Kerberos && output.back().udp &&
                output.back().application->fields.contains(field) && output.back().state == state &&
                output.back().source.port == 42000 && output.back().destination.port == 443 &&
                output.back().source.family == (ipv6 ? 6 : 4),
                "A change-password datagram was lost, misclassified, or assigned to the wrong endpoint");
        }
        const auto summary = summarized(output[0]);
        require(summary["transport"] == "UDP" &&
            summary["krb_password_request"] == expectedChange["krb_password_request"] &&
            summary["handshake_confirmation"].get<std::string>().find("unverified") != std::string::npos,
            "UDP change-password evidence was lost or implied a completed change");

        // A plausible header around an invalid message is counted; unrelated datagrams are left alone.
        engine.packet(ipTransport(passwordMessage(1, recordedRequest, privateMessage(18, 20)), ipv6), PacketKind::Ip,
            timestamp++);
        engine.packet(ipTransport(resized(change, 0), ipv6), PacketKind::Ip, timestamp++);
        engine.packet(ipTransport(Buffer{0, 8, 0, 2, 0, 0, 0x7e, 0}, ipv6), PacketKind::Ip, timestamp++);
        engine.expire(timestamp, true);
        require(output.size() == 3 && health.malformed == 1 && health.bufferedBytes == 0 && health.activeFlows == 0,
            "Invalid change-password datagrams produced evidence or bypassed capture-health accounting");
    }
}

void authenticationEngineCoverage()
{
    // A Kerberos exchange is its own protocol, and its state follows the latest KDC message.
    {
        const auto& vectors = recordedVectors();
        const auto& asRequest = vectors.asRequest;
        const auto& preauthRequired = vectors.preauthRequired;
        Counters health;
        auto output = replayConnection(asRequest, preauthRequired, 88, health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Kerberos &&
            output.back().state == "kerberos_error" && output.back().source.address[3] == 1 &&
            health.malformed == 0 && health.bufferedBytes == 0, "A Kerberos error exchange was not classified");
        auto evidence = summarized(output.back());
        require(evidence["protocol"] == "Kerberos" && evidence.contains("krb_as_request") &&
                evidence["krb_error"]["code"] == 25 &&
                evidence["handshake_confirmation"].get<std::string>().find("unverified") != std::string::npos,
            "Kerberos evidence was lost or implied authentication");
        Counters replyHealth;
        output = replayConnection(asRequest, kdcFrame(kdcReply(false, 18, 23)), 88, replyHealth);
        require(!output.empty() && output.back().state == "kerberos_reply" && replyHealth.malformed == 0,
            "A Kerberos reply exchange was not classified");
        evidence = summarized(output.back());
        require(evidence["krb_as_reply"]["reply_encryption"] == "rc4-hmac" &&
                evidence["krb_as_request"]["offered_encryption_types"].size() == 8,
            "Kerberos request and reply evidence were not merged");
        Counters badHealth;
        output = replayConnection(asRequest, concat({preauthRequired, kdcFrame(Buffer{0x6b, 0x01, 0x00})}), 88,
            badHealth);
        require(badHealth.malformed == 1, "A malformed KDC reply was not counted");
    }

    // A change-password exchange joins its request and reply without stating whether the password changed.
    {
        const auto request = kdcFrame(passwordMessage(0xff80, apRequest(18, 18, 0x20, Names{"kadmin", "changepw"}),
            privateMessage(18)));
        Counters health;
        auto output = replayConnection(request, kdcFrame(passwordMessage(1, apReply(18), privateMessage(18))), 464,
            health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Kerberos &&
            output.back().state == "kerberos_reply" && output.back().destination.port == 464 &&
            health.malformed == 0 && health.bufferedBytes == 0, "A change-password exchange was not classified");
        auto evidence = summarized(output.back());
        require(evidence["protocol"] == "Kerberos" &&
            evidence["krb_password_request"]["service_principal"] == "kadmin/changepw" &&
            evidence["krb_password_reply"]["private_message_encryption"] == "aes256-cts-hmac-sha1-96" &&
            !evidence["krb_password_reply"].contains("result") &&
            evidence["handshake_confirmation"].get<std::string>().find("unverified") != std::string::npos,
            "Change-password evidence was lost or implied a completed change");
        Counters failureHealth;
        output = replayConnection(request, kdcFrame(passwordMessage(1, {}, kerberosError(60, Buffer{0, 5}))), 464,
            failureHealth);
        require(!output.empty() && output.back().state == "kerberos_error" && failureHealth.malformed == 0 &&
            summarized(output.back())["krb_password_reply"]["result"] == "KRB5_KPASSWD_ACCESSDENIED",
            "A refused password change was not classified");
        Counters badHealth;
        output = replayConnection(request, kdcFrame(passwordMessage(1, apReply(18), privateMessage(18, 22))), 464,
            badHealth);
        require(badHealth.malformed == 1, "A malformed change-password reply was not counted");
    }

    // A failed NTLM logon remains SMB evidence and is distinguished from negotiation only.
    {
        const auto& vectors = recordedVectors();
        const auto& negotiateToken = vectors.negotiateToken;
        const auto& ntlmNegotiate = vectors.ntlmNegotiate;
        const auto& ntlmChallenge = vectors.ntlmChallenge;
        const auto& ntlmAuthenticate = vectors.ntlmAuthenticate;
        Counters health;
        const auto failure =
            smb2Frame(1, true, 0xc000006d, concat({little(9, 2), Buffer{0, 0}, little(0, 4), Buffer{0}}));
        auto output = replayConnection(
            concat({sessionSetupRequest(ntlmNegotiate), sessionSetupRequest(ntlmAuthenticate)}),
            concat({negotiateResponse(negotiateToken), sessionSetupResponse(0xc0000016, 0, ntlmChallenge), failure}),
            445, health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Smb &&
                output.back().state == "smb_authentication" && health.malformed == 0,
            "An SMB logon failure was not classified");
        const auto evidence = summarized(output.back());
        require(evidence["protocol"] == "SMB" && evidence["ntlm_authenticate"]["nt_response"] == "NTLMv2" &&
                evidence["smb_session_setup_status"] == "0xC000006D" &&
                evidence["spnego_server_mechanisms"] == nlohmann::json::array({"NTLM"}) &&
                evidence.dump().find("smbuser") == std::string::npos,
            "SMB authentication evidence was lost or kept an account name");
    }
}
}
