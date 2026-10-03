#include "NetworkFixtures.h"

namespace Cipherazzi::Tests
{
using namespace NetworkFixtures;

// SMB1 NEGOTIATE exposes public dialect offers and server security mode without implying authentication.
void smbLegacyCoverage()
{
    auto legacyFrame = [](bool response, uint8_t command, uint32_t status, Bytes parameters, Bytes data)
    {
        Buffer message{0xff, 'S', 'M', 'B', command};
        for (int shift = 0; shift < 32; shift += 8)
            message.push_back(static_cast<uint8_t>(status >> shift));
        message.push_back(response ? 0x98 : 0x18);
        message.resize(32, 0);
        message[10] = 0x01;
        message[11] = 0xc8;
        message.push_back(static_cast<uint8_t>(parameters.size() / 2));
        append(message, parameters);
        message.push_back(static_cast<uint8_t>(data.size()));
        message.push_back(static_cast<uint8_t>(data.size() >> 8));
        append(message, data);
        Buffer result{0, static_cast<uint8_t>(message.size() >> 16)};
        word(result, static_cast<uint16_t>(message.size()));
        append(result, message);
        return result;
    };
    auto dialects = [](std::initializer_list<const char*> names)
    {
        Buffer data;
        for (const auto* name : names)
        {
            data.push_back(2);
            for (const char* character = name;; ++character)
            {
                data.push_back(static_cast<uint8_t>(*character));
                if (!*character)
                    break;
            }
        }
        return data;
    };
    auto ntParameters = [](uint8_t mode, uint32_t capabilities, uint8_t challenge)
    {
        Buffer parameters(34, 0);
        parameters[0] = 5;
        parameters[2] = mode;
        for (int index = 0; index < 4; ++index)
            parameters[19 + index] = static_cast<uint8_t>(capabilities >> (index * 8));
        parameters[33] = challenge;
        return parameters;
    };
    auto request = [&](std::initializer_list<const char*> names)
    {
        return legacyFrame(false, 0x72, 0, {}, dialects(names));
    };

    // Feed one byte at a time; returns emitted field sets so split-frame handling is covered.
    auto feedBytes = [](FramedStream& framing, const Buffer& bytes, std::vector<nlohmann::json>& reports)
    {
        for (size_t offset = 0; offset < bytes.size(); ++offset)
            if (!framing.feed(Bytes(bytes).subspan(offset, 1), [&](const FramedMessage& message)
            {
                require(message.kind == FramedMessage::Kind::Smb, "SMB1 evidence used the wrong framed kind");
                reports.push_back(message.fields);
                return true;
            }))
                return false;
        return true;
    };

    // A multi-protocol request retains its ordered offers and identifies the SMB2 hand-off.
    const std::vector<std::string> offered{"PC NETWORK PROGRAM 1.0", "LANMAN1.0", "LM1.2X002", "LANMAN2.1",
        "NT LM 0.12", "SMB 2.002", "SMB 2.???"};
    {
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, request({"PC NETWORK PROGRAM 1.0", "LANMAN1.0", "LM1.2X002", "LANMAN2.1",
            "NT LM 0.12", "SMB 2.002", "SMB 2.???"}), reports) && reports.size() == 1,
            "A fragmented SMB1 multi-protocol request was rejected or repeated");
        const auto& fields = reports[0];
        require(fields["smb_legacy_offered_dialects"] == nlohmann::json(offered) &&
            fields["smb_legacy_smb2_dialect_offered"] == true &&
            fields["smb_transport_framing"] == "TCP session framing" &&
            !fields.contains("smb_offered_dialects") && !fields.contains("smb_selected_dialect") &&
            !fields.contains("smb_signed_message_observed") && !fields.contains("smb_encrypted_transform_observed"),
            "SMB1 dialect offers were lost or implied SMB2, signing, or encryption evidence");
    }
    for (const auto* smb2Name : {"SMB 2.002", "SMB 2.???"})
    {
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, request({"NT LM 0.12", smb2Name}), reports) && reports.size() == 1 &&
            reports[0]["smb_legacy_smb2_dialect_offered"] == true, "An SMB2 hand-off name was not recognized");
    }
    {
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, request({"NT LM 0.12", "SMB 2.xxx"}), reports) && reports.size() == 1 &&
            reports[0]["smb_legacy_smb2_dialect_offered"] == false,
            "An unrecognized SMB2-like name implied an SMB2 offer");
        FramedStream legacyOnly;
        reports.clear();
        require(feedBytes(legacyOnly, request({"NT LM 0.12"}), reports) && reports.size() == 1 &&
            reports[0]["smb_legacy_smb2_dialect_offered"] == false,
            "An SMB1-only request implied an SMB2 offer");
    }

    // NT LM 0.12 responses expose independent signing and security-mode flags without verifying signatures.
    const Buffer guid(16 + 4, 0x42);
    for (const auto& [mode, enabled, required] : {std::tuple{0x0f, true, true}, {0x07, true, false},
        {0x03, false, false}})
    {
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, legacyFrame(true, 0x72, 0, ntParameters(static_cast<uint8_t>(mode),
            0x80000400u, 0), guid), reports) && reports.size() == 1,
            "A fragmented SMB1 NT LM 0.12 response was rejected or repeated");
        const auto& fields = reports[0];
        require(fields["smb_legacy_selected_dialect_index"] == 5 &&
            fields["smb_legacy_response_format"] == "NT LM 0.12" &&
            fields["smb_server_signing_enabled"] == enabled && fields["smb_server_signing_required"] == required &&
            fields["smb_legacy_encrypted_passwords"] == true && fields["smb_legacy_extended_security"] == true &&
            fields["smb_legacy_server_capabilities"] == 0x80000400u &&
            !fields.contains("smb_signed_message_observed") && !fields.contains("smb_server_capabilities"),
            "SMB1 server security mode or capabilities were misreported");
    }
    {
        // Challenge-response servers carry the challenge in the data area instead of extended security.
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, legacyFrame(true, 0x72, 0, ntParameters(0x03, 0x00000400u, 8),
            Buffer(8 + 6, 7)), reports) && reports.size() == 1 &&
            reports[0]["smb_legacy_extended_security"] == false &&
            reports[0]["smb_server_signing_enabled"] == false,
            "An SMB1 challenge-response negotiation was misclassified");
        bool retainedChallenge = false;
        for (const auto& item : reports[0].items())
            retainedChallenge |= item.key().find("challenge") != std::string::npos;
        require(!retainedChallenge, "An SMB1 server challenge was retained");
    }

    // Pre-NT dialects have no signing negotiation, and a rejected dialect list selects nothing.
    {
        Buffer parameters(26, 0);
        parameters[0] = 3;
        parameters[2] = 3;
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, legacyFrame(true, 0x72, 0, parameters, Buffer(8, 1)), reports) &&
            reports.size() == 1 && reports[0]["smb_legacy_response_format"] == "LAN Manager" &&
            reports[0]["smb_legacy_encrypted_passwords"] == true &&
            !reports[0].contains("smb_server_signing_enabled") &&
            !reports[0].contains("smb_server_signing_required"),
            "A LAN Manager negotiation fabricated signing evidence");
    }
    {
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, legacyFrame(true, 0x72, 0, Buffer{0xff, 0xff}, {}), reports) &&
            reports.size() == 1 && reports[0]["smb_legacy_dialect_rejected"] == true &&
            reports[0]["smb_legacy_selected_dialect_index"] == 0xffff &&
            !reports[0].contains("smb_legacy_response_format"),
            "A rejected SMB1 dialect list implied a selection");
        FramedStream core;
        reports.clear();
        require(feedBytes(core, legacyFrame(true, 0x72, 0, Buffer{0, 0}, {}), reports) &&
            reports.size() == 1 && reports[0]["smb_legacy_response_format"] == "Core",
            "A core-protocol SMB1 response was not recognized");
    }

    // Error replies and later SMB1 commands are framed but contribute no negotiation evidence.
    {
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, legacyFrame(true, 0x72, 0xc00000bb, {}, {}), reports) &&
            feedBytes(framing, legacyFrame(false, 0x75, 0, Buffer(8, 0), Buffer(8, 0)), reports) &&
            reports.empty(), "SMB1 error replies or later commands produced negotiation evidence");

        // Signing is observed in the common header even when the command payload is not decoded.
        auto signedMessage = legacyFrame(false, 0x75, 0, Buffer(8, 0), Buffer(8, 0));
        signedMessage[14] |= 4;
        require(feedBytes(framing, signedMessage, reports) && reports.size() == 1 &&
            reports[0]["smb_signed_message_observed"] == true &&
            !reports[0].contains("smb_legacy_offered_dialects"),
            "A signed SMB1 command did not report its header signing flag");
    }

    // A client sends its SMB1 hand-off request and then a real SMB2 NEGOTIATE on the same stream.
    {
        Buffer smb2(104, 0);
        smb2[0] = 0xfe; smb2[1] = 'S'; smb2[2] = 'M'; smb2[3] = 'B';
        smb2[4] = 64;
        smb2[64] = 36;
        smb2[66] = 2;
        smb2[68] = 1;
        smb2[100] = 2; smb2[101] = 2; smb2[102] = 2; smb2[103] = 3;
        Buffer sequence = request({"NT LM 0.12", "SMB 2.???"});
        Buffer frame{0, 0};
        word(frame, static_cast<uint16_t>(smb2.size()));
        append(frame, smb2);
        append(sequence, frame);
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, sequence, reports) && reports.size() == 2 &&
            reports[0].contains("smb_legacy_offered_dialects") && reports[1].contains("smb_offered_dialects") &&
            !reports[1].contains("smb_legacy_offered_dialects"),
            "SMB1 hand-off displaced or duplicated the following SMB2 negotiation");
    }

    // NetBIOS session setup precedes SMB1 on legacy transports.
    {
        Buffer transcript{0x81, 0, 0, 68};
        for (int name = 0; name < 2; ++name)
        {
            transcript.push_back(32);
            transcript.insert(transcript.end(), 32, 'A');
            transcript.push_back(0);
        }
        append(transcript, request({"NT LM 0.12"}));
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        require(feedBytes(framing, transcript, reports) && reports.size() == 1 &&
            reports[0]["smb_transport_framing"] == "NetBIOS over TCP" &&
            reports[0].contains("smb_legacy_offered_dialects"),
            "NetBIOS session setup displaced SMB1 negotiation");
    }

    // Truncation emits nothing, and malformed negotiations are rejected before values are exposed.
    {
        const auto valid = request({"NT LM 0.12", "SMB 2.???"});
        for (size_t length = 0; length < valid.size(); ++length)
        {
            FramedStream truncated;
            int emitted = 0;
            require(truncated.feed(Bytes(valid).first(length), [&](const FramedMessage&) { ++emitted; return true; }) &&
                emitted == 0, "A truncated SMB1 negotiation produced evidence");
        }
        auto rejects = [](const Buffer& bytes)
        {
            FramedStream framing;
            int emitted = 0;
            const bool accepted = framing.feed(bytes, [&](const FramedMessage&) { ++emitted; return true; });
            return !accepted && emitted == 0;
        };
        auto unterminated = dialects({"NT LM 0.12"});
        unterminated.pop_back();
        require(rejects(legacyFrame(false, 0x72, 0, {}, unterminated)), "An unterminated SMB1 dialect was accepted");
        require(rejects(legacyFrame(false, 0x72, 0, {}, Buffer{3, 'A', 0})),
            "An SMB1 dialect with an invalid buffer format was accepted");
        require(rejects(legacyFrame(false, 0x72, 0, {}, Buffer{2, 'A', 7, 'B', 0})),
            "A non-printable SMB1 dialect was accepted");
        require(rejects(legacyFrame(false, 0x72, 0, {}, Buffer{2, 0})),
            "An empty SMB1 dialect was accepted");
        require(rejects(legacyFrame(false, 0x72, 0, Buffer{0, 0}, dialects({"NT LM 0.12"}))),
            "An SMB1 request with parameters was accepted");
        require(rejects(legacyFrame(false, 0x72, 0, {}, {})), "An empty SMB1 dialect list was accepted");
        std::vector<const char*> excessive(33, "NT LM 0.12");
        Buffer many;
        for (const auto* name : excessive)
            append(many, dialects({name}));
        require(rejects(legacyFrame(false, 0x72, 0, {}, many)), "An excessive SMB1 dialect list was accepted");

        // Byte count must match the frame exactly.
        auto mismatch = legacyFrame(false, 0x72, 0, {}, dialects({"NT LM 0.12"}));
        mismatch[4 + 32 + 1] ^= 1;
        require(rejects(mismatch), "An SMB1 byte count outside the frame was accepted");
        require(rejects(legacyFrame(true, 0x72, 0, ntParameters(0x10, 0x80000400u, 0), guid)),
            "Reserved SMB1 security-mode bits were accepted");
        require(rejects(legacyFrame(true, 0x72, 0, ntParameters(0x0f, 0x80000400u, 8), guid)),
            "An extended-security SMB1 response with a challenge was accepted");
        require(rejects(legacyFrame(true, 0x72, 0, ntParameters(0x0f, 0x80000400u, 0), Buffer(8, 0))),
            "An extended-security SMB1 response without a server GUID was accepted");
        require(rejects(legacyFrame(true, 0x72, 0, ntParameters(0x03, 0x00000400u, 9), Buffer(8, 0))),
            "An SMB1 challenge longer than its data area was accepted");
        require(!rejects(legacyFrame(true, 0x72, 0, Buffer(34, 0), {})),
            "A valid zero-index SMB1 response was rejected");
        auto badIndex = ntParameters(0x03, 0, 0);
        badIndex[0] = 0xff;
        badIndex[1] = 0xff;
        require(rejects(legacyFrame(true, 0x72, 0, badIndex, {})),
            "A rejected dialect index inside a full NT LM 0.12 response was accepted");
        require(rejects(legacyFrame(true, 0x72, 0, Buffer(10, 0), {})),
            "An unknown SMB1 negotiate response layout was accepted");
        require(rejects(legacyFrame(true, 0x72, 0, Buffer{0, 0}, Buffer{1})),
            "A core SMB1 response with trailing data was accepted");
    }

    // The reply's index names an entry of the offer sent in the other direction of the same connection.
    {
        auto negotiated = [&](const Buffer& response)
        {
            Counters health;
            const auto output = replayConnection(request({"PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12"}),
                response, 445, health);
            require(!output.empty() && output.back().protocol == Observation::Protocol::Smb &&
                output.back().state == "smb_negotiation" && health.malformed == 0 && health.bufferedBytes == 0,
                "An SMB1 negotiation was not replayed as SMB evidence");
            return summarized(output.back());
        };
        auto indexed = [&](uint8_t index)
        {
            auto parameters = ntParameters(0x03, 0x00000400u, 8);
            parameters[0] = index;
            return legacyFrame(true, 0x72, 0, parameters, Buffer(8 + 6, 7));
        };
        const auto selected = negotiated(indexed(2));
        require(selected["smb_legacy_selected_dialect"] == "NT LM 0.12" &&
            selected["smb_legacy_selected_dialect_index"] == 2 && selected["smb_legacy_offered_dialects"].size() == 3,
            "The selected SMB1 index was not resolved against the client's offer");
        require(negotiated(legacyFrame(true, 0x72, 0, Buffer{0, 0}, {}))["smb_legacy_selected_dialect"] ==
            "PC NETWORK PROGRAM 1.0", "A core-protocol SMB1 selection was not resolved");
        require(!negotiated(indexed(3)).contains("smb_legacy_selected_dialect") &&
            !negotiated(legacyFrame(true, 0x72, 0, Buffer{0xff, 0xff}, {})).contains("smb_legacy_selected_dialect"),
            "An SMB1 index outside the offer or a rejected offer was given a dialect name");

        // An index without its offer stays unresolved, and a changed offer replaces an earlier name.
        nlohmann::json fields{{"smb_legacy_selected_dialect_index", 0}};
        resolveNegotiation(fields);
        require(!fields.contains("smb_legacy_selected_dialect"), "An SMB1 index was resolved without its offer");
        fields["smb_legacy_offered_dialects"] = nlohmann::json::array({"LANMAN1.0"});
        resolveNegotiation(fields);
        require(fields["smb_legacy_selected_dialect"] == "LANMAN1.0", "A later SMB1 offer was not resolved");
        fields["smb_legacy_selected_dialect_index"] = 1;
        resolveNegotiation(fields);
        require(!fields.contains("smb_legacy_selected_dialect"), "A stale SMB1 dialect name was retained");
    }

    // SESSION_SETUP password fields are classified by their form and by the mode the server negotiated.
    {
        auto passwords = [&](Bytes insensitive, Bytes sensitive, bool named = true)
        {
            Buffer parameters(26, 0), data(insensitive.begin(), insensitive.end());
            parameters[0] = 0xff;
            parameters[14] = static_cast<uint8_t>(insensitive.size());
            parameters[16] = static_cast<uint8_t>(sensitive.size());
            append(data, sensitive);
            data.resize(data.size() + (data.size() % 2 ? 0 : 1) + 2, 0);
            if (named)
                data[data.size() - 2] = 'a';
            append(data, Buffer{0, 0});
            return legacyFrame(false, 0x73, 0, parameters, data);
        };
        auto exchanged = [&](uint8_t mode, const Buffer& setup, const Buffer& reply)
        {
            Counters health;
            auto client = request({"NT LM 0.12"});
            auto server = legacyFrame(true, 0x72, 0, ntParameters(mode, 0x00000400u, 8), Buffer(8 + 6, 7));
            append(client, setup);
            append(server, reply);
            const auto output = replayConnection(client, server, 445, health);
            require(!output.empty() && output.back().state == "smb_authentication" && health.malformed == 0 &&
                health.bufferedBytes == 0, "An SMB1 session setup was not replayed as SMB evidence");
            return summarized(output.back());
        };
        const Buffer lanManager(24, 0x11), challengeResponse(24, 0x22), accepted{0xff, 0, 0, 0, 1, 0};
        const auto success = legacyFrame(true, 0x73, 0, accepted, {});
        Buffer second(52, 0);
        second[16] = second[17] = 1;

        const auto first = exchanged(0x03, passwords(lanManager, challengeResponse), success);
        require(first["smb_legacy_nt_response"] == "NTLMv1" && first["smb_legacy_lm_response"] == "LM" &&
            first["smb_session_setup_status"] == "0x00000000" && first["smb_session_guest"] == true &&
            !first.contains("smb_legacy_plaintext_password") && !first.contains("smb_legacy_anonymous_session"),
            "SMB1 LM and NTLMv1 responses were not classified");
        const auto repeated = exchanged(0x03, passwords(challengeResponse, challengeResponse), success);
        require(repeated["smb_legacy_nt_response"] == "NTLMv1" &&
            repeated["smb_legacy_lm_response"] == "same as NT response",
            "An NTLMv1 response repeated in the LM field was reported as an LM response");
        const auto modern = exchanged(0x03, passwords(lanManager, second), success);
        require(modern["smb_legacy_nt_response"] == "NTLMv2" && modern["smb_legacy_lm_response"] == "LMv2",
            "SMB1 NTLMv2 responses were not classified");

        // A server without challenge/response support receives the password itself, whatever its length.
        for (const auto& password : {Buffer{'h', 'u', 'n', 't', 'e', 'r', '2', 0}, lanManager})
        {
            const auto clear = exchanged(0x01, passwords(password, {}), success);
            require(clear["smb_legacy_plaintext_password"] == true && !clear.contains("smb_legacy_lm_response") &&
                !clear.contains("smb_legacy_nt_response") && clear.dump().find("hunter") == std::string::npos,
                "A plaintext SMB1 password was not reported or was retained");
        }
        const auto odd = exchanged(0x03, passwords(Buffer(9, 'x'), {}), success);
        require(odd["smb_legacy_plaintext_password"] == true,
            "A password field that is no challenge response was not reported as plaintext");
        const auto null = exchanged(0x03, passwords(Buffer{0}, {}, false), success);
        require(null["smb_legacy_anonymous_session"] == true && !null.contains("smb_legacy_plaintext_password") &&
            !null.contains("smb_legacy_nt_response"), "An SMB1 null session was not recognized");

        // Extended security carries NTLMSSP in a security blob, and a refused logon reports only its status.
        Buffer negotiate{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, 1, 0, 0, 0, 0x07, 0x82, 0x08, 0xa2}, challenge(48, 0);
        std::copy_n(negotiate.begin(), 8, challenge.begin());
        challenge[8] = 2;
        Buffer blobRequest(24, 0), blobReply{0xff, 0, 0, 0, 0, 0, 48, 0};
        blobRequest[0] = 0xff;
        blobRequest[14] = 16;
        const auto extended = exchanged(0x03, legacyFrame(false, 0x73, 0, blobRequest, negotiate),
            legacyFrame(true, 0x73, 0xc0000016, blobReply, challenge));
        require(extended.contains("ntlm_negotiate") && extended.contains("ntlm_challenge") &&
            extended["smb_session_setup_status"] == "0xC0000016" && !extended.contains("smb_session_guest") &&
            !extended.contains("smb_legacy_session_setup"), "An SMB1 security blob exchange was not decoded");
        const auto refused = exchanged(0x03, passwords(lanManager, challengeResponse),
            legacyFrame(true, 0x73, 0xc000006d, {}, {}));
        require(refused["smb_session_setup_status"] == "0xC000006D" && !refused.contains("smb_session_guest"),
            "A refused SMB1 logon lost its status or reported session flags");

        // Lengths that run past the message end inspection instead of exposing bytes beyond the fields.
        for (auto malformed : {passwords(lanManager, challengeResponse), legacyFrame(false, 0x73, 0, blobRequest,
            negotiate), legacyFrame(true, 0x73, 0, blobReply, challenge)})
        {
            const bool reply = (malformed[13] & 0x80) != 0;
            malformed[4 + 33 + (reply ? 6 : 14)] = 200;
            FramedStream framing;
            require(!framing.feed(malformed, [](const FramedMessage&) { return true; }),
                "An SMB1 session setup length beyond its message was accepted");
        }
    }
}

void smbAuthenticationCoverage()
{
    // Recorded Samba SMB2 security buffers: NEGOTIATE response, NTLMSSP exchange, and final SPNEGO response.
    const auto& vectors = recordedVectors();
    const auto& negotiateToken = vectors.negotiateToken;
    const auto& ntlmNegotiate = vectors.ntlmNegotiate;
    const auto& ntlmChallenge = vectors.ntlmChallenge;
    const auto& ntlmAuthenticate = vectors.ntlmAuthenticate;
    const auto& sessionFinal = vectors.sessionFinal;
    auto names = [](std::initializer_list<const char*> values)
    {
        return nlohmann::json(std::vector<std::string>(values.begin(), values.end()));
    };
    const auto flagNames =
        names({"Sign", "NTLM", "Always sign", "Extended session security", "128-bit", "Key exchange"});
    const nlohmann::json expectedNegotiate{{"flags", "0x62088215"}, {"flag_names", flagNames}};
    const nlohmann::json expectedChallenge{{"flags", "0x628A8215"}, {"flag_names", names({"Sign", "NTLM", "Always sign",
        "Extended session security", "Target info", "128-bit", "Key exchange"})},
        {"target_info_attributes", names({"NetBIOS domain name", "NetBIOS computer name", "DNS domain name",
        "DNS computer name", "Timestamp"})}};
    const nlohmann::json expectedAuthenticate{{"anonymous", false}, {"attributes", names({"NetBIOS domain name",
        "NetBIOS computer name", "DNS domain name", "DNS computer name", "Timestamp", "Flags", "Single host",
        "Channel bindings", "Target name"})}, {"channel_bindings", false}, {"encrypted_session_key", true},
        {"flag_names", flagNames}, {"flags", "0x62088215"}, {"lm_response", "zero-filled"},
        {"message_integrity_code", true}, {"nt_response", "NTLMv2"}};

    // The exchange is reported identically whole or split, without the account, domain, or workstation names.
    for (const bool split : {false, true})
    {
        const auto client = observe(concat({sessionSetupRequest(ntlmNegotiate), sessionSetupRequest(ntlmAuthenticate)}),
            split);
        require(client.valid && client.reports.size() == 2 && client.kinds[0] == FramedMessage::Kind::Smb &&
            client.reports[0]["ntlm_negotiate"] == expectedNegotiate &&
            client.reports[0]["spnego_client_mechanisms"] == names({"NTLM"}) &&
            !client.reports[0].contains("spnego_token_undecoded") &&
            client.reports[1]["ntlm_authenticate"] == expectedAuthenticate &&
            client.reports[1]["spnego_client_mech_list_mic"] == true &&
            !client.reports[0].contains("smb_session_setup_status"), "Recorded client NTLM messages were mis-decoded");
        for (const auto& report : client.reports)
            for (const auto* name : {"smbuser", "TESTGRP"})
                require(
                    report.dump().find(name) == std::string::npos, "NTLM evidence retained an account or domain name");
        const auto server = observe(concat({negotiateResponse(negotiateToken),
            sessionSetupResponse(0xc0000016, 0, ntlmChallenge), sessionSetupResponse(0, 0, sessionFinal)}), split);
        require(server.valid && server.reports.size() == 3 &&
                server.reports[0]["spnego_server_mechanisms"] == names({"NTLM"}) &&
                !server.reports[0].contains("smb_session_setup_status") &&
                server.reports[1]["ntlm_challenge"] == expectedChallenge &&
                server.reports[1]["smb_session_setup_status"] == "0xC0000016" &&
                server.reports[1]["spnego_server_state"] == "accept-incomplete" &&
                server.reports[1]["spnego_server_selected_mechanism"] == "NTLM" &&
                !server.reports[1].contains("smb_session_guest") &&
                server.reports[2]["smb_session_setup_status"] == "0x00000000" &&
                server.reports[2]["smb_session_guest"] == false &&
                server.reports[2]["smb_session_anonymous"] == false &&
                server.reports[2]["smb_session_encryption_required"] == false &&
                server.reports[2]["spnego_server_state"] == "accept-completed" &&
                server.reports[2]["spnego_server_mech_list_mic"] == true,
            "Recorded server SPNEGO messages were mis-decoded");
    }

    // NTLM response strength is derived from the response structures and flags, never from account data.
    const uint32_t v2Flags = 0x62088215;
    const auto weak = ntlmEvidence(ntlmType3(0x200, Buffer(24, 0x66), Buffer(24, 0x77)), false, "ntlm_authenticate");
    require(weak["nt_response"] == "NTLMv1" && weak["lm_response"] == "LM" && weak["message_integrity_code"] == false &&
            weak["channel_bindings"] == false && !weak.contains("attributes"),
        "A plain NTLMv1 response was not identified");
    Buffer repeatedResponse(24);
    for (size_t index = 0; index < repeatedResponse.size(); ++index)
        repeatedResponse[index] = static_cast<uint8_t>(index + 1);
    for (const uint32_t flags : {0x200u, 0x80200u})
    {
        const auto repeated = ntlmEvidence(ntlmType3(flags, repeatedResponse, repeatedResponse), false,
            "ntlm_authenticate");
        require(repeated["nt_response"] == (flags == 0x200 ? "NTLMv1" : "NTLMv1 with extended session security") &&
            repeated["lm_response"] == "same as NT response",
            "An NTLMv1 response repeated in the LM field was reported as LM");
    }
    const auto repeatedSmb = observe(sessionSetupRequest(ntlmType3(0x200, repeatedResponse, repeatedResponse)), true);
    require(repeatedSmb.valid && repeatedSmb.reports.size() == 1 &&
        repeatedSmb.reports[0]["ntlm_authenticate"]["lm_response"] == "same as NT response",
        "An SMB2 session setup reported a repeated NTLMv1 response as LM");
    const auto session = ntlmEvidence(ntlmType3(0x80200, concat({Buffer(8, 0x66), Buffer(16, 0)}), Buffer(24, 0x77)),
        false, "ntlm_authenticate");
    require(session["nt_response"] == "NTLMv1 with extended session security" &&
        session["lm_response"] == "NTLM2 session client challenge", "NTLMv1 session security was not identified");
    const auto pairs = concat({avPair(7, Buffer(8, 1)), avPair(6, little(2, 4)), avPair(10, Buffer(16, 9)),
        avPair(9, utf16("cifs/server")), avPair(0x77, Buffer(2, 1))});
    const auto strong = ntlmEvidence(ntlmType3(v2Flags, Buffer(24, 0x55), ntlmV2Response(pairs, 4)), false,
        "ntlm_authenticate");
    require(strong["nt_response"] == "NTLMv2" && strong["lm_response"] == "LMv2" &&
        strong["message_integrity_code"] == true && strong["channel_bindings"] == true &&
        strong["attributes"] == names({"Timestamp", "Flags", "Channel bindings", "Target name", "AV pair 119"}) &&
        strong["flags"] == "0x62088215" && strong["anonymous"] == false,
        "NTLMv2 attributes, MIC, or channel bindings were lost");
    const auto plain = ntlmEvidence(ntlmType3(v2Flags, {}, ntlmV2Response(concat({avPair(7, Buffer(8, 1)),
        avPair(10, Buffer(16, 0))})), "someone", false), false, "ntlm_authenticate");
    require(plain["lm_response"] == "absent" && plain["message_integrity_code"] == false &&
        plain["channel_bindings"] == false && plain["encrypted_session_key"] == false,
        "An unprotected NTLMv2 response was reported as protected");
    const auto anonymous = ntlmEvidence(ntlmType3(0x800 | 0x200, Buffer{0}, {}, "", false), false, "ntlm_authenticate");
    require(anonymous["anonymous"] == true && anonymous["nt_response"] == "absent" &&
        anonymous["lm_response"] == "zero-filled", "An anonymous NTLM authentication was not identified");
    for (const size_t header : {64, 72, 88})
        require(
            ntlmEvidence(ntlmType3(header == 64 ? 0x200 : 0x02000200, Buffer(24, 1), Buffer(24, 2), "x", true, header),
                false, "ntlm_authenticate")["nt_response"] == "NTLMv1",
            "An NTLM header size was not accepted");
    const auto challenge = ntlmEvidence(ntlmType2(0x628a8215, attributeList(concat({avPair(2, utf16("D")),
        avPair(7, Buffer(8, 1))}))), true, "ntlm_challenge");
    require(challenge["target_info_attributes"] == names({"NetBIOS domain name", "Timestamp"}) &&
        challenge["flags"] == "0x628A8215", "NTLM target information was lost");
    require(!ntlmEvidence(ntlmType2(0x00008205, {}, false), true, "ntlm_challenge").contains("target_info_attributes"),
        "A challenge without target information invented attributes");
    require(ntlmEvidence(ntlmType1(0x02088215), false, "ntlm_negotiate")["flags"] == "0x02088215",
        "An NTLM negotiate message was mis-decoded");

    // A message that is inconsistent, from the wrong role, or truncated never produces NTLM evidence.
    const auto good = ntlmType3(v2Flags, Buffer(24, 0x55), ntlmV2Response(pairs));
    require(
        !undecoded(good, false) && undecoded(good, true), "An NTLM authenticate message was accepted from a server");
    require(undecoded(ntlmType2(v2Flags, {}), false) && undecoded(ntlmType1(v2Flags), true),
        "An NTLM message was accepted from the wrong role");
    require(undecoded(patched(good, "4e544c4d53535000030000", "4e544c4d53535000040000"), false),
        "An unknown NTLM message type was accepted");
    require(undecoded(ntlmType3(v2Flags, Buffer(10, 1), Buffer(24, 2)), false) &&
        undecoded(ntlmType3(v2Flags, Buffer(24, 1), Buffer(30, 2)), false) &&
        undecoded(ntlmType3(v2Flags, Buffer(24, 1), ntlmV2Response(pairs, 0, 2)), false) &&
        undecoded(ntlmType3(v2Flags, Buffer(24, 1), ntlmV2Response(pairs, 5)), false),
        "A malformed NTLM response was accepted");
    require(undecoded(ntlmType3(v2Flags, Buffer(24, 1), concat({Buffer(16, 0x11), Buffer{1, 1, 0, 0, 0, 0, 0, 0},
        Buffer(20, 0x22), avPair(7, Buffer(8, 1))})), false), "Attributes without a terminator were accepted");
    for (const auto offset : {10, 0x7fff})
    {
        auto bad = good;
        bad[24] = static_cast<uint8_t>(offset);
        bad[25] = static_cast<uint8_t>(offset >> 8);
        require(undecoded(bad, false), "An NTLM buffer outside the message was accepted");
    }

    // The recorded message ends 360 bytes after its signature; the SPNEGO list MIC follows it.
    const auto signature = std::search(ntlmAuthenticate.begin(), ntlmAuthenticate.end(), NtlmSignature.begin(),
        NtlmSignature.end());
    const Buffer raw(signature, signature + 360);
    require(
        securityEvidence(raw, false).contains("ntlm_authenticate"), "A raw NTLMSSP security buffer was not decoded");
    for (size_t size = 1; size < raw.size(); ++size)
        require(
            undecoded(Buffer(raw.begin(), raw.begin() + size), false), "A truncated NTLM message produced evidence");
    for (size_t size = 1; size < ntlmAuthenticate.size(); ++size)
        require(undecoded(Buffer(ntlmAuthenticate.begin(), ntlmAuthenticate.begin() + size), false),
            "A truncated SPNEGO token produced evidence");

    // Kerberos tokens inside SPNEGO identify the encryption of the service ticket and authenticator.
    const auto mechanisms = names({"Microsoft Kerberos", "Kerberos", "NTLM"});
    const auto init = [](uint8_t options, const char* first = MicrosoftKerberosOid)
    {
        return negotiationInit({first, KerberosOid, NtlmOid}, kerberosGss(0x0100, apRequest(18, 17, options)));
    };
    auto evidence = securityEvidence(init(0x20), false);
    require(evidence ==
            nlohmann::json{{"spnego_client_mechanisms", mechanisms},
                {"krb_ap_request",
                    {{"ticket_encryption", "aes256-cts-hmac-sha1-96"},
                        {"authenticator_encryption", "aes128-cts-hmac-sha1-96"},
                        {"mutual_authentication_required", true}, {"user_to_user", false},
                        {"service_principal", "cifs/server.example.test"}}}},
        "A Kerberos AP request in SPNEGO was mis-decoded");
    evidence = securityEvidence(init(0x40), false);
    require(evidence["krb_ap_request"]["user_to_user"] == true &&
        evidence["krb_ap_request"]["mutual_authentication_required"] == false,
        "AP request options were not decoded");
    evidence = securityEvidence(negotiationResponse(0, KerberosOid, kerberosGss(0x0200, apReply(18))), true);
    require(evidence ==
            nlohmann::json{{"spnego_server_state", "accept-completed"},
                {"spnego_server_selected_mechanism", "Kerberos"},
                {"krb_ap_reply", {{"encryption", "aes256-cts-hmac-sha1-96"}}}},
        "A Kerberos AP reply in SPNEGO was mis-decoded");
    evidence = securityEvidence(negotiationResponse(2, KerberosOid, kerberosGss(0x0300, kerberosError(37))), true);
    require(evidence["spnego_server_state"] == "reject" && evidence["krb_error"]["name"] == "KRB_AP_ERR_SKEW",
        "A Kerberos error in SPNEGO was mis-decoded");
    require(securityEvidence(negotiationResponse(3, nullptr, {}, true), false) ==
            nlohmann::json{{"spnego_client_state", "request-mic"}, {"spnego_client_mech_list_mic", true}},
        "A bare SPNEGO continuation was mis-decoded");

    // Unrecognized or misdirected tokens keep the valid SPNEGO evidence and are flagged.
    evidence = securityEvidence(negotiationInit({NegoExOid, "2a864886f70d010101"}, ascii("opaque token")), false);
    require(evidence == nlohmann::json{{"spnego_client_mechanisms", names({"NegoEx", "1.2.840.113549.1.1.1"})},
        {"spnego_token_undecoded", true}}, "An unrecognized SPNEGO token hid the mechanism list");
    const auto request = kerberosGss(0x0100, apRequest(18, 18, 0)), reply = kerberosGss(0x0200, apReply(18));
    for (const auto& [token, response, decoded] : {std::tuple{request, true, false}, {reply, false, false},
        {kerberosGss(0x0400, apReply(18)), false, false}, {request, false, true}})
    {
        evidence = securityEvidence(negotiationInit({KerberosOid}, token), response);
        require(evidence.contains("krb_ap_request") == decoded &&
                evidence.contains("spnego_token_undecoded") == !decoded &&
                evidence.contains(response ? "spnego_server_mechanisms" : "spnego_client_mechanisms"),
            "Kerberos tokens from the wrong role or of unknown type were accepted");
    }
    require(undecoded(ascii("garbage!"), false) && undecoded(Buffer{0x60, 0x03, 0x06, 0x01, 0x2a}, false) &&
        undecoded(negotiationInit({}, {}), false), "Malformed SPNEGO was not flagged");

    // SMB SESSION_SETUP framing: session flags are reported, error responses carry no security buffer, and bad
    // structure is rejected.
    for (const auto& [flag, key] : {std::pair{1, "smb_session_guest"}, {2, "smb_session_anonymous"},
        {4, "smb_session_encryption_required"}})
    {
        const auto outcome = observe(sessionSetupResponse(0, static_cast<uint16_t>(flag), {}), false);
        require(outcome.valid && outcome.reports.size() == 1 && outcome.reports[0][key] == true &&
            !outcome.reports[0].contains("spnego_token_undecoded"), "SMB session flags were lost");
    }
    const auto failure =
        observe(smb2Frame(1, true, 0xc000006d, concat({little(9, 2), Buffer{0, 0}, little(0, 4), Buffer{0}})), true);
    require(failure.valid && failure.reports.size() == 1 && failure.reports[0] ==
        nlohmann::json{{"smb_session_setup_status", "0xC000006D"}, {"smb_transport_framing", "TCP session framing"}},
        "A failed SMB session setup reported flags or a security buffer");
    require(!observe(sessionSetupResponse(0, 8, {}), false).valid, "Unknown SMB session flags were accepted");
    require(!observe(sessionSetupResponse(0, 0, Buffer(5, 1), 200), false).valid &&
        !observe(sessionSetupResponse(0, 0, Buffer(5, 1), 5, 64), false).valid,
        "An SMB security buffer outside its message was accepted");
    require(!observe(sessionSetupRequest(ntlmNegotiate, 24), false).valid &&
        !observe(sessionSetupRequest(ntlmNegotiate, 25, 80), false).valid,
        "A malformed SESSION_SETUP request header was accepted");
    const auto garbage = observe(sessionSetupRequest(ascii("garbage!")), true);
    require(garbage.valid && garbage.reports.size() == 1 && garbage.reports[0] ==
        nlohmann::json{{"spnego_token_undecoded", true}, {"smb_transport_framing", "TCP session framing"}},
        "An undecodable SMB security buffer invalidated the message or leaked fields");
    const auto empty = observe(smb2Frame(1, false, 0, concat({little(25, 2), Buffer{0, 1}, little(0, 4), little(0, 4),
        little(88, 2), little(0, 2), little(0, 8), Buffer{0}})), false);
    require(empty.valid && empty.reports.empty(), "An empty SMB security buffer produced evidence");
    const auto unplaced = observe(sessionSetupResponse(0, 1, {}, 0, 0xffff), false);
    require(unplaced.valid && unplaced.reports.size() == 1 && unplaced.reports[0]["smb_session_guest"] == true,
        "An empty SMB security buffer was held to an offset it does not use");

    // Compounded commands are inspected in full: evidence in a later command is not lost behind the first.
    auto leading = smb2Frame(3, false, 0, Buffer(8, 0)), trailing = smb2Frame(5, false, 0, Buffer(8, 0));
    leading.erase(leading.begin(), leading.begin() + 4);
    trailing.erase(trailing.begin(), trailing.begin() + 4);
    trailing[16] |= 8;
    for (const uint8_t next : {uint8_t{72}, uint8_t{70}})
    {
        leading[20] = next;
        Buffer compound{0, 0, 0, static_cast<uint8_t>(leading.size() + trailing.size())};
        append(compound, leading);
        append(compound, trailing);
        const auto chained = observe(compound, false);
        require(next == 72 ? chained.valid && chained.reports.size() == 1 &&
            chained.reports[0]["smb_signed_message_observed"] == true : !chained.valid,
            "An SMB compound lost a later command's evidence or accepted a misaligned offset");
    }
    const auto garbageNegotiate = observe(negotiateResponse(ascii("garbage!")), false);
    require(garbageNegotiate.valid && garbageNegotiate.reports[0]["spnego_token_undecoded"] == true,
        "An undecodable NEGOTIATE security buffer was not flagged");
}
}
