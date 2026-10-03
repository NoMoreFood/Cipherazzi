#include "Engine.h"
#include "Auth.h"
#include "Crypto.h"
#include <algorithm>
#include <fstream>
#include <random>
#include <stdexcept>
#include <tuple>
#include <windows.h>

namespace Cipherazzi::Tests
{
using Buffer = std::vector<uint8_t>;
void require(bool result, const char* message);
void word(Buffer& bytes, uint16_t value);
void append(Buffer& bytes, Bytes value);
Buffer hello(bool client, uint16_t version, bool retry, bool ech, Bytes extensions);
Buffer record(Bytes payload, uint8_t type);
Buffer fromHex(const std::string& text);

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

Buffer ipTransport(Bytes payload, bool ipv6, bool udp = true, bool client = true)
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

Buffer ipFragment(Bytes datagram, bool ipv6, size_t offset, size_t length, bool more, uint16_t id = 100)
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

// Replays one TCP connection through the engine with roles learned from the handshake.
std::vector<Observation> replayConnection(const Buffer& client, const Buffer& server, uint16_t port, Counters& health)
{
    std::vector<Observation> output;
    Engine engine(health, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            output.push_back(std::move(observation));
    });
    auto packet = [port](Bytes payload, bool fromServer, uint32_t sequence, uint8_t flags = 0x18)
    {
        TcpPacket value;
        value.source.address[0] = value.destination.address[0] = 10;
        value.source.address[3] = fromServer ? 2 : 1;
        value.destination.address[3] = fromServer ? 1 : 2;
        value.source.port = fromServer ? port : 50123;
        value.destination.port = fromServer ? 50123 : port;
        value.sequence = sequence;
        value.flags = flags;
        value.payload = payload;
        return value;
    };
    engine.tcp(packet({}, false, 1000, 2), 1);
    engine.tcp(packet({}, true, 9000, 0x12), 2);
    engine.tcp(packet(client, false, 1001), 3);
    engine.tcp(packet(server, true, 9001), 4);
    engine.expire(1000000, true);
    return output;
}

nlohmann::json summarized(const Observation& observation)
{
    CryptoCatalog catalog;
    return nlohmann::json::parse(catalog.summarize(observation, [](auto&, auto&, Bytes) {}).json);
}

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
            feedBytes(framing, legacyFrame(false, 0x73, 0, Buffer(26, 0), Buffer(8, 0)), reports) &&
            reports.empty(), "SMB1 error replies or later commands produced negotiation evidence");
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
}

// Standard RDP Security states its encryption choice in cleartext MCS Connect PDUs; TLS flows are unaffected.
void rdpStandardCoverage()
{
    // Recorded xrdp and FreeRDP exchange: Standard Security, 128-bit RC4, and a proprietary 2048-bit RSA key.
    const auto clientRequest = fromHex(
        "030000241fe00000000000436f6f6b69653a206d737473686173683d6e6f626f64790d0a");
    const auto serverConfirm = fromHex(
        "0300000b06d00000123400");
    const auto negotiatedRequest = fromHex(
        "0300002c27e00000000000436f6f6b69653a206d737473686173683d6e6f626f64790d0a0100080003000000");
    const auto negotiatedConfirm = fromHex(
        "030000130ed000001234000201080000000000");
    const auto connectInitial = fromHex(
        "030001c302f0807f658201b70401010401010101ff301a020122020102020100020101020100020101020300ffff0201"
        "023019020101020101020101020101020100020101020204200201023020020300ffff020300fc17020300ffff020101"
        "020100020101020300ffff02010204820151000500147c00018148000800100001c00044756361813a01c0ea000c0008"
        "000004000301ca03aa09040000bb47000076006d00000000000000000000000000000000000000000000000000000000"
        "0004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000001ca01000000000018000f00e3050000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000007000000000000000000000000000000000000000000000004c00c000d0000000000000002"
        "c00c001b0000000000000003c03800040000007264706472000000000080c0726470736e640000000000c0636c697072"
        "6472000000a0c0647264796e766300000080c0");
    const auto connectResponse = fromHex(
        "0300020d02f0807f668202010a0100020100301a020116020103020100020101020100020101020300fff80201020482"
        "01db000500147c00012a14760a01010001c0004d63446e81c4010c080004000800030c1000eb030400ec03ed03ee03ef"
        "03020cac01020000000300000020000000780100004b842dbf8ed1d8c776e65ff96641a4f97ef18fd9ac67b4f95a0af2"
        "0af12822be01000000010000000100000006001c01525341310801000000080000ff00000001000100dd34cd9e77fbfc"
        "0e738ba6b51f109eb5ff936e2e7299ce6b44310c4c07b58609b6eff3e032e1f766e33c026c29552a9ef87955fd322def"
        "c93119d3467cecbd49052ed0f23e9d8ecd2a26f35b67eb4b51211429696a07e3e5de022438a86137a18e0c6c3aca0f88"
        "b88062ef38835d9dd3ed43c169cfe43a3d5653a061396422d1eaa127389a1e6b9bca8d71d20454c3d62cd98193d878e6"
        "5c001c950d3b331fbea95d25a6501ca78174d15d6d9253368654c371a298b6f5f7f2d3b260c841bd2a7e1368ffd6c07f"
        "67a68f047e11a63254cc0cfa7c3f1ab57234c9b2a71989bc4a179e7dd256d87b70bfcbd546ab23e8420754f8472a6b1a"
        "7b03191de0e8d66aba000000000000000008004800ab86d368e337c00c48758c9963078083dbe9e9af510e188b5197fe"
        "bf409c2c4e8b97a86aa759a6033e41ce55a6e4fabe1f4dff9e01635ea3b3046980bfbfbc470000000000000000");
    struct Outcome
    {
        std::vector<nlohmann::json> reports;
        size_t tlsBytes{}, memory{};
        bool valid{}, finished{};
    };
    auto run = [](const Buffer& bytes, bool split)
    {
        FramedStream framing;
        Outcome outcome;
        auto sink = [&](const FramedMessage& message)
        {
            if (message.kind == FramedMessage::Kind::Rdp)
                outcome.reports.push_back(message.fields);
            else
                outcome.tlsBytes += message.payload.size();
            return true;
        };
        outcome.valid = true;
        if (split)
            for (size_t offset = 0; outcome.valid && offset < bytes.size(); ++offset)
                outcome.valid = framing.feed(Bytes(bytes).subspan(offset, 1), sink);
        else
            outcome.valid = framing.feed(bytes, sink);
        outcome.finished = framing.finished();
        outcome.memory = framing.memory();
        return outcome;
    };
    auto join = [](Buffer first, const Buffer& second)
    {
        append(first, second);
        return first;
    };
    const nlohmann::json expectedRequest{
        {"rdp_client_encryption_methods", {"RC4 40-bit", "RC4 128-bit", "RC4 56-bit", "FIPS 3DES"}},
        {"rdp_mcs_connect_request_observed", true}};
    const nlohmann::json expectedResponse{
        {"rdp_mcs_connect_response_observed", true}, {"rdp_server_certificate_type", "Proprietary"},
        {"rdp_server_encryption_level", "High"}, {"rdp_server_encryption_method", "RC4 128-bit"},
        {"rdp_server_key_bits", 2048}};
    for (const bool split : {false, true})
    {
        // Both directions of a negotiated or legacy connection stop inspecting once the MCS PDU is reported.
        const char* const clientFault = "RDP Standard Security client evidence was lost or retained storage";
        const char* const serverFault = "RDP Standard Security server evidence was lost or retained storage";
        for (const auto& [x224, mcs, expected, fault] : {
            std::tuple{clientRequest, connectInitial, expectedRequest, clientFault},
            {negotiatedRequest, connectInitial, expectedRequest, clientFault},
            {serverConfirm, connectResponse, expectedResponse, serverFault},
            {negotiatedConfirm, connectResponse, expectedResponse, serverFault}})
        {
            const auto outcome = run(join(x224, mcs), split);
            require(outcome.valid && outcome.reports.size() == 2 && outcome.reports[1] == expected &&
                outcome.finished && outcome.memory == 0 && outcome.tlsBytes == 0, fault);
        }
    }
    {
        const auto negotiated = run(join(negotiatedConfirm, connectResponse), false);
        require(negotiated.reports[0]["rdp_selected_protocol"] == 0 &&
            !negotiated.reports[0].contains("rdp_server_encryption_method"),
            "A selected Standard RDP Security protocol was merged into MCS evidence");

        // A negotiation failure ends the connection attempt, so nothing further is inspected.
        const Buffer failure{3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 3, 0, 8, 0, 5, 0, 0, 0};
        const auto failed = run(failure, true);
        require(failed.valid && failed.reports.size() == 1 && failed.reports[0]["rdp_failure_code"] == 5 &&
            failed.finished && failed.memory == 0, "An RDP negotiation failure continued inspection");

        // A legacy X.224 response without negotiation waits for the MCS PDU before releasing inspection storage.
        FramedStream legacy;
        require(legacy.feed(serverConfirm, [](const FramedMessage&) { return true; }) && !legacy.finished(),
            "A legacy X.224 response ended inspection before the MCS PDU");
        require(legacy.feed(connectResponse, [](const FramedMessage&) { return true; }) && legacy.finished() &&
            legacy.memory() == 0, "Legacy RDP MCS traffic retained inspection storage");
    }

    // Enhanced security continues with TLS in both directions and never reaches the MCS parser.
    for (const auto& x224 : {clientRequest, negotiatedRequest, serverConfirm, negotiatedConfirm})
    {
        const Buffer tlsStart{0x16, 3, 1, 0, 5, 1, 2, 3, 4, 5};
        const auto outcome = run(join(x224, tlsStart), true);
        require(outcome.valid && outcome.reports.size() == 1 && outcome.tlsBytes == tlsStart.size() && !outcome.finished,
            "TLS after an X.224 exchange was withheld or parsed as MCS");
    }

    // Assemble MCS PDUs around chosen user-data blocks to cover selections absent from the recordings.
    auto littleWord = [](Buffer& bytes, uint32_t value, int count)
    {
        for (int index = 0; index < count; ++index)
            bytes.push_back(static_cast<uint8_t>(value >> (index * 8)));
    };
    auto block = [&](uint16_t type, const Buffer& data)
    {
        Buffer result;
        littleWord(result, type, 2);
        littleWord(result, static_cast<uint32_t>(data.size() + 4), 2);
        append(result, data);
        return result;
    };
    auto ber = [](Buffer prefix, const Buffer& value)
    {
        prefix.push_back(0x82);
        word(prefix, static_cast<uint16_t>(value.size()));
        append(prefix, value);
        return prefix;
    };
    auto per = [](Buffer& bytes, size_t length)
    {
        word(bytes, static_cast<uint16_t>(0x8000 | length));
    };
    auto wrap = [&](bool request, const Buffer& content)
    {
        Buffer payload{2, 0xf0, 0x80, 0x7f, static_cast<uint8_t>(request ? 0x65 : 0x66)};
        append(payload, ber({}, content));
        Buffer result{3, 0};
        word(result, static_cast<uint16_t>(payload.size() + 4));
        append(result, payload);
        return result;
    };
    const Buffer requestHead{4, 1, 1, 4, 1, 1, 1, 1, 0xff, 0x30, 0, 0x30, 0, 0x30, 0};
    const Buffer responseHead{0x0a, 1, 0, 2, 1, 0, 0x30, 0};
    auto pdu = [&](bool request, const Buffer& userData)
    {
        auto content = request ? requestHead : responseHead;
        append(content, ber({4}, userData));
        return wrap(request, content);
    };
    auto gcc = [&](bool request, const Buffer& blocks, std::ptrdiff_t adjust = 0)
    {
        Buffer data{0, 5, 0, 0x14, 0x7c, 0, 1, 0x2a};
        if (request)
            data = {0, 5, 0, 0x14, 0x7c, 0, 1, 0x2a, 0, 8, 0, 0x10, 0, 1, 0xc0, 0, 'D', 'u', 'c', 'a'};
        else
            append(data, Buffer{0x14, 0x76, 0x0a, 1, 1, 0, 1, 0xc0, 0, 'M', 'c', 'D', 'n'});
        per(data, static_cast<size_t>(static_cast<std::ptrdiff_t>(blocks.size()) + adjust));
        append(data, blocks);
        return data;
    };
    auto serverBlock = [&](uint32_t method, uint32_t level, const Buffer& certificate)
    {
        Buffer data;
        littleWord(data, method, 4);
        littleWord(data, level, 4);
        if (method || level)
        {
            littleWord(data, 32, 4);
            littleWord(data, static_cast<uint32_t>(certificate.size()), 4);
            data.insert(data.end(), 32, 0x55);
            append(data, certificate);
        }
        return block(0x0c02, data);
    };
    auto proprietary = [&](uint32_t bits, uint32_t keyLength)
    {
        Buffer certificate;
        for (const uint32_t value : {1u, 1u, 1u})
            littleWord(certificate, value, 4);
        littleWord(certificate, 6, 2);
        littleWord(certificate, keyLength + 20, 2);
        append(certificate, Buffer{'R', 'S', 'A', '1'});
        for (const uint32_t value : {keyLength, bits, keyLength - 1, 65537u})
            littleWord(certificate, value, 4);
        certificate.insert(certificate.end(), keyLength, 0xaa);
        append(certificate, Buffer{8, 0, 4, 0, 1, 2, 3, 4});
        return certificate;
    };
    auto chain = [&](uint32_t count)
    {
        Buffer certificate;
        littleWord(certificate, 2, 4);
        littleWord(certificate, count, 4);
        for (uint32_t index = 0; index < count; ++index)
        {
            littleWord(certificate, 6, 4);
            certificate.insert(certificate.end(), 6, 0x30);
        }
        return certificate;
    };
    auto response = [&](const Buffer& blocks) { return join(serverConfirm, pdu(false, gcc(false, blocks))); };
    auto request = [&](const Buffer& blocks) { return join(clientRequest, pdu(true, gcc(true, blocks))); };
    auto second = [&](const Outcome& outcome) { return outcome.reports.size() == 2 ? outcome.reports[1] : nlohmann::json{}; };

    // Method and level are reported as selected; unknown values retain their numeric identity.
    for (const auto& [method, level, methodName, levelName] : {
        std::tuple{1u, 1u, "RC4 40-bit", "Low"}, {1u, 2u, "RC4 40-bit", "Client compatible"},
        {8u, 3u, "RC4 56-bit", "High"}, {0x10u, 4u, "FIPS 3DES", "FIPS"}, {2u, 2u, "RC4 128-bit", "Client compatible"},
        {4u, 3u, "0x00000004", "High"}, {2u, 5u, "RC4 128-bit", "0x00000005"}, {2u, 9u, "RC4 128-bit", "0x00000009"},
        {0u, 3u, "None", "High"}})
    {
        const auto outcome = run(response(serverBlock(method, level, proprietary(1024, 136))), true);
        const auto fields = second(outcome);
        require(outcome.valid && fields["rdp_server_encryption_method"] == methodName &&
            fields["rdp_server_encryption_level"] == levelName && fields["rdp_server_key_bits"] == 1024,
            "RDP server encryption selection was misreported");
    }
    {
        // Enhanced security reports neither encryption nor key material in the MCS response.
        const auto fields = second(run(response(serverBlock(0, 0, {})), false));
        require(fields["rdp_server_encryption_method"] == "None" && fields["rdp_server_encryption_level"] == "None" &&
            !fields.contains("rdp_server_certificate_type"), "Enhanced-security MCS evidence implied key material");

        // Other blocks and X.509 chains do not displace the security selection.
        auto blocks = block(0x0c01, Buffer{4, 0, 8, 0});
        append(blocks, serverBlock(2, 3, chain(2)));
        append(blocks, block(0x0c03, Buffer{0xeb, 3, 0, 0}));
        const auto chained = second(run(response(blocks), true));
        require(chained["rdp_server_certificate_type"] == "X.509 chain" && chained["rdp_server_certificate_count"] == 2 &&
            !chained.contains("rdp_server_key_bits") && chained["rdp_server_encryption_method"] == "RC4 128-bit",
            "An RDP X.509 certificate chain was misreported");

        // The most significant version bit marks a temporary certificate and does not change its layout.
        auto temporary = proprietary(2048, 264);
        temporary[3] = 0x80;
        auto temporaryChain = chain(1);
        temporaryChain[3] = 0x80;
        const auto marked = second(run(response(serverBlock(2, 3, temporary)), false));
        const auto markedChain = second(run(response(serverBlock(2, 3, temporaryChain)), false));
        require(marked["rdp_server_certificate_type"] == "Proprietary" && marked["rdp_server_key_bits"] == 2048 &&
            markedChain["rdp_server_certificate_type"] == "X.509 chain" && markedChain["rdp_server_certificate_count"] == 1,
            "A temporary RDP certificate was not recognized");

        // A damaged or unrecognized certificate withholds key metadata without discarding the selection.
        auto damagedProprietary = [&](size_t offset, uint8_t value)
        {
            auto certificate = proprietary(2048, 264);
            certificate[offset] = value;
            return certificate;
        };
        auto truncated = proprietary(2048, 264);
        truncated.resize(100);
        auto keyLength = proprietary(2048, 264);
        keyLength[20] ^= 1;
        auto oversizedEntry = chain(2);
        oversizedEntry[8] = 0xff;
        auto truncatedChain = chain(2);
        truncatedChain.resize(20);
        for (const auto& certificate : {
            damagedProprietary(16, 'X'), damagedProprietary(0, 3), damagedProprietary(4, 2), damagedProprietary(8, 2),
            damagedProprietary(12, 7), proprietary(2048, 100), proprietary(0, 264), truncated, keyLength,
            oversizedEntry, truncatedChain, chain(0), chain(33), Buffer{}, Buffer{1, 0}, Buffer{1, 0, 0, 0}, Buffer{2, 0, 0, 0}})
        {
            const auto damaged = second(run(response(serverBlock(2, 3, certificate)), false));
            require(damaged["rdp_server_encryption_method"] == "RC4 128-bit" &&
                !damaged.contains("rdp_server_certificate_type") && !damaged.contains("rdp_server_key_bits") &&
                !damaged.contains("rdp_server_certificate_count"), "A damaged RDP certificate fabricated key metadata");
        }
    }

    // Client offers list each recognized method and retain unrecognized bits.
    for (const auto& [methods, expected] : {
        std::tuple{0u, nlohmann::json::array()}, {2u, nlohmann::json::array({"RC4 128-bit"})},
        {0x1bu, expectedRequest["rdp_client_encryption_methods"]},
        {0x24u, nlohmann::json::array({"0x00000024"})}, {0x12u, nlohmann::json::array({"RC4 128-bit", "FIPS 3DES"})}})
    {
        Buffer data;
        littleWord(data, methods, 4);
        littleWord(data, 0, 4);
        const auto fields = second(run(request(block(0xc002, data)), true));
        require(fields["rdp_client_encryption_methods"] == expected, "RDP client encryption offers were misreported");

        // Clients predating extended methods send only the legacy field.
        data.resize(4);
        const auto legacy = second(run(request(block(0xc002, data)), false));
        require(legacy["rdp_client_encryption_methods"] == expected, "A legacy RDP client security block was misreported");
    }

    // Unknown user-data layouts and failed conferences report framing only, never fabricated selections.
    {
        const nlohmann::json observedResponse{{"rdp_mcs_connect_response_observed", true}};
        const nlohmann::json observedRequest{{"rdp_mcs_connect_request_observed", true}};

        // Every fixed byte of the GCC wrapper must match before the user data is interpreted.
        for (const bool isRequest : {false, true})
        {
            const auto good = gcc(isRequest, isRequest ? block(0xc002, Buffer(8, 2)) : serverBlock(2, 3, proprietary(2048, 264)));
            for (size_t offset = 0; offset < (isRequest ? 20u : 21u); ++offset)
            {
                // The connectPDU length and unchecked ASN.1 header bytes vary between implementations.
                if (offset == 7 || (!isRequest && (offset == 9 || offset == 10 || offset == 12)))
                    continue;
                auto data = good;
                data[offset] ^= 1;
                const auto outcome = run(join(isRequest ? clientRequest : serverConfirm, pdu(isRequest, data)), false);
                require(outcome.valid && second(outcome) == (isRequest ? observedRequest : observedResponse),
                    "An unrecognized GCC layout produced security evidence");
            }

            // A complete GCC prefix without its length is malformed, while shorter user data is merely unrecognized.
            for (const size_t length : {0u, 3u, 6u, 7u, 8u, 12u, 16u})
            {
                const auto outcome = run(join(isRequest ? clientRequest : serverConfirm,
                    pdu(isRequest, Buffer(good.begin(), good.begin() + length))), false);
                require(length == 7 ? !outcome.valid : outcome.valid &&
                    second(outcome) == (isRequest ? observedRequest : observedResponse),
                    "Truncated GCC user data produced security evidence");
            }
        }

        // A failed conference result is reported without interpreting the user data it carries.
        auto failed = pdu(false, gcc(false, serverBlock(2, 3, proprietary(2048, 264))));
        failed[14] = 1;
        const auto rejected = run(join(serverConfirm, failed), false);
        require(rejected.valid && second(rejected) == observedResponse && rejected.finished,
            "A failed MCS connection produced security evidence");
        const auto noSecurity = run(response(block(0x0c03, Buffer{0xeb, 3, 0, 0})), false);
        require(noSecurity.valid && second(noSecurity) == nlohmann::json{{"rdp_mcs_connect_response_observed", true}},
            "An MCS response without a security block produced evidence");
    }

    // Truncation emits nothing, and malformed PDUs are rejected without exposing partial evidence.
    {
        const auto valid = join(serverConfirm, connectResponse);
        for (size_t length = serverConfirm.size(); length < valid.size(); ++length)
        {
            const auto outcome = run(Buffer(valid.begin(), valid.begin() + length), false);
            require(outcome.valid && outcome.reports.size() == 1 && !outcome.finished,
                "A truncated MCS response produced evidence");
        }
        auto rejects = [&](Buffer bytes)
        {
            const auto outcome = run(bytes, false);
            return !outcome.valid && outcome.reports.size() == 1;
        };
        const size_t base = serverConfirm.size();
        auto mutate = [&](size_t offset, uint8_t value)
        {
            auto copy = valid;
            copy[base + offset] = value;
            return copy;
        };
        require(rejects(mutate(1, 1)), "An MCS response with a corrupt TPKT header was accepted");
        require(rejects(mutate(5, 0)), "An MCS response with the wrong X.224 data header was accepted");
        require(rejects(mutate(6, 0)), "An MCS response with the wrong X.224 data header was accepted");
        require(rejects(mutate(8, 0x65)), "A Connect-Initial tag was accepted in a response");
        require(rejects(mutate(9, 0x81)), "A BER length that disagrees with the TPKT was accepted");
        require(rejects(mutate(12, 0x02)), "A Connect-Response with the wrong result tag was accepted");

        // BER lengths, flags and trailing content are validated within each Connect PDU.
        auto raw = [&](bool isRequest, const Buffer& tail, const Buffer* head = nullptr)
        {
            auto content = head ? *head : isRequest ? requestHead : responseHead;
            append(content, tail);
            return join(isRequest ? clientRequest : serverConfirm, wrap(isRequest, content));
        };
        for (const bool isRequest : {false, true})
        {
            const nlohmann::json observed{{isRequest ? "rdp_mcs_connect_request_observed" : "rdp_mcs_connect_response_observed", true}};
            const auto empty = run(raw(isRequest, Buffer{4, 0}), false);
            require(empty.valid && second(empty) == observed, "A Connect PDU without user data was rejected");
            for (const auto& tail : {Buffer{4, 0x80}, Buffer{4, 0x83, 0, 0, 0}, Buffer{4, 0x82, 0}, Buffer{4, 5, 0}, Buffer{4, 0, 0}})
                require(rejects(raw(isRequest, tail)), "A malformed Connect PDU user-data length was accepted");
        }
        const Buffer wideUpward{4, 1, 1, 4, 1, 1, 1, 2, 0xff, 0xff, 0x30, 0, 0x30, 0, 0x30, 0};
        const Buffer wideResult{0x0a, 2, 0, 0, 2, 1, 0, 0x30, 0};
        require(rejects(raw(true, Buffer{4, 0}, &wideUpward)), "A Connect-Initial with a multi-byte flag was accepted");
        require(rejects(raw(false, Buffer{4, 0}, &wideResult)), "A Connect-Response with a multi-byte result was accepted");
        auto padded = pdu(false, Buffer{});
        padded.push_back(0);
        padded[3] += 1;
        require(rejects(join(serverConfirm, padded)), "An MCS response with trailing bytes was accepted");

        // Block structure is validated within the declared user-data length.
        require(rejects(join(serverConfirm, pdu(false, gcc(false, serverBlock(2, 3, proprietary(2048, 264)), 1)))),
            "User-data blocks longer than the PDU were accepted");
        require(rejects(join(serverConfirm, pdu(false, gcc(false, serverBlock(2, 3, proprietary(2048, 264)), -1)))),
            "A truncated final user-data block was accepted");
        auto tiny = block(0x0c03, Buffer{});
        tiny[2] = 0;
        require(rejects(response(tiny)), "A user-data block smaller than its header was accepted");
        auto twice = serverBlock(2, 3, proprietary(2048, 264));
        append(twice, serverBlock(2, 3, proprietary(2048, 264)));
        require(rejects(response(twice)), "Duplicate RDP security blocks were accepted");
        auto shortBlock = block(0x0c02, Buffer{2, 0, 0, 0});
        require(rejects(response(shortBlock)), "A short RDP security block was accepted");
        auto badRandom = serverBlock(2, 3, proprietary(2048, 264));
        badRandom[4 + 8] = 31;
        require(rejects(response(badRandom)), "An RDP server random of the wrong size was accepted");
        auto badCertificate = serverBlock(2, 3, proprietary(2048, 264));
        badCertificate[4 + 12] ^= 1;
        require(rejects(response(badCertificate)), "An RDP certificate length outside its block was accepted");
        auto overflow = block(0x0c03, Buffer{});
        overflow[2] = 0xff;
        require(rejects(response(overflow)), "A user-data block beyond its container was accepted");
        require(rejects(response(Buffer{0x02, 0x0c, 0x03})), "A truncated user-data block header was accepted");
        auto enhancedWithKey = serverBlock(0, 0, {});
        enhancedWithKey[2] = 20;
        enhancedWithKey.insert(enhancedWithKey.end(), 8, 0);
        require(rejects(response(enhancedWithKey)), "An enhanced-security block carrying key material was accepted");
        require(rejects(request(block(0xc002, Buffer{1, 0}))), "A short client security block was accepted");
        require(rejects(request(block(0xc002, Buffer(9, 0)))), "An oversized client security block was accepted");
    }
}

namespace
{
Buffer concat(std::initializer_list<Buffer> parts)
{
    Buffer result;
    for (const auto& part : parts)
        append(result, part);
    return result;
}

Buffer little(uint64_t value, size_t size)
{
    Buffer bytes;
    for (size_t index = 0; index < size; ++index)
        bytes.push_back(static_cast<uint8_t>(value >> (index * 8)));
    return bytes;
}

Buffer ascii(std::string_view text)
{
    return Buffer(text.begin(), text.end());
}

Buffer utf16(std::string_view text)
{
    Buffer bytes;
    for (const char character : text)
    {
        bytes.push_back(static_cast<uint8_t>(character));
        bytes.push_back(0);
    }
    return bytes;
}

// Definite-length DER with minimal length encoding.
Buffer der(uint8_t tag, const Buffer& content)
{
    Buffer result{tag};
    if (content.size() < 128)
        result.push_back(static_cast<uint8_t>(content.size()));
    else
    {
        const size_t count = content.size() > 65535 ? 3 : content.size() > 255 ? 2 : 1;
        result.push_back(static_cast<uint8_t>(0x80 | count));
        for (size_t shift = count; shift--;)
            result.push_back(static_cast<uint8_t>(content.size() >> (shift * 8)));
    }
    append(result, content);
    return result;
}

Buffer derInt(int64_t value)
{
    Buffer content;
    for (int shift = 56; shift >= 0; shift -= 8)
        content.push_back(static_cast<uint8_t>(value >> shift));
    while (content.size() > 1 && ((content[0] == 0 && !(content[1] & 0x80)) ||
        (content[0] == 0xff && (content[1] & 0x80))))
        content.erase(content.begin());
    return der(2, content);
}

Buffer context(unsigned index, const Buffer& inner)
{
    return der(static_cast<uint8_t>(0xa0 | index), inner);
}

Buffer sequence(std::initializer_list<Buffer> parts)
{
    return der(0x30, concat(parts));
}

Buffer sequenceOf(const std::vector<Buffer>& items)
{
    Buffer content;
    for (const auto& item : items)
        append(content, item);
    return der(0x30, content);
}

using Names = std::vector<std::string_view>;

Buffer kerberosName(const Names& parts)
{
    Buffer strings;
    for (const auto part : parts)
        append(strings, der(0x1b, ascii(part)));
    return sequence({context(0, derInt(1)), context(1, der(0x30, strings))});
}

Buffer kerberosEncrypted(int64_t type)
{
    return sequence({context(0, derInt(type)), context(1, derInt(3)), context(2, der(4, Buffer(32, 0x5a)))});
}

const Names KdcService{"krbtgt", "EXAMPLE.TEST"}, FileService{"cifs", "server.example.test"};

Buffer kerberosTicket(int64_t type, const Names& service)
{
    return der(0x61, sequence({context(0, derInt(5)), context(1, der(0x1b, ascii("EXAMPLE.TEST"))),
        context(2, kerberosName(service)), context(3, kerberosEncrypted(type))}));
}

Buffer preauthData(int64_t type, const Buffer& value)
{
    return sequence({context(1, derInt(type)), context(2, der(4, value))});
}

Buffer kdcRequest(bool tgs, const std::vector<int64_t>& types, const std::vector<Buffer>& padata = {},
    const Buffer& additional = {}, const Names& service = {})
{
    Buffer etypes;
    for (const auto type : types)
        append(etypes, derInt(type));
    auto body = concat({context(0, der(3, Buffer{0, 0x40, 0x81, 0, 0x10})), context(1, kerberosName({"alice"})),
        context(2, der(0x1b, ascii("EXAMPLE.TEST"))),
        context(3, kerberosName(!service.empty() ? service : tgs ? FileService : KdcService)),
        context(7, derInt(1234567)), context(8, der(0x30, etypes))});
    if (!additional.empty())
        append(body, context(11, der(0x30, additional)));
    auto fields = concat({context(1, derInt(5)), context(2, derInt(tgs ? 12 : 10))});
    if (!padata.empty())
        append(fields, context(3, sequenceOf(padata)));
    append(fields, context(4, der(0x30, body)));
    return der(tgs ? 0x6c : 0x6a, der(0x30, fields));
}

Buffer kdcReply(bool tgs, int64_t ticketType, int64_t replyType, const std::vector<Buffer>& padata = {})
{
    auto fields = concat({context(0, derInt(5)), context(1, derInt(tgs ? 13 : 11))});
    if (!padata.empty())
        append(fields, context(2, sequenceOf(padata)));
    append(fields, concat({context(3, der(0x1b, ascii("EXAMPLE.TEST"))), context(4, kerberosName({"alice"})),
        context(5, kerberosTicket(ticketType, tgs ? FileService : KdcService)),
        context(6, kerberosEncrypted(replyType))}));
    return der(tgs ? 0x6d : 0x6b, der(0x30, fields));
}

Buffer kerberosError(int64_t code, const Buffer& data = {}, bool service = true)
{
    auto fields = concat({context(0, derInt(5)), context(1, derInt(30)),
        context(4, der(0x18, ascii("20261010000000Z"))), context(5, derInt(1)), context(6, derInt(code)),
        context(9, der(0x1b, ascii("EXAMPLE.TEST")))});
    if (service)
        append(fields, context(10, kerberosName(KdcService)));
    if (!data.empty())
        append(fields, context(12, der(4, data)));
    return der(0x7e, der(0x30, fields));
}

Buffer apRequest(int64_t ticketType, int64_t authenticatorType, uint8_t options, const Names& service = FileService)
{
    return der(0x6e, sequence({context(0, derInt(5)), context(1, derInt(14)),
        context(2, der(3, Buffer{0, options, 0, 0, 0})), context(3, kerberosTicket(ticketType, service)),
        context(4, kerberosEncrypted(authenticatorType))}));
}

Buffer apReply(int64_t type)
{
    return der(0x6f, sequence({context(0, derInt(5)), context(1, derInt(15)), context(2, kerberosEncrypted(type))}));
}

Buffer privateMessage(int64_t type, int64_t messageType = 21)
{
    return der(0x75, sequence({context(0, derInt(5)), context(1, derInt(messageType)),
        context(3, kerberosEncrypted(type))}));
}

// RFC 3244 messages state their length, protocol version, and AP-REQ or AP-REP length before both parts.
Buffer passwordMessage(uint16_t version, const Buffer& exchange, const Buffer& protectedPart)
{
    Buffer message;
    word(message, static_cast<uint16_t>(6 + exchange.size() + protectedPart.size()));
    word(message, version);
    word(message, static_cast<uint16_t>(exchange.size()));
    append(message, exchange);
    append(message, protectedPart);
    return message;
}

// KDC and change-password messages over TCP are preceded by a four-byte length.
Buffer kdcFrame(const Buffer& message)
{
    Buffer frame{0, static_cast<uint8_t>(message.size() >> 16)};
    word(frame, static_cast<uint16_t>(message.size()));
    append(frame, message);
    return frame;
}

Buffer patched(Buffer bytes, const char* from, const char* to)
{
    const auto old = fromHex(from), replacement = fromHex(to);
    const auto found = std::search(bytes.begin(), bytes.end(), old.begin(), old.end());
    require(found != bytes.end() && old.size() == replacement.size(), "A test fixture patch pattern was missing");
    std::copy(replacement.begin(), replacement.end(), found);
    return bytes;
}

const char* const SpnegoOid = "2b0601050502";
const char* const KerberosOid = "2a864886f712010202";
const char* const MicrosoftKerberosOid = "2a864882f712010202";
const char* const NtlmOid = "2b06010401823702020a";
const char* const NegoExOid = "2b06010401823702021e";

Buffer oid(const char* hex)
{
    return der(6, fromHex(hex));
}

Buffer kerberosGss(uint16_t tokenId, const Buffer& message, const char* mechanism = KerberosOid)
{
    auto content = oid(mechanism);
    word(content, tokenId);
    append(content, message);
    return der(0x60, content);
}

Buffer negotiationInit(std::initializer_list<const char*> mechanisms, const Buffer& token = {})
{
    Buffer list;
    for (const auto* mechanism : mechanisms)
        append(list, oid(mechanism));
    auto fields = context(0, der(0x30, list));
    if (!token.empty())
        append(fields, context(2, der(4, token)));
    return der(0x60, concat({oid(SpnegoOid), context(0, der(0x30, fields))}));
}

Buffer negotiationResponse(int state, const char* mechanism, const Buffer& token = {}, bool mic = false)
{
    Buffer fields;
    if (state >= 0)
        append(fields, context(0, der(0x0a, Buffer{static_cast<uint8_t>(state)})));
    if (mechanism)
        append(fields, context(1, oid(mechanism)));
    if (!token.empty())
        append(fields, context(2, der(4, token)));
    if (mic)
        append(fields, context(3, der(4, Buffer(16, 0x33))));
    return context(1, der(0x30, fields));
}

const Buffer NtlmSignature{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

// Security buffer descriptors reference payload that follows the fixed header.
void ntlmField(Buffer& message, Buffer& payload, size_t header, const Buffer& value)
{
    append(message, little(value.size(), 2));
    append(message, little(value.size(), 2));
    append(message, little(header + payload.size(), 4));
    append(payload, value);
}

Buffer ntlmType1(uint32_t flags)
{
    auto message = concat({NtlmSignature, little(1, 4), little(flags, 4)});
    Buffer payload;
    ntlmField(message, payload, 40, {});
    ntlmField(message, payload, 40, {});
    append(message, Buffer(8, 0));
    return message;
}

Buffer ntlmType2(uint32_t flags, const Buffer& targetInfo, bool version = true)
{
    const size_t header = version ? 56 : 48;
    auto message = concat({NtlmSignature, little(2, 4)});
    Buffer payload;
    ntlmField(message, payload, header, utf16("SERVER"));
    append(message, concat({little(flags, 4), Buffer(8, 0x77), Buffer(8, 0)}));
    ntlmField(message, payload, header, targetInfo);
    if (version)
        append(message, Buffer(8, 0));
    append(message, payload);
    return message;
}

Buffer ntlmType3(uint32_t flags, const Buffer& lm, const Buffer& nt, std::string_view user = "someone",
    bool sessionKey = true, size_t header = 88)
{
    auto message = concat({NtlmSignature, little(3, 4)});
    Buffer payload;
    ntlmField(message, payload, header, lm);
    ntlmField(message, payload, header, nt);
    ntlmField(message, payload, header, utf16("DOMAIN"));
    ntlmField(message, payload, header, utf16(user));
    ntlmField(message, payload, header, utf16("WORKSTATION"));
    ntlmField(message, payload, header, sessionKey ? Buffer(16, 0x44) : Buffer{});
    append(message, little(flags, 4));
    message.resize(header, 0);
    append(message, payload);
    return message;
}

Buffer avPair(uint16_t id, const Buffer& value)
{
    return concat({little(id, 2), little(value.size(), 2), value});
}

Buffer attributeList(const Buffer& pairs)
{
    return concat({pairs, avPair(0, {})});
}

Buffer ntlmV2Response(const Buffer& pairs, size_t trailing = 0, uint8_t type = 1)
{
    return concat({Buffer(16, 0x11), Buffer{type, 1, 0, 0, 0, 0, 0, 0}, Buffer(8, 0x22), Buffer(8, 0x33),
        Buffer(4, 0), attributeList(pairs), Buffer(trailing, 0)});
}

Buffer smb2Frame(uint16_t command, bool response, uint32_t status, const Buffer& body)
{
    auto message = concat({Buffer{0xfe, 'S', 'M', 'B'}, little(64, 2), little(0, 2), little(status, 4),
        little(command, 2), little(1, 2), little(response ? 1 : 0, 4), little(0, 4), little(7, 8), little(0, 8),
        little(0x1234, 8), Buffer(16, 0)});
    append(message, body);
    Buffer frame{0, static_cast<uint8_t>(message.size() >> 16)};
    word(frame, static_cast<uint16_t>(message.size()));
    append(frame, message);
    return frame;
}

Buffer negotiateResponse(const Buffer& security)
{
    auto body = concat({little(65, 2), little(1, 2), little(0x0210, 2), little(0, 2), Buffer(16, 9), little(7, 4),
        little(65536, 4), little(65536, 4), little(65536, 4), Buffer(16, 0), little(128, 2),
        little(security.size(), 2), little(0, 4)});
    append(body, security);
    return smb2Frame(0, true, 0, body);
}

Buffer sessionSetupRequest(const Buffer& security, uint16_t structure = 25, uint16_t offset = 88)
{
    auto body = concat({little(structure, 2), Buffer{0, 1}, little(0, 4), little(0, 4), little(offset, 2),
        little(security.size(), 2), little(0, 8)});
    append(body, security);
    return smb2Frame(1, false, 0, body);
}

Buffer sessionSetupResponse(uint32_t status, uint16_t flags, const Buffer& security, size_t declared = SIZE_MAX,
    uint16_t offset = 72)
{
    auto body = concat({little(9, 2), little(flags, 2), little(offset, 2),
        little(declared == SIZE_MAX ? security.size() : declared, 2)});
    append(body, security);
    return smb2Frame(1, true, status, body);
}

// Recorded exchanges: an MIT Kerberos KDC and a Samba SMB2 server (NTLMv2 logon with MIC), as sent on the wire.
struct Recorded
{
    Buffer asRequest, preauthRequired, tgsRequest, kerberoastReply, negotiateToken, ntlmNegotiate, ntlmChallenge, ntlmAuthenticate, sessionFinal;
};

const Recorded& recordedVectors()
{
    static const Recorded value{
        fromHex(
            "000000b96a81b63081b3a103020105a20302010aa31a3018300aa10402020096a2020400300aa10402020095a2020400a4"
            "818a308187a00703050000000010a1123010a003020101a10930071b05616c696365a20e1b0c4558414d504c452e544553"
            "54a321301fa003020102a11830161b066b72627467741b0c4558414d504c452e54455354a511180f323032363130313032"
            "33353131305aa70602044646428ba81a301802011202011102011402011302011002011702011902011a"),
        fromHex(
            "000000ed7e81ea3081e7a003020105a10302011ea411180f32303236313030393233353132345aa50502030be900a60302"
            "0119a70e1b0c4558414d504c452e54455354a8123010a003020101a10930071b05616c696365a90e1b0c4558414d504c45"
            "2e54455354aa21301fa003020102a11830161b066b72627467741b0c4558414d504c452e54455354ab101b0e4e45454445"
            "445f50524541555448ac530451304f300aa10402020088a20204003027a103020113a220041e301c301aa003020112a113"
            "1b114558414d504c452e54455354616c6963653009a103020102a2020400300da10402020085a20504034d4954"),
        fromHex(
            "000003f06c8203ec308203e8a103020105a20302010ca38203683082036430820284a103020101a282027b048202776e82"
            "02733082026fa003020105a10302010ea20703050000000000a382019c6182019830820194a003020105a10e1b0c455841"
            "4d504c452e54455354a221301fa003020102a11830161b066b72627467741b0c4558414d504c452e54455354a382015830"
            "820154a003020112a103020101a2820146048201423c5f75e83be4c33719a8efa392d89247d4a07ce0c67dc0bba92d40f0"
            "46f98856fb7027252c5e63a923758c13f8ea1715b00aee4deade1adaa30d7bfd357d11d027dba9f8205a27e629b8af05f9"
            "c17d6e5b15ae3a1a6c73197a1a0445ca2b249ee3e46971e1d6c0aa06cc351531046a01e7edc3f510636d717b44af4d7902"
            "579e8032065fc5b7523653de685b34cf7c8081d85388a58bfde13a6c90b87052997b89dbddd05ed4e20984cb73bdb60e0e"
            "75e61651f2baaa06fa8a633e272cf4b445a1aea5ff5ad8a349bade4749a42b05a88fc77e2791f0204860cef71adac17d52"
            "c77f2ec82ecc6530d047eac3ddc3d64b84e58065a9822b3ff04d7f694129da0d8b68c951a0e57a15303b787577d0986908"
            "6d0bbc660be2b0b79a559c26be8d829ed8fdea25cde24472fbefeceb11e2d53351ffcde29edf9d15806026fffc9ed2eb2e"
            "a481b93081b6a003020112a281ae0481aba0abad31aee3a50c4fe9a04bfd70a1a9e9b9b2ed9d77ac2879eafb26f8380e93"
            "a08713556e6d10db0f38c323c3f749b22060fc868e316819a0b432319a211f64a5af078027b1157ad03602f669b0ab5e79"
            "e1b3ed36a8f47765e656ab34a67be87b7014a7a53444c6c474f66f4b21ce15c0c07dc425304e2f973c9e24f4faf8cc8d1e"
            "5604ddc1f6cdb43d92c0559a70a7d66da87c48a799e76c64d4c3fd5500bd4af572799b8be8bd2e9cda3081d9a104020200"
            "88a281d00481cda081ca3081c7a1173015a003020110a10e040cde5044f4a2fda4d9584c9b4ea281ab3081a8a003020112"
            "a281a004819d1b48b173f3dc8897f675ba29452f9d74a9e64f4e7fa9dbdad6d9d5d75dc86f3ababe395f7a44ae0052a492"
            "5546f5b64af117f72f97f79fac22104fd4c399ad30c2b9a93e577c3af81e064c35d0ae70d19d52c0e7343b1366141d8db6"
            "c1c23aa7cf03022982e5a82add3be2f6d3e831792c1b4060351288a8051db6abe4330c9b03007819406c11b479e1245561"
            "22cbb2b0bbfe63956506db772eace107a470306ea00703050000010000a20e1b0c4558414d504c452e54455354a31c301a"
            "a003020101a11330111b04636966731b096c6f63616c686f7374a511180f32303236313031303233353231375aa7060204"
            "379ca82fa81a301802011202011102011402011302011002011702011902011a"),
        fromHex(
            "000003d06d8203cc308203c8a003020105a10302010da281dc3081d93081d6a10402020088a281cd0481caa081c73081c4"
            "a081c13081bea003020112a281b60481b34b0d997331c21def43d9c3745a1ad1e99ad8470f1c3b1390058b5c6c32b9753d"
            "8a6987d5ed7024d6dec5ad8205bcd2be3870bbbdeee6a691a7fde71257125d37f21aba3971aa13446e686f472e5c24d4e7"
            "d68eb9497ff5a443b16396d0f5e31b3f65803f028f20691282ba7359bb41a3b450e4e0f777ffc5ad0a25e6172f0eb60cde"
            "3a2961842f69a91c48d169026bf50bfc583cf1cafe6d7b0920ae15f5c31d9c3ca3c7c9f11c407724f14f5c7d753efa6bf9"
            "a30e1b0c4558414d504c452e54455354a4123010a003020101a10930071b05616c696365a58201ca618201c6308201c2a0"
            "03020105a10e1b0c4558414d504c452e54455354a2263024a003020101a11d301b1b04686f73741b137263347376632e65"
            "78616d706c652e74657374a38201813082017da003020117a103020101a282016f0482016b12e277e3ecafcd71112501d4"
            "362ad9e28852bfecccc1c90b968636abd0386caa8ff9e47cf245aaa2325a396139fdfc7d5d1fdda01051fbdbaa16329f42"
            "a4dd08fa240f7b182c22392d31cf791d6c86d6a51e0f587ea74c589f0df766c722f030c388679fc84d66b106cfc976ef3e"
            "996ed154b80135ec69317e4691a5e5194df73f01f6f67cfcdc60b044e92058075acdeff98601430b1e7eab83e9d66df0bf"
            "1ccc9543a2efa5278db521593a9059a8960db7d93802862c2063a111b0bb7ccb40fdd5b29fd34450e8b2c350a2dd29fcd1"
            "52326aa73a43fcb37af0023966a6c884b12f85792020e2c4db5055db2bd590aecccec5065f759577aa2270a1a32c51d8eb"
            "5a61761d7a223e63b541bc9813b9c0db1de8699d2739d929cac4e1bce47bd79b7ae3122da4903c4bf1e0db6b868b9e7a60"
            "851d6f1a5386849a61b33b8f689d84f89b0cf0765f623a224612132d6240b0e0635a37afe0cf662bcd6e34a54c9e9948c4"
            "fea228514179c52ba681ea3081e7a003020112a281df0481dc4e7629a985ceb90a0eb52e41792fa1e0b7f8e490c89059b6"
            "cf84d92d4e783baff4ab5e5acb396069dab722601ebee784275d1b19400b73c3999216e3703b32e1425cc8c5d6f495f728"
            "41be590bae187f8346ba5d7abba5f36e8dd37615e43acd01f83159a4a50fe871ea37db54b3e85ea262ede0ec0a4ba0f800"
            "e48fd21deecc2129258b2e80fac775c6bce18547c1dca7ab84ba91e6ab868ff43524a54aee9b9ce7143532693a80cb7f0b"
            "e9dbe95072f8147037397b2ff1b30a4314bfaa8c3849d70c41c9252ef427c59a329472efe6a2f4491b1008c266effbf227"),
        fromHex(
            "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e6564"
            "5f696e5f5246433431373840706c656173655f69676e6f7265"),
        fromHex(
            "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000158208"
            "6200000000280000000000000028000000060100000000000f"),
        fromHex(
            "a18181307fa0030a0101a10c060a2b06010401823702020aa26a04684e544c4d5353500002000000040004003800000015"
            "828a62ee340552f90ba10700000000000000002c002c003c000000060100000000000f56004d000200040056004d000100"
            "040056004d00040000000300040076006d0007000800f868ba594958dd0100000000"),
        fromHex(
            "a182018830820184a282016c048201684e544c4d53535000030000001800180058000000c800c800700000000e000e0038"
            "0100000e000e00460100000400040054010000100010005801000015820862060100000000000fd327069c6fddb85eb4dd"
            "53cb144fe11f00000000000000000000000000000000000000000000000016bed43b34365fb9f0a6ffc3180a232c010100"
            "0000000000f868ba594958dd01d323eaad736575e6000000000200040056004d000100040056004d000400000003000400"
            "76006d0007000800f868ba594958dd01060004000200000008003000300000000000000000000000000000002e70b67a5e"
            "83adfdaaa3277864ec56bc31b29d1ba1ee1f39b98239aa27a112510a001000000000000000000000000000000000000900"
            "1c0063006900660073002f003100320037002e0030002e0030002e00310000000000540045005300540047005200500073"
            "006d006200750073006500720056004d00e5593b35d2acf5ea96e39c192621b740a3120410010000003ff2f919270439aa"
            "00000000"),
        fromHex(
            "a11b3019a0030a0100a312041001000000ad00516c3edac27200000000")};
    return value;
}

struct Outcome
{
    bool valid{true}, finished{};
    std::vector<nlohmann::json> reports;
    std::vector<FramedMessage::Kind> kinds;
    size_t passthrough{}, memory{};
    bool limited{};
};

Outcome observe(const Buffer& bytes, bool split)
{
    FramedStream framing;
    Outcome outcome;
    auto sink = [&](const FramedMessage& message)
    {
        if (message.fields.empty())
            outcome.passthrough += message.payload.size();
        else
        {
            outcome.reports.push_back(message.fields);
            outcome.kinds.push_back(message.kind);
        }
        return true;
    };
    if (split)
        for (size_t offset = 0; outcome.valid && offset < bytes.size(); ++offset)
            outcome.valid = framing.feed(Bytes(bytes).subspan(offset, 1), sink);
    else
        outcome.valid = framing.feed(bytes, sink);
    outcome.finished = framing.finished();
    outcome.memory = framing.memory();
    outcome.limited = framing.limited();
    return outcome;
}

nlohmann::json securityEvidence(const Buffer& token, bool response)
{
    nlohmann::json fields = nlohmann::json::object();
    parseSecurityBuffer(token, response, fields);
    return fields;
}

nlohmann::json ntlmEvidence(const Buffer& message, bool response, const char* name)
{
    const auto fields = securityEvidence(message, response);
    require(fields.size() == 1 && fields.contains(name), "An NTLM message produced unexpected evidence");
    return fields[name];
}

bool undecoded(const Buffer& token, bool response)
{
    const auto fields = securityEvidence(token, response);
    return fields == nlohmann::json{{"spnego_token_undecoded", true}};
}
}

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
    const nlohmann::json expectedTgsRequest{{"krb_tgs_request", {{"authenticator_encryption", "aes256-cts-hmac-sha1-96"},
        {"offered_encryption_types", offered}, {"preauthentication", names({"PA-TGS-REQ", "PA-FX-FAST"})},
        {"service_principal", "cifs/localhost"}, {"ticket_granting_ticket_encryption", "aes256-cts-hmac-sha1-96"}}}};
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
    require(single(kdcRequest(true, {18, 17}, {preauthData(1, apRequest(18, 17, 0x20))}, kerberosTicket(23, FileService))) ==
        nlohmann::json{{"krb_tgs_request", {{"offered_encryption_types", names({"aes256-cts-hmac-sha1-96",
        "aes128-cts-hmac-sha1-96"})}, {"preauthentication", names({"PA-TGS-REQ"})},
        {"service_principal", "cifs/server.example.test"}, {"ticket_granting_ticket_encryption", "aes256-cts-hmac-sha1-96"},
        {"authenticator_encryption", "aes128-cts-hmac-sha1-96"}, {"additional_ticket_encryption", "rc4-hmac"}}}},
        "TGS ticket, authenticator, or additional-ticket encryption was lost");
    require(single(kdcRequest(false, {23}, {preauthData(2, kerberosEncrypted(23))})) == nlohmann::json{{"krb_as_request", {
        {"offered_encryption_types", names({"rc4-hmac"})}, {"preauthentication", names({"PA-ENC-TIMESTAMP"})},
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
        described.dump().find("saltvalue") == std::string::npos, "Error pre-authentication data was lost or kept a salt");
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
    rejected(patched(kdcReply(false, 18, 18), "a10302010b", "a10302010d"), "A reply with the wrong message type was accepted");
    rejected(patched(kerberosError(25), "a10302011e", "a10302011f"), "An error with the wrong message type was accepted");
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
    const auto flagNames = names({"Sign", "NTLM", "Always sign", "Extended session security", "128-bit", "Key exchange"});
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
                require(report.dump().find(name) == std::string::npos, "NTLM evidence retained an account or domain name");
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
            server.reports[2]["smb_session_guest"] == false && server.reports[2]["smb_session_anonymous"] == false &&
            server.reports[2]["smb_session_encryption_required"] == false &&
            server.reports[2]["spnego_server_state"] == "accept-completed" &&
            server.reports[2]["spnego_server_mech_list_mic"] == true, "Recorded server SPNEGO messages were mis-decoded");
    }

    // NTLM response strength is derived from the response structures and flags, never from account data.
    const uint32_t v2Flags = 0x62088215;
    const auto weak = ntlmEvidence(ntlmType3(0x200, Buffer(24, 0x66), Buffer(24, 0x77)), false, "ntlm_authenticate");
    require(weak["nt_response"] == "NTLMv1" && weak["lm_response"] == "LM" && weak["message_integrity_code"] == false &&
        weak["channel_bindings"] == false && !weak.contains("attributes"), "A plain NTLMv1 response was not identified");
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
        require(ntlmEvidence(ntlmType3(header == 64 ? 0x200 : 0x02000200, Buffer(24, 1), Buffer(24, 2), "x", true, header),
            false, "ntlm_authenticate")["nt_response"] == "NTLMv1", "An NTLM header size was not accepted");
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
    require(!undecoded(good, false) && undecoded(good, true), "An NTLM authenticate message was accepted from a server");
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
    require(securityEvidence(raw, false).contains("ntlm_authenticate"), "A raw NTLMSSP security buffer was not decoded");
    for (size_t size = 1; size < raw.size(); ++size)
        require(undecoded(Buffer(raw.begin(), raw.begin() + size), false), "A truncated NTLM message produced evidence");
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
    require(evidence == nlohmann::json{{"spnego_client_mechanisms", mechanisms}, {"krb_ap_request", {
        {"ticket_encryption", "aes256-cts-hmac-sha1-96"}, {"authenticator_encryption", "aes128-cts-hmac-sha1-96"},
        {"mutual_authentication_required", true}, {"user_to_user", false}, {"service_principal", "cifs/server.example.test"}}}},
        "A Kerberos AP request in SPNEGO was mis-decoded");
    evidence = securityEvidence(init(0x40), false);
    require(evidence["krb_ap_request"]["user_to_user"] == true &&
        evidence["krb_ap_request"]["mutual_authentication_required"] == false,
        "AP request options were not decoded");
    evidence = securityEvidence(negotiationResponse(0, KerberosOid, kerberosGss(0x0200, apReply(18))), true);
    require(evidence == nlohmann::json{{"spnego_server_state", "accept-completed"},
        {"spnego_server_selected_mechanism", "Kerberos"}, {"krb_ap_reply", {{"encryption", "aes256-cts-hmac-sha1-96"}}}},
        "A Kerberos AP reply in SPNEGO was mis-decoded");
    evidence = securityEvidence(negotiationResponse(2, KerberosOid, kerberosGss(0x0300, kerberosError(37))), true);
    require(evidence["spnego_server_state"] == "reject" && evidence["krb_error"]["name"] == "KRB_AP_ERR_SKEW",
        "A Kerberos error in SPNEGO was mis-decoded");
    require(securityEvidence(negotiationResponse(3, nullptr, {}, true), false) == nlohmann::json{
        {"spnego_client_state", "request-mic"}, {"spnego_client_mech_list_mic", true}}, "A bare SPNEGO continuation was mis-decoded");

    // Unrecognized or misdirected tokens keep the valid SPNEGO evidence and are flagged.
    evidence = securityEvidence(negotiationInit({NegoExOid, "2a864886f70d010101"}, ascii("opaque token")), false);
    require(evidence == nlohmann::json{{"spnego_client_mechanisms", names({"NegoEx", "1.2.840.113549.1.1.1"})},
        {"spnego_token_undecoded", true}}, "An unrecognized SPNEGO token hid the mechanism list");
    const auto request = kerberosGss(0x0100, apRequest(18, 18, 0)), reply = kerberosGss(0x0200, apReply(18));
    for (const auto& [token, response, decoded] : {std::tuple{request, true, false}, {reply, false, false},
        {kerberosGss(0x0400, apReply(18)), false, false}, {request, false, true}})
    {
        evidence = securityEvidence(negotiationInit({KerberosOid}, token), response);
        require(evidence.contains("krb_ap_request") == decoded && evidence.contains("spnego_token_undecoded") == !decoded &&
            evidence.contains(response ? "spnego_server_mechanisms" : "spnego_client_mechanisms"),
            "Kerberos tokens from the wrong role or of unknown type were accepted");
    }
    require(undecoded(ascii("garbage!"), false) && undecoded(Buffer{0x60, 0x03, 0x06, 0x01, 0x2a}, false) &&
        undecoded(negotiationInit({}, {}), false), "Malformed SPNEGO was not flagged");

    // SMB SESSION_SETUP framing: session flags are reported, error responses carry no security buffer, and bad structure is rejected.
    for (const auto& [flag, key] : {std::pair{1, "smb_session_guest"}, {2, "smb_session_anonymous"},
        {4, "smb_session_encryption_required"}})
    {
        const auto outcome = observe(sessionSetupResponse(0, static_cast<uint16_t>(flag), {}), false);
        require(outcome.valid && outcome.reports.size() == 1 && outcome.reports[0][key] == true &&
            !outcome.reports[0].contains("spnego_token_undecoded"), "SMB session flags were lost");
    }
    const auto failure = observe(smb2Frame(1, true, 0xc000006d, concat({little(9, 2), Buffer{0, 0}, little(0, 4), Buffer{0}})),
        true);
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
    const auto garbageNegotiate = observe(negotiateResponse(ascii("garbage!")), false);
    require(garbageNegotiate.valid && garbageNegotiate.reports[0]["spnego_token_undecoded"] == true,
        "An undecodable NEGOTIATE security buffer was not flagged");
}

void kerberosUdpCoverage()
{
    // Replay KDC messages as individual UDP datagrams on standard and alternate ports in both IP families.
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
            Engine engine(health, [&](Observation observation) { output.push_back(std::move(observation)); });
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
                require(output.size() == index + 1 && output.back().protocol == Observation::Protocol::Kerberos &&
                    output.back().udp && output.back().application->fields.size() == 1 &&
                    output.back().application->fields.contains(fields[index]) &&
                    output.back().source.port == 42000 && output.back().destination.port == port &&
                    output.back().source.family == (ipv6 ? 6 : 4) &&
                    output.back().firstUs == output.back().lastUs &&
                    output.back().endedUs == output.back().lastUs &&
                    (index == 0 || output.back().flowId != output[index - 1].flowId),
                    "UDP KDC messages were lost, combined, or assigned to the wrong endpoint");
            }
            CryptoCatalog catalog;
            auto summary = nlohmann::json::parse(catalog.summarize(output[3], [](auto&, auto&, Bytes) {}).json);
            require(summary["transport"] == "UDP" && summary["krb_tgs_reply"]["ticket_encryption"] == "rc4-hmac" &&
                summary["handshake_confirmation"].get<std::string>().find("unverified") != std::string::npos &&
                summary.dump().find("alice") == std::string::npos && !summary.contains("krb_tgs_request"),
                "UDP Kerberos lost weak-encryption evidence, retained an account, or implied correlation");

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
                health.bufferedBytes == 0 && health.activeFlows == 0,
                "UDP Kerberos fragmentation leaked state or corrupted evidence");

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
            evidence["krb_error"]["code"] == 25 && evidence["handshake_confirmation"].get<std::string>().find("unverified") !=
            std::string::npos, "Kerberos evidence was lost or implied authentication");
        Counters replyHealth;
        output = replayConnection(asRequest, kdcFrame(kdcReply(false, 18, 23)), 88, replyHealth);
        require(!output.empty() && output.back().state == "kerberos_reply" && replyHealth.malformed == 0,
            "A Kerberos reply exchange was not classified");
        evidence = summarized(output.back());
        require(evidence["krb_as_reply"]["reply_encryption"] == "rc4-hmac" &&
            evidence["krb_as_request"]["offered_encryption_types"].size() == 8, "Kerberos request and reply evidence were not merged");
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
        const auto failure = smb2Frame(1, true, 0xc000006d, concat({little(9, 2), Buffer{0, 0}, little(0, 4), Buffer{0}}));
        auto output = replayConnection(
            concat({sessionSetupRequest(ntlmNegotiate), sessionSetupRequest(ntlmAuthenticate)}),
            concat({negotiateResponse(negotiateToken), sessionSetupResponse(0xc0000016, 0, ntlmChallenge), failure}), 445, health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Smb &&
            output.back().state == "smb_authentication" && health.malformed == 0, "An SMB logon failure was not classified");
        const auto evidence = summarized(output.back());
        require(evidence["protocol"] == "SMB" && evidence["ntlm_authenticate"]["nt_response"] == "NTLMv2" &&
            evidence["smb_session_setup_status"] == "0xC000006D" && evidence["spnego_server_mechanisms"] == nlohmann::json::array({"NTLM"}) &&
            evidence.dump().find("smbuser") == std::string::npos, "SMB authentication evidence was lost or kept an account name");
    }
}


void networkCoverage()
{
    smbLegacyCoverage();
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
    require(unencryptedTds.feed(tdsFrame(prelogin), [](const FramedMessage&) { return true; }) &&
        unencryptedTds.feed(Buffer{0x10, 1, 0, 20, 0, 0, 1, 0}, [&](const FramedMessage& message)
        {
            if (!message.payload.empty() || message.kind != FramedMessage::Kind::Tds ||
                message.fields != nlohmann::json{{"tds_unencrypted_login_observed", true}})
                throw std::runtime_error("LOGIN7 payload reached TLS inspection");
            ++unencryptedLogins;
            return true;
        }) && unencryptedLogins == 1 && unencryptedTds.finished() && unencryptedTds.memory() == 0,
        "Plain LOGIN7 traffic was counted as a malformed handshake or retained its private payload");
    FramedStream implausibleLogin;
    require(implausibleLogin.feed(tdsFrame(prelogin), [](const FramedMessage&) { return true; }) &&
        implausibleLogin.feed(Buffer{0x10, 0x40, 0, 20, 0, 0, 1, 0}, [](const FramedMessage&) -> bool
            { throw std::runtime_error("An implausible LOGIN7 header produced evidence"); }) &&
        implausibleLogin.finished(), "An implausible LOGIN7 header did not end TDS inspection quietly");

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
        Buffer login{0x10, 1, 0, 102, 0, 0, 1, 0};
        login.resize(102, 'Q');
        Counters health;
        auto output = replayConnection(concat({options(2, false), login}), options(2, true), 1433, health);
        require(!output.empty() && output.back().protocol == Observation::Protocol::Tds &&
            output.back().state == "tds_prelogin" && health.malformed == 0 && health.reassemblyLimit == 0 &&
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
            TcpPacket value;
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
            Engine engine(counters, [&](Observation row)
                { if (!row.lifecycleOnly) observations.push_back(std::move(row)); });
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
        Engine engine(counters, [&](Observation row)
            { if (!row.lifecycleOnly) observations.push_back(std::move(row)); });
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

    // A known CID links rebinding even after Initial inspection has released its decryption state.
    std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "quic.json");
    const auto fixtures = nlohmann::json::parse(input);
    Counters counters;
    std::vector<Observation> observations;
    Engine engine(counters, [&](Observation row)
        { if (!row.lifecycleOnly) observations.push_back(std::move(row)); });
    for (const auto& encoded : fixtures[0]["packets"])
        engine.packet(fromHex(encoded.get<std::string>()), PacketKind::Ip, 1000000);
    const auto original = observations.back();
    auto id = fromHex(original.quicServerId);
    Buffer shortPacket{0x40};
    append(shortPacket, id);
    shortPacket.resize(shortPacket.size() + 20);
    TcpPacket migrated;
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
