#include "Engine.h"
#include "Rpc.h"
#include "SmbPipe.h"
#include <algorithm>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);

void rpcCoverage()
{
    using Buffer = std::vector<uint8_t>;
    auto write16 = [](Buffer& bytes, size_t offset, uint16_t value, bool big)
    {
        bytes[offset] = static_cast<uint8_t>(big ? value >> 8 : value);
        bytes[offset + 1] = static_cast<uint8_t>(big ? value : value >> 8);
    };
    auto write32 = [](Buffer& bytes, size_t offset, uint32_t value, bool big)
    {
        for (size_t index = 0; index < 4; ++index)
            bytes[offset + index] = static_cast<uint8_t>(value >> (big ? 24 - index * 8 : index * 8));
    };
    auto bind = [&](uint8_t kind, uint8_t type, uint8_t level, bool authenticated, bool big = false,
        size_t contexts = 1)
    {
        Buffer pdu{5, 0, kind, 3, static_cast<uint8_t>(big ? 0 : 0x10), 0, 0, 0};
        pdu.resize(28, 0);
        write32(pdu, 12, 0x12345678, big);
        write16(pdu, 16, 4280, big);
        write16(pdu, 18, 4280, big);
        pdu[24] = static_cast<uint8_t>(contexts);
        for (size_t index = 0; index < contexts; ++index)
        {
            Buffer context(44, 0);
            context[2] = 1;
            context[4] = 8;
            context[5] = 0x83;
            context[6] = 0xaf;
            context[7] = 0xe1;
            context[24] = 4;
            context[25] = 0x5d;
            context[26] = 0x88;
            context[27] = 0x8a;
            pdu.insert(pdu.end(), context.begin(), context.end());
        }
        if (authenticated)
        {
            const size_t padding = (16 - pdu.size() % 16) % 16;
            pdu.resize(pdu.size() + padding, 0);
            pdu.insert(pdu.end(), {type, level, static_cast<uint8_t>(padding), 0, 0, 0, 0, 0});
            write32(pdu, pdu.size() - 4, 0xaabbccdd, big);
            for (const char byte : std::string_view("private-token"))
                pdu.push_back(static_cast<uint8_t>(byte));
            write16(pdu, 10, 13, big);
        }
        write16(pdu, 8, static_cast<uint16_t>(pdu.size()), big);
        return pdu;
    };

    // Bind evidence reports the requested provider and protection level without retaining the token.
    nlohmann::json fields;
    require(parseRpcBind(bind(11, 0, 0, false), fields) && fields["rpc_bind"] == nlohmann::json{
        {"kind", "Bind"}, {"call_id", 0x12345678}, {"authentication_type", "None"},
        {"protection_level", "None"}, {"authentication_trailer_present", false}},
        "An unauthenticated RPC bind was not identified");
    fields.clear();
    require(parseRpcBind(bind(11, 10, 5, true), fields) &&
        fields["rpc_bind"]["authentication_type"] == "NTLM" &&
        fields["rpc_bind"]["authentication_type_id"] == 10 &&
        fields["rpc_bind"]["protection_level"] == "Packet integrity" &&
        fields["rpc_bind"]["protection_level_id"] == 5 &&
        fields["rpc_bind"]["authentication_context_id"] == 0xaabbccdd &&
        fields.dump().find("private-token") == std::string::npos,
        "An authenticated RPC bind lost its security level or retained its token");
    fields.clear();
    require(parseRpcBind(bind(14, 16, 6, true, true, 2), fields) &&
        fields["rpc_bind"]["kind"] == "Alter context" &&
        fields["rpc_bind"]["call_id"] == 0x12345678 &&
        fields["rpc_bind"]["authentication_type"] == "Kerberos" &&
        fields["rpc_bind"]["protection_level"] == "Packet privacy" &&
        fields["rpc_bind"]["authentication_context_id"] == 0xaabbccdd,
        "A big-endian RPC alter context lost its authentication details");
    fields.clear();
    require(parseRpcBind(bind(11, 0x77, 0x7f, true), fields) &&
        fields["rpc_bind"]["authentication_type"] == "Unknown" &&
        fields["rpc_bind"]["authentication_type_id"] == 0x77 &&
        fields["rpc_bind"]["protection_level"] == "Unknown" &&
        fields["rpc_bind"]["protection_level_id"] == 0x7f,
        "An unknown RPC authentication value lost its numeric identifier");

    // Split and coalesced PDUs retain each bind through framing and observation merging.
    const auto first = bind(11, 10, 5, true), second = bind(14, 16, 6, true);
    Buffer exchange = first;
    exchange.insert(exchange.end(), second.begin(), second.end());
    for (const size_t segment : {size_t{1}, exchange.size()})
    {
        FramedStream framing;
        std::vector<nlohmann::json> reports;
        for (size_t offset = 0; offset < exchange.size(); offset += segment)
            require(framing.feed(Bytes(exchange).subspan(offset, std::min(segment, exchange.size() - offset)),
                [&](const FramedMessage& message)
                {
                    require(message.kind == FramedMessage::Kind::Rpc, "An RPC bind used the wrong framed kind");
                    reports.push_back(message.fields);
                    return true;
                }), "An RPC bind was rejected during stream framing");
        require(reports.size() == 2 && reports[0]["rpc_bind"]["authentication_type"] == "NTLM" &&
            reports[1]["rpc_bind"]["authentication_type"] == "Kerberos",
            "Split or coalesced RPC binds were not framed separately");

        Counters health;
        std::vector<Observation> observations;
        Engine engine(health, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                observations.push_back(std::move(observation));
        });
        TransportPacket outbound;
        outbound.source.address[0] = outbound.destination.address[0] = 10;
        outbound.source.address[3] = 1;
        outbound.destination.address[3] = 2;
        outbound.source.port = 50123;
        outbound.destination.port = 135;
        outbound.sequence = 1000;
        outbound.flags = 2;
        engine.tcp(outbound, 1);
        TransportPacket inbound = outbound;
        std::swap(inbound.source, inbound.destination);
        inbound.sequence = 9000;
        inbound.flags = 0x12;
        engine.tcp(inbound, 2);
        outbound.sequence = 1001;
        outbound.flags = 0x18;
        for (size_t offset = 0; offset < exchange.size(); offset += segment)
        {
            outbound.payload = Bytes(exchange).subspan(offset, std::min(segment, exchange.size() - offset));
            engine.tcp(outbound, static_cast<int64_t>(3 + offset));
            outbound.sequence += static_cast<uint32_t>(outbound.payload.size());
        }
        engine.expire(1000000, true);
        const auto merged = std::find_if(observations.rbegin(), observations.rend(), [](const Observation& item)
        {
            return item.protocol == Observation::Protocol::Rpc && item.application &&
                item.application->fields.contains("rpc_binds");
        });
        require(merged != observations.rend() && merged->application->fields["rpc_binds"].size() == 2 &&
            merged->application->fields["rpc_binds"][0]["protection_level"] == "Packet integrity" &&
            merged->application->fields["rpc_binds"][1]["protection_level"] == "Packet privacy" &&
            !merged->application->fields.contains("rpc_bind") &&
            merged->application->fields.dump().find("private-token") == std::string::npos,
            "RPC bind security levels were lost or tokens retained during observation merging");
    }

    // Incomplete context lists and trailers never produce a bind observation.
    auto malformed = bind(11, 9, 4, true);
    malformed[24] = 2;
    fields.clear();
    require(!parseRpcBind(malformed, fields) && fields.empty(), "An incomplete RPC context list was accepted");
    malformed = bind(11, 9, 4, true);
    malformed[82] = 7;
    require(!parseRpcBind(malformed, fields) && fields.empty(), "An inconsistent RPC auth padding length was accepted");
    malformed = bind(11, 9, 4, true);
    malformed.pop_back();
    require(!parseRpcBind(malformed, fields) && fields.empty(), "A truncated RPC token was accepted");
    malformed = bind(11, 9, 4, true);
    malformed[4] = 0x11;
    require(!parseRpcBind(malformed, fields) && fields.empty(), "An unsupported RPC data representation was accepted");

    // A non-bind PDU is valid framing but adds no bind evidence.
    Buffer other{5, 0, 12, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0};
    require(parseRpcBind(other, fields) && fields.empty(), "A non-bind RPC PDU produced bind evidence");

    // A named-pipe tree and successful CREATE establish the handle before its data is read as RPC.
    auto write64 = [&](Buffer& bytes, size_t offset, uint64_t value)
    {
        write32(bytes, offset, static_cast<uint32_t>(value), false);
        write32(bytes, offset + 4, static_cast<uint32_t>(value >> 32), false);
    };
    auto smb = [&](uint16_t command, bool response, uint64_t messageId, uint32_t tree, Buffer body)
    {
        Buffer frame(64, 0);
        frame[0] = 0xfe; frame[1] = 'S'; frame[2] = 'M'; frame[3] = 'B';
        write16(frame, 4, 64, false);
        write16(frame, 12, command, false);
        write32(frame, 16, response ? 1 : 0, false);
        write64(frame, 24, messageId);
        write32(frame, 36, tree, false);
        write64(frame, 40, 0x100);
        frame.insert(frame.end(), body.begin(), body.end());
        return frame;
    };
    auto treeRequest = [&]()
    {
        Buffer body(20, 0);
        write16(body, 0, 9, false);
        write16(body, 4, 72, false);
        write16(body, 6, 12, false);
        const std::string name = "IPC$aa";
        for (size_t index = 0; index < name.size(); ++index)
            body[8 + index * 2] = static_cast<uint8_t>(name[index]);
        return smb(3, false, 1, 0, body);
    };
    auto treeResponse = [&](uint8_t shareType)
    {
        Buffer body(16, 0);
        write16(body, 0, 16, false);
        body[2] = shareType;
        return smb(3, true, 1, 7, body);
    };
    auto createRequest = [&]()
    {
        Buffer body(68, 0);
        write16(body, 0, 57, false);
        write16(body, 44, 120, false);
        write16(body, 46, 12, false);
        const std::string name = "srvsvc";
        for (size_t index = 0; index < name.size(); ++index)
            body[56 + index * 2] = static_cast<uint8_t>(name[index]);
        return smb(5, false, 2, 7, body);
    };
    std::array<uint8_t, 16> fid{};
    fid[0] = 0xa1; fid[8] = 0xb2;
    auto createResponse = [&]()
    {
        Buffer body(88, 0);
        write16(body, 0, 89, false);
        std::copy(fid.begin(), fid.end(), body.begin() + 64);
        return smb(5, true, 2, 7, body);
    };
    auto writeRequest = [&](uint64_t id, Bytes data, bool rightHandle = true)
    {
        Buffer body(48, 0);
        write16(body, 0, 49, false);
        write16(body, 2, 112, false);
        write32(body, 4, static_cast<uint32_t>(data.size()), false);
        if (rightHandle)
            std::copy(fid.begin(), fid.end(), body.begin() + 16);
        body.insert(body.end(), data.begin(), data.end());
        return smb(9, false, id, 7, body);
    };
    auto readRequest = [&]()
    {
        Buffer body(48, 0);
        write16(body, 0, 49, false);
        std::copy(fid.begin(), fid.end(), body.begin() + 16);
        return smb(8, false, 5, 7, body);
    };
    auto readResponse = [&](Bytes data)
    {
        Buffer body(16, 0);
        write16(body, 0, 17, false);
        body[2] = 80;
        write32(body, 4, static_cast<uint32_t>(data.size()), false);
        body.insert(body.end(), data.begin(), data.end());
        return smb(8, true, 5, 7, body);
    };
    auto transceive = [&](bool response, Bytes data)
    {
        Buffer body(response ? 48 : 56, 0);
        write16(body, 0, response ? 49 : 57, false);
        write32(body, 4, 0x0011c017, false);
        std::copy(fid.begin(), fid.end(), body.begin() + 8);
        write32(body, response ? 32 : 24, response ? 112 : 120, false);
        write32(body, response ? 36 : 28, static_cast<uint32_t>(data.size()), false);
        body.insert(body.end(), data.begin(), data.end());
        return smb(11, response, 6, 7, body);
    };
    auto closeRequest = [&]()
    {
        Buffer body(24, 0);
        write16(body, 0, 24, false);
        std::copy(fid.begin(), fid.end(), body.begin() + 8);
        return smb(6, false, 7, 7, body);
    };
    auto netbios = [](const Buffer& payload)
    {
        Buffer framed{0, static_cast<uint8_t>(payload.size() >> 16),
            static_cast<uint8_t>(payload.size() >> 8), static_cast<uint8_t>(payload.size())};
        framed.insert(framed.end(), payload.begin(), payload.end());
        return framed;
    };
    const auto pipeBind = bind(11, 10, 5, true), pipeAlter = bind(14, 16, 6, true);
    const std::vector<std::pair<Buffer, int>> pipeFrames{
        {treeRequest(), 0}, {treeResponse(2), 1}, {createRequest(), 0}, {createResponse(), 1},
        {writeRequest(3, Bytes(pipeBind).first(10)), 0},
        {writeRequest(4, Bytes(pipeBind).subspan(10)), 0},
        {readRequest(), 0}, {readResponse(pipeAlter), 1},
        {transceive(false, pipeBind), 0}, {transceive(true, other), 1},
        {writeRequest(10, exchange), 0}};
    SmbPipeInspection pipeInspection;
    std::vector<nlohmann::json> pipeBinds;
    for (const auto& [frame, direction] : pipeFrames)
    {
        fields.clear();
        pipeInspection.feed(frame, direction, fields);
        if (fields.contains("rpc_bind_events"))
            for (const auto& item : fields["rpc_bind_events"])
                pipeBinds.push_back(item);
    }
    require(pipeBinds.size() == 5 && pipeBinds[0]["authentication_type"] == "NTLM" &&
        pipeBinds[1]["protection_level"] == "Packet privacy" &&
        pipeBinds[2]["transport"] == "SMB named pipe" && pipeBinds[4]["kind"] == "Alter context" &&
        pipeInspection.memory() < 20000,
        "SMB named-pipe WRITE, READ, or transceive data lost a fragmented RPC bind");

    // Unrelated files, unmatched responses, wrong handles, and closed pipes cannot produce bind evidence.
    SmbPipeInspection unrelated;
    for (const auto& [frame, direction] : std::vector<std::pair<Buffer, int>>{
        {treeRequest(), 0}, {treeResponse(1), 1}, {createRequest(), 0}, {createResponse(), 1},
        {writeRequest(3, pipeBind), 0}})
    {
        fields.clear();
        unrelated.feed(frame, direction, fields);
        require(!fields.contains("rpc_bind_events"), "RPC-shaped disk data was reported as a pipe bind");
    }
    fields.clear();
    pipeInspection.feed(readResponse(pipeBind), 1, fields);
    pipeInspection.feed(writeRequest(8, pipeBind, false), 0, fields);
    pipeInspection.feed(closeRequest(), 0, fields);
    pipeInspection.feed(writeRequest(9, pipeBind), 0, fields);
    pipeInspection.feed(readResponse(pipeBind), 1, fields);
    require(!fields.contains("rpc_bind_events"),
        "An unmatched read response or a wrong or closed pipe handle produced an RPC bind");

    // Disconnecting a tree discards partial RPC bytes and allows a later pipe with the same identifiers.
    SmbPipeInspection treeEviction;
    for (size_t index = 0; index < 4; ++index)
    {
        fields.clear();
        treeEviction.feed(pipeFrames[index].first, pipeFrames[index].second, fields);
    }
    treeEviction.feed(writeRequest(3, Bytes(pipeBind).first(10)), 0, fields);
    const size_t beforeDisconnect = treeEviction.memory();
    Buffer disconnect(4, 0);
    write16(disconnect, 0, 4, false);
    treeEviction.feed(smb(4, false, 11, 7, disconnect), 0, fields);
    require(treeEviction.memory() < beforeDisconnect, "A disconnected SMB tree retained partial RPC bytes");
    for (size_t index = 0; index < 4; ++index)
        treeEviction.feed(pipeFrames[index].first, pipeFrames[index].second, fields);
    fields.clear();
    treeEviction.feed(writeRequest(12, pipeBind), 0, fields);
    require(fields.contains("rpc_bind_events") && fields["rpc_bind_events"].size() == 1,
        "A reconnected SMB named pipe did not admit a fresh RPC bind");

    // Reused SMB2 tree and FileIds invalidate responses pending on their former pipe handles.
    SmbPipeInspection reusedSmb2;
    for (size_t index = 0; index < 4; ++index)
        reusedSmb2.feed(pipeFrames[index].first, pipeFrames[index].second, fields);
    reusedSmb2.feed(readRequest(), 0, fields);
    reusedSmb2.feed(createRequest(), 0, fields);
    reusedSmb2.feed(createResponse(), 1, fields);
    fields.clear();
    reusedSmb2.feed(readResponse(pipeAlter), 1, fields);
    require(!fields.contains("rpc_bind_events"), "A stale SMB2 read response attached to a reused FileId");
    reusedSmb2.feed(treeRequest(), 0, fields);
    reusedSmb2.feed(treeResponse(1), 1, fields);
    reusedSmb2.feed(writeRequest(12, pipeBind), 0, fields);
    require(!fields.contains("rpc_bind_events"), "A disk tree reused an SMB2 pipe TreeId");

    SmbPipeInspection evictedSmb2;
    evictedSmb2.feed(treeRequest(), 0, fields);
    evictedSmb2.feed(treeResponse(2), 1, fields);
    evictedSmb2.feed(createRequest(), 0, fields);
    for (uint32_t tid = 8; tid < 40; ++tid)
    {
        auto request = treeRequest(), reply = treeResponse(2);
        write64(request, 24, tid + 20);
        write64(reply, 24, tid + 20);
        write32(reply, 36, tid, false);
        evictedSmb2.feed(request, 0, fields);
        evictedSmb2.feed(reply, 1, fields);
    }
    evictedSmb2.feed(createResponse(), 1, fields);
    fields.clear();
    evictedSmb2.feed(writeRequest(13, pipeBind), 0, fields);
    require(!fields.contains("rpc_bind_events"), "An evicted SMB2 tree admitted a delayed pipe open");

    // Transport framing and observation merging retain the SMB outer protocol and omit authentication tokens.
    Counters smbHealth;
    std::vector<Observation> smbObservations;
    Engine smbEngine(smbHealth, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            smbObservations.push_back(std::move(observation));
    });
    TransportPacket client;
    client.source.address[0] = client.destination.address[0] = 10;
    client.source.address[3] = 1; client.destination.address[3] = 2;
    client.source.port = 50123; client.destination.port = 445;
    client.sequence = 1000; client.flags = 2;
    smbEngine.tcp(client, 1);
    TransportPacket server = client;
    std::swap(server.source, server.destination);
    server.sequence = 9000; server.flags = 0x12;
    smbEngine.tcp(server, 2);
    client.sequence = 1001; client.flags = 0x18;
    server.sequence = 9001; server.flags = 0x18;
    for (size_t index = 0; index < pipeFrames.size(); ++index)
    {
        const auto& [frame, direction] = pipeFrames[index];
        auto bytes = netbios(frame);
        auto& packet = direction ? server : client;
        packet.payload = bytes;
        smbEngine.tcp(packet, static_cast<int64_t>(index + 3));
        packet.sequence += static_cast<uint32_t>(bytes.size());
    }
    smbEngine.expire(1000000, true);
    const auto mergedPipe = std::find_if(smbObservations.rbegin(), smbObservations.rend(),
        [](const Observation& item)
    {
        return item.protocol == Observation::Protocol::Smb && item.application &&
            item.application->fields.contains("rpc_binds");
    });
    require(mergedPipe != smbObservations.rend() && mergedPipe->state == "smb_rpc_bind" &&
        mergedPipe->application->fields["rpc_binds"].size() == 5 &&
        mergedPipe->application->fields.dump().find("private-token") == std::string::npos &&
        smbHealth.malformed == 0, "SMB pipe RPC bind evidence was not merged into the SMB observation");

    // SMB1 needs a confirmed IPC tree and named-pipe FID before file data can be read as RPC.
    auto legacy = [&](uint8_t command, bool response, uint16_t mid, uint16_t uid, uint16_t tid,
        Buffer words, Buffer data, uint32_t status = 0)
    {
        Buffer frame(32, 0);
        frame[0] = 0xff; frame[1] = 'S'; frame[2] = 'M'; frame[3] = 'B';
        frame[4] = command;
        write32(frame, 5, status, false);
        frame[9] = response ? 0x80 : 0;
        write16(frame, 10, 0x4000, false);
        write16(frame, 24, tid, false);
        write16(frame, 26, 0x1234, false);
        write16(frame, 28, uid, false);
        write16(frame, 30, mid, false);
        frame.push_back(static_cast<uint8_t>(words.size() / 2));
        frame.insert(frame.end(), words.begin(), words.end());
        frame.push_back(static_cast<uint8_t>(data.size()));
        frame.push_back(static_cast<uint8_t>(data.size() >> 8));
        frame.insert(frame.end(), data.begin(), data.end());
        return frame;
    };
    auto legacyTreeRequest = [&]()
    {
        Buffer words(8, 0);
        words[0] = 0xff;
        write16(words, 6, 1, false);
        const std::string path = "\\\\server\\IPC$";
        Buffer data{0};
        data.insert(data.end(), path.begin(), path.end());
        data.insert(data.end(), {0, '?', '?', '?', '?', '?', 0});
        return legacy(0x75, false, 1, 3, 0, words, data);
    };
    auto legacyTreeResponse = [&](std::string service)
    {
        Buffer words(6, 0);
        words[0] = 0xff;
        Buffer data(service.begin(), service.end());
        data.insert(data.end(), {0, 0});
        return legacy(0x75, true, 1, 3, 7, words, data);
    };
    auto legacyCreateRequest = [&]()
    {
        Buffer words(48, 0);
        words[0] = 0xff;
        const std::string name = "\\srvsvc";
        write16(words, 5, static_cast<uint16_t>(name.size() + 1), false);
        Buffer data(name.begin(), name.end());
        data.push_back(0);
        return legacy(0xa2, false, 2, 3, 7, words, data);
    };
    auto legacyCreateResponse = [&](uint16_t type, uint32_t status = 0)
    {
        Buffer words(68, 0);
        words[0] = 0xff;
        write16(words, 5, 0x4001, false);
        write16(words, 63, type, false);
        return legacy(0xa2, true, 2, 3, 7, words, {}, status);
    };
    auto legacyWrite = [&](uint16_t mid, Bytes data, uint16_t fid = 0x4001, uint16_t tid = 7)
    {
        Buffer words(24, 0);
        words[0] = 0xff;
        write16(words, 4, fid, false);
        write16(words, 20, static_cast<uint16_t>(data.size()), false);
        write16(words, 22, 60, false);
        Buffer payload{0};
        payload.insert(payload.end(), data.begin(), data.end());
        return legacy(0x2f, false, mid, 3, tid, words, payload);
    };
    auto legacyRead = [&]()
    {
        Buffer words(20, 0);
        words[0] = 0xff;
        write16(words, 4, 0x4001, false);
        write16(words, 10, static_cast<uint16_t>(pipeAlter.size()), false);
        return legacy(0x2e, false, 5, 3, 7, words, {});
    };
    auto legacyReadResponse = [&](Bytes data)
    {
        Buffer words(24, 0);
        words[0] = 0xff;
        write16(words, 10, static_cast<uint16_t>(data.size()), false);
        write16(words, 12, 60, false);
        Buffer payload{0};
        payload.insert(payload.end(), data.begin(), data.end());
        return legacy(0x2e, true, 5, 3, 7, words, payload);
    };
    auto legacyTransaction = [&](Bytes data)
    {
        Buffer words(32, 0);
        write16(words, 2, static_cast<uint16_t>(data.size()), false);
        write16(words, 22, static_cast<uint16_t>(data.size()), false);
        words[26] = 2;
        write16(words, 28, 0x26, false);
        write16(words, 30, 0x4001, false);
        const std::string name = "\\PIPE\\";
        Buffer payload(name.begin(), name.end());
        payload.insert(payload.end(), {0, 0});
        const size_t offset = 32 + 1 + words.size() + 2 + payload.size();
        write16(words, 24, static_cast<uint16_t>(offset), false);
        payload.insert(payload.end(), data.begin(), data.end());
        return legacy(0x25, false, 6, 3, 7, words, payload);
    };
    auto legacyTransactionResponse = [&](Bytes data, uint16_t total, bool dos)
    {
        Buffer words(20, 0);
        write16(words, 2, total, false);
        write16(words, 12, static_cast<uint16_t>(data.size()), false);
        write16(words, 14, 56, false);
        Buffer payload{0};
        payload.insert(payload.end(), data.begin(), data.end());
        auto frame = legacy(0x25, true, 6, 3, 7, words, payload, dos ? 0x00ea0001 : 0x80000005);
        if (dos)
            write16(frame, 10, 0, false);
        return frame;
    };
    const std::vector<std::pair<Buffer, int>> legacyFrames{
        {legacyTreeRequest(), 0}, {legacyTreeResponse("IPC"), 1},
        {legacyCreateRequest(), 0}, {legacyCreateResponse(2), 1},
        {legacyWrite(3, Bytes(pipeBind).first(10)), 0},
        {legacyWrite(4, Bytes(pipeBind).subspan(10)), 0},
        {legacyRead(), 0}, {legacyReadResponse(pipeAlter), 1},
        {legacyTransaction(pipeBind), 0}};
    SmbPipeInspection legacyInspection;
    std::vector<nlohmann::json> legacyBinds;
    for (const auto& [frame, direction] : legacyFrames)
    {
        fields.clear();
        legacyInspection.feed(frame, direction, fields);
        if (fields.contains("rpc_bind_events"))
            for (const auto& item : fields["rpc_bind_events"])
                legacyBinds.push_back(item);
    }
    require(legacyBinds.size() == 3 && legacyBinds[0]["authentication_type"] == "NTLM" &&
        legacyBinds[1]["protection_level"] == "Packet privacy" &&
        legacyBinds[2]["transport"] == "SMB named pipe" && legacyInspection.memory() < 20000,
        "SMB1 named-pipe writes, reads, or transactions lost RPC bind evidence");

    // A pipe transaction can return partial data with either NT or DOS overflow status.
    for (const bool dos : {false, true})
    {
        SmbPipeInspection partial;
        for (size_t index = 0; index < 4; ++index)
            partial.feed(legacyFrames[index].first, legacyFrames[index].second, fields);
        partial.feed(legacyTransaction(other), 0, fields);
        fields.clear();
        partial.feed(legacyTransactionResponse(Bytes(pipeAlter).first(10),
            static_cast<uint16_t>(pipeAlter.size()), dos), 1, fields);
        require(!fields.contains("rpc_bind_events"), "A partial SMB1 transaction invented a complete RPC bind");
        partial.feed(legacyRead(), 0, fields);
        partial.feed(legacyReadResponse(Bytes(pipeAlter).subspan(10)), 1, fields);
        require(fields.contains("rpc_bind_events") && fields["rpc_bind_events"].size() == 1 &&
            fields["rpc_bind_events"][0]["protection_level"] == "Packet privacy",
            "An SMB1 pipe overflow discarded the remaining RPC bind bytes");
    }

    // Disk shares, disk FIDs, failed opens, other tree IDs, and closed handles cannot imply a pipe bind.
    for (const auto& [service, resourceType, status] :
        std::vector<std::tuple<std::string, uint16_t, uint32_t>>{
            {"A:", uint16_t{2}, uint32_t{0}}, {"IPC", uint16_t{0}, uint32_t{0}},
            {"IPC", uint16_t{2}, uint32_t{0xc0000022}}})
    {
        SmbPipeInspection rejected;
        for (const auto& [frame, direction] : std::vector<std::pair<Buffer, int>>{
            {legacyTreeRequest(), 0}, {legacyTreeResponse(service), 1},
            {legacyCreateRequest(), 0}, {legacyCreateResponse(resourceType, status), 1},
            {legacyWrite(3, pipeBind), 0}})
        {
            fields.clear();
            rejected.feed(frame, direction, fields);
            require(!fields.contains("rpc_bind_events"), "Non-pipe SMB1 data produced an RPC bind");
        }
    }
    for (const auto& [uid, mid] : std::vector<std::pair<uint16_t, uint16_t>>{
        {uint16_t{4}, uint16_t{1}}, {uint16_t{3}, uint16_t{2}}})
    {
        SmbPipeInspection mismatched;
        mismatched.feed(legacyTreeRequest(), 0, fields);
        auto reply = legacyTreeResponse("IPC");
        write16(reply, 28, uid, false);
        write16(reply, 30, mid, false);
        mismatched.feed(reply, 1, fields);
        mismatched.feed(legacyCreateRequest(), 0, fields);
        mismatched.feed(legacyCreateResponse(2), 1, fields);
        fields.clear();
        mismatched.feed(legacyWrite(3, pipeBind), 0, fields);
        require(!fields.contains("rpc_bind_events"), "An SMB1 IPC reply crossed user or message identity");
    }
    for (const bool successful : {false, true})
    {
        SmbPipeInspection replacing;
        for (size_t index = 0; index < 4; ++index)
            replacing.feed(legacyFrames[index].first, legacyFrames[index].second, fields);
        auto request = legacyTreeRequest();
        write16(request, 24, 7, false);
        write16(request, 30, 12, false);
        write16(request, 37, 1, false);
        replacing.feed(request, 0, fields);
        auto reply = legacyTreeResponse("A:");
        write16(reply, 24, 8, false);
        write16(reply, 30, 12, false);
        if (!successful)
            write32(reply, 5, 0xc0000022, false);
        replacing.feed(reply, 1, fields);
        fields.clear();
        replacing.feed(legacyWrite(13, pipeBind), 0, fields);
        require(fields.contains("rpc_bind_events") == !successful,
            "A flagged SMB1 tree replacement kept a stale pipe or dropped it after failure");
    }
    SmbPipeInspection reusedTree;
    for (size_t index = 0; index < 4; ++index)
        reusedTree.feed(legacyFrames[index].first, legacyFrames[index].second, fields);
    auto newTree = legacyTreeRequest();
    write16(newTree, 30, 12, false);
    reusedTree.feed(newTree, 0, fields);
    auto nonPipe = legacyTreeResponse("UNKNOWN");
    write16(nonPipe, 30, 12, false);
    reusedTree.feed(nonPipe, 1, fields);
    fields.clear();
    reusedTree.feed(legacyWrite(13, pipeBind), 0, fields);
    require(!fields.contains("rpc_bind_events"),
        "A successful non-IPC SMB1 tree reused a TID without retiring its prior pipe handle");
    SmbPipeInspection reusedLegacyFid;
    for (size_t index = 0; index < 4; ++index)
        reusedLegacyFid.feed(legacyFrames[index].first, legacyFrames[index].second, fields);
    reusedLegacyFid.feed(legacyRead(), 0, fields);
    reusedLegacyFid.feed(legacyCreateRequest(), 0, fields);
    reusedLegacyFid.feed(legacyCreateResponse(2), 1, fields);
    fields.clear();
    reusedLegacyFid.feed(legacyReadResponse(pipeAlter), 1, fields);
    require(!fields.contains("rpc_bind_events"), "A stale SMB1 read response attached to a reused FID");

    SmbPipeInspection evictedLegacy;
    evictedLegacy.feed(legacyTreeRequest(), 0, fields);
    evictedLegacy.feed(legacyTreeResponse("IPC"), 1, fields);
    evictedLegacy.feed(legacyCreateRequest(), 0, fields);
    for (uint16_t tid = 8; tid < 40; ++tid)
    {
        auto request = legacyTreeRequest(), reply = legacyTreeResponse("IPC");
        write16(request, 30, static_cast<uint16_t>(tid + 20), false);
        write16(reply, 30, static_cast<uint16_t>(tid + 20), false);
        write16(reply, 24, tid, false);
        evictedLegacy.feed(request, 0, fields);
        evictedLegacy.feed(reply, 1, fields);
    }
    evictedLegacy.feed(legacyCreateResponse(2), 1, fields);
    fields.clear();
    evictedLegacy.feed(legacyWrite(13, pipeBind), 0, fields);
    require(!fields.contains("rpc_bind_events"), "An evicted SMB1 tree admitted a delayed pipe open");
    fields.clear();
    legacyInspection.feed(legacyWrite(8, pipeBind, 0x4002), 0, fields);
    legacyInspection.feed(legacyWrite(9, pipeBind, 0x4001, 8), 0, fields);
    Buffer close(6, 0);
    write16(close, 0, 0x4001, false);
    legacyInspection.feed(legacy(0x04, false, 10, 3, 7, close, {}), 0, fields);
    legacyInspection.feed(legacyWrite(11, pipeBind), 0, fields);
    require(!fields.contains("rpc_bind_events"),
        "An unmatched SMB1 FID, tree, or closed handle produced an RPC bind");

    // Framing and observation merging retain the SMB outer protocol for SMB1 pipe binds.
    Counters legacyHealth;
    std::vector<Observation> legacyObservations;
    Engine legacyEngine(legacyHealth, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            legacyObservations.push_back(std::move(observation));
    });
    TransportPacket legacyClient = client, legacyServer = server;
    legacyClient.sequence = 1000;
    legacyClient.flags = 2;
    legacyClient.payload = {};
    legacyServer.sequence = 9000;
    legacyServer.flags = 0x12;
    legacyServer.payload = {};
    legacyEngine.tcp(legacyClient, 1);
    legacyEngine.tcp(legacyServer, 2);
    legacyClient.sequence = 1001;
    legacyClient.flags = 0x18;
    legacyServer.sequence = 9001;
    legacyServer.flags = 0x18;
    for (size_t index = 0; index < legacyFrames.size(); ++index)
    {
        const auto& [frame, direction] = legacyFrames[index];
        const auto bytes = netbios(frame);
        auto& packet = direction ? legacyServer : legacyClient;
        packet.payload = bytes;
        legacyEngine.tcp(packet, static_cast<int64_t>(index + 3));
        packet.sequence += static_cast<uint32_t>(bytes.size());
    }
    legacyEngine.expire(1000000, true);
    const auto mergedLegacy = std::find_if(legacyObservations.rbegin(), legacyObservations.rend(),
        [](const Observation& item)
    {
        return item.protocol == Observation::Protocol::Smb && item.application &&
            item.application->fields.contains("rpc_binds");
    });
    require(mergedLegacy != legacyObservations.rend() && mergedLegacy->state == "smb_rpc_bind" &&
        mergedLegacy->application->fields["rpc_binds"].size() == 3 &&
        mergedLegacy->application->fields.dump().find("private-token") == std::string::npos &&
        legacyHealth.malformed == 0, "SMB1 named-pipe binds were not preserved through framing and merging");
}
}
