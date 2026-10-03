#include "Capture.h"
#include "Crypto.h"
#include "PacketQueue.h"
#include "Loopback.h"
#include "Processes.h"
#include "Storage.h"
#include "Telemetry.h"
#include <fstream>
#include <sqlite3.h>
#define SECURITY_WIN32
#include <security.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <tuple>

namespace Cipherazzi::Tests
{
using Buffer = std::vector<uint8_t>;
void protocolCoverage();
void vpnCoverage();
void networkCoverage();
void rdmaCoverage();
void roceCoverage();
void retentionCoverage();
void endpointIntegration(const std::filesystem::path& output = {});

void require(bool result, const char* message)
{
    if (!result)
        throw std::runtime_error(message);
}

void word(Buffer& bytes, uint16_t value)
{
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value));
}

void append(Buffer& bytes, Bytes value) { bytes.insert(bytes.end(), value.begin(), value.end()); }

void vector16(Buffer& bytes, Bytes value)
{
    word(bytes, static_cast<uint16_t>(value.size()));
    append(bytes, value);
}

void extension(Buffer& bytes, uint16_t type, Bytes value)
{
    word(bytes, type);
    vector16(bytes, value);
}

Buffer hello(bool client, uint16_t version = 0x0304, bool retry = false, bool ech = false,
    Bytes additionalExtensions = {})
{
    Buffer body;
    word(body, std::min<uint16_t>(version, 0x0303));
    body.resize(34, 0x42);
    if (retry)
    {
        const Buffer random{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
            0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c};
        std::copy(random.begin(), random.end(), body.begin() + 2);
    }
    body.push_back(0);
    if (client)
        append(body, Buffer{0, 4, 0x13, 1, 0xc0, 0x2f, 1, 0});
    else
    {
        word(body, version == 0x0304 ? 0x1301 : 0xc02f);
        body.push_back(0);
    }
    Buffer extensions;
    if (version == 0x0304)
        extension(extensions, 43, client ? Buffer{4, 3, 4, 3, 3} : Buffer{3, 4});
    if (client)
    {
        const std::string hostname = "service.example.test";
        Buffer names{0};
        vector16(names, Bytes(reinterpret_cast<const uint8_t*>(hostname.data()), hostname.size()));
        Buffer sni;
        vector16(sni, names);
        extension(extensions, 0, sni);
        extension(extensions, 16, Buffer{0, 3, 2, 'h', '2'});
        if (ech)
            extension(extensions, 0xfe0d, Buffer{0, 0, 0, 0});
    }
    else if (version == 0x0303)
        extension(extensions, 16, Buffer{0, 3, 2, 'h', '2'});
    append(extensions, additionalExtensions);
    vector16(body, extensions);
    Buffer message{static_cast<uint8_t>(client ? 1 : 2), 0};
    word(message, static_cast<uint16_t>(body.size()));
    append(message, body);
    return message;
}

Buffer record(Bytes payload, uint8_t type = 22)
{
    Buffer result{type, 3, 3};
    word(result, static_cast<uint16_t>(payload.size()));
    append(result, payload);
    return result;
}

Endpoint endpoint(uint8_t last, uint16_t port)
{
    Endpoint result;
    result.address[0] = 10;
    result.address[3] = last;
    result.port = port;
    return result;
}

TcpPacket packet(Bytes bytes, uint32_t sequence, bool client = true, uint8_t flags = 0x18)
{
    const auto source = endpoint(1, 50000);
    const auto destination = endpoint(2, 443);
    return {client ? source : destination, client ? destination : source, sequence, flags, bytes};
}

void fragmentationAndRetransmission()
{
    // Exercise randomized packet ordering, duplicate segments, and TCP sequence wrap through the engine.
    for (uint32_t seed = 0; seed < 200; ++seed)
    {
        Counters counters;
        std::vector<Observation> output;
        Engine engine(counters, [&](Observation row) { output.push_back(std::move(row)); });
        auto message = hello(true, 0x0304, false, true);
        Buffer client = record(Bytes(message).first(17));
        append(client, record(Bytes(message).subspan(17)));
        const auto server = record(hello(false));
        const uint32_t start = seed % 2 ? 0xfffffff0U : 1000;
        engine.tcp(packet({}, start - 1, true, 2), 1000000);
        engine.tcp(packet({}, 2999, false, 0x12), 1000001);
        std::mt19937 random(seed);
        std::vector<std::pair<size_t, size_t>> segments;
        for (size_t at = 0; at < client.size();)
        {
            const auto size = std::min<size_t>(1 + random() % 19, client.size() - at);
            segments.emplace_back(at, size);
            at += size;
        }
        std::shuffle(segments.begin(), segments.end(), random);
        for (const auto& [at, size] : segments)
        {
            const auto part = packet(Bytes(client).subspan(at, size), start + static_cast<uint32_t>(at));
            engine.tcp(part, 1000010);
            engine.tcp(part, 1000011);
        }
        for (size_t i = 0; i < server.size(); ++i)
            engine.tcp(packet(Bytes(server).subspan(i, 1), 3000 + static_cast<uint32_t>(i), false), 1000020);
        require(!output.empty(), "Fragmented hello was missed");
        const auto& last = output.back();
        require(last.version == 0x0304 && last.cipher == 0x1301 && last.clientHello && last.serverHello,
            "Incorrect TLS 1.3 selection");
        require(last.sni == "service.example.test" && last.echOffered && last.offeredAlpn == "h2",
            "Client extensions were lost");
        require(last.selectedAlpn.empty(), "TLS 1.3 ALPN was incorrectly inferred");
        const auto count = output.size();
        engine.tcp(packet(client, start), 1000030);
        engine.tcp(packet(server, 3000, false), 1000031);
        require(output.size() == count, "Retransmission duplicated a completed flow");
        engine.expire(1000040, true);
        require(counters.bufferedBytes == 0 && counters.activeFlows == 0, "Flow memory was retained");
    }
}

void retryAndIncomplete()
{
    Counters counters;
    std::vector<Observation> output;
    Engine engine(counters, [&](Observation row) { output.push_back(std::move(row)); });
    const auto client = record(hello(true));
    const auto retry = record(hello(false, 0x0304, true));
    engine.tcp(packet(client, 100), 1000000);
    engine.tcp(packet(retry, 200, false), 1000010);
    require(output.back().retrySeen && !output.back().serverHello && output.back().version == 0,
        "HelloRetryRequest was treated as a server selection");
    const auto ccs = record(Buffer{1}, 20);
    engine.tcp(packet(ccs, 200 + static_cast<uint32_t>(retry.size()), false), 1000020);
    const auto server = record(hello(false));
    engine.tcp(packet(server, 200 + static_cast<uint32_t>(retry.size() + ccs.size()), false), 1000030);
    require(output.back().serverHello && output.back().retrySeen, "ServerHello after retry was missed");

    // Reuse of the same endpoint tuple starts a new observation instead of inheriting a cipher.
    engine.tcp(packet({}, 9000, true, 2), 2000000);
    engine.tcp(packet(client, 9001), 2000010);
    engine.expire(2000020, true);
    const auto& incomplete = output[output.size() - 2];
    require(incomplete.flowId == 2 && !incomplete.serverHello && incomplete.version == 0,
        "A client-only connection inherited server fields");
    require(!incomplete.detail.empty() && output.back().lifecycleOnly && !output.back().closeReason.empty(),
        "Incomplete observation did not explain missing data");
}

Buffer pqHello(bool client, std::span<const uint16_t> groups,
    std::span<const NegotiationStage::KeyShare> shares, bool retry = false, Bytes additionalExtensions = {})
{
    Buffer extensions, values, entries;
    if (client)
    {
        for (const auto id : groups)
            word(values, id);
        vector16(entries, values);
        extension(extensions, 10, entries);
        extension(extensions, 13, Buffer{0, 4, 8, 4, 4, 3});
        extension(extensions, 50, Buffer{0, 2, 8, 4});
    }
    entries.clear();
    for (const auto& share : shares)
    {
        word(entries, share.group);
        if (!retry)
            vector16(entries, Buffer(share.bytes, 0x5a));
    }
    values.clear();
    if (client)
        vector16(values, entries);
    else
        values = entries;
    extension(extensions, 51, values);
    append(extensions, additionalExtensions);
    return hello(client, 0x0304, retry, false, extensions);
}

void pqNegotiationEvidence()
{
    // Replay retry negotiation with realistically sized shares across TLS records and TCP segments.
    Counters counters;
    std::vector<Observation> output;
    Engine engine(counters, [&](Observation row) { output.push_back(std::move(row)); });
    CryptoCatalog catalog;
    const auto summarize = [&](const Observation& row)
    {
        return nlohmann::json::parse(catalog.summarize(row, [](const auto&, const auto&, Bytes) {}).json);
    };
    const std::array<uint16_t, 4> firstGroups{0x0a0a, 0x11ec, 0x001d, 0xbeef};
    const std::array<NegotiationStage::KeyShare, 1> firstShares{{{0x001d, 32}}};
    const auto first = record(pqHello(true, firstGroups, firstShares));
    const std::array<NegotiationStage::KeyShare, 1> requested{{{0x11ec, 0}}};
    const auto retry = record(pqHello(false, {}, requested, true));
    engine.tcp(packet(first, 100), 1000000);
    engine.tcp(packet(retry, 9000, false), 1000010);
    auto data = summarize(output.back());
    require(data["selected_group_id"].is_null() && data["group_class"] == "Not observed" &&
        data["negotiation_stages"][1]["selected_group_id"] == 0x11ec &&
        data["negotiation_stages"][1]["key_shares"].empty(), "Retry request was promoted to a selected PQ group");
    const std::array<uint16_t, 3> secondGroups{0x11ec, 0x001d, 0xbeef};
    const std::array<NegotiationStage::KeyShare, 1> secondShares{{{0x11ec, 1216}}};
    const auto message = pqHello(true, secondGroups, secondShares);
    auto second = record(Bytes(message).first(800));
    append(second, record(Bytes(message).subspan(800)));
    const auto next = 100 + static_cast<uint32_t>(first.size());
    engine.tcp(packet(Bytes(second).first(13), next), 1000020);
    engine.tcp(packet(Bytes(second).subspan(400), next + 400), 1000021);
    engine.tcp(packet(Bytes(second).subspan(13, 387), next + 13), 1000022);
    engine.tcp(packet(second, next), 1000023);
    const std::array<NegotiationStage::KeyShare, 1> selected{{{0x11ec, 1120}}};
    const auto server = record(pqHello(false, {}, selected));
    engine.tcp(packet(server, 9000 + static_cast<uint32_t>(retry.size()), false), 1000030);
    data = summarize(output.back());
    const auto& stages = data["negotiation_stages"];
    require(stages.size() == 4 && stages[0]["group_ids"] == firstGroups &&
        stages[2]["group_ids"] == secondGroups && stages[0]["key_shares"][0]["bytes"] == 32 &&
        stages[2]["key_shares"][0]["bytes"] == 1216 && stages[3]["key_shares"][0]["bytes"] == 1120,
        "Negotiation stages lost ordered offers, share lengths, or duplicated retransmissions");
    require(stages[0]["type"] == "ClientHello" && stages[1]["type"] == "HelloRetryRequest" &&
        stages[2]["type"] == "ClientHello" && stages[3]["type"] == "ServerHello" &&
        stages[2]["handshake_bytes"] == message.size() && stages[2]["timestamp_us"] == 1000022 &&
        stages[2]["signature_ids"] == std::array<uint16_t, 2>{0x0804, 0x0403} &&
        stages[2]["certificate_signature_ids"] == std::array<uint16_t, 1>{0x0804},
        "Negotiation stages lost message identity or signature evidence");
    require(data["group_class"] == "Hybrid post-quantum" && data["group_standardization"] == "Standardized" &&
        data["group_components"] == std::array<std::string, 2>{"ML-KEM-768", "X25519"} &&
        data["classification_rule_version"] == 1 && data["negotiation_history_truncated"] == false &&
        data["handshake_confirmation"] == "Not confirmed by endpoint",
        "Selected PQ group classification claims or loses unsupported evidence");

    // Exercise named hybrids, draft and obsolete exchanges, and identifiers that must remain unknown.
    struct Selection
    {
        uint16_t id, clientBytes, serverBytes;
        const char* classification;
        const char* standardization;
    };
    for (const auto& selection : {
        Selection{0x11ea, 832, 800, "Hybrid post-quantum", "Draft"},
        Selection{0x0201, 1184, 1088, "Post-quantum", "Draft"},
        Selection{0x6399, 1216, 1120, "Hybrid post-quantum", "Obsolete"},
        Selection{0x001d, 32, 32, "Classical", "Assigned"},
        Selection{0xbeef, 57, 83, "Unknown", "Unknown"},
        Selection{0xfe12, 57, 83, "Unknown", "Private use"},
        Selection{0x1a1a, 57, 83, "Unknown", "GREASE"}})
    {
        std::vector<Observation> captured;
        Engine candidate(counters, [&](Observation row) { captured.push_back(std::move(row)); });
        const std::array<uint16_t, 1> groups{selection.id};
        const std::array<NegotiationStage::KeyShare, 1> clientShare{{{selection.id, selection.clientBytes}}};
        const std::array<NegotiationStage::KeyShare, 1> serverShare{{{selection.id, selection.serverBytes}}};
        const auto clientRecord = record(pqHello(true, groups, clientShare));
        const auto serverRecord = record(pqHello(false, {}, serverShare));
        candidate.tcp(packet(clientRecord, 100), 2000000);
        candidate.tcp(packet(serverRecord, 9000, false), 2000010);
        const auto evidence = summarize(captured.back());
        require(evidence["group_class"] == selection.classification &&
            evidence["group_standardization"] == selection.standardization &&
            evidence["negotiation_stages"][1]["key_shares"][0]["bytes"] == selection.serverBytes,
            "Wire group identifier was misclassified or its observed length was replaced");
    }

    // Excess complete hellos preserve the retained prefix and report every dropped stage.
    std::vector<Observation> limited;
    Engine bounded(counters, [&](Observation row) { limited.push_back(std::move(row)); });
    uint32_t sequence = 100;
    size_t memoryAtLimit = 0;
    for (int index = 0; index < 12; ++index)
    {
        bounded.tcp(packet(first, sequence), 3000000 + index);
        sequence += static_cast<uint32_t>(first.size());
        if (index == 7)
            memoryAtLimit = limited.back().memory();
        require(index < 8 || limited.back().memory() == memoryAtLimit,
            "Retained negotiation history grew beyond its bound");
    }
    data = summarize(limited.back());
    require(data["negotiation_stages"].size() == 8 && data["negotiation_stages_dropped"] == 4 &&
        data["negotiation_history_truncated"] == true, "Dropped negotiation evidence was not explicit");
    Observation withoutStages = limited.back();
    std::vector<NegotiationStage>().swap(withoutStages.crypto.stages);
    require(limited.back().memory() > withoutStages.memory() + 8 * sizeof(NegotiationStage),
        "Negotiation stage allocations escaped observation memory accounting");

    // Incomplete key shares cannot fabricate a retained complete stage or a server selection.
    Counters partialCounters;
    std::vector<Observation> partial;
    Engine truncated(partialCounters, [&](Observation row) { partial.push_back(std::move(row)); });
    truncated.tcp(packet(first, 100), 4000000);
    truncated.tcp(packet(Bytes(server).first(server.size() - 1), 9000, false), 4000010);
    truncated.expire(4000020, true);
    const auto incomplete = summarize(partial[partial.size() - 2]);
    require(incomplete["negotiation_stages"].size() == 1 && incomplete["selected_group_id"].is_null() &&
        incomplete["group_class"] == "Not observed" && partialCounters.bufferedBytes == 0,
        "Truncated server share was accepted as a complete PQ negotiation");
}

void startTlsAndLegacy()
{
    for (const uint16_t version : std::array<uint16_t, 4>{0x0300, 0x0301, 0x0302, 0x0303})
    {
        Counters counters;
        std::vector<Observation> output;
        Engine engine(counters, [&](Observation row) { output.push_back(std::move(row)); });
        const std::string prefix = "EHLO host\r\nSTARTTLS\r\n";
        Buffer bytes(prefix.begin(), prefix.end());
        append(bytes, record(hello(true, version)));
        auto incoming = packet(bytes, 100);
        incoming.destination.port = 2525;
        engine.tcp(incoming, 1000000);
        const auto server = record(hello(false, version));
        auto outgoing = packet(server, 200, false);
        outgoing.source.port = 2525;
        engine.tcp(outgoing, 1000010);
        require(output.back().version == version && output.back().destination.port == 2525,
            "STARTTLS on a nonstandard port was missed");
        require(output.back().crypto.stages[0].versions.empty() &&
            output.back().crypto.stages[0].legacyVersion == version,
            "Legacy maximum version was represented as an explicit supported_versions offer");
        if (version == 0x0303)
            require(output.back().selectedAlpn == "h2", "TLS 1.2 selected ALPN was missed");
    }

    // The plaintext scan passes over other bytes in bulk without missing a hello behind record-type decoys,
    // across a chunk boundary, or at its bound.
    const auto client = record(hello(true, 0x0303));
    auto scan = [&](const Buffer& bytes, size_t chunk, bool expected = false)
    {
        TlsStream stream;
        if (expected)
            stream.expectTls();
        int hellos = 0;
        bool valid = true;
        for (size_t offset = 0; valid && offset < bytes.size(); offset += chunk)
            valid = stream.feed(Bytes(bytes).subspan(offset, std::min(chunk, bytes.size() - offset)),
                [&](const Hello& found) { hellos += found.type == 1; });
        return std::tuple{valid, hellos, stream.unmatched(), stream.limited()};
    };
    Buffer decoys;
    for (int index = 0; index < 5000; ++index)
        decoys.push_back(static_cast<uint8_t>(index * 31));
    append(decoys, Buffer{22, 3, 9, 0, 5, 22, 3, 1, 0, 0, 21, 3, 3, 0, 2, 22, 22, 3});
    append(decoys, client);
    for (const size_t chunk : {size_t{1}, size_t{7}, size_t{4096}, decoys.size()})
    {
        require(scan(decoys, chunk) == std::tuple{true, 1, false, false},
            "A hello behind record-type decoys or across a chunk boundary was missed");
        require(scan(decoys, chunk, true) == std::tuple{false, 0, false, false},
            "An alert record type was not examined on a stream known to carry TLS");
    }
    Buffer plaintext(1024 * 1024, 'x');
    append(plaintext, client);
    require(scan(plaintext, 65536) == std::tuple{true, 1, false, false}, "A hello at the scan bound was missed");
    plaintext.insert(plaintext.begin(), 'x');
    require(scan(plaintext, 65536) == std::tuple{false, 0, true, true},
        "A stream without a handshake in its scanned prefix was not reported as unmatched");

    // Such a stream ends inspection without counting an inspection limit; after a hello the evidence is
    // incomplete, so the same stream is counted.
    for (const bool afterHello : {false, true})
    {
        Counters counters;
        Engine engine(counters, [](Observation) {});
        if (afterHello)
            engine.tcp(packet(client, 100), 1);
        const Buffer chunk(60000, 'x');
        for (uint32_t index = 0; index < 18; ++index)
            engine.tcp(packet(chunk, 5000 + index * 60000, false), 10 + index);
        require(counters.malformed == 0 && counters.reassemblyLimit == (afterHello ? 1u : 0u) &&
            counters.activeFlows == 1 && counters.bufferedBytes == 0,
            "A stream without a handshake was counted as an inspection limit, or lost evidence was not");
    }
}

Buffer ipPacket(Bytes payload, bool ipv6, bool extensionHeader = false)
{
    Buffer result(ipv6 ? (extensionHeader ? 48 : 40) : 20);
    const auto tcpOffset = result.size();
    if (ipv6)
    {
        result[0] = 0x60;
        const auto length = static_cast<uint16_t>(20 + payload.size() + (extensionHeader ? 8 : 0));
        result[4] = static_cast<uint8_t>(length >> 8);
        result[5] = static_cast<uint8_t>(length);
        result[6] = extensionHeader ? 0 : 6;
        result[23] = 1;
        result[39] = 2;
        if (extensionHeader)
            result[40] = 6;
    }
    else
    {
        result[0] = 0x45;
        const auto length = static_cast<uint16_t>(40 + payload.size());
        result[2] = static_cast<uint8_t>(length >> 8);
        result[3] = static_cast<uint8_t>(length);
        result[9] = 6;
        result[15] = 1;
        result[19] = 2;
    }
    result.resize(tcpOffset + 20);
    result[tcpOffset] = 0xc3;
    result[tcpOffset + 1] = 0x50;
    result[tcpOffset + 2] = 1;
    result[tcpOffset + 3] = 0xbb;
    result[tcpOffset + 12] = 0x50;
    result[tcpOffset + 13] = 0x18;
    append(result, payload);
    return result;
}

void packetMonitorOffload()
{
    // Reproduce an outgoing resumed hybrid ClientHello larger than the NIC segment size.
    Buffer identities, binders{32}, psk, extensions;
    vector16(identities, Buffer(256, 0x5a));
    append(identities, Buffer(4));
    vector16(psk, identities);
    append(binders, Buffer(32, 0x5a));
    vector16(psk, binders);
    extension(extensions, 41, psk);
    const std::array<uint16_t, 1> groups{0x11ec};
    const std::array<NegotiationStage::KeyShare, 1> offered{{{0x11ec, 1216}}};
    const std::array<NegotiationStage::KeyShare, 1> selected{{{0x11ec, 1120}}};
    const auto client = record(pqHello(true, groups, offered, false, extensions));
    const auto server = record(pqHello(false, {}, selected));
    auto ip = ipPacket(client, false);
    ip[12] = ip[16] = 10;
    ip[2] = ip[3] = 0;
    require(ip.size() > 1500, "Offload replay did not exceed the NIC segment size");
    Buffer frame(12, 0);
    append(frame, Buffer{8, 0});
    append(frame, ip);
    Counters strictCounters;
    require(!decodePacket(frame, PacketKind::Ethernet, strictCounters),
        "A wire packet with zero IPv4 total length was accepted without Packet Monitor context");

    // The live decoder consumes the captured LSO bytes while normal TCP retransmissions remain deduplicated.
    Counters liveCounters;
    std::vector<Observation> output;
    Engine live(liveCounters, [&](Observation row) { output.push_back(std::move(row)); });
    live.packet(frame, PacketKind::Ethernet, 1000000, PacketOrigin::PacketMonitor);
    require(!output.empty() && output.back().clientHello && output.back().crypto.pskOffers == 1,
        "Packet Monitor lost an offloaded resumed ClientHello");
    const auto observed = output.size();
    live.tcp(packet(Bytes(client).first(1460), 0), 1000010);
    live.tcp(packet(Bytes(client).subspan(1460), 1460), 1000020);
    require(output.size() == observed, "Segmented retransmission duplicated the offloaded ClientHello");
    live.tcp(packet(server, 9000, false), 1000030);
    require(output.back().clientHello && output.back().serverHello && output.back().crypto.stages.size() == 2 &&
        output.back().crypto.stages[0].keyShares[0].bytes == 1216 && liveCounters.malformed == 0,
        "An offloaded ClientHello and ServerHello did not form one observation");

    // Complete hellos in capped offload prefixes remain usable without claiming a complete packet.
    append(frame, record(Buffer(16384), 23));
    frame.resize(PacketMonitorCaptureLimit);
    const auto capped = decodePacket(frame, PacketKind::Ethernet, liveCounters, PacketOrigin::PacketMonitor);
    require(capped && capped->truncated && liveCounters.truncated == 1,
        "Capture-capped LSO prefix did not retain its truncation status");
    std::vector<Observation> cappedOutput;
    Engine cappedEngine(liveCounters, [&](Observation row) { cappedOutput.push_back(std::move(row)); });
    cappedEngine.packet(frame, PacketKind::Ethernet, 2000000, PacketOrigin::PacketMonitor);
    require(!cappedOutput.empty() && cappedOutput.back().clientHello,
        "A complete hello in a capped offload prefix was lost");

    // Missing offload bytes must be retransmitted before an incomplete hello can become evidence.
    Buffer padding;
    extension(padding, 21, Buffer(16000));
    const auto largeClient = record(hello(true, 0x0304, false, false, padding));
    auto largeIp = ipPacket(largeClient, false);
    largeIp[12] = largeIp[16] = 10;
    largeIp[2] = largeIp[3] = 0;
    largeIp.resize(PacketMonitorCaptureLimit);
    std::vector<Observation> partialOutput;
    Engine partialEngine(liveCounters, [&](Observation row) { partialOutput.push_back(std::move(row)); });
    partialEngine.packet(largeIp, PacketKind::Ip, 3000000, PacketOrigin::PacketMonitor);
    partialEngine.tcp(packet(Bytes(largeClient).subspan(12000), 12000), 3000010);
    require(partialOutput.empty(), "Missing offload bytes were bridged into a fabricated hello");
    constexpr size_t prefix = PacketMonitorCaptureLimit - 40;
    partialEngine.tcp(packet(Bytes(largeClient).subspan(prefix, 12000 - prefix), prefix), 3000020);
    require(!partialOutput.empty() && partialOutput.back().clientHello,
        "Retransmission did not recover a capture-capped hello");

    // Offload context does not relax validation of malformed IP or TCP headers.
    ip[33] |= 2;
    require(!decodePacket(ip, PacketKind::Ip, liveCounters, PacketOrigin::PacketMonitor),
        "Invalid LSO SYN was accepted");
    ip[33] &= static_cast<uint8_t>(~2);
    ip[6] = 0x20;
    require(!decodePacket(ip, PacketKind::Ip, liveCounters, PacketOrigin::PacketMonitor),
        "Fragmented offload buffer bypassed fragment validation");
    ip[6] = 0;
    ip.resize(39);
    require(!decodePacket(ip, PacketKind::Ip, liveCounters, PacketOrigin::PacketMonitor),
        "Incomplete offload TCP header was accepted");
}

void packetBoundariesAndLimits()
{
    Counters counters;
    const auto tls = record(hello(true));
    auto ipv6 = ipPacket(tls, true, true);
    auto decoded = decodePacket(ipv6, PacketKind::Ip, counters);
    require(decoded && decoded->source.family == 6 && decoded->payload.size() == tls.size(),
        "IPv6 extension header broke decoding");
    auto ip = ipPacket(tls, false);
    Buffer ethernet(12, 0);
    append(ethernet, Buffer{0x88, 0xa8, 0, 1, 0x81, 0, 0, 2, 8, 0});
    append(ethernet, ip);
    require(decodePacket(ethernet, PacketKind::Ethernet, counters).has_value(), "Stacked VLAN tags failed");
    ip[6] = 0x20;
    require(!decodePacket(ip, PacketKind::Ip, counters) && counters.fragments == 1,
        "Fragmented IP payload was interpreted as complete TCP");
    for (size_t size = 0; size < 60; ++size)
        decodePacket(Bytes(ipv6).first(size), PacketKind::Ip, counters);

    std::vector<Observation> output;
    Engine engine(counters, [&](Observation row) { output.push_back(std::move(row)); }, {1, 1024, 1000000});
    engine.tcp(packet({}, 100, true, 2), 1);
    auto other = packet({}, 500, true, 2);
    other.source.port = 50001;
    engine.tcp(other, 2);
    require(counters.flowLimit == 1 && counters.activeFlows == 1, "Flow admission was not bounded");
    Buffer gap(2000, 0);
    engine.tcp(packet(gap, 200), 3);
    require(counters.reassemblyLimit == 1 && counters.bufferedBytes == 0, "Memory budget was not enforced");
    engine.expire(2000000);
    require(counters.activeFlows == 0, "Idle flows did not expire");
}

void malformedAndFuzz()
{
    // Reject incomplete extension vectors without emitting partially parsed identity data.
    auto message = hello(true);
    message[message.size() - 4] = 255;
    TlsStream malformed;
    size_t emitted = 0;
    require(!malformed.feed(record(message), [&](const Hello&) { ++emitted; }) && emitted == 0,
        "Malformed extension produced a hello");
    std::mt19937 random(314159);
    Counters counters;
    for (int iteration = 0; iteration < 20000; ++iteration)
    {
        Buffer bytes(random() % 2048);
        for (auto& byte : bytes)
            byte = static_cast<uint8_t>(random());
        if (iteration % 2 && bytes.size() > 10)
        {
            bytes[0] = 22;
            bytes[1] = 3;
            bytes[2] = 3;
            const auto length = bytes.size() - 5;
            bytes[3] = static_cast<uint8_t>(length >> 8);
            bytes[4] = static_cast<uint8_t>(length);
            bytes[5] = iteration % 3 ? 1 : 2;
        }
        TlsStream parser;
        parser.feed(bytes, [](const Hello&) {});
        decodePacket(bytes, iteration % 2 ? PacketKind::Ethernet : PacketKind::Ip, counters);
    }
}

int scalar(sqlite3* database, const char* sql)
{
    sqlite3_stmt* statement = nullptr;
    require(sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) == SQLITE_OK, "Test query failed to prepare");
    require(sqlite3_step(statement) == SQLITE_ROW, "Test query failed");
    const auto result = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    return result;
}

Buffer fromHex(const std::string& text)
{
    Buffer bytes;
    for (size_t offset = 0; offset < text.size(); offset += 2)
        bytes.push_back(static_cast<uint8_t>(std::stoul(text.substr(offset, 2), nullptr, 16)));
    return bytes;
}

void inspectCapture(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    std::array<uint32_t, 6> header{};
    input.read(reinterpret_cast<char*>(header.data()), sizeof(header));
    require(input && header[0] == 0xa1b2c3d4 && header[5] == 1, "Expected little-endian Ethernet PCAP");
    Counters counters;
    Engine engine(counters, [](Observation) {}, {.raw = true});
    size_t index = 0;
    std::array<uint32_t, 4> record{};
    while (input.read(reinterpret_cast<char*>(record.data()), sizeof(record)))
    {
        require(record[2] <= 65535, "Capture packet exceeds the diagnostic bound");
        Buffer bytes(record[2]);
        input.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
        require(static_cast<bool>(input), "Truncated diagnostic capture");
        const auto malformed = counters.malformed.load();
        const auto limited = counters.reassemblyLimit.load();
        engine.packet(bytes, PacketKind::Ethernet, static_cast<int64_t>(record[0]) * 1000000 + record[1],
            PacketOrigin::PacketMonitor);
        if (counters.malformed != malformed || counters.reassemblyLimit != limited)
        {
            std::cout << (counters.malformed != malformed ? "Malformed packet " : "Limited packet ") <<
                index << "; length " << bytes.size() << "; header ";
            for (const auto byte : Bytes(bytes).first(std::min<size_t>(bytes.size(), 54)))
                printf("%02x", byte);
            std::cout << '\n';
        }
        ++index;
    }
    engine.expire(nowUs(), true);
    std::cout << "Packets " << counters.packets << "; malformed " << counters.malformed <<
        "; limits " << counters.reassemblyLimit << "; retained bytes " << counters.bufferedBytes << '\n';
}

void quicCoverage()
{
    std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "quic.json");
    const auto fixtures = nlohmann::json::parse(input);
    for (const auto& fixture : fixtures)
    {
        for (const bool tamper : {false, true})
        {
            Counters counters;
            std::vector<Observation> observations;
            Engine engine(counters, [&](Observation observation)
            {
                if (!observation.lifecycleOnly)
                    observations.push_back(std::move(observation));
            });
            int64_t timestamp = 1700000000000000;
            if (tamper)
            {
                auto packet = fromHex(fixture["packets"][0]);
                const auto decoded = decodePacket(packet, PacketKind::Ip, counters);
                require(decoded && decoded->protocol == 17, "QUIC UDP datagram did not decode");
                const auto header = quicHeader(decoded->payload);
                require(header.has_value(), "QUIC Initial header did not decode");
                const auto offset = decoded->payload.data() - packet.data();
                packet[offset + header->packet.size() - 1] ^= 1;
                engine.packet(packet, PacketKind::Ip, timestamp++);
                require(observations.empty(), "Unauthenticated QUIC payload created a hello observation");
            }
            for (const auto& encoded : fixture["packets"])
            {
                const auto bytes = fromHex(encoded);
                engine.packet(bytes, PacketKind::Ip, timestamp += 1000);
                const auto decoded = decodePacket(bytes, PacketKind::Ip, counters);
                const auto header = decoded ? quicHeader(decoded->payload) : std::nullopt;
                if (header && header->retry())
                    engine.packet(bytes, PacketKind::Ip, timestamp += 1000);
            }
            engine.expire(timestamp, true);
            require(!observations.empty(), "QUIC transcript produced no hello observation");
            const auto& final = observations.back();
            require(final.quic && final.clientHello && final.serverHello && final.version == 772 &&
                final.sni == "quic.lab" && final.offeredAlpn == "h3" && final.selectedAlpn.empty(),
                "QUIC hello metadata or role attribution was incorrect");
            require(final.quicVersion == fixture["version"] && final.quicRetry == fixture["retry"],
                "QUIC version or validated Retry was lost");
            require(final.crypto.stages.size() == (final.quicRetry ? 3 : 2),
                "QUIC retransmission or reordered CRYPTO created duplicate stages");
            require(counters.malformed == (tamper ? 1 : 0) && counters.reassemblyLimit == 0 &&
                counters.flowLimit == 0 && counters.activeFlows == 0 && counters.bufferedBytes == 0,
                "QUIC counters or retained allocations were incorrect");
        }
    }

    // Expiring an incomplete Initial must return its entire budget and permit another connection.
    for (const auto& fixture : fixtures)
    {
        for (const bool idle : {false, true})
        {
            Counters partialCounters;
            Engine partialEngine(partialCounters, [](Observation) {}, {4, 65536, 1000000});
            int64_t timestamp = 1700000000000000;
            for (int iteration = 0; iteration < 4; ++iteration)
            {
                partialEngine.packet(fromHex(fixture["packets"][0]), PacketKind::Ip, timestamp);
                require(partialCounters.activeFlows == 1 && partialCounters.bufferedBytes > 0,
                    "An expired QUIC connection prevented readmission");
                timestamp += 2000000;
                partialEngine.expire(timestamp, !idle);
                require(partialCounters.activeFlows == 0 && partialCounters.bufferedBytes == 0 &&
                    partialCounters.reassemblyLimit == 0, "Incomplete QUIC expiry corrupted the memory budget");
            }
        }
    }

    // TCP and QUIC compete for one resource budget while keeping their transport identities separate.
    Counters counters;
    Engine engine(counters, [](Observation) {}, {1, 1024 * 1024, 120000000});
    engine.packet(fromHex(fixtures[0]["packets"][0]), PacketKind::Ip, 1700000000000000);
    engine.tcp(packet(hello(true), 100, true, 2), 1700000000001000);
    require(counters.flowLimit == 1, "QUIC bypassed the shared flow limit");
    engine.expire(1700000000002000, true);
}

void endpointConfirmation()
{
    const auto path = std::filesystem::temp_directory_path() /
        ("cipherazzi-endpoint-match-" + std::to_string(GetCurrentProcessId()) + ".db");
    std::filesystem::remove(path);
    Counters counters;
    std::atomic<bool> identityReady{};
    {
        Storage storage(path, counters, "test", "delayed test identity", [&](Observation& observation)
        {
            if (identityReady && observation.flowId <= 2)
            {
                observation.sourceOwner.pid = 4242;
                observation.sourceOwner.startedUs = 1699999000000000;
                observation.sourceOwner.evidence = "Test socket identity";
            }
        });
        require(Telemetry::importEndpoint(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) /
            "endpoint-pq.json", storage) == 1, "Public endpoint report did not import");
        Observation observation;
        observation.flowId = 1;
        observation.firstUs = 1700000000000000;
        observation.lastUs = 1700000000050000;
        observation.source = {{10,20,0,1},52000,4};
        observation.destination = {{10,20,0,2},443,4};
        observation.clientHello = observation.serverHello = true;
        observation.version = 772;
        observation.cipher = 4866;
        observation.crypto.groupId = 4588;
        storage.enqueue(observation, true);
        sqlite3* reader = nullptr;
        require(sqlite3_open_v2(utf8(path.wstring()).c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Endpoint test reader could not open");
        auto await = [&](const char* query)
        {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
            while (!scalar(reader, query) && std::chrono::steady_clock::now() < deadline)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            require(scalar(reader, query) != 0, "Endpoint evidence did not stream to the reader");
        };
        await("SELECT count(*) FROM connections");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE json_extract(crypto_json,"
            "'$.handshake_confirmation')='Not confirmed by endpoint'") == 1,
            "Unattributed endpoint report was assigned to a packet connection");
        identityReady = true;
        await("SELECT count(*) FROM connections WHERE json_extract(crypto_json,"
            "'$.handshake_confirmation')='Endpoint confirmed completion'");
        require(scalar(reader, "SELECT count(*) FROM certificates WHERE json_extract(metadata_json,"
            "'$.public_key_class')='Post-quantum'") == 2, "PQ public certificates were not cataloged by algorithm");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE json_extract(crypto_json,"
            "'$.endpoint_confirmations[0].handshake_signature_id')=2308") == 1,
            "Endpoint authentication signature was not retained");
        storage.enqueue(observation, true);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        require(scalar(reader, "SELECT count(*) FROM connections WHERE json_extract(crypto_json,"
            "'$.handshake_confirmation')='Endpoint confirmed completion'") == 1,
            "Late packet update removed independent endpoint evidence");

        // Reject reused PIDs, different negotiations, transports, and unrelated socket lifetimes.
        for (int id = 3; id <= 9; ++id)
        {
            auto candidate = observation;
            candidate.flowId = id;
            candidate.sourceOwner.pid = 4242;
            candidate.sourceOwner.startedUs = 1699999000000000;
            if (id == 3) candidate.sourceOwner.pid = 4243;
            else if (id == 4) candidate.sourceOwner.startedUs += 2000;
            else if (id == 5) candidate.version = 771;
            else if (id == 6) candidate.cipher = 4865;
            else if (id == 7) candidate.quic = true;
            else if (id == 8) candidate.crypto.groupId = 4589;
            else { candidate.firstUs += 1000000; candidate.lastUs += 1000000; }
            storage.enqueue(std::move(candidate), true);
        }
        await("SELECT count(*)=8 FROM connections");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE json_extract(crypto_json,"
            "'$.handshake_confirmation')='Endpoint confirmed completion'") == 1,
            "Endpoint evidence matched a different process, negotiation, or lifetime");

        // Late ambiguity retracts a match and certificate references without changing visible packet evidence.
        observation.flowId = 2;
        storage.enqueue(observation, true);
        await("SELECT count(*) FROM endpoint_events WHERE json_extract(detail_json,'$.correlation') "
            "LIKE 'Ambiguous%'");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE json_extract(crypto_json,"
            "'$.handshake_confirmation')='Endpoint confirmed completion'") == 0,
            "An ambiguous endpoint report remained confirmed");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE flow_id<=2 AND tls_version=772 "
            "AND cipher_id=4866") == 2,
            "Endpoint ambiguity changed the original packet selections");
        storage.finish();
        sqlite3_close(reader);
    }
    require(counters.telemetryLost == 0 && counters.storageLost == 0, "Endpoint matching lost evidence");
    std::filesystem::remove(path);
}

void quicSocketMultiplexing()
{
    std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "quic.json");
    const auto fixtures = nlohmann::json::parse(input);
    Counters counters;
    std::unordered_map<int64_t, Observation> rows;
    Engine engine(counters, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            rows[observation.flowId] = std::move(observation);
    });
    int64_t timestamp = 1700000000000000;

    // Two real encrypted handshakes share one UDP tuple; their connection IDs must keep them distinct.
    for (const size_t fixture : {0, 2})
        for (const auto& encoded : fixtures[fixture]["packets"])
        {
            auto bytes = fromHex(encoded);
            const size_t offset = be16(bytes, 20) == 443 ? 22 : 20;
            bytes[offset] = 52000 >> 8;
            bytes[offset + 1] = 52000 & 255;
            engine.packet(bytes, PacketKind::Ip, timestamp += 1000);
        }
    engine.expire(timestamp, true);
    require(rows.size() == 2 && rows.at(1).serverHello && rows.at(2).serverHello &&
        rows.at(1).quicOriginalId != rows.at(2).quicOriginalId && counters.malformed == 0,
        "Distinct QUIC connection IDs were merged on a shared socket");
    const auto base = std::filesystem::temp_directory_path() /
        ("cipherazzi-quic-socket-" + std::to_string(GetCurrentProcessId()));
    auto database = base;
    database += ".db";
    auto reportPath = base;
    reportPath += ".json";
    std::filesystem::remove(database);
    {
        Storage storage(database, counters, "QUIC multiplexing", "test identity", [](Observation& observation)
        {
            observation.sourceOwner.pid = 4242;
            observation.sourceOwner.startedUs = 1699999000000000;
        });
        for (const auto& [id, row] : rows)
            storage.enqueue(row, true);
        std::ifstream endpointFixture(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "endpoint-pq.json");
        auto report = nlohmann::json::parse(endpointFixture);
        report["transport"] = "QUIC";
        report["provider"] = "QUIC shared socket adapter";
        report["quic_original_dcid"] = rows.at(1).quicOriginalId;
        report["cipher_id"] = rows.at(1).cipher;
        report["group_id"] = -1;
        report["signature_scheme"] = -1;
        report["selected_alpn"] = "h3";
        report["server_certificates_der"] = nlohmann::json::array();
        report["client_certificates_der"] = nlohmann::json::array();
        {
            std::ofstream file(reportPath);
            file << report;
        }
        require(Telemetry::importEndpoint(reportPath, storage) == 1, "QUIC socket report did not import");
        report["provider"] = "QUIC unmatched ID adapter";
        report["quic_original_dcid"] = "0102030405060708";
        {
            std::ofstream file(reportPath);
            file << report;
        }
        require(Telemetry::importEndpoint(reportPath, storage) == 1, "QUIC unmatched report did not import");
        storage.finish();
        sqlite3* reader = nullptr;
        require(sqlite3_open_v2(utf8(database.wstring()).c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "QUIC socket reader could not open");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE flow_id=1 AND "
            "json_extract(crypto_json,'$.handshake_confirmation')='Endpoint confirmed completion'") == 1 &&
            scalar(reader, "SELECT count(*) FROM connections WHERE flow_id=2 AND "
            "json_extract(crypto_json,'$.handshake_confirmation')='Not confirmed by endpoint'") == 1 &&
            scalar(reader, "SELECT count(*) FROM endpoint_events WHERE provider='QUIC unmatched ID adapter' "
            "AND json_extract(detail_json,'$.correlation') LIKE 'Unmatched%'") == 1,
            "Endpoint confirmation crossed connection IDs on a shared QUIC socket");
        sqlite3_close(reader);
    }
    std::filesystem::remove(reportPath);
    std::filesystem::remove(database);
}

void importEndpointDirectory(const std::filesystem::path& directory, const std::filesystem::path& database)
{
    Counters counters;
    Storage storage(database, counters, "Endpoint adapter validation", "Reported process lifetime");
    size_t imported = 0;
    for (const auto& file : std::filesystem::directory_iterator(directory))
        if (file.path().extension() == ".json")
            imported += Telemetry::importEndpoint(file.path(), storage);
    require(imported != 0, "No endpoint adapter reports were imported");
    storage.finish();
    std::cout << "Imported public endpoint reports: " << imported << '\n';
}

void endpointInvalidReports()
{
    const auto base = std::filesystem::temp_directory_path() /
        ("cipherazzi-endpoint-invalid-" + std::to_string(GetCurrentProcessId()));
    const auto database = base.string() + ".db";
    const auto reportPath = base.string() + ".json";
    std::filesystem::remove(database);
    std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "endpoint-pq.json");
    auto valid = nlohmann::json::parse(input);
    valid["server_certificates_der"] = nlohmann::json::array();
    valid["client_certificates_der"] = nlohmann::json::array();
    Counters counters;
    {
        Storage storage(database, counters, "Invalid report stress", "Reported process lifetime");

        // Numeric coercion must never fabricate a socket, process instance, or negotiated parameter.
        for (const auto& [field, value] : std::vector<std::pair<std::string, nlohmann::json>>{
            {"/pid", (uint64_t{1} << 32) + 4242}, {"/pid", -4294963054ll}, {"/pid", true},
            {"/pid", 4242.5}, {"/local/port", (uint64_t{1} << 32) + 50000}, {"/remote/port", 443.5},
            {"/tls_version", (uint64_t{1} << 32) + 772}, {"/cipher_id", (uint64_t{1} << 32) + 4866},
            {"/signature_scheme", (uint64_t{1} << 32) + 2308},
            {"/local_signature_scheme", (uint64_t{1} << 32) + 2309},
            {"/group_id", (uint64_t{1} << 32) + 4588}, {"/tls_version", 772.5},
            {"/handshake_started_us", valid["handshake_started_us"].get<double>()},
            {"/process_started_us", valid["process_started_us"].get<double>()},
            {"/timestamp_us", valid["timestamp_us"].get<double>()}})
        {
            auto report = valid;
            report[nlohmann::json::json_pointer(field)] = value;
            { std::ofstream output(reportPath); output << report; }
            bool rejected = false;
            try { Telemetry::importEndpoint(reportPath, storage); }
            catch (const std::exception&) { rejected = true; }
            require(rejected, "A malformed numeric endpoint identity or parameter was accepted");
        }
        auto future = valid;
        future["process_started_us"] = 9223372036854000000ll;
        future["handshake_started_us"] = 9223372036854775000ll;
        future["timestamp_us"] = 9223372036854775807ll;
        { std::ofstream output(reportPath); output << future; }
        bool rejected = false;
        try { Telemetry::importEndpoint(reportPath, storage); }
        catch (const std::exception&) { rejected = true; }
        require(rejected, "An endpoint timestamp outside the viewer range was accepted");
        { std::ofstream output(reportPath); output << valid; }
        require(Telemetry::importEndpoint(reportPath, storage) == 1, "Invalid reports prevented valid ingestion");
        storage.finish();
        sqlite3* reader = nullptr;
        require(sqlite3_open_v2(database.c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Invalid report reader could not open");
        require(scalar(reader, "SELECT count(*) FROM endpoint_events") == 1,
            "Invalid endpoint reports were persisted as evidence");
        sqlite3_close(reader);
    }
    std::filesystem::remove(reportPath);
    std::filesystem::remove(database);
}

void endpointWatcherBurst()
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("cipherazzi-endpoint-watch-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    const auto database = directory / "capture.db";
    std::filesystem::remove(database);
    std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "endpoint-pq.json");
    auto report = nlohmann::json::parse(input);
    report["server_certificates_der"] = nlohmann::json::array();
    report["client_certificates_der"] = nlohmann::json::array();
    for (int index = 0; index < 1500; ++index)
    {
        std::ofstream output(directory / ("unrelated-" + std::to_string(index) + ".tmp"));
    }
    for (int index = 0; index < 1100; ++index)
    {
        report["provider"] = "Watcher stress " + std::to_string(index);
        std::ofstream output(directory / (std::to_string(index) + ".json"));
        output << report;
    }
    report["provider"] = "Watcher sharing retry";
    const auto lockedPath = directory / "sharing-retry.json";
    { std::ofstream output(lockedPath); output << report; }
    std::unique_ptr<void, decltype(&CloseHandle)> locked(
        CreateFileW(lockedPath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr), CloseHandle);
    require(locked.get() != INVALID_HANDLE_VALUE, "The report read lock could not be acquired");
    Counters counters;
    {
        Storage storage(database, counters, "Endpoint directory burst", "disabled");
        Telemetry telemetry(storage, counters, false, {}, directory);
        sqlite3* reader = nullptr;
        require(sqlite3_open_v2(utf8(database.wstring()).c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Watcher reader could not open");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
        while (!counters.telemetryLost && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        require(counters.telemetryLost != 0, "The watcher did not encounter the temporary read lock");
        locked.reset();
        while (scalar(reader, "SELECT count(*) FROM endpoint_events WHERE provider LIKE 'Watcher stress %'") < 1100 &&
            std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        const auto retryDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
        while (!scalar(reader, "SELECT count(*) FROM endpoint_events WHERE provider='Watcher sharing retry'") &&
            std::chrono::steady_clock::now() < retryDeadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        const auto stopping = std::chrono::steady_clock::now();
        telemetry.stop();
        storage.finish();
        require(std::chrono::steady_clock::now() - stopping < std::chrono::seconds(3),
            "An endpoint burst prevented collector shutdown");
        require(scalar(reader, "SELECT count(*) FROM endpoint_events WHERE provider LIKE 'Watcher stress %'") == 1100,
            "Endpoint directory scanning starved reports beyond the first batch");
        require(scalar(reader, "SELECT count(*) FROM endpoint_events WHERE provider='Watcher sharing retry'") == 1,
            "A temporary file lock permanently hid an endpoint report");
        sqlite3_close(reader);
    }
    for (const auto& entry : std::filesystem::directory_iterator(directory))
        std::filesystem::remove(entry.path());
    std::filesystem::remove(directory);
}

void endpointShutdownAttribution()
{
    const auto path = std::filesystem::temp_directory_path() /
        ("cipherazzi-endpoint-shutdown-" + std::to_string(GetCurrentProcessId()) + ".db");
    std::filesystem::remove(path);
    Counters counters;
    {
        std::unordered_map<int64_t, int> attempts;
        Storage storage(path, counters, "shutdown", "delayed identity", [&](Observation& observation)
        {
            if (++attempts[observation.flowId] < 2)
                return;
            observation.sourceOwner.pid = 4242;
            observation.sourceOwner.startedUs = 1699999000000000;
            observation.sourceOwner.name = "endpoint.exe";
        });
        require(Telemetry::importEndpoint(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) /
            "endpoint-pq.json", storage) == 1, "Endpoint shutdown fixture did not import");

        // Drain more ownership refinements than one transaction can write before finalizing correlation.
        for (int i = 1; i <= 512; ++i)
        {
            Observation observation;
            observation.flowId = i;
            observation.firstUs = 1700000000000000;
            observation.lastUs = 1700000000050000;
            observation.source = {{10,20,0,1},static_cast<uint16_t>(i == 512 ? 52000 : 53000 + i),4};
            observation.destination = {{10,20,0,2},443,4};
            observation.clientHello = observation.serverHello = true;
            observation.version = 772;
            observation.cipher = 4866;
            observation.crypto.groupId = 4588;
            storage.enqueue(std::move(observation), true);
        }
        storage.finish();
        sqlite3* reader = nullptr;
        require(sqlite3_open_v2(utf8(path.wstring()).c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Endpoint shutdown reader could not open");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE flow_id=512 AND "
            "json_extract(crypto_json,'$.handshake_confirmation')='Endpoint confirmed completion'") == 1,
            "Shutdown finalized correlation before the last ownership refinement");
        sqlite3_close(reader);
    }
    std::filesystem::remove(path);
}

void storageConcurrencyAndFailure()
{
    const auto directory = std::filesystem::temp_directory_path() /
        (L"Cipherazzi-tests-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    std::filesystem::create_directory(directory);
    const auto path = directory / L"metadata-\u03b4.db";
    Counters counters;
    {
        Storage storage(path, counters, "test", "disabled");
        sqlite3* reader = nullptr;
        const auto encoded = utf8(path.wstring());
        require(sqlite3_open_v2(encoded.c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Concurrent reader could not open the database");
        require(scalar(reader, "PRAGMA application_id") == 0x435A5A49, "Database identity is incorrect");
        sqlite3_exec(reader, "BEGIN", nullptr, nullptr, nullptr);
        require(scalar(reader, "SELECT count(*) FROM connections") == 0, "Database should start empty");
        Engine engine(counters, [&](Observation row) { storage.enqueue(std::move(row)); });
        engine.tcp(packet(record(hello(true)), 100), 1000000);
        engine.tcp(packet(record(hello(false)), 200, false), 1000010);
        engine.expire(1000020, true);
        storage.finish();
        require(scalar(reader, "SELECT count(*) FROM connections") == 0, "WAL reader snapshot changed during a write");
        sqlite3_exec(reader, "COMMIT", nullptr, nullptr, nullptr);
        require(scalar(reader, "SELECT count(*) FROM connections") == 1, "Handshake updates created duplicate rows");
        require(scalar(reader, "SELECT tls_version FROM connections") == 0x0304, "Selected version was not persisted");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_pid IS NULL") == 1,
            "Unavailable process ID should be NULL");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_account='' AND source_account_sid='' "
            "AND destination_account='' AND destination_account_sid=''") == 1,
            "An unattributed packet was assigned an account");
        require(scalar(reader, "SELECT count(*) FROM capture_sessions WHERE length(computer_name)>0") == 1,
            "The collector computer was not persisted");
        require(scalar(reader, "SELECT count(*) FROM capture_sessions WHERE stopped_us IS NOT NULL") == 1,
            "Final capture health was not persisted");
        sqlite3_close(reader);
    }
    {
        Storage storage(path, counters, "second import", "disabled");
        storage.finish();
    }

    // Slow attribution must not delay streaming hellos or overwrite a later server selection.
    const auto streamingPath = directory / L"streaming.db";
    {
        const auto started = std::chrono::steady_clock::now();
        Storage storage(streamingPath, counters, "streaming", "delayed", [&](Observation& row)
        {
            if (std::chrono::steady_clock::now() - started > std::chrono::milliseconds(500))
            {
                row.sourceOwner.pid = 1234;
                row.sourceOwner.name = "late-owner.exe";
                row.sourceOwner.evidence = "test";
                row.sourceOwner.account = "late-\u0394";
                row.sourceOwner.accountDomain = "LAB";
                row.sourceOwner.accountSid = "S-1-5-21-1-2-3-1001";
                row.destinationOwner.pid = 4321;
                row.destinationOwner.account = "SYSTEM";
                row.destinationOwner.accountDomain = "NT AUTHORITY";
                row.destinationOwner.accountSid = "S-1-5-18";
            }
        });
        sqlite3* reader = nullptr;
        sqlite3_open_v2(utf8(streamingPath.wstring()).c_str(), &reader, SQLITE_OPEN_READONLY, nullptr);
        sqlite3_busy_timeout(reader, 1000);
        Engine engine(counters, [&](Observation row) { storage.enqueue(std::move(row)); });
        engine.tcp(packet(record(hello(true)), 100), 1000000);
        while (!scalar(reader, "SELECT count(*) FROM connections") &&
            std::chrono::steady_clock::now() - started < std::chrono::milliseconds(700))
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        require(scalar(reader, "SELECT count(*) FROM connections") == 1,
            "Process enrichment delayed the live client hello");
        require(!scalar(reader, "SELECT count(*) FROM connections WHERE tls_version IS NOT NULL"),
            "A client offer was reported as a server selection");
        const auto revision = scalar(reader, "SELECT revision FROM metadata");
        engine.tcp(packet(record(hello(false)), 200, false), 1000010);
        while (!scalar(reader, "SELECT count(*) FROM connections WHERE source_pid=1234") &&
            std::chrono::steady_clock::now() - started < std::chrono::seconds(3))
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_pid=1234 AND tls_version=772") == 1,
            "Delayed ownership lost the server hello or failed to arrive");
        require(scalar(reader, "SELECT change_revision FROM connections") > revision,
            "Late ownership did not advance the streaming cursor");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_account='late-\u0394' "
            "AND source_account_domain='LAB' AND source_account_sid='S-1-5-21-1-2-3-1001' "
            "AND destination_account='SYSTEM' AND destination_account_domain='NT AUTHORITY' "
            "AND destination_account_sid='S-1-5-18'") == 1, "Late process accounts were not persisted");
        storage.finish();
        sqlite3_close(reader);
    }

    // A short database stall must preserve a diagnostic burst without blocking the capture producer.
    const auto endpointPath = directory / L"endpoint-burst.db";
    {
        Counters endpointCounters;
        Storage storage(endpointPath, endpointCounters, "endpoint burst", "disabled");
        sqlite3* writer = nullptr;
        sqlite3_open_v2(utf8(endpointPath.wstring()).c_str(), &writer, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_busy_timeout(writer, 1000);
        require(sqlite3_exec(writer, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK,
            "The burst test could not hold the database writer");
        for (int index = 0; index < 3000; ++index)
        {
            EndpointEvent event;
            event.id = std::to_string(index);
            event.provider = "burst";
            event.detail = R"({"message":")" + std::string(512, 'x') + R"("})";
            storage.enqueue(std::move(event));
        }
        sqlite3_exec(writer, "COMMIT", nullptr, nullptr, nullptr);
        storage.finish();
        require(endpointCounters.telemetryLost == 0 &&
            scalar(writer, "SELECT count(*) FROM endpoint_events") == 3000,
            "A short writer stall dropped endpoint events from a bounded burst");
        sqlite3_close(writer);
    }

    // Oversized diagnostic bursts still stop at the memory budget and report every rejected event.
    {
        Counters endpointCounters;
        const auto boundedPath = directory / L"endpoint-bounded.db";
        Storage storage(boundedPath, endpointCounters, "endpoint limits", "disabled");
        sqlite3* writer = nullptr;
        sqlite3_open_v2(utf8(boundedPath.wstring()).c_str(), &writer, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_busy_timeout(writer, 1000);
        require(sqlite3_exec(writer, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK,
            "The limit test could not hold the database writer");
        for (int index = 0; index < 2048; ++index)
        {
            EndpointEvent event;
            event.id = std::to_string(index);
            event.detail.assign(60000, 'x');
            event.detail.replace(0, 12, R"({"message":")");
            event.detail.replace(59998, 2, R"("})");
            storage.enqueue(std::move(event));
        }
        sqlite3_exec(writer, "COMMIT", nullptr, nullptr, nullptr);
        storage.finish();
        require(endpointCounters.telemetryLost > 0 && endpointCounters.telemetryLost +
            scalar(writer, "SELECT count(*) FROM endpoint_events") == 2048,
            "The endpoint memory limit lost its accounting or accepted an unbounded burst");
        sqlite3_close(writer);
    }

    // A persistent writer lock must fail promptly, roll back its batch, and permit a clean restart.
    const auto stalledPath = directory / L"stalled.db";
    {
        Counters stalledCounters;
        Storage storage(stalledPath, stalledCounters, "persistent lock", "disabled");
        sqlite3* blocker = nullptr;
        sqlite3_open_v2(utf8(stalledPath.wstring()).c_str(), &blocker, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_busy_timeout(blocker, 1000);
        require(sqlite3_exec(blocker, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK,
            "The persistent lock could not be acquired");
        Engine engine(stalledCounters, [&](Observation row) { storage.enqueue(std::move(row)); });
        engine.tcp(packet(record(hello(true)), 100), 1000000);
        engine.tcp(packet(record(hello(false)), 200, false), 1000010);
        engine.expire(1000020, true);
        const auto started = std::chrono::steady_clock::now();
        bool failed = false;
        try { storage.finish(); }
        catch (const std::exception&) { failed = true; }
        require(failed && std::chrono::steady_clock::now() - started < std::chrono::seconds(5),
            "A persistent writer lock did not terminate with an error");
        sqlite3_exec(blocker, "ROLLBACK", nullptr, nullptr, nullptr);
        require(scalar(blocker, "SELECT count(*) FROM connections") == 0 &&
            scalar(blocker, "SELECT count(*) FROM pragma_integrity_check WHERE integrity_check<>'ok'") == 0,
            "Writer failure committed an incomplete batch or corrupted the database");
        {
            Storage recovered(stalledPath, stalledCounters, "writer restart", "disabled");
            Engine restarted(stalledCounters, [&](Observation row) { recovered.enqueue(std::move(row)); });
            restarted.tcp(packet(record(hello(true)), 100), 2000000);
            restarted.tcp(packet(record(hello(false)), 200, false), 2000010);
            restarted.expire(2000020, true);
            recovered.finish();
        }
        require(scalar(blocker, "SELECT count(*) FROM connections") == 1,
            "Writer failure prevented a later collector from using the journal");
        sqlite3_close(blocker);
    }

    // An unrelated SQLite file must never be initialized as a collector database.
    const auto unrelated = directory / L"unrelated.db";
    sqlite3* other = nullptr;
    sqlite3_open(utf8(unrelated.wstring()).c_str(), &other);
    sqlite3_exec(other, "CREATE TABLE keep_me(value INTEGER); INSERT INTO keep_me VALUES(42)",
        nullptr, nullptr, nullptr);
    sqlite3_close(other);
    bool rejected = false;
    try { Storage storage(unrelated, counters, "test", "disabled"); }
    catch (const std::exception&) { rejected = true; }
    require(rejected, "Unrelated database was accepted");
    sqlite3_open(utf8(unrelated.wstring()).c_str(), &other);
    require(scalar(other, "SELECT value FROM keep_me") == 42, "Unrelated database was modified");
    sqlite3_close(other);
    for (const auto& entry : std::filesystem::directory_iterator(directory))
        std::filesystem::remove(entry.path());
    std::filesystem::remove(directory);
}

void captureQueueConcurrency()
{
    // Burst packets wrap both rings while a slower consumer checks every byte and the original ordering.
    PacketQueue queue(64, 32768);
    constexpr int64_t count = 20000;
    std::atomic<bool> cancel{};
    std::atomic<size_t> full{};
    std::jthread producer([&]
    {
        Buffer bytes(PacketMonitorCaptureLimit);
        for (int64_t index = 0; index < count && !cancel; ++index)
        {
            const auto length = static_cast<size_t>(54 + index * 7919 % (PacketMonitorCaptureLimit - 53));
            std::fill_n(bytes.begin(), length, static_cast<uint8_t>(index));
            while (!cancel && !queue.push(Bytes(bytes).first(length), PacketKind::Ethernet, index))
            {
                ++full;
                std::this_thread::yield();
            }
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    try
    {
        for (int64_t index = 0; index < count; ++index)
        {
            const auto packet = queue.take(std::chrono::seconds(5));
            require(packet && packet->timestamp == index && packet->kind == PacketKind::Ethernet &&
                packet->bytes.size() == static_cast<size_t>(54 + index * 7919 % (PacketMonitorCaptureLimit - 53)),
                "Packet queue lost ordering, length, or metadata");
            require(std::ranges::all_of(packet->bytes, [index](uint8_t value)
            {
                return value == static_cast<uint8_t>(index);
            }), "Packet queue reused bytes before consumption");
            queue.release();
        }
        require(full != 0, "Packet queue test did not exercise backpressure");
        queue.wake();
        require(!queue.take(std::chrono::milliseconds(1)), "Packet queue stop signal created a packet");
    }
    catch (...)
    {
        cancel = true;
        throw;
    }
}

void mixedCaptureQueue()
{
    // Concurrent capture sources wrap the same bounded queue without truncating full-size IPv6 packets.
    PacketQueue queue(64, 512 * 1024, LoopbackCaptureLimit);
    constexpr int64_t count = 1500;
    std::atomic<bool> cancel{};
    auto produce = [&](PacketOrigin origin)
    {
        const auto loopback = origin == PacketOrigin::Loopback;
        Buffer bytes(loopback ? LoopbackCaptureLimit : PacketMonitorCaptureLimit);
        for (int64_t index = 0; index < count && !cancel; ++index)
        {
            std::ranges::fill(bytes, static_cast<uint8_t>(index));
            if (loopback)
            {
                std::fill_n(bytes.begin(), 60, uint8_t{});
                bytes[0] = 0x60;
                bytes[4] = bytes[5] = 255;
                bytes[6] = 6;
                bytes[7] = 64;
                bytes[23] = bytes[39] = 1;
                bytes[40] = 0x9c;
                bytes[41] = 0x40;
                bytes[42] = 1;
                bytes[43] = 0xbb;
                bytes[52] = 0x50;
                bytes[53] = 0x18;
            }
            while (!cancel && !queue.push(bytes, loopback ? PacketKind::Ip : PacketKind::Ethernet, index, origin))
                std::this_thread::yield();
        }
    };
    std::jthread network([&] { produce(PacketOrigin::PacketMonitor); });
    std::jthread loopback([&] { produce(PacketOrigin::Loopback); });
    std::array<int64_t, 2> received{};
    Counters counters;
    try
    {
        for (int64_t total = 0; total < count * 2; ++total)
        {
            const auto packet = queue.take(std::chrono::seconds(5));
            require(packet.has_value(), "Mixed capture producers stopped delivering packets");
            const auto local = packet->origin == PacketOrigin::Loopback;
            require(packet->timestamp == received[local]++ &&
                packet->bytes.size() == (local ? LoopbackCaptureLimit : PacketMonitorCaptureLimit),
                "Mixed capture queue lost origin, ordering, or complete packet length");
            Bytes payload = packet->bytes;
            if (local)
            {
                const auto decoded = decodePacket(packet->bytes, packet->kind, counters, packet->origin);
                require(decoded && decoded->source.family == 6 && decoded->destination.family == 6 &&
                    decoded->source.port == 40000 && decoded->destination.port == 443 && !decoded->truncated,
                    "Loopback capture inherited Packet Monitor truncation or lost IPv6 socket identity");
                payload = decoded->payload;
            }
            require(std::ranges::all_of(payload, [&](uint8_t value)
            {
                return value == static_cast<uint8_t>(packet->timestamp);
            }), "Concurrent capture producers overwrote unread packet bytes");
            queue.release();
        }
        require(received[0] == count && received[1] == count && !counters.truncated && !counters.malformed,
            "Mixed capture source verification lost complete packets");
    }
    catch (...)
    {
        cancel = true;
        throw;
    }

    // Sources that collide wait for each other; neither discards a packet while the queue has room.
    PacketQueue roomy(8192, 16 * 1024 * 1024, LoopbackCaptureLimit);
    constexpr int burst = 4000;
    std::atomic<int> refused{};
    {
        const Buffer bytes(1500, 0x5a);
        auto source = [&](PacketOrigin origin)
        {
            for (int index = 0; index < burst; ++index)
                if (!roomy.push(bytes, PacketKind::Ip, index, origin))
                    ++refused;
        };
        std::jthread first([&] { source(PacketOrigin::PacketMonitor); });
        std::jthread second([&] { source(PacketOrigin::Loopback); });
    }
    std::array<int64_t, 2> order{};
    for (int total = 0; total < burst * 2 - refused; ++total)
    {
        const auto packet = roomy.take(std::chrono::seconds(5));
        require(packet && packet->bytes.size() == 1500 &&
            packet->timestamp == order[packet->origin == PacketOrigin::Loopback]++,
            "Colliding capture sources lost a queued packet or its per-source order");
        roomy.release();
    }
    require(refused == 0, "A capture source discarded a packet while the shared queue had room");
}

void captureLifecycle()
{
    // Exercise live stream shutdown and partial startup with an explicitly throttled timer policy.
    require(elevated(), "Capture lifecycle verification requires elevation");
    auto readPower = []
    {
        PROCESS_POWER_THROTTLING_STATE power{PROCESS_POWER_THROTTLING_CURRENT_VERSION};
        require(GetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &power, sizeof(power)),
            "Could not query process timer policy");
        return power;
    };
    auto original = readPower();
    auto initial = original;
    initial.ControlMask |= PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
    initial.StateMask |= PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
    require(SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &initial, sizeof(initial)),
        "Could not configure the timer policy control");
    Counters counters;
    Engine engine(counters, [](Observation) {});
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        {
            Capture capture(engine, counters, {});
            capture.check();
            const auto active = readPower();
            require(active.ControlMask == initial.ControlMask &&
                active.StateMask == (initial.StateMask & ~PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION),
                "Live capture did not honor timer requests or changed unrelated power policies");
            capture.stop();
            capture.stop();
        }
        const auto stopped = readPower();
        require(stopped.ControlMask == initial.ControlMask && stopped.StateMask == initial.StateMask,
            "Capture shutdown did not restore timer policy");
        bool failed = false;
        try { Capture capture(engine, counters, {MAXDWORD}); }
        catch (const std::runtime_error&) { failed = true; }
        const auto afterFailure = readPower();
        require(failed && afterFailure.ControlMask == initial.ControlMask && afterFailure.StateMask == initial.StateMask,
            "Failed capture startup did not restore timer policy");
    }
    require(SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &original, sizeof(original)),
        "Could not restore timer policy");
    std::cout << "Capture lifecycle checks passed.\n";
}

void benchmark()
{
    Counters counters;
    size_t observed = 0;
    Engine engine(counters, [&](Observation row) { if (!row.lifecycleOnly) ++observed; });
    const auto client = record(hello(true));
    const auto server = record(hello(false));
    constexpr uint32_t count = 100000;
    const auto started = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < count; ++i)
    {
        const uint32_t sequence = i * 1000;
        engine.tcp(packet({}, sequence, true, 2), 1000000 + i);
        engine.tcp(packet(client, sequence + 1), 1000000 + i);
        engine.tcp(packet(server, sequence + 500, false), 1000000 + i);
    }
    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    require(observed == count * 2, "Benchmark did not parse all handshakes");
    std::cout << "Reassembly/TLS benchmark: " << count / elapsed << " handshakes/s; "
        << count * 3 / elapsed << " TCP segments/s; " << elapsed << " s\n";
}

void processOwnership()
{
    // Correlate an actual local TCP connection and reject a process name from before its creation.
    WSADATA winsock{};
    require(WSAStartup(MAKEWORD(2, 2), &winsock) == 0, "Winsock initialization failed");
    const SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && listen(server, 1) == 0,
        "Loopback test server failed");
    int size = sizeof(address);
    getsockname(server, reinterpret_cast<sockaddr*>(&address), &size);
    require(connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
        "Loopback test connection failed");
    const SOCKET accepted = accept(server, nullptr, nullptr);
    require(accepted != INVALID_SOCKET, "Loopback test accept failed");
    Observation observation;
    observation.firstUs = observation.lastUs = nowUs();
    std::memcpy(observation.destination.address.data(), &address.sin_addr, 4);
    observation.destination.port = ntohs(address.sin_port);
    getsockname(client, reinterpret_cast<sockaddr*>(&address), &size);
    std::memcpy(observation.source.address.data(), &address.sin_addr, 4);
    observation.source.port = ntohs(address.sin_port);
    Counters counters;
    {
        Processes processes(counters);
        processes.enrich(observation);
    }
    closesocket(accepted);
    closesocket(client);
    closesocket(server);

    // Prime the UDP cache before opening a short-lived socket, then resolve its first observation immediately.
    {
        Processes processes(counters);
        Observation warm;
        warm.udp = true;
        warm.firstUs = warm.lastUs = nowUs();
        warm.source.address[0] = 127;
        warm.source.address[3] = 1;
        warm.source.port = 65534;
        processes.enrich(warm);
        const SOCKET datagram = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        require(datagram != INVALID_SOCKET &&
            connect(datagram, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
            "UDP ownership control could not open its socket");
        getsockname(datagram, reinterpret_cast<sockaddr*>(&address), &size);
        Observation udp;
        udp.udp = true;
        udp.firstUs = udp.lastUs = nowUs();
        std::memcpy(udp.source.address.data(), &address.sin_addr, 4);
        udp.source.port = ntohs(address.sin_port);
        processes.enrich(udp);
        closesocket(datagram);
        require(udp.sourceOwner.pid == GetCurrentProcessId(),
            "A cached UDP binding table hid a newly opened socket");
    }
    WSACleanup();
    require(observation.sourceOwner.pid == GetCurrentProcessId() &&
        observation.destinationOwner.pid == GetCurrentProcessId(), "Local TCP ownership was not resolved");
    require(!observation.sourceOwner.name.empty(), "Local process name was not resolved");
    wchar_t expected[512]{};
    ULONG expectedSize = 512;
    require(GetUserNameExW(NameSamCompatible, expected, &expectedSize), "Could not obtain the test account");
    for (const auto* owner : {&observation.sourceOwner, &observation.destinationOwner})
        require(owner->accountDomain + "\\" + owner->account == utf8(expected) && !owner->accountSid.empty(),
            "The local TCP process owner does not match its Windows account");
    const auto reused = Processes::describe(GetCurrentProcessId(), 1, "test");
    require(reused.name.empty() && reused.path.empty() && reused.account.empty() && reused.accountSid.empty(),
        "A name or account was assigned to a newer process instance");
    const auto inaccessible = Processes::describe(MAXDWORD, nowUs(), "test");
    require(inaccessible.account.empty() && inaccessible.accountSid.empty(),
        "An inaccessible process was assigned the collector's account");
}
}

int main(int argc, char** argv)
{
    using namespace Cipherazzi::Tests;
    try
    {
        if (argc == 2 && std::string_view(argv[1]) == "--protocol-parsers")
        {
            protocolCoverage();
            networkCoverage();
            rdmaCoverage();
            roceCoverage();
            std::cout << "All protocol parser checks passed.\n";
        }
        else if (argc == 3 && std::string_view(argv[1]) == "--endpoint-integration")
            endpointIntegration(argv[2]);
        else if (argc == 4 && std::string_view(argv[1]) == "--import-endpoints")
            importEndpointDirectory(argv[2], argv[3]);
        else if (argc == 3 && std::string_view(argv[1]) == "--inspect-pcap")
            inspectCapture(argv[2]);
        else if (argc > 1 && std::string_view(argv[1]) == "--benchmark")
            benchmark();
        else if (argc == 2 && std::string_view(argv[1]) == "--capture-lifecycle")
            captureLifecycle();
        else if (argc == 2 && std::string_view(argv[1]) == "--capture-queue")
        {
            captureQueueConcurrency();
            mixedCaptureQueue();
            std::cout << "Mixed capture queue checks passed.\n";
        }
        else
        {
            fragmentationAndRetransmission();
            retryAndIncomplete();
            pqNegotiationEvidence();
            startTlsAndLegacy();
            protocolCoverage();
            vpnCoverage();
            networkCoverage();
            rdmaCoverage();
            roceCoverage();
            retentionCoverage();
            packetMonitorOffload();
            packetBoundariesAndLimits();
            malformedAndFuzz();
            captureQueueConcurrency();
            mixedCaptureQueue();
            storageConcurrencyAndFailure();
            quicCoverage();
            endpointConfirmation();
            endpointIntegration();
            endpointInvalidReports();
            endpointWatcherBurst();
            endpointShutdownAttribution();
            quicSocketMultiplexing();
            processOwnership();
            std::cout << "All collector checks passed.\n";
        }
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
