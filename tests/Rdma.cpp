#include "Engine.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);
std::vector<uint8_t> fromHex(const std::string& text);

void rdmaCoverage()
{
    std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "iwarp.json");
    const auto fixtures = nlohmann::json::parse(input);
    for (const auto& fixture : fixtures)
    {
        const auto client = fromHex(fixture["request"].get<std::string>());
        const auto server = fromHex(fixture["response"].get<std::string>());
        Counters counters;
        std::vector<Observation> observations;
        Engine engine(counters, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                observations.push_back(std::move(observation));
        });
        auto packet = [](Bytes payload, bool server, uint32_t sequence, uint8_t flags = 0x18)
        {
            TcpPacket value;
            value.source.address[0] = value.destination.address[0] = 10;
            value.source.address[3] = server ? 2 : 1;
            value.destination.address[3] = server ? 1 : 2;
            value.source.port = server ? 5445 : 41372;
            value.destination.port = server ? 41372 : 5445;
            value.sequence = sequence;
            value.flags = flags;
            value.payload = payload;
            return value;
        };

        // Hold client Sends until the peer declares its marker format, then reassemble both RDMA layers.
        engine.tcp(packet({}, false, 1000, 2), 1);
        engine.tcp(packet({}, true, 9000, 0x12), 2);
        engine.tcp(packet(client, false, 1001), 3);
        require(observations.empty(), "iWARP inspected Sends before the peer declared framing options");
        for (size_t offset = 0; offset < server.size(); ++offset)
            engine.tcp(packet(Bytes(server).subspan(offset, 1), true, static_cast<uint32_t>(9001 + offset)),
                4 + static_cast<int64_t>(offset));
        engine.expire(1000000, true);
        require(!observations.empty() && counters.malformed == 0 && counters.reassemblyLimit == 0 &&
            counters.bufferedBytes == 0, "iWARP reassembly rejected a valid exchange or retained inspection storage");
        CryptoCatalog catalog;
        const auto evidence = nlohmann::json::parse(catalog.summarize(observations.back(),
            [](const auto&, const auto&, Bytes) {}).json);
        require(evidence["protocol"] == "SMB" && evidence["smb_transport_framing"] == "SMB Direct / iWARP" &&
            evidence["smb_iwarp_markers"] == fixture["markers"] &&
            evidence["smb_iwarp_crc_checked"] == fixture["crc"] &&
            evidence["smb_selected_dialect"] == "0x0302" &&
            evidence["smb_offered_dialects"] == nlohmann::json::array({"0x0202", "0x0302"}) &&
            evidence["smb_signed_message_observed"] == true &&
            evidence["smb_encrypted_transform_observed"] == true &&
            evidence["smb_direct_server_negotiation"]["selected_version"] == "0x0100",
            "SMB Direct lost transport, dialect, signing, or encrypted framing evidence");

        // Corrupted CRCs and invalid marker pointers must stop inspection before security evidence is emitted.
        if (fixture["crc"].get<bool>() || fixture["markers"].get<bool>())
        {
            auto malformed = client;
            if (fixture["crc"].get<bool>())
                malformed[malformed.size() - 1] ^= 1;
            else
                malformed[23] = 4;
            IwarpStream rejected;
            int reports = 0;
            require(rejected.feed(malformed, [&](const nlohmann::json&) { ++reports; return true; }),
                "iWARP inspected data before peer setup was available");
            rejected.configurePeer(fixture["peer_flags"].get<uint8_t>());
            require(!rejected.feed({}, [&](const nlohmann::json&) { ++reports; return true; }) && reports <= 1,
                "Malformed iWARP framing produced SMB negotiation or protected-message evidence");
        }
    }

    // Channel metadata is inspected through fragmented SMB Direct Sends, independently of message protection.
    auto set16 = [](std::vector<uint8_t>& bytes, size_t offset, uint16_t value)
    {
        bytes[offset] = static_cast<uint8_t>(value);
        bytes[offset + 1] = static_cast<uint8_t>(value >> 8);
    };
    auto set32 = [&](std::vector<uint8_t>& bytes, size_t offset, uint32_t value)
    {
        set16(bytes, offset, static_cast<uint16_t>(value));
        set16(bytes, offset + 2, static_cast<uint16_t>(value >> 16));
    };
    auto transformed = [&](bool write, uint32_t channel, uint16_t nonce)
    {
        const size_t fixed = write ? 112 : 80;
        const size_t descriptor = (40 + nonce + 7u) & ~size_t{7};
        const auto length = channel ? descriptor + 16 : 40 + nonce;
        std::vector<uint8_t> bytes(fixed + length);
        bytes[0] = 0xfe;
        bytes[1] = 'S'; bytes[2] = 'M'; bytes[3] = 'B';
        set16(bytes, 4, 64);
        set16(bytes, 12, write ? 9 : 8);
        set32(bytes, 16, write ? 0 : 1);
        set16(bytes, 64, write ? 49 : 17);
        if (write)
        {
            set32(bytes, 96, 3);
            set16(bytes, 104, static_cast<uint16_t>(fixed));
            set16(bytes, 106, static_cast<uint16_t>(length));
        }
        else
        {
            bytes[66] = static_cast<uint8_t>(fixed);
            set32(bytes, 68, static_cast<uint32_t>(length));
            set32(bytes, 76, 1);
        }
        set32(bytes, write ? 100 : 72, 65536);
        if (channel)
        {
            set16(bytes, fixed, static_cast<uint16_t>(descriptor));
            set16(bytes, fixed + 2, 16);
            std::fill(bytes.begin() + fixed + descriptor, bytes.end(), uint8_t{0xab});
        }
        set32(bytes, fixed + 4, channel);
        set16(bytes, fixed + 8, 1);
        set16(bytes, fixed + 16, 2);
        set16(bytes, fixed + 18, 16);
        set16(bytes, fixed + 20, nonce);
        std::fill_n(bytes.begin() + fixed + 24, 16 + nonce, uint8_t{0xcd});
        return bytes;
    };
    for (const bool write : {false, true})
        for (const uint32_t channel : {0u, 1u, 2u})
        {
            const auto bytes = transformed(write, channel, 12);
            SmbDirectStream direct;
            nlohmann::json fields;
            for (size_t offset = 0; offset < bytes.size(); offset += 19)
            {
                const auto length = std::min(size_t{19}, bytes.size() - offset);
                std::vector<uint8_t> send(24 + length);
                set32(send, 8, static_cast<uint32_t>(bytes.size() - offset - length));
                set32(send, 12, 24);
                set32(send, 16, static_cast<uint32_t>(length));
                std::copy_n(bytes.begin() + offset, length, send.begin() + 24);
                require(direct.feed(send, [&](const nlohmann::json& observed)
                    { fields.update(observed); return true; }),
                    "SMB Direct rejected fragmented RDMA protection metadata");
                require(offset + length == bytes.size() || fields.empty(),
                    "SMB Direct emitted incomplete RDMA protection metadata");
            }
            const auto& transform = fields[write ? "smb_rdma_write_transform" : "smb_rdma_read_transform"];
            require(fields["smb_rdma_signed_payload_observed"] == true && transform["type"] == "Signing" &&
                transform["signature_length"] == 16 && transform["nonce_length"] == 12 &&
                transform["descriptor_count"] == (channel ? 1 : 0) &&
                !fields.contains("smb_signed_message_observed") &&
                !fields.contains("smb_encrypted_transform_observed") &&
                fields.dump().find("abababab") == std::string::npos &&
                fields.dump().find("cdcdcdcd") == std::string::npos && direct.memory() == 0,
                "RDMA payload protection became message protection evidence or retained signatures/buffer tokens");
        }

    // Validate every compound part before retaining evidence, including offsets that enter another command.
    auto compound = transformed(true, 1, 0);
    set32(compound, 20, static_cast<uint32_t>(compound.size()));
    const auto read = transformed(false, 0, 0);
    compound.insert(compound.end(), read.begin(), read.end());
    bool limited = false;
    nlohmann::json fields;
    require(parseSmb(compound, fields, limited) && fields.contains("smb_rdma_write_transform") &&
        fields.contains("smb_rdma_read_transform"), "Compound SMB commands lost RDMA protection metadata");
    compound.back() ^= 1;
    compound[compound.size() - read.size() + 64] = 18;
    fields.clear();
    require(!parseSmb(compound, fields, limited) && fields.empty(),
        "Malformed compound SMB commands published partial RDMA protection evidence");
    for (const auto [offset, value] : std::initializer_list<std::pair<size_t, uint32_t>>{
        {104, 108}, {112, 41}, {114, 15}, {120, 2}, {128, 1}, {128, 3}, {130, 17}, {132, 65535}})
    {
        auto malformed = transformed(true, 1, 0);
        set16(malformed, offset, static_cast<uint16_t>(value));
        fields.clear();
        require(!parseSmb(malformed, fields, limited) && fields.empty(),
            "Malformed SMB RDMA offsets, counts, or lengths published protection evidence");
    }

    // Negotiated transform IDs describe capability; they never imply that a protected payload was observed.
    for (const bool response : {false, true})
    {
        const size_t context = response ? 128 : 104;
        std::vector<uint8_t> negotiation(context + 20);
        negotiation[0] = 0xfe;
        negotiation[1] = 'S'; negotiation[2] = 'M'; negotiation[3] = 'B';
        set16(negotiation, 4, 64);
        set32(negotiation, 16, response ? 1 : 0);
        set16(negotiation, 64, response ? 65 : 36);
        set16(negotiation, response ? 68 : 100, 0x0311);
        set16(negotiation, response ? 70 : 96, 1);
        set32(negotiation, response ? 124 : 92, static_cast<uint32_t>(context));
        if (!response)
            set16(negotiation, 66, 1);
        set16(negotiation, context, 7);
        set16(negotiation, context + 2, 12);
        set16(negotiation, context + 8, 2);
        set16(negotiation, context + 16, 1);
        set16(negotiation, context + 18, 2);
        fields.clear();
        require(parseSmb(negotiation, fields, limited) &&
            fields[response ? "smb_selected_rdma_transforms" : "smb_offered_rdma_transforms"] ==
                nlohmann::json::array({"0x0001", "0x0002"}) && !fields.contains("smb_rdma_signed_payload_observed") &&
            !fields.contains("smb_signed_message_observed") && !fields.contains("smb_encrypted_transform_observed"),
            "SMB RDMA capabilities became observed payload or message protection");
        set16(negotiation, context + 18, 1);
        fields.clear();
        require(!parseSmb(negotiation, fields, limited) && fields.empty(),
            "SMB RDMA negotiation accepted duplicate transform identifiers");
    }

    // A Send declaring more than the inspection bound cannot allocate its advertised payload.
    SmbDirectStream oversized;
    auto header = fromHex("0a000a000000000001000400180000000400000000000000fe534d42");
    require(!oversized.feed(header, [](const nlohmann::json&) { return true; }) && oversized.limited() &&
        oversized.memory() == 0, "SMB Direct exceeded its inspection bound");
    SmbDirectStream misplaced;
    header[8] = 1;
    header[9] = header[10] = header[11] = 0;
    header[12] = 20;
    require(!misplaced.feed(header, [](const nlohmann::json&) { return true; }),
        "SMB Direct accepted an unaligned DataOffset");
}

void roceCoverage()
{
    std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "roce.json");
    const auto fixtures = nlohmann::json::parse(input);
    CryptoCatalog catalog;
    auto evidence = [&](const Observation& observation)
    {
        return nlohmann::json::parse(catalog.summarize(observation, [](const auto&, const auto&, Bytes) {}).json);
    };

    // Published Linux/Windows negotiation pairs each sender with the peer's advertised receive sequence.
    {
        std::ifstream captured(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "roce-interop.json");
        const auto fixture = nlohmann::json::parse(captured);
        Counters counters;
        std::vector<Observation> observations;
        Engine engine(counters, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                observations.push_back(std::move(observation));
        });
        for (const auto& packet : fixture["packets"])
            engine.packet(fromHex(packet["hex"].get<std::string>()), PacketKind::Ethernet,
                packet["number"].get<int64_t>());
        engine.expire(1000000, true);
        require(!observations.empty() && counters.malformed == 0 && counters.unsupported == 0 &&
            counters.reassemblyLimit == 0 && counters.bufferedBytes == 0 && counters.activeFlows == 0,
            "Captured Linux/Windows RoCE negotiation was dropped or retained inspection storage");
        const auto result = evidence(observations.back());
        require(result["smb_selected_dialect"] == "0x0311" && result["roce_client_queue_pair"] == 25 &&
            result["roce_server_queue_pair"] == 88 && result["roce_connection_response_observed"] == true &&
            result["roce_ready_observed"] == true && result["smb_transport_framing"] == "SMB Direct / RoCEv2" &&
            !result.value("smb_signed_message_observed", false) &&
            !result.value("smb_encrypted_transform_observed", false),
            "Captured RoCE lost negotiated SMB metadata or inferred protection from negotiation alone");
    }

    for (const auto& fixture : fixtures)
    {
        Counters counters;
        std::vector<Observation> observations, lifecycle;
        Engine engine(counters, [&](Observation observation)
        {
            (observation.lifecycleOnly ? lifecycle : observations).push_back(std::move(observation));
        });
        int64_t timestamp = 1;
        for (const auto& packet : fixture["packets"])
            engine.packet(fromHex(packet["hex"].get<std::string>()), PacketKind::Ethernet, timestamp++);
        engine.expire(timestamp, true);
        if (observations.empty() || lifecycle.size() != 1 || counters.malformed || counters.unsupported ||
            counters.reassemblyLimit || counters.flowLimit || counters.bufferedBytes || counters.activeFlows)
            throw std::runtime_error(fixture["name"].get<std::string>() + ": RoCE capture failed: observations=" +
                std::to_string(observations.size()) + ", malformed=" + std::to_string(counters.malformed) +
                ", unsupported=" + std::to_string(counters.unsupported) +
                ", reassembly=" + std::to_string(counters.reassemblyLimit));
        const auto result = evidence(observations.back());
        const bool complete = result["protocol"] == "SMB" && result["transport"] == fixture["transport"] &&
            result["smb_transport_framing"] == "SMB Direct / " + fixture["transport"].get<std::string>() &&
            result["roce_invariant_crc_checked"] == true && result["roce_connection_management_observed"] == true &&
            result["roce_connection_response_observed"] == true && result["roce_ready_observed"] == true &&
            result["roce_roles_known"] == true && result["roce_client_queue_pair"] == fixture["client_qp"] &&
            result["roce_server_queue_pair"] == fixture["server_qp"] &&
            result["smb_selected_dialect"] == "0x0311" &&
            result["encryption"] == "AES-128-GCM" && result["symmetric_key_bits"] == 128 &&
            result["smb_offered_dialects"] == nlohmann::json::array({"0x0202", "0x0311"}) &&
            result["smb_selected_rdma_transforms"] == nlohmann::json::array({"0x0001", "0x0002"}) &&
            result["smb_offered_rdma_transforms"] == nlohmann::json::array({"0x0001", "0x0002"}) &&
            result["smb_rdma_read_transform"]["type"] == "Signing" &&
            result["smb_rdma_write_transform"]["descriptor_count"] == 1 &&
            result["smb_signed_message_observed"] == true && result["smb_encrypted_transform_observed"] == true &&
            result["roce_disconnect_request_observed"] == true;
        if (!complete)
            throw std::runtime_error(fixture["name"].get<std::string>() +
                ": RoCE evidence incomplete: " + result.dump());
        require(lifecycle[0].flowId == observations.back().flowId &&
            lifecycle[0].closeReason == "RDMA disconnect exchange observed" &&
            observations.back().source.port == (fixture["transport"] == "RoCEv1" ? 0 : 55001) &&
            observations.back().destination.port == (fixture["transport"] == "RoCEv1" ? 0 : 4791),
            "RoCE turned queue-pair IDs into socket ports or lost its observed disconnect exchange");
        for (const auto& observation : observations)
        {
            const auto json = evidence(observation).dump();
            require(observation.flowId == observations[0].flowId &&
                json.find("Cipherazzi-CM") == std::string::npos &&
                json.find("Cipherazzi-RDMA-file-payload") == std::string::npos &&
                json.find("abababab") == std::string::npos && json.find("cdcdcdcd") == std::string::npos,
                "RoCE mixed connections or persisted RDMA file data, private CM data, or buffer tokens");
        }

        // Invalid checksums and capture truncation cannot establish SMB evidence from the rejected packet.
        for (const bool truncate : {false, true})
        {
            Counters rejectedCounters;
            std::vector<Observation> rejected;
            Engine rejectedEngine(rejectedCounters, [&](Observation observation)
            {
                if (!observation.lifecycleOnly)
                    rejected.push_back(std::move(observation));
            });
            for (size_t index = 0; index < 3; ++index)
                rejectedEngine.packet(fromHex(fixture["packets"][index]["hex"].get<std::string>()),
                    PacketKind::Ethernet, static_cast<int64_t>(index + 1));
            auto packet = fromHex(fixture["packets"][3]["hex"].get<std::string>());
            if (truncate)
                packet.pop_back();
            else
                packet.back() ^= 1;
            rejectedEngine.packet(packet, PacketKind::Ethernet, 4);
            rejectedEngine.expire(5, true);
            require(rejected.empty() && rejectedCounters.activeFlows == 0 && rejectedCounters.bufferedBytes == 0 &&
                (truncate ? rejectedCounters.truncated == 1 : rejectedCounters.malformed == 1),
                "Invalid RoCE checksum or truncated capture produced SMB evidence or leaked inspection state");
        }
        for (const auto& kind : {"mismatched_gid", "unsupported_uc"})
        {
            Counters rejectedCounters;
            int reports = 0;
            Engine rejectedEngine(rejectedCounters, [&](Observation) { ++reports; });
            rejectedEngine.packet(fromHex(fixture["negative"][kind].get<std::string>()), PacketKind::Ethernet, 1);
            require(reports == 0 && rejectedCounters.activeFlows == 0 && rejectedCounters.bufferedBytes == 0 &&
                (std::string_view(kind) == "unsupported_uc" ? rejectedCounters.unsupported == 1 :
                    rejectedCounters.malformed == 1), "RoCE paired mismatched GIDs or treated UC as an RC connection");
        }

        // Retransmissions with the same future PSN must agree before an out-of-order Send can be inspected.
        Counters conflictCounters;
        std::vector<Observation> conflicted;
        Engine conflictEngine(conflictCounters, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                conflicted.push_back(std::move(observation));
        });
        for (size_t index = 0; index < 5; ++index)
            conflictEngine.packet(fromHex(fixture["packets"][index]["hex"].get<std::string>()),
                PacketKind::Ethernet, static_cast<int64_t>(index + 1));
        conflictEngine.packet(fromHex(fixture["negative"]["conflicting_future_send"].get<std::string>()),
            PacketKind::Ethernet, 6);
        conflictEngine.expire(7, true);
        require(conflictCounters.malformed == 1 && conflictCounters.activeFlows == 0 &&
            conflictCounters.bufferedBytes == 0 && !conflicted.empty(),
            "Conflicting RoCE future PSNs did not stop and release inspection");
        for (const auto& observation : conflicted)
            require(!evidence(observation).contains("smb_offered_dialects") &&
                !evidence(observation).contains("smb_encrypted_transform_observed"),
                "Conflicting RoCE retransmissions published partially reassembled security evidence");

        // Queue-pair collisions and excessive reorder windows stop inspection without merging security evidence.
        for (const auto& kind : {"colliding_request", "outside_psn_window"})
        {
            Counters rejectedCounters;
            std::vector<Observation> rejected;
            Engine rejectedEngine(rejectedCounters, [&](Observation observation)
            {
                if (!observation.lifecycleOnly)
                    rejected.push_back(std::move(observation));
            });
            for (size_t index = 0; index < 4; ++index)
                rejectedEngine.packet(fromHex(fixture["packets"][index]["hex"].get<std::string>()),
                    PacketKind::Ethernet, static_cast<int64_t>(index + 1));
            rejectedEngine.packet(fromHex(fixture["negative"][kind].get<std::string>()), PacketKind::Ethernet, 5);
            for (size_t index = 4; index < fixture["packets"].size(); ++index)
                rejectedEngine.packet(fromHex(fixture["packets"][index]["hex"].get<std::string>()),
                    PacketKind::Ethernet, static_cast<int64_t>(index + 2));
            rejectedEngine.expire(100, true);
            require(!rejected.empty() && rejectedCounters.bufferedBytes == 0 && rejectedCounters.activeFlows == 0,
                "RoCE collision or excessive reorder state did not stop and expire");
            for (const auto& observation : rejected)
                require(!evidence(observation).contains("smb_offered_dialects") &&
                    !evidence(observation).contains("smb_encrypted_transform_observed"),
                    "RoCE collision or excessive reordering merged unsupported SMB security evidence");
        }

        // Without CM, recognizable Sends remain separate directional observations.
        Counters partialCounters;
        std::vector<Observation> partial;
        Engine partialEngine(partialCounters, [&](Observation observation)
        {
            if (!observation.lifecycleOnly)
                partial.push_back(std::move(observation));
        });
        for (const auto& packet : fixture["packets"])
            if (packet["name"] == "client-direct-negotiate" || packet["name"] == "server-direct-negotiate")
                partialEngine.packet(fromHex(packet["hex"].get<std::string>()), PacketKind::Ethernet, timestamp++);
        require(partial.size() == 2 && partial[0].flowId != partial[1].flowId && partialCounters.activeFlows == 2,
            "RoCE guessed a reverse queue-pair association without captured connection management");
        for (const auto& observation : partial)
        {
            const auto fields = evidence(observation);
            require(fields["roce_connection_management_observed"] == false &&
                fields["roce_queue_pair_pairing"] == "Directional capture" &&
                fields.contains("roce_client_queue_pair") != fields.contains("roce_server_queue_pair"),
                "Directional RoCE evidence claimed both queue pairs or captured connection management");
        }
        partialEngine.expire(timestamp, true);
        require(partialCounters.bufferedBytes == 0 && partialCounters.activeFlows == 0,
            "Directional RoCE inspection did not expire");
    }

    // Concurrent queue pairs and partition domains sharing UDP addresses must retain distinct SMB evidence.
    Counters isolatedCounters;
    std::unordered_map<uint64_t, nlohmann::json> isolated;
    Engine isolatedEngine(isolatedCounters, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            isolated[observation.flowId] = evidence(observation);
    });
    int64_t timestamp = 1;
    for (size_t index = 0; index < fixtures[2]["packets"].size(); ++index)
        for (const size_t fixture : {size_t{2}, size_t{4}, size_t{5}})
            isolatedEngine.packet(fromHex(fixtures[fixture]["packets"][index]["hex"].get<std::string>()),
                PacketKind::Ethernet, timestamp++);
    isolatedEngine.expire(timestamp, true);
    require(isolated.size() == 3 && isolatedCounters.activeFlows == 0 && isolatedCounters.bufferedBytes == 0 &&
        isolatedCounters.malformed == 0 && isolatedCounters.reassemblyLimit == 0,
        "RoCE mixed concurrent queue pairs or partition domains with identical UDP endpoints");
    for (const auto& [id, result] : isolated)
        require(result["smb_encrypted_transform_observed"] == true &&
            result["smb_rdma_signed_payload_observed"] == true, "Concurrent RoCE capture lost SMB protection evidence");

    // RoCEv2 also accepts the IP-only capture format, preserving the wire UDP ports and queue-pair IDs.
    Counters ipCounters;
    std::vector<Observation> ipObservations;
    Engine ipEngine(ipCounters, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            ipObservations.push_back(std::move(observation));
    });
    for (const auto& packet : fixtures[2]["packets"])
    {
        const auto bytes = fromHex(packet["hex"].get<std::string>());
        ipEngine.packet(Bytes(bytes).subspan(14), PacketKind::Ip, timestamp++);
    }
    ipEngine.expire(timestamp, true);
    require(!ipObservations.empty() && evidence(ipObservations.back())["smb_encrypted_transform_observed"] == true &&
        ipCounters.malformed == 0 && ipCounters.bufferedBytes == 0,
        "RoCEv2 rejected IP-only capture or lost its protected SMB framing");

    // Pending CM, TCP, and packet reassembly all share the engine's admission and memory budgets.
    const auto request = fromHex(fixtures[2]["packets"][0]["hex"].get<std::string>());
    const auto second = fromHex(fixtures[4]["packets"][0]["hex"].get<std::string>());
    TcpPacket tcp;
    tcp.source.address[0] = tcp.destination.address[0] = 192;
    tcp.source.address[3] = 1;
    tcp.destination.address[3] = 2;
    tcp.source.port = 40000;
    tcp.destination.port = 443;
    tcp.flags = 2;
    for (const bool tcpFirst : {false, true})
    {
        Counters boundedCounters;
        Engine bounded(boundedCounters, [](Observation) {}, {1, 1048576, 120000000, false});
        if (tcpFirst)
        {
            bounded.tcp(tcp, 1);
            bounded.packet(request, PacketKind::Ethernet, 2);
        }
        else
        {
            bounded.packet(request, PacketKind::Ethernet, 1);
            bounded.packet(second, PacketKind::Ethernet, 2);
            bounded.tcp(tcp, 3);
        }
        require(boundedCounters.activeFlows == 1 && boundedCounters.flowLimit == (tcpFirst ? 1 : 2),
            "RoCE and TCP did not share the capture flow budget");
        bounded.expire(4, true);
        require(boundedCounters.activeFlows == 0 && boundedCounters.bufferedBytes == 0,
            "Bounded RoCE/TCP state did not expire");
    }
    Counters memoryCounters;
    Engine memoryBounded(memoryCounters, [](Observation) {}, {16, 256, 120000000, false});
    memoryBounded.packet(request, PacketKind::Ethernet, 1);
    require(memoryCounters.reassemblyLimit == 1 && memoryCounters.activeFlows == 0 && memoryCounters.bufferedBytes == 0,
        "RoCE admitted pending CM beyond the capture memory budget");

    // Unobserved CM state releases its parsers after the inspection window and expires without an SMB report.
    Counters idleCounters;
    int reports = 0;
    Engine idle(idleCounters, [&](Observation) { ++reports; });
    idle.packet(request, PacketKind::Ethernet, 1);
    const auto before = idleCounters.bufferedBytes.load();
    idle.expire(31000000);
    require(idleCounters.activeFlows == 1 && idleCounters.bufferedBytes > 0 && idleCounters.bufferedBytes < before &&
        reports == 0, "RoCE retained idle cleartext parsers or emitted SMB evidence from CM alone");
    idle.expire(121000000);
    require(idleCounters.activeFlows == 0 && idleCounters.bufferedBytes == 0 && reports == 0,
        "Unobserved RoCE CM did not expire without producing false SMB evidence");
}
}
