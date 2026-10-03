#include "Rdma.h"
#include "Framing.h"
#include "Vpn.h"

#include <algorithm>
#include <format>

namespace Cipherazzi
{
constexpr size_t RdmaInspectionLimit = 262144;

uint32_t rdmaCrc32c(Bytes bytes)
{
    static constexpr auto table = []
    {
        std::array<uint32_t, 256> result{};
        for (uint32_t index = 0; index < result.size(); ++index)
        {
            auto value = index;
            for (int bit = 0; bit < 8; ++bit)
                value = (value >> 1) ^ ((value & 1) ? 0x82f63b78u : 0);
            result[index] = value;
        }
        return result;
    }();
    uint32_t result = 0xffffffffu;
    for (const auto byte : bytes)
        result = table[(result ^ byte) & 255] ^ (result >> 8);
    return ~result;
}

bool SmbDirectStream::feed(Bytes message, const Sink& sink)
{
    if (finished_)
        return true;
    auto word = [&](size_t offset)
    {
        return static_cast<uint16_t>(message[offset] | (message[offset + 1] << 8));
    };
    auto number = [&](size_t offset)
    {
        return word(offset) | (static_cast<uint32_t>(word(offset + 2)) << 16);
    };

    // SMB Direct's first Send exchanges transport limits rather than SMB security capabilities.
    if (!started_ && (message.size() == 20 || message.size() == 32) &&
        word(0) == 0x0100 && word(2) == 0x0100)
    {
        const bool response = message.size() == 32;
        const size_t offset = response ? 20 : 8;
        const auto status = response ? number(12) : 0;
        if (!status && (!number(offset) || !number(offset + 4) || !number(offset + 8)))
            return false;
        nlohmann::json fields;
        auto& negotiation = fields[response ? "smb_direct_server_negotiation" : "smb_direct_client_negotiation"];
        negotiation = {{"minimum_version", hex16(word(0))}, {"maximum_version", hex16(word(2))},
            {"preferred_send_size", number(offset)}, {"maximum_receive_size", number(offset + 4)},
            {"maximum_fragmented_size", number(offset + 8)}};
        if (response)
        {
            negotiation["selected_version"] = hex16(word(4));
            negotiation["status"] = status;
            negotiation["maximum_read_write_size"] = number(16);
            if (!status && word(4) != 0x0100)
                return false;
            finished_ = status != 0;
        }
        fields["smb_transport_framing"] = "SMB Direct / RDMA";
        started_ = true;
        return sink(fields);
    }

    // Reassemble only Send payloads; RDMA Read/Write file data is not retained or interpreted.
    if (message.size() < 20 || (word(4) & ~1u) || word(6))
        return false;
    const size_t offset = number(12), length = number(16);
    const auto remaining = number(8);
    if (!length)
        return message.size() == 20 && !remaining && !offset;
    if (offset < 24 || offset % 8 || offset > message.size() || length != message.size() - offset ||
        std::any_of(message.begin() + 20, message.begin() + offset, [](uint8_t value) { return value != 0; }) ||
        (!buffer_.empty() && (length > remaining_ || remaining != remaining_ - length)))
        return false;
    if (length > RdmaInspectionLimit - buffer_.size() || remaining > RdmaInspectionLimit - buffer_.size() - length)
    {
        limited_ = true;
        return false;
    }
    buffer_.insert(buffer_.end(), message.begin() + offset, message.end());
    remaining_ = remaining;
    started_ = true;
    if (remaining)
        return true;
    nlohmann::json fields;
    if (!parseSmb(buffer_, fields, limited_))
        return false;
    fields["smb_transport_framing"] = "SMB Direct / RDMA";
    const bool valid = sink(fields);
    finished_ = fields.value("smb_encrypted_transform_observed", false);
    std::vector<uint8_t>().swap(buffer_);
    return valid;
}

void IwarpStream::configurePeer(uint8_t flags)
{
    markers_ = (flags & 0x80) != 0;
    crc_ = ((flags | flags_.value_or(0)) & 0x40) != 0;
    ready_ = flags_.has_value();
}

bool IwarpStream::feed(Bytes bytes, const SmbDirectStream::Sink& sink)
{
    if (finished())
        return true;
    if (bytes.size() > RdmaInspectionLimit - buffer_.size())
    {
        limited_ = true;
        return false;
    }
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());

    // MPA startup advertises the peer's outgoing marker format and both endpoints' CRC requirements.
    if (!flags_)
    {
        if (buffer_.size() < 20)
            return true;
        const std::string_view key(reinterpret_cast<const char*>(buffer_.data()), 16);
        const size_t length = be16(buffer_, 18);
        if ((key != "MPA ID Req Frame" && key != "MPA ID Rep Frame") || !buffer_[17] ||
            buffer_[17] > 2 || length > 512 || ((buffer_[16] & 0x10) && length < 4))
            return false;
        if (buffer_.size() < 20 + length)
            return true;
        flags_ = buffer_[16];
        if (key == "MPA ID Rep Frame" && (*flags_ & 0x20))
        {
            finished_ = true;
            std::vector<uint8_t>().swap(buffer_);
            return true;
        }
        buffer_.erase(buffer_.begin(), buffer_.begin() + 20 + length);
    }
    if (!ready_)
        return true;

    // Remove fixed-interval MPA markers only after validating each complete wire frame and its CRC.
    size_t consumed = 0;
    while (buffer_.size() - consumed >= 2)
    {
        const auto pending = Bytes(buffer_).subspan(consumed);
        const size_t prefix = markers_ && wireOffset_ % 512 == 0 ? 4 : 0;
        if (pending.size() < prefix + 2)
            break;
        const size_t length = be16(pending, prefix);
        if (length < 2)
            return false;
        const size_t logicalLength = ((length + 5) & ~size_t{3}) + 4;
        size_t wireLength = prefix, logical = 0;
        while (logical < logicalLength)
        {
            if (markers_ && (wireOffset_ + wireLength) % 512 == 0)
                wireLength += 4;
            const size_t count = markers_ ?
                std::min(logicalLength - logical, 512 - (wireOffset_ + wireLength) % 512) :
                logicalLength - logical;
            logical += count;
            wireLength += count;
        }
        if (pending.size() < wireLength)
            break;
        const auto checksum = pending.subspan(wireLength - 4, 4);
        const auto expected = static_cast<uint32_t>(checksum[0]) | (static_cast<uint32_t>(checksum[1]) << 8) |
            (static_cast<uint32_t>(checksum[2]) << 16) | (static_cast<uint32_t>(checksum[3]) << 24);
        if (crc_ && rdmaCrc32c(pending.first(wireLength - 4)) != expected)
            return false;
        std::vector<uint8_t> clean;
        clean.reserve(logicalLength);
        size_t position = 0;
        const size_t start = wireOffset_ + prefix;
        while (position < wireLength)
        {
            if (markers_ && (wireOffset_ + position) % 512 == 0)
            {
                const auto pointer = be16(pending, position + 2) & ~3u;
                const auto distance = position == 0 ? 0 : wireOffset_ + position - start;
                if (pointer != distance)
                    return false;
                position += 4;
            }
            const size_t count = markers_ ?
                std::min(wireLength - position, 512 - (wireOffset_ + position) % 512) : wireLength - position;
            clean.insert(clean.end(), pending.begin() + position, pending.begin() + position + count);
            position += count;
        }
        const auto segment = Bytes(clean).subspan(2, length);
        const bool tagged = (segment[0] & 0x80) != 0;
        const auto opcode = segment[1] & 15;
        if ((segment[0] & 3) != 1 || segment[1] >> 6 != 1 ||
            segment.size() < (tagged ? 14u : 18u) || (tagged ? opcode != 0 && opcode != 2 : opcode < 1 || opcode > 7))
            return false;
        consumed += wireLength;
        wireOffset_ += wireLength;
        if (tagged || opcode == 1)
            continue;
        if (opcode == 7)
        {
            finished_ = true;
            break;
        }
        if (be32(segment, 6))
            return false;

        // DDP offsets permit reordered segments within an ordered Send message; overlapping bytes must agree.
        const auto sequence = be32(segment, 10);
        const size_t offset = be32(segment, 14), size = segment.size() - 18;
        if (offset > RdmaInspectionLimit || size > RdmaInspectionLimit - offset)
        {
            limited_ = true;
            return false;
        }
        if (!assembling_)
        {
            assembling_ = true;
            sequence_ = sequence;
            opcode_ = static_cast<uint8_t>(opcode);
        }
        if (sequence != sequence_ || opcode != opcode_ || (last_ && offset + size > lastSize_))
            return false;
        if (segment[0] & 0x40)
        {
            if ((last_ && lastSize_ != offset + size) || offset + size < message_.size())
                return false;
            last_ = true;
            lastSize_ = offset + size;
        }
        message_.resize(std::max(message_.size(), offset + size));
        present_.resize(message_.size());
        for (size_t index = 0; index < size; ++index)
        {
            const auto byte = segment[index + 18];
            if (present_[offset + index] && message_[offset + index] != byte)
                return false;
            filled_ += !present_[offset + index];
            present_[offset + index] = 1;
            message_[offset + index] = byte;
        }
        if (!last_ || filled_ != lastSize_)
            continue;
        if (!message_.empty() && !direct_.feed(message_, [&](const nlohmann::json& fields)
        {
            auto evidence = fields;
            evidence["smb_transport_framing"] = "SMB Direct / iWARP";
            evidence["smb_iwarp_markers"] = markers_;
            evidence["smb_iwarp_crc_checked"] = crc_;
            return sink(evidence);
        }))
            return false;
        std::vector<uint8_t>().swap(message_);
        std::vector<uint8_t>().swap(present_);
        assembling_ = last_ = false;
        filled_ = lastSize_ = 0;
        if (finished())
            break;
    }
    if (finished())
    {
        std::vector<uint8_t>().swap(buffer_);
        std::vector<uint8_t>().swap(message_);
        std::vector<uint8_t>().swap(present_);
    }
    else
        buffer_.erase(buffer_.begin(), buffer_.begin() + consumed);
    return true;
}

uint32_t roceCrc(uint32_t crc, Bytes bytes)
{
    static constexpr auto table = []
    {
        std::array<uint32_t, 256> result{};
        for (uint32_t index = 0; index < result.size(); ++index)
        {
            auto value = index;
            for (int bit = 0; bit < 8; ++bit)
                value = (value >> 1) ^ ((value & 1) ? 0xedb88320u : 0);
            result[index] = value;
        }
        return result;
    }();
    for (const auto byte : bytes)
        crc = table[(crc ^ byte) & 255] ^ (crc >> 8);
    return crc;
}

size_t RoceConnections::pathHash(const Path& path)
{
    auto hash = FlowHash{}(path.hosts);
    for (const auto vlan : path.vlans)
        hash = (hash * 1099511628211ULL) ^ vlan;
    return (hash * 1099511628211ULL) ^ (path.partition | (static_cast<size_t>(path.version) << 16));
}

size_t RoceConnections::Hash::operator()(const Key& key) const
{
    return pathHash(key.path) ^ (static_cast<size_t>(key.id) << 2) ^ static_cast<size_t>(key.fromB) ^
        (key.unilateral ? 2 : 0);
}

size_t RoceConnections::Hash::operator()(const Channel& key) const
{
    return pathHash(key.path) ^ (static_cast<size_t>(key.qp) << 1) ^ static_cast<size_t>(key.receiverB);
}

bool RoceConnections::decode(Bytes bytes, bool ethernet, Packet& packet, bool& valid)
{
    // Preserve VLAN and partition domains while recognizing Ethernet RoCE and UDP-encapsulated RoCE.
    valid = false;
    uint16_t type = 0;
    if (ethernet)
    {
        if (bytes.size() < 14)
            return false;
        type = be16(bytes, 12);
        bytes = bytes.subspan(14);
        for (int index = 0; index < 2 && (type == 0x8100 || type == 0x88a8); ++index)
        {
            if (bytes.size() < 4)
                return false;
            packet.path.vlans[index] = be16(bytes, 0) & 0x0fff;
            type = be16(bytes, 2);
            bytes = bytes.subspan(4);
        }
        if (type != 0x8915 && type != 0x0800 && type != 0x86dd)
            return false;
    }
    const bool v1 = type == 0x8915;
    auto malformed = [&] { ++counters_.malformed; return true; };
    auto truncated = [&] { ++counters_.truncated; return true; };
    const auto family = bytes.empty() ? 0 : bytes[0] >> 4;
    size_t header = family == 4 ? 20 : 40;
    size_t total = 0;
    if (v1 && (bytes.size() < 40 || family != 6 || bytes[6] != 27))
        return malformed();
    if (!v1)
    {
        if ((family != 4 && family != 6) || bytes.size() < header ||
            bytes[family == 4 ? 9 : 6] != 17 || (family == 4 && (be16(bytes, 6) & 0x3fff)))
            return false;
        if (family == 4)
            header = (bytes[0] & 15) * 4;
        if (header < 20 || header + 8 > bytes.size() || be16(bytes, header + 2) != 4791)
            return false;
        if (header + 24 > bytes.size())
            return false;
        const auto probe = bytes.subspan(header + 8);
        if ((probe[0] > 0x65 && probe[0] != 0x81) || (probe[1] & 15) || (probe[4] & 0x3f) ||
            (probe[8] & 0x7f) || !(be16(probe, 2) & 0x7fff))
            return false;
        if ((family == 4 && header != 20) || !be16(bytes, family == 4 ? 2 : 4))
        {
            ++counters_.unsupported;
            return true;
        }
    }
    packet.path.version = v1 ? 1 : 2;
    if (family == 4)
    {
        total = be16(bytes, 2);
        std::copy_n(bytes.begin() + 12, 4, packet.source.address.begin());
        std::copy_n(bytes.begin() + 16, 4, packet.destination.address.begin());
    }
    else
    {
        total = 40u + be16(bytes, 4);
        packet.source.family = packet.destination.family = 6;
        std::copy_n(bytes.begin() + 8, 16, packet.source.address.begin());
        std::copy_n(bytes.begin() + 24, 16, packet.destination.address.begin());
    }
    if (total < header + (v1 ? 16 : 24))
        return malformed();
    if (total > bytes.size())
        return truncated();
    bytes = bytes.first(total);
    if (!v1)
    {
        if (be16(bytes, header + 4) != total - header)
            return malformed();
        packet.source.port = be16(bytes, header);
        packet.destination.port = 4791;
        header += 8;
    }
    auto source = packet.source, destination = packet.destination;
    source.port = destination.port = 0;
    packet.path.hosts = FlowKey::make(source, destination);
    const auto bth = bytes.subspan(header);
    const size_t padding = (bth[1] >> 4) & 3;
    if ((bth.size() % 4) || (bth[1] & 15) || (bth[4] & 0x3f) || (bth[8] & 0x7f) ||
        padding > bth.size() - 16)
        return malformed();

    // The invariant CRC masks mutable network fields and the BTH's congestion/reserved byte.
    std::array<uint8_t, 60> invariant{};
    std::copy_n(bytes.begin(), header + 12, invariant.begin());
    if (family == 4)
    {
        invariant[1] = invariant[8] = invariant[10] = invariant[11] = 0xff;
    }
    else
    {
        invariant[0] |= 15;
        invariant[1] = invariant[2] = invariant[3] = invariant[7] = 0xff;
    }
    if (!v1)
        invariant[header - 2] = invariant[header - 1] = 0xff;
    invariant[header + 4] = 0xff;
    auto crc = roceCrc(0xdebb20e3u, Bytes(invariant).first(header + 12));
    crc = ~roceCrc(crc, bth.subspan(12, bth.size() - 16));
    const auto tail = bth.last(4);
    const uint32_t expected = tail[0] | (static_cast<uint32_t>(tail[1]) << 8) |
        (static_cast<uint32_t>(tail[2]) << 16) | (static_cast<uint32_t>(tail[3]) << 24);
    if (crc != expected)
        return malformed();
    packet.opcode = bth[0];
    packet.path.partition = be16(bth, 2) & 0x7fff;
    packet.qp = be32(bth, 4) & 0xffffff;
    packet.psn = be32(bth, 8) & 0xffffff;
    packet.send = packet.opcode <= 5 || packet.opcode == 0x16 || packet.opcode == 0x17;
    packet.request = packet.send || packet.opcode <= 0x0c || packet.opcode == 0x13 || packet.opcode == 0x14;

    // Strip opcode-specific headers before inspecting Sends; Read/Write buffers remain opaque.
    size_t transportHeader = 12;
    switch (packet.opcode)
    {
    case 0: case 1: case 2: case 4: case 7: case 8: case 0x0e:
        break;
    case 3: case 5: case 9: case 0x0d: case 0x0f: case 0x10: case 0x11: case 0x16: case 0x17:
        transportHeader = 16;
        break;
    case 6: case 0x0a: case 0x0c:
        transportHeader = 28;
        break;
    case 0x0b:
        transportHeader = 32;
        break;
    case 0x12:
        transportHeader = 24;
        break;
    case 0x13: case 0x14:
        transportHeader = 40;
        break;
    case 0x64:
        transportHeader = 20;
        packet.request = false;
        break;
    default:
        ++counters_.unsupported;
        return true;
    }
    if (!packet.path.partition || !packet.qp || transportHeader + padding + 4 > bth.size())
        return malformed();
    packet.payload = bth.subspan(transportHeader, bth.size() - transportHeader - padding - 4);
    packet.fingerprint = packet.send ? ~roceCrc(0xffffffffu, bth.subspan(12, bth.size() - 16)) : packet.opcode;
    if (packet.opcode == 0x0c)
    {
        packet.readLength = be32(bth, 24);
        packet.fingerprint ^= packet.readLength;
    }
    if (packet.opcode == 0x64 &&
        (packet.qp != 1 || be32(bth, 12) != 0x80010000 || be32(bth, 16) != 1))
        return true;
    valid = true;
    return true;
}

bool RoceConnections::Stream::begin(uint32_t psn, uint32_t packetMtu)
{
    if (initialized)
    {
        if (first != psn || (mtu && packetMtu && mtu != packetMtu))
            return false;
        if (packetMtu)
            mtu = packetMtu;
        return true;
    }
    initialized = true;
    first = next = psn;
    mtu = packetMtu;
    return true;
}

size_t RoceConnections::Stream::memory() const
{
    size_t result = message.capacity() + direct.memory() + pending.capacity() * sizeof(Piece);
    for (const auto& piece : pending)
        result += piece.payload.capacity();
    return result;
}

bool RoceConnections::Stream::consume(const Piece& piece, const SmbDirectStream::Sink& sink)
{
    const bool send = piece.opcode <= 5 || piece.opcode == 0x16 || piece.opcode == 0x17;
    if (!send)
        return !assembling;
    const bool start = piece.opcode == 0 || piece.opcode == 4 || piece.opcode == 5 || piece.opcode == 0x17;
    const bool end = piece.opcode != 0 && piece.opcode != 1;
    if (start == assembling)
        return false;
    if (piece.payload.size() > RdmaInspectionLimit - message.size())
    {
        limited = true;
        return false;
    }
    assembling = true;
    message.insert(message.end(), piece.payload.begin(), piece.payload.end());
    if (!end)
        return true;
    const bool valid = direct.feed(message, sink);
    std::vector<uint8_t>().swap(message);
    assembling = false;
    return valid;
}

bool RoceConnections::Stream::feed(const Packet& packet, const SmbDirectStream::Sink& sink)
{
    if (!packet.request || direct.finished())
        return true;
    if (!initialized)
    {
        if (!packet.send || (packet.opcode != 0 && packet.opcode != 4 && packet.opcode != 5 && packet.opcode != 0x17))
            return true;
        begin(packet.psn, 0);
    }
    int32_t distance = static_cast<int32_t>((packet.psn - next) & 0xffffff);
    if (distance & 0x800000)
        distance -= 0x1000000;
    if (distance < 0)
    {
        for (size_t index = 0; index < std::min(historyCount, history.size()); ++index)
            if (history[index].psn == packet.psn)
                return history[index].fingerprint == packet.fingerprint;
        return true;
    }
    uint32_t advance = 1;
    if (packet.opcode == 0x0c)
    {
        // Read requests reserve response PSNs; ACK and Read responses belong to the opposite request sequence.
        if (!mtu)
            return false;
        advance = static_cast<uint32_t>(std::max(uint64_t{1}, (uint64_t{packet.readLength} + mtu - 1) / mtu));
        if (advance >= 0x800000)
        {
            limited = true;
            return false;
        }
    }
    if (distance > 0)
    {
        const auto existing = std::ranges::find(pending, packet.psn, &Piece::psn);
        if (existing != pending.end())
            return existing->opcode == packet.opcode && existing->advance == advance &&
                existing->fingerprint == packet.fingerprint;
        if (distance > 4096 || pending.size() >= 64 ||
            (packet.send && packet.payload.size() > RdmaInspectionLimit - std::min(memory(), RdmaInspectionLimit)))
        {
            limited = true;
            return false;
        }
        Piece piece{packet.psn, packet.fingerprint, advance, packet.opcode};
        if (packet.send)
            piece.payload.assign(packet.payload.begin(), packet.payload.end());
        pending.push_back(std::move(piece));
        return true;
    }
    Piece piece{packet.psn, packet.fingerprint, advance, packet.opcode};
    if (packet.send)
        piece.payload.assign(packet.payload.begin(), packet.payload.end());

    // Deliver consecutive request packets once, including sequence-number wrap and bounded reordering.
    for (;;)
    {
        if (!consume(piece, sink))
            return false;
        history[historyCount++ % history.size()] = {piece.psn, piece.fingerprint};
        next = (next + piece.advance) & 0xffffff;
        if (direct.finished())
        {
            std::vector<Piece>().swap(pending);
            return true;
        }
        const auto found = std::ranges::find(pending, next, &Piece::psn);
        if (found == pending.end())
            return true;
        piece = std::move(*found);
        pending.erase(found);
    }
}

size_t RoceConnections::Connection::memory() const
{
    return sizeof(*this) - sizeof(observation) + 512 + observation.memory() +
        (streams ? sizeof(*streams) + (*streams)[0].memory() + (*streams)[1].memory() : 0);
}

void RoceConnections::remove(Connections::iterator found, std::string_view reason, const Sink& sink)
{
    auto& connection = *found->second;
    if (connection.observed)
    {
        Observation update;
        update.flowId = connection.observation.flowId;
        update.lifecycleOnly = true;
        update.endedUs = connection.lastUs;
        update.closeReason = reason;
        sink(std::move(update));
    }
    for (int receiver = 0; receiver < 2; ++receiver)
    {
        auto address = connection.endpoints[receiver];
        address.port = 0;
        const auto channel = channels_.find({connection.key.path, connection.qps[receiver],
            address == connection.key.path.hosts.b});
        if (channel != channels_.end() && channel->second.connection == &connection)
            channels_.erase(channel);
    }
    bytes_ -= connection.memory();
    connections_.erase(found);
}

bool RoceConnections::index(Connection& connection, int receiver, const Sink& sink)
{
    auto address = connection.endpoints[receiver];
    address.port = 0;
    const Channel key{connection.key.path, connection.qps[receiver], address == connection.key.path.hosts.b};
    auto found = channels_.find(key);
    if (found != channels_.end() && found->second.connection != &connection &&
        found->second.connection->key.unilateral && !connection.key.unilateral)
    {
        remove(connections_.find(found->second.connection->key),
            "RDMA connection management observed; directional inspection ended", sink);
        found = channels_.end();
    }
    if (found == channels_.end())
    {
        channels_.emplace(key, Owner{&connection, 1 - receiver});
        return true;
    }
    if (found->second.connection == &connection && found->second.direction == 1 - receiver)
        return true;

    // Keep colliding queue pairs quarantined until their connections expire; do not choose an owner by IP address.
    for (auto* candidate : {found->second.connection, &connection})
    {
        const auto before = candidate->memory();
        candidate->blocked = true;
        candidate->streams.reset();
        if (candidate->observed)
        {
            candidate->observation.detail = "Ambiguous RDMA queue-pair reuse; inspection ended";
            sink(candidate->observation);
        }
        bytes_ = bytes_ - before + candidate->memory();
        if (found->second.connection == &connection)
            break;
    }
    return false;
}

bool RoceConnections::update(Connection& connection, const nlohmann::json& fields, size_t budget, const Sink& sink)
{
    if (fields.empty() && !connection.observation.application)
        return true;
    auto evidence = std::make_shared<VpnEvidence>();
    if (connection.observation.application)
        evidence->fields = connection.observation.application->fields;
    else
        evidence->fields = nlohmann::json::object();
    evidence->fields.update(fields);
    const auto transport = connection.key.path.version == 1 ? "RoCEv1" : "RoCEv2";
    evidence->fields["transport"] = transport;
    evidence->fields["smb_transport_framing"] = std::string("SMB Direct / ") + transport;
    evidence->fields["roce_invariant_crc_checked"] = true;
    evidence->fields["roce_partition_key"] = hex16(connection.key.path.partition);
    if (connection.key.path.vlans[0] != 0xffff)
    {
        evidence->fields["roce_vlan_ids"] = nlohmann::json::array();
        for (const auto vlan : connection.key.path.vlans)
            if (vlan != 0xffff)
                evidence->fields["roce_vlan_ids"].push_back(vlan);
    }
    evidence->fields["roce_connection_management_observed"] = !connection.key.unilateral;
    evidence->fields["roce_connection_response_observed"] = connection.response;
    evidence->fields["roce_ready_observed"] = connection.ready;
    evidence->fields["roce_disconnect_request_observed"] = connection.disconnect;
    const auto client = connection.clientDirection < 0 ? 0 : connection.clientDirection;
    evidence->fields["roce_roles_known"] = connection.clientDirection >= 0;
    evidence->fields["roce_queue_pair_pairing"] = connection.key.unilateral ?
        "Directional capture" : "Connection management";
    if (connection.clientDirection >= 0)
        for (const auto name : {"roce_source_queue_pair", "roce_destination_queue_pair", "roce_source_udp_port",
            "roce_destination_udp_port"})
            evidence->fields.erase(name);
    if (connection.key.path.version == 2)
    {
        evidence->fields["roce_udp_destination_port"] = 4791;
        if (connection.sendPorts[client])
            evidence->fields[connection.clientDirection < 0 ? "roce_source_udp_port" :
                "roce_client_udp_source_port"] = connection.sendPorts[client];
        if (connection.sendPorts[1 - client])
            evidence->fields[connection.clientDirection < 0 ? "roce_destination_udp_port" :
                "roce_server_udp_source_port"] = connection.sendPorts[1 - client];
    }
    if (connection.qps[client])
        evidence->fields[connection.clientDirection < 0 ? "roce_source_queue_pair" : "roce_client_queue_pair"] =
            connection.qps[client];
    if (connection.qps[1 - client])
        evidence->fields[connection.clientDirection < 0 ? "roce_destination_queue_pair" : "roce_server_queue_pair"] =
            connection.qps[1 - client];
    if (!connection.key.unilateral)
    {
        evidence->fields["roce_service_id"] = std::format("0x{:016X}", connection.service);
        evidence->fields["roce_client_communication_id"] = connection.key.id;
        if (connection.response)
            evidence->fields["roce_server_communication_id"] = connection.remoteId;
    }
    if (connection.observation.application && connection.observation.application->fields == evidence->fields)
        return true;
    evidence->retainedBytes = evidence->fields.dump().size() * 3 + 1024;
    const auto previous = connection.observation.application;
    const auto before = connection.memory();
    connection.observation.application = evidence;
    if (bytes_ - before + connection.memory() > budget)
    {
        connection.observation.application = previous;
        return false;
    }
    connection.observation.protocol = Observation::Protocol::Smb;
    connection.observation.source = connection.endpoints[client];
    connection.observation.destination = connection.endpoints[1 - client];
    connection.observed = true;
    bytes_ = bytes_ - before + connection.memory();
    sink(connection.observation);
    return true;
}

bool RoceConnections::feed(Bytes bytes, bool ethernet, int64_t timestampUs, uint64_t& nextId, size_t budget,
    size_t limit, const Sink& sink)
{
    Packet packet;
    bool valid;
    if (!decode(bytes, ethernet, packet, valid))
        return false;
    if (!valid)
        return true;
    auto source = packet.source, destination = packet.destination;
    source.port = destination.port = 0;
    const bool sourceB = source == packet.path.hosts.b, destinationB = destination == packet.path.hosts.b;

    // Admit both pending CM and recognizable directional captures within the shared engine budgets.
    auto create = [&](const Key& key, uint32_t localQp, uint32_t psn, uint32_t mtu, uint64_t service)
        -> Connections::iterator
    {
        if (connections_.size() >= limit)
        {
            ++counters_.flowLimit;
            return connections_.end();
        }
        auto connection = std::make_unique<Connection>();
        connection->key = key;
        connection->endpoints[0] = source;
        connection->endpoints[1] = destination;
        connection->qps[key.unilateral ? 1 : 0] = localQp;
        connection->starts[0] = psn;
        connection->mtu = mtu;
        connection->service = service;
        connection->lastUs = timestampUs;
        connection->clientDirection = key.unilateral ? -1 : 0;
        connection->observation.firstUs = connection->observation.lastUs = timestampUs;
        connection->observation.udp = packet.path.version == 2;

        // CM advertises the local receive sequence; a directional capture supplies its observed send sequence.
        connection->streams = std::make_unique<std::array<Stream, 2>>();
        (*connection->streams)[key.unilateral ? 0 : 1].begin(psn, mtu);
        if (bytes_ + connection->memory() > budget)
        {
            ++counters_.reassemblyLimit;
            return connections_.end();
        }
        connection->observation.flowId = ++nextId;
        bytes_ += connection->memory();
        return connections_.emplace(key, std::move(connection)).first;
    };
    auto boundedUpdate = [&](Connections::iterator found, const nlohmann::json& fields)
    {
        if (update(*found->second, fields, budget, sink))
            return;
        ++counters_.reassemblyLimit;
        remove(found, "RDMA inspection memory limit reached; outcome unknown", sink);
    };

    // Connection-management IDs and advertised GIDs establish the bidirectional queue-pair association.
    if (packet.opcode == 0x64)
    {
        const auto mad = packet.payload;
        if (mad.size() < 24 || mad[1] != 7)
            return true;
        if (mad.size() != 256 || mad[0] != 1 || mad[2] != 2 || mad[3] != 3 || be16(mad, 4))
        {
            ++counters_.malformed;
            return true;
        }
        const auto body = mad.subspan(24);
        const auto attribute = be16(mad, 16);
        if (attribute == 0x10)
        {
            const auto local = be32(body, 0), qp = be32(body, 32) >> 8, psn = be32(body, 44) >> 8;
            const auto mtuCode = body[50] >> 4;
            const uint64_t service = (static_cast<uint64_t>(be32(body, 8)) << 32) | be32(body, 12);
            auto gid = [&](size_t offset)
            {
                Endpoint value;
                const auto bytes = body.subspan(offset, 16);
                if (packet.path.version == 2 && packet.source.family == 4 &&
                    std::all_of(bytes.begin(), bytes.begin() + 10, [](uint8_t byte) { return byte == 0; }) &&
                    bytes[10] == 0xff && bytes[11] == 0xff)
                    std::copy_n(bytes.begin() + 12, 4, value.address.begin());
                else
                {
                    value.family = 6;
                    std::copy(bytes.begin(), bytes.end(), value.address.begin());
                }
                return value;
            };
            if ((body[43] >> 1) & 3)
            {
                ++counters_.unsupported;
                return true;
            }
            if (!local || qp <= 1 || mtuCode < 1 || mtuCode > 5 ||
                (be16(body, 48) & 0x7fff) != packet.path.partition || gid(56) != source || gid(72) != destination)
            {
                ++counters_.malformed;
                return true;
            }
            const uint32_t mtu = 128u << mtuCode;
            const Key key{packet.path, local, sourceB, false};
            auto found = connections_.find(key);
            if (found != connections_.end() && (found->second->qps[0] != qp || found->second->starts[0] != psn ||
                found->second->service != service || found->second->mtu != mtu))
            {
                remove(found, "RDMA communication ID reused; inspection ended", sink);
                found = connections_.end();
            }
            if (found == connections_.end())
                found = create(key, qp, psn, mtu, service);
            if (found == connections_.end())
                return true;
            auto& connection = *found->second;
            connection.lastUs = connection.observation.lastUs = timestampUs;
            if (!connection.blocked && index(connection, 0, sink))
                boundedUpdate(found, nlohmann::json::object());
            return true;
        }
        if (attribute == 0x13)
        {
            const auto local = be32(body, 0), remote = be32(body, 4), qp = be32(body, 12) >> 8;
            const auto psn = be32(body, 20) >> 8;
            const auto found = connections_.find({packet.path, remote, destinationB, false});
            if (found == connections_.end())
                return true;
            auto& connection = *found->second;
            if (!local || qp <= 1 || (connection.response &&
                (connection.remoteId != local || connection.qps[1] != qp || connection.starts[1] != psn)))
            {
                ++counters_.malformed;
                return true;
            }
            connection.lastUs = connection.observation.lastUs = timestampUs;
            connection.remoteId = local;
            connection.qps[1] = qp;
            connection.starts[1] = psn;
            connection.response = true;
            if (!index(connection, 1, sink) || connection.blocked)
                return true;
            if (connection.streams && !(*connection.streams)[0].begin(psn, connection.mtu))
            {
                const auto before = connection.memory();
                connection.streams.reset();
                connection.observation.detail = "RDMA startup sequence not fully captured; inspection ended";
                bytes_ = bytes_ - before + connection.memory();
                ++counters_.reassemblyLimit;
            }
            boundedUpdate(found, nlohmann::json::object());
            return true;
        }
        if (attribute != 0x12 && attribute != 0x14 && attribute != 0x15 && attribute != 0x16)
            return true;
        auto found = connections_.find({packet.path, be32(body, 0), sourceB, false});
        int direction = 0;
        if (found == connections_.end() || !found->second->response || found->second->remoteId != be32(body, 4))
        {
            found = connections_.find({packet.path, be32(body, 4), destinationB, false});
            if (found == connections_.end() ||
                (attribute != 0x12 && (!found->second->response || found->second->remoteId != be32(body, 0))))
                return true;
            direction = 1;
        }
        auto& connection = *found->second;
        connection.lastUs = connection.observation.lastUs = timestampUs;
        if (attribute == 0x12 || attribute == 0x16)
        {
            remove(found, attribute == 0x12 ? "RDMA connection rejected" :
                connection.disconnect ? "RDMA disconnect exchange observed" : "RDMA disconnect reply observed", sink);
            return true;
        }
        if (attribute == 0x15)
        {
            if ((be32(body, 8) >> 8) != connection.qps[1 - direction])
            {
                ++counters_.malformed;
                return true;
            }
            connection.disconnect = true;
        }
        else
            connection.ready = true;
        boundedUpdate(found, nlohmann::json::object());
        return true;
    }

    // A capture without CM may identify one direction, but reverse queue pairs are never guessed from UDP ports.
    const Channel channel{packet.path, packet.qp, destinationB};
    auto owner = channels_.find(channel);
    if (owner == channels_.end())
    {
        if (!packet.send || (packet.opcode != 0 && packet.opcode != 4 && packet.opcode != 5 && packet.opcode != 0x17))
            return true;
        const auto data = packet.payload;
        auto number = [&](size_t offset)
        {
            return data[offset] | (static_cast<uint32_t>(data[offset + 1]) << 8) |
                (static_cast<uint32_t>(data[offset + 2]) << 16) | (static_cast<uint32_t>(data[offset + 3]) << 24);
        };
        const size_t offset = data.size() >= 24 ? number(12) : 0;
        const bool negotiation = (data.size() == 20 || data.size() == 32) &&
            data[0] == 0 && data[1] == 1 && data[2] == 0 && data[3] == 1;
        const bool message = data.size() >= 28 && offset >= 24 && offset % 8 == 0 && offset <= data.size() - 4 &&
            (data[offset] == 0xfe || data[offset] == 0xfd || data[offset] == 0xfc) &&
            data[offset + 1] == 'S' && data[offset + 2] == 'M' && data[offset + 3] == 'B';
        if (!negotiation && !message)
            return true;
        const Key key{packet.path, packet.qp, sourceB, true};
        auto found = connections_.find(key);
        if (found == connections_.end())
            found = create(key, packet.qp, packet.psn, 0, 0);
        if (found == connections_.end() || !index(*found->second, 1, sink))
            return true;
        owner = channels_.find(channel);
    }
    auto& connection = *owner->second.connection;
    connection.lastUs = connection.observation.lastUs = timestampUs;
    if (connection.blocked || !connection.streams || !packet.request)
        return true;

    // Reassemble both RDMA and SMB Direct framing before merging public protocol evidence.
    const auto before = connection.memory();
    const int direction = owner->second.direction;
    if (!connection.portsKnown)
    {
        connection.endpoints[direction] = packet.source;
        connection.endpoints[1 - direction] = packet.destination;
        connection.portsKnown = true;
    }
    if (!connection.sendPorts[direction])
        connection.sendPorts[direction] = packet.source.port;
    nlohmann::json fields = nlohmann::json::object();
    auto& stream = (*connection.streams)[direction];
    valid = stream.feed(packet, [&](const nlohmann::json& observed)
    {
        const bool clientNegotiation = observed.contains("smb_direct_client_negotiation") ||
            observed.contains("smb_offered_dialects") || observed.contains("smb_rdma_write_transform");
        const bool serverNegotiation = observed.contains("smb_direct_server_negotiation") ||
            observed.contains("smb_selected_dialect") || observed.contains("smb_rdma_read_transform");
        if (clientNegotiation || serverNegotiation)
        {
            const int client = clientNegotiation ? direction : 1 - direction;
            if (connection.clientDirection >= 0 && connection.clientDirection != client)
                return false;
            connection.clientDirection = client;
        }
        fields.update(observed);
        return true;
    });
    const bool limited = stream.limited || stream.direct.limited();
    if (!valid || bytes_ - before + connection.memory() > budget)
    {
        connection.streams.reset();
        connection.blocked = true;
        if (limited || valid)
            ++counters_.reassemblyLimit;
        else if (connection.observed)
            ++counters_.malformed;
        else
            ++counters_.unsupported;
        if (connection.observed)
        {
            connection.observation.detail = limited || valid ? "RDMA reassembly or inspection limit reached" :
                "Malformed or conflicting RDMA framing; inspection ended";
            sink(connection.observation);
        }
        bytes_ = bytes_ - before + connection.memory();
        return true;
    }
    if (stream.direct.finished())
        connection.streams.reset();
    bytes_ = bytes_ - before + connection.memory();
    const auto found = connections_.find(connection.key);
    boundedUpdate(found, fields);
    return true;
}

void RoceConnections::expire(int64_t timestampUs, bool all, int64_t idleUs, const Sink& sink)
{
    for (auto it = connections_.begin(); it != connections_.end();)
    {
        auto& connection = *it->second;
        if (all || timestampUs - connection.lastUs > idleUs)
        {
            const auto found = it++;
            remove(found, all ? "Capture ended; RDMA connection outcome unknown" :
                "RDMA idle timeout; outcome unknown", sink);
            continue;
        }
        if (connection.streams && timestampUs - connection.observation.firstUs > 30000000)
        {
            const auto before = connection.memory();
            connection.streams.reset();
            if (connection.observed)
            {
                connection.observation.detail = "RDMA cleartext inspection window ended";
                sink(connection.observation);
            }
            bytes_ = bytes_ - before + connection.memory();
        }
        ++it;
    }
}
}
