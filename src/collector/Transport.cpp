#include "Engine.h"
#include "Auth.h"

#include <algorithm>
#include <bit>

namespace Cipherazzi
{
std::optional<TransportPacket> decodePacket(Bytes packet, PacketKind kind, Counters& counters, PacketOrigin origin)
{
    const bool captureLimit = origin == PacketOrigin::PacketMonitor && packet.size() >= PacketMonitorCaptureLimit;

    // Strip link headers without trusting lengths supplied by the capture source.
    if (kind == PacketKind::Ethernet)
    {
        const auto type = stripEthernet(packet);
        if (!type || (*type != 0x0800 && *type != 0x86dd))
        {
            ++(type ? counters.unsupported : counters.malformed);
            return {};
        }
    }
    else if (kind != PacketKind::Ip)
    {
        ++counters.unsupported;
        return {};
    }
    if (packet.empty())
    {
        ++counters.malformed;
        return {};
    }

    TransportPacket result;
    result.loopback = origin == PacketOrigin::Loopback;
    size_t offset = 0;
    size_t total = 0;
    uint8_t protocol = 0;
    bool offloadLength = false;
    const auto family = packet[0] >> 4;
    if (family == 4 && packet.size() >= 20)
    {
        offset = (packet[0] & 15) * 4;
        total = be16(packet, 2);

        // Packet Monitor exposes LSOv2 buffers before the NIC assigns their IP lengths.
        if (!total && origin == PacketOrigin::PacketMonitor)
        {
            total = packet.size();
            offloadLength = true;
        }
        if (offset < 20 || offset > packet.size() || total < offset)
        {
            ++counters.malformed;
            return {};
        }
        if (be16(packet, 6) & 0x3fff)
        {
            ++counters.fragments;
            return {};
        }
        protocol = packet[9];
        std::copy_n(packet.begin() + 12, 4, result.source.address.begin());
        std::copy_n(packet.begin() + 16, 4, result.destination.address.begin());
    }
    else if (family == 6 && packet.size() >= 40)
    {
        result.source.family = result.destination.family = 6;
        std::copy_n(packet.begin() + 8, 16, result.source.address.begin());
        std::copy_n(packet.begin() + 24, 16, result.destination.address.begin());
        total = 40ULL + be16(packet, 4);
        offset = 40;
        protocol = packet[6];

        // Walk bounded IPv6 extension chains, accepting atomic fragments only.
        for (int extension = 0; protocol != 6 && protocol != 17 && extension < 8; ++extension)
        {
            if (protocol != 0 && protocol != 43 && protocol != 60 && protocol != 44 && protocol != 51)
                break;
            if (offset + 8 > std::min(total, packet.size()))
            {
                ++counters.malformed;
                return {};
            }
            if (protocol == 44 && (be16(packet, offset + 2) & 0xfff9))
            {
                ++counters.fragments;
                return {};
            }
            const size_t length = protocol == 44 ? 8 : protocol == 51 ?
                (packet[offset + 1] + 2ULL) * 4 : (packet[offset + 1] + 1ULL) * 8;
            if (protocol == 51)
            {
                if (length < 12 || offset + length > std::min(total, packet.size()) ||
                    packet[offset + 2] || packet[offset + 3] || !be32(packet, offset + 4))
                {
                    ++counters.malformed;
                    return {};
                }
                result.ipsecProtocol = 51;
                result.ipsecSpi = be32(packet, offset + 4);
                result.ipsecSequence = be32(packet, offset + 8);
            }
            protocol = packet[offset];
            offset += length;
        }
    }
    else
    {
        ++counters.malformed;
        return {};
    }
    if (protocol == 51)
    {
        if (offset + 12 > std::min(total, packet.size()))
        {
            ++counters.malformed;
            return {};
        }
        const size_t length = (packet[offset + 1] + 2ULL) * 4;
        if (length < 12 || offset + length > std::min(total, packet.size()) ||
            packet[offset + 2] || packet[offset + 3] || !be32(packet, offset + 4))
        {
            ++counters.malformed;
            return {};
        }
        result.ipsecProtocol = 51;
        result.ipsecSpi = be32(packet, offset + 4);
        result.ipsecSequence = be32(packet, offset + 8);
        protocol = packet[offset];
        offset += length;
    }
    if (protocol == 50 || (result.ipsecSpi && protocol != 6 && protocol != 17))
    {
        if (offset > std::min(total, packet.size()) || (protocol == 50 &&
            (offset + 10 > std::min(total, packet.size()) || !be32(packet, offset))))
        {
            ++counters.malformed;
            return {};
        }
        if (protocol == 50)
        {
            result.ipsecProtocol = 50;
            result.ipsecSpi = be32(packet, offset);
            result.ipsecSequence = be32(packet, offset + 4);
        }
        result.protocol = result.ipsecProtocol;
        result.payload = packet.subspan(offset, std::min(total, packet.size()) - offset);
        if (total > packet.size()) ++counters.truncated;
        return result;
    }
    if (protocol != 6 && protocol != 17)
    {
        ++counters.unsupported;
        return {};
    }

    // Captured TCP prefixes remain useful; sequence numbers preserve gaps beyond the capture limit.
    result.truncated = total > packet.size() || (offloadLength && captureLimit);
    if (result.truncated)
        ++counters.truncated;
    packet = packet.first(std::min(total, packet.size()));
    if (protocol == 17)
    {
        if (offloadLength || offset + 8 > packet.size())
        {
            ++counters.malformed;
            return {};
        }
        const size_t length = be16(packet, offset + 4);
        if (length < 8 || length > total - offset)
        {
            ++counters.malformed;
            return {};
        }
        if (length > packet.size() - offset)
        {
            if (!result.truncated)
                ++counters.truncated;
            return {};
        }
        result.protocol = 17;
        result.source.port = be16(packet, offset);
        result.destination.port = be16(packet, offset + 2);
        result.payload = packet.subspan(offset + 8, length - 8);
        return result;
    }
    if (offset + 20 > packet.size())
    {
        ++counters.malformed;
        return {};
    }

    // Offload can make checksums appear invalid at this capture layer.
    const size_t header = (packet[offset + 12] >> 4) * 4;
    if (header < 20 || offset + header > packet.size())
    {
        ++counters.malformed;
        return {};
    }
    if (offloadLength && ((packet[offset + 13] & 0x26) || be16(packet, offset + 18)))
    {
        ++counters.malformed;
        return {};
    }
    result.source.port = be16(packet, offset);
    result.destination.port = be16(packet, offset + 2);
    result.sequence = be32(packet, offset + 4);
    result.flags = packet[offset + 13];
    result.payload = packet.subspan(offset + header);
    return result;
}

void TcpStream::begin(uint32_t sequence)
{
    if (!initialized_)
    {
        next_ = sequence;
        initialized_ = true;
    }
}

bool TcpStream::feed(uint32_t sequence, Bytes bytes, const Sink& sink)
{
    if (bytes.empty())
        return true;
    begin(sequence);
    auto distance = std::bit_cast<int32_t>(sequence - next_);
    if (distance > 0)
    {
        // Keep a small sparse window; retransmissions do not consume additional entries.
        if (distance > 262144 || pending_.size() >= 64 || memory() + bytes.size() > 524288)
        {
            limited_ = true;
            return false;
        }
        for (auto& segment : pending_)
        {
            if (segment.sequence == sequence)
            {
                if (segment.bytes.size() < bytes.size())
                    segment.bytes.assign(bytes.begin(), bytes.end());
                return true;
            }
        }
        pending_.push_back({sequence, {bytes.begin(), bytes.end()}});
        return true;
    }
    const auto overlap = static_cast<uint32_t>(next_ - sequence);
    if (overlap >= bytes.size())
        return true;
    bytes = bytes.subspan(overlap);
    if (!sink(bytes))
        return false;
    next_ += static_cast<uint32_t>(bytes.size());

    // Sequence differences remain signed across the TCP sequence-number wrap.
    while (!pending_.empty())
    {
        const auto found = std::ranges::min_element(pending_, [this](const Segment& a, const Segment& b)
        {
            return std::bit_cast<int32_t>(a.sequence - next_) < std::bit_cast<int32_t>(b.sequence - next_);
        });
        distance = std::bit_cast<int32_t>(found->sequence - next_);
        if (distance > 0)
            break;
        const auto skipped = static_cast<uint32_t>(next_ - found->sequence);
        if (skipped < found->bytes.size())
        {
            const Bytes remaining = Bytes(found->bytes).subspan(skipped);
            if (!sink(remaining))
                return false;
            next_ += static_cast<uint32_t>(remaining.size());
        }
        pending_.erase(found);
    }
    return true;
}

size_t TcpStream::memory() const
{
    size_t result = pending_.capacity() * sizeof(Segment);
    for (const auto& segment : pending_)
        result += segment.bytes.capacity();
    return result;
}

}
