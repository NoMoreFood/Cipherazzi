#include "Network.h"
#include <algorithm>

namespace Cipherazzi
{
size_t IpFragments::Datagram::memory() const
{
    size_t result = sizeof(*this) + sizeof(Key) + 64 + header.capacity() + pieces.capacity() * sizeof(Piece);
    for (const auto& piece : pieces)
        result += piece.bytes.capacity();
    return result;
}

bool IpFragments::feed(Bytes packet, bool ethernet, int64_t timestampUs, size_t budget, size_t limit,
    std::vector<uint8_t>& assembled)
{
    // Leave ordinary packets on the allocation-free decoder path.
    if (ethernet)
    {
        if (packet.size() < 14)
            return false;
        size_t offset = 14;
        auto type = be16(packet, 12);
        for (int tag = 0; (type == 0x8100 || type == 0x88a8) && tag < 2; ++tag)
        {
            if (offset + 4 > packet.size())
                return false;
            type = be16(packet, offset + 2);
            offset += 4;
        }
        if (type != 0x0800 && type != 0x86dd)
            return false;
        packet = packet.subspan(offset);
    }
    if (packet.empty())
        return false;
    Key key;
    size_t header = 0, total = 0, offset = 0, previous = 0;
    uint8_t protocol = 0;
    bool more = false;
    const bool ipv6 = (packet[0] >> 4) == 6;
    if ((packet[0] >> 4) == 4)
    {
        if (packet.size() < 20 || !(be16(packet, 6) & 0x3fff))
            return false;
        header = (packet[0] & 15) * 4ULL;
        total = be16(packet, 2);
        offset = (be16(packet, 6) & 0x1fff) * 8ULL;
        more = (be16(packet, 6) & 0x2000) != 0;
        protocol = key.protocol = packet[9];
        key.id = be16(packet, 4);
        std::copy_n(packet.begin() + 12, 4, key.addresses.a.address.begin());
        std::copy_n(packet.begin() + 16, 4, key.addresses.b.address.begin());
    }
    else if (ipv6)
    {
        if (packet.size() < 40)
            return false;
        total = 40ULL + be16(packet, 4);
        protocol = packet[6];
        header = 40;
        previous = 6;
        for (int extension = 0; protocol != 44 && extension < 8; ++extension)
        {
            if (protocol != 0 && protocol != 43 && protocol != 60 && protocol != 51)
                return false;
            if (header + 8 > std::min(total, packet.size()))
                return false;
            const auto length = protocol == 51 ? (packet[header + 1] + 2ULL) * 4 :
                (packet[header + 1] + 1ULL) * 8;
            previous = header;
            protocol = packet[header];
            header += length;
        }
        if (protocol != 44 || header + 8 > std::min(total, packet.size()))
            return false;
        const auto flags = be16(packet, header + 2);
        if (!(flags & 0xfff9))
            return false;
        offset = flags & 0xfff8;
        more = (flags & 1) != 0;
        protocol = packet[header];
        key.id = be32(packet, header + 4);
        key.addresses.a.family = key.addresses.b.family = 6;
        std::copy_n(packet.begin() + 8, 16, key.addresses.a.address.begin());
        std::copy_n(packet.begin() + 24, 16, key.addresses.b.address.begin());
        header += 8;
        if ((flags & 6) || packet[header - 7])
        {
            ++counters_.malformed;
            return true;
        }
    }
    else
        return false;
    ++counters_.fragments;
    if (total > packet.size())
    {
        ++counters_.truncated;
        return true;
    }
    if (header < (ipv6 ? 48ULL : 20ULL) || header >= total || offset + total - header > 65535 ||
        (more && (total - header) % 8) || (!ipv6 && (be16(packet, 6) & 0xc000)))
    {
        ++counters_.malformed;
        return true;
    }
    auto found = pending_.find(key);
    if (found == pending_.end())
    {
        if (pending_.size() >= std::min(limit, size_t{1024}) || bytes_ + sizeof(Datagram) + 128 > budget)
        {
            ++counters_.reassemblyLimit;
            return true;
        }
        found = pending_.try_emplace(key).first;
        found->second.startedUs = timestampUs;
        found->second.protocol = protocol;
        bytes_ += found->second.memory();
    }
    auto& datagram = found->second;
    if (datagram.rejected)
        return true;
    const auto retained = datagram.memory();
    auto reject = [&](bool limited)
    {
        datagram.header = {};
        datagram.pieces = {};
        datagram.rejected = true;
        bytes_ = bytes_ - retained + datagram.memory();
        if (limited)
            ++counters_.reassemblyLimit;
        else
            ++counters_.malformed;
    };
    const auto payload = packet.subspan(header, total - header);
    const auto end = offset + payload.size();
    if (protocol != datagram.protocol || (datagram.final && (end > datagram.total ||
        (!more && end != datagram.total))))
    {
        reject(false);
        return true;
    }
    for (const auto& piece : datagram.pieces)
    {
        if (offset < piece.offset + piece.bytes.size() && end > piece.offset)
        {
            if (!ipv6 && offset == piece.offset && std::ranges::equal(payload, piece.bytes))
                return true;
            reject(false);
            return true;
        }
        if (!more && piece.offset + piece.bytes.size() > end)
        {
            reject(false);
            return true;
        }
    }
    if (datagram.pieces.size() >= 128 || bytes_ + payload.size() + header + 4096 > budget)
    {
        reject(true);
        return true;
    }
    if (!offset)
    {
        datagram.header.assign(packet.begin(), packet.begin() + header - (ipv6 ? 8 : 0));
        datagram.nextHeader = previous;
    }
    datagram.pieces.push_back({offset, {payload.begin(), payload.end()}});
    if (!more)
    {
        datagram.final = true;
        datagram.total = end;
    }
    bytes_ = bytes_ - retained + datagram.memory();
    size_t received = 0;
    for (const auto& piece : datagram.pieces)
        received += piece.bytes.size();
    if (!datagram.final || datagram.header.empty() || received != datagram.total)
        return true;
    const size_t length = datagram.header.size() + datagram.total;
    const size_t wireLength = length - (ipv6 ? 40 : 0);
    if (wireLength > 65535)
    {
        const auto before = datagram.memory();
        datagram.rejected = true;
        datagram.pieces = {};
        datagram.header = {};
        bytes_ = bytes_ - before + datagram.memory();
        ++counters_.malformed;
        return true;
    }
    // Publish a complete IP datagram; transport inspection never sees gaps or ambiguous overlap.
    assembled = datagram.header;
    assembled.resize(length);
    for (const auto& piece : datagram.pieces)
        std::copy(piece.bytes.begin(), piece.bytes.end(), assembled.begin() + datagram.header.size() + piece.offset);
    const auto sizeOffset = ipv6 ? 4 : 2;
    assembled[sizeOffset] = static_cast<uint8_t>(wireLength >> 8);
    assembled[sizeOffset + 1] = static_cast<uint8_t>(wireLength);
    if (ipv6)
        assembled[datagram.nextHeader] = datagram.protocol;
    else
        assembled[6] = assembled[7] = assembled[10] = assembled[11] = 0;
    bytes_ -= datagram.memory();
    pending_.erase(found);
    return true;
}

void IpFragments::expire(int64_t timestampUs, bool all)
{
    for (auto it = pending_.begin(); it != pending_.end();)
    {
        if (!all && timestampUs - it->second.startedUs <= 30000000)
        {
            ++it;
            continue;
        }
        if (!it->second.rejected)
            ++counters_.reassemblyLimit;
        bytes_ -= it->second.memory();
        it = pending_.erase(it);
    }
}

bool DtlsStream::recognizes(Bytes bytes)
{
    return bytes.size() >= 13 && bytes[0] >= 20 && bytes[0] <= 23 &&
        (be16(bytes, 1) == 0xfeff || be16(bytes, 1) == 0xfefd);
}

size_t DtlsStream::memory() const
{
    size_t result = sizeof(*this) + tls_.memory() + messages_.capacity() * sizeof(Message);
    for (const auto& message : messages_)
        result += message.bytes.capacity() + message.present.capacity();
    return result;
}

bool DtlsStream::feed(Bytes bytes, const TlsStream::Sink& sink)
{
    if (finished_ || (!bytes.empty() && (bytes[0] & 0xe0) == 0x20))
        return true;
    while (!bytes.empty())
    {
        if (!recognizes(bytes) || be16(bytes, 11) > bytes.size() - 13)
            return false;
        const auto type = bytes[0];
        const auto epoch = be16(bytes, 3);
        auto payload = bytes.subspan(13, be16(bytes, 11));
        bytes = bytes.subspan(13 + payload.size());
        if (epoch)
            continue;
        if (type == 20)
        {
            finished_ = true;
            Hello hello;
            hello.type = 253;
            sink(hello);
            continue;
        }
        if (type == 21)
        {
            if (payload.size() != 2)
                return false;
            Hello hello;
            hello.type = 254;
            hello.crypto.alertLevel = payload[0];
            hello.crypto.alertCode = payload[1];
            sink(hello);
        }
        if (type != 22)
            continue;
        while (!payload.empty())
        {
            if (payload.size() < 12)
                return false;
            const auto length = (static_cast<size_t>(payload[1]) << 16) | be16(payload, 2);
            const auto sequence = be16(payload, 4);
            const auto offset = (static_cast<size_t>(payload[6]) << 16) | be16(payload, 7);
            const auto fragment = (static_cast<size_t>(payload[9]) << 16) | be16(payload, 10);
            const auto handshakeType = payload[0];
            if (offset > length || fragment > length - offset || fragment > payload.size() - 12)
                return false;
            const auto body = payload.subspan(12, fragment);
            payload = payload.subspan(12 + fragment);
            if (sequence >= completed_.size() || length > 131072)
            {
                limited_ = true;
                return false;
            }
            if (completed_[sequence])
                continue;
            auto found = std::ranges::find(messages_, sequence, &Message::sequence);
            if (found == messages_.end())
            {
                if (messages_.size() >= 16 || memory() + length * 2 > 262144)
                {
                    limited_ = true;
                    return false;
                }
                messages_.push_back({handshakeType, sequence, std::vector<uint8_t>(length),
                    std::vector<uint8_t>(length), 0});
                found = messages_.end() - 1;
            }
            auto& message = *found;
            if (message.type != handshakeType || message.bytes.size() != length)
                return false;
            // Retransmission may change fragment boundaries, but each overlapping byte must agree.
            for (size_t i = 0; i < fragment; ++i)
            {
                if (message.present[offset + i] && message.bytes[offset + i] != body[i])
                    return false;
                if (!message.present[offset + i])
                    ++message.received;
                message.present[offset + i] = 1;
                message.bytes[offset + i] = body[i];
            }
            if (message.received != length)
                continue;
            if (!flush(sink))
                return false;
        }
    }
    return true;
}

bool DtlsStream::flush(const TlsStream::Sink& sink)
{
    for (;;)
    {
        auto found = messages_.end();
        for (auto it = messages_.begin(); it != messages_.end(); ++it)
            if (it->received == it->bytes.size() && (helloSeen_ || it->type == 1 || it->type == 2 || it->type == 3) &&
                (found == messages_.end() || it->sequence < found->sequence))
                found = it;
        if (found == messages_.end())
            return true;
        const auto& message = *found;
        const auto handshakeType = message.type;
        const auto length = message.bytes.size();
        Hello hello;
        hello.type = handshakeType;
        hello.client = handshakeType == 1;
        if (handshakeType == 1 || handshakeType == 2)
        {
            if (!parseHello(message.bytes, hello, true))
                return false;
            helloSeen_ = true;
            sink(hello);
        }
        else if (handshakeType == 3)
        {
            if (length < 3 || (be16(message.bytes, 0) != 0xfeff && be16(message.bytes, 0) != 0xfefd) ||
                message.bytes[2] != length - 3)
                return false;
            sink(hello);
        }
        else
        {
            std::vector<uint8_t> tlsMessage{handshakeType, static_cast<uint8_t>(length >> 16),
                static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};
            tlsMessage.insert(tlsMessage.end(), message.bytes.begin(), message.bytes.end());
            if (!tls_.feedHandshake(tlsMessage, sink))
                return false;
        }
        completed_[message.sequence] = true;
        messages_.erase(found);

    }
}
}
