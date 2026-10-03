#include "Quic.h"

#include <algorithm>
#include <stdexcept>

namespace Cipherazzi
{
bool quicInteger(Bytes bytes, size_t& offset, uint64_t& value)
{
    if (offset >= bytes.size())
        return false;
    const size_t length = 1ULL << (bytes[offset] >> 6);
    if (length > bytes.size() - offset)
        return false;
    value = bytes[offset++] & 63;
    for (size_t i = 1; i < length; ++i)
        value = (value << 8) | bytes[offset++];
    return true;
}

std::string cidText(Bytes bytes)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes)
    {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}

std::optional<QuicHeader> quicHeader(Bytes bytes)
{
    if (bytes.size() < 7 || !(bytes[0] & 0x80))
        return {};
    QuicHeader header;
    header.version = be32(bytes, 1);
    if (header.version != 1 && header.version != 0x6b3343cf)
        return {};
    header.type = (bytes[0] >> 4) & 3;
    size_t offset = 6;
    const size_t destinationLength = bytes[5];
    if (destinationLength > 20 || destinationLength >= bytes.size() - offset)
        return {};
    header.destinationId = bytes.subspan(offset, destinationLength);
    offset += destinationLength;
    const size_t sourceLength = bytes[offset++];
    if (sourceLength > 20 || sourceLength > bytes.size() - offset)
        return {};
    header.sourceId = bytes.subspan(offset, sourceLength);
    offset += sourceLength;
    if (header.retry())
    {
        if (bytes.size() - offset <= 16)
            return {};
        header.packet = bytes;
        return header;
    }
    uint64_t length = 0;
    if (header.initial())
    {
        if (!quicInteger(bytes, offset, length) || length > bytes.size() - offset)
            return {};
        offset += static_cast<size_t>(length);
    }
    if (!quicInteger(bytes, offset, length) || length < 20 || length > bytes.size() - offset)
        return {};
    header.numberOffset = offset;
    header.packet = bytes.first(offset + static_cast<size_t>(length));
    return header;
}

std::array<uint8_t, 32> quicHmac(Bytes key, Bytes input)
{
    std::array<uint8_t, 32> result{};
    if (BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()), const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()),
        result.data(), static_cast<ULONG>(result.size())) < 0)
        throw std::runtime_error("QUIC Initial key derivation failed");
    return result;
}

std::array<uint8_t, 32> quicExpand(Bytes secret, std::string_view label, uint8_t length)
{
    const std::string text = "tls13 " + std::string(label);
    std::vector<uint8_t> info{0, length, static_cast<uint8_t>(text.size())};
    info.insert(info.end(), text.begin(), text.end());
    info.push_back(0);
    info.push_back(1);
    return quicHmac(secret, info);
}

QuicConnection::QuicConnection(Bytes destinationId, uint32_t version) :
    originalId_(destinationId.begin(), destinationId.end()), version_(version)
{
    derive(destinationId);
}

void QuicConnection::derive(Bytes destinationId)
{
    static constexpr uint8_t salts[2][20]
    {
        {0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a},
        {0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9}
    };
    const auto secret = quicHmac(salts[version_ != 1], destinationId);
    const auto prefix = version_ == 1 ? "quic " : "quicv2 ";
    for (size_t side = 0; side < 2; ++side)
    {
        auto& direction = directions_[side];
        const auto initial = quicExpand(secret, side == 0 ? "client in" : "server in", 32);
        const auto key = quicExpand(initial, std::string(prefix) + "key", 16);
        const auto protection = quicExpand(initial, std::string(prefix) + "hp", 16);
        const auto iv = quicExpand(initial, std::string(prefix) + "iv", 12);
        std::copy_n(iv.begin(), direction.iv.size(), direction.iv.begin());
        BCRYPT_KEY_HANDLE handle = nullptr;
        if (BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &handle, nullptr, 0,
            const_cast<PUCHAR>(key.data()), 16, 0) < 0)
            throw std::runtime_error("QUIC Initial cipher initialization failed");
        direction.key.reset(handle);
        handle = nullptr;
        if (BCryptGenerateSymmetricKey(BCRYPT_AES_ECB_ALG_HANDLE, &handle, nullptr, 0,
            const_cast<PUCHAR>(protection.data()), 16, 0) < 0)
            throw std::runtime_error("QUIC header protection initialization failed");
        direction.protection.reset(handle);
    }
}

bool QuicConnection::retry(const QuicHeader& header)
{
    if (header.version != version_)
        return false;

    // Retry integrity binds the token and connection IDs to the original client destination ID.
    static constexpr uint8_t keys[2][16]
    {
        {0xbe,0x0c,0x69,0x0b,0x9f,0x66,0x57,0x5a,0x1d,0x76,0x6b,0x54,0xe3,0x68,0xc8,0x4e},
        {0x8f,0xb4,0xb0,0x1b,0x56,0xac,0x48,0xe2,0x60,0xfb,0xcb,0xce,0xad,0x7c,0xcc,0x92}
    };
    static constexpr uint8_t nonces[2][12]
    {
        {0x46,0x15,0x99,0xd3,0x5d,0x63,0x2b,0xf2,0x23,0x98,0x25,0xbb},
        {0xd8,0x69,0x69,0xbc,0x2d,0x7c,0x6d,0x99,0x90,0xef,0xb0,0x4a}
    };
    const size_t index = version_ != 1;
    BCRYPT_KEY_HANDLE handle = nullptr;
    if (BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &handle, nullptr, 0,
        const_cast<PUCHAR>(keys[index]), 16, 0) < 0)
        throw std::runtime_error("QUIC Retry cipher initialization failed");
    Key key(handle);
    std::vector<uint8_t> aad{static_cast<uint8_t>(originalId_.size())};
    aad.insert(aad.end(), originalId_.begin(), originalId_.end());
    aad.insert(aad.end(), header.packet.begin(), header.packet.end() - 16);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonces[index]);
    info.cbNonce = 12;
    info.pbAuthData = aad.data();
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = const_cast<PUCHAR>(header.packet.data() + header.packet.size() - 16);
    info.cbTag = 16;
    ULONG written = 0;
    uint8_t empty = 0;
    if (BCryptDecrypt(key.get(), &empty, 0, &info, nullptr, 0, &empty, 0, &written, 0) < 0)
        return false;
    if (retried_)
        return true;
    for (auto& direction : directions_)
    {
        direction.tls = {};
        direction.bytes.clear();
        direction.present.clear();
        direction.consumed = 0;
    }
    derive(header.sourceId);
    retried_ = true;
    return true;
}

bool QuicConnection::feed(const QuicHeader& header, bool client, const TlsStream::Sink& sink)
{
    auto& direction = directions_[client ? 0 : 1];
    const auto packet = header.packet;
    if (header.version != version_ || !header.initial() || header.numberOffset + 20 > packet.size())
        return false;
    std::array<uint8_t, 16> mask{};
    ULONG written = 0;
    if (BCryptEncrypt(direction.protection.get(), const_cast<PUCHAR>(packet.data() + header.numberOffset + 4),
        16, nullptr, nullptr, 0, mask.data(), 16, &written, 0) < 0)
        throw std::runtime_error("QUIC header protection failed");
    const auto first = static_cast<uint8_t>(packet[0] ^ (mask[0] & 15));
    if (first & 12)
        return false;
    const size_t numberLength = (first & 3) + 1;
    const size_t payloadOffset = header.numberOffset + numberLength;
    std::vector<uint8_t> aad(packet.begin(), packet.begin() + payloadOffset);
    aad[0] = first;
    uint64_t number = 0;
    for (size_t i = 0; i < numberLength; ++i)
    {
        aad[header.numberOffset + i] ^= mask[i + 1];
        number = (number << 8) | aad[header.numberOffset + i];
    }

    // Reconstruct packet numbers independently per direction, including out-of-order packets.
    const uint64_t window = 1ULL << (numberLength * 8);
    number |= direction.expected & ~(window - 1);
    if (number + window / 2 <= direction.expected && number + window < (1ULL << 62))
        number += window;
    else if (number > direction.expected + window / 2 && number >= window)
        number -= window;
    if (number >= (1ULL << 62))
        return false;
    auto nonce = direction.iv;
    for (size_t i = 0; i < 8; ++i)
        nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>(number >> (i * 8));
    const auto encrypted = packet.subspan(payloadOffset, packet.size() - payloadOffset - 16);
    std::vector<uint8_t> plain(encrypted.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce.data();
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = aad.data();
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = const_cast<PUCHAR>(packet.data() + packet.size() - 16);
    info.cbTag = 16;
    if (BCryptDecrypt(direction.key.get(), const_cast<PUCHAR>(encrypted.data()),
        static_cast<ULONG>(encrypted.size()), &info, nullptr, 0, plain.data(), static_cast<ULONG>(plain.size()),
        &written, 0) < 0)
        return false;
    direction.expected = std::max(direction.expected, number + 1);
    return frames(plain, direction, sink);
}

bool QuicConnection::frames(Bytes bytes, Direction& direction, const TlsStream::Sink& sink)
{
    size_t offset = 0, frames = 0;
    while (offset < bytes.size())
    {
        uint64_t type = 0, a = 0, b = 0, c = 0, d = 0;
        if (++frames > 8192 || !quicInteger(bytes, offset, type))
            return false;
        if (type == 0 || type == 1)
            continue;
        if (type == 2 || type == 3)
        {
            if (!quicInteger(bytes, offset, a) || !quicInteger(bytes, offset, b) ||
                !quicInteger(bytes, offset, c) || !quicInteger(bytes, offset, d) || c > 256 || d > a)
                return false;
            a -= d;
            for (uint64_t i = 0; i < c; ++i)
            {
                if (!quicInteger(bytes, offset, b) || !quicInteger(bytes, offset, d) || b + 2 > a)
                    return false;
                a -= b + 2;
                if (d > a)
                    return false;
                a -= d;
            }
            if (type == 3 && (!quicInteger(bytes, offset, a) || !quicInteger(bytes, offset, b) ||
                !quicInteger(bytes, offset, c)))
                return false;
        }
        else if (type == 6)
        {
            if (!quicInteger(bytes, offset, a) || !quicInteger(bytes, offset, b) || b > bytes.size() - offset)
                return false;
            if (a > 131076 || b > 131076 - a)
            {
                limited_ = true;
                return false;
            }

            // Keep bounded CRYPTO offsets and reject overlapping fragments with different bytes.
            const size_t end = static_cast<size_t>(a + b);
            if (direction.bytes.size() < end)
            {
                direction.bytes.resize(end);
                direction.present.resize(end);
            }
            for (size_t i = 0; i < b; ++i)
            {
                const size_t position = static_cast<size_t>(a) + i;
                if (direction.present[position] && direction.bytes[position] != bytes[offset + i])
                    return false;
                direction.bytes[position] = bytes[offset + i];
                direction.present[position] = 1;
            }
            offset += static_cast<size_t>(b);
            size_t contiguous = direction.consumed;
            while (contiguous < direction.present.size() && direction.present[contiguous])
                ++contiguous;
            if (contiguous > direction.consumed && !direction.tls.feedHandshake(
                Bytes(direction.bytes).subspan(direction.consumed, contiguous - direction.consumed), sink))
            {
                limited_ = direction.tls.limited();
                return false;
            }
            direction.consumed = contiguous;
        }
        else if (type == 0x1c)
        {
            if (!quicInteger(bytes, offset, a) || !quicInteger(bytes, offset, b) ||
                !quicInteger(bytes, offset, c) || c > bytes.size() - offset)
                return false;
            offset += static_cast<size_t>(c);
            closed_ = true;
            closeError_ = a;
        }
        else
            return false;
    }
    return true;
}

size_t QuicConnection::memory() const
{
    size_t result = sizeof(*this) + originalId_.capacity() + 8192;
    for (const auto& direction : directions_)
        result += direction.bytes.capacity() + direction.present.capacity() + direction.tls.memory();
    return result;
}
}
