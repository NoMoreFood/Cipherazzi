#include "TlsDecrypt.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace Cipherazzi
{
namespace TlsDetail
{
using Buffer = std::vector<uint8_t>;

constexpr size_t MaximumRecord = 18432, MaximumHandshake = 131072;
constexpr uint8_t RetryRandom[32]{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
    0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

Buffer hmac(bool sha384, Bytes key, Bytes data)
{
    Buffer output(sha384 ? 48 : 32);
    if (BCryptHash(sha384 ? BCRYPT_HMAC_SHA384_ALG_HANDLE : BCRYPT_HMAC_SHA256_ALG_HANDLE,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), const_cast<PUCHAR>(data.data()),
        static_cast<ULONG>(data.size()), output.data(), static_cast<ULONG>(output.size())) < 0)
        throw std::runtime_error("TLS key derivation failed");
    return output;
}

// HKDF-Expand-Label with an empty context, as TLS 1.3 derives record keys and later traffic secrets.
Buffer expandLabel(bool sha384, Bytes secret, std::string_view label, size_t length)
{
    Buffer info{static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length),
        static_cast<uint8_t>(6 + label.size())};
    info.insert(info.end(), {'t', 'l', 's', '1', '3', ' '});
    info.insert(info.end(), label.begin(), label.end());
    info.push_back(0);
    Buffer result, block;
    for (uint8_t counter = 1; result.size() < length; ++counter)
    {
        Buffer input(block);
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);
        block = hmac(sha384, secret, input);
        result.insert(result.end(), block.begin(), block.end());
    }
    result.resize(length);
    return result;
}

// The TLS 1.2 pseudorandom function.
Buffer prf(bool sha384, Bytes secret, std::string_view label, Bytes seed, size_t length)
{
    Buffer labelled(label.begin(), label.end());
    labelled.insert(labelled.end(), seed.begin(), seed.end());
    Buffer result, a = hmac(sha384, secret, labelled);
    while (result.size() < length)
    {
        Buffer input(a);
        input.insert(input.end(), labelled.begin(), labelled.end());
        const auto block = hmac(sha384, secret, input);
        result.insert(result.end(), block.begin(), block.end());
        a = hmac(sha384, secret, a);
    }
    result.resize(length);
    return result;
}

uint32_t rotate(uint32_t value, int bits) { return (value << bits) | (value >> (32 - bits)); }
uint32_t little(const uint8_t* p) { return p[0] | (uint32_t{p[1]} << 8) | (uint32_t{p[2]} << 16) | (uint32_t{p[3]} << 24); }

void chachaBlock(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t output[64])
{
    uint32_t state[16]{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 8; ++i)
        state[4 + i] = little(key + i * 4);
    state[12] = counter;
    for (int i = 0; i < 3; ++i)
        state[13 + i] = little(nonce + i * 4);
    uint32_t x[16];
    std::memcpy(x, state, sizeof(x));
    auto quarter = [&](int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = rotate(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = rotate(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = rotate(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = rotate(x[b] ^ x[c], 7);
    };
    for (int round = 0; round < 10; ++round)
    {
        quarter(0, 4, 8, 12); quarter(1, 5, 9, 13); quarter(2, 6, 10, 14); quarter(3, 7, 11, 15);
        quarter(0, 5, 10, 15); quarter(1, 6, 11, 12); quarter(2, 7, 8, 13); quarter(3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i)
    {
        const uint32_t word = x[i] + state[i];
        for (int byte = 0; byte < 4; ++byte)
            output[i * 4 + byte] = static_cast<uint8_t>(word >> (8 * byte));
    }
}

// Poly1305 with 26-bit limbs.
std::array<uint8_t, 16> poly1305(const uint8_t key[32], Bytes message)
{
    constexpr uint32_t mask = 0x3ffffff;
    const uint32_t r0 = little(key) & 0x3ffffff, r1 = (little(key + 3) >> 2) & 0x3ffff03,
        r2 = (little(key + 6) >> 4) & 0x3ffc0ff, r3 = (little(key + 9) >> 6) & 0x3f03fff,
        r4 = (little(key + 12) >> 8) & 0x00fffff;
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    for (size_t offset = 0; offset < message.size(); offset += 16)
    {
        uint8_t block[16]{};
        const auto size = std::min<size_t>(16, message.size() - offset);
        std::memcpy(block, message.data() + offset, size);
        uint32_t high = 1u << 24;
        if (size < 16)
        {
            block[size] = 1;
            high = 0;
        }
        h0 += little(block) & mask;
        h1 += (little(block + 3) >> 2) & mask;
        h2 += (little(block + 6) >> 4) & mask;
        h3 += (little(block + 9) >> 6) & mask;
        h4 += (little(block + 12) >> 8) | high;
        uint64_t d0 = uint64_t{h0} * r0 + uint64_t{h1} * s4 + uint64_t{h2} * s3 + uint64_t{h3} * s2 + uint64_t{h4} * s1;
        uint64_t d1 = uint64_t{h0} * r1 + uint64_t{h1} * r0 + uint64_t{h2} * s4 + uint64_t{h3} * s3 + uint64_t{h4} * s2;
        uint64_t d2 = uint64_t{h0} * r2 + uint64_t{h1} * r1 + uint64_t{h2} * r0 + uint64_t{h3} * s4 + uint64_t{h4} * s3;
        uint64_t d3 = uint64_t{h0} * r3 + uint64_t{h1} * r2 + uint64_t{h2} * r1 + uint64_t{h3} * r0 + uint64_t{h4} * s4;
        uint64_t d4 = uint64_t{h0} * r4 + uint64_t{h1} * r3 + uint64_t{h2} * r2 + uint64_t{h3} * r1 + uint64_t{h4} * r0;
        auto carry = static_cast<uint32_t>(d0 >> 26); h0 = static_cast<uint32_t>(d0) & mask;
        d1 += carry; carry = static_cast<uint32_t>(d1 >> 26); h1 = static_cast<uint32_t>(d1) & mask;
        d2 += carry; carry = static_cast<uint32_t>(d2 >> 26); h2 = static_cast<uint32_t>(d2) & mask;
        d3 += carry; carry = static_cast<uint32_t>(d3 >> 26); h3 = static_cast<uint32_t>(d3) & mask;
        d4 += carry; carry = static_cast<uint32_t>(d4 >> 26); h4 = static_cast<uint32_t>(d4) & mask;
        h0 += carry * 5; carry = h0 >> 26; h0 &= mask; h1 += carry;
    }
    uint32_t carry = h1 >> 26; h1 &= mask;
    h2 += carry; carry = h2 >> 26; h2 &= mask;
    h3 += carry; carry = h3 >> 26; h3 &= mask;
    h4 += carry; carry = h4 >> 26; h4 &= mask;
    h0 += carry * 5; carry = h0 >> 26; h0 &= mask;
    h1 += carry;

    // Subtract the prime when the accumulator reached it.
    uint32_t g0 = h0 + 5; carry = g0 >> 26; g0 &= mask;
    uint32_t g1 = h1 + carry; carry = g1 >> 26; g1 &= mask;
    uint32_t g2 = h2 + carry; carry = g2 >> 26; g2 &= mask;
    uint32_t g3 = h3 + carry; carry = g3 >> 26; g3 &= mask;
    uint32_t g4 = h4 + carry - (1u << 26);
    uint32_t select = (g4 >> 31) - 1;
    g0 &= select; g1 &= select; g2 &= select; g3 &= select; g4 &= select;
    select = ~select;
    h0 = (h0 & select) | g0; h1 = (h1 & select) | g1; h2 = (h2 & select) | g2;
    h3 = (h3 & select) | g3; h4 = (h4 & select) | g4;
    h0 = h0 | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);
    uint64_t sum = uint64_t{h0} + little(key + 16);
    h0 = static_cast<uint32_t>(sum);
    sum = uint64_t{h1} + little(key + 20) + (sum >> 32);
    h1 = static_cast<uint32_t>(sum);
    sum = uint64_t{h2} + little(key + 24) + (sum >> 32);
    h2 = static_cast<uint32_t>(sum);
    sum = uint64_t{h3} + little(key + 28) + (sum >> 32);
    h3 = static_cast<uint32_t>(sum);
    std::array<uint8_t, 16> tag{};
    const uint32_t words[4]{h0, h1, h2, h3};
    for (int i = 0; i < 4; ++i)
        for (int byte = 0; byte < 4; ++byte)
            tag[i * 4 + byte] = static_cast<uint8_t>(words[i] >> (8 * byte));
    return tag;
}

bool chachaOpen(const uint8_t key[32], Bytes nonce, Bytes aad, Bytes sealed, Buffer& plain)
{
    if (sealed.size() < 16 || nonce.size() != 12)
        return false;
    const auto text = sealed.first(sealed.size() - 16);
    uint8_t block[64];
    chachaBlock(key, 0, nonce.data(), block);
    Buffer authenticated(aad.begin(), aad.end());
    authenticated.resize((authenticated.size() + 15) & ~size_t{15});
    authenticated.insert(authenticated.end(), text.begin(), text.end());
    authenticated.resize((authenticated.size() + 15) & ~size_t{15});
    for (const uint64_t length : {uint64_t{aad.size()}, uint64_t{text.size()}})
        for (int byte = 0; byte < 8; ++byte)
            authenticated.push_back(static_cast<uint8_t>(length >> (8 * byte)));
    const auto expected = poly1305(block, authenticated);
    uint8_t difference = 0;
    for (size_t i = 0; i < 16; ++i)
        difference |= expected[i] ^ sealed[text.size() + i];
    if (difference)
        return false;
    plain.resize(text.size());
    for (size_t offset = 0; offset < text.size(); offset += 64)
    {
        chachaBlock(key, static_cast<uint32_t>(offset / 64 + 1), nonce.data(), block);
        for (size_t i = 0; i < 64 && offset + i < text.size(); ++i)
            plain[offset + i] = text[offset + i] ^ block[i];
    }
    return true;
}

void appendBytes(Buffer& target, Bytes value) { target.insert(target.end(), value.begin(), value.end()); }
}
using namespace TlsDetail;

Aead::Aead(Kind kind, Bytes key) : kind_(kind)
{
    if (kind == Kind::ChaCha && key.size() == 32)
        std::copy(key.begin(), key.end(), key_.begin());
    else if (kind == Kind::AesGcm)
    {
        BCRYPT_KEY_HANDLE handle = nullptr;
        if (BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &handle, nullptr, 0,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0) < 0)
            throw std::runtime_error("TLS record cipher initialization failed");
        handle_.reset(handle);
    }
    else
        throw std::runtime_error("Unsupported TLS record cipher");
}

bool Aead::open(Bytes nonce, Bytes aad, Bytes sealed, std::vector<uint8_t>& plain) const
{
    if (kind_ == Kind::ChaCha)
        return chachaOpen(key_.data(), nonce, aad, sealed, plain);
    if (kind_ != Kind::AesGcm || sealed.size() < 16)
        return false;
    const auto size = sealed.size() - 16;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce.data());
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = const_cast<PUCHAR>(aad.data());
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = const_cast<PUCHAR>(sealed.data() + size);
    info.cbTag = 16;
    plain.assign(size + 1, 0);
    ULONG written = 0;
    if (BCryptDecrypt(handle_.get(), const_cast<PUCHAR>(sealed.data()), static_cast<ULONG>(size), &info, nullptr, 0,
        plain.data(), static_cast<ULONG>(plain.size()), &written, 0) < 0)
        return false;
    plain.resize(written);
    return true;
}

TlsDecryptor::TlsDecryptor(const KeyLog& keys, size_t queueLimit) : keys_(keys), queueLimit_(queueLimit) {}

size_t TlsDecryptor::memory() const
{
    size_t result = sizeof(*this) + keyBlock_.capacity() + reason_.capacity() + serverName_.capacity();
    for (const auto& side : sides_)
        result += side.buffer.capacity() + side.handshake.capacity() + side.queued + side.queue.size() * 32;
    return result;
}

std::string TlsDecryptor::reason() const
{
    if (state_ == State::Unsupported || state_ == State::Failed)
        return reason_;
    if (waiting())
        return secrets_ ? "The key log entry for this connection lacks the secrets needed to decrypt it." :
            "No TLS secrets were logged for this connection. The application must export them "
            "(SSLKEYLOGFILE) before it connects.";
    return {};
}

void TlsDecryptor::fail(State state, std::string reason)
{
    if (finished())
        return;
    state_ = state;
    reason_ = std::move(reason);
    for (auto& side : sides_)
    {
        side.buffer = {};
        side.handshake = {};
        side.queue.clear();
        side.queued = 0;
    }
}

void TlsDecryptor::feed(int direction, Bytes bytes, int64_t timestampUs, const Sink& sink)
{
    recordUs_ = timestampUs;
    if (finished())
        return;
    try
    {
        auto& side = sides_[direction];
        side.buffer.insert(side.buffer.end(), bytes.begin(), bytes.end());
        size_t offset = 0;
        while (!finished() && side.buffer.size() - offset >= 5)
        {
            const Bytes header(side.buffer.data() + offset, 5);
            const auto length = size_t{be16(header, 3)};
            if (header[0] < 20 || header[0] > 23 || header[1] != 3 || length > MaximumRecord)
            {
                fail(State::Failed, "The stream is not a TLS record stream.");
                break;
            }
            if (side.buffer.size() - offset < 5 + length)
                break;
            recordUs_ = timestampUs;
            record(direction, header[0], Bytes(side.buffer.data() + offset + 5, length), sink);
            offset += 5 + length;
        }
        if (finished())
            return;
        side.buffer.erase(side.buffer.begin(), side.buffer.begin() + static_cast<ptrdiff_t>(offset));
        drain(sink);
    }
    catch (const std::exception& error)
    {
        fail(State::Failed, error.what());
    }
}

void TlsDecryptor::retry(const Sink& sink)
{
    if (!waiting() || finished() || keys_.generation() == generation_)
        return;
    try { drain(sink); }
    catch (const std::exception& error) { fail(State::Failed, error.what()); }
}

void TlsDecryptor::record(int direction, uint8_t type, Bytes fragment, const Sink& sink)
{
    auto& side = sides_[direction];
    if (side.queue.empty() && handle(direction, type, fragment, sink) == Result::Done)
        return;
    if (finished())
        return;

    // Records wait, in order, for the application to log the secrets that open them.
    Buffer copy{type};
    appendBytes(copy, fragment);
    side.queued += copy.size();
    side.queue.push_back({std::move(copy), recordUs_});
    if (sides_[0].queued + sides_[1].queued > queueLimit_)
    {
        const auto text = reason();
        fail(State::Unsupported, text);
    }
}

void TlsDecryptor::drain(const Sink& sink)
{
    for (int direction = 0; direction < 2; ++direction)
    {
        auto& side = sides_[direction];
        while (!side.queue.empty() && !finished())
        {
            const auto& front = side.queue.front();
            recordUs_ = front.timestampUs;
            if (handle(direction, front.bytes[0], Bytes(front.bytes).subspan(1), sink) == Result::NeedSecrets)
                break;
            if (finished())
                return;
            side.queued -= front.bytes.size();
            side.queue.pop_front();
        }
    }
}

TlsDecryptor::Result TlsDecryptor::handle(int direction, uint8_t type, Bytes fragment, const Sink& sink)
{
    auto& side = sides_[direction];
    if (side.protectedRecords)
        return openRecord(direction, type, fragment, sink);

    // Hellos and, through TLS 1.2, the rest of the handshake are readable until encryption begins.
    if (type == 22)
    {
        side.handshake.insert(side.handshake.end(), fragment.begin(), fragment.end());
        if (!handshakeMessages(direction, false))
            fail(State::Failed, "A TLS handshake message was malformed.");
    }
    else if (type == 20 && haveServer_ && !tls13_)
    {
        side.protectedRecords = true;
        side.sequence = 0;
        side.aead = {};
    }
    else if (type == 23)
        fail(State::Unsupported, direction == 0 && !haveServer_ ? "TLS 1.3 early data is not decoded." :
            "Application data arrived before the handshake finished.");
    return Result::Done;
}

TlsDecryptor::Result TlsDecryptor::openRecord(int direction, uint8_t type, Bytes fragment, const Sink& sink)
{
    auto& side = sides_[direction];

    // A TLS 1.3 compatibility change_cipher_spec record is neither encrypted nor counted.
    if (tls13_ && (type == 20 || type == 21))
        return Result::Done;
    if (!secretsFor(direction))
        return Result::NeedSecrets;
    Buffer plain;
    const auto failure = "A record failed authentication; the logged secrets do not match this connection, "
        "or capture missed a packet.";
    std::array<uint8_t, 12> nonce = side.iv;
    std::array<uint8_t, 13> aad{};
    if (tls13_)
    {
        if (type != 23 || fragment.size() < 17)
        {
            fail(State::Failed, "Unexpected record type in an encrypted TLS 1.3 stream.");
            return Result::Done;
        }
        for (int i = 0; i < 8; ++i)
            nonce[11 - i] ^= static_cast<uint8_t>(side.sequence >> (8 * i));
        aad = {23, 3, 3, static_cast<uint8_t>(fragment.size() >> 8), static_cast<uint8_t>(fragment.size())};
        if (!side.aead.open(Bytes(nonce).first(12), Bytes(aad).first(5), fragment, plain))
        {
            fail(State::Failed, failure);
            return Result::Done;
        }
        ++side.sequence;
        while (!plain.empty() && plain.back() == 0)
            plain.pop_back();
        if (plain.empty())
        {
            fail(State::Failed, "An encrypted TLS 1.3 record had no content type.");
            return Result::Done;
        }
        const auto inner = plain.back();
        plain.pop_back();
        if (inner == 23 && side.application && !plain.empty())
            sink(direction, plain, recordUs_);
        else if (inner == 22)
        {
            side.handshake.insert(side.handshake.end(), plain.begin(), plain.end());
            if (!handshakeMessages(direction, true))
                fail(State::Failed, "An encrypted TLS handshake message was malformed.");
        }
        return Result::Done;
    }
    if (type == 20)
    {
        fail(State::Unsupported, "TLS renegotiation is not decoded.");
        return Result::Done;
    }
    Bytes sealed = fragment;
    if (suite_.kind == Aead::Kind::AesGcm)
    {
        if (fragment.size() < 24)
        {
            fail(State::Failed, failure);
            return Result::Done;
        }
        std::copy_n(fragment.begin(), 8, nonce.begin() + 4);
        sealed = fragment.subspan(8);
    }
    else
        for (int i = 0; i < 8; ++i)
            nonce[11 - i] ^= static_cast<uint8_t>(side.sequence >> (8 * i));
    for (int i = 0; i < 8; ++i)
        aad[7 - i] = static_cast<uint8_t>(side.sequence >> (8 * i));
    const auto length = sealed.size() - 16;
    aad[8] = type;
    aad[9] = 3;
    aad[10] = 3;
    aad[11] = static_cast<uint8_t>(length >> 8);
    aad[12] = static_cast<uint8_t>(length);
    if (!side.aead.open(nonce, aad, sealed, plain))
    {
        fail(State::Failed, failure);
        return Result::Done;
    }
    ++side.sequence;
    if (type == 23 && !plain.empty())
        sink(direction, plain, recordUs_);
    return Result::Done;
}

bool TlsDecryptor::handshakeMessages(int direction, bool encrypted)
{
    auto& side = sides_[direction];
    size_t offset = 0;
    bool valid = true;
    while (valid && !finished() && side.handshake.size() - offset >= 4)
    {
        const Bytes header(side.handshake.data() + offset, 4);
        const size_t length = (size_t{header[1]} << 16) | (size_t{header[2]} << 8) | header[3];
        if (length > MaximumHandshake)
        {
            valid = false;
            break;
        }
        if (side.handshake.size() - offset < 4 + length)
            break;
        const Bytes body(side.handshake.data() + offset + 4, length);
        const auto type = header[0];
        offset += 4 + length;
        if (!encrypted)
        {
            if (type == 1 && direction == 0)
                valid = parseClientHello(body);
            else if (type == 2 && direction == 1)
                valid = parseServerHello(body);
        }
        else if (tls13_ && type == 20 && !side.application)
        {
            // Everything after a side's Finished is protected by its application traffic keys.
            side.application = true;
            side.aead = {};
            side.secret.clear();
            side.sequence = 0;
        }
        else if (tls13_ && type == 24 && side.application && !side.secret.empty())
            install13(side, expandLabel(suite_.sha384, side.secret, "traffic upd", suite_.sha384 ? 48 : 32));
    }
    if (!finished())
        side.handshake.erase(side.handshake.begin(), side.handshake.begin() + static_cast<ptrdiff_t>(offset));
    return valid;
}

bool TlsDecryptor::parseClientHello(Bytes body)
{
    if (body.size() < 38)
        return false;
    size_t offset = 34;
    const auto session = body[offset++];
    offset += session;
    if (offset + 2 > body.size())
        return false;
    offset += 2 + be16(body, offset);
    if (offset + 1 > body.size())
        return false;
    offset += 1 + body[offset];
    if (haveServer_)
        return true;
    std::copy_n(body.begin() + 2, 32, clientRandom_.begin());
    haveClient_ = true;
    if (offset + 2 > body.size())
        return true;
    const auto end = std::min(body.size(), offset + 2 + be16(body, offset));
    for (offset += 2; offset + 4 <= end;)
    {
        const size_t type = be16(body, offset), length = be16(body, offset + 2);
        offset += 4;
        if (offset + length > end)
            return false;
        if (type == 0 && length >= 5 && body[offset + 2] == 0)
        {
            const size_t name = be16(body, offset + 3);
            if (offset + 5 + name <= end)
                serverName_.assign(reinterpret_cast<const char*>(body.data() + offset + 5), name);
        }
        offset += length;
    }
    return true;
}

bool TlsDecryptor::parseServerHello(Bytes body)
{
    if (body.size() < 38)
        return false;
    size_t offset = 34;
    offset += 1 + body[offset];
    if (offset + 3 > body.size())
        return false;
    const auto suite = be16(body, offset);
    offset += 3;
    uint16_t selected = be16(body, 0);
    std::string protocol;
    if (offset + 2 <= body.size())
    {
        const auto end = std::min(body.size(), offset + 2 + be16(body, offset));
        for (offset += 2; offset + 4 <= end;)
        {
            const size_t type = be16(body, offset), length = be16(body, offset + 2);
            offset += 4;
            if (offset + length > end)
                return false;
            if (type == 43 && length == 2)
                selected = be16(body, offset);
            else if (type == 16 && length >= 4 && body[offset + 2] + 3u == length)
                protocol.assign(reinterpret_cast<const char*>(body.data() + offset + 3), body[offset + 2]);
            offset += length;
        }
    }
    if (std::equal(RetryRandom, RetryRandom + 32, body.begin() + 2))
        return true;
    if (!haveClient_ || haveServer_)
        return true;
    std::copy_n(body.begin() + 2, 32, serverRandom_.begin());
    haveServer_ = true;
    cipher_ = suite;
    version_ = selected;
    alpn_ = protocol;
    tls13_ = selected == 0x0304;
    const bool sha384 = suite == 0x1302 || suite == 0xc02c || suite == 0xc030 || suite == 0x009d || suite == 0x009f;
    if (tls13_)
    {
        suite_ = {suite == 0x1303 ? Aead::Kind::ChaCha : Aead::Kind::AesGcm, suite == 0x1301 ? size_t{16} : 32, 12,
            sha384};
        if (suite < 0x1301 || suite > 0x1303)
        {
            fail(State::Unsupported, "Cipher suite " + hex16(suite) + " is not supported for decryption.");
            return true;
        }
        for (auto& side : sides_)
            side.protectedRecords = true;
        return true;
    }
    if (selected != 0x0303)
    {
        fail(State::Unsupported, versionName(selected) + " is not supported for decryption.");
        return true;
    }
    const bool chacha = suite == 0xcca8 || suite == 0xcca9 || suite == 0xccaa;
    const bool gcm128 = suite == 0xc02b || suite == 0xc02f || suite == 0x009c || suite == 0x009e;
    const bool gcm256 = sha384;
    if (!chacha && !gcm128 && !gcm256)
    {
        fail(State::Unsupported, "Cipher suite " + hex16(suite) + " is not supported for decryption.");
        return true;
    }
    suite_ = {chacha ? Aead::Kind::ChaCha : Aead::Kind::AesGcm, gcm128 ? size_t{16} : 32, chacha ? size_t{12} : 4,
        sha384};
    return true;
}

bool TlsDecryptor::install13(Side& side, Bytes secret)
{
    const auto key = expandLabel(suite_.sha384, secret, "key", suite_.keyBytes);
    const auto iv = expandLabel(suite_.sha384, secret, "iv", 12);
    side.aead = Aead(suite_.kind, key);
    std::copy(iv.begin(), iv.end(), side.iv.begin());
    side.secret.assign(secret.begin(), secret.end());
    side.sequence = 0;
    return true;
}

bool TlsDecryptor::secretsFor(int direction)
{
    auto& side = sides_[direction];
    if (side.aead)
        return true;
    if (!haveServer_)
        return false;
    const auto generation = keys_.generation();
    if (!secrets_ || generation != generation_)
    {
        secrets_ = keys_.find(clientRandom_);
        generation_ = generation;
    }
    if (!secrets_)
        return false;
    if (tls13_)
    {
        const auto& secret = side.application ? (direction == 0 ? secrets_->clientTraffic : secrets_->serverTraffic) :
            (direction == 0 ? secrets_->clientHandshake : secrets_->serverHandshake);
        return !secret.empty() && install13(side, secret);
    }
    if (secrets_->master.size() != 48)
        return false;
    if (keyBlock_.empty())
    {
        Buffer seed(serverRandom_.begin(), serverRandom_.end());
        seed.insert(seed.end(), clientRandom_.begin(), clientRandom_.end());
        keyBlock_ = prf(suite_.sha384, secrets_->master, "key expansion", seed,
            2 * (suite_.keyBytes + suite_.ivBytes));
    }
    const auto key = Bytes(keyBlock_).subspan(direction * suite_.keyBytes, suite_.keyBytes);
    side.aead = Aead(suite_.kind, key);
    std::copy_n(keyBlock_.begin() + static_cast<ptrdiff_t>(2 * suite_.keyBytes + direction * suite_.ivBytes),
        suite_.ivBytes, side.iv.begin());
    return true;
}
}
