#include "Tls.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>

namespace Cipherazzi
{
class Cursor
{
public:
    explicit Cursor(Bytes bytes) : bytes_(bytes) {}
    bool take(size_t size, Bytes& result)
    {
        if (size > bytes_.size())
            return false;
        result = bytes_.first(size);
        bytes_ = bytes_.subspan(size);
        return true;
    }
    bool skip(size_t size)
    {
        Bytes ignored;
        return take(size, ignored);
    }
    bool vector8(Bytes& result)
    {
        if (bytes_.empty())
            return false;
        const auto size = bytes_[0];
        bytes_ = bytes_.subspan(1);
        return take(size, result);
    }
    bool vector16(Bytes& result)
    {
        uint16_t size;
        return word(size) && take(size, result);
    }
    bool byte(uint8_t& result)
    {
        if (bytes_.empty())
            return false;
        result = bytes_[0];
        bytes_ = bytes_.subspan(1);
        return true;
    }
    bool vector24(Bytes& result)
    {
        if (bytes_.size() < 3)
            return false;
        const size_t size = (static_cast<size_t>(bytes_[0]) << 16) | be16(bytes_, 1);
        bytes_ = bytes_.subspan(3);
        return take(size, result);
    }
    bool word(uint16_t& result)
    {
        if (bytes_.size() < 2)
            return false;
        result = be16(bytes_, 0);
        bytes_ = bytes_.subspan(2);
        return true;
    }
    bool empty() const { return bytes_.empty(); }

private:
    Bytes bytes_;
};

std::string printable(Bytes bytes)
{
    std::string result;
    for (const auto value : bytes)
    {
        if (value >= 0x20 && value < 0x7f && value != '\\')
            result += static_cast<char>(value);
        else
        {
            constexpr char digits[] = "0123456789ABCDEF";
            result += "\\x";
            result += digits[value >> 4];
            result += digits[value & 15];
        }
    }
    return result;
}

bool parseHello(Bytes bytes, Hello& hello, bool dtls)
{
    // Consume the fixed hello fields before processing length-delimited extensions.
    Cursor cursor(bytes);
    Bytes random, session, value;
    if (!cursor.word(hello.version) || (dtls ? hello.version != 0xfeff && hello.version != 0xfefd :
        hello.version < 0x0300 || hello.version > 0x0303) ||
        !cursor.take(32, random) || !cursor.vector8(session) || session.size() > 32)
        return false;
    if (dtls && hello.client && !cursor.vector8(value))
        return false;

    auto finishVersion = [&]
    {
        if (dtls)
        {
            hello.dtlsVersion = hello.version;
            hello.version = hello.version == 0xfefc ? 0x0304 : hello.version == 0xfefd ? 0x0303 :
                hello.version == 0xfeff ? 0x0302 : 0;
            if (!hello.version)
                return false;
        }
        return true;
    };

    constexpr std::array<uint8_t, 32> retryRandom{
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    hello.retry = !hello.client && std::ranges::equal(random, retryRandom);
    auto& crypto = hello.crypto;
    auto& stage = hello.stage;
    stage.type = hello.client ? NegotiationStage::Type::ClientHello : hello.retry ?
        NegotiationStage::Type::HelloRetryRequest : NegotiationStage::Type::ServerHello;
    stage.legacyVersion = hello.version;
    stage.handshakeBytes = static_cast<uint32_t>(bytes.size() + (dtls ? 12 : 4));
    (hello.client ? crypto.clientSession : crypto.serverSession).assign(session.begin(), session.end());
    crypto.emsOffered = crypto.earlyDataOffered = crypto.ticketOffered = hello.client ? 0 : -1;
    crypto.emsSelected = crypto.secureRenegotiation = hello.client ? -1 : 0;
    if (!hello.client && random.size() == 32 && random[24] == 'D' && random[25] == 'O' &&
        random[26] == 'W' && random[27] == 'N' && random[28] == 'G' && random[29] == 'R' && random[30] == 'D')
        crypto.downgrade = random[31] == 1 ? "TLS 1.2 downgrade sentinel" :
            random[31] == 0 ? "TLS 1.1 or earlier downgrade sentinel" : "";
    if (hello.client)
    {
        if (!cursor.vector16(value) || value.empty() || value.size() % 2 != 0 || value.size() > 4096)
            return false;
        stage.ciphers.reserve(value.size() / 2);
        for (size_t i = 0; i < value.size(); i += 2)
        {
            stage.ciphers.push_back(be16(value, i));
            if (i)
                hello.ciphers += ", ";
            hello.ciphers += hex16(be16(value, i));
        }
        if (!cursor.vector8(value) || value.empty())
            return false;
        hello.versions = versionName(hello.version);
    }
    else
    {
        uint8_t compression;
        if (!cursor.word(hello.cipher) || !cursor.byte(compression))
            return false;
        crypto.compression = compression;
        stage.cipherId = hello.cipher;
        stage.selectedVersion = hello.version;
    }

    if (cursor.empty())
        return finishVersion();
    Bytes extensions;
    if (!cursor.vector16(extensions) || !cursor.empty())
        return false;
    Cursor extensionCursor(extensions);
    auto& seen = stage.extensions;
    while (!extensionCursor.empty())
    {
        uint16_t type;
        if (!extensionCursor.word(type) || !extensionCursor.vector16(value) ||
            std::ranges::find(seen, type) != seen.end() || seen.size() >= 256)
            return false;
        seen.push_back(type);
        auto& extensionNames = hello.client ? crypto.clientExtensions : crypto.serverExtensions;
        if (!extensionNames.empty())
            extensionNames += ", ";
        extensionNames += hex16(type);
        Cursor extension(value);

        // Server supported_versions selects TLS 1.3 despite its legacy_version field.
        if (type == 43)
        {
            if (hello.client)
            {
                Bytes versions;
                if (!extension.vector8(versions) || !extension.empty() || versions.empty() || versions.size() % 2)
                    return false;
                hello.versions.clear();
                stage.versions.clear();
                stage.versions.reserve(versions.size() / 2);
                for (size_t i = 0; i < versions.size(); i += 2)
                {
                    stage.versions.push_back(be16(versions, i));
                    if (i)
                        hello.versions += ", ";
                    hello.versions += versionName(be16(versions, i));
                }
            }
            else if (!extension.word(hello.version) || !extension.empty())
                return false;
            else
                stage.selectedVersion = hello.version;
        }
        else if (type == 0 && hello.client)
        {
            Bytes names;
            if (!extension.vector16(names) || !extension.empty() || names.empty())
                return false;
            Cursor nameCursor(names);
            while (!nameCursor.empty())
            {
                Bytes nameType, name;
                if (!nameCursor.take(1, nameType) || !nameCursor.vector16(name) || name.empty())
                    return false;
                if (nameType[0] == 0)
                {
                    if (!hello.sni.empty() || name.size() > 253 ||
                        std::ranges::any_of(name, [](uint8_t c) { return c < 0x21 || c > 0x7e; }))
                        return false;
                    hello.sni.assign(reinterpret_cast<const char*>(name.data()), name.size());
                    stage.sni = hello.sni;
                }
            }
        }
        else if (type == 16)
        {
            Bytes protocols;
            if (!extension.vector16(protocols) || !extension.empty() || protocols.empty())
                return false;
            Cursor protocolCursor(protocols);
            size_t count = 0;
            while (!protocolCursor.empty())
            {
                Bytes protocol;
                if (!protocolCursor.vector8(protocol) || protocol.empty() || ++count > 64)
                    return false;
                if (!hello.alpn.empty())
                    hello.alpn += ", ";
                hello.alpn += printable(protocol);
            }
            if (!hello.client && count != 1)
                return false;
            stage.alpn = hello.alpn;
        }
        else if (type == 14 && dtls)
        {
            Bytes profiles, mki;
            if (!extension.vector16(profiles) || profiles.empty() || profiles.size() % 2 ||
                profiles.size() > 512 || (!hello.client && profiles.size() != 2) ||
                !extension.vector8(mki) || !extension.empty())
                return false;
            for (size_t offset = 0; offset < profiles.size(); offset += 2)
            {
                const auto profile = be16(profiles, offset);
                if (hello.client)
                {
                    if (std::ranges::find(crypto.srtpProfiles, profile) != crypto.srtpProfiles.end())
                        return false;
                    crypto.srtpProfiles.push_back(profile);
                }
                else
                    crypto.selectedSrtpProfile = profile;
            }
        }
        else if (type == 0xfe0d && hello.client)
            stage.ech = hello.ech = true;
        else if ((type == 10 || type == 13 || type == 50) && hello.client)
        {
            Bytes values;
            if (!extension.vector16(values) || !extension.empty() || values.empty() || values.size() % 2 ||
                values.size() > 1024)
                return false;
            auto& list = type == 10 ? crypto.offeredGroups :
                type == 13 ? crypto.offeredSignatures : crypto.offeredCertificateSignatures;
            auto& ids = type == 10 ? stage.groups : type == 13 ? stage.signatures : stage.certificateSignatures;
            ids.reserve(values.size() / 2);
            for (size_t index = 0; index < values.size(); index += 2)
            {
                ids.push_back(be16(values, index));
                if (!list.empty())
                    list += ", ";
                list += type == 10 ? groupName(be16(values, index)) : signatureName(be16(values, index));
            }
        }
        else if (type == 51)
        {
            Bytes shares = value;
            if (hello.client && (!extension.vector16(shares) || !extension.empty()))
                return false;
            Cursor entries(shares);
            size_t count = 0;
            while (!entries.empty())
            {
                uint16_t group;
                Bytes share;
                if (!entries.word(group) || (!hello.retry && (!entries.vector16(share) || share.empty())) ||
                    ++count > 64)
                    return false;
                if (hello.client)
                {
                    if (!crypto.offeredKeyShares.empty())
                        crypto.offeredKeyShares += ", ";
                    crypto.offeredKeyShares += groupName(group);
                }
                else
                {
                    if (!entries.empty())
                        return false;
                    crypto.groupId = group;
                    crypto.group = groupName(group);
                    stage.selectedGroupId = group;
                }
                if (!hello.retry)
                    stage.keyShares.push_back({group, static_cast<uint16_t>(share.size())});
            }
            if (!hello.client && count != 1)
                return false;
        }
        else if (type == 45 && hello.client)
        {
            Bytes modes;
            if (!extension.vector8(modes) || !extension.empty() || modes.empty())
                return false;
            for (auto mode : modes)
            {
                if (!crypto.offeredPskModes.empty())
                    crypto.offeredPskModes += ", ";
                crypto.offeredPskModes += mode == 0 ? "PSK only" : mode == 1 ? "PSK + asymmetric" :
                    std::to_string(mode);
            }
        }
        else if (type == 41)
        {
            if (hello.client)
            {
                Bytes identities, binders;
                if (!extension.vector16(identities) || !extension.vector16(binders) || !extension.empty())
                    return false;
                Cursor identity(identities), binder(binders);
                int count = 0, binderCount = 0;
                while (!identity.empty())
                {
                    Bytes label;
                    if (!identity.vector16(label) || label.empty() || !identity.skip(4) || ++count > 64)
                        return false;
                }
                while (!binder.empty())
                {
                    Bytes hash;
                    if (!binder.vector8(hash) || hash.size() < 32 || ++binderCount > 64)
                        return false;
                }
                if (!count || count != binderCount)
                    return false;
                crypto.pskOffers = count;
            }
            else
            {
                uint16_t index;
                if (!extension.word(index) || !extension.empty())
                    return false;
                crypto.selectedPsk = index;
            }
        }
        else if (type == 42 && hello.client)
        {
            if (!value.empty())
                return false;
            crypto.earlyDataOffered = 1;
        }
        else if (type == 23)
        {
            if (!value.empty())
                return false;
            (hello.client ? crypto.emsOffered : crypto.emsSelected) = 1;
        }
        else if (type == 35 && hello.client)
            crypto.ticketOffered = 1;
        else if (type == 0xff01 && !hello.client)
        {
            Bytes renegotiated;
            if (!extension.vector8(renegotiated) || !extension.empty())
                return false;
            crypto.secureRenegotiation = 1;
        }
    }
    return finishVersion();
}

bool parseKeyExchange(Bytes bytes, uint16_t version, uint16_t cipher, Observation::Crypto& crypto)
{
    // Parse only cipher families with known ServerKeyExchange layouts.
    const auto name = cipherName(cipher);
    const bool ecdhe = name.find("_ECDHE_") != std::string::npos;
    const bool dhe = name.find("_DHE_") != std::string::npos || name.find("_DH_anon_") != std::string::npos;
    if ((!ecdhe && !dhe) || name.find("PSK") != std::string::npos)
        return true;
    Cursor cursor(bytes);
    Bytes value;
    if (ecdhe)
    {
        uint8_t curveType;
        uint16_t group;
        if (!cursor.byte(curveType) || curveType != 3 || !cursor.word(group) ||
            !cursor.vector8(value) || value.empty())
            return false;
        crypto.groupId = group;
        crypto.group = groupName(group);
    }
    else
    {
        if (!cursor.vector16(value) || value.empty())
            return false;
        size_t zeros = 0;
        while (zeros < value.size() && value[zeros] == 0)
            ++zeros;
        crypto.dhBits = zeros == value.size() ? 0 : static_cast<int>((value.size() - zeros - 1) * 8 +
            std::bit_width(static_cast<unsigned>(value[zeros])));
        crypto.group = "DHE " + std::to_string(crypto.dhBits) + " bits";
        if (!cursor.vector16(value) || value.empty() || !cursor.vector16(value) || value.empty())
            return false;
    }
    if (name.find("_anon_") != std::string::npos)
        return cursor.empty();
    if (version >= 0x0303)
    {
        uint16_t signature;
        if (!cursor.word(signature))
            return false;
        crypto.signature = signatureName(signature);
    }
    return cursor.vector16(value) && !value.empty() && cursor.empty();
}

void applyHello(Observation& observation, const Hello& hello, int64_t timestampUs)
{
    auto& crypto = observation.crypto;
    if (hello.dtlsVersion && (!hello.client || !observation.serverHello))
        observation.dtlsVersion = hello.dtlsVersion;
    // Retain wire-order negotiation evidence with a strict per-flow allocation bound.
    if (crypto.stages.size() < 8)
    {
        crypto.stages.push_back(hello.stage);
        crypto.stages.back().timestampUs = timestampUs;
    }
    else if (crypto.stagesDropped < UINT32_MAX)
        ++crypto.stagesDropped;
    if (hello.client)
    {
        observation.clientHello = true;
        observation.sni = hello.sni;
        observation.offeredVersions = hello.versions;
        observation.offeredCiphers = hello.ciphers;
        observation.offeredAlpn = hello.alpn;
        observation.echOffered = hello.ech;
        const auto& c = hello.crypto;
        crypto.offeredGroups = c.offeredGroups;
        crypto.srtpProfiles = c.srtpProfiles;
        crypto.offeredSignatures = c.offeredSignatures;
        crypto.offeredCertificateSignatures = c.offeredCertificateSignatures;
        crypto.offeredKeyShares = c.offeredKeyShares;
        crypto.clientExtensions = c.clientExtensions;
        crypto.offeredPskModes = c.offeredPskModes;
        crypto.clientSession = c.clientSession;
        crypto.emsOffered = c.emsOffered;
        crypto.earlyDataOffered = std::max(crypto.earlyDataOffered, c.earlyDataOffered);
        crypto.ticketOffered = c.ticketOffered;
        crypto.pskOffers = c.pskOffers;
        if (!crypto.clientHelloUs)
            crypto.clientHelloUs = timestampUs;
    }
    else if (hello.retry)
    {
        observation.retrySeen = true;
        crypto.retryUs = timestampUs;
        crypto.retryGroupId = hello.crypto.groupId;
    }
    else
    {
        observation.serverHello = true;
        observation.version = hello.version;
        observation.cipher = hello.cipher;
        observation.selectedAlpn = hello.version < 0x0304 ? hello.alpn : "";
        const auto& c = hello.crypto;
        crypto.groupId = c.groupId;
        crypto.group = c.group;
        crypto.serverExtensions = c.serverExtensions;
        crypto.selectedSrtpProfile = hello.dtlsVersion && hello.version < 0x0304 ? c.selectedSrtpProfile : -1;
        crypto.serverSession = c.serverSession;
        crypto.compression = c.compression;
        crypto.emsSelected = c.emsSelected;
        crypto.secureRenegotiation = c.secureRenegotiation;
        crypto.downgrade = c.downgrade;
        crypto.selectedPsk = c.selectedPsk;
        crypto.serverHelloUs = timestampUs;
    }
}

bool TlsStream::feedHandshake(Bytes bytes, const Sink& sink)
{
    if (handshake_.size() + bytes.size() > 131076)
    {
        limited_ = true;
        return false;
    }
    handshake_.insert(handshake_.end(), bytes.begin(), bytes.end());
    return parseHandshake(sink);
}

bool TlsStream::parseHandshake(const Sink& sink)
{
    // Handshake messages may span TLS records as well as TCP segments.
    size_t consumed = 0;
    while (handshake_.size() - consumed >= 4)
    {
        const Bytes pending = Bytes(handshake_).subspan(consumed);
        const size_t size = (static_cast<size_t>(pending[1]) << 16) | be16(pending, 2);
        if (size > 131072)
        {
            limited_ = true;
            return false;
        }
        if (pending.size() < size + 4)
            break;
        Hello hello;
        hello.type = pending[0];
        if (hello.type == 1 || hello.type == 2)
        {
            hello.client = pending[0] == 1;
            if (!parseHello(pending.subspan(4, size), hello))
            {
                malformed_ = true;
                return false;
            }
            sink(hello);
        }
        else if (hello.type == 11 || hello.type == 12 || hello.type == 13 || hello.type == 15 ||
            hello.type == 14)
        {
            if (hello.type == 11)
            {
                Cursor cursor(pending.subspan(4, size));
                Bytes chain;
                if (!cursor.vector24(chain) || !cursor.empty())
                {
                    malformed_ = true;
                    return false;
                }
                Cursor entries(chain);
                while (!entries.empty())
                {
                    Bytes certificate;
                    if (!entries.vector24(certificate) || certificate.empty() || certificate.size() > 65536 ||
                        hello.crypto.serverCertificates.size() >= 32)
                    {
                        limited_ = true;
                        return false;
                    }
                    hello.crypto.serverCertificates.push_back(
                        std::make_shared<const std::vector<uint8_t>>(certificate.begin(), certificate.end()));
                }
            }
            else
                hello.body.assign(pending.begin() + 4, pending.begin() + 4 + size);
            sink(hello);
        }
        consumed += size + 4;
        if (finished_)
            break;
    }
    handshake_.erase(handshake_.begin(), handshake_.begin() + consumed);
    return true;
}

bool TlsStream::feed(Bytes bytes, const Sink& sink)
{
    if (finished_)
        return true;
    if (records_.size() + bytes.size() > 262144)
    {
        limited_ = true;
        return false;
    }
    records_.insert(records_.end(), bytes.begin(), bytes.end());
    size_t consumed = 0;
    constexpr size_t ScanLimit = 1024 * 1024;
    while (records_.size() - consumed >= 5)
    {
        if (!synchronized_)
        {
            // Only a handshake or alert type can begin a record, so every other byte is passed over at once.
            const auto* start = records_.data() + consumed;
            const size_t positions = records_.size() - consumed - 4;
            auto* candidate = static_cast<const uint8_t*>(std::memchr(start, 22, positions));
            if (knownTls_)
                if (auto* alert = static_cast<const uint8_t*>(std::memchr(start, 21,
                    candidate ? static_cast<size_t>(candidate - start) : positions)))
                    candidate = alert;
            const size_t skipped = candidate ? static_cast<size_t>(candidate - start) : positions;
            consumed += skipped;
            scanned_ += skipped;
            if (scanned_ > ScanLimit)
            {
                limited_ = unmatched_ = true;
                return false;
            }
            if (!candidate)
                break;
        }
        const Bytes pending = Bytes(records_).subspan(consumed);
        const size_t size = be16(pending, 3);
        const bool header = pending[1] == 3 && pending[2] <= 3 && size > 0 && size <= 18432;
        if (!synchronized_)
        {
            // Scan a bounded plaintext prefix to discover STARTTLS on arbitrary ports.
            const bool hello = pending[0] == 22 &&
                (pending.size() == 5 || pending[5] == 1 || pending[5] == 2);
            const bool alert = knownTls_ && pending[0] == 21 && size == 2;
            if (!header || (!hello && !alert))
            {
                ++consumed;
                if (++scanned_ > ScanLimit)
                {
                    limited_ = unmatched_ = true;
                    return false;
                }
                continue;
            }
            if (pending.size() <= 5)
                break;
            synchronized_ = true;
        }
        if (!header || pending[0] < 20 || pending[0] > 23)
        {
            malformed_ = true;
            return false;
        }
        if (pending.size() < size + 5)
            break;
        if ((afterCcs_ && version_ < 0x0304) || pending[0] == 23)
        {
            Hello end;
            end.type = 253;
            sink(end);
            finished_ = true;
        }
        else if (pending[0] == 22)
        {
            if (handshake_.size() + size > 131076)
            {
                limited_ = true;
                return false;
            }
            handshake_.insert(handshake_.end(), pending.begin() + 5, pending.begin() + 5 + size);
            if (!parseHandshake(sink))
                return false;
        }
        else if (pending[0] == 21)
        {
            if (size != 2 || (pending[5] != 1 && pending[5] != 2))
            {
                malformed_ = true;
                return false;
            }
            Hello alert;
            alert.type = 254;
            alert.crypto.alertLevel = pending[5];
            alert.crypto.alertCode = pending[6];
            sink(alert);
            finished_ = pending[5] == 2 || pending[6] == 0;
        }
        else if (pending[0] == 20)
        {
            if (size != 1 || pending[5] != 1)
            {
                malformed_ = true;
                return false;
            }
            afterCcs_ = true;
        }
        consumed += size + 5;
        if (finished_)
            break;
    }
    records_.erase(records_.begin(), records_.begin() + consumed);
    if (finished_)
    {
        std::vector<uint8_t>().swap(records_);
        std::vector<uint8_t>().swap(handshake_);
    }
    return true;
}

size_t TlsStream::memory() const
{
    return records_.capacity() + handshake_.capacity();
}
}
