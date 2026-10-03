#include "Tls.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>

namespace Cipherazzi
{
namespace TlsDetail
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
}
using namespace TlsDetail;

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
        uint16_t cipher;
        uint8_t compression;
        if (!cursor.word(cipher) || !cursor.byte(compression))
            return false;
        hello.cipher = cipher;
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

bool parseKeyExchange(Bytes bytes, uint16_t version, uint32_t cipher, Observation::Crypto& crypto)
{
    // Parse only cipher families with known ServerKeyExchange layouts.
    const auto name = cipherName(cipher);
    const bool ecdhe = name.contains("_ECDHE_");
    const bool dhe = name.contains("_DHE_") || name.contains("_DH_anon_");
    if ((!ecdhe && !dhe) || name.contains("PSK"))
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
    if (name.contains("_anon_"))
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
        crypto.legacyHello = c.legacyHello;
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
        crypto.serverCiphers = c.serverCiphers;
        crypto.sessionHit = c.sessionHit;
        crypto.serverHelloUs = timestampUs;
    }
}

bool applyHandshake(Observation& observation, const Hello& message, bool client, bool legacy, int64_t timestampUs)
{
    auto& crypto = observation.crypto;
    if (message.type == AlertRecord)
    {
        crypto.alertCode = message.crypto.alertCode;
        crypto.alertLevel = message.crypto.alertLevel;
        crypto.alertUs = timestampUs;
        crypto.alertSide = client ? "Client" : "Server";
    }
    else if (message.type == Ssl2Error)
    {
        crypto.ssl2ErrorCode = message.crypto.ssl2ErrorCode;
        crypto.ssl2ErrorUs = timestampUs;
        crypto.ssl2ErrorSide = client ? "Client" : "Server";
    }
    else if (message.type == EndOfCleartext)
        (client ? crypto.clientCleartextEnded : crypto.serverCleartextEnded) = true;
    else if (!legacy)
        return true;
    else if (message.type == 11)
    {
        // The parser fills the server field with a certificate list from either peer.
        (client ? crypto.clientCertificates : crypto.serverCertificates) = message.crypto.serverCertificates;
        if (client)
            crypto.clientCertificatePresented = message.crypto.serverCertificates.empty() ? 0 : 1;
    }
    else if (message.type == ClientMasterKey)
    {
        if (client && observation.version <= 0x0002)
            observation.cipher = message.cipher;
    }
    else if (message.type == 12 && !client)
        return parseKeyExchange(message.body, observation.version, observation.cipher, crypto);
    else if (message.type == 13 && !client)
        crypto.certificateRequested = 1;
    else if (message.type == 14 && !client && crypto.certificateRequested < 0)
        crypto.certificateRequested = 0;
    else if (message.type == 15 && client && observation.version == 0x0303)
    {
        if (message.body.size() < 4 || be16(message.body, 2) != message.body.size() - 4)
            return false;
        crypto.clientSignature = signatureName(be16(message.body, 0));
    }
    return true;
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
                    if (!entries.vector24(certificate) || certificate.empty())
                    {
                        malformed_ = true;
                        return false;
                    }
                    if (certificate.size() > 65536 || hello.crypto.serverCertificates.size() >= 32)
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
    }
    handshake_.erase(handshake_.begin(), handshake_.begin() + consumed);
    return true;
}

bool TlsStream::legacyRecords(size_t& consumed, const Sink& sink)
{
    // Returns whether TLS records follow; otherwise the stream awaits more bytes or has nothing further in clear.
    for (;;)
    {
        if (records_.size() == consumed)
            return false;

        // A record without the length flag is TLS or, once SSL 2.0 is selected, a padded and so encrypted record.
        const Bytes pending = Bytes(records_).subspan(consumed);
        const bool selected = version_ == 0x0002;
        if (!(pending[0] & 0x80))
        {
            if (!selected)
                break;
            finished_ = true;
            return false;
        }
        if (pending.size() < 3)
            return false;
        const size_t size = ((pending[0] & 0x7f) << 8) | pending[1];

        // SSL 2.0 errors have a three-byte body: message type zero and a two-byte error code.
        if (size == 3 && pending[2] == 0)
        {
            if (pending.size() < 5)
                return false;
            const auto code = be16(pending, 3);
            if (code == 1 || code == 2 || code == 4 || code == 6 || knownTls_ || selected)
            {
                Hello error;
                error.type = Ssl2Error;
                error.crypto.ssl2ErrorCode = code;
                sink(error);
                consumed += 5;
                finished_ = true;
                return false;
            }
        }

        // After the hellos the client names the cipher it chose, and everything later is encrypted.
        if (legacy_ == Legacy::Hello || selected)
        {
            if (pending[2] == 2 && pending.size() < 12)
                return false;
            if (pending[2] == 2 && be16(pending, 8) &&
                size == size_t{10} + be16(pending, 6) + be16(pending, 8) + be16(pending, 10))
            {
                Hello chosen;
                chosen.type = ClientMasterKey;
                chosen.cipher = (static_cast<uint32_t>(pending[3]) << 16) | be16(pending, 4);
                sink(chosen);
            }
            finished_ = true;
            return false;
        }

        // A hello is taken to be SSL 2.0 only when its version and lengths account for the whole record: the client's
        // cipher specs, session ID, and challenge, or the server's certificate, cipher specs, and connection ID.
        const bool client = pending[2] == 1;
        if (!client && pending[2] != 4)
            break;
        if (pending.size() < 13)
            return false;
        const auto version = be16(pending, client ? 3 : 5);
        const size_t specs = be16(pending, client ? 5 : 9), nonce = be16(pending, client ? 9 : 11);
        const size_t session = client ? be16(pending, 7) : 0, certificate = client ? 0 : be16(pending, 7);
        const bool hit = !client && pending[3] != 0;
        if (specs % 3 || nonce < 16 || nonce > 32 ||
            size != (client ? 9 : 11) + specs + session + certificate + nonce ||
            (client ? !specs || (session && session != 16) ||
                    (version != 0x0002 && (version < 0x0300 || version > 0x0303)) :
                version != 0x0002 || pending[3] > 1 ||
                    (hit ? certificate || specs : !certificate || pending[4] != 1)))
            break;
        if (pending.size() < size + 2)
            return false;

        // Offers keep their identifiers, with TLS suites shown in two bytes; a server's list is short enough to name.
        Hello hello;
        hello.type = client ? 1 : 2;
        hello.client = client;
        hello.version = version;
        auto& crypto = hello.crypto;
        auto& stage = hello.stage;
        stage.type = client ? NegotiationStage::Type::ClientHello : NegotiationStage::Type::ServerHello;
        stage.legacyVersion = version;
        stage.handshakeBytes = static_cast<uint32_t>(size);
        const auto list = pending.subspan(client ? 11 : 13 + certificate, specs);
        auto& names = client ? hello.ciphers : crypto.serverCiphers;
        bool kinds = false;
        for (size_t index = 0; index < list.size(); index += 3)
        {
            const auto spec = (static_cast<uint32_t>(list[index]) << 16) | be16(list, index + 1);
            if (index)
                names += ", ";
            names += !client ? cipherName(spec) : spec > 0xffff ? hex24(spec) : hex16(static_cast<uint16_t>(spec));
            if (client)
                stage.ciphers.push_back(spec);
            kinds = kinds || spec > 0xffff;
        }
        if (client)
        {
            // Listing SSL 2.0 cipher kinds beside a later version offers SSL 2.0 as well.
            hello.versions = versionName(version) + (kinds && version != 0x0002 ? ", SSL 2.0" : "");
            crypto.legacyHello = true;
            crypto.emsOffered = crypto.earlyDataOffered = crypto.ticketOffered = 0;
            crypto.clientSession.assign(pending.begin() + 11 + specs, pending.begin() + 11 + specs + session);
            legacy_ = Legacy::Hello;
        }
        else
        {
            stage.selectedVersion = version;
            crypto.sessionHit = hit;
        }
        sink(hello);
        if (certificate)
        {
            Hello chain;
            chain.type = 11;
            chain.crypto.serverCertificates.push_back(std::make_shared<const std::vector<uint8_t>>(
                pending.begin() + 13, pending.begin() + 13 + certificate));
            sink(chain);
        }
        consumed += size + 2;
        finished_ = !client;
        if (finished_)
            return false;
    }

    // TLS records that answer a hello in SSL 2.0 format begin here; elsewhere the plaintext scan continues.
    synchronized_ = legacy_ == Legacy::Hello;
    legacy_ = Legacy::None;
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
    const bool tls = legacy_ == Legacy::None || legacyRecords(consumed, sink);
    while (tls && records_.size() - consumed >= 5)
    {
        if (!synchronized_)
        {
            // Scan for TLS records and SSL 2.0 headers behind a bounded STARTTLS plaintext preface.
            const auto* start = records_.data() + consumed;
            const size_t positions = records_.size() - consumed - 4;
            auto* candidate = static_cast<const uint8_t*>(std::memchr(start, 22, positions));
            if (knownTls_)
                if (auto* alert = static_cast<const uint8_t*>(std::memchr(start, 21,
                    candidate ? static_cast<size_t>(candidate - start) : positions)))
                    candidate = alert;
            const auto* legacy = std::find_if(start, start + positions,
                [](uint8_t value) { return (value & 0x80) != 0; });
            if (legacy != start + positions && (!candidate || legacy < candidate))
                candidate = legacy;
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

            if (*candidate & 0x80)
            {
                const size_t before = consumed;
                legacy_ = Legacy::Start;
                if (!legacyRecords(consumed, sink))
                    break;
                if (consumed == before)
                {
                    ++consumed;
                    if (++scanned_ > ScanLimit)
                    {
                        limited_ = unmatched_ = true;
                        return false;
                    }
                }
                continue;
            }
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
            end.type = EndOfCleartext;
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
            alert.type = AlertRecord;
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
