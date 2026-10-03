#pragma once

#include "Crypto.h"
#include "Rdma.h"

namespace Cipherazzi
{
bool parseSmb(Bytes bytes, nlohmann::json& fields, bool& limited);

// Derives the outcomes that depend on both peers' messages from a connection's merged evidence.
void resolveNegotiation(nlohmann::json& fields);

struct FramedMessage
{
    enum class Kind { Tls, OpenVpn, Smb, Rdp, Tds, Kerberos };
    Kind kind{};
    Bytes payload;
    nlohmann::json fields;
};

class FramedStream
{
public:
    using Sink = std::function<bool(const FramedMessage&)>;
    bool feed(Bytes bytes, const Sink& sink);
    size_t memory() const
    {
        return buffer_.capacity() + tdsMessage_.capacity() + (iwarp_ ? iwarp_->memory() : 0);
    }
    bool limited() const { return limited_ || (iwarp_ && iwarp_->limited()); }
    bool finished() const { return mode_ == Mode::Finished || (iwarp_ && iwarp_->finished()); }
    std::optional<uint8_t> mpaFlags() const { return iwarp_ ? iwarp_->flags() : std::nullopt; }
    void configureMpa(uint8_t peerFlags) { if (iwarp_) iwarp_->configurePeer(peerFlags); }

private:
    enum class Mode { Probe, Direct, Tds, Rdp, RdpData, Smb, OpenVpn, Kerberos, Finished };
    Mode mode_{};
    std::unique_ptr<IwarpStream> iwarp_;
    std::vector<uint8_t> buffer_, tdsMessage_;
    uint8_t tdsPacketId_{}, tdsPacketType_{};
    bool limited_{}, netbios_{}, tdsTls_{}, tdsPreloginSeen_{}, rdpRequest_{};
};
}
