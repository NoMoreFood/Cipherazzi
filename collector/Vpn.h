#pragma once

#include "Tls.h"
#include "Crypto.h"
#include <map>
#include <optional>

namespace Cipherazzi
{
struct VpnEvidence
{
    nlohmann::json fields;
    size_t retainedBytes{};
};

struct VpnPacket
{
    Observation::Protocol protocol{};
    nlohmann::json fields;
    Bytes tls;
    uint32_t packetId{};
    bool client{true}, reset{};
};

std::optional<VpnPacket> parseVpn(Bytes bytes);
void applyVpn(Observation& observation, const VpnPacket& packet);
std::string protocolName(Observation::Protocol protocol);

class OpenVpnStream
{
public:
    bool feed(const VpnPacket& packet, const TlsStream::Sink& sink);
    void selectVersion(uint16_t version) { tls_.selectVersion(version); }
    size_t memory() const;

private:
    std::map<uint32_t, std::vector<uint8_t>> pending_;
    TlsStream tls_;
    uint32_t next_{1};
};
}
