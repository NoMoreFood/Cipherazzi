#pragma once

#include "Transport.h"
#include "Tls.h"
#include "Protocols.h"
#include "Framing.h"
#include "Vpn.h"

namespace Cipherazzi
{
// Owns one TCP connection's reassembly, negotiation, and evidence until inspection is retired.
class TcpInspection
{
public:
    enum class Result { Unchanged, Updated, Complete, Unrecognized, Malformed, Limited };
    TcpInspection(const FlowKey& key, uint64_t id, int64_t timestampUs,
        bool raw, bool http);
    Result feed(const TransportPacket& packet, int64_t timestampUs, size_t budget);
    void finishSamples();
    bool expired(int64_t timestampUs) const;
    size_t memory() const;
    Observation observation;

private:
    bool applyApplication(int frameDirection, const FramedMessage& framed, int64_t timestampUs, bool& updated);
    FlowKey key_;
    bool rawEnabled_{}, httpEnabled_{};
    TcpStream streams[2];
    TlsStream tls[2];
    SshStream ssh[2];
    FramedConnection framing;
    std::unique_ptr<std::array<OpenVpnStream, 2>> vpnStreams;
    std::unique_ptr<PayloadSample> samples[2];
    int sourceDirection{-1};
    int64_t handshakeStartedUs{};
    bool rolesKnown{};
};
}
