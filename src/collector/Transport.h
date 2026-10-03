#pragma once

#include "Model.h"
#include <functional>
#include <optional>

namespace Cipherazzi
{
struct TransportPacket
{
    Endpoint source;
    Endpoint destination;
    uint32_t sequence{};
    uint8_t flags{};
    Bytes payload;
    bool truncated{};
    uint8_t protocol{6};
    uint32_t ipsecSpi{}, ipsecSequence{};
    uint8_t ipsecProtocol{};
    bool loopback{};
};

enum class PacketKind : uint16_t { Ethernet = 1, Ip = 3 };
enum class PacketOrigin : uint8_t { Wire, PacketMonitor, Loopback };
std::optional<TransportPacket> decodePacket(Bytes packet, PacketKind kind, Counters& counters,
    PacketOrigin origin = PacketOrigin::Wire);

class TcpStream
{
public:
    using Sink = std::function<bool(Bytes)>;
    void begin(uint32_t sequence);
    bool feed(uint32_t sequence, Bytes bytes, const Sink& sink);
    size_t memory() const;
    bool limited() const { return limited_; }
    bool malformed() const { return malformed_; }

    // Bytes beyond a hole are waiting for the missing ones.
    bool pending() const { return !pending_.empty(); }

private:
    struct Segment
    {
        uint32_t sequence{};
        std::vector<uint8_t> bytes;
    };
    std::vector<Segment> pending_;
    uint32_t next_{};
    bool initialized_{};
    bool limited_{};
    bool malformed_{};
};

}
