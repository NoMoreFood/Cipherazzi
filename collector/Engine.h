#pragma once

#include "Tls.h"
#include "Quic.h"
#include "Protocols.h"
#include "Vpn.h"
#include "Network.h"
#include "Framing.h"
#include <memory>
#include <optional>
#include <unordered_map>

namespace Cipherazzi
{
struct TcpPacket
{
    Endpoint source;
    Endpoint destination;
    uint32_t sequence{};
    uint8_t flags{};
    Bytes payload;
    bool truncated{};
    uint8_t protocol{6};
};

enum class PacketKind : uint16_t { Ethernet = 1, Ip = 3 };
enum class PacketOrigin : uint8_t { Wire, PacketMonitor, Loopback };
std::optional<TcpPacket> decodePacket(Bytes packet, PacketKind kind, Counters& counters,
    PacketOrigin origin = PacketOrigin::Wire);

class TcpStream
{
public:
    using Sink = std::function<bool(Bytes)>;
    void begin(uint32_t sequence);
    bool feed(uint32_t sequence, Bytes bytes, const Sink& sink);
    size_t memory() const;
    bool limited() const { return limited_; }

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
};

struct EngineLimits
{
    size_t flows{32768};
    size_t bytes{128 * 1024 * 1024};
    int64_t idleUs{120 * 1000000LL};
    bool raw{};
};

class Engine
{
public:
    using Sink = std::function<void(Observation)>;
    Engine(Counters& counters, Sink sink, EngineLimits limits = {});
    void packet(Bytes bytes, PacketKind kind, int64_t timestampUs, PacketOrigin origin = PacketOrigin::Wire);
    void tcp(const TcpPacket& packet, int64_t timestampUs);
    void expire(int64_t timestampUs, bool all = false);

private:
    // Include every transport in shared admission, inspection, and capture-health accounting.
    size_t flowCount() const { return flows_.size() + quicFlows_ + raw_.size() + dtls_.size() + roce_.count(); }
    size_t memory() const
    {
        return buffered_ + quicBytes_ + rawBytes_ + dtlsBytes_ + roce_.memory() + fragments_.memory();
    }
    struct Inspection
    {
        TcpStream streams[2];
        TlsStream tls[2];
        SshStream ssh[2];
        FramedStream framing[2];
        std::unique_ptr<std::array<OpenVpnStream, 2>> vpnStreams;
        std::unique_ptr<PayloadSample> samples[2];
        int sourceDirection{-1};
        bool rolesKnown{};
        Observation observation;
        size_t memory() const
        {
            return sizeof(*this) - sizeof(observation) + streams[0].memory() + streams[1].memory() +
                tls[0].memory() + tls[1].memory() + ssh[0].memory() + ssh[1].memory() + observation.memory() +
                framing[0].memory() + framing[1].memory() +
                (vpnStreams ? (*vpnStreams)[0].memory() + (*vpnStreams)[1].memory() : 0) +
                (samples[0] ? sizeof(PayloadSample) : 0) + (samples[1] ? sizeof(PayloadSample) : 0);
        }
    };
    struct Flow
    {
        std::unique_ptr<Inspection> inspection;
        int64_t lastUs{};
        uint64_t id{};
        bool observed{};
        std::optional<uint32_t> syn[2];
        bool fin[2]{};
    };
    struct QuicFlow
    {
        Observation observation;
        std::unique_ptr<QuicConnection> inspection;
        int64_t lastUs{};
        bool observed{}, serverInitialSeen{};
        std::vector<std::pair<std::string, bool>> indexedIds;
        size_t memory() const
        {
            size_t result = sizeof(*this) + 512 + observation.memory() + (inspection ? inspection->memory() : 0) +
                indexedIds.capacity() * sizeof(indexedIds[0]);
            for (const auto& id : indexedIds)
                result += id.first.capacity();
            return result;
        }
    };
    struct RawFlow
    {
        Observation observation;
        PayloadSample samples[2];
        std::unique_ptr<std::array<OpenVpnStream, 2>> vpnStreams;
        int64_t lastUs{};
        bool observed{};
        size_t memory() const
        {
            return sizeof(*this) - sizeof(observation) + observation.memory() +
                (vpnStreams ? (*vpnStreams)[0].memory() + (*vpnStreams)[1].memory() : 0);
        }
    };
    struct DtlsFlow
    {
        Observation observation;
        std::unique_ptr<std::array<DtlsStream, 2>> streams;
        int64_t lastUs{};
        bool observed{};
        size_t memory() const
        {
            return sizeof(*this) - sizeof(observation) + observation.memory() +
                (streams ? (*streams)[0].memory() + (*streams)[1].memory() : 0);
        }
    };
    struct CidOwner { QuicFlow* flow; bool client; };
    struct CidEntry { std::vector<CidOwner> owners; size_t references{}; };
    struct CidHash
    {
        using is_transparent = void;
        size_t operator()(std::string_view value) const { return std::hash<std::string_view>{}(value); }
    };
    void indexQuic(QuicFlow& flow, bool remove = false);
    QuicFlow* findQuic(Bytes cid, bool& client) const;
    bool observeQuic(const TcpPacket& packet, int64_t timestampUs);
    void quicPath(QuicFlow& flow, const TcpPacket& packet, bool client, int64_t timestampUs);
    bool inspectDtls(const TcpPacket& packet, int64_t timestampUs);
    void udp(const TcpPacket& packet, int64_t timestampUs);
    bool inspectVpn(const TcpPacket& packet, int64_t timestampUs);
    bool inspectKerberos(const TcpPacket& packet, int64_t timestampUs);
    void sampleUdp(const TcpPacket& packet, int64_t timestampUs);
    void emit(Observation& observation, std::string_view reason = {});
    void retire(Flow& flow, std::string_view reason);
    void close(Flow& flow, std::string_view reason);
    Counters& counters_;
    Sink sink_;
    EngineLimits limits_;
    std::unordered_map<FlowKey, Flow, FlowHash> flows_;
    std::unordered_map<FlowKey, std::vector<std::unique_ptr<QuicFlow>>, FlowHash> quic_;
    std::unordered_map<FlowKey, RawFlow, FlowHash> raw_;
    std::unordered_map<FlowKey, DtlsFlow, FlowHash> dtls_;
    std::unordered_map<std::string, CidEntry, CidHash, std::equal_to<>> quicIds_;
    std::bitset<21> cidLengths_;
    IpFragments fragments_;
    RoceConnections roce_;
    size_t dtlsBytes_{};
    size_t quicFlows_{}, quicBytes_{};
    size_t rawBytes_{};
    size_t buffered_{};
    uint64_t nextId_{};
    int64_t nextExpiry_{};
};
}
