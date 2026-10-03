#pragma once

#include "Tls.h"
#include "Quic.h"
#include "Protocols.h"
#include "Vpn.h"
#include "Network.h"
#include "Ipsec.h"
#include "Framing.h"
#include "TcpInspection.h"
#include "HttpSpy.h"
#include <memory>
#include <optional>
#include <unordered_map>

namespace Cipherazzi
{
struct EngineLimits
{
    size_t flows{32768};
    size_t bytes{128 * 1024 * 1024};
    int64_t idleUs{120 * 1000000LL};
    bool raw{};
    bool http{true};
};

class Engine
{
public:
    using Sink = std::function<void(Observation)>;
    Engine(Counters& counters, Sink sink, EngineLimits limits = {});
    void packet(Bytes bytes, PacketKind kind, int64_t timestampUs, PacketOrigin origin = PacketOrigin::Wire);
    void tcp(const TransportPacket& packet, int64_t timestampUs);
    void expire(int64_t timestampUs, bool all = false);

    // Decodes HTTP carried by the TCP connections that are reassembled; the object must outlive the engine.
    void httpSpy(HttpSpy* plus) { plus_ = plus; }

private:

    // Include every transport in shared admission, inspection, and capture-health accounting.
    size_t flowCount() const
    {
        return flows_.size() + closedHttp_.size() + quicFlows_ + raw_.size() + dtls_.size() + kerberosFlows_ +
            roce_.count() + ipsec_.count();
    }
    size_t memory() const
    {
        return buffered_ + plusBytes_ + quicBytes_ + rawBytes_ + dtlsBytes_ + kerberosBytes_ + roce_.memory() +
            fragments_.memory() + ipsec_.memory();
    }
    struct Flow
    {
        std::unique_ptr<TcpInspection> inspection;
        std::unique_ptr<HttpSpyFlow> plus;
        size_t plusBytes{};
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
    struct ClosedHttp
    {
        std::unique_ptr<HttpSpyFlow> flow;
        size_t bytes{};
        int64_t endedUs{};
        std::string reason;
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
    struct PendingKerberos
    {
        enum class Kind : uint8_t { As, Tgs, Password } kind{};
        Observation observation;
        std::string requestDigest;
        size_t memory() const
        {
            return sizeof(*this) - sizeof(observation) + observation.memory() + requestDigest.capacity();
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
    bool observeQuic(const TransportPacket& packet, int64_t timestampUs);
    void quicPath(QuicFlow& flow, const TransportPacket& packet, bool client, int64_t timestampUs);
    void inspectIpsec(const TransportPacket& packet, int64_t timestampUs);
    bool inspectDtls(const TransportPacket& packet, int64_t timestampUs);
    void udp(const TransportPacket& packet, int64_t timestampUs);
    bool inspectVpn(const TransportPacket& packet, int64_t timestampUs);
    bool inspectKerberos(const TransportPacket& packet, int64_t timestampUs);
    bool inspectLdap(const TransportPacket& packet, int64_t timestampUs);
    void sampleUdp(const TransportPacket& packet, int64_t timestampUs);
    void emit(Observation& observation, std::string_view reason = {});
    void retire(Flow& flow, std::string_view reason);
    void close(Flow& flow, std::string_view reason);
    void followHttp(Flow& flow, const TransportPacket& packet, int64_t timestampUs);
    void releaseHttp(Flow& flow, int64_t timestampUs, std::string_view reason);
    void end(uint64_t flowId, int64_t endedUs, std::string_view reason);
    void publishUsage();
    Counters& counters_;
    Sink sink_;
    HttpSpy* plus_{};
    EngineLimits limits_;
    std::unordered_map<FlowKey, Flow, FlowHash> flows_;
    std::deque<ClosedHttp> closedHttp_;
    std::unordered_map<FlowKey, std::vector<std::unique_ptr<QuicFlow>>, FlowHash> quic_;
    std::unordered_map<FlowKey, RawFlow, FlowHash> raw_;
    std::unordered_map<FlowKey, DtlsFlow, FlowHash> dtls_;
    std::unordered_map<FlowKey, std::vector<PendingKerberos>, FlowHash> kerberos_;
    std::unordered_map<std::string, CidEntry, CidHash, std::equal_to<>> quicIds_;
    std::bitset<21> cidLengths_;
    IpFragments fragments_;
    RoceConnections roce_;
    IpsecConnections ipsec_;
    size_t dtlsBytes_{};
    size_t kerberosFlows_{}, kerberosBytes_{};
    size_t quicFlows_{}, quicBytes_{};
    size_t rawBytes_{};
    size_t buffered_{}, plusBytes_{};
    uint64_t nextId_{};
    int64_t nextExpiry_{};
};
}
