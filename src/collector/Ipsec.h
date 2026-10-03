#pragma once

#include "Crypto.h"
#include <map>

namespace Cipherazzi
{
struct TransportPacket;

class IpsecConnections
{
public:
    explicit IpsecConnections(Counters& counters) : counters_(counters) {}
    void feed(const TransportPacket& packet, int64_t time, uint64_t& nextId, size_t budget, size_t limit,
        const std::function<void(Observation)>& sink);
    void expire(int64_t time, bool all, int64_t idle, const std::function<void(Observation)>& sink);
    size_t count() const { return flows_.size(); }
    size_t memory() const { return flows_.size() * 4096; }

private:
    struct Key
    {
        Endpoint source, destination;
        uint32_t spi{};
        uint8_t protocol{};
        auto operator<=>(const Key&) const = default;
    };
    struct Flow
    {
        Observation observation;
        uint64_t packets{};
        uint32_t sequence{};
        int64_t published{};
    };
    void publish(const Key& key, Flow& flow, const std::function<void(Observation)>& sink);
    Counters& counters_;
    std::map<Key, Flow> flows_;
};

class IpsecAssociations
{
public:
    void enrich(Observation& observation);

private:
    struct Entry
    {
        Endpoint source, destination;
        uint32_t spi{};
        uint8_t protocol{};
        nlohmann::json fields;
    };
    std::vector<Entry> entries_;
    int64_t refreshed_{};
    uint32_t error_{};
};
}
