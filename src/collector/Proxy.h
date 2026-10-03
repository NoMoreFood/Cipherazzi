#pragma once

#include "CertAuthority.h"
#include "HttpSpy.h"
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Cipherazzi
{
class Processes;

// Reserve upstream ports before connecting; retain the original client tuple while delayed attribution drains.
class UpstreamPorts
{
public:
    void add(Endpoint upstream, Endpoint client, Endpoint server, int64_t startedUs)
    {
        std::lock_guard lock(mutex_);
        const FlowKey key{upstream, {}};
        if (const auto previous = entries_.find(key); previous != entries_.end())
            startedUs = std::max(startedUs, previous->second.endedUs);
        entries_[key] = {upstream, client, server, startedUs, 0};
    }
    void release(Endpoint upstream, int64_t endedUs)
    {
        std::lock_guard lock(mutex_);
        if (auto it = entries_.find({upstream, {}}); it != entries_.end())
            it->second.endedUs = endedUs;
    }
    bool active(Endpoint upstream)
    {
        std::lock_guard lock(mutex_);
        const auto it = entries_.find({upstream, {}});
        return it != entries_.end() && !it->second.endedUs;
    }
    std::optional<Endpoint> client(const Observation& observation)
    {
        if (observation.udp || observation.quic || !(observation.ownerSides & 1))
            return {};
        std::lock_guard lock(mutex_);
        const auto it = entries_.find({observation.source, {}});
        if (it == entries_.end()) return {};
        const auto& entry = it->second;
        if (entry.upstream != observation.source || entry.server != observation.destination ||
            observation.firstUs < entry.startedUs || observation.lastUs < observation.firstUs ||
            (entry.endedUs && observation.lastUs > entry.endedUs))
            return {};
        return entry.client;
    }
    void expire()
    {
        std::lock_guard lock(mutex_);
        const auto now = nowUs();
        std::erase_if(entries_, [now](const auto& item)
        { return item.second.endedUs && now - item.second.endedUs > 120000000; });
    }
    void attribute(Observation& observation, Processes& processes);

private:
    struct Entry
    {
        Endpoint upstream, client, server;
        int64_t startedUs{}, endedUs{};
    };
    std::mutex mutex_;
    std::unordered_map<FlowKey, Entry, FlowHash> entries_;
};

struct ProxyTargets
{
    std::vector<std::string> hosts, processes;
    std::vector<uint16_t> ports{443};
    bool host(std::string_view value) const;
    bool process(uint32_t pid, std::string_view name) const;
    void setPorts(std::string_view value);
};

// Transparent HTTPS interception proxy. Uses WinDivert to reflect selected outbound connections to a local
// listener, performs Schannel TLS MITM with dynamically generated leaf certificates, relays HTTP/1.1, and
// emits decoded HttpExchange objects through the configured sink.
class Proxy
{
public:
    using Sink = std::function<void(HttpExchange)>;
    Proxy(CertAuthority& ca, HttpSpyOptions options, Sink sink, ProxyTargets targets = {});
    ~Proxy();
    Proxy(const Proxy&) = delete;
    Proxy& operator=(const Proxy&) = delete;

    void stop();
    void check();

    // The most recent distinct reasons a connection could not be intercepted.
    std::vector<std::string> failures();

    // The journal sees only the proxy's own connection to a server; this names the client process behind it.
    void attribute(Observation& observation, Processes& processes);

    std::atomic<uint64_t> connections{}, intercepted{}, relayed{}, failed{};
    std::atomic<uint64_t> exchanges{};

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
