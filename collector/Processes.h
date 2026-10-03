#pragma once

#include "Model.h"
#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace Cipherazzi
{
class Processes
{
public:
    explicit Processes(Counters& counters);
    ~Processes();
    Processes(const Processes&) = delete;
    Processes& operator=(const Processes&) = delete;
    void enrich(Observation& observation);
    void stop();
    const std::string& status() const { return status_; }
    static Owner describe(uint32_t pid, int64_t atUs, std::string evidence);

private:
    struct Connection
    {
        Endpoint local;
        Owner owner;
        int64_t startUs{};
        int64_t endUs{};
    };
    struct Lifetime
    {
        Owner owner;
        int64_t endedUs{};
    };
    static void WINAPI eventCallback(EVENT_RECORD* event) noexcept;
    static ULONG WINAPI bufferCallback(EVENT_TRACE_LOGFILEW* trace) noexcept;
    void event(const EVENT_RECORD& event);
    void processEvent(EVENT_RECORD& event);
    Owner lookup(uint32_t pid, int64_t atUs);
    void remember(Owner owner, int64_t endedUs = 0);
    void snapshot();
    void udpOwner(Observation& observation);
    std::vector<Connection> udpSnapshot_;
    std::vector<Endpoint> udpAddresses_;
    int64_t udpSnapshotUs_{};
    Counters& counters_;
    std::string status_;
    std::wstring name_;
    std::vector<uint8_t> properties_;
    TRACEHANDLE session_{};
    TRACEHANDLE trace_{INVALID_PROCESSTRACE_HANDLE};
    std::thread thread_;
    std::mutex mutex_;
    std::unordered_map<FlowKey, std::deque<Connection>, FlowHash> connections_;
    std::unordered_map<FlowKey, std::vector<Connection>, FlowHash> snapshot_;
    std::unordered_map<uint32_t, std::deque<Lifetime>> lifetimes_;
    size_t lifetimeBytes_{};
    int64_t snapshotUs_{};
    int64_t pruneUs_{};
};
}
