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
namespace Tests { struct ProcessAccess; }

class Processes
{
public:
    explicit Processes(Counters& counters);
    ~Processes();
    Processes(const Processes&) = delete;
    Processes& operator=(const Processes&) = delete;
    void enrich(Observation& observation);
    void recheck(Observation& observation);
    void validate(Owner& owner, int64_t firstUs, int64_t lastUs);
    std::vector<OwnerChange> changes();
    void stop();
    const std::string& status() const { return status_; }
    static Owner describe(uint32_t pid, int64_t atUs, std::string evidence);

private:
    friend struct Tests::ProcessAccess;
    struct Connection
    {
        Endpoint local;
        Owner owner;
        int64_t startUs{};
        int64_t endUs{};
    };
    struct SocketEvent
    {
        Endpoint local;
        uint32_t pid{}, id{};
        int64_t timestampUs{};
        bool closed{};
        bool matchedOpen{};
    };
    struct SocketHistory
    {
        std::deque<SocketEvent> events;
        bool incomplete[2]{};
        int64_t discardedThroughUs[2]{};
    };
    struct Lifetime
    {
        Owner owner;
        int64_t endedUs{};
        int64_t verifiedUs{};
    };
    struct LifetimeHistory
    {
        std::deque<Lifetime> entries;
        int64_t discardedThroughUs{};
        int64_t incompleteFromUs{};
    };
    static void WINAPI eventCallback(EVENT_RECORD* event) noexcept;
    static ULONG WINAPI bufferCallback(EVENT_TRACE_LOGFILEW* trace) noexcept;
    void event(const EVENT_RECORD& event);
    void processEvent(EVENT_RECORD& event);
    Owner lookup(uint32_t pid, int64_t firstUs, int64_t lastUs);
    void remember(Owner owner, int64_t endedUs = 0, int64_t verifiedUs = 0);
    void changed(OwnerChange change);
    void evidenceLost();
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
    std::unordered_map<FlowKey, SocketHistory, FlowHash> connections_;
    std::unordered_map<FlowKey, std::vector<Connection>, FlowHash> snapshot_;
    std::unordered_map<uint32_t, LifetimeHistory> lifetimes_;
    std::unordered_map<FlowKey, std::array<std::optional<int64_t>, 2>, FlowHash> changedConnections_;
    std::unordered_map<uint32_t, int64_t> changedProcesses_;
    size_t changedSockets_{};
    bool changesIncomplete_{};
    uint32_t traceEventsLost_{};
    size_t lifetimeBytes_{};
    int64_t snapshotUs_{};
    int64_t pruneUs_{};
};
}
