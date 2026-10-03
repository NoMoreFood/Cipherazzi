#pragma once

#include "Model.h"
#include "Crypto.h"
#include "Retention.h"
#include <condition_variable>
#include <deque>
#include <exception>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

struct sqlite3;
struct sqlite3_stmt;

namespace Cipherazzi
{
class Storage
{
public:
    using Enricher = std::function<void(Observation&)>;
    Storage(const std::filesystem::path& path, Counters& counters, std::string source,
        std::string processStatus, Enricher enricher = {}, RetentionLimits retention = {});
    ~Storage();
    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;
    void enqueue(Observation observation, bool waitForCapacity = false);
    void enqueue(EndpointEvent event, bool waitForCapacity = false);
    void check();
    void finish(std::string status = "stopped");
    const std::string& runId() const { return runId_; }

private:
    struct DatabaseCloser { void operator()(sqlite3* value) const; };
    struct StatementCloser { void operator()(sqlite3_stmt* value) const; };
    using Statement = std::unique_ptr<sqlite3_stmt, StatementCloser>;
    struct Pending
    {
        Observation observation;
        std::chrono::steady_clock::time_point ready;
        uint8_t attempts{};
    };
    Statement prepare(const char* sql);
    void execute(const char* sql);
    void write(const Observation& observation);
    void writeOwners(const Observation& observation);
    void write(EndpointEvent& event);
    void correlateEndpoints(bool final, const std::unordered_set<FlowKey, FlowHash>& dirty);
    void writeEndpointDetail(const EndpointEvent& event);
    struct PendingEndpoint
    {
        EndpointEvent event;
        std::chrono::steady_clock::time_point deadline;
        int64_t linkedFlow{};
        bool checked{};
    };
    std::deque<PendingEndpoint> endpointPending_;
    size_t endpointPendingBytes_{};
    void heartbeat(std::string_view status, bool stopped);
    void work();
    std::unique_ptr<sqlite3, DatabaseCloser> database_;
    Statement insert_;
    Statement session_;
    Statement owners_;
    Statement certificates_;
    Statement certificateLinks_;
    Statement lifecycle_;
    Statement telemetry_;
    CryptoCatalog catalog_;
    std::unique_ptr<Retention> retention_;
    Counters& counters_;
    Enricher enricher_;
    std::string runId_;
    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<Pending> queue_;
    std::deque<Pending> refinements_;
    std::deque<EndpointEvent> events_;
    size_t queueBytes_{};
    size_t eventBytes_{};
    std::unordered_map<uint64_t, Pending*> pending_;
    std::exception_ptr error_;
    std::string finalStatus_{"stopped"};
    bool stopping_{};
    std::thread thread_;
};
}
