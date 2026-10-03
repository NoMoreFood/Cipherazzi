#pragma once

#include "Model.h"
#include "Retention.h"
#include <condition_variable>
#include <deque>
#include <exception>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <stop_token>
#include <thread>
#include <unordered_map>

namespace Cipherazzi
{
class JournalWriter;
struct JournalBatch;

class Storage
{
public:
    using Enricher = std::function<void(Observation&)>;
    using OwnerChanges = std::function<std::vector<OwnerChange>()>;
    Storage(const std::filesystem::path& path, Counters& counters, std::string source,
        std::string processStatus, Enricher enricher = {}, RetentionLimits retention = {}, bool refineProcesses = true,
        OwnerChanges ownerChanges = {});
    ~Storage();
    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;
    void enqueue(Observation observation, bool waitForCapacity = false);
    void enqueue(EndpointEvent event, bool waitForCapacity = false, std::stop_token cancellation = {});
    void check();
    void finish(std::string status = "stopped");
    const std::string& runId() const;

private:
    enum class State { Accepting, Draining, Stopped, Failed };
    JournalBatch take(bool& drained);
    void work(Enricher enricher, bool refineProcesses, OwnerChanges ownerChanges);
    Counters& counters_;
    std::unique_ptr<JournalWriter> journal_;
    std::mutex mutex_, finishMutex_;
    std::condition_variable_any changed_;
    std::deque<Observation> queue_;
    std::deque<EndpointEvent> events_;
    size_t queueBytes_{}, eventBytes_{};
    // deque references remain stable until take removes the observation and its index entry under the same lock.
    std::unordered_map<uint64_t, Observation*> pending_;
    std::exception_ptr error_;
    std::string finalStatus_{"stopped"};
    State state_{State::Accepting};
    std::stop_source draining_;
    std::thread thread_;
};
}
