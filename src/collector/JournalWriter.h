#pragma once

#include "Crypto.h"
#include "Retention.h"
#include <windows.h>
#include <filesystem>
#include <memory>
#include <stop_token>

struct sqlite3;
struct sqlite3_stmt;

namespace Cipherazzi
{
struct JournalBatch
{
    std::vector<Observation> observations, owners;
    std::vector<EndpointEvent> events;
    bool empty() const { return observations.empty() && owners.empty() && events.empty(); }
};

class EndpointCorrelation;

// Constructed before capture starts; only the storage worker uses the connection and its transactional state.
class JournalWriter
{
public:
    JournalWriter(const std::filesystem::path& path, Counters& counters, std::string source,
        std::string processStatus, RetentionLimits retention);
    ~JournalWriter();
    void commit(JournalBatch& batch, std::string_view status, bool final, std::stop_token draining);
    void maintain(bool final = false);
    bool heartbeatDue() const { return std::chrono::steady_clock::now() >= heartbeatDeadline_; }
    void rollback() noexcept;
    void close() { sessionLifetime_.reset(); }
    const std::string& runId() const { return runId_; }

private:
    friend class EndpointCorrelation;
    struct DatabaseCloser { void operator()(sqlite3* value) const; };
    struct StatementCloser { void operator()(sqlite3_stmt* value) const; };
    using Statement = std::unique_ptr<sqlite3_stmt, StatementCloser>;
    Statement prepare(const char* sql);
    void execute(const char* sql);
    void begin(std::stop_token draining);
    void write(const Observation& observation);
    void writeOwners(const Observation& observation);
    void heartbeat(std::string_view status, bool stopped);
    std::unique_ptr<sqlite3, DatabaseCloser> database_;
    Statement insert_, session_, owners_, certificates_, certificateLinks_, lifecycle_;
    CryptoCatalog catalog_;
    std::unique_ptr<Retention> retention_;
    Counters& counters_;
    std::string runId_;
    std::unique_ptr<void, decltype(&CloseHandle)> sessionLifetime_{nullptr, CloseHandle};
    std::unique_ptr<EndpointCorrelation> endpoints_;
    std::chrono::steady_clock::time_point heartbeatDeadline_{}, retentionDeadline_{};
    std::chrono::steady_clock::time_point optimizeDeadline_{std::chrono::steady_clock::now() + std::chrono::hours(1)};
};
}
