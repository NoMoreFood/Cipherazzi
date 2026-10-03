#pragma once

#include "HttpSpy.h"
#include <chrono>
#include <filesystem>
#include <memory>

struct sqlite3;
struct sqlite3_stmt;

namespace Cipherazzi
{
// Decoded HTTP messages live in a separate database that only Administrators and SYSTEM can read, because
// unlike the connection journal they hold request content, cookies, and response bodies.
class HttpSpyStore
{
public:
    HttpSpyStore(const std::filesystem::path& path, std::string runId, std::string source, int days, uint64_t bytes,
        HttpSpyStatistics statistics);
    ~HttpSpyStore();
    HttpSpyStore(const HttpSpyStore&) = delete;
    HttpSpyStore& operator=(const HttpSpyStore&) = delete;

    // The store beside a connection journal.
    static std::filesystem::path pathFor(const std::filesystem::path& journal);
    bool due() const;
    void commit(std::vector<HttpExchange>& exchanges, bool final);
    void maintain(bool final);

private:
    struct DatabaseCloser { void operator()(sqlite3* value) const; };
    struct StatementCloser { void operator()(sqlite3_stmt* value) const; };
    using Statement = std::unique_ptr<sqlite3_stmt, StatementCloser>;
    Statement prepare(const char* sql);
    void execute(const char* sql);
    void write(const HttpExchange& exchange);
    std::array<uint64_t, 7> snapshot() const;
    std::unique_ptr<sqlite3, DatabaseCloser> database_;
    Statement upsert_, owners_, session_, revision_;
    std::string runId_;
    HttpSpyStatistics statistics_;
    std::array<uint64_t, 7> written_{};
    int days_;
    uint64_t bytes_;
    std::chrono::steady_clock::time_point nextStatistics_{}, nextMaintenance_{};
};
}
