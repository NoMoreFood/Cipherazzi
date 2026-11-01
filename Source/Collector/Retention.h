#pragma once

#include <cstdint>
#include <string_view>
#include <string>
#include <functional>
#include "Sqlite.h"

namespace Cipherazzi
{
std::wstring sessionMutexName(std::string_view runId);

struct RetentionLimits
{
    uint32_t days{30};
    uint64_t bytes{512 * 1024 * 1024ULL};
    bool replicationRequired{};
};

class Retention
{
public:
    Retention(sqlite3* database, RetentionLimits limits);
    bool maintain(int64_t timestampUs, std::string_view currentRun,
        const std::function<void(const std::string&)>& forget = {});

private:
    using Statement = Sqlite::Statement;
    Statement prepare(const char* sql) { return Sqlite::prepare(database_, sql); }
    sqlite3* database_;
    RetentionLimits limits_;
    Statement running_, recover_, pageSize_, pageCount_, freePages_, safeRevision_, candidates_, remember_,
        events_, eventId_, orphanIds_, orphan_, sessions_, status_;
};
}
