#pragma once

#include <cstdint>
#include <string_view>
#include <string>
#include <functional>

struct sqlite3;

namespace Cipherazzi
{
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
    sqlite3* database_;
    RetentionLimits limits_;
};
}
