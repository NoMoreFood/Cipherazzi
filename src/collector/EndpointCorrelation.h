#pragma once

#include "JournalWriter.h"
#include <deque>
#include <unordered_set>

namespace Cipherazzi
{
// Owns pending matches; all database access occurs inside the journal writer's current transaction.
class EndpointCorrelation
{
public:
    explicit EndpointCorrelation(JournalWriter& journal);
    void write(EndpointEvent& event);
    void resolve(bool final, const std::unordered_set<FlowKey, FlowHash>& dirty);

private:
    struct Pending
    {
        EndpointEvent event;
        std::chrono::steady_clock::time_point deadline;
        int64_t linkedFlow{};
        bool checked{};
    };
    void writeDetail(const EndpointEvent& event);
    JournalWriter& journal_;
    JournalWriter::Statement telemetry_;
    std::deque<Pending> pending_;
    size_t bytes_{};
};
}
