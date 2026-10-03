#include "Storage.h"
#include "JournalWriter.h"
#include <algorithm>

namespace Cipherazzi
{
// Delayed attribution is worker-local and never holds the producer queue lock or a database transaction.
class ProcessEnrichment
{
public:
    ProcessEnrichment(Storage::Enricher enricher, bool refine, Counters& counters) :
        enricher_(std::move(enricher)), refineProcesses_(refine), counters_(counters) {}
    bool apply(JournalBatch& batch, bool drained);

private:
    struct Pending
    {
        Observation observation;
        std::chrono::steady_clock::time_point ready;
        uint8_t attempts{};
    };
    Storage::Enricher enricher_;
    bool refineProcesses_;
    Counters& counters_;
    std::deque<Pending> pending_;
};

bool ProcessEnrichment::apply(JournalBatch& batch, bool drained)
{
    // Publish hellos immediately; delayed ETW attribution only updates ownership columns.
    if (enricher_)
    {
        for (auto& observation : batch.observations)
        {
            if (observation.lifecycleOnly)
                continue;
            enricher_(observation);
            if (!refineProcesses_ || observation.protocol == Observation::Protocol::Ipsec)
                continue;
            if (pending_.size() < 8192)
            {
                Observation refinement;
                refinement.flowId = observation.flowId;
                refinement.firstUs = observation.firstUs;
                refinement.lastUs = observation.lastUs;
                refinement.quic = observation.quic;
                refinement.udp = observation.udp;
                refinement.source = observation.source;
                refinement.destination = observation.destination;
                pending_.push_back({std::move(refinement),
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(1500)});
            }
            else
                ++counters_.processEventsLost;
        }
        while (!pending_.empty() && batch.owners.size() < 256 &&
            (drained || pending_.front().ready <= std::chrono::steady_clock::now()))
        {
            auto pending = std::move(pending_.front());
            pending_.pop_front();
            batch.owners.push_back(std::move(pending.observation));
            enricher_(batch.owners.back());
            if (!drained && pending.attempts < 3 && batch.owners.back().sourceOwner.name.empty() &&
                batch.owners.back().destinationOwner.name.empty())
                pending_.push_back({batch.owners.back(),
                    std::chrono::steady_clock::now() + std::chrono::seconds(1),
                    static_cast<uint8_t>(pending.attempts + 1)});
        }
    }
    return drained && pending_.empty();
}

Storage::Storage(const std::filesystem::path& path, Counters& counters, std::string source,
    std::string processStatus, Enricher enricher, RetentionLimits retention, bool refineProcesses) :
    counters_(counters), journal_(std::make_unique<JournalWriter>(path, counters,
        std::move(source), std::move(processStatus), retention))
{
    pending_.reserve(8192);
    thread_ = std::thread([this, enricher = std::move(enricher), refineProcesses]() mutable
    {
        work(std::move(enricher), refineProcesses);
    });
}

Storage::~Storage()
{
    try { finish(); }
    catch (...) {}
}

const std::string& Storage::runId() const { return journal_->runId(); }

void Storage::enqueue(Observation observation, bool waitForCapacity)
{
    {
        std::unique_lock lock(mutex_);
        if (waitForCapacity)
        {
            changed_.wait(lock, [this, id = observation.flowId]
            {
                return (queue_.size() < 8192 && queueBytes_ < 60 * 1024 * 1024) ||
                    pending_.contains(id) || state_ != State::Accepting;
            });
            if (error_)
                std::rethrow_exception(error_);
        }
        if (state_ != State::Accepting)
        {
            ++counters_.storageLost;
            return;
        }

        // Collapse successive hello updates while preserving queue order.
        if (const auto found = pending_.find(observation.flowId); found != pending_.end())
        {
            if (observation.lifecycleOnly)
            {
                const auto previous = found->second->memory();
                found->second->endedUs = observation.endedUs;
                found->second->closeReason = observation.closeReason;
                queueBytes_ = queueBytes_ - previous + found->second->memory();
                return;
            }
            const auto previous = found->second->memory();
            if (queueBytes_ - previous + observation.memory() > 64 * 1024 * 1024)
            {
                ++counters_.storageLost;
                return;
            }
            queueBytes_ = queueBytes_ - previous + observation.memory();
            *found->second = std::move(observation);
            return;
        }
        if (queue_.size() >= 8192 || queueBytes_ + observation.memory() > 64 * 1024 * 1024)
        {
            ++counters_.storageLost;
            return;
        }
        queueBytes_ += observation.memory();
        queue_.push_back(std::move(observation));
        pending_.emplace(queue_.back().flowId, &queue_.back());
    }
    changed_.notify_all();
}

void Storage::enqueue(EndpointEvent event, bool waitForCapacity, std::stop_token cancellation)
{
    // Endpoint diagnostics use a separate bounded queue and never block packet capture.
    bool limited = false;
    for (auto* value : {&event.provider, &event.kind, &event.result, &event.peer, &event.protocol,
        &event.cipher, &event.certificateId})
        if (value->size() > 4096)
        {
            std::string("Metadata exceeded the field limit").swap(*value);
            limited = true;
        }
    if (event.detail.size() > 65536)
    {
        limited = true;
        std::string(R"({"error":"Endpoint event exceeded the metadata limit"})").swap(event.detail);
    }
    if (limited)
    {
        event.report.reset();
        ++counters_.telemetryLost;
    }
    const auto bytes = event.memory();
    constexpr size_t byteLimit = 16 * 1024 * 1024;
    if (bytes > byteLimit)
    {
        ++counters_.telemetryLost;
        return;
    }
    {
        std::unique_lock lock(mutex_);
        auto capacity = [this, bytes] { return events_.size() < 8192 && eventBytes_ + bytes <= byteLimit; };
        if (waitForCapacity)
            changed_.wait(lock, cancellation, [&] { return capacity() || state_ != State::Accepting; });
        if (!capacity() || state_ != State::Accepting || cancellation.stop_requested())
        {
            ++counters_.telemetryLost;
            return;
        }
        eventBytes_ += bytes;
        events_.push_back(std::move(event));
    }
    changed_.notify_all();
}

JournalBatch Storage::take(bool& drained)
{
    JournalBatch batch;
    {
        std::unique_lock lock(mutex_);
        changed_.wait_for(lock, std::chrono::milliseconds(100), [this]
        {
            return state_ != State::Accepting || !events_.empty() || !queue_.empty();
        });
        if (state_ == State::Accepting && !queue_.empty() && queue_.size() < 256)
            changed_.wait_for(lock, std::chrono::milliseconds(10), [this]
            {
                return state_ != State::Accepting || queue_.size() >= 256;
            });

        // Transfer bounded batches and release their capacity before enrichment or database access.
        while (batch.observations.size() < 256 && !queue_.empty())
        {
            pending_.erase(queue_.front().flowId);
            queueBytes_ -= queue_.front().memory();
            batch.observations.push_back(std::move(queue_.front()));
            queue_.pop_front();
        }
        while (batch.events.size() < 128 && !events_.empty())
        {
            eventBytes_ -= events_.front().memory();
            batch.events.push_back(std::move(events_.front()));
            events_.pop_front();
        }
        drained = state_ == State::Draining && queue_.empty() && events_.empty();
    }
    changed_.notify_all();
    return batch;
}

void Storage::work(Enricher enricher, bool refineProcesses)
{
    try
    {
        ProcessEnrichment enrichment(std::move(enricher), refineProcesses, counters_);
        for (;;)
        {
            bool drained;
            auto batch = take(drained);
            const bool final = enrichment.apply(batch, drained);
            journal_->maintain();
            if (!final && batch.empty() && !journal_->heartbeatDue())
                continue;
            journal_->commit(batch, final ? finalStatus_ : "running", final, draining_.get_token());
            if (final)
            {
                journal_->maintain(true);
                std::lock_guard lock(mutex_);
                state_ = State::Stopped;
                break;
            }
        }
    }
    catch (...)
    {
        journal_->rollback();
        std::lock_guard lock(mutex_);
        error_ = std::current_exception();
        state_ = State::Failed;
    }
    changed_.notify_all();
}

void Storage::check()
{
    std::lock_guard lock(mutex_);
    if (error_)
        std::rethrow_exception(error_);
}

void Storage::finish(std::string status)
{
    // Close admission once, wake every producer, and drain accepted work before releasing the session lifetime.
    std::lock_guard finishLock(finishMutex_);
    if (thread_.joinable())
    {
        {
            std::lock_guard lock(mutex_);
            if (state_ == State::Accepting)
            {
                finalStatus_ = std::move(status);
                state_ = State::Draining;
            }
        }
        draining_.request_stop();
        changed_.notify_all();
        thread_.join();
    }
    journal_->close();
    check();
}
}
