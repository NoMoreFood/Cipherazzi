#include "Storage.h"
#include "HttpSpyStore.h"
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
    bool apply(JournalBatch& batch, std::vector<HttpExchange>& exchanges, bool drained, size_t ownerLimit);
    void refine(Observation& observation) { if (enricher_) enricher_(observation); }

private:
    struct Pending
    {
        Observation observation;
        std::chrono::steady_clock::time_point ready;
        uint8_t attempts{};
        std::optional<uint32_t> httpSequence;
    };
    Storage::Enricher enricher_;
    bool refineProcesses_;
    Counters& counters_;
    std::deque<Pending> pending_;
};

bool ProcessEnrichment::apply(JournalBatch& batch, std::vector<HttpExchange>& exchanges,
    bool drained, size_t ownerLimit)
{
    // Publish hellos immediately; delayed ETW attribution only updates ownership columns.
    if (enricher_)
    {
        // Keep only ownership metadata while delayed lifetime events refine already-published HTTP bodies.
        for (auto& exchange : exchanges)
        {
            Observation owners;
            owners.flowId = exchange.flowId;
            owners.source = exchange.client;
            owners.destination = exchange.server;
            owners.firstUs = exchange.flowStartedUs;
            owners.lastUs = exchange.startedUs;
            owners.udp = exchange.transport == "udp" || exchange.transport == "quic";
            owners.sourceOwner = exchange.clientOwner;
            owners.destinationOwner = exchange.serverOwner;
            enricher_(owners);

            // An owner that the exchange already carries survives a lookup that finds no evidence.
            if (owners.sourceOwner.pid || owners.sourceOwner.ambiguous || !exchange.clientOwner.pid)
                exchange.clientOwner = owners.sourceOwner;
            if (owners.destinationOwner.pid || owners.destinationOwner.ambiguous || !exchange.serverOwner.pid)
                exchange.serverOwner = owners.destinationOwner;
            if (!refineProcesses_ || drained)
                continue;
            if (pending_.size() < 8192)
                pending_.push_back({std::move(owners),
                    std::chrono::steady_clock::now() + std::chrono::seconds(1), 1, exchange.sequence});
            else
                ++counters_.processEventsLost;
        }
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
        for (size_t refined = 0; !pending_.empty() && refined < ownerLimit &&
            (drained || pending_.front().ready <= std::chrono::steady_clock::now()); ++refined)
        {
            auto pending = std::move(pending_.front());
            pending_.pop_front();
            if (pending.httpSequence)
            {
                const auto previous = std::pair{pending.observation.sourceOwner, pending.observation.destinationOwner};
                enricher_(pending.observation);
                if (previous != std::pair{pending.observation.sourceOwner, pending.observation.destinationOwner})
                    exchanges.push_back({.flowId=pending.observation.flowId, .sequence=*pending.httpSequence,
                        .ownersOnly=true, .clientOwner=pending.observation.sourceOwner,
                        .serverOwner=pending.observation.destinationOwner});
            }
            else
            {
                enricher_(pending.observation);
                batch.owners.push_back(pending.observation);
            }

            // Later closes and process events can revoke even a successful initial attribution.
            if (!drained && pending.attempts < 3)
            {
                pending.ready = std::chrono::steady_clock::now() + std::chrono::seconds(1);
                ++pending.attempts;
                pending_.push_back(std::move(pending));
            }
        }
    }
    return drained && pending_.empty();
}

Storage::Storage(const std::filesystem::path& path, Counters& counters, std::string source,
    std::string processStatus, Enricher enricher, RetentionLimits retention, bool refineProcesses,
    OwnerChanges ownerChanges, HttpSpyStorage httpSpy) :
    counters_(counters), journal_(std::make_unique<JournalWriter>(path, counters,
        source, std::move(processStatus), retention))
{
    pending_.reserve(8192);
    if (!httpSpy.path.empty())
        httpStore_ = std::make_unique<HttpSpyStore>(httpSpy.path, journal_->runId(), std::move(source),
            httpSpy.days, httpSpy.bytes, std::move(httpSpy.statistics));
    thread_ = std::thread([this, enricher = std::move(enricher), refineProcesses,
        ownerChanges = std::move(ownerChanges)]() mutable
    {
        work(std::move(enricher), refineProcesses, std::move(ownerChanges));
    });
}

Storage::~Storage()
{
    // Drain accepted metadata during stack unwinding without reporting a successful stop.
    try { finish(std::uncaught_exceptions() ? "failed: Collection interrupted" : "stopped"); }
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

void Storage::enqueue(HttpExchange exchange, bool waitForCapacity)
{
    // Decoded messages use their own bounded queue, and a newer state of a message replaces a queued older one.
    constexpr size_t byteLimit = 64 * 1024 * 1024;
    const auto bytes = exchange.memory();
    const auto key = std::pair{exchange.flowId, exchange.sequence};
    {
        std::unique_lock lock(mutex_);
        if (!httpStore_)
            return;
        auto capacity = [&]
        {
            const auto found = exchangeIndex_.find(key);
            const bool replacing = found != exchangeIndex_.end();
            const auto retained = exchangeBytes_ - (replacing ? found->second->memory() : 0);
            return (replacing || exchanges_.size() < 8192) && bytes <= byteLimit - retained;
        };
        if (waitForCapacity)
        {
            if (bytes <= byteLimit)
                changed_.wait(lock, [&] { return capacity() || state_ != State::Accepting; });
            if (error_)
                std::rethrow_exception(error_);
        }
        if (state_ != State::Accepting || !capacity())
        {
            ++counters_.storageLost;
            return;
        }
        if (const auto found = exchangeIndex_.find(key); found != exchangeIndex_.end())
        {
            exchangeBytes_ = exchangeBytes_ - found->second->memory() + bytes;
            *found->second = std::move(exchange);
        }
        else
        {
            exchangeBytes_ += bytes;
            exchanges_.push_back({std::move(exchange),
                std::chrono::steady_clock::now() + std::chrono::milliseconds(1500)});
            exchangeIndex_.emplace(key, &exchanges_.back().exchange);
        }
    }
    changed_.notify_all();
}

JournalBatch Storage::take(bool& drained, std::vector<HttpExchange>& exchanges, bool refineProcesses)
{
    JournalBatch batch;
    {
        std::unique_lock lock(mutex_);
        // Let buffered process events arrive before decoded messages are attributed, using the bounded queue.
        auto exchangeReady = [&]
        {
            return !exchanges_.empty() && (!refineProcesses || state_ != State::Accepting ||
                exchanges_.front().ready <= std::chrono::steady_clock::now());
        };
        changed_.wait_for(lock, std::chrono::milliseconds(100), [&]
        {
            return state_ != State::Accepting || !events_.empty() || !queue_.empty() || exchangeReady();
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
        while (exchanges.size() < 256 && exchangeReady())
        {
            auto& front = exchanges_.front().exchange;
            exchangeIndex_.erase(std::pair{front.flowId, front.sequence});
            exchangeBytes_ -= front.memory();
            exchanges.push_back(std::move(front));
            exchanges_.pop_front();
        }
        drained = state_ == State::Draining && queue_.empty() && events_.empty() && exchanges_.empty();
    }
    changed_.notify_all();
    return batch;
}

void Storage::work(Enricher enricher, bool refineProcesses, OwnerChanges ownerChanges)
{
    try
    {
        ProcessEnrichment enrichment(std::move(enricher), refineProcesses, counters_);
        for (;;)
        {
            bool drained;
            std::vector<HttpExchange> exchanges;
            auto batch = take(drained, exchanges, refineProcesses);
            bool final = enrichment.apply(batch, exchanges, drained, ownerChanges ? 128 : 256);
            if (ownerChanges)
            {
                auto changes = ownerChanges();
                if (!changes.empty())
                {
                    // Refresh this batch too, so consuming a notification cannot leave its new observations stale.
                    for (auto& observation : batch.observations)
                        if (!observation.lifecycleOnly)
                            enrichment.refine(observation);
                    for (auto& observation : batch.owners)
                        enrichment.refine(observation);
                }
                const auto first = batch.owners.size();
                final = journal_->ownershipChanges(std::move(changes), batch) && final;
                for (auto index = first; index < batch.owners.size(); ++index)
                    enrichment.refine(batch.owners[index]);
                if (final)
                {
                    // Process verification can discover another lifetime while refining the final batch.
                    auto discovered = ownerChanges();
                    if (!discovered.empty())
                    {
                        const auto next = batch.owners.size();
                        journal_->ownershipChanges(std::move(discovered), batch);
                        for (auto index = next; index < batch.owners.size(); ++index)
                            enrichment.refine(batch.owners[index]);
                        final = false;
                    }
                }
            }

            // Commit accepted shutdown work before spending another writer wait on optional maintenance.
            if (!final && !draining_.stop_requested())
            {
                journal_->maintain();
                if (httpStore_)
                    httpStore_->maintain(false);
            }
            if (!final && batch.empty() && exchanges.empty() && !journal_->heartbeatDue() &&
                !(httpStore_ && httpStore_->due()))
                continue;
            journal_->commit(batch, final ? finalStatus_ : "running", final, draining_.get_token());
            if (httpStore_)
                httpStore_->commit(exchanges, final);
            if (final)
            {
                journal_->maintain(true);
                if (httpStore_)
                    httpStore_->maintain(true);
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
