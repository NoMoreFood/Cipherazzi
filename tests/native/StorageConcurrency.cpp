#include "Capture.h"
#include "Crypto.h"
#include "PacketQueue.h"
#include "Loopback.h"
#include "Processes.h"
#include "Storage.h"
#include "Telemetry.h"
#include <fstream>
#include <sqlite3.h>
#define SECURITY_WIN32
#include <security.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <tuple>

namespace Cipherazzi::Tests
{
using Buffer = std::vector<uint8_t>;
void require(bool result, const char* message);
int scalar(sqlite3* database, const char* sql);
Buffer hello(bool client, uint16_t version = 0x0304, bool retry = false, bool ech = false,
    Bytes additionalExtensions = {});
Buffer record(Bytes payload, uint8_t type = 22);
TransportPacket packet(Bytes bytes, uint32_t sequence, bool client = true, uint8_t flags = 0x18);

void storageConcurrencyAndFailure()
{
    const auto directory = std::filesystem::temp_directory_path() /
        (L"Cipherazzi-tests-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    std::filesystem::create_directory(directory);
    const auto path = directory / L"metadata-\u03b4.db";
    Counters counters;

    // Hold the writer while live and replay producers replace queued HTTP bodies near the byte limit.
    const auto httpPath = directory / L"HttpSpy" / L"bounded.db";
    {
        const std::unique_ptr<void, decltype(&CloseHandle)> entered(CreateEventW(nullptr, TRUE, FALSE, nullptr),
            CloseHandle), released(CreateEventW(nullptr, TRUE, FALSE, nullptr), CloseHandle);
        Counters bounded;
        Storage storage(directory / L"bounded.db", bounded, "HTTP queue", "disabled", {}, {}, false, [&]
        {
            SetEvent(entered.get());
            WaitForSingleObject(released.get(), 10000);
            return std::vector<OwnerChange>{};
        }, {.path = httpPath});
        require(WaitForSingleObject(entered.get(), 2000) == WAIT_OBJECT_0, "HTTP queue writer did not start");
        auto exchange = [](uint64_t id, size_t mebibytes)
        {
            HttpExchange row;
            row.flowId = id;
            row.startedUs = row.endedUs = nowUs();
            row.method = "GET";
            row.target = "/queued";
            row.state = "complete";
            row.responseBody.resize(mebibytes * 1024 * 1024, 'x');
            row.responseBytes = row.responseBody.size();
            return row;
        };
        storage.enqueue(exchange(1, 20));
        storage.enqueue(exchange(2, 40));
        storage.enqueue(exchange(1, 30));
        require(bounded.storageLost == 1, "A growing HTTP replacement exceeded the queue byte limit");
        auto waiting = std::async(std::launch::async, [&] { storage.enqueue(exchange(1, 25), true); });
        const bool blocked = waiting.wait_for(std::chrono::milliseconds(150)) == std::future_status::timeout;
        storage.enqueue(exchange(2, 30));
        const bool resumed = waiting.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
        auto oversized = std::async(std::launch::async, [&] { storage.enqueue(exchange(3, 64), true); });
        const bool rejected = oversized.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
        SetEvent(released.get());
        storage.finish();
        waiting.get();
        oversized.get();
        require(blocked && resumed, "A replay replacement did not wait for capacity or wake after a shrink");
        require(rejected && bounded.storageLost == 2, "An oversized HTTP exchange waited for impossible capacity");
    }
    sqlite3* http = nullptr;
    require(sqlite3_open_v2(utf8(httpPath.wstring()).c_str(), &http, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
        "The bounded HTTP queue store could not be read");
    const auto stored = scalar(http, "SELECT count(*) FROM exchanges WHERE (flow_id=1 AND "
        "length(response_body)=26214400) OR (flow_id=2 AND length(response_body)=31457280)");
    const auto total = scalar(http, "SELECT count(*) FROM exchanges");
    sqlite3_close(http);
    require(stored == 2 && total == 2, "Accepted HTTP replacements were lost or rejected bodies were persisted");
    std::filesystem::remove_all(httpPath.parent_path());
    {
        Storage storage(path, counters, "test", "disabled");
        sqlite3* reader = nullptr;
        const auto encoded = utf8(path.wstring());
        require(sqlite3_open_v2(encoded.c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Concurrent reader could not open the database");
        require(scalar(reader, "PRAGMA application_id") == 0x435A5A49, "Database identity is incorrect");
        sqlite3_exec(reader, "BEGIN", nullptr, nullptr, nullptr);
        require(scalar(reader, "SELECT count(*) FROM connections") == 0, "Database should start empty");
        Engine engine(counters, [&](Observation row) { storage.enqueue(std::move(row)); });
        engine.tcp(packet(record(hello(true)), 100), 1000000);
        engine.tcp(packet(record(hello(false)), 200, false), 1000010);
        engine.expire(1000020, true);
        storage.finish();
        require(scalar(reader, "SELECT count(*) FROM connections") == 0, "WAL reader snapshot changed during a write");
        sqlite3_exec(reader, "COMMIT", nullptr, nullptr, nullptr);
        require(scalar(reader, "SELECT count(*) FROM connections") == 1, "Handshake updates created duplicate rows");
        require(scalar(reader, "SELECT tls_version FROM connections") == 0x0304, "Selected version was not persisted");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_pid IS NULL") == 1,
            "Unavailable process ID should be NULL");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_account='' AND source_account_sid='' "
            "AND destination_account='' AND destination_account_sid=''") == 1,
            "An unattributed packet was assigned an account");
        require(scalar(reader, "SELECT count(*) FROM capture_sessions WHERE length(computer_name)>0") == 1,
            "The collector computer was not persisted");
        require(scalar(reader, "SELECT count(*) FROM capture_sessions WHERE stopped_us IS NOT NULL") == 1,
            "Final capture health was not persisted");
        sqlite3_close(reader);
    }
    {
        Storage storage(path, counters, "second import", "disabled");
        storage.finish();
    }

    // Slow attribution must not delay streaming hellos or overwrite a later server selection.
    const auto streamingPath = directory / L"streaming.db";
    {
        const auto started = std::chrono::steady_clock::now();
        Storage storage(streamingPath, counters, "streaming", "delayed", [&](Observation& row)
        {
            if (std::chrono::steady_clock::now() - started > std::chrono::milliseconds(500))
            {
                row.sourceOwner.pid = 1234;
                row.sourceOwner.name = "late-owner.exe";
                row.sourceOwner.evidence = "test";
                row.sourceOwner.account = "late-\u0394";
                row.sourceOwner.accountDomain = "LAB";
                row.sourceOwner.accountSid = "S-1-5-21-1-2-3-1001";
                row.destinationOwner.pid = 4321;
                row.destinationOwner.account = "SYSTEM";
                row.destinationOwner.accountDomain = "NT AUTHORITY";
                row.destinationOwner.accountSid = "S-1-5-18";
            }
        });
        sqlite3* reader = nullptr;
        sqlite3_open_v2(utf8(streamingPath.wstring()).c_str(), &reader, SQLITE_OPEN_READONLY, nullptr);
        sqlite3_busy_timeout(reader, 1000);
        Engine engine(counters, [&](Observation row) { storage.enqueue(std::move(row)); });
        engine.tcp(packet(record(hello(true)), 100), 1000000);
        while (!scalar(reader, "SELECT count(*) FROM connections") &&
            std::chrono::steady_clock::now() - started < std::chrono::milliseconds(700))
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        require(scalar(reader, "SELECT count(*) FROM connections") == 1,
            "Process enrichment delayed the live client hello");
        require(!scalar(reader, "SELECT count(*) FROM connections WHERE tls_version IS NOT NULL"),
            "A client offer was reported as a server selection");
        const auto revision = scalar(reader, "SELECT revision FROM metadata");
        engine.tcp(packet(record(hello(false)), 200, false), 1000010);
        while (!scalar(reader, "SELECT count(*) FROM connections WHERE source_pid=1234") &&
            std::chrono::steady_clock::now() - started < std::chrono::seconds(3))
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_pid=1234 AND tls_version=772") == 1,
            "Delayed ownership lost the server hello or failed to arrive");
        require(scalar(reader, "SELECT change_revision FROM connections") > revision,
            "Late ownership did not advance the streaming cursor");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_account='late-\u0394' "
            "AND source_account_domain='LAB' AND source_account_sid='S-1-5-21-1-2-3-1001' "
            "AND destination_account='SYSTEM' AND destination_account_domain='NT AUTHORITY' "
            "AND destination_account_sid='S-1-5-18'") == 1, "Late process accounts were not persisted");
        const auto observationRevision = scalar(reader, "SELECT observation_revision FROM metadata");
        const auto ownerRevision = scalar(reader, "SELECT change_revision FROM connections");
        storage.finish();
        require(scalar(reader, "SELECT change_revision FROM connections") == ownerRevision,
            "An unchanged ownership refinement rewrote the observation");
        require(scalar(reader, "SELECT observation_revision FROM metadata") == observationRevision &&
            scalar(reader, "SELECT revision FROM metadata") > observationRevision,
            "A final heartbeat invalidated observation views or failed to advance replication");
        sqlite3_close(reader);
    }

    // A short database stall must preserve a diagnostic burst without blocking the capture producer.
    const auto endpointPath = directory / L"endpoint-burst.db";
    {
        Counters endpointCounters;
        Storage storage(endpointPath, endpointCounters, "endpoint burst", "disabled");
        sqlite3* writer = nullptr;
        sqlite3_open_v2(utf8(endpointPath.wstring()).c_str(), &writer, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_busy_timeout(writer, 1000);
        require(sqlite3_exec(writer, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK,
            "The burst test could not hold the database writer");
        for (int index = 0; index < 3000; ++index)
        {
            EndpointEvent event;
            event.id = std::to_string(index);
            event.provider = "burst";
            event.detail = R"({"message":")" + std::string(512, 'x') + R"("})";
            storage.enqueue(std::move(event));
        }
        sqlite3_exec(writer, "COMMIT", nullptr, nullptr, nullptr);
        storage.finish();
        require(endpointCounters.telemetryLost == 0 &&
            scalar(writer, "SELECT count(*) FROM endpoint_events") == 3000,
            "A short writer stall dropped endpoint events from a bounded burst");
        sqlite3_close(writer);
    }

    // Oversized diagnostic bursts still stop at the memory budget and report every rejected event.
    {
        Counters endpointCounters;
        const auto boundedPath = directory / L"endpoint-bounded.db";
        Storage storage(boundedPath, endpointCounters, "endpoint limits", "disabled");
        sqlite3* writer = nullptr;
        sqlite3_open_v2(utf8(boundedPath.wstring()).c_str(), &writer, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_busy_timeout(writer, 1000);
        require(sqlite3_exec(writer, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK,
            "The limit test could not hold the database writer");
        for (int index = 0; index < 2048; ++index)
        {
            EndpointEvent event;
            event.id = std::to_string(index);
            event.detail.assign(60000, 'x');
            event.detail.replace(0, 12, R"({"message":")");
            event.detail.replace(59998, 2, R"("})");
            storage.enqueue(std::move(event));
        }
        sqlite3_exec(writer, "COMMIT", nullptr, nullptr, nullptr);
        storage.finish();
        require(endpointCounters.telemetryLost > 0 && endpointCounters.telemetryLost +
            scalar(writer, "SELECT count(*) FROM endpoint_events") == 2048,
            "The endpoint memory limit lost its accounting or accepted an unbounded burst");
        sqlite3_close(writer);
    }

    // A writer stall longer than the busy timeout keeps its batch and commits once the journal is free. The
    // stall outlasts both the retention pass's wait and the batch's first wait.
    {
        Counters stallCounters;
        const auto stallPath = directory / L"long-stall.db";
        Storage storage(stallPath, stallCounters, "long stall", "disabled");
        sqlite3* blocker = nullptr;
        sqlite3_open_v2(utf8(stallPath.wstring()).c_str(), &blocker, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_busy_timeout(blocker, 1000);
        require(sqlite3_exec(blocker, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK,
            "The long stall could not hold the database writer");
        Engine engine(stallCounters, [&](Observation row) { storage.enqueue(std::move(row)); });
        engine.tcp(packet(record(hello(true)), 100), 1000000);
        engine.tcp(packet(record(hello(false)), 200, false), 1000010);
        engine.expire(1000020, true);
        std::this_thread::sleep_for(std::chrono::milliseconds(6000));
        storage.check();
        sqlite3_exec(blocker, "COMMIT", nullptr, nullptr, nullptr);
        storage.finish();
        require(scalar(blocker, "SELECT count(*) FROM connections") == 1 && stallCounters.storageLost == 0,
            "A writer stall beyond the busy timeout ended the session or lost its batch");
        sqlite3_close(blocker);
    }

    // At shutdown a persistent writer lock must fail promptly, roll back its batch, and permit a clean restart.
    const auto stalledPath = directory / L"stalled.db";
    {
        Counters stalledCounters;
        Storage storage(stalledPath, stalledCounters, "persistent lock", "disabled");
        sqlite3* blocker = nullptr;
        sqlite3_open_v2(utf8(stalledPath.wstring()).c_str(), &blocker, SQLITE_OPEN_READWRITE, nullptr);
        sqlite3_busy_timeout(blocker, 1000);
        require(sqlite3_exec(blocker, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK,
            "The persistent lock could not be acquired");
        Engine engine(stalledCounters, [&](Observation row) { storage.enqueue(std::move(row)); });
        engine.tcp(packet(record(hello(true)), 100), 1000000);
        engine.tcp(packet(record(hello(false)), 200, false), 1000010);
        engine.expire(1000020, true);
        const auto started = std::chrono::steady_clock::now();
        bool failed = false;
        try { storage.finish(); }
        catch (const std::exception&) { failed = true; }
        const auto shutdownMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        std::cout << "Persistent writer shutdown: " << shutdownMs << " ms; failed=" << failed << '\n';
        require(failed && shutdownMs < 5000,
            "A persistent writer lock did not terminate with an error");
        sqlite3_exec(blocker, "ROLLBACK", nullptr, nullptr, nullptr);
        require(scalar(blocker, "SELECT count(*) FROM connections") == 0 &&
            scalar(blocker, "SELECT count(*) FROM pragma_integrity_check WHERE integrity_check<>'ok'") == 0,
            "Writer failure committed an incomplete batch or corrupted the database");
        {
            Storage recovered(stalledPath, stalledCounters, "writer restart", "disabled");
            Engine restarted(stalledCounters, [&](Observation row) { recovered.enqueue(std::move(row)); });
            restarted.tcp(packet(record(hello(true)), 100), 2000000);
            restarted.tcp(packet(record(hello(false)), 200, false), 2000010);
            restarted.expire(2000020, true);
            recovered.finish();
        }
        require(scalar(blocker, "SELECT count(*) FROM connections") == 1,
            "Writer failure prevented a later collector from using the journal");
        sqlite3_close(blocker);
    }

    // An unrelated SQLite file must never be initialized as a collector database.
    const auto unrelated = directory / L"unrelated.db";
    sqlite3* other = nullptr;
    sqlite3_open(utf8(unrelated.wstring()).c_str(), &other);
    sqlite3_exec(other, "CREATE TABLE keep_me(value INTEGER); INSERT INTO keep_me VALUES(42)",
        nullptr, nullptr, nullptr);
    sqlite3_close(other);
    bool rejected = false;
    try { Storage storage(unrelated, counters, "test", "disabled"); }
    catch (const std::exception&) { rejected = true; }
    require(rejected, "Unrelated database was accepted");
    sqlite3_open(utf8(unrelated.wstring()).c_str(), &other);
    require(scalar(other, "SELECT value FROM keep_me") == 42, "Unrelated database was modified");
    sqlite3_close(other);
    for (const auto& entry : std::filesystem::directory_iterator(directory))
        std::filesystem::remove(entry.path());
    std::filesystem::remove(directory);
}

void captureQueueConcurrency()
{
    // Burst packets wrap both rings while a slower consumer checks every byte and the original ordering.
    PacketQueue queue(64, 32768);
    constexpr int64_t count = 20000;
    std::atomic<bool> cancel{};
    std::atomic<size_t> full{};
    std::jthread producer([&]
    {
        Buffer bytes(PacketMonitorCaptureLimit);
        for (int64_t index = 0; index < count && !cancel; ++index)
        {
            const auto length = static_cast<size_t>(54 + index * 7919 % (PacketMonitorCaptureLimit - 53));
            std::fill_n(bytes.begin(), length, static_cast<uint8_t>(index));
            while (!cancel && !queue.push(Bytes(bytes).first(length), PacketKind::Ethernet, index))
            {
                ++full;
                std::this_thread::yield();
            }
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    try
    {
        for (int64_t index = 0; index < count; ++index)
        {
            const auto packet = queue.take(std::chrono::seconds(5));
            require(packet && packet->timestamp == index && packet->kind == PacketKind::Ethernet &&
                packet->bytes.size() == static_cast<size_t>(54 + index * 7919 % (PacketMonitorCaptureLimit - 53)),
                "Packet queue lost ordering, length, or metadata");
            require(std::ranges::all_of(packet->bytes, [index](uint8_t value)
            {
                return value == static_cast<uint8_t>(index);
            }), "Packet queue reused bytes before consumption");
            queue.release();
        }
        require(full != 0, "Packet queue test did not exercise backpressure");
        queue.wake();
        require(!queue.take(std::chrono::milliseconds(1)), "Packet queue stop signal created a packet");
    }
    catch (...)
    {
        cancel = true;
        throw;
    }
}

}
