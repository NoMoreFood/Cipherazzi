#include "Storage.h"
#include "Crypto.h"
#include "Telemetry.h"
#include <sqlite3.h>
#include <filesystem>
#include <fstream>
#include <future>
#include <stdexcept>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);
int scalar(sqlite3* database, const char* sql);

void retentionOwner(const std::filesystem::path& path)
{
    // Publish an unfinished connection, then let the parent terminate the process without cleanup.
    Counters counters;
    Storage storage(path, counters, "Retention owner", "disabled", {}, {.days=0, .bytes=0});
    Observation observation;
    observation.flowId = 1;
    observation.firstUs = observation.lastUs = nowUs() - 40 * 86400000000LL;
    observation.clientHello = observation.serverHello = true;
    observation.version = 0x0304;
    observation.cipher = 0x1301;
    observation.source.port = 40000;
    observation.destination.port = 443;
    storage.enqueue(std::move(observation), true);
    sqlite3* reader = nullptr;
    require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not open the owner journal");
    while (!scalar(reader, "SELECT count(*) FROM connections"))
    {
        storage.check();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    sqlite3_close(reader);
    { std::ofstream ready(path.wstring() + L".ready"); ready << storage.runId(); }
    for (;;)
        std::this_thread::sleep_for(std::chrono::seconds(1));
}

void storageRecoveryCoverage()
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("cipherazzi-recovery-" + std::to_string(nowUs()));
    std::filesystem::create_directory(directory);

    // A stale heartbeat must not retire a live owner; process death must unblock both retention limits.
    for (const bool sizeLimit : {false, true})
    {
        const auto path = directory / (sizeLimit ? "size.db" : "age.db");
        wchar_t executable[32768]{};
        require(GetModuleFileNameW(nullptr, executable, 32768) != 0, "Could not locate the test executable");
        auto command = L"\"" + std::wstring(executable) + L"\" --retention-owner \"" + path.wstring() + L"\"";
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION child{};
        require(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &child), "Could not start the retention owner");
        CloseHandle(child.hThread);
        std::unique_ptr<void, void(*)(void*)> process(child.hProcess, [](void* handle)
        {
            TerminateProcess(handle, 1);
            WaitForSingleObject(handle, 5000);
            CloseHandle(handle);
        });
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while (!std::filesystem::exists(path.wstring() + L".ready") &&
            std::chrono::steady_clock::now() < deadline && WaitForSingleObject(process.get(), 0) == WAIT_TIMEOUT)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        require(std::filesystem::exists(path.wstring() + L".ready"), "The retention owner did not publish its row");
        sqlite3* database = nullptr;
        require(sqlite3_open(path.string().c_str(), &database) == SQLITE_OK, "Could not open the recovery journal");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(database, sqlite3_close);
        sqlite3_busy_timeout(database, 2000);
        require(sqlite3_exec(database, "UPDATE capture_sessions SET started_us=1,updated_us=2;"
            "INSERT INTO replication_consumers VALUES('offline',0,0)", nullptr, nullptr, nullptr) == SQLITE_OK,
            "Could not prepare the abandoned session");
        Retention retention(database, {.days=sizeLimit ? 0U : 7U, .bytes=sizeLimit ? 1ULL : 0ULL});
        retention.maintain(nowUs(), "other-live-collector");
        require(scalar(database, "SELECT count(*) FROM capture_sessions WHERE stopped_us IS NULL") == 1 &&
            scalar(database, "SELECT count(*) FROM connections") == 1,
            "A stale heartbeat caused a live collector to be retired");
        require(TerminateProcess(process.get(), 1) && WaitForSingleObject(process.get(), 5000) == WAIT_OBJECT_0,
            "Could not terminate the retention owner");

        // Restarting capture repairs the session durably without bypassing outstanding upload protection.
        Counters counters;
        {
            Storage recovered(path, counters, "Recovery", "disabled", {}, {.days=0, .bytes=0});
            recovered.finish();
        }
        require(scalar(database, "SELECT count(*) FROM capture_sessions WHERE status='interrupted' "
            "AND stopped_us=updated_us AND change_revision>0") == 1,
            "A crashed session was not durably marked interrupted");
        retention.maintain(nowUs(), "other-live-collector");
        require(scalar(database, "SELECT count(*) FROM connections") == 1,
            "Crash recovery discarded an unacknowledged connection");
        require(sqlite3_exec(database, "UPDATE replication_consumers SET acknowledged_revision="
            "(SELECT revision FROM metadata)", nullptr, nullptr, nullptr) == SQLITE_OK,
            "Could not acknowledge recovered history");
        retention.maintain(nowUs(), "other-live-collector");
        require(scalar(database, "SELECT count(*) FROM connections") == 0,
            "A crashed collector permanently protected completed history");
        require(scalar(database, "SELECT count(*) FROM pragma_foreign_key_check") == 0,
            "Crash recovery violated journal foreign keys");
    }

    // Cancellation must wake an importer blocked behind a saturated queue and a persistent database writer.
    const auto path = directory / "blocked.db";
    const auto reports = directory / "reports";
    std::filesystem::create_directory(reports);
    std::ifstream input(std::filesystem::path(CIPHERAZZI_FIXTURE_DIRECTORY) / "endpoint-pq.json");
    auto report = nlohmann::json::parse(input);
    report["server_certificates_der"] = nlohmann::json::array();
    report["client_certificates_der"] = nlohmann::json::array();
    { std::ofstream output(reports / "endpoint.json"); output << report; }
    Counters counters;
    {
        Storage storage(path, counters, "Blocked endpoint importer", "disabled", {}, {.days=0, .bytes=0});
        sqlite3* writer = nullptr;
        require(sqlite3_open(path.string().c_str(), &writer) == SQLITE_OK, "Could not open the blocking writer");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> blocker(writer, sqlite3_close);
        sqlite3_busy_timeout(writer, 2000);
        require(sqlite3_exec(writer, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK,
            "Could not lock the endpoint journal");
        for (int index = 0; index < 9500; ++index)
        {
            EndpointEvent event;
            event.id = std::to_string(index);
            event.timestampUs = nowUs();
            event.detail = "{}";
            storage.enqueue(std::move(event));
        }
        require(counters.telemetryLost > 0, "The endpoint queue was not saturated");
        Telemetry telemetry(storage, counters, false, {}, reports);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto stopped = std::async(std::launch::async, [&] { telemetry.stop(); });
        const bool cancelled = stopped.wait_for(std::chrono::seconds(3)) == std::future_status::ready;
        sqlite3_exec(writer, "ROLLBACK", nullptr, nullptr, nullptr);
        stopped.get();
        storage.finish();
        require(cancelled, "A blocked endpoint importer prevented shutdown cancellation");
    }
    std::filesystem::remove_all(directory);
}

void retentionCoverage()
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("cipherazzi-retention-" + std::to_string(nowUs()));
    std::filesystem::create_directory(directory);
    const auto path = directory / "capture.db";
    Counters counters;
    {
        Storage storage(path, counters, "retention test", "disabled");
        for (uint64_t id = 1; id <= 64; ++id)
        {
            Observation observation;
            observation.flowId = id;
            observation.firstUs = observation.lastUs = nowUs() - 40 * 86400000000LL;
            observation.endedUs = observation.lastUs;
            observation.clientHello = observation.serverHello = true;
            observation.version = 0x0304;
            observation.cipher = 0x1301;
            observation.source.port = static_cast<uint16_t>(40000 + id);
            observation.destination.port = 443;
            storage.enqueue(std::move(observation), true);
        }
        storage.finish();
    }
    sqlite3* database = nullptr;
    require(sqlite3_open(path.string().c_str(), &database) == SQLITE_OK, "Could not open retention journal");
    auto execute = [&](const char* sql)
    {
        require(sqlite3_exec(database, sql, nullptr, nullptr, nullptr) == SQLITE_OK, sqlite3_errmsg(database));
    };
    auto scalar = [&](const char* sql)
    {
        sqlite3_stmt* statement = nullptr;
        require(sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) == SQLITE_OK, sqlite3_errmsg(database));
        require(sqlite3_step(statement) == SQLITE_ROW, "Retention query failed");
        const auto value = sqlite3_column_int64(statement, 0);
        sqlite3_finalize(statement);
        return value;
    };
    try
    {
        execute("PRAGMA foreign_keys=ON; UPDATE capture_sessions SET started_us=1,stopped_us=2;"
            "INSERT INTO replication_consumers VALUES('slow',0,0);"
            "INSERT INTO replication_consumers SELECT 'fast',revision,0 FROM metadata;");
        const auto revision = scalar("SELECT revision FROM metadata");
        Retention retention(database, {.days=7, .bytes=0, .replicationRequired=true});
        retention.maintain(nowUs(), "current");
        require(scalar("SELECT count(*) FROM connections") == 64, "An outage discarded pending uploads");

        // One active session and one late update must survive the acknowledged history's deletion.
        execute("INSERT INTO capture_sessions(id,started_us,updated_us,source,process_status,status,computer_name)"
            " VALUES('active',1,1,'test','disabled','running','test');"
            "UPDATE connections SET run_id='active',ended_us=NULL WHERE flow_id=1;"
            "UPDATE metadata SET revision=revision+1;"
            "UPDATE connections SET change_revision=(SELECT revision FROM metadata) WHERE flow_id=2;"
            "UPDATE replication_consumers SET acknowledged_revision=(SELECT revision-1 FROM metadata);"
            "INSERT INTO certificates VALUES('public','{}',x'01',0);"
            "INSERT INTO connection_certificates SELECT run_id,flow_id,'server',0,'public',0"
            " FROM connections WHERE flow_id=3;");
        sqlite3* reader = nullptr;
        require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not open retention reader");
        require(sqlite3_exec(reader, "BEGIN; SELECT * FROM connections", nullptr, nullptr, nullptr) == SQLITE_OK,
            "Could not start a concurrent viewer snapshot");
        bool forgotten = false;
        retention.maintain(nowUs(), "active", [&](const std::string& hash) { forgotten |= hash == "public"; });
        require(scalar("SELECT count(*) FROM connections") == 2, "Acknowledged completed metadata was not pruned");
        require(scalar("SELECT count(*) FROM connection_certificates") == 0 &&
            scalar("SELECT count(*) FROM certificates") == 0 && forgotten, "Retention left dangling certificate state");
        require(scalar("SELECT observation_revision FROM metadata") > revision,
            "Cleanup did not invalidate observation views");
        sqlite3_stmt* snapshot = nullptr;
        sqlite3_prepare_v2(reader, "SELECT count(*) FROM connections", -1, &snapshot, nullptr);
        require(sqlite3_step(snapshot) == SQLITE_ROW && sqlite3_column_int(snapshot, 0) == 64,
            "Cleanup invalidated a concurrent viewer snapshot");
        sqlite3_finalize(snapshot);
        sqlite3_exec(reader, "COMMIT", nullptr, nullptr, nullptr);
        sqlite3_close(reader);
        execute("UPDATE replication_consumers SET acknowledged_revision=(SELECT revision FROM metadata)");
        retention.maintain(nowUs(), "active");
        require(scalar("SELECT count(*) FROM connections") == 1, "Late updates were not pruned after upload");
        require(scalar("SELECT count(*) FROM pragma_foreign_key_check") == 0,
            "Retention violated journal foreign keys");
        Retention size(database, {.days=0, .bytes=1, .replicationRequired=true});
        size.maintain(nowUs(), "active");
        require(scalar("SELECT blocked FROM retention_state") == 1 &&
            scalar("SELECT count(*) FROM connections") == 1, "The size target discarded an active connection");
        execute("DELETE FROM replication_consumers");
        size.maintain(nowUs(), "active");
        require(scalar("SELECT count(*) FROM connections") == 1, "Required replication without a relay lost data");

        // A long connection's old hello does not make a recent close eligible for cleanup.
        const auto closed = "UPDATE connections SET ended_us=" + std::to_string(nowUs()) + " WHERE flow_id=1";
        execute(closed.c_str());
        Retention recent(database, {.days=7, .bytes=0});
        recent.maintain(nowUs(), "active");
        require(scalar("SELECT count(*) FROM connections") == 1, "Retention pruned a recently closed connection");
        execute("UPDATE connections SET ended_us=2 WHERE flow_id=1");
        recent.maintain(nowUs(), "active");
        require(scalar("SELECT count(*) FROM connections") == 0, "Aged completed connections were not pruned");
        sqlite3_close(database);
        std::filesystem::remove_all(directory);
    }
    catch (...)
    {
        sqlite3_close(database);
        throw;
    }
}
}
