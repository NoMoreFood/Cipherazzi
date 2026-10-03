#include "Storage.h"
#include <sqlite3.h>
#include <filesystem>
#include <stdexcept>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);

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
        require(scalar("SELECT revision FROM metadata") > revision, "Cleanup did not invalidate viewer data");
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
