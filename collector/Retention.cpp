#include "Retention.h"
#include <sqlite3.h>
#include <algorithm>
#include <limits>
#include <memory>
#include <stdexcept>
#include <vector>
#include <string>

namespace Cipherazzi
{
Retention::Retention(sqlite3* database, RetentionLimits limits) : database_(database), limits_(limits)
{
    const bool linkInventoryNeeded = sqlite3_table_column_metadata(database_, nullptr, "endpoint_certificates",
        "event_id", nullptr, nullptr, nullptr, nullptr, nullptr) != SQLITE_OK;
    const char* schema = R"SQL(
        CREATE TABLE IF NOT EXISTS replication_consumers (
            target_id TEXT PRIMARY KEY, acknowledged_revision INTEGER NOT NULL CHECK(acknowledged_revision>=0),
            updated_us INTEGER NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS retention_state (
            id INTEGER PRIMARY KEY CHECK(id=1), checked_us INTEGER NOT NULL,
            deleted_connections INTEGER NOT NULL, deleted_events INTEGER NOT NULL,
            live_bytes INTEGER NOT NULL, blocked INTEGER NOT NULL, days INTEGER NOT NULL,
            max_bytes INTEGER NOT NULL, replication_required INTEGER NOT NULL
        ) STRICT;
        INSERT OR IGNORE INTO retention_state VALUES(1,0,0,0,0,0,30,536870912,0);
        CREATE INDEX IF NOT EXISTS connections_retention_activity ON connections
            (max(last_us,coalesce(ended_us,last_us)),id);
        CREATE INDEX IF NOT EXISTS endpoint_events_time_id ON endpoint_events(timestamp_us DESC,id DESC);
        CREATE TABLE IF NOT EXISTS endpoint_certificates (
            event_id TEXT NOT NULL REFERENCES endpoint_events(id), sha256 TEXT NOT NULL REFERENCES certificates(sha256),
            PRIMARY KEY(event_id,sha256)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS endpoint_certificates_hash ON endpoint_certificates(sha256);
    )SQL";
    if (sqlite3_exec(database_, schema, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_));
    if (linkInventoryNeeded && sqlite3_exec(database_, R"SQL(
        INSERT OR IGNORE INTO endpoint_certificates
            SELECT e.id,p.sha256 FROM endpoint_events e JOIN certificates p ON e.certificate_id=p.sha256;
        INSERT OR IGNORE INTO endpoint_certificates
            SELECT e.id,j.value FROM endpoint_events e,json_each(e.detail_json,'$.server_certificates') j
            WHERE j.type='text' AND EXISTS(SELECT 1 FROM certificates p WHERE p.sha256=j.value);
        INSERT OR IGNORE INTO endpoint_certificates
            SELECT e.id,j.value FROM endpoint_events e,json_each(e.detail_json,'$.client_certificates') j
            WHERE j.type='text' AND EXISTS(SELECT 1 FROM certificates p WHERE p.sha256=j.value);
    )SQL", nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_));
}

bool Retention::maintain(int64_t timestampUs, std::string_view currentRun,
    const std::function<void(const std::string&)>& forget)
{
    // Short transactions reclaim completed observations without waiting on a remote server.
    auto execute = [&](const char* sql)
    {
        if (sqlite3_exec(database_, sql, nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(database_));
    };
    auto prepare = [&](const char* sql)
    {
        sqlite3_stmt* statement = nullptr;
        if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(database_));
        return std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>(statement, sqlite3_finalize);
    };
    auto scalar = [&](const char* sql)
    {
        auto statement = prepare(sql);
        if (sqlite3_step(statement.get()) != SQLITE_ROW)
            throw std::runtime_error(sqlite3_errmsg(database_));
        return sqlite3_column_int64(statement.get(), 0);
    };
    auto step = [&](sqlite3_stmt* statement)
    {
        if (sqlite3_step(statement) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_));
        return sqlite3_changes(database_);
    };
    execute("BEGIN IMMEDIATE");
    const auto pageSize = scalar("PRAGMA page_size");
    const auto liveBytes = (scalar("PRAGMA page_count") - scalar("PRAGMA freelist_count")) * pageSize;
    const bool overSize = limits_.bytes && static_cast<uint64_t>(liveBytes) > limits_.bytes;
    const auto safeRevision = scalar(limits_.replicationRequired ?
        "SELECT coalesce(min(acknowledged_revision),0) FROM replication_consumers" :
        "SELECT coalesce((SELECT min(acknowledged_revision) FROM replication_consumers),revision) FROM metadata");
    const auto age = limits_.days ? timestampUs - limits_.days * 86400000000LL : 0;
    const auto quiet = timestampUs - 300000000LL;
    const auto cutoff = safeRevision && (limits_.days || overSize) ?
        (overSize ? quiet : std::min(quiet, age)) : std::numeric_limits<int64_t>::min();

    // Name the activity-ordered index and the join order: planner statistics gathered while the journal was
    // small would otherwise read every observation of a session on each pass.
    auto candidates = prepare(R"SQL(
        SELECT c.id FROM connections c INDEXED BY connections_retention_activity
            CROSS JOIN capture_sessions s ON s.id=c.run_id
        WHERE max(c.last_us,coalesce(c.ended_us,c.last_us))<? AND
            (c.ended_us IS NOT NULL OR s.stopped_us IS NOT NULL)
            AND c.change_revision<=? AND NOT EXISTS
                (SELECT 1 FROM connection_certificates l WHERE l.run_id=c.run_id AND l.flow_id=c.flow_id
                    AND l.change_revision>?)
            AND (? OR (? AND max(c.last_us,coalesce(c.ended_us,c.last_us))<? AND s.started_us<?))
        ORDER BY max(c.last_us,coalesce(c.ended_us,c.last_us)),c.id LIMIT 256
    )SQL");
    sqlite3_bind_int64(candidates.get(), 1, cutoff);
    sqlite3_bind_int64(candidates.get(), 2, safeRevision);
    sqlite3_bind_int64(candidates.get(), 3, safeRevision);
    sqlite3_bind_int(candidates.get(), 4, overSize);
    sqlite3_bind_int(candidates.get(), 5, limits_.days != 0);
    sqlite3_bind_int64(candidates.get(), 6, age);
    sqlite3_bind_int64(candidates.get(), 7, age);
    execute("CREATE TEMP TABLE IF NOT EXISTS retention_ids(id INTEGER PRIMARY KEY); DELETE FROM retention_ids");
    auto remember = prepare("INSERT INTO retention_ids VALUES(?)");
    int result;
    while ((result = sqlite3_step(candidates.get())) == SQLITE_ROW)
    {
        sqlite3_reset(remember.get());
        sqlite3_bind_int64(remember.get(), 1, sqlite3_column_int64(candidates.get(), 0));
        step(remember.get());
    }
    if (result != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_));
    candidates.reset();
    execute(R"SQL(
        DELETE FROM connection_certificates WHERE (run_id,flow_id) IN
            (SELECT run_id,flow_id FROM connections WHERE id IN(SELECT id FROM retention_ids));
        DELETE FROM connections WHERE id IN(SELECT id FROM retention_ids);
    )SQL");
    const auto connections = sqlite3_changes(database_);
    auto events = prepare(R"SQL(
        SELECT e.id FROM endpoint_events e INDEXED BY endpoint_events_time_id
            CROSS JOIN capture_sessions s ON s.id=e.run_id
        WHERE e.timestamp_us<? AND e.change_revision<=? AND
            (? OR (? AND e.timestamp_us<? AND s.started_us<?))
        ORDER BY e.timestamp_us LIMIT 256
    )SQL");
    sqlite3_bind_int64(events.get(), 1, cutoff);
    sqlite3_bind_int64(events.get(), 2, safeRevision);
    sqlite3_bind_int(events.get(), 3, overSize);
    sqlite3_bind_int(events.get(), 4, limits_.days != 0);
    sqlite3_bind_int64(events.get(), 5, age);
    sqlite3_bind_int64(events.get(), 6, age);
    execute("CREATE TEMP TABLE IF NOT EXISTS retention_events(id TEXT PRIMARY KEY); DELETE FROM retention_events");
    auto eventId = prepare("INSERT INTO retention_events VALUES(?)");
    while ((result = sqlite3_step(events.get())) == SQLITE_ROW)
    {
        sqlite3_reset(eventId.get());
        sqlite3_bind_text(eventId.get(), 1, reinterpret_cast<const char*>(sqlite3_column_text(events.get(), 0)),
            -1, SQLITE_TRANSIENT);
        step(eventId.get());
    }
    if (result != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_));
    events.reset();
    eventId.reset();
    execute("DELETE FROM endpoint_certificates WHERE event_id IN(SELECT id FROM retention_events);"
        "DELETE FROM endpoint_events WHERE id IN(SELECT id FROM retention_events)");
    const auto deletedEvents = sqlite3_changes(database_);
    auto orphanIds = prepare(R"SQL(
        SELECT sha256 FROM certificates p WHERE p.change_revision<=? AND NOT EXISTS
            (SELECT 1 FROM connection_certificates l WHERE l.sha256=p.sha256)
            AND NOT EXISTS (SELECT 1 FROM endpoint_certificates e WHERE e.sha256=p.sha256) LIMIT 32
    )SQL");
    sqlite3_bind_int64(orphanIds.get(), 1, safeRevision);
    std::vector<std::string> removed;
    if (limits_.days || overSize)
    {
        while ((result = sqlite3_step(orphanIds.get())) == SQLITE_ROW)
            removed.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(orphanIds.get(), 0)));
        if (result != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_));
    }
    orphanIds.reset();
    auto orphan = prepare("DELETE FROM certificates WHERE sha256=?");
    for (const auto& hash : removed)
    {
        sqlite3_reset(orphan.get());
        sqlite3_bind_text(orphan.get(), 1, hash.c_str(), -1, SQLITE_TRANSIENT);
        step(orphan.get());
    }
    orphan.reset();
    auto sessions = prepare(R"SQL(
        DELETE FROM capture_sessions WHERE id IN (
            SELECT s.id FROM capture_sessions s WHERE s.id<>? AND s.stopped_us<?
                AND s.change_revision<=? AND (? OR (? AND s.started_us<?))
                AND NOT EXISTS(SELECT 1 FROM connections c WHERE c.run_id=s.id)
                AND NOT EXISTS(SELECT 1 FROM endpoint_events e WHERE e.run_id=s.id) LIMIT 32)
    )SQL");
    sqlite3_bind_text(sessions.get(), 1, currentRun.data(), static_cast<int>(currentRun.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(sessions.get(), 2, cutoff);
    sqlite3_bind_int64(sessions.get(), 3, safeRevision);
    sqlite3_bind_int(sessions.get(), 4, overSize);
    sqlite3_bind_int(sessions.get(), 5, limits_.days != 0);
    sqlite3_bind_int64(sessions.get(), 6, age);
    const auto deletedSessions = step(sessions.get());
    sessions.reset();
    if (connections || deletedEvents || deletedSessions || !removed.empty())
        execute("UPDATE metadata SET revision=revision+1 WHERE id=1");

    // A size target cannot justify discarding active connections or an unacknowledged upload backlog.
    auto status = prepare("UPDATE retention_state SET checked_us=?,deleted_connections=deleted_connections+?,"
        "deleted_events=deleted_events+?,live_bytes=?,blocked=?,days=?,max_bytes=?,replication_required=? WHERE id=1");
    sqlite3_bind_int64(status.get(), 1, timestampUs);
    sqlite3_bind_int64(status.get(), 2, connections);
    sqlite3_bind_int64(status.get(), 3, deletedEvents);
    sqlite3_bind_int64(status.get(), 4, liveBytes);
    sqlite3_bind_int(status.get(), 5,
        overSize && !connections && !deletedEvents && !deletedSessions && removed.empty());
    sqlite3_bind_int64(status.get(), 6, limits_.days);
    sqlite3_bind_int64(status.get(), 7, static_cast<sqlite3_int64>(limits_.bytes));
    sqlite3_bind_int(status.get(), 8, limits_.replicationRequired);
    step(status.get());
    status.reset();
    execute("COMMIT");
    if (forget)
        for (const auto& hash : removed)
            forget(hash);

    // Incremental vacuum bounds each maintenance pass; WAL readers may delay physical reclamation.
    if (connections || deletedEvents || deletedSessions || !removed.empty())
        execute("PRAGMA incremental_vacuum(128)");
    sqlite3_wal_checkpoint_v2(database_, nullptr, SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
    return connections == 256 || deletedEvents == 256 || removed.size() == 32;
}
}
