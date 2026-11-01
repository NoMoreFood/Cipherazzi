#include "Retention.h"
#include <windows.h>
#include <sqlite3.h>
#include <algorithm>
#include <limits>
#include <memory>
#include <stdexcept>
#include <vector>
#include <string>

namespace Cipherazzi
{
std::wstring sessionMutexName(std::string_view runId)
{
    return L"Global\\Cipherazzi.Capture." + std::wstring(runId.begin(), runId.end());
}

Retention::Retention(sqlite3* database, RetentionLimits limits) : database_(database), limits_(limits)
{
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
        CREATE TABLE IF NOT EXISTS endpoint_certificates (
            event_id TEXT NOT NULL REFERENCES endpoint_events(id), sha256 TEXT NOT NULL REFERENCES certificates(sha256),
            PRIMARY KEY(event_id,sha256)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS endpoint_certificates_hash ON endpoint_certificates(sha256);
        CREATE TEMP TABLE IF NOT EXISTS retention_ids(id INTEGER PRIMARY KEY);
        CREATE TEMP TABLE IF NOT EXISTS retention_events(id TEXT PRIMARY KEY);
    )SQL";
    Sqlite::execute(database_, schema);

    // Maintenance repeats every 100 ms while catching up, so its statements are compiled once.
    running_ = prepare("SELECT id FROM capture_sessions WHERE stopped_us IS NULL AND id<>?");
    recover_ = prepare("UPDATE capture_sessions SET stopped_us=updated_us,status='interrupted',"
        "active_flows=0,buffered_bytes=0,change_revision=(SELECT revision FROM metadata) WHERE id=?");
    pageSize_ = prepare("PRAGMA page_size");
    pageCount_ = prepare("PRAGMA page_count");
    freePages_ = prepare("PRAGMA freelist_count");
    safeRevision_ = prepare(limits_.replicationRequired ?
        "SELECT coalesce(min(acknowledged_revision),0) FROM replication_consumers" :
        "SELECT coalesce((SELECT min(acknowledged_revision) FROM replication_consumers),revision) FROM metadata");

    // Name the activity-ordered index and the join order: planner statistics gathered while the journal was
    // small would otherwise read every observation of a session on each pass.
    candidates_ = prepare(R"SQL(
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
    remember_ = prepare("INSERT INTO retention_ids VALUES(?)");
    events_ = prepare(R"SQL(
        SELECT e.id FROM endpoint_events e INDEXED BY endpoint_events_time_id
            CROSS JOIN capture_sessions s ON s.id=e.run_id
        WHERE e.timestamp_us<? AND e.change_revision<=? AND
            (? OR (? AND e.timestamp_us<? AND s.started_us<?))
        ORDER BY e.timestamp_us LIMIT 256
    )SQL");
    eventId_ = prepare("INSERT INTO retention_events VALUES(?)");
    orphanIds_ = prepare(R"SQL(
        SELECT sha256 FROM certificates p WHERE p.change_revision<=? AND NOT EXISTS
            (SELECT 1 FROM connection_certificates l WHERE l.sha256=p.sha256)
            AND NOT EXISTS (SELECT 1 FROM endpoint_certificates e WHERE e.sha256=p.sha256) LIMIT 32
    )SQL");
    orphan_ = prepare("DELETE FROM certificates WHERE sha256=?");
    sessions_ = prepare(R"SQL(
        DELETE FROM capture_sessions WHERE id IN (
            SELECT s.id FROM capture_sessions s WHERE s.id<>? AND s.stopped_us<?
                AND s.change_revision<=? AND (? OR (? AND s.started_us<?))
                AND NOT EXISTS(SELECT 1 FROM connections c WHERE c.run_id=s.id)
                AND NOT EXISTS(SELECT 1 FROM endpoint_events e WHERE e.run_id=s.id) LIMIT 32)
    )SQL");
    status_ = prepare("UPDATE retention_state SET checked_us=?,deleted_connections=deleted_connections+?,"
        "deleted_events=deleted_events+?,live_bytes=?,blocked=?,days=?,max_bytes=?,replication_required=? WHERE id=1");
}

bool Retention::maintain(int64_t timestampUs, std::string_view currentRun,
    const std::function<void(const std::string&)>& forget)
{
    // Short transactions reclaim completed observations without waiting on a remote server.
    auto execute = [&](const char* sql) { Sqlite::execute(database_, sql); };
    auto use = [](const Statement& statement)
    {
        sqlite3_reset(statement.get());
        sqlite3_clear_bindings(statement.get());
        return statement.get();
    };
    auto scalar = [&](const Statement& statement)
    {
        const auto query = use(statement);
        if (sqlite3_step(query) != SQLITE_ROW)
            throw std::runtime_error(sqlite3_errmsg(database_));
        const auto value = sqlite3_column_int64(query, 0);
        sqlite3_reset(query);
        return value;
    };
    auto step = [&](sqlite3_stmt* statement)
    {
        if (sqlite3_step(statement) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_));
        return sqlite3_changes(database_);
    };

    // Another writer can hold the journal for longer than the busy timeout; cleanup then waits for its next pass.
    const auto begun = sqlite3_exec(database_, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
    if (begun == SQLITE_BUSY)
        return false;
    if (begun != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_));

    // OS handles outlive delayed heartbeats and disappear when a collector exits, including after a crash.
    const auto running = use(running_);
    sqlite3_bind_text(running, 1, currentRun.data(), static_cast<int>(currentRun.size()), SQLITE_TRANSIENT);
    std::vector<std::string> abandoned;
    int result;
    while ((result = sqlite3_step(running)) == SQLITE_ROW)
    {
        const std::string id = reinterpret_cast<const char*>(sqlite3_column_text(running, 0));
        const auto owner = OpenMutexW(SYNCHRONIZE, FALSE, sessionMutexName(id).c_str());
        if (owner)
            CloseHandle(owner);
        else if (GetLastError() == ERROR_FILE_NOT_FOUND)
            abandoned.push_back(id);
    }
    if (result != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_));
    if (!abandoned.empty())
    {
        execute("UPDATE metadata SET revision=revision+1,observation_revision=revision+1 WHERE id=1");
        for (const auto& id : abandoned)
        {
            const auto recover = use(recover_);
            sqlite3_bind_text(recover, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            step(recover);
        }
    }
    const auto pageSize = scalar(pageSize_);
    const auto liveBytes = (scalar(pageCount_) - scalar(freePages_)) * pageSize;
    const bool overSize = limits_.bytes && static_cast<uint64_t>(liveBytes) > limits_.bytes;
    const auto safeRevision = scalar(safeRevision_);
    const auto age = limits_.days ? timestampUs - limits_.days * 86400000000LL : 0;
    const auto quiet = timestampUs - 300000000LL;
    const auto cutoff = safeRevision && (limits_.days || overSize) ?
        (overSize ? quiet : std::min(quiet, age)) : std::numeric_limits<int64_t>::min();

    const auto candidates = use(candidates_);
    sqlite3_bind_int64(candidates, 1, cutoff);
    sqlite3_bind_int64(candidates, 2, safeRevision);
    sqlite3_bind_int64(candidates, 3, safeRevision);
    sqlite3_bind_int(candidates, 4, overSize);
    sqlite3_bind_int(candidates, 5, limits_.days != 0);
    sqlite3_bind_int64(candidates, 6, age);
    sqlite3_bind_int64(candidates, 7, age);
    execute("DELETE FROM retention_ids");
    while ((result = sqlite3_step(candidates)) == SQLITE_ROW)
    {
        const auto remember = use(remember_);
        sqlite3_bind_int64(remember, 1, sqlite3_column_int64(candidates, 0));
        step(remember);
    }
    if (result != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_));
    execute(R"SQL(
        DELETE FROM connection_certificates WHERE (run_id,flow_id) IN
            (SELECT run_id,flow_id FROM connections WHERE id IN(SELECT id FROM retention_ids));
        DELETE FROM connections WHERE id IN(SELECT id FROM retention_ids);
    )SQL");
    const auto connections = sqlite3_changes(database_);
    const auto events = use(events_);
    sqlite3_bind_int64(events, 1, cutoff);
    sqlite3_bind_int64(events, 2, safeRevision);
    sqlite3_bind_int(events, 3, overSize);
    sqlite3_bind_int(events, 4, limits_.days != 0);
    sqlite3_bind_int64(events, 5, age);
    sqlite3_bind_int64(events, 6, age);
    execute("DELETE FROM retention_events");
    while ((result = sqlite3_step(events)) == SQLITE_ROW)
    {
        const auto eventId = use(eventId_);
        sqlite3_bind_text(eventId, 1, reinterpret_cast<const char*>(sqlite3_column_text(events, 0)),
            -1, SQLITE_TRANSIENT);
        step(eventId);
    }
    if (result != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_));
    execute("DELETE FROM endpoint_certificates WHERE event_id IN(SELECT id FROM retention_events);"
        "DELETE FROM endpoint_events WHERE id IN(SELECT id FROM retention_events)");
    const auto deletedEvents = sqlite3_changes(database_);
    std::vector<std::string> removed;
    if (limits_.days || overSize)
    {
        const auto orphanIds = use(orphanIds_);
        sqlite3_bind_int64(orphanIds, 1, safeRevision);
        while ((result = sqlite3_step(orphanIds)) == SQLITE_ROW)
            removed.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(orphanIds, 0)));
        if (result != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_));
    }
    for (const auto& hash : removed)
    {
        const auto orphan = use(orphan_);
        sqlite3_bind_text(orphan, 1, hash.c_str(), -1, SQLITE_TRANSIENT);
        step(orphan);
    }
    const auto sessions = use(sessions_);
    sqlite3_bind_text(sessions, 1, currentRun.data(), static_cast<int>(currentRun.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(sessions, 2, cutoff);
    sqlite3_bind_int64(sessions, 3, safeRevision);
    sqlite3_bind_int(sessions, 4, overSize);
    sqlite3_bind_int(sessions, 5, limits_.days != 0);
    sqlite3_bind_int64(sessions, 6, age);
    const auto deletedSessions = step(sessions);
    if (connections || deletedEvents || deletedSessions || !removed.empty())
        execute("UPDATE metadata SET revision=revision+1,observation_revision=revision+1 WHERE id=1");

    // A size target cannot justify discarding active connections or an unacknowledged upload backlog.
    const auto status = use(status_);
    sqlite3_bind_int64(status, 1, timestampUs);
    sqlite3_bind_int64(status, 2, connections);
    sqlite3_bind_int64(status, 3, deletedEvents);
    sqlite3_bind_int64(status, 4, liveBytes);
    sqlite3_bind_int(status, 5, overSize && !connections && !deletedEvents && !deletedSessions && removed.empty());
    sqlite3_bind_int64(status, 6, limits_.days);
    sqlite3_bind_int64(status, 7, static_cast<sqlite3_int64>(limits_.bytes));
    sqlite3_bind_int(status, 8, limits_.replicationRequired);
    step(status);
    execute("COMMIT");
    if (forget)
        for (const auto& hash : removed)
            forget(hash);

    // Incremental vacuum bounds each maintenance pass; WAL readers may delay physical reclamation.
    if (connections || deletedEvents || deletedSessions || !removed.empty())
    {
        const auto vacuumed = sqlite3_exec(database_, "PRAGMA incremental_vacuum(128)", nullptr, nullptr, nullptr);
        if (vacuumed != SQLITE_OK && vacuumed != SQLITE_BUSY)
            throw std::runtime_error(sqlite3_errmsg(database_));
    }
    sqlite3_wal_checkpoint_v2(database_, nullptr, SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
    return connections == 256 || deletedEvents == 256 || removed.size() == 32;
}
}
