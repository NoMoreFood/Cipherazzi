#include "HttpSpyStore.h"
#include "../shared/FileSecurity.h"

#include <sqlite3.h>
#include <stdexcept>

namespace Cipherazzi
{
bool elevated();

void HttpSpyStore::DatabaseCloser::operator()(sqlite3* value) const { sqlite3_close_v2(value); }
void HttpSpyStore::StatementCloser::operator()(sqlite3_stmt* value) const { sqlite3_finalize(value); }

std::filesystem::path HttpSpyStore::pathFor(const std::filesystem::path& journal)
{
    return journal.parent_path() / L"HttpSpy" / journal.filename();
}

HttpSpyStore::Statement HttpSpyStore::prepare(const char* sql)
{
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database_.get(), sql, -1, &statement, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
    return Statement(statement);
}

void HttpSpyStore::execute(const char* sql)
{
    if (sqlite3_exec(database_.get(), sql, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
}

HttpSpyStore::HttpSpyStore(const std::filesystem::path& path, std::string runId, std::string source, int days,
    uint64_t bytes, HttpSpyStatistics statistics) :
    runId_(std::move(runId)), statistics_(std::move(statistics)), days_(days), bytes_(bytes)
{
    // An elevated collector keeps the folder private; replaying a capture without elevation stays with the user.
    const auto absolute = std::filesystem::absolute(path);
    const auto directory = absolute.parent_path();
    const bool existing = !std::filesystem::create_directories(directory);
    const bool administrative = elevated();
    if (administrative)
    {
        if (existing)
            FileSecurity::requireAdministrativeOwner(directory);
        FileSecurity::applyDacl(directory, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        if (!existing)
            FileSecurity::assignAdministrativeOwner(directory);

        // Existing databases and SQLite sidecars may have protected permissions that ignore directory inheritance.
        for (const auto suffix : {L"", L"-wal", L"-shm", L"-journal"})
        {
            auto file = absolute;
            file += suffix;
            const auto attributes = GetFileAttributesW(file.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES)
            {
                const auto error = GetLastError();
                FileSecurity::require(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND,
                    "Inspect HTTP Spy storage");
                continue;
            }
            if (attributes & FILE_ATTRIBUTE_DIRECTORY)
                throw std::runtime_error("HTTP Spy storage must use ordinary files");
            FileSecurity::requireAdministrativeOwner(file);
            FileSecurity::requireAdministrativeWrites(file);
            FileSecurity::applyDacl(file, L"D:P(A;;FA;;;SY)(A;;FA;;;BA)");
        }
    }
    sqlite3* database = nullptr;
    const auto text = utf8(absolute.wstring());
    const auto opened = sqlite3_open_v2(text.c_str(), &database,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, nullptr);
    database_.reset(database);
    if (opened != SQLITE_OK)
        throw std::runtime_error(database ? sqlite3_errmsg(database) : "Could not open the HTTP Spy database");
    if (administrative)
        FileSecurity::assignAdministrativeOwner(absolute);
    sqlite3_busy_timeout(database, 2000);
    auto scalar = [&](const char* sql)
    {
        auto statement = prepare(sql);
        if (sqlite3_step(statement.get()) != SQLITE_ROW)
            throw std::runtime_error("Could not inspect the HTTP Spy database");
        return sqlite3_column_int64(statement.get(), 0);
    };
    constexpr int ApplicationId = 0x48545050;
    const auto application = scalar("PRAGMA application_id");
    if (application != 0 && application != ApplicationId)
        throw std::runtime_error("The selected HTTP Spy database belongs to another application");
    if (application == 0)
    {
        if (scalar("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'") != 0)
            throw std::runtime_error("The selected HTTP Spy database is not empty");
        execute("PRAGMA page_size=8192; PRAGMA auto_vacuum=INCREMENTAL");
    }
    else if (const auto version = scalar("PRAGMA user_version"); version != 1 && version != 2)
        throw std::runtime_error("Unsupported HTTP Spy database schema");
    if (application == ApplicationId && scalar("PRAGMA user_version") == 1)
        execute("BEGIN IMMEDIATE; ALTER TABLE exchanges ADD COLUMN flow_started_us INTEGER NOT NULL DEFAULT 0; "
            "ALTER TABLE exchanges ADD COLUMN connection_client_port INTEGER NOT NULL DEFAULT 0; "
            "PRAGMA user_version=2; COMMIT;");

    // Deleted messages must not linger in free pages.
    execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA secure_delete=ON; PRAGMA trusted_schema=OFF;");
    execute(R"SQL(
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS store (
            id INTEGER PRIMARY KEY CHECK(id=1), database_id TEXT NOT NULL, revision INTEGER NOT NULL
        ) STRICT;
        INSERT OR IGNORE INTO store VALUES(1,lower(hex(randomblob(16))),0);
        CREATE TABLE IF NOT EXISTS sessions (
            run_id TEXT PRIMARY KEY, started_us INTEGER NOT NULL, updated_us INTEGER NOT NULL, source TEXT NOT NULL,
            tls_flows INTEGER NOT NULL DEFAULT 0, decoded_flows INTEGER NOT NULL DEFAULT 0,
            missing_secrets INTEGER NOT NULL DEFAULT 0, unsupported INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0, exchanges INTEGER NOT NULL DEFAULT 0,
            secrets INTEGER NOT NULL DEFAULT 0
        ) STRICT;
        CREATE TABLE IF NOT EXISTS exchanges (
            id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES sessions(run_id),
            flow_id INTEGER NOT NULL, sequence INTEGER NOT NULL,
            started_us INTEGER NOT NULL, request_end_us INTEGER, response_start_us INTEGER, ended_us INTEGER NOT NULL,
            client_address TEXT NOT NULL, client_port INTEGER NOT NULL,
            server_address TEXT NOT NULL, server_port INTEGER NOT NULL,
            client_pid INTEGER, client_process TEXT NOT NULL, client_path TEXT NOT NULL, client_account TEXT NOT NULL,
            server_pid INTEGER, server_process TEXT NOT NULL,
            transport TEXT NOT NULL, scheme TEXT NOT NULL, version TEXT NOT NULL, method TEXT NOT NULL,
            host TEXT NOT NULL, target TEXT NOT NULL, status INTEGER, reason TEXT NOT NULL,
            request_headers TEXT NOT NULL, response_headers TEXT NOT NULL, request_body BLOB, response_body BLOB,
            request_bytes INTEGER NOT NULL, response_bytes INTEGER NOT NULL, content_type TEXT NOT NULL,
            state TEXT NOT NULL, note TEXT NOT NULL,
            flow_started_us INTEGER NOT NULL DEFAULT 0, connection_client_port INTEGER NOT NULL DEFAULT 0,
            UNIQUE(run_id,flow_id,sequence)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS exchanges_time ON exchanges(started_us DESC,id DESC);
        CREATE INDEX IF NOT EXISTS exchanges_ended ON exchanges(ended_us);
        PRAGMA application_id=1213485136;
        PRAGMA user_version=2;
        COMMIT;
    )SQL");
    auto start = prepare("INSERT OR IGNORE INTO sessions(run_id,started_us,updated_us,source) VALUES(?,?,?,?)");
    sqlite3_bind_text(start.get(), 1, runId_.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(start.get(), 2, nowUs());
    sqlite3_bind_int64(start.get(), 3, nowUs());
    sqlite3_bind_text(start.get(), 4, source.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(start.get()) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database));
    upsert_ = prepare(R"SQL(
        INSERT INTO exchanges (run_id,flow_id,sequence,started_us,request_end_us,response_start_us,ended_us,
            client_address,client_port,server_address,server_port,client_pid,client_process,client_path,
            client_account,server_pid,server_process,transport,scheme,version,method,host,target,status,reason,
            request_headers,response_headers,request_body,response_body,request_bytes,response_bytes,content_type,
            state,note,flow_started_us,connection_client_port)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(run_id,flow_id,sequence) DO UPDATE SET
            started_us=excluded.started_us,request_end_us=excluded.request_end_us,
            response_start_us=excluded.response_start_us,ended_us=excluded.ended_us,
            client_pid=CASE WHEN @client_owner THEN excluded.client_pid ELSE exchanges.client_pid END,
            client_process=CASE WHEN @client_owner THEN excluded.client_process
                ELSE exchanges.client_process END,
            client_path=CASE WHEN @client_owner THEN excluded.client_path ELSE exchanges.client_path END,
            client_account=CASE WHEN @client_owner THEN excluded.client_account
                ELSE exchanges.client_account END,
            server_pid=CASE WHEN @server_owner THEN excluded.server_pid ELSE exchanges.server_pid END,
            server_process=CASE WHEN @server_owner THEN excluded.server_process
                ELSE exchanges.server_process END,
            transport=excluded.transport,scheme=excluded.scheme,version=excluded.version,method=excluded.method,
            host=excluded.host,target=excluded.target,status=excluded.status,reason=excluded.reason,
            request_headers=excluded.request_headers,response_headers=excluded.response_headers,
            request_body=excluded.request_body,response_body=excluded.response_body,
            request_bytes=excluded.request_bytes,response_bytes=excluded.response_bytes,
            content_type=excluded.content_type,state=excluded.state,note=excluded.note,
            flow_started_us=excluded.flow_started_us,connection_client_port=excluded.connection_client_port
    )SQL");
    owners_ = prepare(R"SQL(
        UPDATE exchanges SET
            client_pid=CASE WHEN ?10 THEN ?4 ELSE client_pid END,
            client_process=CASE WHEN ?10 THEN ?5 ELSE client_process END,
            client_path=CASE WHEN ?10 THEN ?6 ELSE client_path END,
            client_account=CASE WHEN ?10 THEN ?7 ELSE client_account END,
            server_pid=CASE WHEN ?11 THEN ?8 ELSE server_pid END,
            server_process=CASE WHEN ?11 THEN ?9 ELSE server_process END
        WHERE run_id=?1 AND flow_id=?2 AND sequence=?3
    )SQL");
    session_ = prepare(R"SQL(
        UPDATE sessions SET updated_us=?,tls_flows=?,decoded_flows=?,missing_secrets=?,unsupported=?,failed=?,
            exchanges=?,secrets=? WHERE run_id=?
    )SQL");
    revision_ = prepare("UPDATE store SET revision=revision+1 WHERE id=1");
    if (administrative)
        for (const auto suffix : {L"-wal", L"-shm"})
        {
            auto sidecar = absolute;
            sidecar += suffix;
            if (std::filesystem::exists(sidecar))
                FileSecurity::assignAdministrativeOwner(sidecar);
        }
    nextMaintenance_ = std::chrono::steady_clock::now() + std::chrono::seconds(5);
}

HttpSpyStore::~HttpSpyStore() = default;

std::array<uint64_t, 7> HttpSpyStore::snapshot() const
{
    return statistics_ ? statistics_() : std::array<uint64_t, 7>{};
}

bool HttpSpyStore::due() const
{
    return std::chrono::steady_clock::now() >= nextStatistics_ && snapshot() != written_;
}

void HttpSpyStore::write(const HttpExchange& exchange)
{
    auto* statement = exchange.ownersOnly ? owners_.get() : upsert_.get();
    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    int index = 0;
    auto text = [&](const std::string& value)
    {
        if (sqlite3_bind_text(statement, ++index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT))
            throw std::runtime_error("Could not bind HTTP Spy text");
    };
    auto integer = [&](int64_t value, bool present = true)
    {
        ++index;
        if (present ? sqlite3_bind_int64(statement, index, value) : sqlite3_bind_null(statement, index))
            throw std::runtime_error("Could not bind HTTP Spy value");
    };
    auto blob = [&](const std::vector<uint8_t>& value, bool present)
    {
        ++index;
        if (present ? sqlite3_bind_blob(statement, index, value.data(), static_cast<int>(value.size()),
            SQLITE_TRANSIENT) : sqlite3_bind_null(statement, index))
            throw std::runtime_error("Could not bind HTTP Spy content");
    };
    const auto account = exchange.clientOwner.account.empty() ? std::string{} :
        exchange.clientOwner.accountDomain.empty() ? exchange.clientOwner.account :
        exchange.clientOwner.accountDomain + "\\" + exchange.clientOwner.account;
    text(runId_);
    integer(exchange.flowId);
    integer(exchange.sequence);
    if (!exchange.ownersOnly)
    {
        integer(exchange.startedUs);
        integer(exchange.requestEndUs, exchange.requestEndUs != 0);
        integer(exchange.responseStartUs, exchange.responseStartUs != 0);
        integer(exchange.endedUs ? exchange.endedUs : exchange.startedUs);
        text(exchange.client.text());
        integer(exchange.client.port);
        text(exchange.server.text());
        integer(exchange.server.port);
    }
    integer(exchange.clientOwner.pid, exchange.clientOwner.pid != 0);
    text(exchange.clientOwner.name);
    text(exchange.clientOwner.path);
    text(account);
    integer(exchange.serverOwner.pid, exchange.serverOwner.pid != 0);
    text(exchange.serverOwner.name);
    if (!exchange.ownersOnly)
    {
        text(exchange.transport);
        text(exchange.scheme);
        text(exchange.version);
        text(exchange.method);
        text(exchange.host);
        text(exchange.target);
        integer(exchange.status, exchange.status != 0);
        text(exchange.reason);
        text(exchange.requestHeaders);
        text(exchange.responseHeaders);
        blob(exchange.requestBody, exchange.requestBytes != 0);
        blob(exchange.responseBody, exchange.responseBytes != 0);
        integer(static_cast<int64_t>(exchange.requestBytes));
        integer(static_cast<int64_t>(exchange.responseBytes));
        text(exchange.contentType);
        text(exchange.state);
        text(exchange.note);
        integer(exchange.flowStartedUs);
        integer(exchange.connectionClientPort ? exchange.connectionClientPort : exchange.client.port);
    }
    integer(exchange.clientOwner.pid || exchange.clientOwner.ambiguous);
    integer(exchange.serverOwner.pid || exchange.serverOwner.ambiguous);
    if (sqlite3_step(statement) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
}

void HttpSpyStore::commit(std::vector<HttpExchange>& exchanges, bool final)
{
    // One transaction publishes messages and the counters that explain the connections left undecoded.
    const auto counts = snapshot();
    if (exchanges.empty() && counts == written_ && !final)
        return;
    execute("BEGIN IMMEDIATE");
    try
    {
        for (const auto& exchange : exchanges)
            write(exchange);
        auto* session = session_.get();
        sqlite3_reset(session);
        sqlite3_bind_int64(session, 1, nowUs());
        for (size_t i = 0; i < counts.size(); ++i)
            sqlite3_bind_int64(session, static_cast<int>(2 + i), static_cast<sqlite3_int64>(counts[i]));
        sqlite3_bind_text(session, 9, runId_.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(session) != SQLITE_DONE || sqlite3_step(revision_.get()) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_.get()));
        sqlite3_reset(revision_.get());
        execute("COMMIT");
    }
    catch (...)
    {
        sqlite3_exec(database_.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    written_ = counts;
    nextStatistics_ = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    exchanges.clear();
}

void HttpSpyStore::maintain(bool final)
{
    const auto now = std::chrono::steady_clock::now();
    if (!final && now < nextMaintenance_)
        return;
    nextMaintenance_ = now + std::chrono::seconds(5);
    auto scalar = [&](const char* sql)
    {
        auto statement = prepare(sql);
        if (sqlite3_step(statement.get()) != SQLITE_ROW)
            throw std::runtime_error(sqlite3_errmsg(database_.get()));
        return sqlite3_column_int64(statement.get(), 0);
    };

    // Publish retained messages and their revision together, deferring cleanup while another writer is active.
    const auto begun = sqlite3_exec(database_.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
    if (begun == SQLITE_BUSY)
        return;
    if (begun != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
    int64_t removed = 0;
    try
    {
        // Age and size limits remove the oldest messages in bounded steps.
        if (days_)
        {
            auto expired = prepare("DELETE FROM exchanges WHERE id IN "
                "(SELECT id FROM exchanges WHERE ended_us<? ORDER BY ended_us LIMIT 512)");
            sqlite3_bind_int64(expired.get(), 1, nowUs() - days_ * 86400000000LL);
            if (sqlite3_step(expired.get()) != SQLITE_DONE)
                throw std::runtime_error(sqlite3_errmsg(database_.get()));
            removed += sqlite3_changes(database_.get());
        }
        for (int pass = 0; bytes_ && pass < 8; ++pass)
        {
            const auto live = (scalar("PRAGMA page_count") - scalar("PRAGMA freelist_count")) *
                scalar("PRAGMA page_size");
            if (static_cast<uint64_t>(live) <= bytes_)
                break;
            execute("DELETE FROM exchanges WHERE id IN (SELECT id FROM exchanges ORDER BY id LIMIT 256)");
            const auto deleted = sqlite3_changes(database_.get());
            removed += deleted;
            if (!deleted)
                break;
            execute("PRAGMA incremental_vacuum(256)");
        }
        if (removed)
            execute("UPDATE store SET revision=revision+1 WHERE id=1");
        execute("COMMIT");
    }
    catch (...)
    {
        sqlite3_exec(database_.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
    if (removed)
        execute("PRAGMA incremental_vacuum(128)");
    sqlite3_wal_checkpoint_v2(database_.get(), nullptr, SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
}
}
