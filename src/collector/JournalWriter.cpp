#include "JournalWriter.h"
#include "EndpointCorrelation.h"
#include "Vpn.h"
#include <sqlite3.h>
#include <windows.h>
#include <random>
#include <algorithm>
#include <stdexcept>

namespace Cipherazzi
{
void JournalWriter::DatabaseCloser::operator()(sqlite3* value) const { sqlite3_close_v2(value); }
void JournalWriter::StatementCloser::operator()(sqlite3_stmt* value) const { sqlite3_finalize(value); }

JournalWriter::Statement JournalWriter::prepare(const char* sql)
{
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database_.get(), sql, -1, &statement, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
    return Statement(statement);
}

void JournalWriter::execute(const char* sql)
{
    if (sqlite3_exec(database_.get(), sql, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
}

void JournalWriter::begin(std::stop_token draining)
{
    // The relay and the publisher also write the journal and can hold its lock for longer than the busy
    // timeout. The batch in hand is kept and the transaction retried; each attempt waits out that timeout.
    // Once a stop is requested the next refusal is final, so a writer that never lets go cannot hold up shutdown.
    for (;;)
    {
        const auto result = sqlite3_exec(database_.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
        if (result == SQLITE_OK)
            return;
        if (result != SQLITE_BUSY || draining.stop_requested())
            throw std::runtime_error(sqlite3_errmsg(database_.get()));
    }
}

JournalWriter::JournalWriter(const std::filesystem::path& path, Counters& counters, std::string source,
    std::string processStatus, RetentionLimits retention) : counters_(counters)
{
    // A single connection owns all writes; WAL permits concurrent viewer reads.
    sqlite3* database = nullptr;
    const auto pathString = utf8(path.wstring());
    const auto opened = sqlite3_open_v2(pathString.c_str(), &database,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, nullptr);
    database_.reset(database);
    if (opened != SQLITE_OK)
        throw std::runtime_error(database ? sqlite3_errmsg(database) : "Could not open database");
    sqlite3_busy_timeout(database, 2000);
    auto application = prepare("PRAGMA application_id");
    if (sqlite3_step(application.get()) != SQLITE_ROW)
        throw std::runtime_error("Could not inspect database");
    const auto applicationId = sqlite3_column_int(application.get(), 0);
    application.reset();
    auto schema = prepare("PRAGMA user_version");
    if (sqlite3_step(schema.get()) != SQLITE_ROW)
        throw std::runtime_error("Could not inspect database schema");
    const auto schemaVersion = sqlite3_column_int(schema.get(), 0);
    schema.reset();
    if (applicationId != 0 && applicationId != 0x435A5A49)
        throw std::runtime_error("The selected database belongs to another application");
    if (applicationId == 0)
    {
        auto tables = prepare("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'");
        if (sqlite3_step(tables.get()) != SQLITE_ROW || sqlite3_column_int(tables.get(), 0) != 0)
            throw std::runtime_error("The selected database is not an empty Cipherazzi database");
    }
    else if (schemaVersion != 4)
        throw std::runtime_error("Unsupported Cipherazzi database schema");

    // Keep handshake metadata within larger table pages and reclaim old captures incrementally.
    if (applicationId == 0)
        execute("PRAGMA page_size=16384; PRAGMA auto_vacuum=INCREMENTAL");

    // Budget the page cache for metadata batches to reduce disk spills during each transaction.
    execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;"
        "PRAGMA trusted_schema=OFF; PRAGMA cache_size=-16384; PRAGMA wal_autocheckpoint=1000;");
    execute(R"SQL(
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS metadata (
            id INTEGER PRIMARY KEY CHECK(id=1), database_id TEXT NOT NULL,
            schema_version INTEGER NOT NULL, revision INTEGER NOT NULL, observation_revision INTEGER NOT NULL DEFAULT 0
        ) STRICT;
        INSERT OR IGNORE INTO metadata(id,database_id,schema_version,revision)
            VALUES(1,lower(hex(randomblob(16))),4,0);
        CREATE TABLE IF NOT EXISTS capture_sessions (
            id TEXT PRIMARY KEY, started_us INTEGER NOT NULL, updated_us INTEGER NOT NULL,
            stopped_us INTEGER, source TEXT NOT NULL, process_status TEXT NOT NULL, status TEXT NOT NULL,
            computer_name TEXT NOT NULL,
            packets INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
            capture_lost INTEGER NOT NULL DEFAULT 0, queue_lost INTEGER NOT NULL DEFAULT 0,
            truncated INTEGER NOT NULL DEFAULT 0, malformed INTEGER NOT NULL DEFAULT 0,
            fragments INTEGER NOT NULL DEFAULT 0, unsupported INTEGER NOT NULL DEFAULT 0,
            flow_limit INTEGER NOT NULL DEFAULT 0, reassembly_limit INTEGER NOT NULL DEFAULT 0,
            observations INTEGER NOT NULL DEFAULT 0, storage_lost INTEGER NOT NULL DEFAULT 0,
            process_events_lost INTEGER NOT NULL DEFAULT 0, active_flows INTEGER NOT NULL DEFAULT 0,
            buffered_bytes INTEGER NOT NULL DEFAULT 0, telemetry_lost INTEGER NOT NULL DEFAULT 0,
            change_revision INTEGER NOT NULL DEFAULT 0
        ) STRICT;
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES capture_sessions(id),
            flow_id INTEGER NOT NULL, first_us INTEGER NOT NULL, last_us INTEGER NOT NULL,
            source_address TEXT NOT NULL, source_port INTEGER NOT NULL,
            destination_address TEXT NOT NULL, destination_port INTEGER NOT NULL, ip_version INTEGER NOT NULL,
            tls_version INTEGER, tls_name TEXT, cipher_id INTEGER, cipher_name TEXT,
            sni TEXT NOT NULL, offered_versions TEXT NOT NULL, offered_ciphers TEXT NOT NULL,
            offered_alpn TEXT NOT NULL, selected_alpn TEXT NOT NULL,
            state TEXT NOT NULL, detail TEXT NOT NULL, ech_offered INTEGER NOT NULL, retry_seen INTEGER NOT NULL,
            source_pid INTEGER, source_process TEXT NOT NULL, source_path TEXT NOT NULL,
            source_process_started_us INTEGER, source_evidence TEXT NOT NULL,
            source_account TEXT NOT NULL, source_account_domain TEXT NOT NULL, source_account_sid TEXT NOT NULL,
            destination_pid INTEGER, destination_process TEXT NOT NULL, destination_path TEXT NOT NULL,
            destination_process_started_us INTEGER, destination_evidence TEXT NOT NULL,
            destination_account TEXT NOT NULL, destination_account_domain TEXT NOT NULL,
            destination_account_sid TEXT NOT NULL,
            crypto_json TEXT NOT NULL DEFAULT '{}', group_name TEXT NOT NULL DEFAULT '',
            key_exchange TEXT NOT NULL DEFAULT '', encryption TEXT NOT NULL DEFAULT '', key_bits INTEGER,
            hash_name TEXT NOT NULL DEFAULT '', authentication TEXT NOT NULL DEFAULT '',
            psk_mode TEXT NOT NULL DEFAULT '',
            certificate_sha256 TEXT NOT NULL DEFAULT '', hello_latency_us INTEGER, alert TEXT NOT NULL DEFAULT '',
            ended_us INTEGER, close_reason TEXT NOT NULL DEFAULT '',
            change_revision INTEGER NOT NULL DEFAULT 0,
            UNIQUE(run_id, flow_id)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS connections_time ON connections(first_us DESC, id DESC);
        CREATE INDEX IF NOT EXISTS connections_sni ON connections(sni);
        CREATE INDEX IF NOT EXISTS connections_changes ON connections(change_revision);
        CREATE INDEX IF NOT EXISTS sessions_changes ON capture_sessions(change_revision);
        CREATE INDEX IF NOT EXISTS sessions_time ON capture_sessions(started_us DESC);
        CREATE INDEX IF NOT EXISTS connections_run_time ON connections(run_id,first_us);
        CREATE INDEX IF NOT EXISTS connections_tuple_time ON connections
            (run_id,source_address,source_port,destination_address,destination_port,first_us);
        CREATE TABLE IF NOT EXISTS certificates (
            sha256 TEXT PRIMARY KEY, metadata_json TEXT NOT NULL, der BLOB NOT NULL,
            change_revision INTEGER NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS connection_certificates (
            run_id TEXT NOT NULL, flow_id INTEGER NOT NULL, role TEXT NOT NULL, chain_index INTEGER NOT NULL,
            sha256 TEXT NOT NULL REFERENCES certificates(sha256), change_revision INTEGER NOT NULL,
            PRIMARY KEY(run_id,flow_id,role,chain_index),
            FOREIGN KEY(run_id,flow_id) REFERENCES connections(run_id,flow_id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS endpoint_events (
            id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES capture_sessions(id), timestamp_us INTEGER NOT NULL,
            provider TEXT NOT NULL, kind TEXT NOT NULL, result TEXT NOT NULL, pid INTEGER NOT NULL,
            peer TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL, cipher TEXT NOT NULL,
            certificate_id TEXT NOT NULL, detail_json TEXT NOT NULL, change_revision INTEGER NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS certificates_changes ON certificates(change_revision);
        CREATE INDEX IF NOT EXISTS connection_certificates_changes ON connection_certificates(change_revision);
        CREATE INDEX IF NOT EXISTS connection_certificates_hash ON connection_certificates(sha256);
        CREATE INDEX IF NOT EXISTS endpoint_events_changes ON endpoint_events(change_revision);
        CREATE INDEX IF NOT EXISTS endpoint_events_time_id ON endpoint_events(timestamp_us DESC,id DESC);
        DROP INDEX IF EXISTS endpoint_events_time;
        CREATE INDEX IF NOT EXISTS endpoint_events_run ON endpoint_events(run_id);
        PRAGMA application_id=1129994825;
        PRAGMA user_version=4;
    )SQL");

    // Health updates advance replication without invalidating observation views.
    if (sqlite3_table_column_metadata(database, nullptr, "metadata", "observation_revision",
        nullptr, nullptr, nullptr, nullptr, nullptr) != SQLITE_OK)
        execute("ALTER TABLE metadata ADD COLUMN observation_revision INTEGER NOT NULL DEFAULT 0;"
            "UPDATE metadata SET observation_revision=revision WHERE id=1;");
    execute("COMMIT");

    // Use immutable run identifiers so independent imports cannot overwrite flows.
    runId_ = std::to_string(nowUs()) + "-" + std::to_string(GetCurrentProcessId()) + "-" +
        std::to_string(std::random_device{}());
    sessionLifetime_.reset(CreateMutexW(nullptr, FALSE, sessionMutexName(runId_).c_str()));
    if (!sessionLifetime_)
        throw std::runtime_error("Could not establish the capture session lifetime");
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD computerSize = MAX_COMPUTERNAME_LENGTH + 1;
    const auto computerName = GetComputerNameW(computer, &computerSize) ? utf8(computer) : std::string{};
    auto start = prepare("INSERT INTO capture_sessions"
        "(id,started_us,updated_us,source,process_status,computer_name,status) VALUES(?,?,?,?,?,?,'running')");
    sqlite3_bind_text(start.get(), 1, runId_.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(start.get(), 2, nowUs());
    sqlite3_bind_int64(start.get(), 3, nowUs());
    sqlite3_bind_text(start.get(), 4, source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(start.get(), 5, processStatus.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(start.get(), 6, computerName.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(start.get()) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database));

    insert_ = prepare(R"SQL(
        INSERT INTO connections (
            run_id,flow_id,first_us,last_us,source_address,source_port,destination_address,destination_port,
            ip_version,tls_version,tls_name,cipher_id,cipher_name,sni,offered_versions,offered_ciphers,
            offered_alpn,selected_alpn,state,detail,ech_offered,retry_seen,
            source_pid,source_process,source_path,source_process_started_us,source_evidence,
            source_account,source_account_domain,source_account_sid,
            destination_pid,destination_process,destination_path,destination_process_started_us,destination_evidence,
            destination_account,destination_account_domain,destination_account_sid,
            crypto_json,group_name,key_exchange,encryption,key_bits,hash_name,authentication,psk_mode,
            certificate_sha256,hello_latency_us,alert,ended_us,close_reason,change_revision
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
            ?,?,?,?,?,?,
            (SELECT revision FROM metadata))
        ON CONFLICT(run_id,flow_id) DO UPDATE SET
            last_us=excluded.last_us,tls_version=excluded.tls_version,tls_name=excluded.tls_name,
            cipher_id=excluded.cipher_id,cipher_name=excluded.cipher_name,sni=excluded.sni,
            offered_versions=excluded.offered_versions,offered_ciphers=excluded.offered_ciphers,
            offered_alpn=excluded.offered_alpn,selected_alpn=excluded.selected_alpn,state=excluded.state,
            detail=excluded.detail,ech_offered=excluded.ech_offered,retry_seen=excluded.retry_seen,
            source_pid=coalesce(excluded.source_pid,connections.source_pid),
            source_process=CASE WHEN excluded.source_process<>'' THEN excluded.source_process
                ELSE connections.source_process END,
            source_path=CASE WHEN excluded.source_path<>'' THEN excluded.source_path ELSE connections.source_path END,
            source_process_started_us=coalesce(excluded.source_process_started_us,
                connections.source_process_started_us),
            source_evidence=CASE WHEN excluded.source_pid IS NOT NULL THEN excluded.source_evidence
                ELSE connections.source_evidence END,
            source_account=CASE WHEN excluded.source_account<>'' THEN excluded.source_account
                ELSE connections.source_account END,
            source_account_domain=CASE WHEN excluded.source_account_domain<>'' THEN excluded.source_account_domain
                ELSE connections.source_account_domain END,
            source_account_sid=CASE WHEN excluded.source_account_sid<>'' THEN excluded.source_account_sid
                ELSE connections.source_account_sid END,
            destination_pid=coalesce(excluded.destination_pid,connections.destination_pid),
            destination_process=CASE WHEN excluded.destination_process<>'' THEN excluded.destination_process
                ELSE connections.destination_process END,
            destination_path=CASE WHEN excluded.destination_path<>'' THEN excluded.destination_path
                ELSE connections.destination_path END,
            destination_process_started_us=coalesce(excluded.destination_process_started_us,
                connections.destination_process_started_us),
            destination_evidence=CASE WHEN excluded.destination_pid IS NOT NULL THEN excluded.destination_evidence
                ELSE connections.destination_evidence END,
            destination_account=CASE WHEN excluded.destination_account<>'' THEN excluded.destination_account
                ELSE connections.destination_account END,
            destination_account_domain=CASE WHEN excluded.destination_account_domain<>''
                THEN excluded.destination_account_domain ELSE connections.destination_account_domain END,
            destination_account_sid=CASE WHEN excluded.destination_account_sid<>'' THEN excluded.destination_account_sid
                ELSE connections.destination_account_sid END,
            crypto_json=CASE WHEN json_type(connections.crypto_json,'$.endpoint_confirmations')='array'
                THEN json_set(excluded.crypto_json,'$.endpoint_confirmations',
                    json_extract(connections.crypto_json,'$.endpoint_confirmations'),
                    '$.handshake_confirmation',json_extract(connections.crypto_json,'$.handshake_confirmation'))
                ELSE excluded.crypto_json END,
            group_name=excluded.group_name,key_exchange=excluded.key_exchange,encryption=excluded.encryption,
            key_bits=excluded.key_bits,hash_name=excluded.hash_name,authentication=excluded.authentication,
            psk_mode=excluded.psk_mode,certificate_sha256=excluded.certificate_sha256,
            hello_latency_us=excluded.hello_latency_us,alert=excluded.alert,
            ended_us=coalesce(excluded.ended_us,connections.ended_us),
            close_reason=CASE WHEN excluded.close_reason<>'' THEN excluded.close_reason
                ELSE connections.close_reason END,
            change_revision=excluded.change_revision
    )SQL");
    session_ = prepare(R"SQL(
        UPDATE capture_sessions SET updated_us=?,stopped_us=?,status=?,packets=?,bytes=?,capture_lost=?,
            queue_lost=?,truncated=?,malformed=?,fragments=?,unsupported=?,flow_limit=?,reassembly_limit=?,
            observations=?,storage_lost=?,process_events_lost=?,active_flows=?,buffered_bytes=?,telemetry_lost=?,
            change_revision=(SELECT revision FROM metadata) WHERE id=?
    )SQL");
    certificates_ = prepare("INSERT OR IGNORE INTO certificates VALUES(?,?,?,(SELECT revision FROM metadata))");
    certificateLinks_ = prepare(R"SQL(
        INSERT INTO connection_certificates VALUES(?,?,?,?,?,(SELECT revision FROM metadata))
        ON CONFLICT(run_id,flow_id,role,chain_index) DO UPDATE SET
            sha256=excluded.sha256,change_revision=excluded.change_revision
        WHERE connection_certificates.sha256<>excluded.sha256
    )SQL");
    lifecycle_ = prepare("UPDATE connections SET ended_us=?,close_reason=?,"
        "change_revision=(SELECT revision FROM metadata) WHERE run_id=? AND flow_id=?");
    owners_ = prepare(R"SQL(
        UPDATE connections SET
            source_pid=coalesce(?1,source_pid),source_process=CASE WHEN ?2<>'' THEN ?2 ELSE source_process END,
            source_path=CASE WHEN ?3<>'' THEN ?3 ELSE source_path END,
            source_process_started_us=coalesce(?4,source_process_started_us),
            source_evidence=CASE WHEN ?5<>'' THEN ?5 ELSE source_evidence END,
            source_account=CASE WHEN ?6<>'' THEN ?6 ELSE source_account END,
            source_account_domain=CASE WHEN ?7<>'' THEN ?7 ELSE source_account_domain END,
            source_account_sid=CASE WHEN ?8<>'' THEN ?8 ELSE source_account_sid END,
            destination_pid=coalesce(?9,destination_pid),
            destination_process=CASE WHEN ?10<>'' THEN ?10 ELSE destination_process END,
            destination_path=CASE WHEN ?11<>'' THEN ?11 ELSE destination_path END,
            destination_process_started_us=coalesce(?12,destination_process_started_us),
            destination_evidence=CASE WHEN ?13<>'' THEN ?13 ELSE destination_evidence END,
            destination_account=CASE WHEN ?14<>'' THEN ?14 ELSE destination_account END,
            destination_account_domain=CASE WHEN ?15<>'' THEN ?15 ELSE destination_account_domain END,
            destination_account_sid=CASE WHEN ?16<>'' THEN ?16 ELSE destination_account_sid END,
            change_revision=(SELECT revision FROM metadata) WHERE run_id=?17 AND flow_id=?18 AND (
                (?1 IS NOT NULL AND source_pid IS NOT ?1) OR
                (?2<>'' AND source_process IS NOT ?2) OR
                (?3<>'' AND source_path IS NOT ?3) OR
                (?4 IS NOT NULL AND source_process_started_us IS NOT ?4) OR
                (?5<>'' AND source_evidence IS NOT ?5) OR
                (?6<>'' AND source_account IS NOT ?6) OR
                (?7<>'' AND source_account_domain IS NOT ?7) OR
                (?8<>'' AND source_account_sid IS NOT ?8) OR
                (?9 IS NOT NULL AND destination_pid IS NOT ?9) OR
                (?10<>'' AND destination_process IS NOT ?10) OR
                (?11<>'' AND destination_path IS NOT ?11) OR
                (?12 IS NOT NULL AND destination_process_started_us IS NOT ?12) OR
                (?13<>'' AND destination_evidence IS NOT ?13) OR
                (?14<>'' AND destination_account IS NOT ?14) OR
                (?15<>'' AND destination_account_domain IS NOT ?15) OR
                (?16<>'' AND destination_account_sid IS NOT ?16))
    )SQL");
    retention_ = std::make_unique<Retention>(database, retention);

    // Seed bounded planner statistics before capture starts; contention can defer optional maintenance.
    sqlite3_exec(database, "PRAGMA optimize=0x10002", nullptr, nullptr, nullptr);
    endpoints_ = std::make_unique<EndpointCorrelation>(*this);
}

void JournalWriter::write(const Observation& o)
{
    if (o.lifecycleOnly)
    {
        auto* statement = lifecycle_.get();
        sqlite3_reset(statement);
        sqlite3_bind_int64(statement, 1, o.endedUs);
        sqlite3_bind_text(statement, 2, o.closeReason.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, runId_.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 4, o.flowId);
        if (sqlite3_step(statement) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_.get()));
        return;
    }
    const auto crypto = catalog_.summarize(o, [this](const std::string& hash, const std::string& metadata, Bytes der)
    {
        sqlite3_reset(certificates_.get());
        sqlite3_bind_text(certificates_.get(), 1, hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(certificates_.get(), 2, metadata.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(certificates_.get(), 3, der.data(), static_cast<int>(der.size()), SQLITE_TRANSIENT);
        if (sqlite3_step(certificates_.get()) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_.get()));
    });
    auto* statement = insert_.get();
    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    int index = 0;
    auto text = [&](const std::string& value)
    {
        if (sqlite3_bind_text(statement, ++index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT))
            throw std::runtime_error("Could not bind observation text");
    };
    auto integer = [&](int64_t value, bool present = true)
    {
        ++index;
        const int result = present ? sqlite3_bind_int64(statement, index, value) : sqlite3_bind_null(statement, index);
        if (result)
            throw std::runtime_error("Could not bind observation value");
    };
    text(runId_);
    integer(o.flowId);
    integer(o.firstUs);
    integer(o.lastUs);
    text(o.source.text());
    integer(o.source.port);
    text(o.destination.text());
    integer(o.destination.port);
    integer(o.source.family);
    integer(o.version, o.protocol == Observation::Protocol::Tls && o.serverHello);
    text(o.protocol == Observation::Protocol::Tls ? versionName(o.dtlsVersion ? o.dtlsVersion : o.version) :
        protocolName(o.protocol));
    integer(o.cipher, o.protocol == Observation::Protocol::Tls && o.cipherSelected());
    text(o.protocol == Observation::Protocol::Ssh ?
        (o.ssh->selected[2] == o.ssh->selected[3] ? o.ssh->selected[2] : "Directional ciphers; see SSH evidence") :
        o.protocol == Observation::Protocol::Tls && o.cipherSelected() ? cipherName(o.cipher) : "");
    text(o.sni);
    text(o.offeredVersions);
    text(o.offeredCiphers);
    text(o.offeredAlpn);
    text(o.selectedAlpn);
    text(o.state);
    text(o.detail);
    integer(o.echOffered);
    integer(o.retrySeen);
    for (const auto* owner : {&o.sourceOwner, &o.destinationOwner})
    {
        integer(owner->pid, owner->pid != 0);
        text(owner->name);
        text(owner->path);
        integer(owner->startedUs, owner->startedUs != 0);
        text(owner->evidence);
        text(owner->account);
        text(owner->accountDomain);
        text(owner->accountSid);
    }
    text(crypto.json);
    text(crypto.group);
    text(crypto.exchange);
    text(crypto.encryption);
    integer(crypto.keyBits, crypto.keyBits != 0);
    text(crypto.hash);
    text(crypto.authentication);
    text(crypto.psk);
    text(crypto.certificate);
    integer(o.crypto.serverHelloUs - o.crypto.clientHelloUs,
        o.crypto.clientHelloUs > 0 && o.crypto.serverHelloUs >= o.crypto.clientHelloUs);
    text(alertName(o.crypto.alertCode));
    integer(o.endedUs, o.endedUs != 0);
    text(o.closeReason);
    if (sqlite3_step(statement) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));

    // Preserve each presented chain's role and order while sharing its original certificate bytes.
    for (const auto& certificate : crypto.certificates)
    {
        auto* link = certificateLinks_.get();
        sqlite3_reset(link);
        sqlite3_bind_text(link, 1, runId_.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(link, 2, o.flowId);
        sqlite3_bind_text(link, 3, certificate.role.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(link, 4, certificate.position);
        sqlite3_bind_text(link, 5, certificate.sha256.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(link) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_.get()));
    }
}

void JournalWriter::heartbeat(std::string_view status, bool stopped)
{
    auto* statement = session_.get();
    sqlite3_reset(statement);
    sqlite3_bind_int64(statement, 1, nowUs());
    if (stopped)
        sqlite3_bind_int64(statement, 2, nowUs());
    else
        sqlite3_bind_null(statement, 2);
    sqlite3_bind_text(statement, 3, status.data(), static_cast<int>(status.size()), SQLITE_TRANSIENT);
    int index = 3;
    for (const auto* count : {&counters_.packets, &counters_.bytes, &counters_.captureLost, &counters_.queueLost,
        &counters_.truncated, &counters_.malformed, &counters_.fragments, &counters_.unsupported,
        &counters_.flowLimit, &counters_.reassemblyLimit, &counters_.observations, &counters_.storageLost,
        &counters_.processEventsLost, &counters_.activeFlows, &counters_.bufferedBytes, &counters_.telemetryLost})
        sqlite3_bind_int64(statement, ++index, static_cast<sqlite3_int64>(count->load(std::memory_order_relaxed)));
    sqlite3_bind_text(statement, ++index, runId_.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
}

void JournalWriter::writeOwners(const Observation& observation)
{
    if (!observation.sourceOwner.pid && !observation.destinationOwner.pid)
        return;
    auto* statement = owners_.get();
    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    int index = 0;
    for (const auto* owner : {&observation.sourceOwner, &observation.destinationOwner})
    {
        if (owner->pid)
            sqlite3_bind_int64(statement, ++index, owner->pid);
        else
            sqlite3_bind_null(statement, ++index);
        for (const auto* value : {&owner->name, &owner->path})
            sqlite3_bind_text(statement, ++index, value->c_str(), -1, SQLITE_TRANSIENT);
        if (owner->startedUs)
            sqlite3_bind_int64(statement, ++index, owner->startedUs);
        else
            sqlite3_bind_null(statement, ++index);
        for (const auto* value : {&owner->evidence, &owner->account, &owner->accountDomain, &owner->accountSid})
            sqlite3_bind_text(statement, ++index, value->c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(statement, ++index, runId_.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, ++index, observation.flowId);
    if (sqlite3_step(statement) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
}

JournalWriter::~JournalWriter() = default;

void JournalWriter::maintain(bool final)
{
    // Maintenance runs between transactions and shares the writer's certificate inventory.
    const auto now = std::chrono::steady_clock::now();
    if (final || now >= retentionDeadline_)
    {
        const bool more = retention_->maintain(nowUs(), runId_,
            [this](const std::string& hash) { catalog_.forget(hash); });
        retentionDeadline_ = std::chrono::steady_clock::now() +
            (more ? std::chrono::milliseconds(100) : std::chrono::milliseconds(5000));
    }
    if (final || now >= optimizeDeadline_)
    {
        sqlite3_exec(database_.get(), "PRAGMA optimize", nullptr, nullptr, nullptr);
        optimizeDeadline_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
    }
}

void JournalWriter::commit(JournalBatch& batch, std::string_view status, bool final, std::stop_token draining)
{
    // One transaction publishes observations, owner refinements, correlations, health, and their durable cursor.
    begin(draining);
    execute("UPDATE metadata SET revision=revision+1 WHERE id=1");
    const auto changes = sqlite3_total_changes64(database_.get());
    for (const auto& observation : batch.observations)
        write(observation);
    for (const auto& observation : batch.owners)
        writeOwners(observation);
    for (auto& event : batch.events)
        endpoints_->write(event);
    std::unordered_set<FlowKey, FlowHash> dirty;
    for (const auto* observations : {&batch.observations, &batch.owners})
        for (const auto& observation : *observations)
            if (!observation.lifecycleOnly)
                dirty.insert(FlowKey::make(observation.source, observation.destination));
    endpoints_->resolve(final, dirty);
    if (sqlite3_total_changes64(database_.get()) != changes)
        execute("UPDATE metadata SET observation_revision=revision WHERE id=1");
    heartbeat(status, final);
    execute("COMMIT");

    // Idle journals write health less often while remaining within the reader's freshness interval.
    heartbeatDeadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(batch.empty() ? 5 : 1);
}

void JournalWriter::rollback() noexcept
{
    sqlite3_exec(database_.get(), "ROLLBACK", nullptr, nullptr, nullptr);
}
}
