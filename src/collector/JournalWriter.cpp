#include "JournalWriter.h"
#include "EndpointCorrelation.h"
#include "Vpn.h"
#include <ws2tcpip.h>
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
        CREATE INDEX IF NOT EXISTS connections_analytics ON connections
            (run_id,first_us,tls_version,tls_name,group_name,alert,hello_latency_us,
                source_process,destination_process,
                CASE WHEN json_valid(crypto_json) THEN json_extract(crypto_json,'$.group_class') END,
                CASE WHEN json_valid(crypto_json) THEN coalesce(json_extract(crypto_json,'$.transport'),'TCP') END,
                CASE WHEN json_valid(crypto_json) THEN json_extract(crypto_json,'$.handshake_confirmation') END,
                coalesce(nullif(sni,''),
                    CASE WHEN json_valid(crypto_json) THEN json_extract(crypto_json,'$.http_host') END,''));
        CREATE INDEX IF NOT EXISTS connections_readiness ON connections
            (first_us DESC,id DESC,jsonb_extract(
                CASE WHEN json_valid(crypto_json) THEN CASE WHEN json_type(crypto_json)='object'
                    THEN crypto_json END END,
                '$.transport','$.selected_group_id','$.group_class','$.group_standardization',
                '$.classification_rule_version','$.selected_psk_index','$.handshake_signature',
                '$.client_handshake_signature','$.negotiation_history_truncated','$.evidence_source',
                '$.endpoint_confirmations'));
        CREATE INDEX IF NOT EXISTS connections_tuple_time ON connections
            (run_id,source_address,source_port,destination_address,destination_port,first_us);
        CREATE INDEX IF NOT EXISTS connections_owner_tuple ON connections
            (run_id,source_address,source_port,destination_address,destination_port,last_us,id);
        CREATE INDEX IF NOT EXISTS connections_owner_source ON connections(run_id,source_pid,last_us,id);
        CREATE INDEX IF NOT EXISTS connections_owner_destination ON connections(run_id,destination_pid,last_us,id);
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
        CREATE INDEX IF NOT EXISTS endpoint_events_run ON endpoint_events(run_id);
        PRAGMA application_id=1129994825;
        PRAGMA user_version=4;
    )SQL");

    // Publish the journal schema and retention state together.
    retention_ = std::make_unique<Retention>(database, retention);
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
            source_pid=CASE WHEN ?20 THEN ?1 ELSE source_pid END,
            source_process=CASE WHEN ?20 THEN ?2 ELSE source_process END,
            source_path=CASE WHEN ?20 THEN ?3 ELSE source_path END,
            source_process_started_us=CASE WHEN ?20 THEN ?4 ELSE source_process_started_us END,
            source_evidence=CASE WHEN ?20 THEN ?5 ELSE source_evidence END,
            source_account=CASE WHEN ?20 THEN ?6 ELSE source_account END,
            source_account_domain=CASE WHEN ?20 THEN ?7 ELSE source_account_domain END,
            source_account_sid=CASE WHEN ?20 THEN ?8 ELSE source_account_sid END,
            destination_pid=CASE WHEN ?21 THEN ?9 ELSE destination_pid END,
            destination_process=CASE WHEN ?21 THEN ?10 ELSE destination_process END,
            destination_path=CASE WHEN ?21 THEN ?11 ELSE destination_path END,
            destination_process_started_us=CASE WHEN ?21 THEN ?12 ELSE destination_process_started_us END,
            destination_evidence=CASE WHEN ?21 THEN ?13 ELSE destination_evidence END,
            destination_account=CASE WHEN ?21 THEN ?14 ELSE destination_account END,
            destination_account_domain=CASE WHEN ?21 THEN ?15 ELSE destination_account_domain END,
            destination_account_sid=CASE WHEN ?21 THEN ?16 ELSE destination_account_sid END,
            change_revision=(SELECT revision FROM metadata)
        WHERE run_id=?17 AND flow_id=?18 AND last_us<=?19 AND (
            (?20 AND (source_pid,source_process,source_path,source_process_started_us,
                source_evidence,source_account,source_account_domain,source_account_sid)
                IS NOT (?1,?2,?3,?4,?5,?6,?7,?8)) OR
            (?21 AND (destination_pid,destination_process,destination_path,destination_process_started_us,
                destination_evidence,destination_account,destination_account_domain,destination_account_sid)
                IS NOT (?9,?10,?11,?12,?13,?14,?15,?16)))
    )SQL");

    // Page affected identities through indexes without holding the process evidence mutex or a write transaction.
    const std::array<std::string, 5> ownerPredicates{
        "source_address=?5 AND source_port=?6 AND destination_address=?7 AND destination_port=?8",
        "source_address=?7 AND source_port=?8 AND destination_address=?5 AND destination_port=?6",
        "source_pid=?5", "destination_pid=?5", "1=1"};
    for (size_t index = 0; index < ownerPredicates.size(); ++index)
    {
        const std::string time = index == 4 ? "first_us" : "last_us";
        const auto sql = "SELECT id,flow_id,first_us,last_us,ip_version,source_address,source_port,"
            "destination_address,destination_port,source_pid,source_process_started_us,"
            "destination_pid,destination_process_started_us,"
            "CASE WHEN json_valid(crypto_json) THEN json_extract(crypto_json,'$.transport') END "
            "FROM connections WHERE run_id=?1 AND " + time + ">=?2 AND "
            "(" + time + ",id)>(?3,?4) AND tls_name<>'IPsec' AND " +
            ownerPredicates[index] + " ORDER BY " + time + ",id LIMIT 256";
        ownerQueries_[index] = prepare(sql.c_str());
    }
    clearOwners_ = prepare(R"SQL(
        UPDATE connections SET source_pid=NULL,source_process='',source_path='',source_process_started_us=NULL,
            source_evidence='',source_account='',source_account_domain='',source_account_sid='',
            destination_pid=NULL,destination_process='',destination_path='',destination_process_started_us=NULL,
            destination_evidence='',destination_account='',destination_account_domain='',destination_account_sid='',
            change_revision=(SELECT revision FROM metadata)
        WHERE run_id=? AND tls_name<>'IPsec' AND (
            (source_pid,source_process,source_path,source_process_started_us,source_evidence,
                source_account,source_account_domain,source_account_sid) IS NOT (NULL,'','',NULL,'','','','') OR
            (destination_pid,destination_process,destination_path,destination_process_started_us,destination_evidence,
                destination_account,destination_account_domain,destination_account_sid)
                IS NOT (NULL,'','',NULL,'','','',''))
    )SQL");

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

    // Apply ownership as a complete identity so a correction cannot retain another process's name or account.
    writeOwners(o);

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
    const bool source = observation.sourceOwner.pid || observation.sourceOwner.ambiguous;
    const bool destination = observation.destinationOwner.pid || observation.destinationOwner.ambiguous;
    if (!source && !destination)
        return;
    auto* statement = owners_.get();
    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    int index = 0;
    const Owner empty;
    for (const auto* proposed : {&observation.sourceOwner, &observation.destinationOwner})
    {
        const auto* owner = proposed->ambiguous ? &empty : proposed;
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
    sqlite3_bind_int64(statement, ++index, observation.lastUs);
    sqlite3_bind_int(statement, ++index, source);
    sqlite3_bind_int(statement, ++index, destination);
    if (sqlite3_step(statement) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
}

bool JournalWriter::ownershipChanges(std::vector<OwnerChange> changes, JournalBatch& batch)
{
    for (auto& change : changes)
    {
        if ((!change.flow && !change.pid) || ownershipQueries_.size() >= 8192)
        {
            // Saturation loses the affected set, so revoke identities instead of silently dropping corrections.
            if (change.flow || change.pid)
                ++counters_.processEventsLost;
            ownershipQueries_.clear();
            ownershipQueries_.push_back({});
            batch.clearOwners = true;
            return false;
        }
        ownershipQueries_.push_back({std::move(change)});
    }

    struct Candidate
    {
        int64_t id{};
        Observation observation;
    };
    for (size_t visited = 0; !ownershipQueries_.empty() && visited < 256 && batch.owners.size() < 256; ++visited)
    {
        auto& query = ownershipQueries_.front();
        std::vector<Candidate> candidates;
        const auto& change = query.change;
        const bool all = !change.flow && !change.pid;
        const auto first = all ? 4 : change.flow ? 0 : 2;
        for (int index = first; index < first + (all ? 1 : 2); ++index)
        {
            auto* statement = ownerQueries_[index].get();
            sqlite3_reset(statement);
            sqlite3_clear_bindings(statement);
            sqlite3_bind_text(statement, 1, runId_.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(statement, 2, change.sinceUs);
            sqlite3_bind_int64(statement, 3, query.cursorUs);
            sqlite3_bind_int64(statement, 4, query.id);
            if (change.flow)
            {
                const auto a = change.flow->a.text(), b = change.flow->b.text();
                sqlite3_bind_text(statement, 5, a.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(statement, 6, change.flow->a.port);
                sqlite3_bind_text(statement, 7, b.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(statement, 8, change.flow->b.port);
            }
            else if (change.pid)
                sqlite3_bind_int64(statement, 5, change.pid);
            int result;
            while ((result = sqlite3_step(statement)) == SQLITE_ROW)
            {
                Candidate candidate;
                candidate.id = sqlite3_column_int64(statement, 0);
                auto& observation = candidate.observation;
                observation.flowId = sqlite3_column_int64(statement, 1);
                observation.firstUs = sqlite3_column_int64(statement, 2);
                observation.lastUs = sqlite3_column_int64(statement, 3);
                auto endpoint = [&](int address, int port)
                {
                    Endpoint value;
                    value.family = static_cast<uint8_t>(sqlite3_column_int(statement, 4));
                    value.port = static_cast<uint16_t>(sqlite3_column_int(statement, port));
                    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, address));
                    if (!text || InetPtonA(value.family == 6 ? AF_INET6 : AF_INET, text, value.address.data()) != 1)
                        throw std::runtime_error("The journal contains an invalid network address.");
                    return value;
                };
                observation.source = endpoint(5, 6);
                observation.destination = endpoint(7, 8);
                observation.sourceOwner.pid = static_cast<uint32_t>(sqlite3_column_int64(statement, 9));
                observation.sourceOwner.startedUs = sqlite3_column_int64(statement, 10);
                observation.destinationOwner.pid = static_cast<uint32_t>(sqlite3_column_int64(statement, 11));
                observation.destinationOwner.startedUs = sqlite3_column_int64(statement, 12);
                if (change.flow)
                    observation.ownerSides = observation.source == change.flow->a ? change.sides :
                        static_cast<uint8_t>(((change.sides & 1) << 1) | ((change.sides & 2) >> 1));
                else if (change.pid)
                    observation.ownerSides = static_cast<uint8_t>((observation.sourceOwner.pid == change.pid ? 1 : 0) |
                        (observation.destinationOwner.pid == change.pid ? 2 : 0));
                const auto* transport = reinterpret_cast<const char*>(sqlite3_column_text(statement, 13));
                const std::string_view recorded = transport ? transport : "";
                observation.quic = recorded == "QUIC";
                observation.udp = observation.quic || recorded == "UDP" || recorded == "DTLS";
                candidates.push_back(std::move(candidate));
            }
            sqlite3_reset(statement);
            if (result != SQLITE_DONE)
                throw std::runtime_error(sqlite3_errmsg(database_.get()));
        }

        // Merge both endpoint directions before advancing the shared time and row cursor.
        std::ranges::sort(candidates, [all](const Candidate& a, const Candidate& b)
        {
            return std::pair{all ? a.observation.firstUs : a.observation.lastUs, a.id} <
                std::pair{all ? b.observation.firstUs : b.observation.lastUs, b.id};
        });
        auto cursor = std::pair{query.cursorUs, query.id};
        size_t consumed = 0;
        for (auto& candidate : candidates)
        {
            const auto time = all ? candidate.observation.firstUs : candidate.observation.lastUs;
            const auto next = std::pair{time, candidate.id};
            if (next <= cursor)
                continue;
            if (batch.owners.size() == 256)
                break;
            cursor = next;
            batch.owners.push_back(std::move(candidate.observation));
            ++consumed;
        }
        query.cursorUs = cursor.first;
        query.id = cursor.second;
        if (consumed)
            ownershipQueries_.push_back(std::move(query));
        ownershipQueries_.pop_front();
    }
    return ownershipQueries_.empty();
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
    if (batch.clearOwners)
    {
        sqlite3_reset(clearOwners_.get());
        sqlite3_bind_text(clearOwners_.get(), 1, runId_.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(clearOwners_.get()) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_.get()));
    }
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
