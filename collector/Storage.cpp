#include "Storage.h"
#include "Vpn.h"
#include <sqlite3.h>
#include <windows.h>
#include <random>
#include <algorithm>
#include <stdexcept>

namespace Cipherazzi
{
void Storage::DatabaseCloser::operator()(sqlite3* value) const { sqlite3_close_v2(value); }
void Storage::StatementCloser::operator()(sqlite3_stmt* value) const { sqlite3_finalize(value); }

Storage::Statement Storage::prepare(const char* sql)
{
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database_.get(), sql, -1, &statement, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
    return Statement(statement);
}

void Storage::execute(const char* sql)
{
    if (sqlite3_exec(database_.get(), sql, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
}

Storage::Storage(const std::filesystem::path& path, Counters& counters, std::string source,
    std::string processStatus, Enricher enricher, RetentionLimits retention) :
    counters_(counters), enricher_(std::move(enricher))
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
            schema_version INTEGER NOT NULL, revision INTEGER NOT NULL
        ) STRICT;
        INSERT OR IGNORE INTO metadata VALUES(1,lower(hex(randomblob(16))),4,0);
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
            hash_name TEXT NOT NULL DEFAULT '', authentication TEXT NOT NULL DEFAULT '', psk_mode TEXT NOT NULL DEFAULT '',
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
        COMMIT;
    )SQL");

    // Use immutable run identifiers so independent imports cannot overwrite flows.
    runId_ = std::to_string(nowUs()) + "-" + std::to_string(GetCurrentProcessId()) + "-" +
        std::to_string(std::random_device{}());
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
                ELSE connections.destination_account_sid END,crypto_json=CASE WHEN json_type(connections.crypto_json,'$.endpoint_confirmations')='array'
                THEN json_set(excluded.crypto_json,'$.endpoint_confirmations',
                    json_extract(connections.crypto_json,'$.endpoint_confirmations'),
                    '$.handshake_confirmation',json_extract(connections.crypto_json,'$.handshake_confirmation'))
                ELSE excluded.crypto_json END,
            group_name=excluded.group_name,key_exchange=excluded.key_exchange,encryption=excluded.encryption,
            key_bits=excluded.key_bits,hash_name=excluded.hash_name,authentication=excluded.authentication,
            psk_mode=excluded.psk_mode,certificate_sha256=excluded.certificate_sha256,
            hello_latency_us=excluded.hello_latency_us,alert=excluded.alert,
            ended_us=coalesce(excluded.ended_us,connections.ended_us),
            close_reason=CASE WHEN excluded.close_reason<>'' THEN excluded.close_reason ELSE connections.close_reason END,
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
    telemetry_ = prepare("INSERT OR IGNORE INTO endpoint_events VALUES"
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,(SELECT revision FROM metadata))");
    owners_ = prepare(R"SQL(
        UPDATE connections SET
            source_pid=coalesce(?,source_pid),source_process=CASE WHEN ?<>'' THEN ? ELSE source_process END,
            source_path=CASE WHEN ?<>'' THEN ? ELSE source_path END,
            source_process_started_us=coalesce(?,source_process_started_us),
            source_evidence=CASE WHEN ?<>'' THEN ? ELSE source_evidence END,
            source_account=CASE WHEN ?<>'' THEN ? ELSE source_account END,
            source_account_domain=CASE WHEN ?<>'' THEN ? ELSE source_account_domain END,
            source_account_sid=CASE WHEN ?<>'' THEN ? ELSE source_account_sid END,
            destination_pid=coalesce(?,destination_pid),
            destination_process=CASE WHEN ?<>'' THEN ? ELSE destination_process END,
            destination_path=CASE WHEN ?<>'' THEN ? ELSE destination_path END,
            destination_process_started_us=coalesce(?,destination_process_started_us),
            destination_evidence=CASE WHEN ?<>'' THEN ? ELSE destination_evidence END,
            destination_account=CASE WHEN ?<>'' THEN ? ELSE destination_account END,
            destination_account_domain=CASE WHEN ?<>'' THEN ? ELSE destination_account_domain END,
            destination_account_sid=CASE WHEN ?<>'' THEN ? ELSE destination_account_sid END,
            change_revision=(SELECT revision FROM metadata) WHERE run_id=? AND flow_id=?
    )SQL");
    retention_ = std::make_unique<Retention>(database, retention);

    // Seed bounded planner statistics before capture starts; contention can defer optional maintenance.
    sqlite3_exec(database, "PRAGMA optimize=0x10002", nullptr, nullptr, nullptr);
    pending_.reserve(8192);
    thread_ = std::thread([this] { work(); });
}

Storage::~Storage()
{
    try { finish(); }
    catch (...) {}
}

void Storage::enqueue(Observation observation, bool waitForCapacity)
{
    {
        std::unique_lock lock(mutex_);
        if (waitForCapacity)
        {
            changed_.wait(lock, [this, id = observation.flowId]
            {
                return (queue_.size() < 8192 && queueBytes_ < 60 * 1024 * 1024) ||
                    pending_.contains(id) || error_ || stopping_;
            });
            if (error_)
                std::rethrow_exception(error_);
        }
        if (error_ || stopping_)
        {
            ++counters_.storageLost;
            return;
        }

        // Collapse successive hello updates while preserving queue order.
        if (const auto found = pending_.find(observation.flowId); found != pending_.end())
        {
            if (observation.lifecycleOnly)
            {
                const auto previous = found->second->observation.memory();
                found->second->observation.endedUs = observation.endedUs;
                found->second->observation.closeReason = observation.closeReason;
                queueBytes_ = queueBytes_ - previous + found->second->observation.memory();
                return;
            }
            const auto previous = found->second->observation.memory();
            if (queueBytes_ - previous + observation.memory() > 64 * 1024 * 1024)
            {
                ++counters_.storageLost;
                return;
            }
            queueBytes_ = queueBytes_ - previous + observation.memory();
            found->second->observation = std::move(observation);
            return;
        }
        if (queue_.size() >= 8192 || queueBytes_ + observation.memory() > 64 * 1024 * 1024)
        {
            ++counters_.storageLost;
            return;
        }
        queueBytes_ += observation.memory();
        queue_.push_back({std::move(observation), std::chrono::steady_clock::now()});
        pending_.emplace(queue_.back().observation.flowId, &queue_.back());
    }
    changed_.notify_one();
}

void Storage::enqueue(EndpointEvent event, bool waitForCapacity)
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
            changed_.wait(lock, [&] { return capacity() || error_ || stopping_; });
        if (!capacity() || error_ || stopping_)
        {
            ++counters_.telemetryLost;
            return;
        }
        eventBytes_ += bytes;
        events_.push_back(std::move(event));
    }
    changed_.notify_one();
}

nlohmann::json endpointConfirmation(const EndpointEvent& event, std::string_view status, int client)
{
    const auto& report = *event.report;
    const auto detail = nlohmann::json::parse(event.detail);
    return {
        {"event_id", event.id}, {"provider", event.provider}, {"timestamp_us", event.timestampUs},
        {"pid", event.pid}, {"process_started_us", report.processStartedUs},
        {"process_scope", detail.value("process_scope", "endpoint")},
        {"local_role", client < 0 ? "Unknown" : client ? "Client" : "Server"}, {"success", report.success},
        {"match", status}, {"peer_verified", report.peerVerified},
        {"handshake_signature_id", report.signature < 0 ? nlohmann::json(nullptr) : nlohmann::json(report.signature)},
        {"handshake_signature", report.signature < 0 ? "" : signatureName(static_cast<uint16_t>(report.signature))},
        {"authentication_class", signatureClass(report.signature)}, {"selected_alpn", report.alpn},
        {"local_handshake_signature_id", report.localSignature < 0 ? nlohmann::json(nullptr) :
            nlohmann::json(report.localSignature)},
        {"local_handshake_signature", report.localSignature < 0 ? "" :
            signatureName(static_cast<uint16_t>(report.localSignature))},
        {"local_authentication_class", signatureClass(report.localSignature)},
        {"certificate_facts", detail.contains("assessment") ?
            detail["assessment"].value("certificate_facts", "") : std::string{}},
        {"server_certificates", detail.value("server_certificates", nlohmann::json::array())},
        {"client_certificates", detail.value("client_certificates", nlohmann::json::array())}
    };
}

void Storage::write(EndpointEvent& event)
{
    if (event.report)
    {
        // Catalog endpoint certificates once; confirmation does not imply collector-side trust validation.
        Observation certificates;
        const auto& report = *event.report;
        certificates.version = static_cast<uint16_t>(report.version);
        certificates.cipher = static_cast<uint16_t>(report.cipher);
        certificates.serverHello = report.success && report.cipher > 0;
        certificates.quic = report.quic;
        certificates.udp = report.udp;
        certificates.dtlsVersion = report.dtlsVersion;
        certificates.crypto.groupId = report.group;
        if (report.group >= 0)
            certificates.crypto.group = groupName(static_cast<uint16_t>(report.group));
        certificates.crypto.serverCertificates = event.report->serverCertificates;
        certificates.crypto.clientCertificates = event.report->clientCertificates;
        const auto summary = catalog_.summarize(certificates,
        [this](const std::string& hash, const std::string& metadata, Bytes der)
        {
            sqlite3_reset(certificates_.get());
            sqlite3_bind_text(certificates_.get(), 1, hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(certificates_.get(), 2, metadata.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(certificates_.get(), 3, der.data(), static_cast<int>(der.size()), SQLITE_TRANSIENT);
            if (sqlite3_step(certificates_.get()) != SQLITE_DONE)
                throw std::runtime_error(sqlite3_errmsg(database_.get()));
        });
        if (!report.raw)
        {
            // Unmatched public endpoint evidence is assessed without inventing a captured connection.
            auto detail = nlohmann::json::parse(event.detail);
            auto crypto = nlohmann::json::parse(summary.json);
            crypto["evidence_source"] = "Endpoint";
            crypto["transport"] = detail.value("transport", "Unknown");
            crypto["protocol"] = report.udp ? "DTLS" : "TLS";
            crypto["endpoint_confirmations"] = nlohmann::json::array({endpointConfirmation(event,
                "Endpoint report; packet association evaluated independently", report.roleKnown ? report.client : -1)});
            std::string facts;
            auto read = prepare("SELECT metadata_json FROM certificates WHERE sha256=?");
            for (const auto& reference : summary.certificates)
            {
                sqlite3_reset(read.get());
                sqlite3_bind_text(read.get(), 1, reference.sha256.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(read.get()) != SQLITE_ROW)
                    continue;
                const auto metadata = nlohmann::json::parse(
                    reinterpret_cast<const char*>(sqlite3_column_text(read.get(), 0)));
                facts += (facts.empty() ? "" : ",") + reference.role;
                for (const auto* field : {"public_key_oid", "signature_oid", "public_key_class",
                    "certificate_signature_class"})
                    facts += "|" + metadata.value(field, "");
            }
            auto peer = report.peerName;
            if (peer.empty())
                peer = report.partial ? event.peer : (report.client ? report.remote : report.local).text();
            crypto["endpoint_confirmations"][0]["certificate_facts"] = facts;
            const auto localRole = detail.value("process_scope", "endpoint") == "application" ? "Unknown" :
                report.roleKnown ? report.client ? "Client" : "Server" : "Unknown";
            detail["assessment"] = {
                {"first_us", report.partial ? event.timestampUs : report.startedUs},
                {"last_us", event.timestampUs}, {"tls_version", report.version},
                {"crypto", std::move(crypto)}, {"key_exchange", summary.exchange},
                {"authentication", summary.authentication}, {"certificate_facts", facts},
                {"group_name", summary.group},
                {"provider", event.provider}, {"local_role", localRole},
                {"process", report.owner.name}, {"path", report.owner.path},
                {"server_name", peer.empty() ? "Unknown peer" : peer},
                {"server_port", report.partial || report.client ? report.remote.port : report.local.port}
            };
            event.detail = detail.dump();
        }
    }
    auto* statement = telemetry_.get();
    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    int index = 0;
    auto text = [&](const std::string& value)
    {
        sqlite3_bind_text(statement, ++index, value.c_str(), -1, SQLITE_TRANSIENT);
    };
    text(event.id);
    text(runId_);
    sqlite3_bind_int64(statement, ++index, event.timestampUs);
    text(event.provider);
    text(event.kind);
    text(event.result);
    sqlite3_bind_int64(statement, ++index, event.pid);
    text(event.peer);
    sqlite3_bind_int(statement, ++index, event.port);
    text(event.protocol);
    text(event.cipher);
    text(event.certificateId);
    text(event.detail);
    if (sqlite3_step(statement) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
    const bool inserted = sqlite3_changes(database_.get()) != 0;
    if (inserted && !event.certificateId.empty())
    {
        auto link = prepare("INSERT OR IGNORE INTO endpoint_certificates "
            "SELECT ?,sha256 FROM certificates WHERE sha256=?");
        sqlite3_bind_text(link.get(), 1, event.id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(link.get(), 2, event.certificateId.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(link.get()) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_.get()));
    }
    if (event.report && inserted)
    {
        auto link = prepare("INSERT OR IGNORE INTO endpoint_certificates VALUES(?,?)");
        const auto certificateDetail = nlohmann::json::parse(event.detail);
        for (const auto* field : {"server_certificates", "client_certificates"})
            for (const auto& value : certificateDetail.value(field, nlohmann::json::array()))
            {
                const auto hash = value.get<std::string>();
                sqlite3_reset(link.get());
                sqlite3_bind_text(link.get(), 1, event.id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(link.get(), 2, hash.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(link.get()) != SQLITE_DONE)
                    throw std::runtime_error(sqlite3_errmsg(database_.get()));
            }
        if (!event.report->correlatable)
            return;
        if (endpointPending_.size() >= 2048 || endpointPendingBytes_ + event.memory() > 16 * 1024 * 1024)
        {
            auto detail = nlohmann::json::parse(event.detail);
            detail["correlation"] = "Endpoint matching capacity exceeded; no association asserted";
            event.detail = detail.dump();
            writeEndpointDetail(event);
            ++counters_.telemetryLost;
        }
        else
        {
            EndpointEvent pending = event;
            auto publicReport = std::make_shared<EndpointReport>(*event.report);
            publicReport->serverCertificates.clear();
            publicReport->clientCertificates.clear();
            pending.report = std::move(publicReport);
            endpointPendingBytes_ += pending.memory();
            endpointPending_.push_back({std::move(pending), std::chrono::steady_clock::now() + std::chrono::seconds(120)});
        }
    }
}

void Storage::writeEndpointDetail(const EndpointEvent& event)
{
    auto statement = prepare("UPDATE endpoint_events SET detail_json=?,"
        "change_revision=(SELECT revision FROM metadata) WHERE id=? AND run_id=?");
    sqlite3_bind_text(statement.get(), 1, event.detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement.get(), 2, event.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement.get(), 3, runId_.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement.get()) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
}

void Storage::correlateEndpoints(bool final, const std::unordered_set<FlowKey, FlowHash>& dirty)
{
    for (auto it = endpointPending_.begin(); it != endpointPending_.end();)
    {
        auto& event = it->event;
        const auto& report = *event.report;
        const bool expired = final || std::chrono::steady_clock::now() >= it->deadline;
        if (it->checked && !expired && (report.partial ? dirty.empty() :
            !dirty.contains(FlowKey::make(report.local, report.remote))))
        {
            ++it;
            continue;
        }
        it->checked = true;
        const auto& source = report.client ? report.local : report.remote;
        const auto& destination = report.client ? report.remote : report.local;

        // Keep peer windows and socket tuples separate so each lookup can seek its matching index.
        std::string candidateSql = R"SQL(
            SELECT flow_id,tls_version,cipher_id,crypto_json,
                source_pid,source_process_started_us,destination_pid,destination_process_started_us,
                source_address,source_port
            FROM connections WHERE run_id=?1 AND
                first_us>=?6 AND first_us<=?7 AND last_us>=?8 AND
        )SQL";
        candidateSql += report.partial ? R"SQL(
            length(?12)>0 AND
                (((?11=0 OR destination_port=?11) AND (destination_address=?12 OR sni=?12 COLLATE NOCASE)) OR
                ((?11=0 OR source_port=?11) AND (source_address=?12 OR sni=?12 COLLATE NOCASE)))
        )SQL" : report.raw ? R"SQL(
            ((source_address=?2 AND source_port=?3 AND destination_address=?4 AND destination_port=?5) OR
                (source_address=?4 AND source_port=?5 AND destination_address=?2 AND destination_port=?3))
        )SQL" : R"SQL(
            source_address=?2 AND source_port=?3 AND destination_address=?4 AND destination_port=?5
        )SQL";
        candidateSql += " LIMIT 32";
        auto candidates = prepare(candidateSql.c_str());
        sqlite3_bind_text(candidates.get(), 1, runId_.c_str(), -1, SQLITE_TRANSIENT);
        if (report.partial)
        {
            sqlite3_bind_int(candidates.get(), 11, report.remote.port);
            const auto peer = std::ranges::any_of(report.remote.address, [](uint8_t value) { return value != 0; }) ?
                report.remote.text() : report.peerName;
            sqlite3_bind_text(candidates.get(), 12, peer.c_str(), -1, SQLITE_TRANSIENT);
        }
        else
        {
            sqlite3_bind_text(candidates.get(), 2, source.text().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(candidates.get(), 3, source.port);
            sqlite3_bind_text(candidates.get(), 4, destination.text().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(candidates.get(), 5, destination.port);
        }
        sqlite3_bind_int64(candidates.get(), 6, report.startedUs - 250000);
        sqlite3_bind_int64(candidates.get(), 7, event.timestampUs + 100000);
        sqlite3_bind_int64(candidates.get(), 8,
            report.partial ? event.timestampUs - 2000000 : report.startedUs - 100000);
        int64_t flow = 0;
        bool matchedClient = report.client;
        size_t matches = 0, rows = 0;
        nlohmann::json crypto;
        int result;
        while ((result = sqlite3_step(candidates.get())) == SQLITE_ROW)
        {
            ++rows;
            auto data = nlohmann::json::parse(reinterpret_cast<const char*>(sqlite3_column_text(candidates.get(), 3)));
            const bool localSource = report.local.text() ==
                reinterpret_cast<const char*>(sqlite3_column_text(candidates.get(), 8)) &&
                report.local.port == sqlite3_column_int(candidates.get(), 9);
            bool client = report.client;
            if (report.partial)
            {
                bool identities[2]{};
                for (int side = 0; side < 2; ++side)
                    identities[side] = report.processStartedUs > 0 &&
                        sqlite3_column_int64(candidates.get(), 4 + side * 2) == event.pid &&
                        std::abs(sqlite3_column_int64(candidates.get(), 5 + side * 2) -
                            report.processStartedUs) <= 1000;
                if (identities[0] == identities[1])
                    continue;
                client = identities[0];
                if (report.roleKnown && report.client != client)
                    continue;
            }
            const int pidColumn = (report.raw ? localSource : client) ? 4 : 6;
            const auto processStart = sqlite3_column_int64(candidates.get(), pidColumn + 1);
            if (sqlite3_column_int64(candidates.get(), pidColumn) != event.pid || !processStart ||
                std::abs(processStart - report.processStartedUs) > 1000 ||
                data.value("transport", "TCP") != (report.quic ? "QUIC" : report.udp ? "UDP" : "TCP") ||
                (report.raw ? data.value("protocol", "TLS") != "Unknown" :
                    data.value("protocol", "TLS") != (report.udp ? "DTLS" : "TLS")) ||
                (report.quic && data.value("quic_original_dcid", "") != report.quicId) ||
                (report.version && sqlite3_column_int(candidates.get(), 1) != report.version) ||
                (report.cipher && sqlite3_column_int(candidates.get(), 2) != report.cipher) ||
                (report.group >= 0 && (!data.contains("selected_group_id") || data["selected_group_id"] != report.group)))
                continue;
            ++matches;
            matchedClient = client;
            flow = sqlite3_column_int64(candidates.get(), 0);
            crypto = std::move(data);
        }
        if (result != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(database_.get()));
        if (rows >= 32)
            matches = 2;
        auto detail = nlohmann::json::parse(event.detail);
        const std::string status = matches == 1 ? (report.partial ?
            "Unique provider, process lifetime, peer, timing, and parameters; socket not reported" : report.raw ?
            "Exact socket, process lifetime, and timing; algorithm reported by endpoint" :
            "Exact socket, process lifetime, timing, and parameters") :
            matches > 1 ? "Ambiguous matching connections; no association asserted" :
            expired ? "Unmatched socket, process lifetime, timing, or parameters" :
            "Awaiting exact socket and process-lifetime match";
        detail["correlation"] = status;
        if (matches == 1)
        {
            auto confirmation = endpointConfirmation(event, status, matchedClient);
            if (report.raw)
            {
                confirmation["protocol"] = "Raw";
                confirmation["algorithm"] = report.algorithm;
                confirmation["mode"] = report.mode;
                confirmation["key_bits"] = report.keyBits;
            }
            if (!crypto.contains("endpoint_confirmations"))
                crypto["endpoint_confirmations"] = nlohmann::json::array();
            auto& confirmations = crypto["endpoint_confirmations"];
            auto found = std::ranges::find_if(confirmations, [&](const nlohmann::json& value)
            {
                return value.value("event_id", "") == event.id;
            });
            if (found != confirmations.end())
                *found = confirmation;
            else if (confirmations.size() < 16)
                confirmations.push_back(confirmation);
            else
            {
                detail["correlation"] = "Connection endpoint evidence limit reached";
                flow = 0;
                ++counters_.telemetryLost;
            }
            if (flow)
            {
                const bool success = std::ranges::any_of(confirmations,
                    [](const nlohmann::json& value) { return value.value("success", false); });
                const bool failure = std::ranges::any_of(confirmations,
                    [](const nlohmann::json& value) { return !value.value("success", false); });
                crypto["handshake_confirmation"] = report.raw ? (success && failure ?
                    "Conflicting endpoint encryption reports" : success ? "Endpoint reported encryption" :
                    "Endpoint reported encryption failure") : success && failure ? "Conflicting endpoint outcomes" :
                        success ? "Endpoint confirmed completion" : "Endpoint confirmed failure";
                auto update = prepare("UPDATE connections SET crypto_json=?,"
                    "change_revision=(SELECT revision FROM metadata) WHERE run_id=? AND flow_id=? AND crypto_json<>?");
                const auto json = crypto.dump();
                sqlite3_bind_text(update.get(), 1, json.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(update.get(), 2, runId_.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(update.get(), 3, flow);
                sqlite3_bind_text(update.get(), 4, json.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(update.get()) != SQLITE_DONE)
                    throw std::runtime_error(sqlite3_errmsg(database_.get()));
                detail["matched_flow_id"] = flow;
                detail["matched_run_id"] = runId_;

            }
        }
        if (it->linkedFlow && (matches != 1 || flow != it->linkedFlow))
        {
            // Late tuple reuse can invalidate an earlier association; remove only this event's evidence.
            auto read = prepare("SELECT crypto_json FROM connections WHERE run_id=? AND flow_id=?");
            sqlite3_bind_text(read.get(), 1, runId_.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(read.get(), 2, it->linkedFlow);
            if (sqlite3_step(read.get()) == SQLITE_ROW)
            {
                auto previous = nlohmann::json::parse(reinterpret_cast<const char*>(sqlite3_column_text(read.get(), 0)));
                auto& confirmations = previous["endpoint_confirmations"];
                std::erase_if(confirmations.get_ref<nlohmann::json::array_t&>(), [&](const nlohmann::json& value)
                {
                    return value.value("event_id", "") == event.id;
                });
                const bool success = std::ranges::any_of(confirmations,
                    [](const nlohmann::json& value) { return value.value("success", false); });
                const bool failure = std::ranges::any_of(confirmations,
                    [](const nlohmann::json& value) { return !value.value("success", false); });
                previous["handshake_confirmation"] = report.raw ? (success && failure ?
                    "Conflicting endpoint encryption reports" : success ? "Endpoint reported encryption" :
                    failure ? "Endpoint reported encryption failure" : "Not confirmed by endpoint") :
                    success && failure ? "Conflicting endpoint outcomes" :
                    success ? "Endpoint confirmed completion" : failure ? "Endpoint confirmed failure" :
                    "Not confirmed by endpoint";
                auto update = prepare("UPDATE connections SET crypto_json=?,"
                    "change_revision=(SELECT revision FROM metadata) WHERE run_id=? AND flow_id=?");
                const auto json = previous.dump();
                sqlite3_bind_text(update.get(), 1, json.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(update.get(), 2, runId_.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(update.get(), 3, it->linkedFlow);
                if (sqlite3_step(update.get()) != SQLITE_DONE)
                    throw std::runtime_error(sqlite3_errmsg(database_.get()));
            }

        }
        if (matches != 1 || !flow)
        {
            detail.erase("matched_flow_id");
            detail.erase("matched_run_id");
        }
        it->linkedFlow = matches == 1 ? flow : 0;
        const auto json = detail.dump();
        if (event.detail != json)
        {
            const auto previousBytes = event.memory();
            event.detail = json;
            endpointPendingBytes_ = endpointPendingBytes_ - previousBytes + event.memory();
            writeEndpointDetail(event);
        }
        if (expired)
        {
            endpointPendingBytes_ -= event.memory();
            it = endpointPending_.erase(it);
        }
        else
            ++it;
    }
}

void Storage::write(const Observation& o)
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
    integer(o.cipher, o.protocol == Observation::Protocol::Tls && o.serverHello);
    text(o.protocol == Observation::Protocol::Ssh ?
        (o.ssh->selected[2] == o.ssh->selected[3] ? o.ssh->selected[2] : "Directional ciphers; see SSH evidence") :
        o.protocol == Observation::Protocol::Tls && o.serverHello ? cipherName(o.cipher) : "");
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

void Storage::heartbeat(std::string_view status, bool stopped)
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

void Storage::writeOwners(const Observation& observation)
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
            for (int copy = 0; copy < 2; ++copy)
                sqlite3_bind_text(statement, ++index, value->c_str(), -1, SQLITE_TRANSIENT);
        if (owner->startedUs)
            sqlite3_bind_int64(statement, ++index, owner->startedUs);
        else
            sqlite3_bind_null(statement, ++index);
        for (const auto* value : {&owner->evidence, &owner->account, &owner->accountDomain, &owner->accountSid})
            for (int copy = 0; copy < 2; ++copy)
                sqlite3_bind_text(statement, ++index, value->c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(statement, ++index, runId_.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, ++index, observation.flowId);
    if (sqlite3_step(statement) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(database_.get()));
}

void Storage::work()
{
    try
    {
        auto heartbeatDeadline = std::chrono::steady_clock::now();
        auto retentionDeadline = heartbeatDeadline;
        auto optimizeDeadline = heartbeatDeadline + std::chrono::hours(1);
        for (;;)
        {
            std::vector<Observation> batch;
            std::vector<Observation> owners;
            std::vector<EndpointEvent> events;
            bool done = false;
            {
                std::unique_lock lock(mutex_);
                changed_.wait_for(lock, std::chrono::milliseconds(100), [this]
                {
                    return stopping_ || !events_.empty() ||
                        (!queue_.empty() && queue_.front().ready <= std::chrono::steady_clock::now());
                });
                if (!stopping_ && !queue_.empty() && queue_.size() < 256)
                    changed_.wait_for(lock, std::chrono::milliseconds(10), [this]
                    {
                        return stopping_ || queue_.size() >= 256;
                    });
                while (batch.size() < 256 && !queue_.empty() &&
                    (stopping_ || queue_.front().ready <= std::chrono::steady_clock::now()))
                {
                    pending_.erase(queue_.front().observation.flowId);
                    queueBytes_ -= queue_.front().observation.memory();
                    batch.push_back(std::move(queue_.front().observation));
                    queue_.pop_front();
                }
                while (events.size() < 128 && !events_.empty())
                {
                    eventBytes_ -= events_.front().memory();
                    events.push_back(std::move(events_.front()));
                    events_.pop_front();
                }
                done = stopping_ && queue_.empty() && events_.empty();
            }
            changed_.notify_all();

            // Publish hellos immediately; delayed ETW attribution only updates ownership columns.
            if (enricher_)
            {
                for (auto& observation : batch)
                {
                    if (observation.lifecycleOnly)
                        continue;
                    enricher_(observation);
                    if (refinements_.size() < 8192)
                    {
                        Observation refinement;
                        refinement.flowId = observation.flowId;
                        refinement.firstUs = observation.firstUs;
                        refinement.lastUs = observation.lastUs;
                        refinement.quic = observation.quic;
                        refinement.udp = observation.udp;
                        refinement.source = observation.source;
                        refinement.destination = observation.destination;
                        refinements_.push_back({std::move(refinement),
                            std::chrono::steady_clock::now() + std::chrono::milliseconds(1500)});
                    }
                    else
                        ++counters_.processEventsLost;
                }
                while (!refinements_.empty() && owners.size() < 256 &&
                    (done || refinements_.front().ready <= std::chrono::steady_clock::now()))
                {
                    auto pending = std::move(refinements_.front());
                    refinements_.pop_front();
                    owners.push_back(std::move(pending.observation));
                    enricher_(owners.back());
                    if (!done && pending.attempts < 3 && owners.back().sourceOwner.name.empty() &&
                        owners.back().destinationOwner.name.empty())
                        refinements_.push_back({owners.back(),
                            std::chrono::steady_clock::now() + std::chrono::seconds(1),
                            static_cast<uint8_t>(pending.attempts + 1)});
                }
            }
            if (std::chrono::steady_clock::now() >= retentionDeadline)
            {
                const bool more = retention_->maintain(nowUs(), runId_,
                    [this](const std::string& hash) { catalog_.forget(hash); });
                retentionDeadline = std::chrono::steady_clock::now() +
                    (more ? std::chrono::milliseconds(100) : std::chrono::milliseconds(5000));
            }

            // Refresh planner statistics outside capture transactions with SQLite's bounded analysis budget.
            if (std::chrono::steady_clock::now() >= optimizeDeadline)
            {
                sqlite3_exec(database_.get(), "PRAGMA optimize", nullptr, nullptr, nullptr);
                optimizeDeadline = std::chrono::steady_clock::now() + std::chrono::hours(1);
            }
            if (!done && batch.empty() && owners.empty() && events.empty() &&
                std::chrono::steady_clock::now() < heartbeatDeadline)
                continue;
            // Serialize the durable cursor with the data, including across independent collectors.
            execute("BEGIN IMMEDIATE");
            execute("UPDATE metadata SET revision=revision+1 WHERE id=1");
            for (const auto& observation : batch)
                write(observation);
            for (const auto& observation : owners)
                writeOwners(observation);
            for (auto& event : events)
                write(event);
            std::unordered_set<FlowKey, FlowHash> dirty;
            for (const auto* observations : {&batch, &owners})
                for (const auto& observation : *observations)
                    if (!observation.lifecycleOnly)
                        dirty.insert(FlowKey::make(observation.source, observation.destination));
            const bool final = done && refinements_.empty();
            correlateEndpoints(final, dirty);
            heartbeat(final ? finalStatus_ : "running", final);
            execute("COMMIT");

            if (final)
            {
                retention_->maintain(nowUs(), runId_, [this](const std::string& hash) { catalog_.forget(hash); });
                sqlite3_exec(database_.get(), "PRAGMA optimize", nullptr, nullptr, nullptr);
            }

            // A journal with nothing new to record writes its heartbeat less often, still well inside the
            // interval after which readers report a session as having no recent heartbeat.
            const bool idle = batch.empty() && owners.empty() && events.empty();
            heartbeatDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(idle ? 5 : 1);
            if (final)
                break;
        }
    }
    catch (...)
    {
        sqlite3_exec(database_.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        std::lock_guard lock(mutex_);
        error_ = std::current_exception();
        changed_.notify_all();
    }
}

void Storage::check()
{
    std::lock_guard lock(mutex_);
    if (error_)
        std::rethrow_exception(error_);
}

void Storage::finish(std::string status)
{
    if (thread_.joinable())
    {
        {
            std::lock_guard lock(mutex_);
            finalStatus_ = std::move(status);
            stopping_ = true;
        }
        changed_.notify_one();
        thread_.join();
    }
    check();
}
}
