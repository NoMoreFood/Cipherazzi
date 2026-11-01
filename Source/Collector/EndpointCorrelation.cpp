#include "EndpointCorrelation.h"
#include <sqlite3.h>
#include <algorithm>
#include <stdexcept>

namespace Cipherazzi
{
EndpointCorrelation::EndpointCorrelation(JournalWriter& journal) : journal_(journal),
    telemetry_(journal.prepare("INSERT OR IGNORE INTO endpoint_events VALUES"
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,(SELECT revision FROM metadata))")),
    readCertMetadata_(journal.prepare("SELECT metadata_json FROM certificates WHERE sha256=?")),
    linkCert_(journal.prepare("INSERT OR IGNORE INTO endpoint_certificates "
        "SELECT ?,sha256 FROM certificates WHERE sha256=?")),
    linkEndpointCert_(journal.prepare("INSERT OR IGNORE INTO endpoint_certificates VALUES(?,?)")),
    writeDetail_(journal.prepare("UPDATE endpoint_events SET detail_json=?,"
        "change_revision=(SELECT revision FROM metadata) WHERE id=? AND run_id=?")),
    writeCorrelation_(journal.prepare("UPDATE endpoint_events SET "
        "detail_json=json_set(detail_json,'$.correlation',?1),change_revision=(SELECT revision FROM metadata) "
        "WHERE id=?2 AND run_id=?3 AND json_extract(detail_json,'$.correlation') IS NOT ?1 RETURNING detail_json")),
    candidatesPartial_(journal.prepare(R"SQL(
        SELECT flow_id,tls_version,cipher_id,crypto_json,
            source_pid,source_process_started_us,destination_pid,destination_process_started_us,
            source_address,source_port
        FROM connections WHERE run_id=?1 AND
            first_us>=?6 AND first_us<=?7 AND last_us>=?8 AND
            length(?12)>0 AND
            (((?11=0 OR destination_port=?11) AND (destination_address=?12 OR sni=?12 COLLATE NOCASE)) OR
            ((?11=0 OR source_port=?11) AND (source_address=?12 OR sni=?12 COLLATE NOCASE)))
        LIMIT 32)SQL")),
    candidatesRaw_(journal.prepare(R"SQL(
        SELECT flow_id,tls_version,cipher_id,crypto_json,
            source_pid,source_process_started_us,destination_pid,destination_process_started_us,
            source_address,source_port
        FROM connections WHERE run_id=?1 AND
            first_us>=?6 AND first_us<=?7 AND last_us>=?8 AND
            ((source_address=?2 AND source_port=?3 AND destination_address=?4 AND destination_port=?5) OR
                (source_address=?4 AND source_port=?5 AND destination_address=?2 AND destination_port=?3))
        LIMIT 32)SQL")),
    candidatesDefault_(journal.prepare(R"SQL(
        SELECT flow_id,tls_version,cipher_id,crypto_json,
            source_pid,source_process_started_us,destination_pid,destination_process_started_us,
            source_address,source_port
        FROM connections WHERE run_id=?1 AND
            first_us>=?6 AND first_us<=?7 AND last_us>=?8 AND
            source_address=?2 AND source_port=?3 AND destination_address=?4 AND destination_port=?5
        LIMIT 32)SQL")),
    updateConnectionCrypto_(journal.prepare("UPDATE connections SET crypto_json=?,"
        "change_revision=(SELECT revision FROM metadata) WHERE run_id=? AND flow_id=? AND crypto_json<>?")),
    readConnectionCrypto_(journal.prepare("SELECT crypto_json FROM connections WHERE run_id=? AND flow_id=?")),
    updateConnectionCryptoUnconditional_(journal.prepare("UPDATE connections SET crypto_json=?,"
        "change_revision=(SELECT revision FROM metadata) WHERE run_id=? AND flow_id=?")) {}

namespace EndpointCorrelationDetail
{
// Summarizes what the endpoints matched to one connection reported about it.
const char* confirmationSummary(const Json& confirmations, bool raw)
{
    const bool success = std::ranges::any_of(confirmations,
        [](const Json& value) { return value.value("success", false); });
    const bool failure = std::ranges::any_of(confirmations,
        [](const Json& value) { return !value.value("success", false); });
    if (!success && !failure)
        return "Not confirmed by endpoint";
    if (raw)
        return success && failure ? "Conflicting endpoint encryption reports" :
            success ? "Endpoint reported encryption" : "Endpoint reported encryption failure";
    return success && failure ? "Conflicting endpoint outcomes" :
        success ? "Endpoint confirmed completion" : "Endpoint confirmed failure";
}

Json endpointConfirmation(const EndpointEvent& event, const Json& detail,
    std::string_view status, int client)
{
    const auto& report = *event.report;
    return {
        {"event_id", event.id}, {"provider", event.provider}, {"timestamp_us", event.timestampUs},
        {"pid", event.pid}, {"process_started_us", report.processStartedUs},
        {"process_scope", detail.value("process_scope", "endpoint")},
        {"observation", report.connection ? "connection" : "handshake"},
        {"local_role", client < 0 ? "Unknown" : client ? "Client" : "Server"}, {"success", report.success},
        {"match", status}, {"peer_verified", report.peerVerified},
        {"handshake_signature_id", report.signature < 0 ? Json(nullptr) : Json(report.signature)},
        {"handshake_signature", report.signature < 0 ? "" : signatureName(static_cast<uint16_t>(report.signature))},
        {"authentication_class", signatureClass(report.signature)}, {"selected_alpn", report.alpn},
        {"local_handshake_signature_id", report.localSignature < 0 ? Json(nullptr) :
            Json(report.localSignature)},
        {"local_handshake_signature", report.localSignature < 0 ? "" :
            signatureName(static_cast<uint16_t>(report.localSignature))},
        {"local_authentication_class", signatureClass(report.localSignature)},
        {"certificate_facts", detail.contains("assessment") ?
            detail["assessment"].value("certificate_facts", "") : std::string{}},
        {"server_certificates", detail.value("server_certificates", Json::array())},
        {"client_certificates", detail.value("client_certificates", Json::array())}
    };
}
}
using namespace EndpointCorrelationDetail;

void EndpointCorrelation::write(EndpointEvent& event)
{
    // A report's detail is parsed once; the steps below read and amend this copy.
    Json detail;
    if (event.report)
    {
        detail = Json::parse(event.detail);

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
        const auto summary = journal_.catalog_.summarize(certificates,
        [this](const std::string& hash, const std::string& metadata, Bytes der)
        {
            sqlite3_reset(journal_.certificates_.get());
            sqlite3_bind_text(journal_.certificates_.get(), 1, hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(journal_.certificates_.get(), 2, metadata.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(journal_.certificates_.get(), 3, der.data(),
                static_cast<int>(der.size()), SQLITE_TRANSIENT);
            if (sqlite3_step(journal_.certificates_.get()) != SQLITE_DONE)
                throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
        });
        if (!report.raw)
        {
            // Unmatched public endpoint evidence is assessed without inventing a captured connection.
            auto crypto = Json::parse(summary.json);
            crypto["evidence_source"] = "Endpoint";
            crypto["transport"] = detail.value("transport", "Unknown");
            crypto["protocol"] = report.udp ? "DTLS" : "TLS";
            crypto["endpoint_confirmations"] = Json::array({endpointConfirmation(event, detail,
                "Endpoint report; packet association evaluated independently", report.roleKnown ? report.client : -1)});
            std::string facts;
            auto* read = readCertMetadata_.get();
            for (const auto& reference : summary.certificates)
            {
                sqlite3_reset(read);
                sqlite3_bind_text(read, 1, reference.sha256.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(read) != SQLITE_ROW)
                    continue;
                const auto metadata = Json::parse(
                    reinterpret_cast<const char*>(sqlite3_column_text(read, 0)));
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
                {"first_us", report.partial || report.connection ? event.timestampUs : report.startedUs},
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
    text(journal_.runId_);
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
        throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
    const bool inserted = sqlite3_changes(journal_.database_.get()) != 0;
    if (inserted && !event.certificateId.empty())
    {
        auto* link = linkCert_.get();
        sqlite3_reset(link);
        sqlite3_bind_text(link, 1, event.id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(link, 2, event.certificateId.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(link) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
    }
    if (event.report && inserted)
    {
        auto* link = linkEndpointCert_.get();
        for (const auto* field : {"server_certificates", "client_certificates"})
            for (const auto& value : detail.value(field, Json::array()))
            {
                const auto hash = value.get<std::string>();
                sqlite3_reset(link);
                sqlite3_bind_text(link, 1, event.id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(link, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(link) != SQLITE_DONE)
                    throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
            }
        if (!event.report->correlatable)
            return;
        if (pending_.size() >= 2048 || bytes_ + event.memory() > 16 * 1024 * 1024)
        {
            detail["correlation"] = "Endpoint matching capacity exceeded; no association asserted";
            event.detail = detail.dump();
            writeDetail(event);
            ++journal_.counters_.telemetryLost;
        }
        else
        {
            EndpointEvent pending = event;
            auto publicReport = std::make_shared<EndpointReport>(*event.report);
            publicReport->serverCertificates.clear();
            publicReport->clientCertificates.clear();
            pending.report = std::move(publicReport);
            bytes_ += pending.memory();
            pending_.push_back(
                {std::move(pending), std::chrono::steady_clock::now() + std::chrono::seconds(120)});
        }
    }
}

void EndpointCorrelation::writeDetail(const EndpointEvent& event)
{
    auto* statement = writeDetail_.get();
    sqlite3_reset(statement);
    sqlite3_bind_text(statement, 1, event.detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, event.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE)
        throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
}

void EndpointCorrelation::resolve(bool final, const std::unordered_set<FlowKey, FlowHash>& dirty)
{
    for (auto it = pending_.begin(); it != pending_.end();)
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
        sqlite3_stmt* candidates = report.partial ? candidatesPartial_.get() :
            report.raw ? candidatesRaw_.get() : candidatesDefault_.get();
        sqlite3_reset(candidates);
        sqlite3_clear_bindings(candidates);
        sqlite3_bind_text(candidates, 1, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
        if (report.partial)
        {
            sqlite3_bind_int(candidates, 11, report.remote.port);
            const auto peer = std::ranges::any_of(report.remote.address, [](uint8_t value) { return value != 0; }) ?
                report.remote.text() : report.peerName;
            sqlite3_bind_text(candidates, 12, peer.c_str(), -1, SQLITE_TRANSIENT);
        }
        else
        {
            sqlite3_bind_text(candidates, 2, source.text().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(candidates, 3, source.port);
            sqlite3_bind_text(candidates, 4, destination.text().c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(candidates, 5, destination.port);
        }
        sqlite3_bind_int64(candidates, 6, report.startedUs - 250000);
        sqlite3_bind_int64(candidates, 7, event.timestampUs + 100000);
        sqlite3_bind_int64(candidates, 8,
            report.partial ? event.timestampUs - 2000000 : report.startedUs - 100000);
        int64_t flow = 0;
        bool matchedClient = report.client;
        size_t matches = 0, rows = 0;
        Json crypto;
        int result;
        while ((result = sqlite3_step(candidates)) == SQLITE_ROW)
        {
            ++rows;
            auto data = Json::parse(reinterpret_cast<const char*>(sqlite3_column_text(candidates, 3)));
            const bool localSource = report.local.text() ==
                reinterpret_cast<const char*>(sqlite3_column_text(candidates, 8)) &&
                report.local.port == sqlite3_column_int(candidates, 9);
            bool client = report.client;
            if (report.partial)
            {
                bool identities[2]{};
                for (int side = 0; side < 2; ++side)
                    identities[side] = report.processStartedUs > 0 &&
                        sqlite3_column_int64(candidates, 4 + side * 2) == event.pid &&
                        std::abs(sqlite3_column_int64(candidates, 5 + side * 2) -
                            report.processStartedUs) <= 1000;
                if (identities[0] == identities[1])
                    continue;
                client = identities[0];
                if (report.roleKnown && report.client != client)
                    continue;
            }
            const int pidColumn = (report.raw ? localSource : client) ? 4 : 6;
            const auto processStart = sqlite3_column_int64(candidates, pidColumn + 1);
            if (sqlite3_column_int64(candidates, pidColumn) != event.pid || !processStart ||
                std::abs(processStart - report.processStartedUs) > 1000 ||
                data.value("transport", "TCP") !=
                    (report.quic         ? "QUIC"
                            : report.udp ? "UDP"
                                         : "TCP") ||
                (report.raw ? data.value("protocol", "TLS") != "Unknown"
                            : data.value("protocol", "TLS") != (report.udp ? "DTLS" : "TLS")) ||
                (report.quic && data.value("quic_original_dcid", "") != report.quicId) ||
                (report.version && sqlite3_column_int(candidates, 1) != report.version) ||
                (report.cipher && sqlite3_column_int(candidates, 2) != report.cipher) ||
                (report.group >= 0 &&
                    (!data.contains("selected_group_id") || data["selected_group_id"] != report.group)))
                continue;
            ++matches;
            matchedClient = client;
            flow = sqlite3_column_int64(candidates, 0);
            crypto = std::move(data);
        }
        if (result != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
        if (rows >= 32)
            matches = 2;
        const std::string status = matches == 1 ? (report.partial ?
            "Unique provider, process lifetime, peer, timing, and parameters; socket not reported" : report.raw ?
            "Exact socket, process lifetime, and timing; algorithm reported by endpoint" :
            "Exact socket, process lifetime, timing, and parameters") :
            matches > 1 ? "Ambiguous matching connections; no association asserted" :
            expired ? "Unmatched socket, process lifetime, timing, or parameters" :
            "Awaiting exact socket and process-lifetime match";
        if (!matches && !it->linkedFlow)
        {
            // Unassociated reports only change status; preserve their assessment without rebuilding its JSON.
            auto* update = writeCorrelation_.get();
            sqlite3_reset(update);
            sqlite3_bind_text(update, 1, status.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(update, 2, event.id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(update, 3, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
            result = sqlite3_step(update);
            if (result == SQLITE_ROW)
            {
                const auto previousBytes = event.memory();
                event.detail = reinterpret_cast<const char*>(sqlite3_column_text(update, 0));
                bytes_ = bytes_ - previousBytes + event.memory();
                result = sqlite3_step(update);
            }
            if (result != SQLITE_DONE)
                throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
            if (expired)
            {
                bytes_ -= event.memory();
                it = pending_.erase(it);
            }
            else
                ++it;
            continue;
        }
        auto detail = Json::parse(event.detail);
        detail["correlation"] = status;
        if (matches == 1)
        {
            auto confirmation = endpointConfirmation(event, detail, status, matchedClient);
            if (report.raw)
            {
                confirmation["protocol"] = "Raw";
                confirmation["algorithm"] = report.algorithm;
                confirmation["mode"] = report.mode;
                confirmation["key_bits"] = report.keyBits;
            }
            if (!crypto.contains("endpoint_confirmations"))
                crypto["endpoint_confirmations"] = Json::array();
            auto& confirmations = crypto["endpoint_confirmations"];
            auto found = std::ranges::find_if(confirmations, [&](const Json& value)
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
                ++journal_.counters_.telemetryLost;
            }
            if (flow)
            {
                crypto["handshake_confirmation"] = confirmationSummary(confirmations, report.raw);
                auto* update = updateConnectionCrypto_.get();
                sqlite3_reset(update);
                const auto json = crypto.dump();
                sqlite3_bind_text(update, 1, json.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(update, 2, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(update, 3, flow);
                sqlite3_bind_text(update, 4, json.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(update) != SQLITE_DONE)
                    throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
                detail["matched_flow_id"] = flow;
                detail["matched_run_id"] = journal_.runId_;
            }
        }
        if (it->linkedFlow && (matches != 1 || flow != it->linkedFlow))
        {
            // Late tuple reuse can invalidate an earlier association; remove only this event's evidence.
            auto* read = readConnectionCrypto_.get();
            sqlite3_reset(read);
            sqlite3_bind_text(read, 1, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(read, 2, it->linkedFlow);
            if (sqlite3_step(read) == SQLITE_ROW)
            {
                auto previous =
                    Json::parse(reinterpret_cast<const char*>(sqlite3_column_text(read, 0)));
                auto& confirmations = previous["endpoint_confirmations"];
                std::erase_if(confirmations.elements(), [&](const Json& value)
                {
                    return value.value("event_id", "") == event.id;
                });
                previous["handshake_confirmation"] = confirmationSummary(confirmations, report.raw);
                auto* update = updateConnectionCryptoUnconditional_.get();
                sqlite3_reset(update);
                const auto json = previous.dump();
                sqlite3_bind_text(update, 1, json.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(update, 2, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(update, 3, it->linkedFlow);
                if (sqlite3_step(update) != SQLITE_DONE)
                    throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
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
            bytes_ = bytes_ - previousBytes + event.memory();
            writeDetail(event);
        }
        if (expired)
        {
            bytes_ -= event.memory();
            it = pending_.erase(it);
        }
        else
            ++it;
    }
}

}
