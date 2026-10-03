#include "EndpointCorrelation.h"
#include <sqlite3.h>
#include <algorithm>
#include <stdexcept>

namespace Cipherazzi
{
EndpointCorrelation::EndpointCorrelation(JournalWriter& journal) : journal_(journal),
    telemetry_(journal.prepare("INSERT OR IGNORE INTO endpoint_events VALUES"
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,(SELECT revision FROM metadata))")) {}

namespace EndpointCorrelationDetail
{
// Summarizes what the endpoints matched to one connection reported about it.
const char* confirmationSummary(const nlohmann::json& confirmations, bool raw)
{
    const bool success = std::ranges::any_of(confirmations,
        [](const nlohmann::json& value) { return value.value("success", false); });
    const bool failure = std::ranges::any_of(confirmations,
        [](const nlohmann::json& value) { return !value.value("success", false); });
    if (!success && !failure)
        return "Not confirmed by endpoint";
    if (raw)
        return success && failure ? "Conflicting endpoint encryption reports" :
            success ? "Endpoint reported encryption" : "Endpoint reported encryption failure";
    return success && failure ? "Conflicting endpoint outcomes" :
        success ? "Endpoint confirmed completion" : "Endpoint confirmed failure";
}

nlohmann::json endpointConfirmation(const EndpointEvent& event, const nlohmann::json& detail,
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
}
using namespace EndpointCorrelationDetail;

void EndpointCorrelation::write(EndpointEvent& event)
{
    // A report's detail is parsed once; the steps below read and amend this copy.
    nlohmann::json detail;
    if (event.report)
    {
        detail = nlohmann::json::parse(event.detail);

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
            auto crypto = nlohmann::json::parse(summary.json);
            crypto["evidence_source"] = "Endpoint";
            crypto["transport"] = detail.value("transport", "Unknown");
            crypto["protocol"] = report.udp ? "DTLS" : "TLS";
            crypto["endpoint_confirmations"] = nlohmann::json::array({endpointConfirmation(event, detail,
                "Endpoint report; packet association evaluated independently", report.roleKnown ? report.client : -1)});
            std::string facts;
            auto read = journal_.prepare("SELECT metadata_json FROM certificates WHERE sha256=?");
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
        auto link = journal_.prepare("INSERT OR IGNORE INTO endpoint_certificates "
            "SELECT ?,sha256 FROM certificates WHERE sha256=?");
        sqlite3_bind_text(link.get(), 1, event.id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(link.get(), 2, event.certificateId.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(link.get()) != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
    }
    if (event.report && inserted)
    {
        auto link = journal_.prepare("INSERT OR IGNORE INTO endpoint_certificates VALUES(?,?)");
        for (const auto* field : {"server_certificates", "client_certificates"})
            for (const auto& value : detail.value(field, nlohmann::json::array()))
            {
                const auto hash = value.get<std::string>();
                sqlite3_reset(link.get());
                sqlite3_bind_text(link.get(), 1, event.id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(link.get(), 2, hash.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(link.get()) != SQLITE_DONE)
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
    auto statement = journal_.prepare("UPDATE endpoint_events SET detail_json=?,"
        "change_revision=(SELECT revision FROM metadata) WHERE id=? AND run_id=?");
    sqlite3_bind_text(statement.get(), 1, event.detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement.get(), 2, event.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement.get(), 3, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement.get()) != SQLITE_DONE)
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
        auto candidates = journal_.prepare(candidateSql.c_str());
        sqlite3_bind_text(candidates.get(), 1, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
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
                data.value("transport", "TCP") !=
                    (report.quic         ? "QUIC"
                            : report.udp ? "UDP"
                                         : "TCP") ||
                (report.raw ? data.value("protocol", "TLS") != "Unknown"
                            : data.value("protocol", "TLS") != (report.udp ? "DTLS" : "TLS")) ||
                (report.quic && data.value("quic_original_dcid", "") != report.quicId) ||
                (report.version && sqlite3_column_int(candidates.get(), 1) != report.version) ||
                (report.cipher && sqlite3_column_int(candidates.get(), 2) != report.cipher) ||
                (report.group >= 0 &&
                    (!data.contains("selected_group_id") || data["selected_group_id"] != report.group)))
                continue;
            ++matches;
            matchedClient = client;
            flow = sqlite3_column_int64(candidates.get(), 0);
            crypto = std::move(data);
        }
        if (result != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
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
            auto confirmation = endpointConfirmation(event, detail, status, matchedClient);
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
                ++journal_.counters_.telemetryLost;
            }
            if (flow)
            {
                crypto["handshake_confirmation"] = confirmationSummary(confirmations, report.raw);
                auto update = journal_.prepare("UPDATE connections SET crypto_json=?,"
                    "change_revision=(SELECT revision FROM metadata) WHERE run_id=? AND flow_id=? AND crypto_json<>?");
                const auto json = crypto.dump();
                sqlite3_bind_text(update.get(), 1, json.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(update.get(), 2, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(update.get(), 3, flow);
                sqlite3_bind_text(update.get(), 4, json.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(update.get()) != SQLITE_DONE)
                    throw std::runtime_error(sqlite3_errmsg(journal_.database_.get()));
                detail["matched_flow_id"] = flow;
                detail["matched_run_id"] = journal_.runId_;

            }
        }
        if (it->linkedFlow && (matches != 1 || flow != it->linkedFlow))
        {
            // Late tuple reuse can invalidate an earlier association; remove only this event's evidence.
            auto read = journal_.prepare("SELECT crypto_json FROM connections WHERE run_id=? AND flow_id=?");
            sqlite3_bind_text(read.get(), 1, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(read.get(), 2, it->linkedFlow);
            if (sqlite3_step(read.get()) == SQLITE_ROW)
            {
                auto previous =
                    nlohmann::json::parse(reinterpret_cast<const char*>(sqlite3_column_text(read.get(), 0)));
                auto& confirmations = previous["endpoint_confirmations"];
                std::erase_if(confirmations.get_ref<nlohmann::json::array_t&>(), [&](const nlohmann::json& value)
                {
                    return value.value("event_id", "") == event.id;
                });
                previous["handshake_confirmation"] = confirmationSummary(confirmations, report.raw);
                auto update = journal_.prepare("UPDATE connections SET crypto_json=?,"
                    "change_revision=(SELECT revision FROM metadata) WHERE run_id=? AND flow_id=?");
                const auto json = previous.dump();
                sqlite3_bind_text(update.get(), 1, json.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(update.get(), 2, journal_.runId_.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(update.get(), 3, it->linkedFlow);
                if (sqlite3_step(update.get()) != SQLITE_DONE)
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
