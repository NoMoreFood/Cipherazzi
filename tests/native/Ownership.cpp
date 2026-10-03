#include "Engine.h"
#include "Storage.h"
#include "Processes.h"
#include "Proxy.h"
#include "HttpSpyStore.h"
#include "JournalWriter.h"
#include <sqlite3.h>
#include <algorithm>
#include <cstring>
#include <future>
#include <iostream>
#include <map>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);
int scalar(sqlite3* database, const char* sql);
std::vector<uint8_t> hello(bool client, uint16_t version, bool retry, bool ech, Bytes extensions);
std::vector<uint8_t> record(Bytes payload, uint8_t type);

struct ProcessAccess
{
    static void reset(Processes& processes)
    {
        processes.stop();
        processes.counters_.processEventsLost = 0;
        processes.connections_.clear();
        processes.lifetimes_.clear();
        processes.changedConnections_.clear();
        processes.changedProcesses_.clear();
        processes.changedSockets_ = 0;
        processes.changesIncomplete_ = false;
        processes.traceEventsLost_ = 0;
        processes.lifetimeBytes_ = 0;
        processes.snapshot_.clear();
        processes.udpSnapshot_.clear();
        processes.udpAddresses_.clear();
        processes.snapshotUs_ = processes.udpSnapshotUs_ = processes.pruneUs_ = 0;
    }
    static void remember(Processes& processes, Owner owner, int64_t ended, int64_t verified = 0)
    {
        processes.remember(std::move(owner), ended, verified);
    }
    static Owner lookup(Processes& processes, uint32_t pid, int64_t first, int64_t last)
    {
        return processes.lookup(pid, first, last);
    }
    static void loss(Processes& processes, uint32_t count)
    {
        EVENT_TRACE_LOGFILEW trace{};
        trace.Context = &processes;
        trace.EventsLost = count;
        processes.bufferCallback(&trace);
    }
    static void forgetSockets(Processes& processes)
    {
        std::lock_guard lock(processes.mutex_);
        processes.connections_.clear();
    }
    static void forgetProcess(Processes& processes, uint32_t pid)
    {
        std::lock_guard lock(processes.mutex_);
        const auto found = processes.lifetimes_.find(pid);
        if (found == processes.lifetimes_.end())
            return;
        for (const auto& lifetime : found->second.entries)
            processes.lifetimeBytes_ -= sizeof(Processes::Lifetime) - sizeof(Owner) + lifetime.owner.memory();
        processes.lifetimes_.erase(found);
    }
    static void event(Processes& processes, const Observation& row, uint32_t pid, uint32_t socket,
        int64_t timestamp, bool closed, bool server = false)
    {
        const auto& local = server ? row.destination : row.source;
        const auto& remote = server ? row.source : row.destination;
        const size_t length = local.family == 6 ? 16 : 4;
        const auto offset = 12 + length * 2 + (closed ? 4 : 20);
        std::vector<uint8_t> data(offset + 4);
        std::memcpy(data.data(), &pid, 4);
        std::memcpy(data.data() + offset, &socket, 4);
        std::copy_n(remote.address.begin(), length, data.begin() + 8);
        std::copy_n(local.address.begin(), length, data.begin() + 8 + length);
        data[8 + length * 2] = static_cast<uint8_t>(remote.port >> 8);
        data[9 + length * 2] = static_cast<uint8_t>(remote.port);
        data[10 + length * 2] = static_cast<uint8_t>(local.port >> 8);
        data[11 + length * 2] = static_cast<uint8_t>(local.port);
        EVENT_RECORD event{};
        event.EventHeader.ProviderId = {0x7dd42a49, 0x5329, 0x4832,
            {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
        event.EventHeader.EventDescriptor.Id = local.family == 6 ? closed ? 29 : server ? 31 : 28 :
            closed ? 13 : server ? 15 : 12;
        event.EventHeader.TimeStamp.QuadPart = 116444736000000000LL + timestamp * 10;
        event.UserData = data.data();
        event.UserDataLength = static_cast<USHORT>(data.size());
        processes.event(event);
    }
    static void snapshot(Processes& processes, const Observation& row, Owner owner, int64_t created, bool add = false)
    {
        const auto timestamp = nowUs();
        processes.remember(owner, 0, timestamp);
        if (row.udp)
        {
            if (!add) processes.udpSnapshot_.clear();
            processes.udpSnapshotUs_ = timestamp;
            processes.udpSnapshot_.push_back({row.source, std::move(owner), created, timestamp});
        }
        else
        {
            if (!add) processes.snapshot_.clear();
            processes.snapshotUs_ = timestamp;
            processes.snapshot_[FlowKey::make(row.source, row.destination)].push_back(
                {row.source, std::move(owner), created, timestamp});
        }
    }
    static void bounded(const Processes& processes, const Observation& row, uint32_t pid)
    {
        require(processes.connections_.at(FlowKey::make(row.source, row.destination)).events.size() <= 16 &&
            processes.lifetimes_.at(pid).entries.size() <= 4, "Rapid reuse exceeded ownership history limits");
    }
};

void proxyOwnershipCoverage()
{
    Counters counters;
    Processes processes(counters);
    ProcessAccess::reset(processes);
    UpstreamPorts ports;
    Observation client;
    client.source = {{192, 0, 2, 1}, 45000, 4};
    client.destination = {{192, 0, 2, 2}, 443, 4};
    client.firstUs = 2020000;
    client.lastUs = 2030000;
    Owner owner{0xfffe0001, 1000000, "client.exe", "C:/client.exe", "test"};
    ProcessAccess::remember(processes, owner, 3000000);
    ProcessAccess::event(processes, client, owner.pid, 0, 2000000, false);
    ProcessAccess::event(processes, client, owner.pid, 0, 2040000, true);
    auto upstream = client;
    upstream.source.port = 46000;
    ports.add(upstream.source, client.source, client.destination, 2010000);
    ports.attribute(upstream, processes);
    require(upstream.sourceOwner.pid == owner.pid && upstream.sourceOwner.startedUs == owner.startedUs &&
        upstream.sourceOwner.evidence == "HTTP Spy client" && upstream.source.port == 46000,
        "Proxy attribution did not validate the original zero-ID socket and preserve the journal endpoint");

    // The mapping belongs to one TCP tuple, observation interval, and correction side.
    for (int mismatch = 0; mismatch < 8; ++mismatch)
    {
        auto other = upstream;
        if (mismatch == 0) other.udp = true;
        if (mismatch == 1) other.quic = true;
        if (mismatch == 2) other.source.address[3] = 9;
        if (mismatch == 3) other.destination.address[3] = 9;
        if (mismatch == 4) other.destination.port = 8443;
        if (mismatch == 5) other.firstUs = 2009999;
        if (mismatch == 6) other.ownerSides = 2;
        if (mismatch == 7) other.source.family = 6;
        require(!ports.client(other), "Proxy mapping crossed a transport, endpoint, time, or correction boundary");
    }
    // IPv4 and IPv6 sockets may reserve the same port without sharing the original client or lifetime.
    auto ipv6 = upstream;
    ipv6.source.family = ipv6.destination.family = 6;
    ports.add(ipv6.source, client.source, ipv6.destination, 2010000);
    require(ports.client(upstream) == client.source && ports.client(ipv6) == client.source,
        "Concurrent IPv4/IPv6 upstream ports replaced each other's ownership mapping");
    ports.release(upstream.source, 2035000);
    require(!ports.active(upstream.source) && ports.active(ipv6.source) && ports.client(upstream) == client.source,
        "Closing the upstream socket lost delayed attribution");
    auto later = upstream;
    later.lastUs = 2035001;
    require(!ports.client(later), "Proxy mapping attributed traffic after its connection ended");

    // A reused proxy port must not replace the original client of a historical observation.
    auto next = client.source;
    next.port = 47000;
    ports.add(upstream.source, next, client.destination, 2034000);
    auto boundary = upstream;
    boundary.firstUs = 2034500;
    boundary.lastUs = 2034600;
    require(!ports.client(boundary), "Coarse clock ticks let a replacement mapping overlap its predecessor");
    ports.add(upstream.source, next, client.destination, 2050000);
    require(!ports.client(upstream), "A reused proxy port matched an earlier connection");
    ports.attribute(upstream, processes);
    require(upstream.sourceOwner.pid == owner.pid, "A retired mapping lost its verified historical client");
    later.firstUs = 2060000;
    later.lastUs = 2070000;
    require(ports.client(later) == next, "A reused proxy port did not resolve the new client tuple");

    // Missing process evidence revokes even a cached client, and conflicts cannot be bypassed by proxy attribution.
    ProcessAccess::loss(processes, 1);
    ports.attribute(upstream, processes);
    require(!upstream.sourceOwner.pid && upstream.sourceOwner.ambiguous,
        "Lost process evidence left a cached proxy attribution authoritative");
    ports.add(upstream.source, client.source, client.destination, 2010000);
    ports.attribute(upstream, processes);
    require(!upstream.sourceOwner.pid && upstream.sourceOwner.ambiguous,
        "Proxy attribution overrode ambiguous socket evidence");

    // Persist a whole identity together; explicit uncertainty clears it, while a lookup without evidence preserves it.
    const auto folder = std::filesystem::temp_directory_path() / ("Cipherazzi-proxy-owners-" + std::to_string(nowUs()));
    const auto path = folder / "capture.db";
    {
        HttpSpyStore store(path, "owners", "test", 0, 0, {});
        HttpExchange exchange;
        exchange.flowId = 1;
        exchange.startedUs = nowUs();
        exchange.method = "GET";
        exchange.state = "complete";
        exchange.responseBody = {'k', 'e', 'p', 't'};
        exchange.responseBytes = 4;
        exchange.clientOwner = owner;
        exchange.serverOwner = owner;
        std::vector<HttpExchange> batch{exchange};
        store.commit(batch, false);
        sqlite3* database = nullptr;
        require(sqlite3_open_v2(utf8(path.wstring()).c_str(), &database, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Could not inspect the decoded owner fixture");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> reader(database, sqlite3_close);
        exchange.clientOwner = {};
        batch.push_back(exchange);
        store.commit(batch, false);
        require(scalar(database, "SELECT count(*) FROM exchanges WHERE client_process='client.exe'") == 1,
            "An empty decoded ownership lookup erased an established identity");
        exchange.ownersOnly = true;
        exchange.responseBody.clear();
        exchange.responseBytes = 0;
        exchange.state.clear();
        exchange.clientOwner = {.pid=owner.pid + 1};
        batch.push_back(exchange);
        store.commit(batch, false);
        require(scalar(database, "SELECT count(*) FROM exchanges WHERE client_process='' AND client_path=''") == 1,
            "A changed decoded PID retained fields from another process");
        require(scalar(database, "SELECT count(*) FROM exchanges WHERE hex(response_body)='6B657074' "
            "AND response_bytes=4 AND state='complete'") == 1, "An ownership update replaced message content");
        exchange.clientOwner = exchange.serverOwner = {.ambiguous=true};
        batch.push_back(exchange);
        store.commit(batch, true);
        require(scalar(database, "SELECT count(*) FROM exchanges WHERE client_pid IS NULL AND server_pid IS NULL "
            "AND client_process='' AND client_path='' AND client_account='' AND server_process=''") == 1,
            "The decoded store retained explicitly revoked process attribution");
        exchange.sequence = 99;
        batch.push_back(exchange);
        store.commit(batch, true);
        require(scalar(database, "SELECT count(*) FROM exchanges") == 1,
            "An ownership update recreated a missing message");
    }

    // Buffered lifetime events arrive after a short-lived client has already sent its request and exited.
    {
        std::atomic<int> evidence{};
        HttpExchange exchange;
        exchange.flowId = 2;
        exchange.sequence = 3;
        exchange.flowStartedUs = nowUs();
        exchange.startedUs = exchange.flowStartedUs + 1;
        exchange.endedUs = exchange.startedUs + 100;
        exchange.method = "GET";
        exchange.state = "complete";
        exchange.responseBody = {'k', 'e', 'p', 't'};
        exchange.responseBytes = 4;
        const auto decoded = folder / "delayed" / "capture.db";
        Storage storage(folder / "journal.db", counters, "test", "delayed", [&](Observation& row)
        {
            require(row.firstUs == exchange.flowStartedUs && row.lastUs == exchange.startedUs,
                "Decoded attribution included response processing after the client could have exited");
            row.sourceOwner = evidence == 1 ? owner : Owner{.ambiguous=true};
        }, {}, true, {}, {.path=decoded});
        storage.enqueue(exchange);
        sqlite3* database = nullptr;
        require(sqlite3_open_v2(utf8(decoded.wstring()).c_str(), &database, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Could not inspect delayed decoded attribution");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> reader(database, sqlite3_close);
        for (int attempt = 0; attempt < 50 && scalar(database, "SELECT count(*) FROM exchanges") == 0; ++attempt)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        require(scalar(database, "SELECT count(*) FROM exchanges WHERE client_pid IS NULL") == 1,
            "An exchange without lifetime evidence was not published as unattributed");
        evidence = 1;
        for (int attempt = 0; attempt < 40 && scalar(database,
            "SELECT count(*) FROM exchanges WHERE client_process='client.exe'") == 0; ++attempt)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        require(scalar(database, "SELECT count(*) FROM exchanges WHERE client_process='client.exe'") == 1,
            "Late lifetime evidence did not refine an already-published HTTP exchange");
        evidence = 2;
        for (int attempt = 0; attempt < 30 && scalar(database,
            "SELECT count(*) FROM exchanges WHERE client_pid IS NULL") == 0; ++attempt)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        require(scalar(database, "SELECT count(*) FROM exchanges WHERE client_pid IS NULL AND client_process='' "
            "AND hex(response_body)='6B657074' AND response_bytes=4 AND state='complete' AND sequence=3") == 1,
            "Late ambiguity failed to revoke ownership without changing the message body");
        storage.finish();
    }
    std::filesystem::remove_all(folder);
}

void processLifetimeCoverage()
{
    Counters counters;
    Processes processes(counters);
    constexpr uint32_t pid = 0xfffe0001;
    for (const bool ipv6 : {false, true})
    {
        Observation row;
        row.source.family = row.destination.family = ipv6 ? 6 : 4;
        row.source.address = ipv6 ? std::array<uint8_t, 16>{0x20, 1, 0xdb, 8, 1} :
            std::array<uint8_t, 16>{192, 0, 2, 1};
        row.destination.address = ipv6 ? std::array<uint8_t, 16>{0x20, 1, 0xdb, 8, 2} :
            std::array<uint8_t, 16>{192, 0, 2, 2};
        row.source.port = 45000;
        row.destination.port = 443;
        row.firstUs = 2020000;
        row.lastUs = 2030000;
        Owner old{pid, 1000000, "old.exe", "C:/old.exe", "test", "old-user", "LAB", "old-sid"};
        Owner newer{pid + 1, 2040000, "new.exe", "C:/new.exe", "test", "new-user", "LAB", "new-sid"};

        // Delayed and reversed delivery must preserve both sides and the actual timestamp boundaries.
        for (const bool missingIds : {false, true})
        {
            std::array<int, 3> order{0, 1, 2};
            do
            {
                ProcessAccess::reset(processes);
                ProcessAccess::remember(processes, old, 2040000);
                ProcessAccess::remember(processes, newer, 10000000);
                for (const auto step : order)
                {
                    if (step == 0) ProcessAccess::event(processes, row, old.pid, missingIds ? 0 : 10, 2000000, false);
                    if (step == 1) ProcessAccess::event(processes, row, old.pid, missingIds ? 0 : 10, 2035000, true);
                    if (step == 2) ProcessAccess::event(processes, row, newer.pid, missingIds ? 0 : 20, 2050000, false);
                }
                ProcessAccess::event(processes, row, old.pid, missingIds ? 0 : 30, 2000000, false, true);
                processes.enrich(row);
                require(row.sourceOwner.name == "old.exe" && row.destinationOwner.name == "old.exe",
                    "A future socket replaced historical ownership or lost the other endpoint");
                auto next = row;
                next.firstUs = 2060000;
                next.lastUs = 2070000;
                processes.enrich(next);
                require(next.sourceOwner.name == "new.exe" && !next.destinationOwner.pid,
                    "A delayed close or an expired process lifetime corrupted the newer socket");
            } while (std::next_permutation(order.begin(), order.end()));
        }

        // Zero IDs need unique chronological lifetimes, including reuse within the same process.
        for (const bool server : {false, true})
        {
            std::array<int, 3> order{0, 1, 2};
            do
            {
                ProcessAccess::reset(processes);
                ProcessAccess::remember(processes, old, 10000000);
                for (const auto step : order)
                {
                    if (step == 0) ProcessAccess::event(processes, row, pid, 0, 2000000, false, server);
                    if (step == 1) ProcessAccess::event(processes, row, pid, 0, 2035000, true, server);
                    if (step == 2) ProcessAccess::event(processes, row, pid, 0, 2050000, false, server);
                }
                auto next = row;
                next.firstUs = 2060000;
                next.lastUs = 2070000;
                processes.enrich(next);
                const auto& owner = server ? next.destinationOwner : next.sourceOwner;
                require(owner.pid == pid && owner.startedUs == old.startedUs && owner.accountSid == old.accountSid,
                    "Zero socket IDs lost a unique process identity after tuple reuse");
                next.firstUs = row.firstUs;
                processes.enrich(next);
                require(!owner.pid && owner.ambiguous, "Zero socket IDs attributed an interval spanning reuse");
            } while (std::next_permutation(order.begin(), order.end()));

            // An unidentified close cannot end multiple opens or choose between known and unknown sockets.
            for (const uint32_t firstId : {0u, 10u})
            {
                ProcessAccess::reset(processes);
                ProcessAccess::remember(processes, old, 10000000);
                ProcessAccess::event(processes, row, pid, firstId, 2000000, false, server);
                ProcessAccess::event(processes, row, pid, 0, 2025000, false, server);
                ProcessAccess::event(processes, row, pid, 0, 2035000, true, server);
                ProcessAccess::event(processes, row, pid, 20, 2050000, false, server);
                auto next = row;
                next.firstUs = 2060000;
                next.lastUs = 2070000;
                processes.enrich(next);
                const auto& owner = server ? next.destinationOwner : next.sourceOwner;
                require(!owner.pid && owner.ambiguous,
                    "An ambiguous zero-ID close manufactured a unique later socket");
            }

            // A known close must not consume a zero-ID open when its identified open has been evicted.
            ProcessAccess::reset(processes);
            ProcessAccess::remember(processes, old, 10000000);
            ProcessAccess::event(processes, row, pid, 10, 2000000, false, server);
            ProcessAccess::event(processes, row, pid, 0, 2025000, false, server);
            ProcessAccess::event(processes, row, pid, 10, 2035000, true, server);
            ProcessAccess::event(processes, row, pid, 20, 2050000, false, server);
            for (uint32_t socket = 100; socket < 113; ++socket)
                ProcessAccess::event(processes, row, pid, socket, 3000000 + socket, false, !server);
            auto next = row;
            next.firstUs = 2060000;
            next.lastUs = 2070000;
            processes.enrich(next);
            const auto& owner = server ? next.destinationOwner : next.sourceOwner;
            require(!owner.pid && owner.ambiguous,
                "An identified close ended another socket after its open was discarded");
        }

        // An unclosed older socket makes reuse ambiguous until its delayed close is delivered.
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, old, 2040000);
        ProcessAccess::remember(processes, newer, 10000000);
        ProcessAccess::event(processes, row, old.pid, 10, 2000000, false);
        ProcessAccess::event(processes, row, newer.pid, 20, 2050000, false);
        auto next = row;
        next.firstUs = 2060000;
        next.lastUs = 2070000;
        processes.enrich(next);
        require(!next.sourceOwner.pid && next.sourceOwner.ambiguous && next.sourceOwner.name.empty(),
            "Overlapping socket lifetimes retained an attribution");
        ProcessAccess::event(processes, row, old.pid, 10, 2035000, true);
        processes.enrich(next);
        require(next.sourceOwner.name == "new.exe", "A resolved socket ambiguity did not recover ownership");
        auto crossing = row;
        crossing.lastUs = 2070000;
        processes.enrich(crossing);
        require(!crossing.sourceOwner.pid && crossing.sourceOwner.ambiguous,
            "An observation spanning two socket lifetimes was attributed");

        // Activity on the peer must not erase a close that disproves ownership of an older observation.
        for (const bool closeRemoved : {false, true})
        {
            ProcessAccess::reset(processes);
            auto reused = newer;
            reused.startedUs = 1100000;
            ProcessAccess::remember(processes, old, 10000000);
            ProcessAccess::remember(processes, reused, 10000000);
            ProcessAccess::event(processes, row, old.pid, 10, 2000000, false);
            ProcessAccess::event(processes, row, old.pid, 10, 2035000, true);
            ProcessAccess::event(processes, row, reused.pid, 20, closeRemoved ? 2050000 : 2025000, false);
            for (uint32_t socket = 100; socket < (closeRemoved ? 115u : 114u); ++socket)
                ProcessAccess::event(processes, row, old.pid, socket, 3000000 + socket, false, true);
            auto historical = row;
            historical.lastUs = closeRemoved ? 2070000 : row.lastUs;
            processes.enrich(historical);
            require(!historical.sourceOwner.pid && historical.sourceOwner.ambiguous,
                "Evicting a socket lifetime attributed an observation spanning port reuse");
            processes.enrich(next);
            require(next.sourceOwner.name == reused.name,
                "Discarded socket history prevented attribution after its uncertainty interval");
        }

        // A close with the older socket ID must not terminate a newer socket even with the same PID.
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, old, 10000000);
        ProcessAccess::event(processes, row, pid, 10, 2000000, false);
        ProcessAccess::event(processes, row, pid, 20, 2050000, false);
        ProcessAccess::event(processes, row, pid, 10, 2080000, true);
        next.firstUs = 2090000;
        next.lastUs = 2100000;
        processes.enrich(next);
        require(next.sourceOwner.name == "old.exe", "An older socket ID closed a newer connection");

        // Process instance identity survives reverse lifecycle delivery and never spans PID recycling.
        newer.pid = pid;
        for (const bool missingIds : {false, true})
        {
            ProcessAccess::reset(processes);
            ProcessAccess::remember(processes, newer, 10000000);
            ProcessAccess::remember(processes, old, 2035000);
            ProcessAccess::event(processes, row, pid, missingIds ? 0 : 10, 2000000, false);
            ProcessAccess::event(processes, row, pid, missingIds ? 0 : 20, 2050000, false);
            ProcessAccess::event(processes, row, pid, missingIds ? 0 : 10, 2035000, true);
            processes.enrich(row);
            next.firstUs = 2060000;
            next.lastUs = 2070000;
            processes.enrich(next);
            require(row.sourceOwner.name == "old.exe" && next.sourceOwner.name == "new.exe",
                "PID reuse mixed process names across socket lifetimes");
            require(ProcessAccess::lookup(processes, pid, 2030000, 2060000).ambiguous,
                "A process association crossed a PID lifetime boundary");
        }

        // A later process start disproves the older identity even before its lifetime is verified again.
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, old, 10000000);
        ProcessAccess::remember(processes, newer, 0);
        require(ProcessAccess::lookup(processes, pid, 2060000, 2070000).ambiguous,
            "A recycled PID retained its older identity while the new process awaited verification");
        ProcessAccess::event(processes, row, pid, 10, 2000000, false);
        ProcessAccess::event(processes, row, pid, 20, 2050000, false);
        ProcessAccess::event(processes, row, pid, 10, 2035000, true);
        processes.enrich(next);
        require(!next.sourceOwner.pid && next.sourceOwner.ambiguous,
            "A delayed socket close restored an older instance of a recycled PID");
        ProcessAccess::remember(processes, old, 2035000);
        ProcessAccess::remember(processes, newer, 10000000);
        processes.enrich(next);
        require(next.sourceOwner.startedUs == newer.startedUs && next.sourceOwner.name == newer.name,
            "A resolved process and socket lifetime ambiguity did not recover ownership");

        // Competing process lifetimes cannot be resolved by delivery order even when one covers the interval.
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, old, 10000000);
        ProcessAccess::remember(processes, newer, 10000000);
        require(ProcessAccess::lookup(processes, pid, 2060000, 2070000).ambiguous,
            "Overlapping process lifetimes selected an arbitrary identity");

        // Recycling the PID again must not make an evicted, overlapping process lifetime disappear.
        for (int generation = 0; generation < 3; ++generation)
        {
            auto future = newer;
            future.startedUs = 3000000 + generation * 1000000;
            ProcessAccess::remember(processes, future, future.startedUs + 100000);
        }
        require(ProcessAccess::lookup(processes, pid, 2060000, 2070000).ambiguous,
            "Evicting a process lifetime manufactured a unique PID association");
        auto settled = newer;
        settled.startedUs = 10000001;
        ProcessAccess::remember(processes, settled, 20000000);
        require(ProcessAccess::lookup(processes, pid, 11000000, 11001000).startedUs == settled.startedUs,
            "Discarded PID history prevented attribution after its uncertainty interval");

        // A connect can follow the SYN, but an intervening close proves the observation spans reused sockets.
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, old, 10000000);
        ProcessAccess::event(processes, row, pid, 20, 2022000, false);
        processes.enrich(row);
        require(row.sourceOwner.pid == pid, "A connect after the SYN lost a consistent process lifetime");
        ProcessAccess::event(processes, row, pid, 10, 2021000, true);
        processes.enrich(row);
        require(!row.sourceOwner.pid && row.sourceOwner.ambiguous,
            "A close with a missing open hid reuse inside the observation");

        // A close without its open also contradicts an older socket after the close's timestamp.
        for (const bool server : {false, true})
        {
            ProcessAccess::reset(processes);
            ProcessAccess::remember(processes, old, 10000000);
            ProcessAccess::event(processes, row, pid, 10, 2000000, false, server);
            processes.enrich(next);
            const auto& initial = server ? next.destinationOwner : next.sourceOwner;
            require(initial.pid == pid, "The socket owner was not resolved before a delayed close");
            ProcessAccess::event(processes, row, pid + 1, 30, 2035000, true, server);
            processes.enrich(next);
            const auto& uncertain = server ? next.destinationOwner : next.sourceOwner;
            require(!uncertain.pid && uncertain.ambiguous && uncertain.name.empty(),
                "A close without its open left an older socket attributed after port reuse");

            // Once both earlier sockets have ended, a later open can establish a new unambiguous lifetime.
            ProcessAccess::event(processes, row, pid, 20, 2050000, false, server);
            ProcessAccess::event(processes, row, pid, 10, 2030000, true, server);
            processes.enrich(next);
            const auto& resolved = server ? next.destinationOwner : next.sourceOwner;
            require(resolved.pid == pid && !resolved.ambiguous,
                "An unmatched earlier close prevented attribution of a later socket");
        }

        // Missing socket IDs and evicted unresolved opens must never manufacture a unique match.
        for (const bool missingId : {false, true})
        {
            ProcessAccess::reset(processes);
            ProcessAccess::remember(processes, old, 10000000);
            ProcessAccess::event(processes, row, pid, missingId ? 0 : 1, 2000000, false);
            for (uint32_t socket = 2; socket < 16; ++socket)
            {
                ProcessAccess::event(processes, row, pid, socket, 2000000 + socket * 1000, false);
                ProcessAccess::event(processes, row, pid, socket, 2000500 + socket * 1000, true);
            }
            ProcessAccess::event(processes, row, pid, 16, 2050000, false);
            next.firstUs = 2060000;
            next.lastUs = 2070000;
            processes.enrich(next);
            require(!next.sourceOwner.pid && next.sourceOwner.ambiguous,
                "Incomplete socket history manufactured an unambiguous owner");
            ProcessAccess::bounded(processes, row, pid);
        }

        // Saturate both bounded histories with rapid reuse and closes delivered after the next open.
        ProcessAccess::reset(processes);
        auto oldest = row;
        for (int iteration = 0; iteration < 256; ++iteration)
        {
            const int64_t time = 20000000 + iteration * 2000;
            auto instance = old;
            instance.startedUs = time;
            instance.name = "process-" + std::to_string(iteration);
            ProcessAccess::remember(processes, instance, time + 1500);
            ProcessAccess::event(processes, row, pid, iteration + 1, time + 100, false);
            next.firstUs = time + 200;
            next.lastUs = time + 500;
            if (iteration)
            {
                processes.enrich(next);
                require(next.sourceOwner.ambiguous && !next.sourceOwner.pid,
                    "Rapid reuse accepted an outstanding socket ambiguity");
                ProcessAccess::event(processes, row, pid, iteration, time - 800, true);
            }
            else
                oldest = next;
            processes.enrich(next);
            require(next.sourceOwner.name == instance.name && next.sourceOwner.startedUs == time,
                "Rapid port/PID reuse selected another process instance");
            ProcessAccess::bounded(processes, row, pid);
        }
        processes.enrich(oldest);
        require(!oldest.sourceOwner.pid && oldest.sourceOwner.ambiguous,
            "Evicted history was attributed to a surviving process instance");
    }

    // A missed process-exit event cannot extend a cached identity over the current process instance.
    ProcessAccess::reset(processes);
    const auto current = Processes::describe(GetCurrentProcessId(), nowUs(), "test");
    auto stale = current;
    stale.startedUs -= 1000000;
    stale.name = "recycled.exe";
    ProcessAccess::remember(processes, stale, 0, current.startedUs - 500000);
    const auto resolved = ProcessAccess::lookup(processes, current.pid, current.startedUs + 1, nowUs());
    require(resolved.startedUs == current.startedUs && resolved.name == current.name,
        "An unclosed cached PID lifetime overrode the current process instance");
    require(ProcessAccess::lookup(processes, current.pid,
        current.startedUs - 400000, current.startedUs - 300000).ambiguous,
        "A cached process lifetime was extended beyond its last verification");

    // TCP and UDP table fallbacks require socket creation and reject contradictory identities.
    for (const bool udp : {false, true})
    {
        ProcessAccess::reset(processes);
        Observation row;
        row.udp = udp;
        row.source.port = 45000;
        row.destination.port = 443;
        row.firstUs = nowUs() - 200000;
        row.lastUs = row.firstUs + 1000;
        auto owner = current;
        owner.startedUs = row.firstUs - 1000000;
        ProcessAccess::snapshot(processes, row, owner, row.firstUs + 10000);
        processes.enrich(row);
        require(!row.sourceOwner.pid && row.sourceOwner.ambiguous,
            "A reused snapshot socket was attached to an earlier observation");
        ProcessAccess::snapshot(processes, row, owner, row.firstUs - 10000);
        processes.enrich(row);
        require(row.sourceOwner.pid == owner.pid, "A lifetime-valid table fallback was rejected");
        ++owner.pid;
        ProcessAccess::snapshot(processes, row, owner, row.firstUs - 10000, true);
        processes.enrich(row);
        require(!row.sourceOwner.pid && row.sourceOwner.ambiguous,
            "Conflicting table ownership was resolved by row order");

        // A unique table row cannot override competing or discarded PID lifetime evidence.
        owner.pid = current.pid;
        ProcessAccess::snapshot(processes, row, owner, row.firstUs - 10000);
        auto competing = owner;
        competing.startedUs -= 100000;
        ProcessAccess::remember(processes, competing, row.lastUs + 100000);
        for (int phase = 0; phase < 2; ++phase)
        {
            if (phase)
                for (int generation = 0; generation < 3; ++generation)
                {
                    auto future = owner;
                    future.startedUs = row.lastUs + 1000000 + generation * 100000;
                    ProcessAccess::remember(processes, future, future.startedUs + 50000);
                }
            processes.enrich(row);
            require(!row.sourceOwner.pid && row.sourceOwner.ambiguous,
                "A table fallback overrode ambiguous PID lifetime evidence");
        }
    }
}

void protocolOwnershipCoverage()
{
    // Interleaved connections keep their request pairing and upgrades through fragmentation and tuple reuse.
    for (const size_t segment : {size_t{1}, size_t{7}, SIZE_MAX})
    {
        Counters counters;
        std::map<uint64_t, Observation> observed;
        Engine engine(counters, [&](Observation row)
        {
            if (!row.lifecycleOnly)
                observed[row.flowId] = std::move(row);
        });
        uint32_t sequences[2][2]{{100, 900}, {100, 900}};
        int64_t timestamp = 1;
        auto bytes = [](std::string_view text)
        {
            return Bytes(reinterpret_cast<const uint8_t*>(text.data()), text.size());
        };
        auto send = [&](int flow, bool server, Bytes payload, uint8_t flags = 0x18)
        {
            TransportPacket packet;
            packet.source.address[0] = packet.destination.address[0] = 10;
            packet.source.address[3] = server ? 2 : 1;
            packet.destination.address[3] = server ? 1 : 2;
            packet.source.port = server ? 8080 : static_cast<uint16_t>(40000 + flow);
            packet.destination.port = server ? static_cast<uint16_t>(40000 + flow) : 8080;
            packet.flags = flags;
            size_t offset = 0;
            do
            {
                const auto size = std::min(segment, payload.size() - offset);
                packet.sequence = sequences[flow][server];
                packet.payload = payload.subspan(offset, size);
                engine.tcp(packet, timestamp++);
                sequences[flow][server] += static_cast<uint32_t>(size) + ((flags & 3) != 0);
                offset += size;
            } while (offset < payload.size());
        };
        auto connect = [&](int flow)
        {
            send(flow, false, {}, 2);
            send(flow, true, {}, 0x12);
        };
        connect(0);
        connect(1);
        send(0, false, bytes("CONNECT target.test:443 HTTP/1.1\r\n\r\n"));
        send(1, false, bytes("HEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n"));
        send(1, true, bytes("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"
            "HTTP/1.1 204 No Content\r\n\r\n"));
        const std::string_view response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        std::vector<uint8_t> tunnel(response.begin(), response.end());
        const auto serverHello = record(hello(false, 0x0304, false, false, {}), 22);
        tunnel.insert(tunnel.end(), serverHello.begin(), serverHello.end());
        send(0, true, tunnel);
        send(0, false, record(hello(true, 0x0304, false, false, {}), 22));
        require(observed.at(1).clientHello && observed.at(1).serverHello &&
            observed.at(1).application->fields.value("http_tunnel_established", false) &&
            observed.at(2).protocol == Observation::Protocol::Http && !observed.at(2).serverHello &&
            observed.at(2).application->fields["http_status_codes"].size() == 2,
            "Interleaved HTTP pairing or a tunnel transition leaked between connections");

        // One connection's terminal upgrade must not finish another connection or survive socket reuse.
        send(1, false, bytes("GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"));
        send(1, true, bytes("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
            "Upgrade: websocket\r\n\r\n"));
        send(1, false, bytes("\x81\x82xxxxxx"));
        connect(0);
        send(0, false, bytes("GET /fresh HTTP/1.1\r\nHost: fresh.test\r\n\r\n"));
        send(0, true, bytes("HTTP/1.1 204 No Content\r\n\r\n"));
        require(observed.at(3).protocol == Observation::Protocol::Http && !observed.at(3).serverHello &&
            !observed.at(3).application->fields.contains("http_tunnel_established") &&
            observed.at(3).application->fields["http_host"] == "fresh.test",
            "Reused sockets inherited an old connection's protocol state");
        engine.expire(timestamp, true);
        require(!counters.malformed && !counters.reassemblyLimit && !counters.activeFlows && !counters.bufferedBytes,
            "Protocol retirement leaked parser memory or reported a false failure");
    }
}

void ownershipCorrectionCoverage()
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("cipherazzi-correction-" + std::to_string(nowUs()));
    std::filesystem::create_directory(directory);
    Observation row;
    row.flowId = 1;
    row.firstUs = 2020000;
    row.lastUs = 2030000;
    row.clientHello = row.serverHello = true;
    row.version = 0x0304;
    row.cipher = 0x1301;
    row.source.address = {192, 0, 2, 1};
    row.destination.address = {192, 0, 2, 2};
    row.source.port = 45000;
    row.destination.port = 443;
    row.sourceOwner = {0xfffe0001, 1000000, "old.exe", "C:/old.exe", "test", "old-user", "LAB", "old-sid"};
    row.destinationOwner = {0xfffe0002, 1000000, "server.exe", "C:/server.exe", "test", "server", "LAB", "server-sid"};
    const char* cleared = "SELECT count(*) FROM connections WHERE source_pid IS NULL AND source_process='' "
        "AND source_path='' AND source_process_started_us IS NULL AND source_evidence='' AND source_account='' "
        "AND source_account_domain='' AND source_account_sid='' AND destination_process='server.exe'";

    // Delayed zero-ID events retain a table-proven identity, while actual evidence loss still revokes it.
    {
        Counters counters;
        Processes processes(counters);
        ProcessAccess::reset(processes);
        auto observed = row;
        observed.firstUs = nowUs() - 200000;
        observed.lastUs = observed.firstUs + 10000;
        auto owner = row.sourceOwner;
        owner.startedUs = observed.firstUs - 1000000;
        ProcessAccess::snapshot(processes, observed, owner, observed.firstUs - 10000);
        processes.enrich(observed);
        require(observed.sourceOwner.pid == owner.pid, "The initial table-proven identity was not resolved");
        const auto path = directory / "zero-id.db";
        JournalWriter journal(path, counters, "zero socket ID", "test", {.days=0, .bytes=0});
        sqlite3* reader = nullptr;
        require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not read zero-ID corrections");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(reader, sqlite3_close);
        JournalBatch batch;
        batch.observations = {observed};
        journal.commit(batch, "running", false, {});
        const auto owned = "SELECT count(*) FROM connections WHERE source_pid=" + std::to_string(owner.pid) +
            " AND source_process_started_us=" + std::to_string(owner.startedUs) +
            " AND source_process='old.exe' AND source_path='C:/old.exe' AND source_account='old-user' "
            "AND source_account_domain='LAB' AND source_account_sid='old-sid'";
        for (int phase = 0; phase < 3; ++phase)
        {
            if (phase == 0) ProcessAccess::event(processes, observed, owner.pid, 0, observed.firstUs - 10000, false);
            if (phase == 1) ProcessAccess::event(processes, observed, owner.pid, 0, observed.lastUs + 10000, true);
            if (phase == 2) ProcessAccess::loss(processes, 1);
            processes.recheck(observed);
            batch = {};
            batch.owners = {observed};
            journal.commit(batch, "running", false, {});
            require(scalar(reader, owned.c_str()) == (phase < 2 ? 1 : 0),
                "Zero-ID refinements lost a valid persisted identity or ignored actual evidence loss");
        }
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_pid IS NULL AND source_process='' "
            "AND source_path='' AND source_process_started_us IS NULL AND source_account='' "
            "AND source_account_domain='' AND source_account_sid=''") == 1,
            "Evidence loss left stale identity fields after zero-ID attribution");
    }

    // Both ordinary updates and delayed refinements replace an identity atomically, including explicit revocation.
    {
        Counters counters;
        const auto path = directory / "updates.db";
        JournalWriter journal(path, counters, "ownership correction", "test", {.days=0, .bytes=0});
        sqlite3* reader = nullptr;
        require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not read ownership corrections");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(reader, sqlite3_close);
        sqlite3_busy_timeout(reader, 2000);
        JournalBatch batch;
        batch.observations = {row};
        journal.commit(batch, "running", false, {});
        const auto revision = scalar(reader, "SELECT observation_revision FROM metadata");
        batch = {};
        auto corrected = row;
        corrected.sourceOwner.ambiguous = true;
        corrected.destinationOwner = {};
        batch.owners = {corrected};
        journal.commit(batch, "running", false, {});
        require(scalar(reader, cleared) == 1 &&
            scalar(reader, "SELECT observation_revision FROM metadata") > revision,
            "Ownership revocation did not clear every field, preserve the peer, and invalidate readers");
        const auto clearedRevision = scalar(reader, "SELECT observation_revision FROM metadata");
        journal.commit(batch, "running", false, {});
        require(scalar(reader, "SELECT observation_revision FROM metadata") == clearedRevision,
            "An unchanged ownership revocation invalidated observation views");

        // A changed PID must not inherit strings from the previous owner, even when its image is unavailable.
        batch.owners = {row};
        journal.commit(batch, "running", false, {});
        corrected = row;
        corrected.sourceOwner = {.pid=9999, .startedUs=1000001};
        corrected.destinationOwner = {};
        batch.owners = {corrected};
        journal.commit(batch, "running", false, {});
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_pid=9999 AND source_process='' "
            "AND source_path='' AND source_process_started_us=1000001 AND source_evidence='' "
            "AND source_account='' AND source_account_domain='' AND source_account_sid=''") == 1,
            "A replacement process inherited the previous identity's name or account");

        // An earlier hello's deferred result cannot restore an owner rejected by the complete observation.
        batch = {};
        auto complete = row;
        complete.lastUs += 1000;
        complete.sourceOwner.ambiguous = true;
        batch.observations = {complete};
        journal.commit(batch, "running", false, {});
        require(scalar(reader, cleared) == 1, "An ordinary observation update did not revoke ownership");
        const auto completeRevision = scalar(reader, "SELECT observation_revision FROM metadata");
        batch = {};
        batch.owners = {row};
        journal.commit(batch, "running", false, {});
        require(scalar(reader, cleared) == 1 &&
            scalar(reader, "SELECT observation_revision FROM metadata") == completeRevision,
            "A stale ownership refinement overwrote a later observation's correction");
        complete.sourceOwner = complete.destinationOwner = {};
        batch.owners = {complete};
        journal.commit(batch, "running", false, {});
        require(scalar(reader, cleared) == 1, "Missing evidence erased a valid peer identity");
        complete.sourceOwner.ambiguous = complete.destinationOwner.ambiguous = true;
        batch.owners = {complete};
        journal.commit(batch, "stopped", true, {});
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_pid IS NULL "
            "AND destination_pid IS NULL AND destination_process='' AND destination_path='' "
            "AND destination_process_started_us IS NULL AND destination_evidence='' AND destination_account='' "
            "AND destination_account_domain='' AND destination_account_sid=''") == 1,
            "Revoking both endpoints left a persisted owner");
    }

    // Late lifetime evidence revokes a published identity, and history eviction cannot restore it.
    {
        Counters counters;
        Processes processes(counters);
        ProcessAccess::reset(processes);
        auto reused = row.sourceOwner;
        reused.pid += 2;
        reused.startedUs = 1100000;
        reused.name = "reused.exe";
        ProcessAccess::remember(processes, row.sourceOwner, 10000000);
        ProcessAccess::remember(processes, reused, 10000000);
        ProcessAccess::event(processes, row, reused.pid, 20, 2050000, false);
        auto crossing = row;
        crossing.lastUs = 2070000;
        processes.enrich(crossing);
        require(crossing.sourceOwner.pid == reused.pid, "The provisional owner was not resolved");

        const auto path = directory / "history.db";
        JournalWriter journal(path, counters, "history correction", "test", {.days=0, .bytes=0});
        sqlite3* reader = nullptr;
        require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not read history corrections");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(reader, sqlite3_close);
        sqlite3_busy_timeout(reader, 2000);
        JournalBatch batch;
        batch.observations = {crossing};
        journal.commit(batch, "running", false, {});
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_process='reused.exe'") == 1,
            "The provisional owner was not persisted");
        const auto revision = scalar(reader, "SELECT observation_revision FROM metadata");

        ProcessAccess::event(processes, row, row.sourceOwner.pid, 10, 2000000, false);
        ProcessAccess::event(processes, row, row.sourceOwner.pid, 10, 2035000, true);
        batch = {};
        for (int phase = 0; phase < 2; ++phase)
        {
            if (phase)
                for (uint32_t socket = 100; socket < 115; ++socket)
                    ProcessAccess::event(processes, row, row.sourceOwner.pid, socket, 3000000 + socket, false, true);
            processes.enrich(crossing);
            batch.owners = {crossing};
            journal.commit(batch, "running", false, {});
            require(scalar(reader, "SELECT count(*) FROM connections WHERE source_pid IS NULL AND source_process='' "
                "AND source_path='' AND source_process_started_us IS NULL AND source_evidence='' "
                "AND source_account='' AND source_account_domain='' AND source_account_sid=''") == 1,
                "Discarded lifetime evidence restored a revoked persisted identity");
        }
        require(scalar(reader, "SELECT observation_revision FROM metadata") > revision,
            "A delayed lifetime correction did not invalidate observation views");
    }

    // Rejected process history still revokes published ownership when retained identities exhaust memory.
    {
        Counters counters;
        Processes processes(counters);
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, row.sourceOwner, 10000000);
        ProcessAccess::event(processes, row, row.sourceOwner.pid, 10, 2000000, false);
        auto corrected = row;
        processes.enrich(corrected);
        require(corrected.sourceOwner.pid == row.sourceOwner.pid, "The initial process owner was not resolved");

        const auto path = directory / "memory-capacity.db";
        JournalWriter journal(path, counters, "ownership capacity", "test", {.days=0, .bytes=0});
        sqlite3* reader = nullptr;
        require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not read capacity corrections");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(reader, sqlite3_close);
        JournalBatch batch;
        batch.observations = {row};
        journal.commit(batch, "running", false, {});
        const auto revision = scalar(reader, "SELECT observation_revision FROM metadata");

        // Keep real retained entries up to the production memory limit before delivering the competing lifetime.
        const auto lost = counters.processEventsLost.load();
        for (uint32_t index = 0; index < 1024; ++index)
        {
            auto busy = row.sourceOwner;
            busy.pid += index + 100;
            busy.path.assign(32768, 'x');
            ProcessAccess::remember(processes, std::move(busy), 10000000);
        }
        require(counters.processEventsLost > lost, "The process history capacity was not exhausted");
        auto reused = row.sourceOwner;
        reused.startedUs = row.firstUs - 1000;
        reused.name = "recycled.exe";
        reused.path.assign(32768, 'y');
        ProcessAccess::remember(processes, reused, 10000000);
        require(ProcessAccess::lookup(processes, row.sourceOwner.pid, 1900000, 1910000).pid == row.sourceOwner.pid,
            "Later rejected lifetime evidence erased an earlier unambiguous process identity");
        processes.enrich(corrected);
        batch = {};
        batch.owners = {corrected};
        journal.commit(batch, "stopped", true, {});
        require(corrected.sourceOwner.ambiguous && !corrected.sourceOwner.pid && scalar(reader, cleared) == 1 &&
            scalar(reader, "SELECT observation_revision FROM metadata") > revision,
            "Rejected process lifetime evidence preserved an incorrect persisted identity");
    }

    // Delayed closes revoke published ownership even when the corresponding open was never delivered.
    for (const std::string scenario :
        {"delayed", "missing-open", "late-close", "late-close-reversed", "late-pid", "late-loss"})
    {
        const bool missingOpen = scenario == "missing-open";
        const bool late = scenario.starts_with("late-");
        auto observed = row;
        if (scenario == "late-close-reversed")
            std::swap(observed.source, observed.destination);
        Counters counters;
        Processes processes(counters);
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, row.sourceOwner, 10000000);
        ProcessAccess::remember(processes, row.destinationOwner, 10000000);
        ProcessAccess::event(processes, observed, row.sourceOwner.pid, 10, 2000000, false);
        ProcessAccess::event(processes, observed, row.destinationOwner.pid, 20, 2000000, false, true);
        processes.changes();
        const auto path = directory / (scenario + ".db");
        std::atomic<unsigned> calls{};
        std::promise<void> refined;
        auto ready = refined.get_future();
        Storage storage(path, counters, "delayed close", "test", [&](Observation& observation)
        {
            processes.recheck(observation);
            if (++calls == (late ? 5u : 2u))
                refined.set_value();
        }, {.days=0, .bytes=0}, true, [&] { return processes.changes(); });
        storage.enqueue(observed);
        require(ready.wait_for(std::chrono::seconds(7)) == std::future_status::ready,
            "The deferred owner refinement did not finish");
        sqlite3* reader = nullptr;
        require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not read the delayed correction");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(reader, sqlite3_close);
        sqlite3_busy_timeout(reader, 2000);
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_process='old.exe'") == 1,
            "The initial owner was not published before correction");
        const auto revision = scalar(reader, "SELECT observation_revision FROM metadata");
        if (scenario == "late-close-reversed")
        {
            ProcessAccess::forgetSockets(processes);
            ProcessAccess::forgetProcess(processes, row.destinationOwner.pid);
        }
        if (scenario == "late-loss")
        {
            counters.processEventsLost += 100;
            ProcessAccess::loss(processes, 1);
            ProcessAccess::loss(processes, 1);
            require(counters.processEventsLost == 101,
                "ETW loss was hidden by another process loss counter or counted twice");
        }
        else if (scenario == "late-pid")
        {
            auto reused = row.sourceOwner;
            reused.startedUs = row.firstUs - 1000;
            reused.name = "recycled.exe";
            ProcessAccess::remember(processes, reused, 0);
        }
        else
            ProcessAccess::event(processes, observed, row.sourceOwner.pid + (missingOpen ? 1 : 0),
                missingOpen ? 30 : 10, row.firstUs - 1, true);
        const auto* corrected = scenario == "late-loss" ?
            "SELECT count(*) FROM connections WHERE source_pid IS NULL AND source_process='' AND source_path='' "
            "AND source_process_started_us IS NULL AND source_evidence='' AND source_account='' "
            "AND source_account_domain='' AND source_account_sid='' AND destination_pid IS NULL "
            "AND destination_process='' AND destination_path='' AND destination_process_started_us IS NULL "
            "AND destination_evidence='' AND destination_account='' AND destination_account_domain='' "
            "AND destination_account_sid=''" : cleared;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!scalar(reader, corrected) && std::chrono::steady_clock::now() < deadline)
        {
            storage.check();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        require(scalar(reader, corrected) == 1 &&
            scalar(reader, "SELECT observation_revision FROM metadata") > revision,
            "A successful initial refinement prevented delayed ownership revocation");
        storage.finish();
    }

    // Page both PID directions without duplicate loopback rows after deferred checks and socket history expire.
    {
        Counters counters;
        Processes processes(counters);
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, row.sourceOwner, 10000000);
        ProcessAccess::remember(processes, row.destinationOwner, 10000000);
        constexpr size_t count = 600;
        std::array<std::atomic<unsigned>, count> visits{};
        std::atomic<size_t> settled{};
        std::promise<void> refined;
        auto ready = refined.get_future();
        std::vector<Observation> observations;
        for (size_t index = 0; index < count; ++index)
        {
            auto current = row;
            current.flowId = index + 1;
            current.lastUs += index % 4;
            current.source.port = static_cast<uint16_t>(40000 + index);
            if (index % 2)
            {
                current.source.family = current.destination.family = 6;
                current.source.address = {0x20, 1, 0xdb, 8, 1};
                current.destination.address = {0x20, 1, 0xdb, 8, 2};
            }
            if (index % 3 == 1)
            {
                std::swap(current.source, current.destination);
                std::swap(current.sourceOwner, current.destinationOwner);
            }
            if (index % 3 == 2)
                current.destinationOwner = current.sourceOwner;
            ProcessAccess::event(processes, current, current.sourceOwner.pid, 10, 2000000, false);
            ProcessAccess::event(processes, current, current.destinationOwner.pid, 20, 2000000, false, true);
            observations.push_back(std::move(current));
        }
        processes.changes();
        const auto path = directory / "paged-pid.db";
        Storage storage(path, counters, "paged PID corrections", "test", [&](Observation& observation)
        {
            processes.recheck(observation);
            if (++visits.at(observation.flowId - 1) == 5 && ++settled == count)
                refined.set_value();
        }, {.days=0, .bytes=0}, true, [&] { return processes.changes(); });
        for (const auto& observation : observations)
            storage.enqueue(observation, true);
        require(ready.wait_for(std::chrono::seconds(10)) == std::future_status::ready,
            "The paged ownership observations did not finish deferred verification");
        sqlite3* reader = nullptr;
        require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not read paged ownership");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(reader, sqlite3_close);
        sqlite3_busy_timeout(reader, 2000);
        const auto owned = "SELECT count(*) FROM connections WHERE run_id='" + storage.runId() +
            "' AND (source_pid=" + std::to_string(row.sourceOwner.pid) +
            " OR destination_pid=" + std::to_string(row.sourceOwner.pid) + ")";
        require(scalar(reader, owned.c_str()) == count, "The paged ownership fixture was not published");

        // A large unrelated journal must not turn one PID correction into a full-table enrichment pass.
        {
            sqlite3_stmt* statement = nullptr;
            require(sqlite3_prepare_v2(reader, "PRAGMA table_info(connections)", -1, &statement, nullptr) == SQLITE_OK,
                "Could not read the ownership scale fixture schema");
            std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> columns(statement, sqlite3_finalize);
            std::vector<std::string> names;
            while (sqlite3_step(statement) == SQLITE_ROW)
            {
                const std::string name = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
                if (name != "id")
                    names.push_back(name);
            }
            std::map<std::string, std::string> replacements{
                {"flow_id", "c.flow_id+n+600"}, {"first_us", "c.last_us+n*2000"}, {"last_us", "c.last_us+n*2000+1000"}};
            for (const std::string side : {"source", "destination"})
            {
                replacements[side + "_pid"] = std::to_string(row.sourceOwner.pid + 7);
                replacements[side + "_process"] = "'unrelated.exe'";
                replacements[side + "_path"] = "'C:/unrelated.exe'";
                replacements[side + "_account"] = "'unrelated-user'";
                replacements[side + "_account_sid"] = "'unrelated-sid'";
            }
            std::string fields, selected;
            for (const auto& name : names)
            {
                if (!fields.empty()) { fields += ','; selected += ','; }
                fields += name;
                selected += replacements.contains(name) ? replacements.at(name) : "c." + name;
            }
            const auto sql = "WITH RECURSIVE copies(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM copies WHERE n<99400) "
                "INSERT INTO connections(" + fields + ") SELECT " + selected +
                " FROM (SELECT * FROM connections WHERE flow_id=1 LIMIT 1) c CROSS JOIN copies";
            require(sqlite3_exec(reader, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK &&
                scalar(reader, "SELECT count(*) FROM connections") == 100000,
                "Could not populate the large unrelated ownership journal");
        }

        // Another capture's records must not be rewritten using this capture's lifetime evidence.
        {
            JournalWriter other(path, counters, "other capture", "test", {.days=0, .bytes=0});
            JournalBatch batch;
            batch.observations = {row};
            other.commit(batch, "stopped", true, {});
        }
        ProcessAccess::forgetSockets(processes);
        ProcessAccess::forgetProcess(processes, row.destinationOwner.pid);
        auto reused = row.sourceOwner;
        reused.startedUs = row.firstUs - 1000;
        reused.name = "recycled.exe";
        const auto started = std::chrono::steady_clock::now();
        ProcessAccess::remember(processes, reused, 0);
        while (scalar(reader, owned.c_str()) && std::chrono::steady_clock::now() - started < std::chrono::seconds(5))
        {
            storage.check();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        require(!scalar(reader, owned.c_str()) && scalar(reader,
            "SELECT count(*) FROM connections WHERE source_process='server.exe' OR "
            "destination_process='server.exe'") == 401 &&
            scalar(reader, "SELECT count(*) FROM connections WHERE source_process='old.exe'") == 1,
            "Paged PID correction skipped a direction, lost a peer, or modified another capture");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_process='unrelated.exe' "
            "AND destination_process='unrelated.exe'") == 99400,
            "A narrow PID correction rewrote unrelated observations");
        storage.finish();
        std::cout << "Late PID correction: " << count << " of 100000 observations in " <<
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count() <<
            " ms\n";
    }

    // Dropping the notification set under saturation must revoke, rather than preserve, an incorrect identity.
    {
        Counters counters;
        Processes processes(counters);
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, row.sourceOwner, 10000000);
        ProcessAccess::remember(processes, row.destinationOwner, 10000000);
        ProcessAccess::event(processes, row, row.sourceOwner.pid, 10, 2000000, false);
        ProcessAccess::event(processes, row, row.destinationOwner.pid, 20, 2000000, false, true);
        processes.changes();
        std::promise<void> entered, release;
        auto ready = entered.get_future();
        const auto gate = release.get_future().share();
        std::atomic<unsigned> calls{};
        const auto path = directory / "notification-capacity.db";
        Storage storage(path, counters, "notification capacity", "test", [&](Observation& observation)
        {
            processes.recheck(observation);
            if (++calls == 2)
            {
                entered.set_value();
                gate.wait();
            }
        }, {.days=0, .bytes=0}, true, [&] { return processes.changes(); });
        auto unblock = [](std::promise<void>* value) { value->set_value(); };
        std::unique_ptr<std::promise<void>, decltype(unblock)> guard(&release, unblock);
        storage.enqueue(row);
        require(ready.wait_for(std::chrono::seconds(5)) == std::future_status::ready,
            "The notification capacity fixture did not reach deferred enrichment");
        for (uint16_t port = 30000; port < 38200; ++port)
        {
            auto busy = row;
            busy.source.port = port;
            ProcessAccess::event(processes, busy, row.sourceOwner.pid, port, 2000000, false);
        }
        ProcessAccess::event(processes, row, row.sourceOwner.pid, 10, row.firstUs - 1, true);
        guard.reset();
        storage.finish();
        sqlite3* reader = nullptr;
        require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not read saturated corrections");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(reader, sqlite3_close);
        require(counters.processEventsLost > 0 && scalar(reader, cleared) == 1,
            "Notification saturation retained an incorrect persisted owner or lost the valid peer");
    }

    // A full database correction backlog revokes ownership and safely rebuilds provable identities during drain.
    {
        Counters counters;
        Processes processes(counters);
        ProcessAccess::reset(processes);
        ProcessAccess::remember(processes, row.sourceOwner, 10000000);
        ProcessAccess::remember(processes, row.destinationOwner, 10000000);
        ProcessAccess::event(processes, row, row.sourceOwner.pid, 10, 2000000, false);
        ProcessAccess::event(processes, row, row.destinationOwner.pid, 20, 2000000, false, true);
        processes.changes();
        std::atomic<bool> pause{};
        std::promise<void> entered, firstRelease, drained, secondRelease;
        auto paused = entered.get_future(), copied = drained.get_future();
        const auto firstGate = firstRelease.get_future().share(), secondGate = secondRelease.get_future().share();
        const auto path = directory / "correction-capacity.db";
        Storage storage(path, counters, "correction capacity", "test",
            [&](Observation& observation) { processes.recheck(observation); }, {.days=0, .bytes=0}, true, [&]
        {
            if (pause.exchange(false))
            {
                entered.set_value();
                firstGate.wait();
            }
            auto changes = processes.changes();
            if (changes.size() == 4096)
            {
                drained.set_value();
                secondGate.wait();
            }
            return changes;
        });
        auto unblock = [](std::promise<void>* value) { value->set_value(); };
        std::unique_ptr<std::promise<void>, decltype(unblock)> firstGuard(&firstRelease, unblock);
        std::unique_ptr<std::promise<void>, decltype(unblock)> secondGuard(&secondRelease, unblock);
        storage.enqueue(row);
        sqlite3* reader = nullptr;
        require(sqlite3_open(path.string().c_str(), &reader) == SQLITE_OK, "Could not read correction capacity");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(reader, sqlite3_close);
        sqlite3_busy_timeout(reader, 2000);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!scalar(reader, "SELECT count(*) FROM connections") && std::chrono::steady_clock::now() < deadline)
        {
            storage.check();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        require(scalar(reader, "SELECT count(*) FROM connections WHERE source_process='old.exe'") == 1,
            "The correction capacity fixture was not initially attributed");
        pause = true;
        require(paused.wait_for(std::chrono::seconds(3)) == std::future_status::ready,
            "The correction reader did not pause before consuming notifications");
        for (uint16_t port = 10000; port < 14096; ++port)
        {
            auto busy = row;
            busy.source.port = port;
            ProcessAccess::event(processes, busy, row.sourceOwner.pid, port, 2000000, false);
        }
        firstGuard.reset();
        require(copied.wait_for(std::chrono::seconds(3)) == std::future_status::ready,
            "The correction reader did not receive its first complete batch");
        for (uint16_t port = 25000; port < 33191; ++port)
        {
            auto busy = row;
            busy.source.port = port;
            ProcessAccess::event(processes, busy, row.sourceOwner.pid, port, 2000000, false);
        }
        ProcessAccess::event(processes, row, row.sourceOwner.pid, 10, row.firstUs - 1, true);
        require(!counters.processEventsLost, "The notification fixture lost evidence before database saturation");
        secondGuard.reset();
        storage.finish();
        require(counters.processEventsLost > 0 && scalar(reader, cleared) == 1,
            "Correction backlog saturation retained an incorrect owner or skipped recovery during shutdown");
    }
    std::filesystem::remove_all(directory);
}

void storageOwnershipCoverage()
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("cipherazzi-ownership-" + std::to_string(nowUs()));
    std::filesystem::create_directory(directory);
    auto observation = [](uint64_t id)
    {
        Observation row;
        row.flowId = id;
        row.firstUs = row.lastUs = nowUs();
        row.clientHello = row.serverHello = true;
        row.version = 0x0304;
        row.cipher = 0x1301;
        row.source.port = static_cast<uint16_t>(40000 + id);
        row.destination.port = 443;
        return row;
    };

    // Drain more than one batch of each work type, including coalesced closes and delayed owner refinements.
    const auto drainedPath = directory / "drained.db";
    {
        Counters counters;
        std::promise<void> entered, release;
        auto ready = entered.get_future();
        const auto gate = release.get_future().share();
        std::map<uint64_t, unsigned> visits;
        Storage storage(drainedPath, counters, "drain", "test", [&](Observation& row)
        {
            const auto visit = ++visits[row.flowId];
            if (row.flowId == 1 && visit == 1)
            {
                entered.set_value();
                gate.wait();
            }
            if (visit > 1)
            {
                row.sourceOwner.pid = 1234;
                row.sourceOwner.name = "late-owner";
            }
        }, {.days=0, .bytes=0});
        auto unblock = [](std::promise<void>* promise) { promise->set_value(); };
        std::unique_ptr<std::promise<void>, decltype(unblock)> guard(&release, unblock);
        storage.enqueue(observation(1));
        require(ready.wait_for(std::chrono::seconds(3)) == std::future_status::ready,
            "The enrichment worker did not start");
        constexpr int count = 600;
        for (int id = 1; id <= count; ++id)
        {
            if (id > 1)
                storage.enqueue(observation(id));
            Observation closed;
            closed.flowId = id;
            closed.lifecycleOnly = true;
            closed.endedUs = nowUs();
            closed.closeReason = "closed";
            storage.enqueue(std::move(closed));
            EndpointEvent event;
            event.id = std::to_string(id);
            event.timestampUs = nowUs();
            event.detail = "{}";
            storage.enqueue(std::move(event));
        }
        auto finish = std::async(std::launch::async, [&] { storage.finish("complete"); });
        guard.reset();
        storage.finish("complete");
        finish.get();
        storage.enqueue(observation(count + 1));
        storage.enqueue(EndpointEvent{});
        require(counters.storageLost == 1 && counters.telemetryLost == 1 && !counters.processEventsLost,
            "Closed admission accepted new work or lost accepted work during drain");
        sqlite3* database = nullptr;
        require(sqlite3_open(drainedPath.string().c_str(), &database) == SQLITE_OK, "Could not read drained history");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(database, sqlite3_close);
        require(scalar(database, "SELECT count(*) FROM connections WHERE ended_us IS NOT NULL "
            "AND close_reason='closed' AND source_process='late-owner'") == count &&
            scalar(database, "SELECT count(*) FROM endpoint_events") == count &&
            scalar(database, "SELECT count(*) FROM capture_sessions WHERE stopped_us IS NOT NULL "
                "AND status='complete'") == 1 &&
            scalar(database, "SELECT count(*) FROM pragma_foreign_key_check") == 0,
            "Drain lost a close, owner refinement, endpoint event, or final session state");
    }

    // A worker failure wakes producers waiting on both queues and publishes no partial batch.
    const auto failedPath = directory / "failed.db";
    {
        Counters counters;
        std::promise<void> entered, release;
        auto ready = entered.get_future();
        const auto gate = release.get_future().share();
        Storage storage(failedPath, counters, "failure", "test", [&](Observation&)
        {
            entered.set_value();
            gate.wait();
        }, {.days=0, .bytes=0});
        auto unblock = [](std::promise<void>* promise) { promise->set_value(); };
        std::unique_ptr<std::promise<void>, decltype(unblock)> guard(&release, unblock);
        sqlite3* database = nullptr;
        require(sqlite3_open(failedPath.string().c_str(), &database) == SQLITE_OK, "Could not open failing history");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(database, sqlite3_close);
        require(sqlite3_exec(database, "CREATE TRIGGER fail_health BEFORE UPDATE ON capture_sessions "
            "BEGIN SELECT RAISE(ABORT,'Injected write failure'); END", nullptr, nullptr, nullptr) == SQLITE_OK,
            "Could not inject a failure after the batch writes");
        const auto revision = scalar(database, "SELECT revision FROM metadata");
        storage.enqueue(observation(1));
        require(ready.wait_for(std::chrono::seconds(3)) == std::future_status::ready,
            "The failing enrichment worker did not start");
        for (int id = 2; id < 8194; ++id)
        {
            storage.enqueue(observation(id));
            EndpointEvent event;
            event.id = std::to_string(id);
            event.detail = "{}";
            storage.enqueue(std::move(event));
        }
        auto blockedObservation = std::async(std::launch::async, [&]
        {
            try { storage.enqueue(observation(8194), true); }
            catch (const std::exception&) { return true; }
            return false;
        });
        auto blockedEndpoint = std::async(std::launch::async, [&] { storage.enqueue(EndpointEvent{}, true); });
        const bool blocked =
            blockedObservation.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout &&
            blockedEndpoint.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout;
        guard.reset();
        const bool woke = blockedObservation.wait_for(std::chrono::seconds(3)) == std::future_status::ready &&
            blockedEndpoint.wait_for(std::chrono::seconds(3)) == std::future_status::ready;
        bool failed = false;
        try { storage.finish(); }
        catch (const std::exception&) { failed = true; }
        const bool propagated = blockedObservation.get();
        blockedEndpoint.get();
        require(blocked && woke && failed && propagated && counters.telemetryLost == 1,
            "Worker failure did not release blocked producers and propagate the error");
        require(scalar(database, "SELECT revision FROM metadata") == revision &&
            scalar(database, "SELECT count(*) FROM connections") == 0 &&
            scalar(database, "SELECT count(*) FROM endpoint_events") == 0,
            "Worker failure committed a partial batch");
    }
    std::filesystem::remove_all(directory);
}
}
