#include "Engine.h"
#include "Storage.h"
#include <sqlite3.h>
#include <future>
#include <map>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);
int scalar(sqlite3* database, const char* sql);
std::vector<uint8_t> hello(bool client, uint16_t version, bool retry, bool ech, Bytes extensions);
std::vector<uint8_t> record(Bytes payload, uint8_t type);

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
