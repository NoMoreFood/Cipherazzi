#include "Capture.h"
#include "HttpSpy.h"
#include "KeyLog.h"
#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);

// Exercise append boundaries and file replacement without depending on an application's flush schedule.
void liveKeyLogCoverage(const std::filesystem::path& capture = {}, const std::filesystem::path& secrets = {})
{
    const auto directory = std::filesystem::temp_directory_path() /
        (L"Cipherazzi-KeyLog-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    std::filesystem::create_directory(directory);
    const auto file = directory / "keys.log";
    KeyLog keys;
    keys.tail(file);
    const auto random = std::string(64, '1'), secret = std::string(96, '2');
    const auto line = "CLIENT_RANDOM " + random + " " + secret;
    {
        std::ofstream output(file, std::ios::binary);
        output << line.substr(0, 50);
    }
    keys.tail(file);
    require(keys.count() == 0, "A partially flushed TLS key was ingested");
    {
        std::ofstream output(file, std::ios::binary | std::ios::app);
        output << line.substr(50) << "\r\n" << std::string(5000, 'x') << '\n';
        output << "CLIENT_RANDOM " << std::string(64, '3') << " " << secret << '\n';
    }
    keys.tail(file);
    require(keys.count() == 2, "An appended key or a line after an oversized line was lost");
    keys.tail(file);
    require(keys.count() == 2, "Unchanged key log content was ingested twice");
    {
        const auto locked = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        require(locked != INVALID_HANDLE_VALUE, "Could not lock the test key log for a writer");
        std::unique_ptr<void, decltype(&CloseHandle)> writer(locked, CloseHandle);
        keys.tail(file);
        require(keys.count() == 2, "A busy key log changed the captured secrets");
    }
    {
        std::ofstream output(file, std::ios::binary | std::ios::trunc);
        output << line << '\n';
    }
    keys.tail(file);
    require(keys.count() == 3, "A truncated key log was not reread");
    std::filesystem::rename(file, directory / "retired.log");
    {
        std::ofstream output(file, std::ios::binary);
        output << line << '\n';
    }
    keys.tail(file);
    require(keys.count() == 4, "A replaced key log was not reread");
    keys.ingest(line + "F");
    require(keys.count() == 4, "An odd-length TLS secret was accepted");

    if (!capture.empty())
    {
        // Replay the real TLS fixture without its final drain, then provide keys after every TCP close.
        KeyLog late;
        HttpSpy spy({.secretWaitUs=5000000}, late);
        std::map<std::pair<uint64_t, uint32_t>, HttpExchange> decoded;
        spy.sink([&](HttpExchange exchange)
        {
            decoded[{exchange.flowId, exchange.sequence}] = std::move(exchange);
        });
        Counters counters;
        Engine engine(counters, [](Observation) {});
        engine.httpSpy(&spy);
        std::ifstream input(capture, std::ios::binary);
        std::array<uint32_t, 6> header{};
        require(bool(input.read(reinterpret_cast<char*>(header.data()), sizeof(header))) &&
            header[0] == 0xa1b2c3d4 && header[5] == 101, "Expected the generated raw-IP PCAP fixture");
        int64_t lastUs{};
        std::vector<std::pair<int64_t, std::vector<uint8_t>>> packets;
        std::array<uint32_t, 4> record{};
        while (input.read(reinterpret_cast<char*>(record.data()), sizeof(record)))
        {
            require(record[2] <= 65536, "Oversized test packet");
            std::vector<uint8_t> bytes(record[2]);
            require(bool(input.read(reinterpret_cast<char*>(bytes.data()), bytes.size())), "Truncated test packet");
            lastUs = int64_t(record[0]) * 1000000 + record[1];
            engine.packet(bytes, PacketKind::Ip, lastUs);
            packets.emplace_back(lastUs, std::move(bytes));
        }
        require(spy.decoded == 0, "TLS traffic decoded without the fixture's secrets");
        late.tail(secrets);
        engine.expire(lastUs + 1000000);
        require(spy.decoded == 9 && spy.withoutSecrets == 0,
            "Late keys did not decrypt closed TLS 1.2/1.3 and HTTP/2 connections");
        engine.expire(lastUs + 6000000);
        require(spy.withoutSecrets == 1, "A connection without secrets did not expire after the bounded wait");

        KeyLog ready;
        ready.load(secrets);
        HttpSpy baseline({}, ready);
        std::map<std::pair<uint64_t, uint32_t>, HttpExchange> expected;
        baseline.sink([&](HttpExchange exchange)
        {
            expected[{exchange.flowId, exchange.sequence}] = std::move(exchange);
        });
        Counters original;
        Engine reference(original, [](Observation) {});
        reference.httpSpy(&baseline);
        std::atomic<bool> stopped{};
        replayPcap(capture, reference, stopped);
        require(expected.size() == decoded.size(), "Deferred decryption lost HTTP exchanges");
        for (const auto& [key, exchange] : expected)
        {
            const auto& actual = decoded.at(key);
            require(actual.state == exchange.state && actual.target == exchange.target &&
                actual.requestBody == exchange.requestBody && actual.responseBody == exchange.responseBody,
                "Deferred decryption changed an HTTP exchange");
            if (actual.startedUs != exchange.startedUs || actual.requestEndUs != exchange.requestEndUs ||
                actual.responseStartUs != exchange.responseStartUs || actual.endedUs != exchange.endedUs)
                throw std::runtime_error("Deferred timing mismatch for " + exchange.target + ": " +
                    std::to_string(actual.startedUs - exchange.startedUs) + "/" +
                    std::to_string(actual.requestEndUs - exchange.requestEndUs) + "/" +
                    std::to_string(actual.responseStartUs - exchange.responseStartUs) + "/" +
                    std::to_string(actual.endedUs - exchange.endedUs));
        }

        // Waiting records refresh secrets before more packets consume their small ciphertext budget.
        KeyLog growing;
        HttpSpy burst({.queueBytes=4096, .secretWaitUs=5000000}, growing, [&] { growing.tail(secrets); });
        Counters burstCounters;
        Engine burstEngine(burstCounters, [](Observation) {});
        burstEngine.httpSpy(&burst);
        for (const auto& [time, bytes] : packets)
            burstEngine.packet(bytes, PacketKind::Ip, time);
        burstEngine.expire(lastUs + 6000000);
        require(growing.count() > 0 && burst.decoded == 9 && burst.withoutSecrets == 1,
            "The live key log was not refreshed before queued ciphertext exhausted its budget");
    }
    std::filesystem::remove_all(directory);
}
}
