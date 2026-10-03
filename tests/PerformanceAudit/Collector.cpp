#include "Engine.h"
#include "Loopback.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace Cipherazzi::Performance
{
void require(bool result, const char* message)
{
    if (!result)
        throw std::runtime_error(message);
}

double cpuMilliseconds()
{
    FILETIME created{}, exited{}, kernel{}, user{};
    require(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user), "Could not read CPU time");
    const auto ticks = [](FILETIME value)
    {
        return (uint64_t{value.dwHighDateTime} << 32) | value.dwLowDateTime;
    };
    return static_cast<double>(ticks(kernel) + ticks(user)) / 10000;
}

nlohmann::json evidence(size_t count, bool changing)
{
    Counters counters;
    size_t observations = 0, facts = 0;
    std::shared_ptr<const ProtocolEvidence> first, last;
    Engine engine(counters, [&](Observation row)
    {
        if (row.lifecycleOnly || !row.application)
            return;
        ++observations;
        facts += row.application->fields.size();
        if (!first)
            first = row.application;
        last = row.application;
    });
    Endpoint client, server;
    client.address[0] = server.address[0] = 10;
    client.address[3] = 1;
    server.address[3] = 2;
    client.port = 50000;
    server.port = 8080;
    std::array<std::string, 16> requests;
    for (size_t index = 0; index < requests.size(); ++index)
        requests[index] = "GET /private-target HTTP/1.1\r\nHost: host-" + std::to_string(index) +
            ".test\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n";
    const std::string response = "HTTP/1.1 204 No Content\r\nServer: private-server\r\n\r\n";
    uint32_t clientSequence = 1, serverSequence = 1;
    int64_t timestamp = 1700000000000000;

    // Keep request/response framing, immutable emitted snapshots, and actual evidence merging in the measurement.
    const auto started = std::chrono::steady_clock::now();
    const auto cpu = cpuMilliseconds();
    for (size_t index = 0; index < count; ++index)
    {
        if (index == 0 || (changing && index % 16 == 0))
        {
            clientSequence = static_cast<uint32_t>(index * 1024 + 1);
            serverSequence = clientSequence + 512;
            engine.tcp({client, server, clientSequence - 1, 2, {}}, timestamp++);
        }
        const auto& request = requests[changing ? index % requests.size() : 0];
        engine.tcp({client, server, clientSequence, 0x18,
            {reinterpret_cast<const uint8_t*>(request.data()), request.size()}}, timestamp++);
        engine.tcp({server, client, serverSequence, 0x18,
            {reinterpret_cast<const uint8_t*>(response.data()), response.size()}}, timestamp++);
        clientSequence += static_cast<uint32_t>(request.size());
        serverSequence += static_cast<uint32_t>(response.size());
    }
    engine.expire(timestamp + 1, true);
    const auto milliseconds = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    const auto used = cpuMilliseconds() - cpu;
    require(first && last && first->fields.at("http_hosts").size() == 1 &&
        !first->fields.contains("http_response_observed"), "An emitted evidence snapshot was mutated");
    require(last->fields.at("http_hosts").size() == (changing ? 16 : 1) &&
        last->fields.value("http_basic_auth_observed", false) &&
        last->fields.value("http_response_observed", false), "HTTP evidence changed during the workload");
    require(observations == (changing ? count / 16 * 18 : 3), "The workload did not inspect every connection");
    require(!counters.malformed && !counters.reassemblyLimit && !counters.flowLimit && !counters.bufferedBytes,
        "Evidence workload lost data or retained flow memory");
    return {{"workload", changing ? "changing_http" : "repeated_http"}, {"requests", count},
        {"elapsed_ms", milliseconds}, {"cpu_ms", used}, {"observations", observations}, {"facts", facts},
        {"first_evidence", first->fields}, {"last_evidence", last->fields}};
}

struct Marker { uint32_t magic, owner, sequence; };
constexpr uint32_t Magic = 0x7a417043;

void sendPackets(uint32_t owner, uint32_t count, std::string_view mode, uint32_t offset)
{
    const bool mixed = mode == "mixed", burst = mode == "burst" || mode == "concurrent";
    WSADATA winsock{};
    require(WSAStartup(MAKEWORD(2, 2), &winsock) == 0, "Winsock startup failed");
    const std::array<SOCKET, 2> sockets{socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP),
        socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)};
    sockaddr_in ipv4{};
    ipv4.sin_family = AF_INET;
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sockaddr_in6 ipv6{};
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_addr.u.Byte[15] = 1;
    std::array<sockaddr*, 2> addresses{reinterpret_cast<sockaddr*>(&ipv4), reinterpret_cast<sockaddr*>(&ipv6)};
    std::array<int, 2> lengths{sizeof(ipv4), sizeof(ipv6)};
    for (size_t index = 0; index < sockets.size(); ++index)
    {
        require(sockets[index] != INVALID_SOCKET && bind(sockets[index], addresses[index], lengths[index]) == 0 &&
            getsockname(sockets[index], addresses[index], &lengths[index]) == 0, "UDP fixture could not bind");
        const DWORD timeout = 5000;
        require(setsockopt(sockets[index], SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0, "UDP timeout could not be set");
    }
    const std::array<size_t, 6> sizes{64, 512, 1400, 8192, 32768, 65000};
    std::vector<uint8_t> data(65000, 0xa5), received(data.size());

    // The separate traffic process owns sending and receiving costs; each datagram must arrive unchanged.
    const uint32_t batch = burst ? 64 : 1;
    for (uint32_t start = 0; start < count; start += batch)
    {
        // Space concurrent bursts within the capture queue limit so both builds process the same packet count.
        if (mode == "concurrent" && start && start % 4096 == 0)
            Sleep(250);
        const auto end = std::min(count, start + batch);
        for (uint32_t index = start; index < end; ++index)
        {
            const auto family = mixed ? index % 2 : 0;
            const auto size = static_cast<int>(mixed ? sizes[index % sizes.size()] : 128);
            const Marker marker{Magic, owner, index + offset};
            std::memcpy(data.data(), &marker, sizeof(marker));
            require(sendto(sockets[family], reinterpret_cast<const char*>(data.data()), size, 0,
                addresses[family], lengths[family]) == size, "UDP fixture send failed");
        }
        for (uint32_t index = start; index < end; ++index)
        {
            const auto family = mixed ? index % 2 : 0;
            const auto size = static_cast<int>(mixed ? sizes[index % sizes.size()] : 128);
            const Marker marker{Magic, owner, index + offset};
            std::memcpy(data.data(), &marker, sizeof(marker));
            require(recv(sockets[family], reinterpret_cast<char*>(received.data()),
                static_cast<int>(received.size()), 0) == size && std::memcmp(data.data(), received.data(), size) == 0,
                "Capture changed or lost application traffic");
        }
    }
    for (const auto socket : sockets)
        closesocket(socket);
    WSACleanup();
}

nlohmann::json capture(uint32_t count, bool mixed, bool burst, bool concurrent)
{
    // Measure capture independently of traffic generation and verify every marked packet.
    Counters counters;
    uint32_t received = 0, duplicates = 0, reordered = 0;
    uint32_t lastSequence = 0, invalidTimes = 0, timestampReversals = 0;
    uint64_t bytes = 0;
    std::vector<bool> seen(count);
    int64_t previous = 0, latest = 0;
    const auto owner = GetCurrentProcessId();
    const auto earliest = nowUs();
    LoopbackCapture observer([&](Bytes data, int64_t timestamp)
    {
        const auto packet = decodePacket(data, PacketKind::Ip, counters, PacketOrigin::Loopback);
        if (!packet || packet->protocol != 17 || packet->payload.size() < sizeof(Marker))
            return;
        Marker marker{};
        std::memcpy(&marker, packet->payload.data(), sizeof(marker));
        if (marker.magic != Magic || marker.owner != owner || marker.sequence >= count)
            return;
        duplicates += seen[marker.sequence];
        reordered += received && marker.sequence <= lastSequence;
        timestampReversals += timestamp < previous;
        invalidTimes += timestamp < earliest;
        seen[marker.sequence] = true;
        lastSequence = marker.sequence;
        previous = timestamp;
        latest = std::max(latest, timestamp);
        bytes += data.size();
        ++received;
    }, counters);
    std::wstring path(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(length && length < path.size(), "Could not locate the traffic generator");
    path.resize(length);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    std::array<PROCESS_INFORMATION, 4> processes{};
    const uint32_t workers = concurrent ? 4 : 1;
    IO_COUNTERS before{}, after{};
    require(GetProcessIoCounters(GetCurrentProcess(), &before), "Could not read I/O counters");
    const auto cpu = cpuMilliseconds();
    const auto started = std::chrono::steady_clock::now();
    for (uint32_t index = 0; index < workers; ++index)
    {
        auto command = L"\"" + path + L"\" --send " + std::to_wstring(owner) + L" " +
            std::to_wstring(count / workers) + (concurrent ? L" concurrent " : mixed ? L" mixed " :
                burst ? L" burst " : L" small ") +
            std::to_wstring(index * (count / workers));
        auto& process = processes[index];
        require(CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &process), "Could not start the traffic generator");
        CloseHandle(process.hThread);
    }
    bool completed = true;
    for (uint32_t index = 0; index < workers; ++index)
    {
        const auto handle = processes[index].hProcess;
        const auto exited = WaitForSingleObject(handle, 60000);
        DWORD code = 1;
        GetExitCodeProcess(handle, &code);
        if (exited != WAIT_OBJECT_0)
            TerminateProcess(handle, 1);
        CloseHandle(handle);
        completed = completed && exited == WAIT_OBJECT_0 && code == 0;
    }
    observer.stop();
    observer.check();
    const auto milliseconds = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    const auto used = cpuMilliseconds() - cpu;
    require(GetProcessIoCounters(GetCurrentProcess(), &after), "Could not read I/O counters");
    require(completed, "Traffic generator failed or timed out");
    if (received != count || duplicates || invalidTimes || latest > nowUs())
        throw std::runtime_error(nlohmann::json{{"error", "Capture verification failed"}, {"expected", count},
            {"received", received}, {"duplicates", duplicates}, {"reordered", reordered},
            {"invalid_times", invalidTimes}, {"last_sequence", lastSequence}}.dump());
    require(!counters.truncated && !counters.malformed, "Capture truncated or malformed a datagram");
    return {{"workload", concurrent ? "concurrent_loopback" : mixed ? "mixed_loopback" :
        burst ? "burst_loopback" : "small_loopback"},
        {"packets", received},
        {"bytes", bytes}, {"elapsed_ms", milliseconds}, {"cpu_ms", used},
        {"duplicates", duplicates}, {"driver_order_reversals", reordered},
        {"io_operations", after.OtherOperationCount - before.OtherOperationCount},
        {"driver_timestamp_reversals", timestampReversals}, {"application_traffic_unchanged", true}};
}
}

int main(int argc, char** argv)
{
    using namespace Cipherazzi::Performance;
    try
    {
        require(argc >= 3, "Usage: Cipherazzi.Performance evidence|loopback COUNT [mixed|burst|concurrent]");
        if (std::string_view(argv[1]) == "--send" && argc == 6)
        {
            sendPackets(std::stoul(argv[2]), std::stoul(argv[3]), argv[4], std::stoul(argv[5]));
            return 0;
        }
        const auto count = std::stoul(argv[2]);
        require(count >= 16 && count <= 1000000 && count % 16 == 0, "Count must be a multiple of 16, up to 1000000");
        nlohmann::json result;
        if (std::string_view(argv[1]) == "evidence")
            result = nlohmann::json::array({evidence(count, false), evidence(count, true)});
        else if (std::string_view(argv[1]) == "loopback")
            result = capture(count, argc == 4 && std::string_view(argv[3]) == "mixed",
                argc == 4 && std::string_view(argv[3]) == "burst",
                argc == 4 && std::string_view(argv[3]) == "concurrent");
        else
            throw std::runtime_error("Unknown benchmark workload");
        PROCESS_MEMORY_COUNTERS memory{};
        require(GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof(memory)), "Could not read peak memory");
        std::cout << nlohmann::json{{"measurements", result},
            {"peak_working_set_bytes", memory.PeakWorkingSetSize}}.dump() << '\n';
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
