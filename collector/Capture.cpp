#include "Capture.h"
#include "PacketQueue.h"
#include "Loopback.h"

#include <winsock2.h>
#include <windows.h>
#include <algorithm>
#include <bit>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_set>

namespace Cipherazzi
{
// These ABI declarations match the Packet Monitor API; the Windows SDK supplies no import library.
namespace PacketMonitor
{
union Address
{
    uint64_t alignment[2];
    uint8_t bytes[16];
};

struct Source
{
    int kind;
    wchar_t name[64];
    wchar_t description[128];
    uint32_t id;
    uint32_t secondaryId;
    uint32_t parentId;
    uint32_t present;
    Address detail;
};

struct SourceList
{
    uint32_t count;
    const Source* sources[1];
};

struct Constraint
{
    wchar_t name[64];
    uint32_t present;
    uint8_t mac1[6];
    uint8_t mac2[6];
    uint16_t vlan;
    uint16_t etherType;
    uint16_t dscp;
    uint8_t protocol;
    Address ip1;
    Address ip2;
    uint8_t prefix1;
    uint8_t prefix2;
    uint16_t port1;
    uint16_t port2;
    uint8_t tcpFlags;
    uint32_t encapsulation;
    uint16_t vxlanPort;
    uint64_t packets;
    uint64_t bytes;
};

struct Data
{
    const void* data;
    uint32_t size;
    uint32_t metadataOffset;
    uint32_t packetOffset;
    uint32_t packetLength;
    uint32_t missedWrite;
    uint32_t missedRead;
};

// Stream metadata is a packed wire format, independent of the configuration structure's alignment.
#pragma pack(push, 1)
struct Metadata
{
    uint64_t group;
    uint16_t count;
    uint16_t appearance;
    uint16_t direction;
    uint16_t packetType;
    uint16_t component;
    uint16_t edge;
    uint16_t reserved;
    uint32_t dropReason;
    uint32_t dropLocation;
    uint16_t processor;
    LARGE_INTEGER timestamp;
};
#pragma pack(pop)

union Event
{
    struct { uint32_t size; uint16_t truncation; } start;
    struct { BOOLEAN fatal; DWORD reason; } stop;
    struct { BOOLEAN warning; DWORD reason; uint64_t length; } process;
};

struct Configuration
{
    void* context;
    void (CALLBACK* eventCallback)(void*, const Event*, int);
    void (CALLBACK* dataCallback)(void*, const Data*);
    uint16_t multiplier;
    uint16_t truncation;
};

static_assert(sizeof(Source) == 424 && sizeof(Constraint) == 216 && sizeof(Metadata) == 40);
static_assert(offsetof(Metadata, timestamp) == 32 && sizeof(Configuration) == 32 && sizeof(Data) == 32);

void require(HRESULT result, const char* operation)
{
    if (FAILED(result))
    {
        char code[16]{};
        sprintf_s(code, "0x%08lX", static_cast<unsigned long>(result));
        throw std::runtime_error(std::string(operation) + " failed (" + code + ")");
    }
}

class Api
{
public:
    HMODULE module{};
    HANDLE handle{};
    HRESULT (WINAPI* initialize)(uint32_t, void*, HANDLE*){};
    void (WINAPI* uninitialize)(HANDLE){};
    HRESULT (WINAPI* createSession)(HANDLE, PCWSTR, HANDLE*){};
    void (WINAPI* closeSession)(HANDLE){};
    HRESULT (WINAPI* setActive)(HANDLE, BOOLEAN){};
    HRESULT (WINAPI* createStream)(HANDLE, const Configuration*, HANDLE*){};
    void (WINAPI* closeStream)(HANDLE){};
    HRESULT (WINAPI* attach)(HANDLE, void*){};
    HRESULT (WINAPI* enumerate)(HANDLE, int, BOOLEAN, SIZE_T, SIZE_T*, SourceList*){};
    HRESULT (WINAPI* addSource)(HANDLE, const Source*){};
    HRESULT (WINAPI* addConstraint)(HANDLE, const Constraint*){};

    Api() = default;
    Api(const Api&) = delete;
    Api& operator=(const Api&) = delete;
    ~Api()
    {
        if (handle)
            uninitialize(handle);
        if (module)
            FreeLibrary(module);
    }

    void open()
    {
        module = LoadLibraryExW(L"PktMonApi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module)
            throw std::runtime_error("Windows Packet Monitor streaming API is unavailable on this system");
        auto load = [&](auto& target, const char* name)
        {
            target = reinterpret_cast<std::remove_reference_t<decltype(target)>>(GetProcAddress(module, name));
            if (!target)
                throw std::runtime_error(std::string("This Windows build does not expose ") + name);
        };
        load(initialize, "PacketMonitorInitialize");
        load(uninitialize, "PacketMonitorUninitialize");
        load(createSession, "PacketMonitorCreateLiveSession");
        load(closeSession, "PacketMonitorCloseSessionHandle");
        load(setActive, "PacketMonitorSetSessionActive");
        load(createStream, "PacketMonitorCreateRealtimeStream");
        load(closeStream, "PacketMonitorCloseRealtimeStream");
        load(attach, "PacketMonitorAttachOutputToSession");
        load(enumerate, "PacketMonitorEnumDataSources");
        load(addSource, "PacketMonitorAddSingleDataSourceToSession");
        load(addConstraint, "PacketMonitorAddCaptureConstraint");
        require(initialize(0x00010000, nullptr, &handle), "Packet Monitor initialization");
    }

    std::vector<Source> sources(int kind)
    {
        SIZE_T needed = 0;
        auto result = enumerate(handle, kind, FALSE, 0, &needed, nullptr);
        if (!needed)
            require(result, "Packet Monitor source enumeration");
        std::vector<uint8_t> buffer;
        for (int retry = 0; retry < 4; ++retry)
        {
            if (needed < sizeof(SourceList) || needed > 16 * 1024 * 1024)
                throw std::runtime_error("Invalid Packet Monitor source list size");
            buffer.resize(needed);
            result = enumerate(handle, kind, FALSE, buffer.size(), &needed,
                reinterpret_cast<SourceList*>(buffer.data()));
            if (SUCCEEDED(result))
                break;
            if (needed <= buffer.size())
                require(result, "Packet Monitor source enumeration");
        }
        require(result, "Packet Monitor source enumeration");
        const auto* list = reinterpret_cast<const SourceList*>(buffer.data());
        if (list->count > (buffer.size() - offsetof(SourceList, sources)) / sizeof(Source*))
            throw std::runtime_error("Invalid Packet Monitor source list");
        std::vector<Source> output;
        for (size_t i = 0; i < list->count; ++i)
        {
            const auto pointer = reinterpret_cast<uintptr_t>(list->sources[i]);
            const auto begin = reinterpret_cast<uintptr_t>(buffer.data());
            if (pointer < begin || pointer - begin > buffer.size() - sizeof(Source))
                throw std::runtime_error("Invalid Packet Monitor source entry");
            output.push_back(*list->sources[i]);
        }
        return output;
    }
};
}

struct Capture::Impl
{
    PacketMonitor::Api api;
    HANDLE session{};
    HANDLE stream{};
    HMODULE timerModule{};
    UINT (WINAPI* endPeriod)(UINT){};
    PROCESS_POWER_THROTTLING_STATE previousPower{PROCESS_POWER_THROTTLING_CURRENT_VERSION};
    bool powerChanged{};
    bool preciseTimer{};
    Engine& engine;
    Counters& counters;
    std::vector<uint32_t> requested;
    bool network;
    bool sameHost;
    std::unique_ptr<LoopbackCapture> loopback;
    std::unordered_set<uint32_t> attached;
    PacketQueue queue;
    std::atomic<bool> stopping{};
    std::atomic<bool> active{};
    std::atomic<DWORD> fatal{};
    std::atomic<uint32_t> missedRead{};
    std::atomic<bool> readerConfigured{};
    HANDLE readerThread{};
    int previousReaderPriority{};
    std::thread worker;
    std::mutex errorMutex;
    std::exception_ptr error;

    Impl(Engine& target, Counters& stats, const std::vector<uint32_t>& sources, CaptureMode mode) :
        engine(target), counters(stats), requested(sources), network(mode != CaptureMode::Loopback),
        sameHost(mode != CaptureMode::Network),
        queue(65536, 8 * 1024 * 1024, sameHost ? LoopbackCaptureLimit : PacketMonitorCaptureLimit) {}
    ~Impl()
    {
        stop();
        if (timerModule)
            FreeLibrary(timerModule);
    }

    static void CALLBACK dataCallback(void* context, const PacketMonitor::Data* data) noexcept
    {
        auto& self = *static_cast<Impl*>(context);

        // Keep the API reader responsive while protocol parsing and storage run at normal priority.
        if (!self.readerConfigured.load(std::memory_order_relaxed) &&
            !self.readerConfigured.exchange(true, std::memory_order_relaxed))
        {
            const auto current = GetCurrentThread();
            self.previousReaderPriority = GetThreadPriority(current);
            if (self.previousReaderPriority == THREAD_PRIORITY_ERROR_RETURN ||
                !DuplicateHandle(GetCurrentProcess(), current, GetCurrentProcess(), &self.readerThread,
                    THREAD_SET_INFORMATION, FALSE, 0) || !SetThreadPriority(current, THREAD_PRIORITY_HIGHEST))
                self.fatal.store(GetLastError());
        }

        // Driver write losses belong to this packet; API read losses are cumulative within the stream.
        const auto previousRead = self.missedRead.exchange(data->missedRead, std::memory_order_relaxed);
        self.counters.captureLost.fetch_add(static_cast<uint32_t>(data->missedRead - previousRead) +
            static_cast<uint64_t>(data->missedWrite),
            std::memory_order_relaxed);
        if (!data->data || data->metadataOffset > data->size ||
            data->size - data->metadataOffset < sizeof(PacketMonitor::Metadata) || data->packetOffset > data->size ||
            data->packetLength > data->size - data->packetOffset || data->packetLength > PacketMonitorCaptureLimit)
        {
            ++self.counters.malformed;
            return;
        }
        PacketMonitor::Metadata metadata;
        std::memcpy(&metadata, static_cast<const uint8_t*>(data->data) + data->metadataOffset, sizeof(metadata));
        if (metadata.packetType != 1 && metadata.packetType != 3)
        {
            ++self.counters.unsupported;
            return;
        }

        const Bytes bytes(static_cast<const uint8_t*>(data->data) + data->packetOffset, data->packetLength);
        const auto timestamp = (metadata.timestamp.QuadPart - 116444736000000000LL) / 10;
        if (!self.queue.push(bytes, static_cast<PacketKind>(metadata.packetType), timestamp))
            ++self.counters.queueLost;
    }

    static void CALLBACK eventCallback(void* context, const PacketMonitor::Event* event, int kind) noexcept
    {
        auto& self = *static_cast<Impl*>(context);
        if (kind == 2 || (kind == 1 && self.active.load(std::memory_order_relaxed)))
            self.fatal.store(event->stop.reason ? event->stop.reason : ERROR_OPERATION_ABORTED);
        else if (kind == 3)
        {
            // Streaming callbacks only update counters; blocking diagnostics stall the capture reader.
            // Missed-read counters report discarded packets; classify warnings without counting a second loss.
            if (event->process.reason == ERROR_INSUFFICIENT_BUFFER)
                ++self.counters.truncated;
            else
                ++self.counters.malformed;
        }
    }

    void refresh()
    {
        if (!network)
            return;
        const auto sources = api.sources(requested.empty() ? 1 : 0);
        for (const auto& source : sources)
        {
            if (!requested.empty() && std::ranges::find(requested, source.id) == requested.end())
                continue;
            if (!attached.contains(source.id))
            {
                PacketMonitor::require(api.addSource(session, &source), "Packet Monitor source selection");
                attached.insert(source.id);
            }
        }
        if (attached.empty())
            throw std::runtime_error("No matching Packet Monitor capture sources; use --list-sources");
        for (const auto id : requested)
            if (!attached.contains(id))
                throw std::runtime_error("Requested Packet Monitor source is unavailable: " + std::to_string(id));
    }

    void start()
    {
        if (network)
        {
            api.open();

            // The stream reader polls with Sleep(1); coarse or suppressed timers let its bounded buffer overflow.
            timerModule = LoadLibraryExW(L"winmm.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (!timerModule)
                throw std::runtime_error("Could not configure packet capture timing");
            const auto beginPeriod = reinterpret_cast<UINT (WINAPI*)(UINT)>(
                GetProcAddress(timerModule, "timeBeginPeriod"));
            endPeriod = reinterpret_cast<UINT (WINAPI*)(UINT)>(GetProcAddress(timerModule, "timeEndPeriod"));
            if (!beginPeriod || !endPeriod || !GetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling,
                &previousPower, sizeof(previousPower)))
                throw std::runtime_error("Could not configure packet capture timing");
            auto power = previousPower;
            power.ControlMask |= PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
            power.StateMask &= ~PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
            if (!SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &power, sizeof(power)))
                throw std::runtime_error("Could not configure packet capture timing");
            powerChanged = true;
            if (beginPeriod(1))
                throw std::runtime_error("Could not configure packet capture timing");
            preciseTimer = true;

            // Select network sources and create a private capture session.
            const auto name = L"Cipherazzi-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(GetTickCount64());
            PacketMonitor::require(api.createSession(api.handle, name.c_str(), &session), "Packet Monitor session");
            refresh();
            PacketMonitor::Constraint constraint{};
            wcscpy_s(constraint.name, L"TCP handshakes");
            constraint.present = 1U << 5;
            constraint.protocol = 6;
            PacketMonitor::require(api.addConstraint(session, &constraint), "Packet Monitor TCP filter");
            wcscpy_s(constraint.name, L"QUIC handshakes");
            constraint.protocol = 17;
            PacketMonitor::require(api.addConstraint(session, &constraint), "Packet Monitor UDP filter");
            const PacketMonitor::Configuration configuration{
                this, eventCallback, dataCallback, 10, PacketMonitorCaptureLimit};
            PacketMonitor::require(api.createStream(api.handle, &configuration, &stream), "Packet Monitor stream");
            PacketMonitor::require(api.attach(session, stream), "Packet Monitor output attachment");
        }
        if (sameHost)
            loopback = std::make_unique<LoopbackCapture>([this](Bytes bytes, int64_t timestamp)
            {
                if (!queue.push(bytes, PacketKind::Ip, timestamp, PacketOrigin::Loopback))
                    ++counters.queueLost;
            }, counters);
        worker = std::thread([this]
        {
            try
            {
                for (;;)
                {
                    const auto packet = queue.take(std::chrono::seconds(1));
                    if (!packet)
                    {
                        if (stopping.load())
                            break;
                        engine.expire(nowUs());
                        continue;
                    }
                    engine.packet(packet->bytes, packet->kind, packet->timestamp, packet->origin);
                    queue.release();
                }
                engine.expire(nowUs(), true);
            }
            catch (...)
            {
                std::lock_guard lock(errorMutex);
                error = std::current_exception();
            }
        });
        if (network)
        {
            active.store(true);
            PacketMonitor::require(api.setActive(session, TRUE), "Packet Monitor activation");
        }
    }

    void stop()
    {
        active.store(false);
        if (session)
            api.setActive(session, FALSE);
        if (stream)
        {
            api.closeStream(stream);
            stream = nullptr;
        }
        if (loopback)
            loopback->stop();
        if (readerThread)
        {
            SetThreadPriority(readerThread, previousReaderPriority);
            CloseHandle(readerThread);
            readerThread = nullptr;
        }
        if (preciseTimer)
        {
            endPeriod(1);
            preciseTimer = false;
        }
        if (powerChanged)
        {
            SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &previousPower, sizeof(previousPower));
            powerChanged = false;
        }
        if (session)
        {
            api.closeSession(session);
            session = nullptr;
        }
        if (worker.joinable())
        {
            stopping.store(true);
            queue.wake();
            worker.join();
        }
    }
};

Capture::Capture(Engine& engine, Counters& counters, const std::vector<uint32_t>& sources, CaptureMode mode) :
    impl_(std::make_unique<Impl>(engine, counters, sources, mode))
{
    impl_->start();
}

Capture::~Capture() = default;
void Capture::stop() { impl_->stop(); }
void Capture::refreshSources() { impl_->refresh(); }

void Capture::check()
{
    if (const auto fatal = impl_->fatal.load())
        throw std::runtime_error("Packet Monitor streaming stopped (" + std::to_string(fatal) + ")");
    if (impl_->loopback)
        impl_->loopback->check();
    std::lock_guard lock(impl_->errorMutex);
    if (impl_->error)
        std::rethrow_exception(impl_->error);
}

void Capture::listSources()
{
    std::cout << "loopback\tSame-host TCP/UDP (default)\tUse --loopback-only or --no-loopback\n";
    PacketMonitor::Api api;
    api.open();
    for (const auto& source : api.sources(0))
        std::cout << source.id << "\t" << utf8(std::wstring_view(source.name, wcsnlen_s(source.name, 64))) << "\t"
            << utf8(std::wstring_view(source.description, wcsnlen_s(source.description, 128))) << '\n';
}

bool elevated()
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID group = nullptr;
    BOOL member = FALSE;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &group))
    {
        CheckTokenMembership(nullptr, group, &member);
        FreeSid(group);
    }
    return member != FALSE;
}

void replayPcap(const std::filesystem::path& path, Engine& engine, const std::atomic<bool>& stopped)
{
    // Replay shares the complete packet decoder and reassembly path with live capture.
    std::ifstream file(path, std::ios::binary);
    std::array<uint8_t, 24> header{};
    if (!file.read(reinterpret_cast<char*>(header.data()), header.size()))
        throw std::runtime_error("Could not read the PCAP header");
    const auto magic = be32(header, 0);
    const bool little = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
    const bool nano = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
    if (!little && magic != 0xa1b2c3d4 && magic != 0xa1b23c4d)
        throw std::runtime_error("Expected classic PCAP; convert PCAPNG before importing");
    auto word = [little](Bytes data, size_t offset)
    {
        const auto value = be32(data, offset);
        return little ? std::byteswap(value) : value;
    };
    const auto link = word(header, 20);
    const bool ethernet = link == 1;
    if (!ethernet && link != 101 && link != 228 && link != 229)
        throw std::runtime_error("PCAP requires Ethernet, raw IPv4, or raw IPv6 packets");
    std::array<uint8_t, 16> record{};
    std::vector<uint8_t> buffer;
    int64_t lastUs = 0;
    while (!stopped.load() && file.read(reinterpret_cast<char*>(record.data()), record.size()))
    {
        const auto captured = word(record, 8);
        const auto original = word(record, 12);
        if (captured > 1024 * 1024 || captured > original)
            throw std::runtime_error("Invalid PCAP packet length");
        buffer.resize(captured);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), captured))
            throw std::runtime_error("Truncated PCAP packet");
        const auto subseconds = word(record, 4);
        if (subseconds >= (nano ? 1000000000U : 1000000U))
            throw std::runtime_error("Invalid PCAP timestamp");
        const auto timestamp = static_cast<int64_t>(word(record, 0)) * 1000000 + subseconds / (nano ? 1000 : 1);
        lastUs = std::max(lastUs, timestamp);
        engine.packet(buffer, ethernet ? PacketKind::Ethernet : PacketKind::Ip, timestamp);
    }
    if (!stopped.load() && (!file.eof() || file.gcount() != 0))
        throw std::runtime_error("Truncated PCAP record header");
    engine.expire(lastUs, true);
}
}
