#include "Processes.h"

#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <tdh.h>
#include <sddl.h>
#include <ntsecapi.h>
#include <algorithm>
#include <cstring>
#include <filesystem>

namespace Cipherazzi
{
constexpr GUID NetworkProvider{0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
constexpr GUID ProcessProvider{0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
constexpr int64_t FileTimeEpoch = 116444736000000000LL;
using ProcessHandle = std::unique_ptr<void, decltype(&CloseHandle)>;

Owner Processes::describe(uint32_t pid, int64_t atUs, std::string evidence)
{
    Owner result;
    result.pid = pid;
    result.evidence = std::move(evidence);
    ProcessHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid), CloseHandle);
    if (!process)
        return result;

    // Validate process creation time before attaching a name to a potentially reused PID.
    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetProcessTimes(process.get(), &created, &exited, &kernel, &user))
    {
        const auto ticks = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        result.startedUs = (static_cast<int64_t>(ticks) - FileTimeEpoch) / 10;
        if (result.startedUs <= atUs)
        {
            // A process instance keeps its image and primary-token user, so one complete description serves
            // every later snapshot; the creation time distinguishes a reused PID.
            static std::mutex cacheMutex;
            static std::unordered_map<uint32_t, Owner> cache;
            {
                std::lock_guard lock(cacheMutex);
                if (const auto found = cache.find(pid);
                    found != cache.end() && found->second.startedUs == result.startedUs)
                {
                    auto described = found->second;
                    described.evidence = std::move(result.evidence);
                    return described;
                }
            }
            std::wstring path(1024, L'\0');
            DWORD size = static_cast<DWORD>(path.size());
            auto queried = QueryFullProcessImageNameW(process.get(), 0, path.data(), &size);
            if (!queried && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                path.resize(32768);
                size = static_cast<DWORD>(path.size());
                queried = QueryFullProcessImageNameW(process.get(), 0, path.data(), &size);
            }
            if (queried)
            {
                path.resize(size);
                result.path = utf8(path);
                result.name = utf8(std::filesystem::path(path).filename().wstring());
            }

            // Read the primary token user, independently of the collector's account or thread impersonation.
            HANDLE rawToken{};
            if (!OpenProcessToken(process.get(), TOKEN_QUERY, &rawToken))
                return result;
            ProcessHandle token(rawToken, CloseHandle);
            alignas(TOKEN_USER) std::array<uint8_t, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE> userBuffer{};
            DWORD bytes{};
            if (!GetTokenInformation(token.get(), TokenUser, userBuffer.data(),
                static_cast<DWORD>(userBuffer.size()), &bytes))
                return result;
            const auto sid = reinterpret_cast<const TOKEN_USER*>(userBuffer.data())->User.Sid;
            PWSTR rawSid{};
            if (!IsValidSid(sid) || !ConvertSidToStringSidW(sid, &rawSid))
                return result;
            std::unique_ptr<wchar_t, decltype(&LocalFree)> sidText(rawSid, LocalFree);
            result.accountSid = utf8(sidText.get());

            // Local logon data avoids domain-controller lookups on the capture and database writer paths.
            TOKEN_STATISTICS statistics{};
            PSECURITY_LOGON_SESSION_DATA rawLogon{};
            if (GetTokenInformation(token.get(), TokenStatistics, &statistics, sizeof(statistics), &bytes) &&
                LsaGetLogonSessionData(&statistics.AuthenticationId, &rawLogon) == 0)
            {
                std::unique_ptr<SECURITY_LOGON_SESSION_DATA, decltype(&LsaFreeReturnBuffer)>
                    logon(rawLogon, LsaFreeReturnBuffer);
                if (logon && logon->Sid && EqualSid(sid, logon->Sid))
                {
                    if (logon->UserName.Buffer)
                        result.account = utf8({logon->UserName.Buffer, logon->UserName.Length / sizeof(wchar_t)});
                    if (logon->LogonDomain.Buffer)
                        result.accountDomain = utf8({logon->LogonDomain.Buffer,
                            logon->LogonDomain.Length / sizeof(wchar_t)});
                }
            }

            // Built-in service accounts can have no ordinary logon session; these SIDs resolve locally.
            if (result.account.empty() && (IsWellKnownSid(sid, WinLocalSystemSid) ||
                IsWellKnownSid(sid, WinLocalServiceSid) || IsWellKnownSid(sid, WinNetworkServiceSid)))
            {
                wchar_t name[256]{}, domain[256]{};
                DWORD nameSize = 256, domainSize = 256;
                SID_NAME_USE use{};
                if (LookupAccountSidW(nullptr, sid, name, &nameSize, domain, &domainSize, &use))
                {
                    result.account = utf8(name);
                    result.accountDomain = utf8(domain);
                }
            }
            if (!result.path.empty() && !result.accountSid.empty())
            {
                std::lock_guard lock(cacheMutex);
                if (cache.size() >= 4096)
                    cache.clear();
                cache[pid] = result;
            }
        }
        else
            result.startedUs = 0;
    }
    return result;
}

Processes::Processes(Counters& counters) : counters_(counters)
{
    // Connection and process lifetimes allow attribution after a short-lived client has already exited.
    name_ = L"Cipherazzi-Process-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    properties_.resize(sizeof(EVENT_TRACE_PROPERTIES) + (name_.size() + 1) * sizeof(wchar_t));
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(properties_.size());
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 2;
    properties->BufferSize = 64;
    properties->MinimumBuffers = 4;
    properties->MaximumBuffers = 32;
    properties->FlushTimer = 1;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    std::memcpy(properties_.data() + properties->LoggerNameOffset, name_.c_str(),
        (name_.size() + 1) * sizeof(wchar_t));
    auto result = StartTraceW(&session_, name_.c_str(), properties);
    if (result != ERROR_SUCCESS)
    {
        session_ = 0;
        status_ = "TCP table snapshots only; ETW unavailable (" + std::to_string(result) + ")";
        return;
    }

    struct EventFilter
    {
        BOOLEAN filterIn{TRUE};
        UCHAR reserved{};
        USHORT count{6};
        USHORT ids[6]{12, 13, 15, 28, 29, 31};
    } filter;
    EVENT_FILTER_DESCRIPTOR descriptor{};
    descriptor.Ptr = reinterpret_cast<ULONGLONG>(&filter);
    descriptor.Size = sizeof(filter);
    descriptor.Type = EVENT_FILTER_TYPE_EVENT_ID;
    ENABLE_TRACE_PARAMETERS parameters{};
    parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    parameters.EnableFilterDesc = &descriptor;
    parameters.FilterDescCount = 1;
    result = EnableTraceEx2(session_, &NetworkProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION, 0x30, 0, 0, &parameters);
    ULONG lifecycleResult = ERROR_NOT_SUPPORTED;
    if (result == ERROR_SUCCESS)
    {
        filter.count = 2;
        filter.ids[0] = 1;
        filter.ids[1] = 2;
        descriptor.Size = offsetof(EventFilter, ids) + 2 * sizeof(USHORT);
        lifecycleResult = EnableTraceEx2(session_, &ProcessProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION, 0x10, 0, 0, &parameters);
    }
    if (result == ERROR_SUCCESS)
    {
        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LoggerName = name_.data();
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = eventCallback;
        logfile.BufferCallback = bufferCallback;
        logfile.Context = this;
        trace_ = OpenTraceW(&logfile);
        if (trace_ == INVALID_PROCESSTRACE_HANDLE)
            result = GetLastError();
    }
    if (result != ERROR_SUCCESS)
    {
        stop();
        status_ = "TCP table snapshots only; ETW unavailable (" + std::to_string(result) + ")";
        return;
    }
    status_ = "ETW connection events with TCP/UDP table fallback; best-effort local ownership";
    if (lifecycleResult != ERROR_SUCCESS)
        status_ += "; process lifetimes unavailable (" + std::to_string(lifecycleResult) + ")";
    try
    {
        thread_ = std::thread([this]
        {
            const auto result = ProcessTrace(&trace_, 1, nullptr, nullptr);
            if (result != ERROR_SUCCESS && result != ERROR_CANCELLED)
                ++counters_.processEventsLost;
        });
    }
    catch (...)
    {
        stop();
        throw;
    }
}

Processes::~Processes() { stop(); }

void Processes::stop()
{
    if (session_)
    {
        ControlTraceW(session_, name_.c_str(), reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data()),
            EVENT_TRACE_CONTROL_STOP);
        session_ = 0;
    }
    if (trace_ != INVALID_PROCESSTRACE_HANDLE)
        CloseTrace(trace_);
    if (thread_.joinable())
        thread_.join();
    trace_ = INVALID_PROCESSTRACE_HANDLE;
}

ULONG WINAPI Processes::bufferCallback(EVENT_TRACE_LOGFILEW* trace) noexcept
{
    auto& self = *static_cast<Processes*>(trace->Context);
    const auto lost = self.counters_.processEventsLost.load(std::memory_order_relaxed);
    if (trace->EventsLost > lost)
        self.counters_.processEventsLost.store(trace->EventsLost, std::memory_order_relaxed);
    return TRUE;
}

void WINAPI Processes::eventCallback(EVENT_RECORD* event) noexcept
{
    auto& self = *static_cast<Processes*>(event->UserContext);
    try
    {
        if (event->EventHeader.ProviderId == ProcessProvider)
            self.processEvent(*event);
        else
            self.event(*event);
    }
    catch (...) { ++self.counters_.processEventsLost; }
}

void Processes::event(const EVENT_RECORD& event)
{
    if (event.EventHeader.ProviderId != NetworkProvider)
        return;
    const auto id = event.EventHeader.EventDescriptor.Id;
    const bool ipv6 = id == 28 || id == 29 || id == 31;
    const bool closed = id == 13 || id == 29;
    if (id != 12 && id != 15 && id != 28 && id != 31 && !closed)
        return;
    if (event.EventHeader.EventDescriptor.Version != 0 || event.UserDataLength < (ipv6 ? 44 : 20))
    {
        ++counters_.processEventsLost;
        return;
    }

    // Read the provider's PID payload; the ETW header may identify a kernel worker instead.
    const Bytes data(static_cast<const uint8_t*>(event.UserData), event.UserDataLength);
    uint32_t pid;
    std::memcpy(&pid, data.data(), sizeof(pid));
    Endpoint local, remote;
    const size_t length = ipv6 ? 16 : 4;
    local.family = remote.family = ipv6 ? 6 : 4;
    std::copy_n(data.begin() + 8, length, remote.address.begin());
    std::copy_n(data.begin() + 8 + length, length, local.address.begin());
    remote.port = be16(data, 8 + length * 2);
    local.port = be16(data, 10 + length * 2);
    const auto timestamp = (event.EventHeader.TimeStamp.QuadPart - FileTimeEpoch) / 10;
    const auto key = FlowKey::make(local, remote);
    auto owner = closed ? Owner{} : lookup(pid, timestamp);
    std::lock_guard lock(mutex_);
    if (timestamp >= pruneUs_)
    {
        std::erase_if(connections_, [timestamp](const auto& item)
        {
            return item.second.empty() || timestamp - item.second.back().startUs > 180000000;
        });
        for (auto it = lifetimes_.begin(); it != lifetimes_.end();)
        {
            std::erase_if(it->second, [&](const Lifetime& lifetime)
            {
                if (!lifetime.endedUs || timestamp - lifetime.endedUs < 180000000)
                    return false;
                lifetimeBytes_ -= sizeof(Lifetime) - sizeof(Owner) + lifetime.owner.memory();
                return true;
            });
            if (it->second.empty())
                it = lifetimes_.erase(it);
            else
                ++it;
        }
        pruneUs_ = timestamp + 1000000;
    }
    if (closed)
    {
        const auto found = connections_.find(key);
        if (found != connections_.end())
            for (auto& connection : found->second)
                if (connection.local == local && connection.owner.pid == pid && !connection.endUs)
                    connection.endUs = timestamp;
        return;
    }
    if (connections_.size() >= 65536 && !connections_.contains(key))
    {
        ++counters_.processEventsLost;
        return;
    }
    auto& entries = connections_[key];
    for (auto& entry : entries)
        if (entry.local == local && !entry.endUs)
            entry.endUs = timestamp;
    entries.push_back({local, std::move(owner), timestamp, 0});
    if (entries.size() > 4)
        entries.pop_front();
}

void Processes::remember(Owner owner, int64_t endedUs)
{
    if (!owner.pid || !owner.startedUs)
        return;
    std::lock_guard lock(mutex_);
    auto bytes = sizeof(Lifetime) - sizeof(Owner) + owner.memory();
    if (lifetimeBytes_ + bytes > 32 * 1024 * 1024 ||
        (lifetimes_.size() >= 8192 && !lifetimes_.contains(owner.pid)))
    {
        ++counters_.processEventsLost;
        return;
    }
    auto& history = lifetimes_[owner.pid];
    for (auto& lifetime : history)
    {
        if (lifetime.owner.startedUs != owner.startedUs)
            continue;
        if (endedUs)
            lifetime.endedUs = endedUs;

        // Exit events can carry truncated image names; retain the complete identity from process start.
        if (!lifetime.owner.path.empty())
        {
            owner.path = lifetime.owner.path;
            owner.name = lifetime.owner.name;
        }
        else if (owner.name.empty())
            owner.name = lifetime.owner.name;
        if (owner.evidence.empty()) owner.evidence = lifetime.owner.evidence;
        if (owner.accountSid.empty()) owner.accountSid = lifetime.owner.accountSid;
        if (owner.account.empty()) owner.account = lifetime.owner.account;
        if (owner.accountDomain.empty()) owner.accountDomain = lifetime.owner.accountDomain;
        bytes = sizeof(Lifetime) - sizeof(Owner) + owner.memory();
        const auto previous = sizeof(Lifetime) - sizeof(Owner) + lifetime.owner.memory();
        if (lifetimeBytes_ - previous + bytes > 32 * 1024 * 1024)
            return;
        lifetime.owner = std::move(owner);
        lifetimeBytes_ = lifetimeBytes_ - previous + bytes;
        return;
    }
    history.push_back({std::move(owner), endedUs});
    lifetimeBytes_ += bytes;
    if (history.size() > 4)
    {
        const auto& oldest = history.front().owner;
        lifetimeBytes_ -= sizeof(Lifetime) - sizeof(Owner) + oldest.memory();
        history.pop_front();
    }
}

Owner Processes::lookup(uint32_t pid, int64_t atUs)
{
    {
        std::lock_guard lock(mutex_);
        if (const auto found = lifetimes_.find(pid); found != lifetimes_.end())
        {
            for (auto it = found->second.rbegin(); it != found->second.rend(); ++it)
            {
                if (it->owner.startedUs <= atUs && (!it->endedUs || atUs <= it->endedUs))
                {
                    auto owner = it->owner;
                    owner.evidence = "ETW connection";
                    return owner;
                }
            }
        }
    }
    auto owner = describe(pid, atUs, "ETW connection");
    remember(owner);
    return owner;
}

void Processes::processEvent(EVENT_RECORD& event)
{
    const auto id = event.EventHeader.EventDescriptor.Id;
    if (id != 1 && id != 2)
        return;

    // TDH resolves evolving process manifests; no command lines or environment values are collected.
    auto property = [&](const wchar_t* name)
    {
        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        if (TdhGetPropertySize(&event, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size > 65536)
            return std::vector<uint8_t>{};
        std::vector<uint8_t> data(size);
        if (TdhGetProperty(&event, 0, nullptr, 1, &descriptor, size, data.data()) != ERROR_SUCCESS)
            data.clear();
        return data;
    };
    const auto pidData = property(L"ProcessID");
    const auto createdData = property(L"CreateTime");
    if (pidData.size() != 4 || createdData.size() != 8)
    {
        ++counters_.processEventsLost;
        return;
    }
    Owner owner;
    int64_t ticks;
    std::memcpy(&owner.pid, pidData.data(), 4);
    std::memcpy(&ticks, createdData.data(), 8);
    owner.startedUs = (ticks - FileTimeEpoch) / 10;
    const auto timestamp = (event.EventHeader.TimeStamp.QuadPart - FileTimeEpoch) / 10;
    const auto image = property(L"ImageName");
    if (id == 1 && image.size() >= 2 && image.size() % 2 == 0)
    {
        std::wstring path(image.size() / 2, L'\0');
        std::memcpy(path.data(), image.data(), image.size());
        const auto end = path.find(L'\0');
        if (end == std::wstring::npos)
        {
            ++counters_.processEventsLost;
            return;
        }
        path.resize(end);
        owner.path = utf8(path);
        owner.name = utf8(std::filesystem::path(path).filename().wstring());
    }
    else if (id == 2 && !image.empty())
    {
        const auto end = std::find(image.begin(), image.end(), 0);
        const auto length = static_cast<int>(end - image.begin());
        const auto size = MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(image.data()), length,
            nullptr, 0);
        std::wstring name(size, L'\0');
        if (size)
            MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(image.data()), length, name.data(), size);
        owner.name = utf8(name);
    }
    if (id == 1)
    {
        auto described = describe(owner.pid, timestamp, "ETW process start");
        if (described.startedUs == owner.startedUs)
        {
            owner.account = std::move(described.account);
            owner.accountDomain = std::move(described.accountDomain);
            owner.accountSid = std::move(described.accountSid);
        }
    }
    remember(std::move(owner), id == 2 ? timestamp : 0);
}

void Processes::snapshot()
{
    const auto timestamp = nowUs();
    if (timestamp - snapshotUs_ < 500000)
        return;
    snapshot_.clear();
    snapshotUs_ = timestamp;
    std::unordered_map<uint32_t, Owner> owners;
    for (const auto family : {AF_INET, AF_INET6})
    {
        ULONG size = 0;
        auto result = GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<uint8_t> buffer;
        for (int retry = 0; result == ERROR_INSUFFICIENT_BUFFER && retry < 4; ++retry)
        {
            if (size > 64 * 1024 * 1024)
                break;
            buffer.resize(size);
            result = GetExtendedTcpTable(buffer.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        }
        if (result != ERROR_SUCCESS || buffer.size() < sizeof(DWORD))
        {
            ++counters_.processEventsLost;
            continue;
        }
        auto add = [&](Endpoint local, Endpoint remote, uint32_t pid, DWORD state)
        {
            if (!pid || !remote.port || state == MIB_TCP_STATE_LISTEN || state == MIB_TCP_STATE_TIME_WAIT)
                return;
            if (snapshot_.size() >= 65536)
                return;
            auto [it, inserted] = owners.try_emplace(pid);
            if (inserted)
            {
                it->second = describe(pid, timestamp, "TCP table snapshot");
                remember(it->second);
            }
            snapshot_[FlowKey::make(local, remote)].push_back({local, it->second, timestamp, 0});
        };
        if (family == AF_INET)
        {
            const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
            const auto maximum = (buffer.size() - offsetof(MIB_TCPTABLE_OWNER_PID, table)) /
                sizeof(MIB_TCPROW_OWNER_PID);
            for (size_t i = 0; i < std::min<size_t>(table->dwNumEntries, maximum); ++i)
            {
                const auto& row = table->table[i];
                Endpoint local, remote;
                std::memcpy(local.address.data(), &row.dwLocalAddr, 4);
                std::memcpy(remote.address.data(), &row.dwRemoteAddr, 4);
                local.port = ntohs(static_cast<uint16_t>(row.dwLocalPort));
                remote.port = ntohs(static_cast<uint16_t>(row.dwRemotePort));
                add(local, remote, row.dwOwningPid, row.dwState);
            }
        }
        else
        {
            const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
            const auto maximum = (buffer.size() - offsetof(MIB_TCP6TABLE_OWNER_PID, table)) /
                sizeof(MIB_TCP6ROW_OWNER_PID);
            for (size_t i = 0; i < std::min<size_t>(table->dwNumEntries, maximum); ++i)
            {
                const auto& row = table->table[i];
                Endpoint local, remote;
                local.family = remote.family = 6;
                std::copy_n(row.ucLocalAddr, 16, local.address.begin());
                std::copy_n(row.ucRemoteAddr, 16, remote.address.begin());
                local.port = ntohs(static_cast<uint16_t>(row.dwLocalPort));
                remote.port = ntohs(static_cast<uint16_t>(row.dwRemotePort));
                add(local, remote, row.dwOwningPid, row.dwState);
            }
        }
    }
}

void Processes::udpOwner(Observation& observation)
{
    const auto timestamp = nowUs();
    const bool knownBinding = std::ranges::any_of(udpSnapshot_, [&](const Connection& binding)
    {
        return (binding.local.family == observation.source.family &&
            binding.local.port == observation.source.port) ||
            (binding.local.family == observation.destination.family &&
                binding.local.port == observation.destination.port);
    });
    // A newly opened socket must not inherit an earlier binding snapshot for its first observation.
    if (timestamp - udpSnapshotUs_ >= 500000 || (!knownBinding && observation.firstUs >= udpSnapshotUs_))
    {
        udpSnapshotUs_ = timestamp;
        udpSnapshot_.clear();
        udpAddresses_.clear();
        MIB_UNICASTIPADDRESS_TABLE* raw = nullptr;
        if (GetUnicastIpAddressTable(AF_UNSPEC, &raw) == NO_ERROR)
        {
            std::unique_ptr<MIB_UNICASTIPADDRESS_TABLE, decltype(&FreeMibTable)> addresses(raw, FreeMibTable);
            for (ULONG i = 0; i < addresses->NumEntries; ++i)
            {
                const auto& address = addresses->Table[i].Address;
                Endpoint local;
                local.family = address.si_family == AF_INET ? 4 : 6;
                if (local.family == 4)
                    std::memcpy(local.address.data(), &address.Ipv4.sin_addr, 4);
                else
                    std::memcpy(local.address.data(), &address.Ipv6.sin6_addr, 16);
                udpAddresses_.push_back(local);
            }
        }
        std::unordered_map<uint32_t, Owner> owners;
        for (const auto family : {AF_INET, AF_INET6})
        {
            DWORD size = 0;
            auto result = GetExtendedUdpTable(nullptr, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
            std::vector<uint8_t> buffer;
            for (int attempt = 0; result == ERROR_INSUFFICIENT_BUFFER && attempt < 4; ++attempt)
            {
                if (size > 16 * 1024 * 1024)
                    break;
                buffer.resize(size);
                result = GetExtendedUdpTable(buffer.data(), &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
            }
            if (result != ERROR_SUCCESS || buffer.size() < sizeof(DWORD))
            {
                ++counters_.processEventsLost;
                continue;
            }
            auto add = [&](Endpoint local, uint32_t pid)
            {
                if (!pid || !local.port || udpSnapshot_.size() >= 65536)
                    return;
                auto [found, inserted] = owners.try_emplace(pid);
                if (inserted)
                {
                    found->second = describe(pid, timestamp, "UDP binding snapshot; peer not confirmed");
                    remember(found->second);
                }
                udpSnapshot_.push_back({local, found->second, timestamp, 0});
            };
            if (family == AF_INET)
            {
                const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
                const auto maximum = (buffer.size() - offsetof(MIB_UDPTABLE_OWNER_PID, table)) /
                    sizeof(MIB_UDPROW_OWNER_PID);
                for (size_t i = 0; i < std::min<size_t>(table->dwNumEntries, maximum); ++i)
                {
                    Endpoint local;
                    std::memcpy(local.address.data(), &table->table[i].dwLocalAddr, 4);
                    local.port = ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort));
                    add(local, table->table[i].dwOwningPid);
                }
            }
            else
            {
                const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
                const auto maximum = (buffer.size() - offsetof(MIB_UDP6TABLE_OWNER_PID, table)) /
                    sizeof(MIB_UDP6ROW_OWNER_PID);
                for (size_t i = 0; i < std::min<size_t>(table->dwNumEntries, maximum); ++i)
                {
                    Endpoint local;
                    local.family = 6;
                    std::copy_n(table->table[i].ucLocalAddr, 16, local.address.begin());
                    local.port = ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort));
                    add(local, table->table[i].dwOwningPid);
                }
            }
        }
    }
    if (udpSnapshotUs_ - observation.lastUs > 5000000)
        return;

    // A shared UDP binding is ambiguous; assign an owner only when every matching binding agrees.
    for (const auto* endpoint : {&observation.source, &observation.destination})
    {
        const bool localAddress = std::ranges::any_of(udpAddresses_, [&](const Endpoint& address)
        {
            return address.family == endpoint->family && address.address == endpoint->address;
        });
        const Owner* candidate = nullptr;
        bool ambiguous = false;
        for (const auto& binding : udpSnapshot_)
        {
            if (binding.local.family != endpoint->family || binding.local.port != endpoint->port ||
                (binding.local.address != endpoint->address && ( !localAddress || !std::ranges::all_of(binding.local.address,
                    [](uint8_t byte) { return byte == 0; }))) || binding.owner.startedUs > observation.firstUs)
                continue;
            if (candidate && (candidate->pid != binding.owner.pid || candidate->startedUs != binding.owner.startedUs))
                ambiguous = true;
            candidate = &binding.owner;
        }
        if (candidate && !ambiguous)
            (endpoint == &observation.source ? observation.sourceOwner : observation.destinationOwner) = *candidate;
    }
}

void Processes::enrich(Observation& observation)
{
    if (observation.quic || observation.udp)
    {
        udpOwner(observation);
        return;
    }
    const auto key = FlowKey::make(observation.source, observation.destination);
    {
        std::lock_guard lock(mutex_);
        const auto found = connections_.find(key);
        if (found != connections_.end())
        {
            for (const auto& connection : found->second)
            {
                if (connection.startUs > observation.lastUs + 100000 ||
                    (connection.endUs && connection.endUs < observation.firstUs))
                    continue;
                auto& owner = connection.local == observation.source ? observation.sourceOwner :
                    observation.destinationOwner;
                owner = connection.owner;
                if (owner.pid)
                {
                    if (const auto process = lifetimes_.find(owner.pid); process != lifetimes_.end())
                        for (auto it = process->second.rbegin(); it != process->second.rend(); ++it)
                            if (it->owner.startedUs <= connection.startUs &&
                                (!it->endedUs || connection.startUs <= it->endedUs) && !it->owner.name.empty())
                            {
                                owner = it->owner;
                                owner.evidence = "ETW connection";
                                break;
                            }
                }
            }
        }
    }
    if (observation.sourceOwner.pid || observation.destinationOwner.pid)
        return;

    // Snapshots are explicitly lower-confidence evidence and never used for historical imports.
    snapshot();
    const auto found = snapshot_.find(key);
    if (found == snapshot_.end() || snapshotUs_ - observation.lastUs > 5000000)
        return;
    for (const auto& connection : found->second)
    {
        if (connection.owner.startedUs > observation.lastUs)
            continue;
        auto& owner = connection.local == observation.source ? observation.sourceOwner : observation.destinationOwner;
        owner = connection.owner;
    }
}
}
