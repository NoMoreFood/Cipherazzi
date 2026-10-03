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

namespace ProcessesDetail
{
// Reads an IP Helper ownership table, growing the buffer until it fits; a failed read returns nothing.
template <class Query>
std::vector<uint8_t> ownershipTable(Query query, ULONG limit)
{
    ULONG size = 0;
    auto result = query(nullptr, &size);
    std::vector<uint8_t> buffer;
    for (int attempt = 0; result == ERROR_INSUFFICIENT_BUFFER && attempt < 4 && size <= limit; ++attempt)
    {
        buffer.resize(size);
        result = query(buffer.data(), &size);
    }
    if (result != ERROR_SUCCESS || buffer.size() < sizeof(DWORD))
        buffer.clear();
    return buffer;
}

// Visits each row that lies within the buffer, whatever count the table claims.
template <class Table, class Visit>
void tableRows(const std::vector<uint8_t>& buffer, Visit visit)
{
    const auto* table = reinterpret_cast<const Table*>(buffer.data());
    if (buffer.size() < offsetof(Table, table))
        return;
    const auto maximum = (buffer.size() - offsetof(Table, table)) / sizeof(table->table[0]);
    for (size_t index = 0; index < std::min<size_t>(table->dwNumEntries, maximum); ++index)
        visit(table->table[index]);
}

Endpoint tableEndpoint(DWORD address, DWORD port)
{
    Endpoint result;
    std::memcpy(result.address.data(), &address, 4);
    result.port = ntohs(static_cast<uint16_t>(port));
    return result;
}

Endpoint tableEndpoint(const UCHAR (&address)[16], DWORD port)
{
    Endpoint result;
    result.family = 6;
    std::copy_n(address, 16, result.address.begin());
    result.port = ntohs(static_cast<uint16_t>(port));
    return result;
}
}
using namespace ProcessesDetail;

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
        const auto exitTicks = (static_cast<uint64_t>(exited.dwHighDateTime) << 32) | exited.dwLowDateTime;
        const auto endedUs = exitTicks ? (static_cast<int64_t>(exitTicks) - FileTimeEpoch) / 10 : 0;
        if (result.startedUs <= atUs && (!endedUs || atUs < endedUs))
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
            {
                ++counters_.processEventsLost;
                evidenceLost();
            }
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
    if (trace->EventsLost > self.traceEventsLost_)
    {
        self.counters_.processEventsLost += trace->EventsLost - self.traceEventsLost_;
        self.traceEventsLost_ = trace->EventsLost;
        self.evidenceLost();
    }
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
    catch (...)
    {
        ++self.counters_.processEventsLost;
        self.evidenceLost();
    }
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
    const size_t length = ipv6 ? 16 : 4;
    const size_t connectionOffset = 12 + length * 2 + (closed ? 4 : 20);
    if (event.EventHeader.EventDescriptor.Version != 0 || !event.UserData ||
        event.UserDataLength < connectionOffset + sizeof(uint32_t))
    {
        ++counters_.processEventsLost;
        evidenceLost();
        return;
    }

    // The payload identifies the process and socket; the ETW header can identify a kernel worker.
    const Bytes data(static_cast<const uint8_t*>(event.UserData), event.UserDataLength);
    SocketEvent observed;
    std::memcpy(&observed.pid, data.data(), sizeof(observed.pid));
    std::memcpy(&observed.id, data.data() + connectionOffset, sizeof(observed.id));
    Endpoint remote;
    observed.local.family = remote.family = ipv6 ? 6 : 4;
    std::copy_n(data.begin() + 8, length, remote.address.begin());
    std::copy_n(data.begin() + 8 + length, length, observed.local.address.begin());
    remote.port = be16(data, 8 + length * 2);
    observed.local.port = be16(data, 10 + length * 2);
    observed.timestampUs = (event.EventHeader.TimeStamp.QuadPart - FileTimeEpoch) / 10;
    observed.closed = closed;
    const auto timestamp = observed.timestampUs;
    const auto key = FlowKey::make(observed.local, remote);
    if (!closed)
        lookup(observed.pid, timestamp, timestamp);
    std::lock_guard lock(mutex_);
    if (timestamp >= pruneUs_)
    {
        std::erase_if(connections_, [timestamp](const auto& item)
        {
            return item.second.events.empty() || timestamp - item.second.events.back().timestampUs > 180000000;
        });
        for (auto it = lifetimes_.begin(); it != lifetimes_.end();)
        {
            std::erase_if(it->second.entries, [&](const Lifetime& lifetime)
            {
                if (timestamp - std::max(lifetime.endedUs, lifetime.verifiedUs) < 180000000)
                    return false;
                it->second.discardedThroughUs = std::max(it->second.discardedThroughUs,
                    std::max(lifetime.endedUs, lifetime.verifiedUs));
                lifetimeBytes_ -= sizeof(Lifetime) - sizeof(Owner) + lifetime.owner.memory();
                return true;
            });
            if (it->second.entries.empty())
                it = lifetimes_.erase(it);
            else
                ++it;
        }
        pruneUs_ = timestamp + 1000000;
    }
    if (connections_.size() >= 65536 && !connections_.contains(key))
    {
        changesIncomplete_ = true;
        ++counters_.processEventsLost;
        return;
    }

    // Preserve closes that arrive before their opens, and never mutate another socket's lifetime.
    auto& history = connections_[key];
    auto& entries = history.events;
    if (!observed.id)
        history.incomplete[observed.local == key.a ? 0 : 1] = true;
    if (std::ranges::any_of(entries, [&](const SocketEvent& entry)
    {
        return entry.local == observed.local && entry.pid == observed.pid && entry.id == observed.id &&
            entry.timestampUs == timestamp && entry.closed == closed;
    }))
        return;

    // Preserve a close's matching-open evidence after bounded history discards the open.
    if (observed.closed)
        observed.matchedOpen = std::ranges::any_of(entries, [&](const SocketEvent& entry)
        {
            return !entry.closed && entry.local == observed.local && entry.pid == observed.pid &&
                entry.id == observed.id && entry.timestampUs <= timestamp;
        });
    else
        for (auto& entry : entries)
            if (entry.closed && entry.local == observed.local && entry.pid == observed.pid &&
                entry.id == observed.id && entry.timestampUs >= timestamp)
                entry.matchedOpen = true;
    const auto position = std::upper_bound(entries.begin(), entries.end(), timestamp,
        [](int64_t time, const SocketEvent& entry) { return time < entry.timestampUs; });
    entries.insert(position, observed);
    changed({.flow=key, .sinceUs=timestamp, .sides=static_cast<uint8_t>(observed.local == key.a ? 1 : 2)});
    if (entries.size() > 16)
    {
        // Discarded sockets still disprove ownership until their closes, even if only the open is removed.
        const auto& oldest = entries.front();
        const auto side = oldest.local == key.a ? 0 : 1;
        history.discardedThroughUs[side] = std::max(history.discardedThroughUs[side], oldest.timestampUs);

        // Losing an unresolved open must not turn a competing socket into a unique owner.
        if (!oldest.closed)
        {
            const auto closing = std::ranges::find_if(entries, [&](const SocketEvent& entry)
            {
                return entry.closed && entry.local == oldest.local && entry.pid == oldest.pid &&
                    entry.id == oldest.id && entry.timestampUs >= oldest.timestampUs;
            });
            if (closing == entries.end())
                history.incomplete[side] = true;
            else
                history.discardedThroughUs[side] = std::max(history.discardedThroughUs[side], closing->timestampUs);
        }
        entries.pop_front();
    }
}

void Processes::remember(Owner owner, int64_t endedUs, int64_t verifiedUs)
{
    if (!owner.pid || !owner.startedUs || (endedUs && endedUs < owner.startedUs))
        return;
    std::lock_guard lock(mutex_);
    auto bytes = sizeof(Lifetime) - sizeof(Owner) + owner.memory();
    auto& recorded = lifetimes_[owner.pid];
    auto& history = recorded.entries;
    for (auto& lifetime : history)
    {
        if (lifetime.owner.startedUs != owner.startedUs)
            continue;
        if (endedUs && (!lifetime.endedUs || endedUs < lifetime.endedUs))
        {
            changed({.pid=owner.pid, .sinceUs=endedUs});
            lifetime.endedUs = lifetime.endedUs ? std::min(lifetime.endedUs, endedUs) : endedUs;
        }
        lifetime.verifiedUs = std::max(lifetime.verifiedUs, verifiedUs);

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
    if (lifetimeBytes_ + bytes > 32 * 1024 * 1024 || lifetimes_.size() > 8192)
    {
        changed({.pid=owner.pid, .sinceUs=owner.startedUs});
        if (history.empty())
            lifetimes_.erase(owner.pid);
        else
        {
            // Dropping a process instance cannot make an older identity appear unique after PID reuse.
            recorded.incompleteFromUs = recorded.incompleteFromUs ?
                std::min(recorded.incompleteFromUs, owner.startedUs) : owner.startedUs;
        }
        ++counters_.processEventsLost;
        return;
    }
    verifiedUs = std::max(owner.startedUs, verifiedUs);
    changed({.pid=owner.pid, .sinceUs=owner.startedUs});
    const auto position = std::upper_bound(history.begin(), history.end(), owner.startedUs,
        [](int64_t time, const Lifetime& lifetime) { return time < lifetime.owner.startedUs; });
    history.insert(position, {std::move(owner), endedUs, verifiedUs});
    lifetimeBytes_ += bytes;
    if (history.size() > 4)
    {
        // Preserve the interval where a discarded process instance can still contradict a surviving one.
        const auto& oldest = history.front();
        recorded.discardedThroughUs = std::max(recorded.discardedThroughUs,
            std::max(oldest.endedUs, oldest.verifiedUs));
        lifetimeBytes_ -= sizeof(Lifetime) - sizeof(Owner) + oldest.owner.memory();
        history.pop_front();
    }
}

void Processes::changed(OwnerChange change)
{
    // Callers hold the evidence mutex; coalesce notifications without retaining observation payloads.
    if (change.flow)
    {
        const auto found = changedConnections_.find(*change.flow);
        if (found == changedConnections_.end() && changedSockets_ + changedProcesses_.size() >= 8192)
        {
            changesIncomplete_ = true;
            ++counters_.processEventsLost;
            return;
        }
        auto& endpoints = changedConnections_[*change.flow];
        for (int side = 0; side < 2; ++side)
            if (change.sides & (1 << side))
            {
                auto& since = endpoints[side];
                if (since)
                    since = std::min(*since, change.sinceUs);
                else if (changedSockets_ + changedProcesses_.size() < 8192)
                {
                    since = change.sinceUs;
                    ++changedSockets_;
                }
                else
                {
                    changesIncomplete_ = true;
                    ++counters_.processEventsLost;
                }
            }
    }
    else
    {
        const auto found = changedProcesses_.find(change.pid);
        if (found != changedProcesses_.end())
            found->second = std::min(found->second, change.sinceUs);
        else if (changedSockets_ + changedProcesses_.size() < 8192)
            changedProcesses_.emplace(change.pid, change.sinceUs);
        else
        {
            changesIncomplete_ = true;
            ++counters_.processEventsLost;
        }
    }
}

std::vector<OwnerChange> Processes::changes()
{
    std::lock_guard lock(mutex_);
    std::vector<OwnerChange> result;
    if (changesIncomplete_)
    {
        // Lost notifications cannot leave an identity whose contradicting evidence was not revisited.
        result.push_back({});
    }
    else
    {
        result.reserve(changedSockets_ + changedProcesses_.size());
        for (const auto& [flow, endpoints] : changedConnections_)
            for (int side = 0; side < 2; ++side)
                if (endpoints[side])
                    result.push_back({.flow=flow, .sinceUs=*endpoints[side], .sides=static_cast<uint8_t>(1 << side)});
        for (const auto& [pid, since] : changedProcesses_)
            result.push_back({.pid=pid, .sinceUs=since});
    }
    changedConnections_.clear();
    changedSockets_ = 0;
    changedProcesses_.clear();
    changesIncomplete_ = false;
    return result;
}

void Processes::evidenceLost()
{
    std::lock_guard lock(mutex_);
    changesIncomplete_ = true;
    const auto until = nowUs();

    // A missing close or process instance leaves existing socket and PID lifetime associations incomplete.
    for (auto& [key, history] : connections_)
        history.incomplete[0] = history.incomplete[1] = true;
    for (auto& [pid, history] : lifetimes_)
        history.discardedThroughUs = std::max(history.discardedThroughUs, until);
}

void Processes::recheck(Observation& observation)
{
    const auto source = std::pair{observation.sourceOwner.pid, observation.sourceOwner.startedUs};
    const auto destination = std::pair{observation.destinationOwner.pid, observation.destinationOwner.startedUs};
    enrich(observation);

    // Preserve endpoints outside this correction's scope, including peers whose retained history has expired.
    auto validate = [&](const auto& previous, Owner& owner, uint8_t side)
    {
        if (!(observation.ownerSides & side))
        {
            owner = {};
            return;
        }
        if (previous.first && !owner.pid && !owner.ambiguous)
        {
            const auto lifetime = lookup(previous.first, observation.firstUs, observation.lastUs);
            if (lifetime.ambiguous || lifetime.startedUs != previous.second)
                owner.ambiguous = true;
        }
    };
    validate(source, observation.sourceOwner, 1);
    validate(destination, observation.destinationOwner, 2);
}

Owner Processes::lookup(uint32_t pid, int64_t firstUs, int64_t lastUs)
{
    auto known = [&]() -> Owner
    {
        std::lock_guard lock(mutex_);
        const auto found = lifetimes_.find(pid);
        const Lifetime* candidate = nullptr;
        size_t matches = 0;
        if (found != lifetimes_.end() &&
            ((found->second.discardedThroughUs && firstUs <= found->second.discardedThroughUs) ||
                (found->second.incompleteFromUs && lastUs >= found->second.incompleteFromUs)))
            return {.ambiguous=true};
        if (found != lifetimes_.end())
            for (const auto& lifetime : found->second.entries)
            {
                const auto until = lifetime.endedUs ? lifetime.endedUs : lifetime.verifiedUs;
                if (lifetime.owner.startedUs > lastUs || until < firstUs ||
                    (lifetime.endedUs && lifetime.endedUs <= firstUs))
                    continue;
                ++matches;
                if (lifetime.owner.startedUs <= firstUs && until >= lastUs &&
                    (!lifetime.endedUs || lastUs < lifetime.endedUs))
                    candidate = &lifetime;
            }

        // A recycled PID cannot belong to an older instance, even when the newer one lacks a verified end.
        if (matches != 1 || !candidate || std::ranges::any_of(found->second.entries, [&](const Lifetime& lifetime)
        {
            return lifetime.owner.startedUs > candidate->owner.startedUs && lifetime.owner.startedUs <= lastUs;
        }))
            return {.ambiguous=true};
        auto owner = candidate->owner;
        owner.evidence = "ETW connection";
        return owner;
    };
    auto owner = known();
    if (owner.pid)
        return owner;

    // An open cached lifetime is valid only through a time when that process instance was seen alive.
    const auto verified = nowUs();
    owner = describe(pid, verified, "ETW connection");
    remember(std::move(owner), 0, verified);
    return known();
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
        evidenceLost();
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
            evidenceLost();
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
    // Seed process ownership from both IP families before processing live updates.
    const auto timestamp = nowUs();
    if (timestamp - snapshotUs_ < 500000)
        return;
    snapshot_.clear();
    snapshotUs_ = timestamp;
    std::unordered_map<uint32_t, Owner> owners;
    for (const auto family : {AF_INET, AF_INET6})
    {
        const auto buffer = ownershipTable([family](void* table, ULONG* size)
        {
            return GetExtendedTcpTable(table, size, FALSE, family, TCP_TABLE_OWNER_MODULE_ALL, 0);
        }, 64 * 1024 * 1024);
        if (buffer.empty())
        {
            ++counters_.processEventsLost;
            continue;
        }
        auto add = [&](Endpoint local, Endpoint remote, uint32_t pid, DWORD state, int64_t created)
        {
            if (!pid || !remote.port || state == MIB_TCP_STATE_LISTEN || state == MIB_TCP_STATE_TIME_WAIT)
                return;
            if (snapshot_.size() >= 65536)
                return;
            auto [it, inserted] = owners.try_emplace(pid);
            if (inserted)
            {
                it->second = describe(pid, timestamp, "TCP table snapshot");
                remember(it->second, 0, timestamp);
            }
            snapshot_[FlowKey::make(local, remote)].push_back(
                {local, it->second, created > FileTimeEpoch ? (created - FileTimeEpoch) / 10 : 0, timestamp});
        };
        auto row = [&](const auto& entry)
        {
            add(tableEndpoint(entry.dwLocalAddr, entry.dwLocalPort),
                tableEndpoint(entry.dwRemoteAddr, entry.dwRemotePort), entry.dwOwningPid, entry.dwState,
                entry.liCreateTimestamp.QuadPart);
        };
        auto row6 = [&](const auto& entry)
        {
            add(tableEndpoint(entry.ucLocalAddr, entry.dwLocalPort),
                tableEndpoint(entry.ucRemoteAddr, entry.dwRemotePort), entry.dwOwningPid, entry.dwState,
                entry.liCreateTimestamp.QuadPart);
        };
        if (family == AF_INET)
            tableRows<MIB_TCPTABLE_OWNER_MODULE>(buffer, row);
        else
            tableRows<MIB_TCP6TABLE_OWNER_MODULE>(buffer, row6);
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
            const auto buffer = ownershipTable([family](void* table, ULONG* size)
            {
                return GetExtendedUdpTable(table, size, FALSE, family, UDP_TABLE_OWNER_MODULE, 0);
            }, 16 * 1024 * 1024);
            if (buffer.empty())
            {
                ++counters_.processEventsLost;
                continue;
            }
            auto add = [&](Endpoint local, uint32_t pid, int64_t created)
            {
                if (!pid || !local.port || udpSnapshot_.size() >= 65536)
                    return;
                auto [found, inserted] = owners.try_emplace(pid);
                if (inserted)
                {
                    found->second = describe(pid, timestamp, "UDP binding snapshot; peer not confirmed");
                    remember(found->second, 0, timestamp);
                }
                udpSnapshot_.push_back({local, found->second,
                    created > FileTimeEpoch ? (created - FileTimeEpoch) / 10 : 0, timestamp});
            };
            if (family == AF_INET)
                tableRows<MIB_UDPTABLE_OWNER_MODULE>(buffer, [&](const MIB_UDPROW_OWNER_MODULE& entry)
                    { add(tableEndpoint(entry.dwLocalAddr, entry.dwLocalPort), entry.dwOwningPid,
                        entry.liCreateTimestamp.QuadPart); });
            else
                tableRows<MIB_UDP6TABLE_OWNER_MODULE>(buffer, [&](const MIB_UDP6ROW_OWNER_MODULE& entry)
                    { add(tableEndpoint(entry.ucLocalAddr, entry.dwLocalPort), entry.dwOwningPid,
                        entry.liCreateTimestamp.QuadPart); });
        }
    }
    if (udpSnapshotUs_ < observation.lastUs || udpSnapshotUs_ - observation.lastUs > 5000000)
        return;

    // A shared UDP binding is ambiguous; assign an owner only when every matching binding agrees.
    for (const auto* endpoint : {&observation.source, &observation.destination})
    {
        const bool localAddress = std::ranges::any_of(udpAddresses_, [&](const Endpoint& address)
        {
            return address.family == endpoint->family && address.address == endpoint->address;
        });
        const Owner* candidate = nullptr;
        auto firstUs = observation.firstUs;
        bool ambiguous = false;
        for (const auto& binding : udpSnapshot_)
        {
            if (binding.local.family != endpoint->family || binding.local.port != endpoint->port ||
                (binding.local.address != endpoint->address &&
                    (!localAddress ||
                        !std::ranges::all_of(binding.local.address, [](uint8_t byte) { return byte == 0; }))))
                continue;
            if (!binding.startUs || binding.startUs > observation.firstUs ||
                binding.endUs < observation.lastUs || !binding.owner.startedUs ||
                binding.owner.startedUs > binding.startUs || (candidate &&
                    (candidate->pid != binding.owner.pid || candidate->startedUs != binding.owner.startedUs)))
                ambiguous = true;
            candidate = &binding.owner;
            firstUs = std::min(firstUs, binding.startUs);
        }
        auto& owner = endpoint == &observation.source ? observation.sourceOwner : observation.destinationOwner;
        if (ambiguous)
            owner.ambiguous = true;
        else if (candidate)
        {
            // Process events can contradict an identity cached in the binding snapshot.
            const auto lifetime = lookup(candidate->pid, firstUs, observation.lastUs);
            owner = !lifetime.ambiguous && lifetime.startedUs == candidate->startedUs ?
                *candidate : Owner{.ambiguous=true};
        }
    }
}

void Processes::enrich(Observation& observation)
{
    if (observation.protocol == Observation::Protocol::Ipsec)
        return;
    observation.sourceOwner = {};
    observation.destinationOwner = {};
    if (observation.quic || observation.udp)
    {
        udpOwner(observation);
        return;
    }
    const auto key = FlowKey::make(observation.source, observation.destination);
    std::vector<SocketEvent> history;
    bool incomplete[2]{};
    {
        std::lock_guard lock(mutex_);
        if (const auto found = connections_.find(key); found != connections_.end())
        {
            const auto& recorded = found->second;
            history.assign(recorded.events.begin(), recorded.events.end());
            for (int side = 0; side < 2; ++side)
            {
                const auto index = (side ? observation.destination : observation.source) == key.a ? 0 : 1;
                incomplete[side] = recorded.incomplete[index] || (recorded.discardedThroughUs[index] &&
                    observation.firstUs <= recorded.discardedThroughUs[index]);
            }
        }
    }
    bool known[2]{};
    for (int side = 0; side < 2; ++side)
    {
        const auto& endpoint = side ? observation.destination : observation.source;
        auto& owner = side ? observation.destinationOwner : observation.sourceOwner;
        const SocketEvent* candidate = nullptr;
        size_t matches = 0;
        int64_t unmatchedCloseUs = 0;
        bool interrupted = incomplete[side];
        known[side] = incomplete[side];
        for (const auto& opened : history)
        {
            if (opened.local != endpoint)
                continue;
            known[side] = true;
            if (opened.closed)
            {
                interrupted |= opened.timestampUs >= observation.firstUs && opened.timestampUs <= observation.lastUs;

                // A missing open leaves the lifetime before its close unknown, contradicting an older socket.
                if (!opened.matchedOpen && opened.timestampUs <= observation.lastUs)
                    unmatchedCloseUs = std::max(unmatchedCloseUs, opened.timestampUs);
                continue;
            }
            if (opened.timestampUs > observation.lastUs)
                continue;

            // Connection IDs distinguish a delayed close from a later socket using the same tuple and PID.
            int64_t ended = 0;
            for (const auto& closed : history)
                if (closed.closed && closed.local == endpoint && closed.pid == opened.pid &&
                    closed.id == opened.id &&
                    closed.timestampUs >= opened.timestampUs)
                {
                    ended = closed.timestampUs;
                    break;
                }
            if (ended && ended <= observation.firstUs)
                continue;
            ++matches;
            if (!ended || observation.lastUs < ended)
                candidate = &opened;
        }
        if (known[side])
        {
            owner = !interrupted && matches == 1 && candidate &&
                (!unmatchedCloseUs || candidate->timestampUs > unmatchedCloseUs) ? lookup(candidate->pid,
                std::min(observation.firstUs, candidate->timestampUs), observation.lastUs) : Owner{.ambiguous=true};
        }
    }
    if ((known[0] && known[1]) || nowUs() - observation.lastUs > 5000000)
        return;

    // A table fallback must prove the socket existed throughout the observation, without overriding ETW conflicts.
    snapshot();
    const auto found = snapshot_.find(key);
    if (found == snapshot_.end() || snapshotUs_ < observation.lastUs ||
        snapshotUs_ - observation.lastUs > 5000000)
        return;
    for (int side = 0; side < 2; ++side)
    {
        if (known[side])
            continue;
        const auto& endpoint = side ? observation.destination : observation.source;
        auto& owner = side ? observation.destinationOwner : observation.sourceOwner;
        const Connection* candidate = nullptr;
        size_t matches = 0;
        for (const auto& connection : found->second)
            if (connection.local == endpoint)
            {
                ++matches;
                candidate = &connection;
            }
        if (!matches)
            continue;
        if (matches != 1 || !candidate->startUs || candidate->startUs > observation.firstUs ||
            candidate->endUs < observation.lastUs || !candidate->owner.startedUs ||
            candidate->owner.startedUs > candidate->startUs)
            owner.ambiguous = true;
        else
        {
            const auto lifetime = lookup(candidate->owner.pid, candidate->startUs, observation.lastUs);
            owner = !lifetime.ambiguous && lifetime.startedUs == candidate->owner.startedUs ?
                candidate->owner : Owner{.ambiguous=true};
        }
    }
}
}
