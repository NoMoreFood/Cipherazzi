#pragma once

#include "Proxy.h"
#include "Processes.h"
#include <ws2tcpip.h>
#include <windivert.h>
#include <iphlpapi.h>

namespace Cipherazzi
{
static Endpoint endpoint(const sockaddr_storage& address)
{
    Endpoint result;
    if (address.ss_family == AF_INET)
    {
        const auto& ip = reinterpret_cast<const sockaddr_in&>(address);
        memcpy(result.address.data(), &ip.sin_addr, 4);
        result.port = ntohs(ip.sin_port);
    }
    else
    {
        const auto& ip = reinterpret_cast<const sockaddr_in6&>(address);
        result.family = IN6_IS_ADDR_V4MAPPED(&ip.sin6_addr) ? 4 : 6;
        memcpy(result.address.data(), ip.sin6_addr.u.Byte + (result.family == 4 ? 12 : 0),
            result.family == 4 ? 4 : 16);
        result.port = ntohs(ip.sin6_port);
    }
    return result;
}

static sockaddr_storage socketAddress(Endpoint endpoint, uint32_t interfaceIndex = 0)
{
    sockaddr_storage result{};
    if (endpoint.family == 4)
    {
        auto& ip = reinterpret_cast<sockaddr_in&>(result);
        ip.sin_family = AF_INET;
        memcpy(&ip.sin_addr, endpoint.address.data(), 4);
        ip.sin_port = htons(endpoint.port);
    }
    else
    {
        auto& ip = reinterpret_cast<sockaddr_in6&>(result);
        ip.sin6_family = AF_INET6;
        memcpy(&ip.sin6_addr, endpoint.address.data(), 16);
        ip.sin6_port = htons(endpoint.port);
        if (IN6_IS_ADDR_LINKLOCAL(&ip.sin6_addr))
            ip.sin6_scope_id = interfaceIndex;
    }
    return result;
}

// Socket ownership is already assigned when its SYN reaches the network layer; unknown owners are left alone.
static Owner socketOwner(Endpoint client, Endpoint server)
{
    const auto family = client.family == 4 ? AF_INET : AF_INET6;
    ULONG size{};
    if (GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return {};
    std::vector<uint8_t> data(size);
    if (GetExtendedTcpTable(data.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return {};
    uint32_t pid{};
    if (family == AF_INET)
    {
        const auto& table = *reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(data.data());
        for (DWORD index = 0; index < table.dwNumEntries; ++index)
        {
            const auto& row = table.table[index];
            if (row.dwLocalPort == htons(client.port) && row.dwRemotePort == htons(server.port) &&
                memcmp(&row.dwLocalAddr, client.address.data(), 4) == 0 &&
                memcmp(&row.dwRemoteAddr, server.address.data(), 4) == 0)
            { pid = row.dwOwningPid; break; }
        }
    }
    else
    {
        const auto& table = *reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(data.data());
        for (DWORD index = 0; index < table.dwNumEntries; ++index)
        {
            const auto& row = table.table[index];
            if (row.dwLocalPort == htons(client.port) && row.dwRemotePort == htons(server.port) &&
                memcmp(row.ucLocalAddr, client.address.data(), 16) == 0 &&
                memcmp(row.ucRemoteAddr, server.address.data(), 16) == 0)
            { pid = row.dwOwningPid; break; }
        }
    }
    return pid ? Processes::describe(pid, nowUs(), "HTTP Spy target") : Owner{};
}

// Flow table entry: the original server destination of a redirected connection.
struct FlowEntry
{
    Endpoint server;
    uint32_t interfaceIndex{};
    uint64_t lastMs{};
    bool held{};
};

class FlowTable
{
public:
    // Admission is bounded; a connection that finds the table full is left uninspected.
    bool add(Endpoint client, FlowEntry entry)
    {
        std::lock_guard lock(mutex_);
        const auto key = pack(client, entry.server);
        if (const auto previous = entries_.find(key); previous != entries_.end() &&
            previous->second.server != entry.server)
            return false;
        if (entries_.size() >= MaximumEntries && !entries_.contains(key))
            return false;
        entry.lastMs = GetTickCount64();
        entries_[key] = entry;
        return true;
    }

    // A connection handler holds its entry so that a long idle period cannot expire it.
    std::optional<FlowEntry> lookup(Endpoint client, Endpoint server, bool hold = false)
    {
        std::lock_guard lock(mutex_);
        if (auto it = entries_.find(pack(client, server)); it != entries_.end())
        {
            if (server.port && server.port != it->second.server.port)
                return {};
            it->second.lastMs = GetTickCount64();
            it->second.held |= hold;
            return it->second;
        }
        return {};
    }

    void release(Endpoint client, Endpoint server)
    {
        std::lock_guard lock(mutex_);
        if (auto it = entries_.find(pack(client, server)); it != entries_.end())
        {
            it->second.lastMs = GetTickCount64();
            it->second.held = false;
        }
    }

    void ignore(Endpoint client, Endpoint server)
    {
        std::lock_guard lock(mutex_);
        entries_.erase(pack(client, server));
    }

    // Closed connections keep their entry while trailing packets and retransmissions drain.
    void expire()
    {
        std::lock_guard lock(mutex_);
        const auto now = GetTickCount64();
        std::erase_if(entries_, [now](const auto& item)
        { return !item.second.held && now - item.second.lastMs > 150000; });
    }

private:
    static constexpr size_t MaximumEntries = 65536;
    static FlowKey pack(Endpoint client, Endpoint server) { server.port = 0; return {client, server}; }
    std::mutex mutex_;
    std::unordered_map<FlowKey, FlowEntry, FlowHash> entries_;
};

// Server addresses whose connections could not be intercepted, such as pinned or mutually authenticated clients.
// Their next connections go straight to the server, which keeps those applications working.
class Bypass
{
public:
    void add(Endpoint server)
    {
        std::lock_guard lock(mutex_);
        if (until_.size() >= 4096)
            until_.clear();
        until_[{Endpoint{}, server}] = GetTickCount64() + 300000;
    }

    bool contains(Endpoint server)
    {
        std::lock_guard lock(mutex_);
        const auto it = until_.find({Endpoint{}, server});
        if (it == until_.end())
            return false;
        if (GetTickCount64() < it->second)
            return true;
        until_.erase(it);
        return false;
    }

private:
    std::mutex mutex_;
    std::unordered_map<FlowKey, uint64_t, FlowHash> until_;
};

}
