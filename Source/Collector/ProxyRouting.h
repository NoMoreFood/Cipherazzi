#pragma once

#include "Proxy.h"
#include "Processes.h"
#include <ws2tcpip.h>
#include <windivert.h>
#include <iphlpapi.h>
#include <netfw.h>
#include <wrl/client.h>
#include <cwchar>
#include <string_view>

namespace Cipherazzi
{
// Reflected outbound connections arrive through the local listener's inbound firewall policy.
static void proxyListenerFirewall(std::wstring& name, const std::wstring& executable, uint16_t port, bool allow)
{
    if (!allow && name.empty())
        return;
    const auto apartment = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    auto require = [](HRESULT result)
    {
        if (FAILED(result))
            throw std::runtime_error("Could not configure the HTTP Spy listener in Windows Firewall");
    };
    try
    {
        if (apartment != RPC_E_CHANGED_MODE)
            require(apartment);
        Microsoft::WRL::ComPtr<INetFwPolicy2> policy;
        require(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(policy.GetAddressOf())));
        Microsoft::WRL::ComPtr<INetFwRules> rules;
        require(policy->get_Rules(rules.GetAddressOf()));
        if (allow)
            name = L"Cipherazzi HTTP Spy " + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(port);
        const auto makeString = [](const std::wstring& value)
        {
            std::unique_ptr<wchar_t, decltype(&SysFreeString)> text(SysAllocString(value.c_str()), SysFreeString);
            if (!text)
                throw std::bad_alloc();
            return text;
        };
        const auto ruleName = makeString(name);
        if (allow)
        {
            // Persistent rules survive abrupt exits; leave live or inaccessible owners and other policy untouched.
            Microsoft::WRL::ComPtr<IUnknown> collection;
            Microsoft::WRL::ComPtr<IEnumVARIANT> iterator;
            require(rules->get__NewEnum(collection.GetAddressOf()));
            require(collection.As(&iterator));
            std::vector<std::wstring> abandoned;
            VARIANT item{};
            HRESULT next;
            ULONG fetched{};
            while ((next = iterator->Next(1, &item, &fetched)) == S_OK && fetched)
            {
                Microsoft::WRL::ComPtr<INetFwRule> existing;
                if (item.vt == VT_DISPATCH && item.pdispVal)
                    item.pdispVal->QueryInterface(IID_PPV_ARGS(existing.GetAddressOf()));
                VariantClear(&item);
                if (!existing)
                    continue;
                BSTR rawName{};
                const auto named = existing->get_Name(&rawName);
                std::unique_ptr<wchar_t, decltype(&SysFreeString)> previousName(rawName, SysFreeString);
                constexpr std::wstring_view prefix = L"Cipherazzi HTTP Spy ";
                if (FAILED(named) || !rawName || !std::wstring_view(rawName).starts_with(prefix))
                    continue;
                wchar_t* end{};
                const auto pid = std::wcstoul(rawName + prefix.size(), &end, 10);
                if (!pid || *end != L'-')
                    continue;
                const auto previousPort = std::wcstoul(end + 1, &end, 10);
                if (*end || !previousPort || previousPort > 65535 || std::wstring_view(rawName) !=
                    std::wstring(prefix) + std::to_wstring(pid) + L"-" + std::to_wstring(previousPort))
                    continue;
                BSTR rawApplication{}, rawPorts{};
                const auto applicationResult = existing->get_ApplicationName(&rawApplication);
                std::unique_ptr<wchar_t, decltype(&SysFreeString)> application(rawApplication, SysFreeString);
                const auto portsResult = existing->get_LocalPorts(&rawPorts);
                std::unique_ptr<wchar_t, decltype(&SysFreeString)> ports(rawPorts, SysFreeString);
                long protocol{}, profiles{};
                NET_FW_RULE_DIRECTION direction{};
                NET_FW_ACTION action{};
                if (FAILED(applicationResult) || !rawApplication || _wcsicmp(rawApplication, executable.c_str()) ||
                    FAILED(portsResult) || !rawPorts || rawPorts != std::to_wstring(previousPort) ||
                    FAILED(existing->get_Protocol(&protocol)) || protocol != IPPROTO_TCP ||
                    FAILED(existing->get_Direction(&direction)) || direction != NET_FW_RULE_DIR_IN ||
                    FAILED(existing->get_Action(&action)) || action != NET_FW_ACTION_ALLOW ||
                    FAILED(existing->get_Profiles(&profiles)) || profiles != NET_FW_PROFILE2_ALL)
                    continue;
                std::unique_ptr<void, decltype(&CloseHandle)> owner(
                    OpenProcess(SYNCHRONIZE, FALSE, pid), CloseHandle);
                if ((!owner && GetLastError() == ERROR_INVALID_PARAMETER) ||
                    (owner && WaitForSingleObject(owner.get(), 0) == WAIT_OBJECT_0))
                    abandoned.emplace_back(rawName);
            }
            require(next);
            for (const auto& previous : abandoned)
            {
                const auto staleName = makeString(previous);
                rules->Remove(staleName.get());
            }

            // Scope the exception to this executable and its currently bound TCP listener.
            Microsoft::WRL::ComPtr<INetFwRule> rule;
            require(CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                IID_PPV_ARGS(rule.GetAddressOf())));
            const auto application = makeString(executable), ports = makeString(std::to_wstring(port));
            require(rule->put_Name(ruleName.get()));
            require(rule->put_ApplicationName(application.get()));
            require(rule->put_Protocol(IPPROTO_TCP));
            require(rule->put_LocalPorts(ports.get()));
            require(rule->put_Direction(NET_FW_RULE_DIR_IN));
            require(rule->put_Action(NET_FW_ACTION_ALLOW));
            require(rule->put_Profiles(NET_FW_PROFILE2_ALL));
            require(rule->put_Enabled(VARIANT_TRUE));
            require(rules->Add(rule.Get()));
        }
        else
        {
            require(rules->Remove(ruleName.get()));
            name.clear();
        }
    }
    catch (...)
    {
        if (SUCCEEDED(apartment))
            CoUninitialize();
        if (allow)
            throw;
        return;
    }
    if (SUCCEEDED(apartment))
        CoUninitialize();
}

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
    ULONG size = 16384;
    std::vector<uint8_t> data(size);
    DWORD status = GetExtendedTcpTable(data.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    while (status == ERROR_INSUFFICIENT_BUFFER)
    {
        data.resize(size);
        status = GetExtendedTcpTable(data.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    if (status != NO_ERROR)
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
    if (!pid)
        return {};
    Owner owner;
    owner.pid = pid;
    std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)> process(
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid), CloseHandle);
    if (process)
    {
        std::wstring path(1024, L'\0');
        DWORD pathSize = static_cast<DWORD>(path.size());
        if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &pathSize))
        {
            path.resize(pathSize);
            owner.path = utf8(path);
            owner.name = utf8(std::filesystem::path(path).filename().wstring());
        }
    }
    return owner;
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
        {
            const auto now = GetTickCount64();
            std::erase_if(until_, [&](const auto& entry) { return entry.second <= now; });
            if (until_.size() >= 4096)
                until_.erase(until_.begin());
        }
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
