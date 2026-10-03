#include "Model.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstdio>

namespace Cipherazzi
{
size_t Owner::memory() const
{
    return sizeof(*this) + name.capacity() + path.capacity() + evidence.capacity() +
        account.capacity() + accountDomain.capacity() + accountSid.capacity();
}

size_t EndpointEvent::memory() const
{
    size_t bytes = sizeof(*this) + (report ? report->memory() : 0);
    for (const auto* value : {&id, &provider, &kind, &result, &peer, &protocol, &cipher, &certificateId, &detail})
        bytes += value->capacity() + 1;
    return bytes;
}

std::string Endpoint::text() const
{
    char buffer[INET6_ADDRSTRLEN]{};
    InetNtopA(family == 4 ? AF_INET : AF_INET6, address.data(), buffer, sizeof(buffer));
    return buffer;
}

FlowKey FlowKey::make(Endpoint source, Endpoint destination)
{
    return source < destination ? FlowKey{source, destination} : FlowKey{destination, source};
}

size_t FlowHash::operator()(const FlowKey& key) const noexcept
{
    // Mix only initialized address fields so hashing does not depend on padding.
    uint64_t hash = 14695981039346656037ULL;
    for (const auto* endpoint : {&key.a, &key.b})
    {
        for (const auto byte : endpoint->address)
            hash = (hash ^ byte) * 1099511628211ULL;
        hash = (hash ^ endpoint->port) * 1099511628211ULL;
        hash = (hash ^ endpoint->family) * 1099511628211ULL;
    }
    return static_cast<size_t>(hash);
}

uint16_t be16(Bytes bytes, size_t offset)
{
    return static_cast<uint16_t>((bytes[offset] << 8) | bytes[offset + 1]);
}

uint32_t be32(Bytes bytes, size_t offset)
{
    return (static_cast<uint32_t>(be16(bytes, offset)) << 16) | be16(bytes, offset + 2);
}

std::string hex16(uint16_t value)
{
    char buffer[7]{};
    sprintf_s(buffer, "0x%04X", value);
    return buffer;
}

std::string versionName(uint16_t version)
{
    switch (version)
    {
    case 0: return "";
    case 0x0300: return "SSL 3.0";
    case 0x0301: return "TLS 1.0";
    case 0x0302: return "TLS 1.1";
    case 0x0303: return "TLS 1.2";
    case 0x0304: return "TLS 1.3";
    case 0xfeff: return "DTLS 1.0";
    case 0xfefd: return "DTLS 1.2";
    case 0xfefc: return "DTLS 1.3";
    default: return hex16(version);
    }
}

std::string utf8(std::wstring_view value)
{
    if (value.empty())
        return {};
    const auto size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
        result.data(), size, nullptr, nullptr);
    return result;
}

int64_t nowUs()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}
}
