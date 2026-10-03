#include "Proxy.h"
#include <charconv>
#include <cctype>
#include <stdexcept>

namespace Cipherazzi
{
// Match wildcard names without regular-expression backtracking.
static bool wildcard(std::string_view pattern, std::string_view value)
{
    size_t p = 0, v = 0, star = std::string_view::npos, retry = 0;
    while (v < value.size())
    {
        if (p < pattern.size() && (pattern[p] == '?' ||
            std::tolower(static_cast<unsigned char>(pattern[p])) ==
                std::tolower(static_cast<unsigned char>(value[v]))))
        { ++p; ++v; }
        else if (p < pattern.size() && pattern[p] == '*')
        { star = p++; retry = v; }
        else if (star != std::string_view::npos)
        { p = star + 1; v = ++retry; }
        else
            return false;
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

bool ProxyTargets::host(std::string_view value) const
{
    return hosts.empty() || std::ranges::any_of(hosts, [&](const auto& pattern) { return wildcard(pattern, value); });
}

bool ProxyTargets::process(uint32_t pid, std::string_view name) const
{
    return processes.empty() || std::ranges::any_of(processes, [&](const auto& value)
    {
        uint32_t wanted{};
        const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), wanted);
        if (error == std::errc{} && end == value.data() + value.size())
            return pid && pid == wanted;
        return !name.empty() && (wildcard(value, name) || wildcard(value + ".exe", name));
    });
}

void ProxyTargets::setPorts(std::string_view value)
{
    std::vector<uint16_t> parsed;
    while (!value.empty())
    {
        const auto comma = value.find(',');
        const auto part = value.substr(0, comma);
        unsigned port{};
        const auto [end, error] = std::from_chars(part.data(), part.data() + part.size(), port);
        if (error != std::errc{} || end != part.data() + part.size() || !port || port > 65535 || parsed.size() >= 128)
            throw std::runtime_error("Use comma-separated HTTPS ports from 1 to 65535 (at most 128)");
        if (std::ranges::find(parsed, port) == parsed.end())
            parsed.push_back(static_cast<uint16_t>(port));
        if (comma == std::string_view::npos)
            break;
        value.remove_prefix(comma + 1);
        if (value.empty())
            throw std::runtime_error("An HTTPS port is missing after the comma");
    }
    if (parsed.empty())
        throw std::runtime_error("Supply at least one HTTPS port");
    ports = std::move(parsed);
}
}
