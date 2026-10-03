#include "Cleartext.h"
#include "Auth.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <string_view>

namespace Cipherazzi
{
namespace CleartextDetail
{
std::string_view view(Bytes bytes)
{
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

bool starts(std::string_view text, std::string_view prefix)
{
    return text.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), text.begin(),
        [](char left, char right) { return std::toupper(static_cast<unsigned char>(left)) ==
            std::toupper(static_cast<unsigned char>(right)); });
}

std::string_view trim(std::string_view text)
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.remove_suffix(1);
    return text;
}

std::vector<uint8_t> decodeBase64(std::string_view value)
{
    // Validate complete base64 groups and their padding before decoding.
    if (value.empty() || value.size() > 32768 || value.size() % 4 == 1)
        return {};
    std::string padded(value);
    padded.append((4 - padded.size() % 4) % 4, '=');
    value = padded;
    std::vector<uint8_t> decoded;
    decoded.reserve(value.size() / 4 * 3);
    for (size_t offset = 0; offset < value.size(); offset += 4)
    {
        uint32_t bits = 0;
        int padding = 0;
        for (size_t index = 0; index < 4; ++index)
        {
            const auto character = value[offset + index];
            const int digit = character >= 'A' && character <= 'Z' ? character - 'A' :
                character >= 'a' && character <= 'z' ? character - 'a' + 26 :
                character >= '0' && character <= '9' ? character - '0' + 52 :
                character == '+' ? 62 : character == '/' ? 63 : -1;
            if (character == '=')
            {
                if (offset + 4 != value.size() || index < 2)
                    return {};
                ++padding;
                bits <<= 6;
            }
            else
            {
                if (digit < 0 || padding)
                    return {};
                bits = (bits << 6) | static_cast<unsigned>(digit);
            }
        }
        if ((padding == 1 && (bits & 0xff) != 0) || (padding == 2 && (bits & 0xffff) != 0))
            return {};
        decoded.push_back(static_cast<uint8_t>(bits >> 16));
        if (padding < 2)
            decoded.push_back(static_cast<uint8_t>(bits >> 8));
        if (!padding)
            decoded.push_back(static_cast<uint8_t>(bits));
    }
    return decoded;
}

bool plainCredentials(std::string_view value)
{
    const auto decoded = decodeBase64(value);
    const auto first = std::find(decoded.begin(), decoded.end(), 0);
    if (first == decoded.end())
        return false;
    const auto second = std::find(first + 1, decoded.end(), 0);
    return second != decoded.end() && second != first + 1;
}

bool hasArguments(std::string_view text, int needed)
{
    // Count protocol arguments while respecting quoted and escaped text.
    int count = 0;
    while (!text.empty())
    {
        text = trim(text);
        if (text.empty())
            break;
        if (text.front() == '"')
        {
            text.remove_prefix(1);
            bool closed = false;
            while (!text.empty())
            {
                const char value = text.front();
                text.remove_prefix(1);
                if (value == '\\' && !text.empty())
                    text.remove_prefix(1);
                else if (value == '"')
                {
                    closed = true;
                    break;
                }
            }
            if (!closed || (!text.empty() && text.front() != ' ' && text.front() != '\t'))
                return false;
        }
        else
        {
            const auto end = text.find_first_of(" \t");
            text.remove_prefix(end == std::string_view::npos ? text.size() : end);
        }
        ++count;
    }
    return count >= needed;
}
}
using namespace CleartextDetail;

CleartextProtocol identifyCleartext(Bytes prefix, uint16_t servicePort)
{
    const auto line = view(prefix);
    for (const auto method : {"GET ", "POST ", "PUT ", "HEAD ", "PATCH ", "DELETE ", "OPTIONS ",
        "CONNECT ", "TRACE ", "HTTP/1."})
        if (starts(line, method))
            return CleartextProtocol::Http;
    const auto first = line.substr(0, line.find("\r\n"));
    if (first.ends_with(" HTTP/1.0") || first.ends_with(" HTTP/1.1"))
        return CleartextProtocol::Http;
    if (servicePort == 25 || servicePort == 587 || servicePort == 465)
        return CleartextProtocol::Smtp;
    if (servicePort == 143 || servicePort == 993)
        return CleartextProtocol::Imap;
    if (servicePort == 110 || servicePort == 995)
        return CleartextProtocol::Pop3;
    if (servicePort == 21 || servicePort == 990)
        return CleartextProtocol::Ftp;
    if (starts(line, "EHLO ") || starts(line, "HELO ") || starts(line, "MAIL FROM:") ||
        starts(line, "AUTH PLAIN ") || starts(line, "AUTH LOGIN"))
        return CleartextProtocol::Smtp;
    if (starts(line, "CAPA\r\n") || starts(line, "APOP ") || starts(line, "STLS\r\n"))
        return CleartextProtocol::Pop3;
    if (starts(line, "USER ") || starts(line, "PASS "))
        return CleartextProtocol::None;
    if (starts(line, "TYPE ") || starts(line, "PASV\r\n") || starts(line, "EPSV\r\n"))
        return CleartextProtocol::Ftp;
    const auto space = line.find(' ');
    if (space != std::string_view::npos && space <= 32 &&
        (starts(line.substr(space + 1), "LOGIN ") || starts(line.substr(space + 1), "AUTHENTICATE ") ||
            starts(line.substr(space + 1), "STARTTLS\r\n")))
        return CleartextProtocol::Imap;
    return CleartextProtocol::None;
}

bool parseHttp2Settings(Bytes bytes, Http2Settings& settings)
{
    if (bytes.size() % 6)
        return false;
    for (size_t offset = 0; offset < bytes.size(); offset += 6)
    {
        const auto id = (uint16_t{bytes[offset]} << 8) | bytes[offset + 1];
        const auto value = (uint32_t{bytes[offset + 2]} << 24) | (uint32_t{bytes[offset + 3]} << 16) |
            (uint32_t{bytes[offset + 4]} << 8) | bytes[offset + 5];
        if ((id == 1 && value > 65536) || (id == 2 && value > 1) || (id == 4 && value > 0x7fffffff) ||
            (id == 5 && (value < 16384 || value > 16777215)))
            return false;
        if (id == 1)
            settings.headerTable = value;
        else if (id == 5)
            settings.frameLimit = value;
    }
    return true;
}

bool parseHttpHeaders(Bytes header, nlohmann::json& fields, size_t& bodyLength, bool& chunked,
    bool& closeDelimited, HttpMethod responseTo, HttpState* state)
{
    const auto text = view(header);
    const auto firstEnd = text.find("\r\n");
    if (firstEnd == std::string_view::npos || firstEnd > 8192 || header.size() > 32768 ||
        !text.ends_with("\r\n\r\n"))
        return false;
    const auto first = text.substr(0, firstEnd);
    const bool response = first.starts_with("HTTP/1.");
    auto validToken = [](std::string_view value)
    {
        return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch)
        {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                std::string_view("!#$%&'*+-.^_`|~").find(ch) != std::string_view::npos;
        });
    };
    if (response && (firstEnd < 12 || (text[7] != '0' && text[7] != '1') || text[8] != ' ' ||
        text[9] < '1' || text[9] > '5' || text[10] < '0' || text[10] > '9' ||
        text[11] < '0' || text[11] > '9' || (firstEnd > 12 && text[12] != ' ')))
        return false;
    std::string_view method, host, upgrade;
    if (!response)
    {
        if (state)
            state->upgradeSettings.reset();

        // Require a complete request line before treating arbitrary text as HTTP; targets are never retained.
        const auto space = first.find(' ');
        if (space == std::string_view::npos || space > 32 || !validToken(first.substr(0, space)) ||
            (!first.ends_with(" HTTP/1.0") && !first.ends_with(" HTTP/1.1")) || first.size() <= space + 10)
            return false;
        method = first.substr(0, space);
        const auto target = first.substr(space + 1, first.size() - space - 10);
        if (std::any_of(target.begin(), target.end(), [](unsigned char ch) { return ch <= 32 || ch == 127; }))
            return false;
    }
    const bool tunnel = response && responseTo == HttpMethod::Connect &&
        text[9] == '2';
    const bool noBody = response && (responseTo == HttpMethod::Head || tunnel ||
        text[9] == '1' || text.substr(9, 3) == "204" || text.substr(9, 3) == "304");
    size_t position = firstEnd + 2;
    bool lengthSeen = false, transferSeen = false;
    bodyLength = 0;
    chunked = closeDelimited = false;
    while (position < text.size())
    {
        const auto end = text.find("\r\n", position);
        if (end == std::string_view::npos)
            return false;
        if (end == position)
            break;
        const auto line = text.substr(position, end - position);
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || colon > 128 || !validToken(line.substr(0, colon)))
            return false;
        const auto name = line.substr(0, colon), value = trim(line.substr(colon + 1));
        if (std::any_of(
                value.begin(), value.end(), [](unsigned char ch) { return (ch < 32 && ch != '\t') || ch == 127; }))
            return false;
        if (!response && starts(name, "Host") && name.size() == 4)
        {
            if (!host.empty() && host != value)
                return false;
            host = value;
        }
        if (response && text.substr(9, 3) == "101" && starts(name, "Upgrade") && name.size() == 7)
            upgrade = value;
        if (!response && state && starts(name, "HTTP2-Settings") && name.size() == 14)
        {
            // An h2c response implicitly acknowledges the settings carried by the upgrade request.
            if (state->upgradeSettings || value.find_first_not_of(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string_view::npos)
                return false;
            std::string encoded(value);
            std::replace(encoded.begin(), encoded.end(), '-', '+');
            std::replace(encoded.begin(), encoded.end(), '_', '/');
            const auto decoded = decodeBase64(encoded);
            Http2Settings settings;
            if ((!value.empty() && decoded.empty()) || !parseHttp2Settings(decoded, settings))
                return false;
            state->upgradeSettings = settings;
        }
        const bool authorization = starts(name, "Authorization") && name.size() == 13;
        const bool proxy = starts(name, "Proxy-Authorization") && name.size() == 19;
        const bool proxyChallenge = starts(name, "Proxy-Authenticate") && name.size() == 18;
        const bool challenge = (starts(name, "WWW-Authenticate") && name.size() == 16) || proxyChallenge;
        if ((!response && (authorization || proxy)) || (response && challenge))
        {
            auto schemeMatch = [&](std::string_view name)
            {
                return starts(value, name) && (value.size() == name.size() || value[name.size()] == ' ');
            };
            const bool basic = schemeMatch("Basic"), ntlm = schemeMatch("NTLM"),
                negotiate = schemeMatch("Negotiate");
            const auto scheme = basic ? "basic" : ntlm ? "ntlm" : negotiate ? "negotiate" : "";
            if (*scheme)
            {
                const auto size = std::string_view(scheme).size();
                const auto token = value.size() > size ? trim(value.substr(size + 1)) : std::string_view{};
                const auto basicDecoded = basic && !challenge ? decodeBase64(token) : std::vector<uint8_t>{};
                const bool valid = challenge || (basic ?
                    std::find(basicDecoded.begin(), basicDecoded.end(), ':') != basicDecoded.end() :
                    !token.empty());
                if (valid)
                {
                    fields[std::string("http_") + scheme + (challenge ? "_challenge_observed" :
                        "_auth_observed")] = true;
                    if (proxy || proxyChallenge)
                        fields["http_proxy_auth_observed"] = true;
                    if (!basic)
                    {
                        const auto decoded = decodeBase64(token);
                        if (!decoded.empty())
                            parseSecurityBuffer(decoded, challenge, fields);
                    }
                }
            }
        }
        else if (!noBody && starts(name, "Content-Length") && name.size() == 14)
        {
            size_t parsed{};
            const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
            if (result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
                (lengthSeen && bodyLength != parsed))
                return false;
            bodyLength = parsed;
            lengthSeen = true;
        }
        else if (!noBody && starts(name, "Transfer-Encoding") && name.size() == 17)
        {
            // Only a final chunked coding supplies a reusable message boundary.
            transferSeen = true;
            auto remaining = value;
            do
            {
                const auto comma = remaining.find(',');
                const auto coding = trim(remaining.substr(0, comma));
                const auto codingName = trim(coding.substr(0, coding.find(';')));
                if (!validToken(codingName) || chunked)
                    return false;
                chunked = starts(codingName, "chunked") && codingName.size() == 7;
                if (comma == std::string_view::npos)
                    break;
                remaining.remove_prefix(comma + 1);
            } while (true);
        }
        position = end + 2;
    }
    if ((transferSeen && lengthSeen) || (!response && transferSeen && !chunked))
        return false;
    closeDelimited = response && !noBody && !chunked && !lengthSeen;

    // Retain bounded public connection metadata, excluding targets, cookies, bodies, and credential values.
    fields[response ? "http_response_observed" : "http_request_observed"] = true;
    fields[response ? "http_response_versions" : "http_request_versions"] =
        nlohmann::json::array({response ? first.substr(0, 8) : first.substr(first.size() - 8)});
    if (response)
    {
        fields["http_status_codes"] = nlohmann::json::array({
            (text[9] - '0') * 100 + (text[10] - '0') * 10 + text[11] - '0'});
        if (text.substr(9, 3) == "101")
        {
            fields["http_upgrade_observed"] = true;
            if (!upgrade.empty() && upgrade.size() <= 128 &&
                upgrade.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._/, ") ==
                    std::string_view::npos)
                fields["http_upgrade_protocol"] = upgrade;
        }
    }
    else
    {
        fields["http_methods"] = nlohmann::json::array({method});
        if (!host.empty() && host.size() <= 512 &&
            host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:[]%") ==
                std::string_view::npos)
            fields["http_hosts"] = nlohmann::json::array({host});
    }
    return true;
}

bool parseMailLine(Bytes bytes, CleartextProtocol protocol, unsigned& authStep, nlohmann::json& fields)
{
    const auto line = trim(view(bytes));
    if (line.empty() || line.size() > 8192)
        return false;

    // An AUTH LOGIN exchange can send the username inline or in the next client line; retain only its form.
    if (authStep)
    {
        if (line == "*")
        {
            authStep = 0;
            return true;
        }
        if (authStep == 3)
        {
            if (!plainCredentials(line))
                return false;
            fields[protocol == CleartextProtocol::Smtp ? "smtp_auth_plain_observed" :
                protocol == CleartextProtocol::Imap ? "imap_auth_plain_observed" :
                "pop3_auth_plain_observed"] = true;
            authStep = 0;
            return true;
        }
        if (decodeBase64(line).empty())
            return false;
        if (authStep == 1)
            authStep = 2;
        else
        {
            fields[protocol == CleartextProtocol::Smtp ? "smtp_auth_login_observed" :
                protocol == CleartextProtocol::Imap ? "imap_auth_plain_observed" :
                "pop3_auth_plain_observed"] = true;
            authStep = 0;
        }
        return true;
    }
    if (protocol == CleartextProtocol::Smtp)
    {
        if (starts(line, "AUTH PLAIN"))
        {
            const auto payload = trim(line.substr(10));
            if (!payload.empty() && plainCredentials(payload))
                fields["smtp_auth_plain_observed"] = true;
            else if (payload.empty())
                authStep = 3;
        }
        else if (starts(line, "AUTH LOGIN"))
        {
            const auto payload = trim(line.substr(10));
            authStep = payload.empty() ? 1 : !decodeBase64(payload).empty() ? 2 : 0;
        }
    }
    else if (protocol == CleartextProtocol::Imap)
    {
        const auto space = line.find(' ');
        if (space != std::string_view::npos)
        {
            const auto command = trim(line.substr(space + 1));
            if (starts(command, "LOGIN ") && hasArguments(command.substr(6), 2))
                fields["imap_plaintext_login_observed"] = true;
            else if (starts(command, "AUTHENTICATE PLAIN"))
            {
                const auto payload = trim(command.substr(18));
                if (!payload.empty() && plainCredentials(payload))
                    fields["imap_auth_plain_observed"] = true;
                else if (payload.empty())
                    authStep = 3;
            }
        }
    }
    else if (protocol == CleartextProtocol::Pop3)
    {
        if (starts(line, "PASS ") && !trim(line.substr(5)).empty())
            fields["pop3_plaintext_password_observed"] = true;
        else if (starts(line, "AUTH PLAIN"))
        {
            const auto payload = trim(line.substr(10));
            if (!payload.empty() && plainCredentials(payload))
                fields["pop3_auth_plain_observed"] = true;
            else if (payload.empty())
                authStep = 3;
        }
    }
    else if (protocol == CleartextProtocol::Ftp && starts(line, "PASS ") && !trim(line.substr(5)).empty())
        fields["ftp_plaintext_password_observed"] = true;
    return true;
}
}
