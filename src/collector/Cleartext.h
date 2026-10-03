#pragma once

#include "Crypto.h"

namespace Cipherazzi
{
enum class HttpMethod : uint8_t { Other, Head, Connect };
struct Http2Settings
{
    uint32_t headerTable{4096}, frameLimit{16384};
};
struct HttpState
{
    enum class Upgrade : uint8_t { None, Tunnel, Other } upgrade{};
    std::vector<HttpMethod> requests;
    int http2Client{-1};
    Http2Settings settings[2];
    std::vector<Http2Settings> pendingSettings[2];
    std::optional<Http2Settings> upgradeSettings;
};

enum class CleartextProtocol : uint8_t { None, Http, Smtp, Imap, Pop3, Ftp };

CleartextProtocol identifyCleartext(Bytes prefix, uint16_t servicePort);
bool parseHttpHeaders(Bytes header, nlohmann::json& fields, size_t& bodyLength, bool& chunked,
    bool& closeDelimited, HttpMethod responseTo = HttpMethod::Other, HttpState* state = nullptr);
bool parseHttp2Settings(Bytes bytes, Http2Settings& settings);
bool parseMailLine(Bytes line, CleartextProtocol protocol, unsigned& authStep, nlohmann::json& fields);
}
