#pragma once

#include "TlsDecrypt.h"
#include "Transport.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <string_view>

namespace Cipherazzi
{
struct HttpSpyOptions
{
    // Bytes of each request and response body that are kept; 0 keeps headers only.
    size_t bodyBytes{65536};

    // Credential-bearing headers such as Authorization and Cookie are masked unless this is set.
    bool credentials{};

    // Ciphertext held for a connection while its secrets have not been logged yet.
    size_t queueBytes{262144};
    // Live writers may flush secrets after the TCP connection has already closed.
    int64_t secretWaitUs{};
};

// Headers whose values are secrets: credentials, session cookies, and API, session, or CSRF tokens. The decoded
// message store masks them unless the options keep credentials.
inline bool credentialHeader(std::string_view lowerName)
{
    constexpr std::string_view names[]{"authorization", "proxy-authorization", "proxy-authenticate", "cookie",
        "set-cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token", "x-refresh-token", "x-session-token",
        "x-csrf-token", "x-xsrf-token", "x-amz-security-token"};
    return std::ranges::find(names, lowerName) != std::end(names);
}

// Counts for the store's session row, in order: HTTPS connections, decoded, without secrets, unsupported, failed,
// messages, and logged secrets.
using HttpSpyStatistics = std::function<std::array<uint64_t, 7>()>;

// One request and its response, decoded from a connection whose TLS secrets the application exported, or from
// cleartext HTTP. A connection that could not be decoded is reported with the reason and no messages.
struct HttpExchange
{
    uint64_t flowId{};
    uint32_t sequence{};
    bool ownersOnly{};
    int64_t flowStartedUs{}, startedUs{}, requestEndUs{}, responseStartUs{}, endedUs{};
    Endpoint client, server;
    uint16_t connectionClientPort{};
    Owner clientOwner, serverOwner;
    std::string transport, scheme, version, method, host, target, reason, contentType, state, note;
    int status{};
    std::string requestHeaders, responseHeaders;
    std::vector<uint8_t> requestBody, responseBody;
    uint64_t requestBytes{}, responseBytes{};
    size_t memory() const;
};

class HttpSpyFlow;

// Decodes HTTP/1.x and HTTP/2 from the TCP connections the engine reassembles.
class HttpSpy
{
public:
    using Sink = std::function<void(HttpExchange)>;
    HttpSpy(HttpSpyOptions options, const KeyLog& keys, std::function<void()> refreshKeys = {}) :
        options_(options), keys_(keys), refreshKeys_(std::move(refreshKeys)) {}
    void sink(Sink sink) { sink_ = std::move(sink); }
    std::unique_ptr<HttpSpyFlow> open(const FlowKey& key, uint64_t flowId, int64_t startedUs);
    const HttpSpyOptions& options() const { return options_; }
    const KeyLog& keys() const { return keys_; }
    void refreshKeys() const { if (refreshKeys_) refreshKeys_(); }
    void emit(HttpExchange exchange);

    std::atomic<uint64_t> tlsFlows{}, decoded{}, withoutSecrets{}, unsupported{}, failed{}, exchanges{};

private:
    HttpSpyOptions options_;
    const KeyLog& keys_;
    std::function<void()> refreshKeys_;
    Sink sink_;
};

class HttpParser;
struct HttpContext;

// The HTTP view of one TCP connection, from its first bytes to its close.
class HttpSpyFlow
{
public:
    HttpSpyFlow(HttpSpy& owner, const FlowKey& key, uint64_t flowId, int64_t startedUs);
    ~HttpSpyFlow();
    HttpSpyFlow(const HttpSpyFlow&) = delete;
    HttpSpyFlow& operator=(const HttpSpyFlow&) = delete;

    // Returns false once the connection holds nothing more to decode.
    bool feed(const TransportPacket& packet, int64_t timestampUs, size_t budget);
    void tick(int64_t timestampUs);
    void finish(int64_t timestampUs, std::string_view reason);
    bool active() const;
    bool waiting() const;
    size_t memory() const;

private:
    enum class Phase : uint8_t { Sniff, Tls, Plain, Done };
    bool consume(int direction, Bytes bytes, int64_t timestampUs);
    bool sniff(int direction, Bytes bytes, int64_t timestampUs);
    bool plain(int direction, Bytes bytes, int64_t timestampUs);
    void conclude(int64_t timestampUs, std::string note, bool graceful = false);
    HttpSpy& owner_;
    FlowKey key_;
    TcpStream streams_[2];
    std::unique_ptr<HttpContext> context_;
    std::unique_ptr<TlsDecryptor> tls_;
    std::unique_ptr<HttpParser> http_;
    std::vector<uint8_t> sniffed_, plainSniffed_, early_;
    int64_t lastUs_{};
    int client_{-1};
    Phase phase_{Phase::Sniff};
};
}
