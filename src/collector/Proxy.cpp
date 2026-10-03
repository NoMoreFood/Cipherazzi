#include "Proxy.h"
#include "Model.h"
#include "Processes.h"
#include "ProxyRouting.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windivert.h>
#include <iphlpapi.h>
#define SECURITY_WIN32
#include <security.h>

// SCH_CREDENTIALS, which carries TLS 1.3 settings, is declared only with the blacklist definitions.
#define SCHANNEL_USE_BLACKLISTS
#include <subauth.h>
#include <schannel.h>

#include <algorithm>
#include <cctype>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace Cipherazzi
{

static const char* securityError(long code)
{
    switch (code)
    {
    case SEC_E_OK: return "SEC_E_OK";
    case SEC_E_UNTRUSTED_ROOT: return "SEC_E_UNTRUSTED_ROOT";
    case SEC_E_CERT_EXPIRED: return "SEC_E_CERT_EXPIRED";
    case SEC_E_WRONG_PRINCIPAL: return "SEC_E_WRONG_PRINCIPAL";
    case SEC_E_CERT_UNKNOWN: return "SEC_E_CERT_UNKNOWN";
    case SEC_E_NO_AUTHENTICATING_AUTHORITY: return "SEC_E_NO_AUTHENTICATING_AUTHORITY";
    case SEC_E_ALGORITHM_MISMATCH: return "SEC_E_ALGORITHM_MISMATCH";
    case SEC_E_ILLEGAL_MESSAGE: return "SEC_E_ILLEGAL_MESSAGE";
    case SEC_E_INVALID_TOKEN: return "SEC_E_INVALID_TOKEN";
    case SEC_E_MESSAGE_ALTERED: return "SEC_E_MESSAGE_ALTERED";
    case SEC_E_DECRYPT_FAILURE: return "SEC_E_DECRYPT_FAILURE";
    case SEC_E_LOGON_DENIED: return "SEC_E_LOGON_DENIED";
    case SEC_E_INTERNAL_ERROR: return "SEC_E_INTERNAL_ERROR";
    case SEC_E_INCOMPLETE_CREDENTIALS: return "SEC_E_INCOMPLETE_CREDENTIALS";
    case SEC_E_NO_CREDENTIALS: return "SEC_E_NO_CREDENTIALS";
    case SEC_E_UNSUPPORTED_FUNCTION: return "SEC_E_UNSUPPORTED_FUNCTION";
    case CRYPT_E_REVOKED: return "CRYPT_E_REVOKED";
    case CRYPT_E_NO_REVOCATION_CHECK: return "CRYPT_E_NO_REVOCATION_CHECK";
    case CRYPT_E_REVOCATION_OFFLINE: return "CRYPT_E_REVOCATION_OFFLINE";
    case ERROR_GRACEFUL_DISCONNECT: return "ERROR_GRACEFUL_DISCONNECT";
    case WSAECONNRESET: return "WSAECONNRESET";
    case WSAECONNREFUSED: return "WSAECONNREFUSED";
    case WSAEHOSTUNREACH: return "WSAEHOSTUNREACH";
    case WSAETIMEDOUT: return "WSAETIMEDOUT";
    default: return "Error";
    }
}

// Whether a failed handshake is a verdict on the server's certificate. Those connections stay refused, because
// bypassing the proxy would only hand the client the same bad certificate.
static bool certificateVerdict(long status)
{
    switch (status)
    {
    case SEC_E_UNTRUSTED_ROOT: case SEC_E_CERT_EXPIRED: case SEC_E_WRONG_PRINCIPAL: case SEC_E_CERT_UNKNOWN:
    case SEC_E_NO_AUTHENTICATING_AUTHORITY: case CRYPT_E_REVOKED: case CRYPT_E_NO_REVOCATION_CHECK:
    case CRYPT_E_REVOCATION_OFFLINE: case CERT_E_UNTRUSTEDROOT: case CERT_E_EXPIRED: case CERT_E_CN_NO_MATCH:
    case CERT_E_CHAINING: case CERT_E_REVOKED: case CERT_E_UNTRUSTEDCA: case CERT_E_UNTRUSTEDTESTROOT:
    case CERT_E_PURPOSE: case CERT_E_WRONG_USAGE:
        return true;
    default:
        return false;
    }
}

// Whether a ClientHello server name can safely be placed in a certificate and handed to Schannel.
static bool plausibleHost(std::string_view name)
{
    return !name.empty() && name.size() <= 253 && std::ranges::all_of(name, [](char c)
    { return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_'; });
}

// Extract the SNI hostname from a TLS ClientHello record.
static std::string extractSni(const uint8_t* data, size_t length)
{
    if (length < 9 || data[0] != 22 || data[5] != 1)
        return {};
    size_t o = 5 + 4 + 2 + 32;
    if (o + 1 > length) return {};
    o += 1 + data[o];
    if (o + 2 > length) return {};
    o += 2 + (size_t(data[o]) << 8 | data[o + 1]);
    if (o + 1 > length) return {};
    o += 1 + data[o];
    if (o + 2 > length) return {};
    size_t extLen = size_t(data[o]) << 8 | data[o + 1];
    o += 2;
    size_t end = std::min(o + extLen, length);
    while (o + 4 <= end)
    {
        uint16_t type = uint16_t(data[o]) << 8 | data[o + 1];
        uint16_t len = uint16_t(data[o + 2]) << 8 | data[o + 3];
        o += 4;
        if (type == 0 && len >= 5 && o + len <= end)
        {
            size_t p = o + 2;
            if (p + 3 <= o + len && data[p] == 0)
            {
                uint16_t nameLen = uint16_t(data[p + 1]) << 8 | data[p + 2];
                p += 3;
                if (p + nameLen <= o + len)
                    return {reinterpret_cast<const char*>(data + p), nameLen};
            }
        }
        o += len;
    }
    return {};
}

static bool sendAll(SOCKET sock, const void* data, size_t len)
{
    auto ptr = static_cast<const char*>(data);
    while (len > 0)
    {
        auto sent = ::send(sock, ptr, static_cast<int>(std::min(len, size_t(65536))), 0);
        if (sent <= 0) return false;
        ptr += sent;
        len -= sent;
    }
    return true;
}

// Schannel TLS wrapper for one direction of a proxied connection.
struct TlsConn
{
    SOCKET sock = INVALID_SOCKET;
    CredHandle cred{};
    CtxtHandle ctx{};
    SecPkgContext_StreamSizes sizes{};
    std::vector<uint8_t> enc;
    size_t encLen = 0;
    std::vector<uint8_t> dec;
    size_t decOff = 0;
    bool credOk = false, ctxOk = false;

    // The connection to the real server, whose name is needed to finish later handshake messages.
    bool outbound = false;
    std::wstring target;

    // Why the last handshake failed: a Schannel status, a socket error, or ERROR_GRACEFUL_DISCONNECT.
    long failure = 0;

    ~TlsConn() { shutdown(); }

    // Server-side handshake, starting from a pre-read ClientHello.
    bool acceptClient(PCCERT_CONTEXT cert, const uint8_t* hello, size_t helloLen)
    {
        SCHANNEL_CRED sc{};
        sc.dwVersion = SCHANNEL_CRED_VERSION;
        sc.cCreds = 1;
        sc.paCred = &cert;
        sc.dwFlags = SCH_USE_STRONG_CRYPTO;
        sc.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
        if ((failure = AcquireCredentialsHandleW(nullptr, const_cast<LPWSTR>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
            nullptr, &sc, nullptr, nullptr, &cred, nullptr)) != SEC_E_OK)
            return false;
        credOk = true;
        enc.assign(hello, hello + helloLen);
        bool first = true;
        for (;;)
        {
            SecBuffer in[2] = {{DWORD(enc.size()), SECBUFFER_TOKEN, enc.data()},
                               {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc inDesc{SECBUFFER_VERSION, 2, in};
            SecBuffer out{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc outDesc{SECBUFFER_VERSION, 1, &out};
            DWORD flags = 0;
            auto status = AcceptSecurityContext(&cred, first ? nullptr : &ctx, &inDesc,
                ASC_REQ_STREAM | ASC_REQ_ALLOCATE_MEMORY, 0, &ctx, &outDesc, &flags, nullptr);
            if (first) ctxOk = true;
            first = false;
            if (out.cbBuffer > 0 && out.pvBuffer)
            {
                auto ok = sendAll(sock, out.pvBuffer, out.cbBuffer);
                FreeContextBuffer(out.pvBuffer);
                if (!ok) return false;
            }

            // A record that is only partly received stays buffered until the rest arrives.
            if (status != SEC_E_INCOMPLETE_MESSAGE)
            {
                if (in[1].BufferType == SECBUFFER_EXTRA && in[1].cbBuffer > 0)
                    enc.assign(enc.end() - in[1].cbBuffer, enc.end());
                else
                    enc.clear();
            }
            if (status == SEC_E_OK)
                return (encLen = enc.size(), QueryContextAttributes(&ctx, SECPKG_ATTR_STREAM_SIZES, &sizes) == SEC_E_OK);
            if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_INCOMPLETE_MESSAGE)
            {
                failure = status;
                return false;
            }
            uint8_t tmp[4096];
            auto n = recv(sock, reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
            if (n <= 0)
            {
                failure = n == 0 ? ERROR_GRACEFUL_DISCONNECT : WSAGetLastError();
                return false;
            }
            enc.insert(enc.end(), tmp, tmp + n);
        }
    }

    // Client-side handshake to the real server. Schannel validates the certificate chain and the server name, so a
    // connection that cannot be authenticated fails here, before the client sees a certificate this proxy signed.
    bool connectServer(const std::string& serverName)
    {
        // TLS 1.3 requires SCH_CREDENTIALS (Windows 11, Server 2022); earlier systems fall back to TLS 1.2.
        auto acquire = [&](void* credentials)
        {
            return AcquireCredentialsHandleW(nullptr, const_cast<LPWSTR>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                nullptr, credentials, nullptr, nullptr, &cred, nullptr);
        };
        constexpr auto flags = SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
        SCH_CREDENTIALS modern{};
        modern.dwVersion = SCH_CREDENTIALS_VERSION;
        modern.dwFlags = flags;
        if ((failure = acquire(&modern)) != SEC_E_OK)
        {
            SCHANNEL_CRED legacy{};
            legacy.dwVersion = SCHANNEL_CRED_VERSION;
            legacy.dwFlags = flags;
            legacy.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
            if ((failure = acquire(&legacy)) != SEC_E_OK)
                return false;
        }
        credOk = true;
        outbound = true;
        target = std::wstring(serverName.begin(), serverName.end());
        auto& wide = target;
        bool first = true;
        for (;;)
        {
            SecBuffer in[2] = {{DWORD(enc.size()), SECBUFFER_TOKEN, enc.data()},
                               {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc inDesc{SECBUFFER_VERSION, 2, in};
            SecBuffer out{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc outDesc{SECBUFFER_VERSION, 1, &out};
            DWORD outFlags = 0;
            auto status = InitializeSecurityContextW(&cred, first ? nullptr : &ctx, wide.data(),
                ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS, 0, 0,
                first ? nullptr : &inDesc, 0, &ctx, &outDesc, &outFlags, nullptr);
            if (first) ctxOk = true;
            first = false;
            if (out.cbBuffer > 0 && out.pvBuffer)
            {
                auto ok = sendAll(sock, out.pvBuffer, out.cbBuffer);
                FreeContextBuffer(out.pvBuffer);
                if (!ok) return false;
            }

            // A record that is only partly received stays buffered until the rest arrives.
            if (status != SEC_E_INCOMPLETE_MESSAGE)
            {
                if (in[1].BufferType == SECBUFFER_EXTRA && in[1].cbBuffer > 0)
                    enc.assign(enc.end() - in[1].cbBuffer, enc.end());
                else
                    enc.clear();
            }
            if (status == SEC_E_OK)
                return (encLen = enc.size(), QueryContextAttributes(&ctx, SECPKG_ATTR_STREAM_SIZES, &sizes) == SEC_E_OK);
            if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_INCOMPLETE_MESSAGE)
            {
                failure = status;
                return false;
            }
            uint8_t tmp[4096];
            auto n = recv(sock, reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
            if (n <= 0)
            {
                failure = n == 0 ? ERROR_GRACEFUL_DISCONNECT : WSAGetLastError();
                return false;
            }
            enc.insert(enc.end(), tmp, tmp + n);
        }
    }

    // Ends the TLS session cleanly. A response that ends only when the connection closes is otherwise indistinguishable
    // from a truncated one, so strict clients reject it.
    void closeNotify()
    {
        if (!ctxOk || !sizes.cbHeader)
            return;
        DWORD type = SCHANNEL_SHUTDOWN;
        SecBuffer token{sizeof(type), SECBUFFER_TOKEN, &type};
        SecBufferDesc control{SECBUFFER_VERSION, 1, &token};
        if (ApplyControlToken(&ctx, &control) != SEC_E_OK)
            return;
        SecBuffer out{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc outDesc{SECBUFFER_VERSION, 1, &out};
        DWORD flags = 0;
        const auto status = outbound ?
            InitializeSecurityContextW(&cred, &ctx, nullptr, ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY |
                ISC_REQ_USE_SUPPLIED_CREDS, 0, 0, nullptr, 0, &ctx, &outDesc, &flags, nullptr) :
            AcceptSecurityContext(&cred, &ctx, nullptr, ASC_REQ_STREAM | ASC_REQ_ALLOCATE_MEMORY, 0, &ctx,
                &outDesc, &flags, nullptr);
        if (out.cbBuffer > 0 && out.pvBuffer)
        {
            if (status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED)
                sendAll(sock, out.pvBuffer, out.cbBuffer);
            FreeContextBuffer(out.pvBuffer);
        }
    }

    // Completes a handshake message that arrives after the handshake; the buffered bytes that follow it stay in enc.
    bool postHandshake(const uint8_t* extra, size_t extraLen)
    {
        std::vector<uint8_t> input(extra, extra + extraLen);
        for (;;)
        {
            SecBuffer in[2] = {{DWORD(input.size()), SECBUFFER_TOKEN, input.data()}, {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc inDesc{SECBUFFER_VERSION, 2, in};
            SecBuffer out{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc outDesc{SECBUFFER_VERSION, 1, &out};
            DWORD outFlags = 0;
            const auto status = InitializeSecurityContextW(&cred, &ctx, target.data(),
                ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS, 0, 0, &inDesc, 0, &ctx,
                &outDesc, &outFlags, nullptr);
            if (out.cbBuffer > 0 && out.pvBuffer)
            {
                const auto ok = sendAll(sock, out.pvBuffer, out.cbBuffer);
                FreeContextBuffer(out.pvBuffer);
                if (!ok) return false;
            }
            if (status != SEC_E_INCOMPLETE_MESSAGE)
            {
                if (in[1].BufferType == SECBUFFER_EXTRA && in[1].cbBuffer > 0)
                    input.assign(input.end() - in[1].cbBuffer, input.end());
                else
                    input.clear();
            }
            if (status == SEC_E_OK)
            {
                enc = std::move(input);
                encLen = enc.size();
                return true;
            }
            if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_INCOMPLETE_MESSAGE)
                return false;
            uint8_t tmp[4096];
            const auto n = recv(sock, reinterpret_cast<char*>(tmp), sizeof(tmp), 0);
            if (n <= 0) return false;
            input.insert(input.end(), tmp, tmp + n);
        }
    }

    int read(void* output, size_t maxLen)
    {
        if (decOff < dec.size())
        {
            auto n = std::min(dec.size() - decOff, maxLen);
            memcpy(output, dec.data() + decOff, n);
            decOff += n;
            if (decOff == dec.size()) { dec.clear(); decOff = 0; }
            return int(n);
        }
        for (;;)
        {
            if (encLen > 0)
            {
                SecBuffer d[4] = {{DWORD(encLen), SECBUFFER_DATA, enc.data()},
                                  {0, SECBUFFER_EMPTY, nullptr},
                                  {0, SECBUFFER_EMPTY, nullptr},
                                  {0, SECBUFFER_EMPTY, nullptr}};
                SecBufferDesc desc{SECBUFFER_VERSION, 4, d};
                auto status = DecryptMessage(&ctx, &desc, 0, nullptr);
                if (status == SEC_E_OK)
                {
                    void* dataPtr = nullptr; DWORD dataLen = 0;
                    void* extraPtr = nullptr; DWORD extraLen = 0;
                    for (auto& b : d)
                    {
                        if (b.BufferType == SECBUFFER_DATA && b.cbBuffer) { dataPtr = b.pvBuffer; dataLen = b.cbBuffer; }
                        if (b.BufferType == SECBUFFER_EXTRA && b.cbBuffer) { extraPtr = b.pvBuffer; extraLen = b.cbBuffer; }
                    }
                    if (!dataPtr || !dataLen)
                    {
                        // A record that carried no application data, such as a TLS 1.3 handshake record.
                        if (extraLen)
                        {
                            memmove(enc.data(), extraPtr, extraLen);
                            encLen = extraLen;
                        }
                        else
                            encLen = 0;
                        continue;
                    }
                    auto n = std::min(size_t(dataLen), maxLen);
                    memcpy(output, dataPtr, n);
                    if (n < dataLen)
                        dec.assign(static_cast<uint8_t*>(dataPtr) + n, static_cast<uint8_t*>(dataPtr) + dataLen);
                    if (extraLen)
                    {
                        memmove(enc.data(), extraPtr, extraLen);
                        encLen = extraLen;
                    }
                    else
                        encLen = 0;
                    return int(n);
                }
                if (status == SEC_I_CONTEXT_EXPIRED) return 0;
                if (status == SEC_I_RENEGOTIATE && outbound)
                {
                    // A TLS 1.3 session ticket or key update is finished through the handshake call.
                    const SecBuffer* extra = nullptr;
                    for (const auto& b : d)
                        if (b.BufferType == SECBUFFER_EXTRA && b.cbBuffer)
                            extra = &b;
                    if (!extra || !postHandshake(static_cast<const uint8_t*>(extra->pvBuffer), extra->cbBuffer))
                    {
                        failure = failure ? failure : status;
                        return -1;
                    }
                    continue;
                }
                if (status != SEC_E_INCOMPLETE_MESSAGE)
                {
                    failure = status;
                    return -1;
                }
            }
            if (enc.size() < encLen + 4096) enc.resize(encLen + 4096);
            auto n = recv(sock, reinterpret_cast<char*>(enc.data() + encLen), int(enc.size() - encLen), 0);
            if (n <= 0)
            {
                failure = n == 0 ? ERROR_GRACEFUL_DISCONNECT : WSAGetLastError();
                return -1;
            }
            encLen += n;
        }
    }

    bool write(const void* data, size_t len)
    {
        auto ptr = static_cast<const uint8_t*>(data);
        while (len > 0)
        {
            auto chunk = std::min(len, size_t(sizes.cbMaximumMessage));
            std::vector<uint8_t> msg(sizes.cbHeader + chunk + sizes.cbTrailer);
            memcpy(msg.data() + sizes.cbHeader, ptr, chunk);
            SecBuffer e[3] = {
                {sizes.cbHeader, SECBUFFER_STREAM_HEADER, msg.data()},
                {DWORD(chunk), SECBUFFER_DATA, msg.data() + sizes.cbHeader},
                {sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, msg.data() + sizes.cbHeader + chunk}};
            SecBufferDesc desc{SECBUFFER_VERSION, 3, e};
            if (EncryptMessage(&ctx, 0, &desc, 0) != SEC_E_OK) return false;
            if (!sendAll(sock, msg.data(), e[0].cbBuffer + e[1].cbBuffer + e[2].cbBuffer)) return false;
            ptr += chunk;
            len -= chunk;
        }
        return true;
    }

    void shutdown()
    {
        if (ctxOk) { DeleteSecurityContext(&ctx); ctxOk = false; }
        if (credOk) { FreeCredentialsHandle(&cred); credOk = false; }
    }
};

static bool headerToken(std::string_view value, std::string_view expected)
{
    // HTTP token lists are case-insensitive; a substring is not a token.
    while (!value.empty())
    {
        const auto comma = value.find(',');
        auto token = value.substr(0, comma);
        const auto first = token.find_first_not_of(" \t");
        if (first != std::string_view::npos)
        {
            token = token.substr(first, token.find_last_not_of(" \t") - first + 1);
            if (std::equal(token.begin(), token.end(), expected.begin(), expected.end(), [](char a, char b)
            { return std::tolower(static_cast<unsigned char>(a)) == b; }))
                return true;
        }
        if (comma == std::string_view::npos)
            break;
        value.remove_prefix(comma + 1);
    }
    return false;
}

static bool readLine(TlsConn& tls, std::string& line, size_t* remaining = nullptr)
{
    line.clear();
    char c;
    for (;;)
    {
        if ((remaining && !*remaining) || line.size() >= 65536)
        {
            tls.failure = ERROR_BUFFER_OVERFLOW;
            return false;
        }
        if (tls.read(&c, 1) != 1) return false;
        if (remaining) --*remaining;
        if (c == '\n') break;
        line += c;
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return true;
}

static bool relayBytes(TlsConn& src, TlsConn& dst, int64_t count,
    std::vector<uint8_t>& body, size_t limit, uint64_t& total)
{
    uint8_t buf[8192];
    while (count > 0)
    {
        auto n = src.read(buf, size_t(std::min(count, int64_t(sizeof(buf)))));
        if (n <= 0) return false;
        if (!dst.write(buf, n)) return false;
        total += n;
        if (body.size() < limit) body.insert(body.end(), buf, buf + std::min(size_t(n), limit - body.size()));
        count -= n;
    }
    return true;
}

static bool relayChunked(TlsConn& src, TlsConn& dst,
    std::vector<uint8_t>& body, size_t limit, uint64_t& total)
{
    for (;;)
    {
        std::string line;
        if (!readLine(src, line)) return false;
        auto raw = line + "\r\n";
        if (!dst.write(raw.data(), raw.size())) return false;
        auto chunkSize = int64_t(std::strtoul(line.c_str(), nullptr, 16));
        if (chunkSize == 0)
        {
            // Trailer fields, if any, precede the blank line that ends the message.
            for (int trailers = 0; trailers < 100; ++trailers)
            {
                if (!readLine(src, line)) return false;
                raw = line + "\r\n";
                if (!dst.write(raw.data(), raw.size())) return false;
                if (line.empty()) return true;
            }
            return false;
        }
        if (!relayBytes(src, dst, chunkSize, body, limit, total)) return false;
        if (!readLine(src, line)) return false;
        raw = line + "\r\n";
        if (!dst.write(raw.data(), raw.size())) return false;
    }
}

// After a protocol switch, such as a WebSocket upgrade, the connection carries opaque bytes in both directions until
// either side ends it. Idle connections are legitimate there, so the receive timeouts are lifted.
static void tunnel(TlsConn& client, TlsConn& server)
{
    DWORD none = 0;
    setsockopt(client.sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&none), sizeof(none));
    setsockopt(server.sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&none), sizeof(none));
    auto pump = [](TlsConn& from, TlsConn& to)
    {
        uint8_t buf[8192];
        for (;;)
        {
            const auto n = from.read(buf, sizeof(buf));
            if (n <= 0 || !to.write(buf, n))
                break;
        }
        ::shutdown(to.sock, SD_BOTH);
        ::shutdown(from.sock, SD_BOTH);
    };
    std::thread back([&] { pump(server, client); });
    pump(client, server);
    back.join();
}

static bool relayUntilClose(TlsConn& src, TlsConn& dst,
    std::vector<uint8_t>& body, size_t limit, uint64_t& total)
{
    uint8_t buf[8192];
    for (;;)
    {
        auto n = src.read(buf, sizeof(buf));
        if (n == 0) return true;
        if (n < 0) return false;
        if (!dst.write(buf, n)) return false;
        total += n;
        if (body.size() < limit) body.insert(body.end(), buf, buf + std::min(size_t(n), limit - body.size()));
    }
}

// Proxy implementation

struct Proxy::Impl
{
    CertAuthority& ca;
    HttpSpyOptions options;
    ProxyTargets targets;
    Sink sink;
    Proxy& proxy;

    HMODULE module{};
    HANDLE divert{};
    decltype(&WinDivertOpen) wdOpen{};
    decltype(&WinDivertRecvEx) wdRecv{};
    decltype(&WinDivertSend) wdSend{};
    decltype(&WinDivertShutdown) wdShutdown{};
    decltype(&WinDivertClose) wdClose{};
    decltype(&WinDivertSetParam) wdParam{};
    decltype(&WinDivertHelperCalcChecksums) wdChecksums{};
    decltype(&WinDivertHelperParsePacket) wdParse{};

    FlowTable flows;
    UpstreamPorts upstreamPorts;
    Bypass bypass;
    SOCKET listener = INVALID_SOCKET;
    uint16_t proxyPort{};
    std::atomic<bool> stopping{};
    std::atomic<uint64_t> nextFlowId{};
    std::atomic<DWORD> fatal{};
    std::thread redirectThread, listenerThread;

    // Connection threads are detached; stop() interrupts their sockets and waits for the count to reach zero.
    static constexpr size_t MaximumConnections = 512;
    std::mutex connMutex;
    std::condition_variable drained;
    size_t active = 0;
    std::vector<SOCKET> connSockets;
    std::mutex failureMutex;
    std::deque<std::string> recentFailures;
    bool winsock{};

    Impl(CertAuthority& authority, HttpSpyOptions opts, Sink callback, Proxy& owner, ProxyTargets selected)
        : ca(authority), options(std::move(opts)), targets(std::move(selected)), sink(std::move(callback)), proxy(owner) {}
    ~Impl() { stop(); if (module) FreeLibrary(module); if (winsock) WSACleanup(); }

    void start()
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa))
            throw std::runtime_error("Failed to initialize Winsock for HTTP Spy proxy");
        winsock = true;

        // Load WinDivert from the packaged loopback capture folder.
        std::wstring exe(32768, L'\0');
        auto len = GetModuleFileNameW(nullptr, exe.data(), DWORD(exe.size()));
        if (!len || len >= exe.size())
            throw std::runtime_error("Could not locate the proxy capture package");
        exe.resize(len);
        auto path = std::filesystem::path(exe).parent_path() / L"CipherazziLoopback" / L"WinDivert.dll";
        module = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module)
            throw std::runtime_error("Loopback capture package is unavailable; restore CipherazziLoopback");
        auto load = [&](auto& fn, const char* name)
        {
            fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(GetProcAddress(module, name));
            if (!fn) throw std::runtime_error("WinDivert API incompatible (missing " + std::string(name) + ")");
        };
        load(wdOpen, "WinDivertOpen");
        load(wdRecv, "WinDivertRecvEx");
        load(wdSend, "WinDivertSend");
        load(wdShutdown, "WinDivertShutdown");
        load(wdClose, "WinDivertClose");
        load(wdParam, "WinDivertSetParam");
        load(wdChecksums, "WinDivertHelperCalcChecksums");
        load(wdParse, "WinDivertHelperParsePacket");

        // Bind a dual-stack listener outside the selected server ports so its return path is unambiguous.
        for (size_t attempt = 0;; ++attempt)
        {
            listener = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            if (listener == INVALID_SOCKET)
                throw std::runtime_error("Failed to create proxy listener socket");
            DWORD dualStack = 0;
            if (setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&dualStack), sizeof(dualStack)))
                throw std::runtime_error("Failed to enable the dual-stack proxy listener");
            sockaddr_in6 bindAddr{};
            bindAddr.sin6_family = AF_INET6;
            if (bind(listener, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) != 0)
                throw std::runtime_error("Failed to bind proxy listener");
            sockaddr_in6 bound{};
            int boundLen = sizeof(bound);
            getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &boundLen);
            proxyPort = ntohs(bound.sin6_port);
            if (std::ranges::find(targets.ports, proxyPort) == targets.ports.end())
                break;
            closesocket(listener);
            listener = INVALID_SOCKET;
            if (attempt >= targets.ports.size())
                throw std::runtime_error("Could not reserve a proxy listener outside the selected HTTPS ports");
        }
        if (listen(listener, SOMAXCONN) != 0)
            throw std::runtime_error("Failed to listen on proxy port");

        // Clients that check revocation fetch the proxy's certificate revocation list from this listener.
        ca.setRevocationUrl("http://127.0.0.1:" + std::to_string(proxyPort) + "/ca.crl");

        // WinDivert filter: intercept outbound HTTPS and the proxy's responses to clients. The network layer has no
        // process field, so the redirect loop separates the proxy's own connections by source port.
        std::string ports;
        for (const auto port : targets.ports)
            ports += (ports.empty() ? "" : " or ") + std::string("tcp.DstPort == ") + std::to_string(port);
        const auto filter = "outbound and tcp and ((" + ports + ") or tcp.SrcPort == " +
            std::to_string(proxyPort) + ")";
        const auto opened = wdOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 100, 0);
        if (opened == INVALID_HANDLE_VALUE)
            throw std::runtime_error("WinDivert proxy filter failed (" + std::to_string(GetLastError()) +
                "); use an elevated console and allow the signed driver");
        divert = opened;
        wdParam(divert, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
        wdParam(divert, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX);
        wdParam(divert, WINDIVERT_PARAM_QUEUE_TIME, 1000);

        redirectThread = std::thread([this, handle = divert] { redirectLoop(handle); });
        listenerThread = std::thread([this] { listenerLoop(); });
    }

    void stop()
    {
        // Stop diverting first so traffic flows normally, release the driver after its reader has exited, and
        // interrupt every connection with a shutdown; each connection thread closes its own sockets.
        stopping = true;
        if (divert)
            wdShutdown(divert, WINDIVERT_SHUTDOWN_BOTH);
        if (listener != INVALID_SOCKET)
        {
            closesocket(listener);
            listener = INVALID_SOCKET;
        }
        if (redirectThread.joinable()) redirectThread.join();
        if (listenerThread.joinable()) listenerThread.join();
        if (divert)
        {
            wdClose(divert);
            divert = nullptr;
        }
        std::unique_lock lock(connMutex);
        for (auto s : connSockets)
            ::shutdown(s, SD_BOTH);
        drained.wait(lock, [this] { return active == 0; });
    }

    // Keep failed connections and partial messages visible in the store and collector summary. A server that
    // refused interception can be bypassed for a while so the application can reconnect.
    void note(HttpExchange exchange, const char* stage, long code, bool bypassServer = false)
    {
        char text[16]{};
        sprintf_s(text, "0x%08lX", static_cast<unsigned long>(code));
        auto reason = exchange.host + ": " + stage + "; " + securityError(code) + " (" + text + ")";
        if (bypassServer)
        {
            bypass.add(exchange.server);
            reason += "; its next connections bypass the proxy";
        }
        if (!exchange.endedUs)
            exchange.endedUs = nowUs();
        if (exchange.state.empty())
            exchange.state = "encrypted";
        exchange.note = reason;
        sink(std::move(exchange));
        ++proxy.exchanges;
        std::lock_guard lock(failureMutex);
        if (std::ranges::find(recentFailures, reason) != recentFailures.end())
            return;
        if (recentFailures.size() >= 16)
            recentFailures.pop_front();
        recentFailures.push_back(std::move(reason));
    }

    // Registers a socket that stop() must be able to interrupt; the caller closes it with untrack().
    void track(SOCKET socket)
    {
        std::lock_guard lock(connMutex);
        connSockets.push_back(socket);
        if (stopping)
            ::shutdown(socket, SD_BOTH);
    }

    void untrack(SOCKET socket)
    {
        {
            std::lock_guard lock(connMutex);
            std::erase(connSockets, socket);
        }
        closesocket(socket);
    }

    // Connects without blocking stop() for the system's full connection timeout.
    bool connectTo(SOCKET socket, const sockaddr_storage& address)
    {
        u_long nonBlocking = 1;
        if (ioctlsocket(socket, FIONBIO, &nonBlocking) != 0)
            return false;
        if (connect(socket, reinterpret_cast<const sockaddr*>(&address), address.ss_family == AF_INET ?
            sizeof(sockaddr_in) : sizeof(sockaddr_in6)) != 0 &&
            WSAGetLastError() != WSAEWOULDBLOCK)
            return false;
        for (int waited = 0; waited < 10000 && !stopping; waited += 100)
        {
            fd_set writable, refused;
            FD_ZERO(&writable);
            FD_ZERO(&refused);
            FD_SET(socket, &writable);
            FD_SET(socket, &refused);
            timeval slice{0, 100000};
            const auto ready = select(0, nullptr, &writable, &refused, &slice);
            if (ready < 0)
                return false;
            if (ready > 0)
            {
                int error{}, size = sizeof(error);
                if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size))
                    return false;
                if (error)
                {
                    WSASetLastError(error);
                    return false;
                }
                nonBlocking = 0;
                return ioctlsocket(socket, FIONBIO, &nonBlocking) == 0;
            }
        }
        WSASetLastError(stopping ? WSAEINTR : WSAETIMEDOUT);
        return false;
    }

    // Reflect selected IPv4/IPv6 flows to the listener and restore the original server on the return path.
    void redirectLoop(HANDLE handle)
    {
        std::vector<uint8_t> packet(WINDIVERT_MTU_MAX);
        WINDIVERT_ADDRESS address{};
        auto swept = GetTickCount64();
        for (;;)
        {
            UINT length{};
            if (!wdRecv(handle, packet.data(), UINT(packet.size()), &length, 0, &address, nullptr, nullptr))
            {
                const auto error = GetLastError();
                if (!stopping || (error != ERROR_NO_DATA && error != ERROR_OPERATION_ABORTED &&
                    error != ERROR_INVALID_HANDLE))
                    fatal = error ? error : ERROR_OPERATION_ABORTED;
                break;
            }
            if (const auto now = GetTickCount64(); now - swept >= 1000)
            {
                flows.expire();
                upstreamPorts.expire();
                swept = now;
            }
            PWINDIVERT_IPHDR ip{};
            PWINDIVERT_IPV6HDR ipv6{};
            PWINDIVERT_TCPHDR tcp{};
            if (wdParse(packet.data(), length, &ip, &ipv6, nullptr, nullptr, nullptr, &tcp, nullptr,
                nullptr, nullptr, nullptr, nullptr) && tcp && (ip || ipv6))
            {
                Endpoint source, destination;
                source.family = destination.family = ip ? 4 : 6;
                auto* sourceBytes = ip ? reinterpret_cast<uint8_t*>(&ip->SrcAddr) :
                    reinterpret_cast<uint8_t*>(ipv6->SrcAddr);
                auto* destinationBytes = ip ? reinterpret_cast<uint8_t*>(&ip->DstAddr) :
                    reinterpret_cast<uint8_t*>(ipv6->DstAddr);
                const auto bytes = ip ? 4 : 16;
                memcpy(source.address.data(), sourceBytes, bytes);
                memcpy(destination.address.data(), destinationBytes, bytes);
                source.port = ntohs(tcp->SrcPort);
                destination.port = ntohs(tcp->DstPort);
                bool reflect = false;
                if (source.port == proxyPort)
                {
                    auto client = source;
                    client.port = destination.port;
                    auto origin = destination;
                    origin.port = 0;
                    if (const auto entry = flows.lookup(client, origin))
                    {
                        tcp->SrcPort = htons(entry->server.port);
                        reflect = true;
                    }
                }
                else if (std::ranges::find(targets.ports, destination.port) != targets.ports.end())
                {
                    const bool syn = tcp->Syn && !tcp->Ack;
                    bool selected = !syn || (!upstreamPorts.active(source) && !bypass.contains(destination));
                    if (selected && syn && !targets.processes.empty())
                    {
                        const auto owner = socketOwner(source, destination);
                        selected = targets.process(owner.pid, owner.name);
                    }
                    if (syn && !selected)
                        flows.ignore(source, destination);
                    if (selected && (syn ? flows.add(source, {destination, address.Network.IfIdx}) :
                        flows.lookup(source, destination).has_value()))
                    {
                        tcp->DstPort = htons(proxyPort);
                        reflect = true;
                    }
                }
                if (reflect)
                {
                    memcpy(sourceBytes, destination.address.data(), bytes);
                    memcpy(destinationBytes, source.address.data(), bytes);
                    address.Outbound = address.Loopback ? 1 : 0;
                    wdChecksums(packet.data(), length, &address, 0);
                }
            }
            if (!wdSend(handle, packet.data(), length, nullptr, &address) && !stopping)
            {
                fatal = GetLastError();
                break;
            }
        }
    }

    void listenerLoop()
    {
        for (;;)
        {
            sockaddr_storage remote{};
            int remoteLength = sizeof(remote);
            SOCKET accepted = accept(listener, reinterpret_cast<sockaddr*>(&remote), &remoteLength);
            if (accepted == INVALID_SOCKET)
            {
                // Redirected connections have nowhere to go without the listener, so its loss must stop the collector.
                const auto error = WSAGetLastError();
                if (stopping)
                    break;
                if (error == WSAECONNRESET || error == WSAEINTR || error == WSAENOBUFS || error == WSAEMFILE)
                {
                    Sleep(50);
                    continue;
                }
                fatal = error;
                break;
            }
            // A reflected connection arrives from the real server and is addressed to the client's own address, so
            // the accepted socket's local address and the remote port identify the client.
            sockaddr_storage local{};
            int peerLength = sizeof(local);
            if (getsockname(accepted, reinterpret_cast<sockaddr*>(&local), &peerLength) != 0)
            {
                ++proxy.failed;
                closesocket(accepted);
                continue;
            }
            auto peer = endpoint(local);
            auto origin = endpoint(remote);
            peer.port = origin.port;
            origin.port = 0;
            {
                std::lock_guard lock(connMutex);
                if (active >= MaximumConnections)
                {
                    ++proxy.failed;
                    closesocket(accepted);
                    continue;
                }
                ++active;
            }
            track(accepted);
            try
            {
                std::thread([this, accepted, peer, origin]
                { serve(accepted, peer, origin); }).detach();
            }
            catch (const std::system_error&)
            {
                ++proxy.failed;
                untrack(accepted);
                finished(peer, origin);
            }
        }
    }

    void finished(Endpoint peer, Endpoint origin)
    {
        flows.release(peer, origin);
        std::lock_guard lock(connMutex);
        --active;
        drained.notify_all();
    }

    // A connection that fails for any reason, including an exception, must never end the collector.
    void serve(SOCKET clientSock, Endpoint peer, Endpoint origin)
    {
        try
        {
            if (flows.lookup(peer, origin))
                handleConnection(clientSock, peer, origin);
            else if ((origin.family == 4 && origin.address[0] == 127) ||
                (origin.family == 6 && origin.address == Endpoint{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}}.address))
                serveRevocation(clientSock);
            else
                untrack(clientSock);
        }
        catch (...) { ++proxy.failed; }
        finished(peer, origin);
    }

    // Closes a connection's socket, which listenerLoop or the connection itself registered, when its scope ends.
    struct Closer
    {
        Impl& impl;
        SOCKET socket;
        ~Closer() { impl.untrack(socket); }
    };

    // Clients that check revocation fetch the proxy root's list from the loopback listener: one bounded GET, one answer.
    void serveRevocation(SOCKET socket)
    {
        Closer closer{*this, socket};
        DWORD timeout = 5000;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
        std::string request;
        char buffer[1024];
        while (request.size() < 4096 && request.find("\r\n\r\n") == std::string::npos)
        {
            const auto received = recv(socket, buffer, sizeof(buffer), 0);
            if (received <= 0)
                return;
            request.append(buffer, received);
        }
        const auto list = ca.revocationList();
        const bool found = request.starts_with("GET /ca.crl ") && !list.empty();
        const auto head = found ? "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: " +
            std::to_string(list.size()) + "\r\nConnection: close\r\n\r\n" :
            std::string("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        if (sendAll(socket, head.data(), head.size()) && found)
            sendAll(socket, list.data(), list.size());
        ::shutdown(socket, SD_SEND);
    }

    // Owns the client socket, which listenerLoop registered, and closes it when the connection ends. The peer is the
    // client's address and port; the server address is where the connection claims to come from.
    void handleConnection(SOCKET clientSock, Endpoint peer, Endpoint origin)
    {
        Closer clientCloser{*this, clientSock};
        DWORD timeout = 30000;
        setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));

        // Only a connection that the redirect loop reflected is served; the listener accepts any network peer.
        auto entry = flows.lookup(peer, origin, true);
        if (!entry) return;

        const auto clientEp = peer, serverEp = entry->server;
        const auto flowStart = nowUs();
        const auto flowId = ++nextFlowId;
        HttpExchange failure;
        failure.flowId = flowId;
        failure.flowStartedUs = failure.startedUs = flowStart;
        failure.client = clientEp;
        failure.server = serverEp;
        failure.transport = "tcp";
        failure.scheme = "https";

        // Keep the original records for a raw splice, including ClientHellos split across TLS records.
        std::vector<uint8_t> hello, handshake(5);
        bool tls = true;
        do
        {
            std::array<uint8_t, 5> header{};
            if (recv(clientSock, reinterpret_cast<char*>(header.data()), int(header.size()), MSG_WAITALL) !=
                header.size()) return;
            hello.insert(hello.end(), header.begin(), header.end());
            if (header[0] != 22 || header[1] != 3)
            {
                tls = false;
                break;
            }
            const auto size = size_t(header[3]) << 8 | header[4];
            if (size > 16384 || hello.size() + size > 65536) return;
            const auto offset = hello.size();
            hello.resize(offset + size);
            if (recv(clientSock, reinterpret_cast<char*>(hello.data() + offset), int(size), MSG_WAITALL) != size)
                return;
            handshake.insert(handshake.end(), hello.begin() + offset, hello.end());
            if (handshake.size() >= 9 && handshake[5] != 1)
            {
                tls = false;
                break;
            }
        } while (handshake.size() < 9 || handshake.size() < 9 +
            (size_t(handshake[6]) << 16 | size_t(handshake[7]) << 8 | handshake[8]));
        handshake[0] = 22;
        auto sni = extractSni(handshake.data(), handshake.size());
        if (!plausibleHost(sni))
            sni = serverEp.text();
        for (auto& c : sni) c = char(std::tolower(static_cast<unsigned char>(c)));
        failure.host = sni;
        const bool intercept = tls && (targets.host(sni) || targets.host(serverEp.text()));
        if (intercept)
            ++proxy.connections;

        // Connect before deciding whether to intercept or splice the original TLS stream.
        SOCKET serverSock = socket(peer.family == 4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (serverSock == INVALID_SOCKET)
        {
            if (intercept) { ++proxy.failed; note(failure, "creating the server socket failed", WSAGetLastError()); }
            return;
        }
        track(serverSock);
        Closer serverCloser{*this, serverSock};
        setsockopt(serverSock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));

        // Reserve the local port first, so the redirect loop recognizes this connection's SYN as the proxy's own.
        auto localEndpoint = clientEp;
        localEndpoint.port = 0;
        auto local = socketAddress(localEndpoint, entry->interfaceIndex);
        int localLength = local.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        if (bind(serverSock, reinterpret_cast<sockaddr*>(&local), localLength) != 0 ||
            getsockname(serverSock, reinterpret_cast<sockaddr*>(&local), &localLength) != 0)
        {
            if (intercept) { ++proxy.failed; note(failure, "binding the server socket failed", WSAGetLastError()); }
            return;
        }
        const auto upstream = endpoint(local);
        failure.connectionClientPort = upstream.port;
        struct PortGuard
        {
            UpstreamPorts& ports;
            Endpoint endpoint;
            ~PortGuard() { ports.release(endpoint, nowUs()); }
        } portGuard{upstreamPorts, upstream};
        // Packet Monitor timestamps use the system clock tick; a precise timestamp can fall after its own SYN.
        FILETIME opened{};
        GetSystemTimeAsFileTime(&opened);
        const auto openedTicks = static_cast<int64_t>((uint64_t(opened.dwHighDateTime) << 32) | opened.dwLowDateTime);
        upstreamPorts.add(upstream, clientEp, serverEp, (openedTicks - 116444736000000000LL) / 10);
        const auto destination = socketAddress(serverEp, entry->interfaceIndex);
        if (!connectTo(serverSock, destination))
        {
            if (intercept) { ++proxy.failed; note(failure, "connecting to the server failed", WSAGetLastError()); }
            return;
        }
        if (!intercept)
        {
            // Leave the application's TLS handshake, ALPN, client certificate, and pinning untouched.
            DWORD unlimited{};
            setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&unlimited), sizeof(unlimited));
            setsockopt(serverSock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&unlimited), sizeof(unlimited));
            if (!sendAll(serverSock, hello.data(), hello.size()))
                return;
            auto pump = [](SOCKET source, SOCKET destination)
            {
                std::array<char, 16384> buffer{};
                for (int received; (received = recv(source, buffer.data(), int(buffer.size()), 0)) > 0;)
                    if (!sendAll(destination, buffer.data(), received)) break;
                ::shutdown(destination, SD_SEND);
            };
            std::thread back([&] { pump(serverSock, clientSock); });
            pump(clientSock, serverSock);
            back.join();
            return;
        }

        // TLS handshake with the real server first, then with the client.
        TlsConn server, client;
        server.sock = serverSock;
        if (!server.connectServer(sni))
        {
            ++proxy.failed;
            note(failure, "the server handshake failed", server.failure, !certificateVerdict(server.failure));
            return;
        }
        const auto cert = ca.leaf(sni);
        client.sock = clientSock;
        if (!client.acceptClient(cert.get(), hello.data(), hello.size()))
        {
            ++proxy.failed;
            note(failure, "the client handshake failed", client.failure, true);
            return;
        }
        ++proxy.intercepted;
        const auto handshaken = GetTickCount64();

        // HTTP/1.1 relay loop. A connection that ends by agreement, not by failure, ends its TLS sessions cleanly.
        bool graceful = false;
        for (uint32_t seq = 0; !stopping; ++seq)
        {
            failure.sequence = seq;
            std::string requestLine;
            size_t requestHeadRemaining = 65536;
            if (!readLine(client, requestLine, &requestHeadRemaining) || requestLine.empty())
            {
                if (client.failure == ERROR_BUFFER_OVERFLOW)
                {
                    ++proxy.failed;
                    note(failure, "request headers exceeded 64 KiB", client.failure);
                    break;
                }
                // A client that hangs up right after the handshake, without a request, has most likely checked the
                // certificate and rejected it, as a pinning client does.
                if (seq == 0 && GetTickCount64() - handshaken < 3000 && client.failure != WSAETIMEDOUT)
                {
                    ++proxy.failed;
                    note(failure, "the client closed the connection without a request", client.failure, true);
                }
                graceful = true;
                break;
            }
            auto started = nowUs();
            auto sp1 = requestLine.find(' ');
            auto sp2 = requestLine.rfind(' ');
            if (sp1 == std::string::npos || sp1 == sp2) break;
            auto method = requestLine.substr(0, sp1);
            auto target = requestLine.substr(sp1 + 1, sp2 - sp1 - 1);
            auto version = requestLine.substr(sp2 + 1);

            // Read and forward request headers.
            std::string rawHeaders, recordHeaders, host;
            int64_t contentLength = -1;
            bool chunked = false, connClose = false, expectContinue = false;
            for (;;)
            {
                std::string line;
                if (!readLine(client, line, &requestHeadRemaining))
                {
                    ++proxy.failed;
                    note(failure, client.failure == ERROR_BUFFER_OVERFLOW ? "request headers exceeded 64 KiB" :
                        "reading the request failed", client.failure);
                    return;
                }
                if (line.empty()) break;
                rawHeaders += line + "\r\n";
                auto colon = line.find(':');
                if (colon == std::string::npos) { recordHeaders += line + "\r\n"; continue; }
                auto name = line.substr(0, colon);
                auto value = line.substr(colon + 1);
                while (!value.empty() && value[0] == ' ') value.erase(0, 1);
                auto lower = name;
                for (auto& c : lower) c = char(std::tolower(static_cast<unsigned char>(c)));
                if (!options.credentials && credentialHeader(lower))
                    recordHeaders += name + ": [redacted, " + std::to_string(value.size()) + " characters]\r\n";
                else
                    recordHeaders += line + "\r\n";
                if (lower == "host") host = value;
                else if (lower == "content-length") contentLength = std::strtoll(value.c_str(), nullptr, 10);
                else if (lower == "transfer-encoding" && headerToken(value, "chunked")) chunked = true;
                else if (lower == "connection" && headerToken(value, "close")) connClose = true;
                else if (lower == "expect" && headerToken(value, "100-continue")) expectContinue = true;
            }
            {
                auto head = requestLine + "\r\n" + rawHeaders + "\r\n";
                if (!server.write(head.data(), head.size())) break;
            }
            // Read the response head and forward it. Interim responses reach the client and are not exchanges; with
            // Expect: 100-continue the head is read before the body, which follows only after a 100.
            int statusCode = 0;
            int64_t responseStart = 0, respContentLength = -1;
            std::string reasonPhrase, contentType, recordRespHeaders;
            bool respChunked = false, respConnClose = false;
            size_t responseHeadRemaining = 65536;
            auto readHead = [&](bool untilContinue)
            {
                for (;;)
                {
                    std::string respLine, rawRespHeaders;
                    if (!readLine(server, respLine, &responseHeadRemaining) || respLine.empty()) return false;
                    responseStart = nowUs();
                    auto rsp1 = respLine.find(' ');
                    statusCode = rsp1 != std::string::npos ? std::atoi(respLine.c_str() + rsp1 + 1) : 0;
                    auto rsp2 = respLine.find(' ', rsp1 + 1);
                    reasonPhrase = rsp2 != std::string::npos ? respLine.substr(rsp2 + 1) : std::string{};
                    recordRespHeaders.clear();
                    contentType.clear();
                    respContentLength = -1;
                    respChunked = respConnClose = false;
                    for (;;)
                    {
                        std::string line;
                        if (!readLine(server, line, &responseHeadRemaining)) return false;
                        if (line.empty()) break;
                        rawRespHeaders += line + "\r\n";
                        auto colon = line.find(':');
                        if (colon == std::string::npos) { recordRespHeaders += line + "\r\n"; continue; }
                        auto name = line.substr(0, colon);
                        auto value = line.substr(colon + 1);
                        while (!value.empty() && value[0] == ' ') value.erase(0, 1);
                        auto lower = name;
                        for (auto& c : lower) c = char(std::tolower(static_cast<unsigned char>(c)));
                        if (!options.credentials && credentialHeader(lower))
                            recordRespHeaders += name + ": [redacted, " + std::to_string(value.size()) +
                                " characters]\r\n";
                        else
                            recordRespHeaders += line + "\r\n";
                        if (lower == "content-length") respContentLength = std::strtoll(value.c_str(), nullptr, 10);
                        else if (lower == "transfer-encoding" && headerToken(value, "chunked"))
                            respChunked = true;
                        else if (lower == "connection" && headerToken(value, "close"))
                            respConnClose = true;
                        else if (lower == "content-type") contentType = value;
                    }
                    auto head = respLine + "\r\n" + rawRespHeaders + "\r\n";
                    if (!client.write(head.data(), head.size()))
                        return false;
                    const bool interim = statusCode >= 100 && statusCode < 200 && statusCode != 101;
                    if (!interim || (untilContinue && statusCode == 100))
                        return true;
                }
            };
            std::vector<uint8_t> reqBody;
            uint64_t reqBytes = 0;
            bool headRead = false, complete = true;
            std::string failureNote;
            if (expectContinue && (chunked || contentLength > 0))
            {
                complete = readHead(true);
                if (!complete) failureNote = "Reading the response headers failed.";
                headRead = true;
                if (statusCode >= 200)
                    connClose = true;
            }
            if (complete && (!headRead || statusCode == 100))
            {
                if (chunked)
                    complete = relayChunked(client, server, reqBody, options.bodyBytes, reqBytes);
                else if (contentLength > 0)
                    complete = relayBytes(client, server, contentLength, reqBody, options.bodyBytes, reqBytes);
                if (!complete) failureNote = "Relaying the request body failed.";
            }
            auto requestEnd = nowUs();
            if (complete && (!headRead || statusCode == 100) && !readHead(false))
            {
                complete = false;
                failureNote = "Reading the response headers failed.";
            }

            std::vector<uint8_t> respBody;
            uint64_t respBytes = 0;
            bool noBody = method == "HEAD" || statusCode < 200 || statusCode == 204 || statusCode == 304;
            if (complete && !noBody)
            {
                if (respChunked)
                    complete = relayChunked(server, client, respBody, options.bodyBytes, respBytes);
                else if (respContentLength >= 0)
                    complete = relayBytes(server, client, respContentLength, respBody, options.bodyBytes, respBytes);
                else
                {
                    complete = relayUntilClose(server, client, respBody, options.bodyBytes, respBytes);
                    respConnClose = true;
                }
                if (!complete) failureNote = "The response body was interrupted.";
            }
            if (server.failure == ERROR_BUFFER_OVERFLOW)
                failureNote = "Response headers exceeded 64 KiB.";
            auto ended = nowUs();

            HttpExchange exchange;
            exchange.flowId = flowId;
            exchange.sequence = seq;
            exchange.flowStartedUs = flowStart;
            exchange.startedUs = started;
            exchange.requestEndUs = requestEnd;
            exchange.responseStartUs = responseStart;
            exchange.endedUs = ended;
            exchange.client = clientEp;
            exchange.server = serverEp;
            exchange.connectionClientPort = upstream.port;
            exchange.transport = "tcp";
            exchange.scheme = "https";
            exchange.version = version;
            exchange.method = method;
            exchange.host = host.empty() ? sni : host;
            exchange.target = target;
            exchange.reason = reasonPhrase;
            exchange.contentType = contentType;
            exchange.status = statusCode;
            exchange.state = complete ? "complete" : "partial";
            exchange.note = failureNote;
            exchange.requestHeaders = std::move(recordHeaders);
            exchange.responseHeaders = std::move(recordRespHeaders);
            exchange.requestBody = std::move(reqBody);
            exchange.responseBody = std::move(respBody);
            exchange.requestBytes = reqBytes;
            exchange.responseBytes = respBytes;
            if (!complete)
            {
                ++proxy.failed;
                note(std::move(exchange), failureNote.c_str(), server.failure ? server.failure : client.failure);
                break;
            }
            sink(std::move(exchange));
            ++proxy.exchanges;
            ++proxy.relayed;
            if (statusCode == 101)
            {
                tunnel(client, server);
                break;
            }
            if (connClose || respConnClose)
            {
                graceful = true;
                break;
            }
        }
        if (graceful)
        {
            client.closeNotify();
            server.closeNotify();
        }
    }
};

Proxy::Proxy(CertAuthority& ca, HttpSpyOptions options, Sink sink, ProxyTargets targets) :
    impl_(std::make_unique<Impl>(ca, std::move(options), std::move(sink), *this, std::move(targets)))
{
    impl_->start();
}

Proxy::~Proxy() = default;
void Proxy::stop() { impl_->stop(); }
void UpstreamPorts::attribute(Observation& observation, Processes& processes)
{
    if (const auto original = client(observation))
    {
        // Use the collector's socket and process lifetime evidence for the original client connection.
        auto attributed = observation;
        attributed.source = *original;
        processes.recheck(attributed);
        observation.sourceOwner = std::move(attributed.sourceOwner);
        observation.destinationOwner = std::move(attributed.destinationOwner);
        if (observation.sourceOwner.pid)
            observation.sourceOwner.evidence = "HTTP Spy client";
        return;
    }
    auto previous = observation.sourceOwner;
    processes.recheck(observation);
    if (!(observation.ownerSides & 1) || observation.udp || observation.quic)
        return;

    // A retired mapping must not replace the verified client with the collector's own process identity.
    if (previous.evidence == "HTTP Spy client")
    {
        processes.validate(previous, observation.firstUs, observation.lastUs);
        observation.sourceOwner = std::move(previous);
    }
    else if (observation.sourceOwner.pid == GetCurrentProcessId())
        observation.sourceOwner = {.ambiguous=true};
}

void Proxy::attribute(Observation& observation, Processes& processes)
{
    impl_->upstreamPorts.attribute(observation, processes);
}

std::vector<std::string> Proxy::failures()
{
    std::lock_guard lock(impl_->failureMutex);
    return {impl_->recentFailures.begin(), impl_->recentFailures.end()};
}
void Proxy::check()
{
    if (auto err = impl_->fatal.load())
        throw std::runtime_error("HTTPS proxy stopped (" + std::to_string(err) + ")");
    impl_->ca.check();
}
}
