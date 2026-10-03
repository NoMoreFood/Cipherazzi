#pragma once

#include "Crypto.h"
#include "Cleartext.h"
#include "Http2.h"
#include "DatabaseProtocol.h"
#include "Rdma.h"
#include "SmbPipe.h"

namespace Cipherazzi
{
bool parseSmb(Bytes bytes, nlohmann::json& fields, bool& limited);

// Derives the outcomes that depend on both peers' messages from a connection's merged evidence.
void resolveNegotiation(nlohmann::json& fields);

struct FramedMessage
{
    enum class Kind
    {
        Tls,
        OpenVpn,
        Smb,
        Rdp,
        Tds,
        Kerberos,
        Ldap,
        Http,
        Rpc,
        Smtp,
        Imap,
        Pop3,
        Ftp,
        PostgreSql,
        MySql
    };
    Kind kind{};
    Bytes payload;
    nlohmann::json fields;
    uint32_t ldapMessageId{};
};

class FramedStream
{
public:
    using Sink = std::function<bool(const FramedMessage&)>;
    bool feed(Bytes bytes, const Sink& sink);
    FramedStream() = default;
    void configurePort(uint16_t port) { servicePort_ = port; }
    size_t memory() const
    {
        return buffer_.capacity() + tdsMessage_.capacity() + (database_ ? database_->memory() : 0) +
            (iwarp_ ? iwarp_->memory() : 0) + (http2_ ? sizeof(*http2_) + http2_->memory() : 0);
    }
    bool limited() const
    {
        return limited_ || (database_ && database_->limited()) || (iwarp_ && iwarp_->limited()) ||
            (http2_ && http2_->limited());
    }
    bool finished() const
    {
        return mode_ == Mode::Finished || (http_ && http_->upgrade == HttpState::Upgrade::Other) ||
            (database_ && database_->finished()) || (iwarp_ && iwarp_->finished());
    }

private:
    friend class FramedConnection;
    FramedStream(HttpState& http, DatabaseNegotiation& database, SmbPipeInspection& pipes,
        int direction, uint16_t sourcePort, uint16_t destinationPort) :
        databaseState_(&database), databaseDirection_(direction), http_(&http), httpDirection_(direction),
        smbPipes_(&pipes), smbDirection_(direction)
    {
        for (const auto port : {sourcePort, destinationPort})
            if (port == 21 || port == 25 || port == 110 || port == 143 || port == 465 || port == 587 ||
                port == 990 || port == 993 || port == 995)
                servicePort_ = port;
    }
    enum class Mode { Probe, Direct, Tds, Rdp, RdpData, Smb, OpenVpn, Kerberos, Ldap, Text, Rpc, Finished };
    Mode mode_{};
    std::unique_ptr<IwarpStream> iwarp_;
    DatabaseNegotiation* databaseState_{};
    int databaseDirection_{};
    std::unique_ptr<DatabaseStream> database_;
    std::vector<uint8_t> buffer_, tdsMessage_;
    uint8_t tdsPacketId_{}, tdsPacketType_{}, tdsSspiMessages_{};
    uint32_t ldapStartTlsResponseId_{};
    bool limited_{}, netbios_{}, tdsTls_{}, tdsPreloginSeen_{}, tdsLoginSeen_{}, rdpRequest_{}, rdpMcsSeen_{},
        ldapBound_{};
    uint8_t rdpPackets_{};
    CleartextProtocol textProtocol_{};
    HttpState* http_{};
    int httpDirection_{};
    std::unique_ptr<Http2Stream> http2_;
    SmbPipeInspection* smbPipes_{};
    int smbDirection_{};
    uint16_t servicePort_{};
    size_t textBodyRemaining_{}, textChunkRemaining_{};
    unsigned textAuthStep_{};
    bool textChunked_{}, textChunkLast_{}, textChunkCrLf_{};
};

// One immovable owner keeps both parsers and every shared negotiation alive for the same connection.
class FramedConnection
{
public:
    using Sink = std::function<bool(int, const FramedMessage&)>;
    explicit FramedConnection(uint16_t firstPort = 0, uint16_t secondPort = 0) : streams_{
        FramedStream(http_, database_, smbPipes_, 0, firstPort, secondPort),
        FramedStream(http_, database_, smbPipes_, 1, secondPort, firstPort)} {}
    FramedConnection(const FramedConnection&) = delete;
    FramedConnection& operator=(const FramedConnection&) = delete;
    bool feed(int direction, Bytes bytes, const Sink& sink);
    bool finished() const { return streams_[0].finished() && streams_[1].finished(); }
    bool limited() const { return streams_[0].limited() || streams_[1].limited(); }
    bool tunnel() const { return http_.upgrade == HttpState::Upgrade::Tunnel; }
    int databaseClient() const { return database_.client; }
    size_t memory() const;

private:
    HttpState http_;
    DatabaseNegotiation database_;
    SmbPipeInspection smbPipes_;
    FramedStream streams_[2];
};
}
