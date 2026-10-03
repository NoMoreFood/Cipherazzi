#pragma once

#include <array>
#include <atomic>
#include <compare>
#include <cstdint>
#include <span>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Cipherazzi
{
using Bytes = std::span<const uint8_t>;

// Reserve the stream record header and metadata within Packet Monitor's 9000-byte read buffer.
inline constexpr uint16_t PacketMonitorCaptureLimit = 9000 - 64;

struct Endpoint
{
    std::array<uint8_t, 16> address{};
    uint16_t port{};
    uint8_t family{4};
    auto operator<=>(const Endpoint&) const = default;
    std::string text() const;
};

struct FlowKey
{
    Endpoint a;
    Endpoint b;
    auto operator<=>(const FlowKey&) const = default;
    static FlowKey make(Endpoint source, Endpoint destination);
};

struct FlowHash
{
    size_t operator()(const FlowKey& key) const noexcept;
};

struct OwnerChange
{
    std::optional<FlowKey> flow;
    uint32_t pid{};
    int64_t sinceUs{};
    uint8_t sides{3}; // FlowKey a and b occupy bits 0 and 1.
};

struct Owner
{
    uint32_t pid{};
    int64_t startedUs{};
    std::string name;
    std::string path;
    std::string evidence;
    std::string account;
    std::string accountDomain;
    std::string accountSid;

    // Uncertain lifetime evidence explicitly revokes an earlier attribution.
    bool ambiguous{};
    size_t memory() const;
    bool operator==(const Owner&) const = default;
};

struct NegotiationStage
{
    struct KeyShare
    {
        uint16_t group{}, bytes{};
    };
    enum class Type : uint8_t { ClientHello, HelloRetryRequest, ServerHello };
    Type type{};
    int64_t timestampUs{};
    uint32_t handshakeBytes{};
    uint16_t legacyVersion{};
    int selectedVersion{-1}, cipherId{-1}, selectedGroupId{-1};
    bool ech{};
    std::string sni, alpn;
    std::vector<uint16_t> versions, groups, signatures, certificateSignatures, extensions;
    std::vector<uint32_t> ciphers;
    std::vector<KeyShare> keyShares;
    size_t memory() const;
};

struct ProtocolEvidence;

struct Observation
{
    enum class Protocol : uint8_t
    {
        Tls, Ssh, Unknown, WireGuard, Ike, OpenVpn, Smb, Rdp, Tds, Kerberos, Ldap, IkeV1, Http, Rpc, Smtp, Imap,
        Pop3, Ftp, PostgreSql, MySql, Ipsec
    };
    Protocol protocol{Protocol::Tls};
    bool udp{};
    bool loopback{};
    struct SshPeer
    {
        std::string banner;
        std::array<std::string, 10> algorithms;
        bool kexInit{}, newKeys{}, firstKexPacketFollows{};
    };
    struct Ssh
    {
        SshPeer peers[2];
        std::array<std::string, 8> selected;
        std::string noCommon;
        std::string hostKeyType, hostKeySha256, exchangeSignature, hostCertificate;
        std::vector<uint8_t> pendingReply;
        int hostKeyBits{};
        bool observed{}, rolesKnown{}, pendingReplySpeculative{};
        size_t memory() const;
    };
    std::shared_ptr<Ssh> ssh;
    std::shared_ptr<const ProtocolEvidence> vpn;
    std::shared_ptr<const ProtocolEvidence> application;
    struct Raw
    {
        size_t sampleBytes{};
        double entropy{};
        int direction{};
        bool possibleEncryption{};
    } raw;
    uint64_t flowId{};
    int64_t firstUs{};
    int64_t lastUs{};
    Endpoint source;
    Endpoint destination;
    Owner sourceOwner;
    Owner destinationOwner;
    uint8_t ownerSides{3}; // Ownership corrections inspect only the selected source and destination endpoints.
    uint16_t version{};
    uint32_t cipher{};
    uint16_t dtlsVersion{};
    bool dtlsCookie{};
    std::string sni;
    std::string offeredVersions;
    std::string offeredCiphers;
    std::string offeredAlpn;
    std::string selectedAlpn;
    std::string state;
    std::string detail;
    bool quic{};
    uint32_t quicVersion{};
    std::string quicOriginalId, quicClientId, quicServerId, quicRetryId;
    bool quicRetry{};
    int64_t quicRetryUs{};
    struct QuicPath
    {
        Endpoint source, destination;
        int64_t firstUs{}, lastUs{};
        uint64_t packets{};
    };
    std::vector<QuicPath> quicPaths;
    uint32_t quicPathsDropped{};
    bool clientHello{};
    bool serverHello{};
    bool echOffered{};
    bool retrySeen{};
    struct Crypto
    {
        std::string offeredGroups, offeredSignatures, offeredCertificateSignatures, offeredKeyShares;
        std::string clientExtensions, serverExtensions, offeredPskModes;
        std::vector<uint16_t> srtpProfiles;
        int selectedSrtpProfile{-1};
        std::string group, keyExchange, signature, clientSignature, downgrade, serverCiphers;
        std::vector<uint8_t> clientSession, serverSession;
        std::vector<std::shared_ptr<const std::vector<uint8_t>>> serverCertificates, clientCertificates;
        std::vector<NegotiationStage> stages;
        uint32_t stagesDropped{};
        int groupId{-1}, dhBits{-1}, selectedPsk{-1}, pskOffers{-1}, compression{-1};
        int emsOffered{-1}, emsSelected{-1}, earlyDataOffered{-1}, certificateRequested{-1};
        int clientCertificatePresented{-1}, secureRenegotiation{-1}, ticketOffered{-1};
        int alertLevel{-1}, alertCode{-1}, ssl2ErrorCode{-1}, retryGroupId{-1};
        std::string alertSide, ssl2ErrorSide;
        int64_t clientHelloUs{}, serverHelloUs{}, retryUs{}, alertUs{}, ssl2ErrorUs{};
        bool clientCleartextEnded{}, serverCleartextEnded{}, legacyHello{}, sessionHit{};
        size_t memory() const;
    } crypto;
    int64_t endedUs{};
    std::string closeReason;
    bool lifecycleOnly{};
    size_t memory() const;

    // Whether the flow's own messages have identified its protocol.
    bool recognized() const
    {
        return clientHello || serverHello || crypto.ssl2ErrorCode >= 0 || application || vpn ||
            (ssh && ssh->observed);
    }

    // An SSL 2.0 server hello selects no cipher; the client names its choice in a later message.
    bool cipherSelected() const { return serverHello && (cipher || version != 0x0002); }
};

struct EndpointReport
{
    Endpoint local, remote;
    int64_t processStartedUs{}, startedUs{};
    bool client{}, quic{}, success{};
    bool raw{}, udp{};
    bool partial{}, connection{}, roleKnown{true};
    bool correlatable{true};
    uint16_t dtlsVersion{};
    std::string peerName;
    Owner owner;
    std::string algorithm, mode;
    int keyBits{};
    int version{}, cipher{}, signature{-1}, localSignature{-1}, group{-1}, peerVerified{-1};
    std::string alpn, quicId;
    std::vector<std::shared_ptr<const std::vector<uint8_t>>> serverCertificates, clientCertificates;
    size_t memory() const;
};

struct EndpointEvent
{
    std::string id, provider, kind, result, peer, protocol, cipher, certificateId, detail;
    std::shared_ptr<const EndpointReport> report;
    uint32_t pid{};
    uint16_t port{};
    int64_t timestampUs{};
    size_t memory() const;
};

struct Counters
{
    std::atomic<uint64_t> packets{};
    std::atomic<uint64_t> bytes{};
    std::atomic<uint64_t> captureLost{};
    std::atomic<uint64_t> queueLost{};
    std::atomic<uint64_t> truncated{};
    std::atomic<uint64_t> malformed{};
    std::atomic<uint64_t> fragments{};
    std::atomic<uint64_t> unsupported{};
    std::atomic<uint64_t> flowLimit{};
    std::atomic<uint64_t> reassemblyLimit{};
    std::atomic<uint64_t> observations{};
    std::atomic<uint64_t> storageLost{};
    std::atomic<uint64_t> processEventsLost{};
    std::atomic<uint64_t> activeFlows{};
    std::atomic<uint64_t> bufferedBytes{};
    std::atomic<uint64_t> telemetryLost{};
};

uint16_t be16(Bytes bytes, size_t offset);
uint32_t be32(Bytes bytes, size_t offset);
uint16_t little16(Bytes bytes, size_t offset);
uint32_t little32(Bytes bytes, size_t offset);

// Removes an Ethernet header and up to two VLAN tags, leaving the payload, and returns the EtherType; a frame
// too short for them returns nothing. Each tag's identifier is stored when the caller asks for them.
std::optional<uint16_t> stripEthernet(Bytes& frame, std::array<uint16_t, 2>* vlans = nullptr);

// Places a fragment into a partly received message, where `present` marks the bytes already held. Bytes that
// arrive again must match what is held: the result is the number of new bytes, or nothing on a contradiction.
std::optional<size_t> placeFragment(std::vector<uint8_t>& bytes, std::vector<uint8_t>& present, size_t offset,
    Bytes fragment);
std::string hex16(uint16_t value);
std::string hex24(uint32_t value);
std::string hex32(uint32_t value);
std::string hex(Bytes bytes);
std::string versionName(uint16_t version);
std::string cipherName(uint32_t cipher);
int cipherId(std::string_view name);
std::string groupName(uint16_t group);
std::string signatureName(uint16_t signature);
std::string utf8(std::wstring_view value);
int64_t nowUs();
}
