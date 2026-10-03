#pragma once

#include <array>
#include <atomic>
#include <compare>
#include <cstdint>
#include <span>
#include <memory>
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
    size_t memory() const;
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
    std::vector<uint16_t> versions, ciphers, groups, signatures, certificateSignatures, extensions;
    std::vector<KeyShare> keyShares;
    size_t memory() const;
};

struct VpnEvidence;

struct Observation
{
    enum class Protocol : uint8_t { Tls, Ssh, Unknown, WireGuard, Ike, OpenVpn, Smb, Rdp, Tds, Kerberos };
    Protocol protocol{Protocol::Tls};
    bool udp{};
    struct SshPeer
    {
        std::string banner;
        std::array<std::string, 10> algorithms;
        bool kexInit{}, newKeys{};
    };
    struct Ssh
    {
        SshPeer peers[2];
        std::array<std::string, 8> selected;
        std::string noCommon;
        std::string hostKeyType, hostKeySha256, exchangeSignature, hostCertificate;
        int hostKeyBits{};
        bool observed{}, rolesKnown{};
        size_t memory() const;
    };
    std::shared_ptr<Ssh> ssh;
    std::shared_ptr<const VpnEvidence> vpn;
    std::shared_ptr<const VpnEvidence> application;
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
    uint16_t version{};
    uint16_t cipher{};
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
        std::string group, keyExchange, signature, clientSignature, downgrade;
        std::vector<uint8_t> clientSession, serverSession;
        std::vector<std::shared_ptr<const std::vector<uint8_t>>> serverCertificates, clientCertificates;
        std::vector<NegotiationStage> stages;
        uint32_t stagesDropped{};
        int groupId{-1}, dhBits{-1}, selectedPsk{-1}, pskOffers{-1}, compression{-1};
        int emsOffered{-1}, emsSelected{-1}, earlyDataOffered{-1}, certificateRequested{-1};
        int clientCertificatePresented{-1}, secureRenegotiation{-1}, ticketOffered{-1};
        int alertLevel{-1}, alertCode{-1}, retryGroupId{-1};
        std::string alertSide;
        int64_t clientHelloUs{}, serverHelloUs{}, retryUs{}, alertUs{};
        bool clientCleartextEnded{}, serverCleartextEnded{};
        size_t memory() const;
    } crypto;
    int64_t endedUs{};
    std::string closeReason;
    bool lifecycleOnly{};
    size_t memory() const;
};

struct EndpointReport
{
    Endpoint local, remote;
    int64_t processStartedUs{}, startedUs{};
    bool client{}, quic{}, success{};
    bool raw{}, udp{};
    bool partial{}, roleKnown{true};
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
std::string hex16(uint16_t value);
std::string versionName(uint16_t version);
std::string cipherName(uint16_t cipher);
int cipherId(std::string_view name);
std::string groupName(uint16_t group);
std::string signatureName(uint16_t signature);
std::string utf8(std::wstring_view value);
int64_t nowUs();
}
