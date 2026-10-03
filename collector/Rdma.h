#pragma once

#include "Crypto.h"
#include <optional>
#include <unordered_map>

namespace Cipherazzi
{
class SmbDirectStream
{
public:
    using Sink = std::function<bool(const nlohmann::json&)>;
    bool feed(Bytes message, const Sink& sink);
    size_t memory() const { return buffer_.capacity(); }
    bool limited() const { return limited_; }
    bool finished() const { return finished_; }

private:
    std::vector<uint8_t> buffer_;
    uint32_t remaining_{};
    bool started_{}, limited_{}, finished_{};
};

class IwarpStream
{
public:
    bool feed(Bytes bytes, const SmbDirectStream::Sink& sink);
    void configurePeer(uint8_t flags);
    std::optional<uint8_t> flags() const { return flags_; }
    size_t memory() const
    {
        return buffer_.capacity() + message_.capacity() + present_.capacity() + direct_.memory();
    }
    bool limited() const { return limited_ || direct_.limited(); }
    bool finished() const { return finished_ || direct_.finished(); }

private:
    SmbDirectStream direct_;
    std::vector<uint8_t> buffer_, message_, present_;
    std::optional<uint8_t> flags_;
    uint32_t sequence_{};
    size_t wireOffset_{}, filled_{}, lastSize_{};
    uint8_t opcode_{};
    bool ready_{}, markers_{}, crc_{}, assembling_{}, last_{}, limited_{}, finished_{};
};

class RoceConnections
{
public:
    using Sink = std::function<void(Observation)>;
    explicit RoceConnections(Counters& counters) : counters_(counters) {}
    bool feed(Bytes bytes, bool ethernet, int64_t timestampUs, uint64_t& nextId, size_t budget, size_t limit,
        const Sink& sink);
    void expire(int64_t timestampUs, bool all, int64_t idleUs, const Sink& sink);
    size_t memory() const { return bytes_; }
    size_t count() const { return connections_.size(); }

private:
    struct Path
    {
        FlowKey hosts;
        std::array<uint16_t, 2> vlans{0xffff, 0xffff};
        uint16_t partition{};
        uint8_t version{};
        auto operator<=>(const Path&) const = default;
    };
    struct Key
    {
        Path path;
        uint32_t id{};
        bool fromB{}, unilateral{};
        auto operator<=>(const Key&) const = default;
    };
    struct Channel
    {
        Path path;
        uint32_t qp{};
        bool receiverB{};
        auto operator<=>(const Channel&) const = default;
    };
    struct Hash
    {
        size_t operator()(const Key& key) const;
        size_t operator()(const Channel& key) const;
    };
    struct Packet
    {
        Path path;
        Endpoint source, destination;
        Bytes payload;
        uint32_t qp{}, psn{}, fingerprint{}, readLength{};
        uint8_t opcode{};
        bool request{}, send{};
    };
    struct Stream
    {
        struct Piece
        {
            uint32_t psn{}, fingerprint{}, advance{1};
            uint8_t opcode{};
            std::vector<uint8_t> payload;
        };
        struct Seen { uint32_t psn{}, fingerprint{}; };
        SmbDirectStream direct;
        std::vector<Piece> pending;
        std::vector<uint8_t> message;
        std::array<Seen, 64> history{};
        uint32_t first{}, next{}, mtu{};
        size_t historyCount{};
        bool initialized{}, assembling{}, limited{};
        bool begin(uint32_t psn, uint32_t packetMtu);
        bool feed(const Packet& packet, const SmbDirectStream::Sink& sink);
        bool consume(const Piece& piece, const SmbDirectStream::Sink& sink);
        size_t memory() const;
    };
    struct Connection
    {
        Key key;
        Endpoint endpoints[2];
        uint32_t qps[2]{}, starts[2]{}, remoteId{}, mtu{};
        uint16_t sendPorts[2]{};
        uint64_t service{};
        Observation observation;
        std::unique_ptr<std::array<Stream, 2>> streams;
        int64_t lastUs{};
        int clientDirection{-1};
        bool response{}, ready{}, disconnect{}, observed{}, blocked{}, portsKnown{};
        size_t memory() const;
    };
    struct Owner { Connection* connection; int direction; };
    using Connections = std::unordered_map<Key, std::unique_ptr<Connection>, Hash>;
    bool decode(Bytes bytes, bool ethernet, Packet& packet, bool& valid);
    bool index(Connection& connection, int receiver, const Sink& sink);
    bool update(Connection& connection, const nlohmann::json& fields, size_t budget, const Sink& sink);
    void remove(Connections::iterator found, std::string_view reason, const Sink& sink);
    static size_t pathHash(const Path& path);
    Counters& counters_;
    Connections connections_;
    std::unordered_map<Channel, Owner, Hash> channels_;
    size_t bytes_{};
};
}
