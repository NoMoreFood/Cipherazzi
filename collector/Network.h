#pragma once

#include "Tls.h"
#include <bitset>
#include <unordered_map>

namespace Cipherazzi
{
class IpFragments
{
public:
    explicit IpFragments(Counters& counters) : counters_(counters) {}
    bool feed(Bytes packet, bool ethernet, int64_t timestampUs, size_t budget, size_t limit,
        std::vector<uint8_t>& assembled);
    void expire(int64_t timestampUs, bool all);
    size_t memory() const { return bytes_; }

private:
    struct Key
    {
        FlowKey addresses;
        uint32_t id{};
        uint8_t protocol{};
        auto operator<=>(const Key&) const = default;
    };
    struct Hash
    {
        size_t operator()(const Key& key) const
        {
            return FlowHash{}(key.addresses) ^ (static_cast<size_t>(key.id) << 1) ^ key.protocol;
        }
    };
    struct Piece
    {
        size_t offset{};
        std::vector<uint8_t> bytes;
    };
    struct Datagram
    {
        int64_t startedUs{};
        std::vector<uint8_t> header;
        std::vector<Piece> pieces;
        size_t total{}, nextHeader{};
        uint8_t protocol{};
        bool final{}, rejected{};
        size_t memory() const;
    };
    Counters& counters_;
    std::unordered_map<Key, Datagram, Hash> pending_;
    size_t bytes_{};
};

class DtlsStream
{
public:
    static bool recognizes(Bytes bytes);
    bool feed(Bytes bytes, const TlsStream::Sink& sink);
    size_t memory() const;
    bool limited() const { return limited_; }
    bool finished() const { return finished_; }

private:
    struct Message
    {
        uint8_t type{};
        uint16_t sequence{};
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> present;
        size_t received{};
    };
    std::vector<Message> messages_;
    std::bitset<64> completed_;
    TlsStream tls_;
    bool limited_{}, finished_{};
    bool helloSeen_{};
    bool flush(const TlsStream::Sink& sink);
};
}
