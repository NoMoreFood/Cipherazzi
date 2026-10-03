#pragma once

#include "Tls.h"
#include <windows.h>
#include <bcrypt.h>
#include <memory>
#include <optional>

namespace Cipherazzi
{
struct QuicHeader
{
    uint32_t version{};
    uint8_t type{};
    Bytes destinationId, sourceId, packet;
    size_t numberOffset{};
    bool initial() const { return type == (version == 1 ? 0 : 1); }
    bool retry() const { return type == (version == 1 ? 3 : 0); }
};

std::optional<QuicHeader> quicHeader(Bytes bytes);
std::string cidText(Bytes bytes);

class QuicConnection
{
public:
    QuicConnection(Bytes destinationId, uint32_t version);
    bool feed(const QuicHeader& header, bool client, const TlsStream::Sink& sink);
    bool retry(const QuicHeader& header);
    size_t memory() const;
    bool limited() const { return limited_; }
    bool closed() const { return closed_; }
    uint64_t closeError() const { return closeError_; }

private:
    struct KeyCloser { void operator()(BCRYPT_KEY_HANDLE key) const { BCryptDestroyKey(key); } };
    using Key = std::unique_ptr<std::remove_pointer_t<BCRYPT_KEY_HANDLE>, KeyCloser>;
    struct Direction
    {
        Key key, protection;
        std::array<uint8_t, 12> iv{};
        uint64_t expected{};
        TlsStream tls;
        std::vector<uint8_t> bytes, present;
        size_t consumed{};
    };
    void derive(Bytes destinationId);
    bool frames(Bytes bytes, Direction& direction, const TlsStream::Sink& sink);
    Direction directions_[2];
    std::vector<uint8_t> originalId_;
    uint32_t version_{};
    bool retried_{}, limited_{}, closed_{};
    uint64_t closeError_{};
};
}
