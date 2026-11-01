#pragma once

#include "Cleartext.h"
#include "Hpack.h"

namespace Cipherazzi
{
class Http2Stream
{
public:
    using Sink = std::function<bool(const Json&)>;
    Http2Stream(HttpState& state, int direction);
    Http2Stream(const Http2Stream&) = delete;
    Http2Stream& operator=(const Http2Stream&) = delete;
    bool feed(Bytes bytes, const Sink& sink);
    size_t memory() const { return decoder_.memory() + payload_.capacity() + block_.capacity(); }
    bool limited() const { return limited_ || decoder_.limited(); }

private:
    bool frame(const Sink& sink);
    bool headers(const Sink& sink);
    HttpState& state_;
    int direction_{};
    bool limited_{}, started_{}, push_{};
    HpackDecoder decoder_;
    std::vector<uint8_t> payload_, block_;
    std::array<uint8_t, 9> header_{};
    size_t preface_{}, headerSize_{}, remaining_{}, length_{}, kept_{};
    uint32_t stream_{}, continuation_{};
    uint8_t type_{}, flags_{};
};
}
