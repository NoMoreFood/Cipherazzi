#pragma once

#include "Cleartext.h"
#include <nghttp2/nghttp2.h>
#include <memory>

namespace Cipherazzi
{
class Http2Stream
{
public:
    using Sink = std::function<bool(const nlohmann::json&)>;
    Http2Stream(HttpState& state, int direction);
    Http2Stream(const Http2Stream&) = delete;
    Http2Stream& operator=(const Http2Stream&) = delete;
    bool feed(Bytes bytes, const Sink& sink);
    size_t memory() const { return allocated_ + payload_.capacity() + block_.capacity(); }
    bool limited() const { return limited_; }

private:
    static void* allocate(size_t size, void* context);
    static void* resize(void* pointer, size_t size, void* context);
    static void* zeroAllocate(size_t count, size_t size, void* context);
    static void release(void* pointer, void* context);
    bool frame(const Sink& sink);
    bool headers(const Sink& sink);
    HttpState& state_;
    int direction_{};
    size_t allocated_{};
    bool limited_{}, started_{}, push_{};
    nghttp2_mem allocator_{this, allocate, release, zeroAllocate, resize};
    std::unique_ptr<nghttp2_hd_inflater, decltype(&nghttp2_hd_inflate_del)> inflater_{
        nullptr, nghttp2_hd_inflate_del};
    std::vector<uint8_t> payload_, block_;
    std::array<uint8_t, 9> header_{};
    size_t preface_{}, headerSize_{}, remaining_{}, length_{}, kept_{};
    uint32_t stream_{}, continuation_{};
    uint8_t type_{}, flags_{};
};
}
