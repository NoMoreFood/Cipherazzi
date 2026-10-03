#include "Http2.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <set>

namespace Cipherazzi
{
struct alignas(std::max_align_t) Http2Allocation { size_t size; };

void* Http2Stream::allocate(size_t size, void* context)
{
    auto& self = *static_cast<Http2Stream*>(context);
    if (size > 262144 - sizeof(Http2Allocation) || size + sizeof(Http2Allocation) > 262144 - self.allocated_)
    {
        self.limited_ = true;
        return nullptr;
    }
    auto* allocation = static_cast<Http2Allocation*>(std::malloc(sizeof(Http2Allocation) + size));
    if (!allocation)
        return nullptr;
    allocation->size = size;
    self.allocated_ += size + sizeof(Http2Allocation);
    return allocation + 1;
}

void Http2Stream::release(void* pointer, void* context)
{
    if (!pointer)
        return;
    auto* allocation = static_cast<Http2Allocation*>(pointer) - 1;
    static_cast<Http2Stream*>(context)->allocated_ -= allocation->size + sizeof(Http2Allocation);
    std::free(allocation);
}

void* Http2Stream::resize(void* pointer, size_t size, void* context)
{
    if (!pointer)
        return allocate(size, context);
    const auto previous = (static_cast<Http2Allocation*>(pointer) - 1)->size;
    auto* next = allocate(size, context);
    if (next)
    {
        std::memcpy(next, pointer, std::min(size, previous));
        release(pointer, context);
    }
    return next;
}

void* Http2Stream::zeroAllocate(size_t count, size_t size, void* context)
{
    if (count && size > 262144 / count)
    {
        static_cast<Http2Stream*>(context)->limited_ = true;
        return nullptr;
    }
    auto* pointer = allocate(count * size, context);
    if (pointer)
        std::memset(pointer, 0, count * size);
    return pointer;
}

Http2Stream::Http2Stream(HttpState& state, int direction) : state_(state), direction_(direction)
{
    nghttp2_hd_inflater* inflater = nullptr;
    if (nghttp2_hd_inflate_new2(&inflater, &allocator_) == 0)
    {
        inflater_.reset(inflater);
        if (nghttp2_hd_inflate_change_table_size(inflater_.get(), state_.settings[direction_].headerTable))
            inflater_.reset();
    }
}

bool Http2Stream::feed(Bytes bytes, const Sink& sink)
{
    if (!inflater_)
        return false;

    // A cleartext client must send the complete connection preface before any binary frames.
    constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (direction_ == state_.http2Client)
        while (preface_ < preface.size() && !bytes.empty())
        {
            if (bytes.front() != preface[preface_++])
                return false;
            bytes = bytes.subspan(1);
        }
    if (direction_ == state_.http2Client && preface_ != preface.size())
        return true;

    // Keep only bounded control and header bytes; DATA and unknown frame payloads are discarded incrementally.
    while (!bytes.empty())
    {
        if (headerSize_ < header_.size())
        {
            const size_t size = std::min(bytes.size(), header_.size() - headerSize_);
            std::copy_n(bytes.begin(), size, header_.begin() + headerSize_);
            headerSize_ += size;
            bytes = bytes.subspan(size);
            if (headerSize_ < header_.size())
                break;
            length_ = (size_t{header_[0]} << 16) | (size_t{header_[1]} << 8) | header_[2];
            type_ = header_[3];
            flags_ = header_[4];
            stream_ = (uint32_t{header_[5] & 127u} << 24) | (uint32_t{header_[6]} << 16) |
                (uint32_t{header_[7]} << 8) | header_[8];
            if (length_ > state_.settings[direction_].frameLimit ||
                (!started_ && (type_ != 4 || stream_ || (flags_ & 1))) ||
                (continuation_ && (type_ != 9 || stream_ != continuation_)))
                return false;
            kept_ = type_ == 1 || type_ == 4 || type_ == 5 || type_ == 9 ? length_ :
                std::min(size_t{8}, length_);
            if (kept_ > 65536)
            {
                limited_ = true;
                return false;
            }
            payload_.clear();
            remaining_ = length_;
        }
        const size_t size = std::min(bytes.size(), remaining_);
        const size_t keep = std::min(size, kept_ - payload_.size());
        payload_.insert(payload_.end(), bytes.begin(), bytes.begin() + keep);
        remaining_ -= size;
        bytes = bytes.subspan(size);
        if (remaining_)
            break;
        if (!frame(sink))
            return false;
        headerSize_ = 0;
    }
    return true;
}

bool Http2Stream::frame(const Sink& sink)
{
    auto u32 = [&](size_t offset)
    {
        return (uint32_t{payload_[offset]} << 24) | (uint32_t{payload_[offset + 1]} << 16) |
            (uint32_t{payload_[offset + 2]} << 8) | payload_[offset + 3];
    };
    if (type_ == 4)
    {
        if (stream_ || length_ % 6 || ((flags_ & 1) && length_))
            return false;
        if (flags_ & 1)
        {
            // Acknowledgments define when settings apply; packets already in flight retain the previous limits.
            auto& pending = state_.pendingSettings[direction_];
            if (!pending.empty())
            {
                state_.settings[direction_] = pending.front();
                pending.erase(pending.begin());
                if (nghttp2_hd_inflate_change_table_size(inflater_.get(), state_.settings[direction_].headerTable))
                    return false;
            }
            return true;
        }
        auto& pending = state_.pendingSettings[1 - direction_];
        if (pending.size() >= 32)
        {
            limited_ = true;
            return false;
        }
        auto settings = pending.empty() ? state_.settings[1 - direction_] : pending.back();
        if (!parseHttp2Settings(payload_, settings))
            return false;
        pending.push_back(settings);
        if (!started_)
        {
            started_ = true;
            nlohmann::json fields;
            fields[direction_ == state_.http2Client ? "http_request_versions" : "http_response_versions"] =
                nlohmann::json::array({"HTTP/2"});
            return sink(fields);
        }
        return true;
    }
    if (type_ == 1 || type_ == 5 || type_ == 9)
    {
        if (!stream_ || (type_ == 9 && !continuation_) ||
            (type_ == 5 && direction_ == state_.http2Client) ||
            (type_ == 1 && direction_ == state_.http2Client && !(stream_ & 1)))
            return false;
        size_t begin = 0, end = payload_.size();
        if (type_ != 9 && (flags_ & 8))
        {
            if (!end || payload_[0] >= end)
                return false;
            end -= payload_[0];
            ++begin;
        }
        if (type_ == 1 && (flags_ & 32))
        {
            if (end - begin < 5 || (u32(begin) & 0x7fffffff) == stream_)
                return false;
            begin += 5;
        }
        if (type_ == 5)
        {
            if (end - begin < 4 || !(u32(begin) & 0x7fffffff) || (u32(begin) & 1))
                return false;
            begin += 4;
        }
        if (type_ != 9)
        {
            block_.clear();
            push_ = type_ == 5;
        }
        if (end - begin > 65536 - block_.size())
        {
            limited_ = true;
            return false;
        }
        block_.insert(block_.end(), payload_.begin() + begin, payload_.begin() + end);
        continuation_ = flags_ & 4 ? 0 : stream_;
        return continuation_ || headers(sink);
    }
    if (type_ == 0)
        return stream_ && (!(flags_ & 8) || (length_ && payload_[0] < length_));
    if (type_ == 2)
        return stream_ && length_ == 5 && (u32(0) & 0x7fffffff) != stream_;
    if (type_ == 3)
        return stream_ && length_ == 4;
    if (type_ == 6)
        return !stream_ && length_ == 8;
    if (type_ == 7)
        return !stream_ && length_ >= 8;
    if (type_ == 8)
        return length_ == 4 && (u32(0) & 0x7fffffff);
    return true;
}

bool Http2Stream::headers(const Sink& sink)
{
    // Decode HPACK with an allocation cap and retain only the same public fields as HTTP/1.x.
    std::string method, status, authority, host, authentication;
    std::set<std::string> pseudo;
    size_t consumed = 0, decoded = 0, count = 0;
    bool regular = false;
    while (true)
    {
        nghttp2_nv field{};
        int flags = 0;
        const auto size = nghttp2_hd_inflate_hd3(inflater_.get(), &field, &flags,
            block_.empty() ? nullptr : block_.data() + consumed, block_.size() - consumed, 1);
        if (size < 0)
            return false;
        consumed += static_cast<size_t>(size);
        if (flags & NGHTTP2_HD_INFLATE_EMIT)
        {
            if (++count > 256 || field.namelen > 65536 - decoded ||
                field.valuelen > 65536 - decoded - field.namelen)
            {
                limited_ = true;
                return false;
            }
            decoded += field.namelen + field.valuelen;
            const std::string_view name(reinterpret_cast<const char*>(field.name), field.namelen);
            const std::string_view value(reinterpret_cast<const char*>(field.value), field.valuelen);
            if (name.empty() || !nghttp2_check_header_value(field.value, field.valuelen))
                return false;
            if (name.front() == ':')
            {
                if (regular || !pseudo.insert(std::string(name)).second)
                    return false;
                if (name == ":method") method = value;
                else if (name == ":status") status = value;
                else if (name == ":authority") authority = value;
                else if (name != ":scheme" && name != ":path" && name != ":protocol") return false;
            }
            else
            {
                regular = true;
                if (!nghttp2_check_header_name(field.name, field.namelen) || name == "connection" ||
                    name == "upgrade" || name == "transfer-encoding" || name == "keep-alive" ||
                    name == "proxy-connection" || (name == "te" && value != "trailers"))
                    return false;
                if (name == "host")
                {
                    if (!host.empty() && host != value)
                        return false;
                    host = value;
                }
                if (name == "authorization" || name == "proxy-authorization" ||
                    name == "www-authenticate" || name == "proxy-authenticate")
                    authentication += std::string(name) + ": " + std::string(value) + "\r\n";
            }
        }
        if (flags & NGHTTP2_HD_INFLATE_FINAL)
            break;
        if (!size && !(flags & NGHTTP2_HD_INFLATE_EMIT))
            return false;
    }
    if (consumed != block_.size() || nghttp2_hd_inflate_end_headers(inflater_.get()))
        return false;
    if (pseudo.empty())
        return true;
    const bool response = direction_ != state_.http2Client && !push_;
    if (response ? status.empty() || !method.empty() || pseudo.size() != 1 :
        method.empty() || !status.empty() || (method != "CONNECT" &&
            (!pseudo.contains(":path") || !pseudo.contains(":scheme"))))
        return false;
    if (!authority.empty() && !host.empty() && authority != host)
        return false;
    if (push_)
        return true;

    // Reuse authentication parsing without copying targets, cookies, or bodies into evidence.
    std::string metadata = response ? "HTTP/1.1 " + status + "\r\n" : method + " / HTTP/1.1\r\n";
    if (!response && (!authority.empty() || !host.empty()))
        metadata += "Host: " + (authority.empty() ? host : authority) + "\r\n";
    metadata += authentication + "\r\n";
    nlohmann::json fields;
    size_t length = 0;
    bool chunked = false, closeDelimited = false;
    if (!parseHttpHeaders({reinterpret_cast<const uint8_t*>(metadata.data()), metadata.size()}, fields,
        length, chunked, closeDelimited))
        return false;
    fields[response ? "http_response_versions" : "http_request_versions"] = nlohmann::json::array({"HTTP/2"});
    return sink(fields);
}
}
