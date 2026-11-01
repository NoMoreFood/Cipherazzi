#include "Hpack.h"

#include <algorithm>
#include <limits>

namespace Cipherazzi
{
namespace HpackDetail
{
// Fixed protocol tables from RFC 7541, Appendices A and B.
constexpr std::pair<std::string_view, std::string_view> StaticTable[] = {
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""},
};
struct Code { uint32_t bits; uint8_t length; };
constexpr Code Codes[] = {
    {0x1ff8, 13}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28}, {0xfffffe4, 28}, {0xfffffe5, 28},
    {0xfffffe6, 28}, {0xfffffe7, 28}, {0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28},
    {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28}, {0xfffffed, 28}, {0xfffffee, 28},
    {0xfffffef, 28}, {0xffffff0, 28}, {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28},
    {0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28}, {0xffffff8, 28}, {0xffffff9, 28},
    {0xffffffa, 28}, {0xffffffb, 28}, {0x14, 6}, {0x3f8, 10}, {0x3f9, 10}, {0xffa, 12},
    {0x1ff9, 13}, {0x15, 6}, {0xf8, 8}, {0x7fa, 11}, {0x3fa, 10}, {0x3fb, 10},
    {0xf9, 8}, {0x7fb, 11}, {0xfa, 8}, {0x16, 6}, {0x17, 6}, {0x18, 6},
    {0x0, 5}, {0x1, 5}, {0x2, 5}, {0x19, 6}, {0x1a, 6}, {0x1b, 6},
    {0x1c, 6}, {0x1d, 6}, {0x1e, 6}, {0x1f, 6}, {0x5c, 7}, {0xfb, 8},
    {0x7ffc, 15}, {0x20, 6}, {0xffb, 12}, {0x3fc, 10}, {0x1ffa, 13}, {0x21, 6},
    {0x5d, 7}, {0x5e, 7}, {0x5f, 7}, {0x60, 7}, {0x61, 7}, {0x62, 7},
    {0x63, 7}, {0x64, 7}, {0x65, 7}, {0x66, 7}, {0x67, 7}, {0x68, 7},
    {0x69, 7}, {0x6a, 7}, {0x6b, 7}, {0x6c, 7}, {0x6d, 7}, {0x6e, 7},
    {0x6f, 7}, {0x70, 7}, {0x71, 7}, {0x72, 7}, {0xfc, 8}, {0x73, 7},
    {0xfd, 8}, {0x1ffb, 13}, {0x7fff0, 19}, {0x1ffc, 13}, {0x3ffc, 14}, {0x22, 6},
    {0x7ffd, 15}, {0x3, 5}, {0x23, 6}, {0x4, 5}, {0x24, 6}, {0x5, 5},
    {0x25, 6}, {0x26, 6}, {0x27, 6}, {0x6, 5}, {0x74, 7}, {0x75, 7},
    {0x28, 6}, {0x29, 6}, {0x2a, 6}, {0x7, 5}, {0x2b, 6}, {0x76, 7},
    {0x2c, 6}, {0x8, 5}, {0x9, 5}, {0x2d, 6}, {0x77, 7}, {0x78, 7},
    {0x79, 7}, {0x7a, 7}, {0x7b, 7}, {0x7ffe, 15}, {0x7fc, 11}, {0x3ffd, 14},
    {0x1ffd, 13}, {0xffffffc, 28}, {0xfffe6, 20}, {0x3fffd2, 22}, {0xfffe7, 20}, {0xfffe8, 20},
    {0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22}, {0x7fffd9, 23}, {0x3fffd6, 22}, {0x7fffda, 23},
    {0x7fffdb, 23}, {0x7fffdc, 23}, {0x7fffdd, 23}, {0x7fffde, 23}, {0xffffeb, 24}, {0x7fffdf, 23},
    {0xffffec, 24}, {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 23}, {0xffffee, 24}, {0x7fffe1, 23},
    {0x7fffe2, 23}, {0x7fffe3, 23}, {0x7fffe4, 23}, {0x1fffdc, 21}, {0x3fffd8, 22}, {0x7fffe5, 23},
    {0x3fffd9, 22}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0xffffef, 24}, {0x3fffda, 22}, {0x1fffdd, 21},
    {0xfffe9, 20}, {0x3fffdb, 22}, {0x3fffdc, 22}, {0x7fffe8, 23}, {0x7fffe9, 23}, {0x1fffde, 21},
    {0x7fffea, 23}, {0x3fffdd, 22}, {0x3fffde, 22}, {0xfffff0, 24}, {0x1fffdf, 21}, {0x3fffdf, 22},
    {0x7fffeb, 23}, {0x7fffec, 23}, {0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21},
    {0x7fffed, 23}, {0x3fffe1, 22}, {0x7fffee, 23}, {0x7fffef, 23}, {0xfffea, 20}, {0x3fffe2, 22},
    {0x3fffe3, 22}, {0x3fffe4, 22}, {0x7ffff0, 23}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x7ffff1, 23},
    {0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20}, {0x7fff1, 19}, {0x3fffe7, 22}, {0x7ffff2, 23},
    {0x3fffe8, 22}, {0x1ffffec, 25}, {0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26}, {0x7ffffde, 27},
    {0x7ffffdf, 27}, {0x3ffffe5, 26}, {0xfffff1, 24}, {0x1ffffed, 25}, {0x7fff2, 19}, {0x1fffe3, 21},
    {0x3ffffe6, 26}, {0x7ffffe0, 27}, {0x7ffffe1, 27}, {0x3ffffe7, 26}, {0x7ffffe2, 27}, {0xfffff2, 24},
    {0x1fffe4, 21}, {0x1fffe5, 21}, {0x3ffffe8, 26}, {0x3ffffe9, 26}, {0xffffffd, 28}, {0x7ffffe3, 27},
    {0x7ffffe4, 27}, {0x7ffffe5, 27}, {0xfffec, 20}, {0xfffff3, 24}, {0xfffed, 20}, {0x1fffe6, 21},
    {0x3fffe9, 22}, {0x1fffe7, 21}, {0x1fffe8, 21}, {0x7ffff3, 23}, {0x3fffea, 22}, {0x3fffeb, 22},
    {0x1ffffee, 25}, {0x1ffffef, 25}, {0xfffff4, 24}, {0xfffff5, 24}, {0x3ffffea, 26}, {0x7ffff4, 23},
    {0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26}, {0x3ffffed, 26}, {0x7ffffe7, 27}, {0x7ffffe8, 27},
    {0x7ffffe9, 27}, {0x7ffffea, 27}, {0x7ffffeb, 27}, {0xffffffe, 28}, {0x7ffffec, 27}, {0x7ffffed, 27},
    {0x7ffffee, 27}, {0x7ffffef, 27}, {0x7fffff0, 27}, {0x3ffffee, 26}, {0x3fffffff, 30},
};
struct Node { uint16_t next[2]{}; int16_t symbol{-1}; };
constexpr auto Tree = []
{
    std::array<Node, 513> nodes{};
    uint16_t used = 1;
    for (size_t symbol = 0; symbol < std::size(Codes); ++symbol)
    {
        uint16_t node = 0;
        const auto code = Codes[symbol];
        for (int bit = code.length - 1; bit >= 0; --bit)
        {
            auto& next = nodes[node].next[(code.bits >> bit) & 1];
            if (!next) next = used++;
            node = next;
        }
        nodes[node].symbol = static_cast<int16_t>(symbol);
    }
    return nodes;
}();

bool integer(Bytes& input, unsigned prefix, uint32_t& result)
{
    if (input.empty())
        return false;
    const uint32_t mask = (uint32_t{1} << prefix) - 1;
    result = input.front() & mask;
    input = input.subspan(1);
    if (result != mask)
        return true;

    // All used lengths, indices, and settings fit in 32 bits; reject continuation overflow.
    for (unsigned shift = 0; shift <= 28 && !input.empty(); shift += 7)
    {
        const auto byte = input.front();
        input = input.subspan(1);
        const uint32_t value = byte & 127;
        if (value > (std::numeric_limits<uint32_t>::max() - result) >> shift)
            return false;
        result += value << shift;
        if (!(byte & 128))
            return true;
    }
    return false;
}
}

bool HpackDecoder::setTableLimit(size_t size)
{
    if (size > MaximumMemory)
    {
        limited_ = true;
        return false;
    }
    limit_ = size;
    if (size < capacity_)
    {
        requiredSize_ = std::min(requiredSize_.value_or(size), size);
        capacity_ = size;
        evict(size);
    }
    return true;
}

size_t HpackDecoder::allocation(const Field& field)
{
    return sizeof(Field) + field.first.capacity() + field.second.capacity() + 34;
}

void HpackDecoder::evict(size_t maximum)
{
    while (tableBytes_ > maximum)
    {
        const auto& field = table_.back();
        tableBytes_ -= field.first.size() + field.second.size() + 32;
        memory_ -= allocation(field);
        table_.pop_back();
    }
}

bool HpackDecoder::add(Field field)
{
    const size_t size = field.first.size() + field.second.size() + 32;
    if (size > capacity_)
    {
        evict(0);
        return true;
    }
    evict(capacity_ - size);
    const auto bytes = allocation(field);
    if (bytes > MaximumMemory - memory())
    {
        limited_ = true;
        return false;
    }
    tableBytes_ += size;
    memory_ += bytes;
    table_.push_front(std::move(field));
    return true;
}

bool HpackDecoder::lookup(uint32_t index, std::string_view& name, std::string_view& value) const
{
    if (!index)
        return false;
    if (index <= std::size(HpackDetail::StaticTable))
    {
        const auto& field = HpackDetail::StaticTable[index - 1];
        name = field.first;
        value = field.second;
        return true;
    }
    const auto dynamic = index - std::size(HpackDetail::StaticTable) - 1;
    if (dynamic >= table_.size())
        return false;
    name = table_[dynamic].first;
    value = table_[dynamic].second;
    return true;
}

bool HpackDecoder::string(Bytes& input, std::string& output, size_t maximum)
{
    if (input.empty())
        return false;
    const bool huffman = (input.front() & 128) != 0;
    uint32_t length{};
    if (!HpackDetail::integer(input, 7, length) || length > input.size())
        return false;
    const auto bytes = input.first(length);
    input = input.subspan(length);
    if (!huffman)
    {
        if (length > maximum)
        {
            limited_ = true;
            return false;
        }
        output.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return true;
    }

    // Walk the fixed prefix tree, rejecting EOS and padding longer than seven one bits.
    uint16_t node = 0;
    unsigned pending = 0;
    bool ones = true;
    for (const auto byte : bytes)
        for (int bit = 7; bit >= 0; --bit)
        {
            const auto value = (byte >> bit) & 1;
            node = HpackDetail::Tree[node].next[value];
            if (!node)
                return false;
            ++pending;
            ones &= value != 0;
            const auto symbol = HpackDetail::Tree[node].symbol;
            if (symbol < 0)
                continue;
            if (symbol == 256)
                return false;
            if (output.size() == maximum)
            {
                limited_ = true;
                return false;
            }
            output += static_cast<char>(symbol);
            node = 0;
            pending = 0;
            ones = true;
        }
    return !node || (pending <= 7 && ones);
}

bool HpackDecoder::decode(Bytes block, const Sink& sink, size_t maximumFields, size_t maximumBytes)
{
    if (block.size() > MaximumMemory || maximumBytes > MaximumMemory)
    {
        limited_ = true;
        return false;
    }
    bool started = false;
    size_t fields = 0, decoded = 0;
    auto emit = [&](std::string_view name, std::string_view value)
    {
        if (++fields > maximumFields || name.size() > maximumBytes - decoded ||
            value.size() > maximumBytes - decoded - name.size())
        {
            limited_ = true;
            return false;
        }
        decoded += name.size() + value.size();
        return sink(name, value);
    };

    // Table-size updates precede all fields, including the smallest acknowledged limit after a reduction.
    while (!block.empty())
    {
        const auto first = block.front();
        uint32_t index{};
        if ((first & 0xe0) == 0x20)
        {
            if (started || !HpackDetail::integer(block, 5, index) || index > limit_ ||
                (requiredSize_ && index > *requiredSize_))
                return false;
            capacity_ = index;
            requiredSize_.reset();
            evict(capacity_);
            continue;
        }
        if (requiredSize_)
            return false;
        started = true;
        std::string_view name, value;
        if (first & 128)
        {
            if (!HpackDetail::integer(block, 7, index) || !lookup(index, name, value) || !emit(name, value))
                return false;
            continue;
        }

        // Copy a referenced name before insertion can evict its dynamic-table entry.
        const bool indexed = (first & 64) != 0;
        if (!HpackDetail::integer(block, indexed ? 6 : 4, index))
            return false;
        Field field;
        if (index)
        {
            if (!lookup(index, name, value))
                return false;
            field.first = name;
        }
        else if (!string(block, field.first, maximumBytes - decoded))
            return false;
        if (field.first.size() > maximumBytes - decoded)
        {
            limited_ = true;
            return false;
        }
        if (!string(block, field.second, maximumBytes - decoded - field.first.size()) ||
            !emit(field.first, field.second) || (indexed && !add(std::move(field))))
            return false;
    }
    return !requiredSize_;
}
}
