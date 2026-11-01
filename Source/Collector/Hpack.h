#pragma once

#include "Model.h"
#include <deque>
#include <functional>

namespace Cipherazzi
{
// Each HTTP/2 direction owns its compression table across complete header blocks.
class HpackDecoder
{
public:
    using Sink = std::function<bool(std::string_view, std::string_view)>;
    bool setTableLimit(size_t size);
    bool decode(Bytes block, const Sink& sink, size_t maximumFields = 256, size_t maximumBytes = 65536);
    size_t memory() const { return memory_ + 512; }
    bool limited() const { return limited_; }

private:
    using Field = std::pair<std::string, std::string>;
    bool lookup(uint32_t index, std::string_view& name, std::string_view& value) const;
    bool string(Bytes& input, std::string& output, size_t maximum);
    void evict(size_t maximum);
    bool add(Field field);
    static size_t allocation(const Field& field);
    static constexpr size_t MaximumMemory = 262144;
    std::deque<Field> table_;
    size_t tableBytes_{}, memory_{}, capacity_{4096}, limit_{4096};
    std::optional<size_t> requiredSize_;
    bool limited_{};
};
}
