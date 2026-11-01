#include "Json.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <istream>
#include <ostream>

namespace Cipherazzi
{
namespace JsonDetail
{
constexpr size_t MaximumInput = 16 * 1024 * 1024;

// Reject overlong encodings, isolated continuations, surrogates, and values outside Unicode.
size_t utf8Width(std::string_view text, size_t offset)
{
    const auto first = static_cast<unsigned char>(text[offset]);
    if (first < 0x80)
        return 1;
    const size_t width = first >= 0xc2 && first <= 0xdf ? 2 :
        first >= 0xe0 && first <= 0xef ? 3 : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
    if (!width || width > text.size() - offset)
        return 0;
    for (size_t index = 1; index < width; ++index)
    {
        const auto byte = static_cast<unsigned char>(text[offset + index]);
        if (byte < 0x80 || byte > 0xbf)
            return 0;
    }
    const auto second = static_cast<unsigned char>(text[offset + 1]);
    if ((first == 0xe0 && second < 0xa0) || (first == 0xed && second >= 0xa0) ||
        (first == 0xf0 && second < 0x90) || (first == 0xf4 && second >= 0x90))
        return 0;
    return width;
}

class Parser
{
public:
    Parser(std::string_view text, size_t maximumDepth, bool rejectDuplicates) :
        text_(text), maximumDepth_(std::min(maximumDepth, size_t{64})), rejectDuplicates_(rejectDuplicates) {}

    Json parse()
    {
        if (text_.size() > MaximumInput)
            fail();
        if (text_.starts_with("\xef\xbb\xbf"))
            offset_ = 3;
        auto result = value(0);
        whitespace();
        if (offset_ != text_.size())
            fail();
        return result;
    }

private:
    [[noreturn]] void fail() const
    {
        throw std::runtime_error("Invalid JSON at byte " + std::to_string(offset_));
    }
    void whitespace()
    {
        while (offset_ < text_.size() && (text_[offset_] == ' ' || text_[offset_] == '\t' ||
            text_[offset_] == '\r' || text_[offset_] == '\n'))
            ++offset_;
    }
    bool take(char expected)
    {
        if (offset_ == text_.size() || text_[offset_] != expected)
            return false;
        ++offset_;
        return true;
    }
    bool digit() const { return offset_ < text_.size() && text_[offset_] >= '0' && text_[offset_] <= '9'; }
    uint32_t hex4()
    {
        if (text_.size() - offset_ < 4)
            fail();
        uint32_t result = 0;
        for (int index = 0; index < 4; ++index)
        {
            const char ch = text_[offset_++];
            const int digit = ch >= '0' && ch <= '9' ? ch - '0' :
                ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
            if (digit < 0)
                fail();
            result = (result << 4) | static_cast<uint32_t>(digit);
        }
        return result;
    }
    std::string string()
    {
        if (!take('"'))
            fail();
        std::string result;
        while (offset_ < text_.size())
        {
            const auto ch = static_cast<unsigned char>(text_[offset_++]);
            if (ch == '"')
                return result;
            if (ch < 0x20)
                fail();
            if (ch >= 0x80)
            {
                const size_t width = utf8Width(text_, offset_ - 1);
                if (!width)
                    fail();
                result.append(text_.substr(offset_ - 1, width));
                offset_ += width - 1;
                continue;
            }
            if (ch != '\\')
            {
                result += static_cast<char>(ch);
                continue;
            }
            if (offset_ == text_.size())
                fail();
            switch (text_[offset_++])
            {
            case '"': result += '"'; break;
            case '\\': result += '\\'; break;
            case '/': result += '/'; break;
            case 'b': result += '\b'; break;
            case 'f': result += '\f'; break;
            case 'n': result += '\n'; break;
            case 'r': result += '\r'; break;
            case 't': result += '\t'; break;
            case 'u':
            {
                uint32_t code = hex4();
                if (code >= 0xd800 && code <= 0xdbff)
                {
                    if (!take('\\') || !take('u'))
                        fail();
                    const auto low = hex4();
                    if (low < 0xdc00 || low > 0xdfff)
                        fail();
                    code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
                }
                else if (code >= 0xdc00 && code <= 0xdfff)
                    fail();
                if (code < 0x80)
                    result += static_cast<char>(code);
                else
                {
                    if (code < 0x800) result += static_cast<char>(0xc0 | (code >> 6));
                    else
                    {
                        if (code < 0x10000) result += static_cast<char>(0xe0 | (code >> 12));
                        else
                        {
                            result += static_cast<char>(0xf0 | (code >> 18));
                            result += static_cast<char>(0x80 | ((code >> 12) & 63));
                        }
                        result += static_cast<char>(0x80 | ((code >> 6) & 63));
                    }
                    result += static_cast<char>(0x80 | (code & 63));
                }
                break;
            }
            default: fail();
            }
        }
        fail();
    }
    Json number()
    {
        const auto start = offset_;
        const bool negative = take('-');
        if (!take('0'))
        {
            if (!digit() || text_[offset_] == '0')
                fail();
            while (digit()) ++offset_;
        }
        bool floating = take('.');
        if (floating)
        {
            if (!digit()) fail();
            while (digit()) ++offset_;
        }
        if (take('e') || take('E'))
        {
            floating = true;
            if (!take('+')) take('-');
            if (!digit()) fail();
            while (digit()) ++offset_;
        }

        // Preserve integer identities exactly, including values beyond double precision.
        const auto first = text_.data() + start;
        const auto last = text_.data() + offset_;
        if (!floating)
        {
            if (negative)
            {
                int64_t result{};
                if (std::from_chars(first, last, result).ec == std::errc{}) return result;
            }
            else
            {
                uint64_t result{};
                if (std::from_chars(first, last, result).ec == std::errc{}) return result;
            }
        }
        double result{};
        if (std::from_chars(first, last, result).ec != std::errc{} || !std::isfinite(result))
            fail();
        return result;
    }
    Json value(size_t depth)
    {
        whitespace();
        if (depth > maximumDepth_ || offset_ == text_.size())
            fail();
        const char first = text_[offset_];
        if (first == '"')
            return string();
        if (first == '-' || digit())
            return number();
        if (first == '[' || first == '{')
        {
            ++offset_;
            const bool object = first == '{';
            const char end = object ? '}' : ']';
            auto result = object ? Json::object() : Json::array();
            whitespace();
            if (take(end))
                return result;
            for (;;)
            {
                if (object)
                {
                    auto key = string();
                    if (rejectDuplicates_ && result.contains(key))
                        fail();
                    whitespace();
                    if (!take(':')) fail();
                    result[key] = value(depth + 1);
                }
                else
                    result.push_back(value(depth + 1));
                whitespace();
                if (take(end)) return result;
                if (!take(',')) fail();
                whitespace();
            }
        }
        for (const auto& [literal, result] : {
            std::pair<std::string_view, Json>{"true", true}, {"false", false}, {"null", nullptr}})
            if (text_.substr(offset_).starts_with(literal))
            {
                offset_ += literal.size();
                return result;
            }
        fail();
    }

    std::string_view text_;
    size_t offset_{}, maximumDepth_{};
    bool rejectDuplicates_{};
};

void quote(std::string& output, std::string_view text, bool replaceInvalidUtf8)
{
    constexpr char digits[] = "0123456789abcdef";
    output += '"';
    for (size_t index = 0; index < text.size();)
    {
        const auto ch = static_cast<unsigned char>(text[index]);
        if (ch >= 0x80)
        {
            const auto width = utf8Width(text, index);
            if (width)
            {
                output.append(text.substr(index, width));
                index += width;
                continue;
            }
            if (!replaceInvalidUtf8)
                throw std::runtime_error("Invalid UTF-8 in JSON string");
            output += "\xef\xbf\xbd";
            ++index;
            continue;
        }
        ++index;
        switch (ch)
        {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (ch < 0x20)
            {
                output += "\\u00";
                output += digits[ch >> 4];
                output += digits[ch & 15];
            }
            else output += static_cast<char>(ch);
        }
    }
    output += '"';
}

template<std::integral T> std::partial_ordering compareDouble(T integer, double floating)
{
    // Check bounds before conversion; converting an out-of-range double to an integer is undefined.
    constexpr double upper = std::is_signed_v<T> ? 0x1p63 : 0x1p64;
    constexpr double lower = std::is_signed_v<T> ? -0x1p63 : 0;
    if (floating >= upper) return std::partial_ordering::less;
    if (floating < lower) return std::partial_ordering::greater;
    const auto truncated = static_cast<T>(floating);
    if (integer < truncated) return std::partial_ordering::less;
    if (integer > truncated) return std::partial_ordering::greater;
    return 0.0 <=> (floating - static_cast<double>(truncated));
}
}

Json::Json(double value) : value_(value)
{
    if (!std::isfinite(value))
        throw std::runtime_error("JSON numbers must be finite");
}

Json::Json(std::initializer_list<Json> values)
{
    const bool object = std::ranges::all_of(values, [](const Json& value)
    {
        return value.is_array() && value.size() == 2 && value[0].is_string();
    });
    if (object)
    {
        value_ = Object{};
        for (const auto& value : values)
            (*this)[value[0].string()] = value[1];
    }
    else value_ = Array(values);
}

Json Json::object()
{
    Json result;
    result.value_ = Object{};
    return result;
}

Json Json::array(std::initializer_list<Json> values)
{
    Json result;
    result.value_ = Array(values);
    return result;
}

Json Json::parse(std::string_view text, size_t maximumDepth, bool rejectDuplicates)
{
    return JsonDetail::Parser(text, maximumDepth, rejectDuplicates).parse();
}

Json Json::parse(std::istream& input, size_t maximumDepth, bool rejectDuplicates)
{
    std::string text;
    char buffer[8192];
    while (input.read(buffer, sizeof(buffer)) || input.gcount())
    {
        const auto count = static_cast<size_t>(input.gcount());
        if (count > JsonDetail::MaximumInput - text.size())
            throw std::runtime_error("JSON input exceeds the size limit");
        text.append(buffer, count);
    }
    if (!input.eof())
        throw std::runtime_error("Could not read JSON input");
    return parse(text, maximumDepth, rejectDuplicates);
}

size_t Json::size() const
{
    if (const auto value = std::get_if<Object>(&value_)) return value->size();
    if (const auto value = std::get_if<Array>(&value_)) return value->size();
    return is_null() ? 0 : 1;
}

Json::Object& Json::items()
{
    if (is_null()) value_ = Object{};
    if (const auto value = std::get_if<Object>(&value_)) return *value;
    throw std::runtime_error("Expected a JSON object");
}

const Json::Object& Json::items() const
{
    static const Object empty;
    if (is_null()) return empty;
    if (const auto value = std::get_if<Object>(&value_)) return *value;
    throw std::runtime_error("Expected a JSON object");
}

Json::Array& Json::elements()
{
    if (is_null()) value_ = Array{};
    if (const auto value = std::get_if<Array>(&value_)) return *value;
    throw std::runtime_error("Expected a JSON array");
}

const Json::Array& Json::elements() const
{
    static const Array empty;
    if (is_null()) return empty;
    if (const auto value = std::get_if<Array>(&value_)) return *value;
    throw std::runtime_error("Expected a JSON array");
}

const std::string& Json::string() const
{
    if (const auto value = std::get_if<std::string>(&value_)) return *value;
    throw std::runtime_error("Expected a JSON string");
}

Json& Json::operator[](std::string_view key)
{
    auto& object = items();
    const auto found = object.lower_bound(key);
    if (found != object.end() && found->first == key) return found->second;
    return object.emplace_hint(found, std::string(key), Json{})->second;
}

Json* Json::find(std::string_view key)
{
    if (!is_object()) return nullptr;
    auto& object = std::get<Object>(value_);
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &found->second;
}

const Json* Json::find(std::string_view key) const
{
    if (!is_object()) return nullptr;
    const auto& object = std::get<Object>(value_);
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &found->second;
}

Json& Json::at(std::string_view key)
{
    const auto found = find(key);
    if (!found) throw std::runtime_error("Missing JSON field: " + std::string(key));
    return *found;
}

const Json& Json::at(std::string_view key) const
{
    const auto found = find(key);
    if (!found) throw std::runtime_error("Missing JSON field: " + std::string(key));
    return *found;
}

void Json::erase(std::string_view key)
{
    auto& object = items();
    const auto found = object.find(key);
    if (found != object.end()) object.erase(found);
}

void Json::update(const Json& value)
{
    auto& object = items();
    for (const auto& [key, child] : value.items())
        object[key] = child;
}

void Json::push_back(Json value)
{
    elements().push_back(std::move(value));
}

size_t Json::memory() const
{
    // Include container capacity and conservative node overhead in retained-evidence budgets.
    if (const auto value = std::get_if<Object>(&value_))
    {
        size_t result = (value->size() + 1) * (sizeof(Object::value_type) + 4 * sizeof(void*) + 32);
        for (const auto& [key, child] : *value)
            result += key.capacity() + 33 + child.memory();
        return result;
    }
    if (const auto value = std::get_if<Array>(&value_))
    {
        size_t result = value->capacity() * sizeof(Json) + 32;
        for (const auto& child : *value) result += child.memory();
        return result;
    }
    if (const auto value = std::get_if<std::string>(&value_)) return value->capacity() + 33;
    return 0;
}

void Json::write(std::string& output, bool replaceInvalidUtf8, size_t depth) const
{
    if (depth > 64)
        throw std::runtime_error("JSON nesting exceeds the limit");
    std::visit([&](const auto& value)
    {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::same_as<T, std::monostate>) output += "null";
        else if constexpr (std::same_as<T, bool>) output += value ? "true" : "false";
        else if constexpr (std::same_as<T, std::string>) JsonDetail::quote(output, value, replaceInvalidUtf8);
        else if constexpr (std::same_as<T, Array> || std::same_as<T, Object>)
        {
            output += std::same_as<T, Array> ? '[' : '{';
            bool first = true;
            for (const auto& child : value)
            {
                if (!first) output += ',';
                first = false;
                if constexpr (std::same_as<T, Object>)
                {
                    JsonDetail::quote(output, child.first, replaceInvalidUtf8);
                    output += ':';
                    child.second.write(output, replaceInvalidUtf8, depth + 1);
                }
                else child.write(output, replaceInvalidUtf8, depth + 1);
            }
            output += std::same_as<T, Array> ? ']' : '}';
        }
        else
        {
            char buffer[64];
            const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
            if (result.ec != std::errc{})
                throw std::runtime_error("Could not serialize JSON number");
            const std::string_view text(buffer, result.ptr);
            output += text;
            if constexpr (std::same_as<T, double>)
                if (text.find_first_of(".eE") == std::string_view::npos) output += ".0";
        }
    }, value_);
}

std::string Json::dump(bool replaceInvalidUtf8) const
{
    std::string result;
    write(result, replaceInvalidUtf8, 0);
    return result;
}

std::partial_ordering operator<=>(const Json& left, const Json& right)
{
    if (!left.numeric() || !right.numeric())
        throw std::runtime_error("Expected JSON numbers for comparison");
    if (const auto floating = std::get_if<double>(&right.value_))
    {
        if (const auto integer = std::get_if<int64_t>(&left.value_))
            return JsonDetail::compareDouble(*integer, *floating);
        if (const auto integer = std::get_if<uint64_t>(&left.value_))
            return JsonDetail::compareDouble(*integer, *floating);
        return std::get<double>(left.value_) <=> *floating;
    }
    if (std::holds_alternative<double>(left.value_))
        return 0 <=> (right <=> left);
    if (const auto signedLeft = std::get_if<int64_t>(&left.value_))
    {
        if (const auto signedRight = std::get_if<int64_t>(&right.value_)) return *signedLeft <=> *signedRight;
        if (*signedLeft < 0) return std::partial_ordering::less;
        return static_cast<uint64_t>(*signedLeft) <=> std::get<uint64_t>(right.value_);
    }
    if (const auto signedRight = std::get_if<int64_t>(&right.value_))
    {
        if (*signedRight < 0) return std::partial_ordering::greater;
        return std::get<uint64_t>(left.value_) <=> static_cast<uint64_t>(*signedRight);
    }
    return std::get<uint64_t>(left.value_) <=> std::get<uint64_t>(right.value_);
}

bool operator==(const Json& left, const Json& right)
{
    if (left.numeric() && right.numeric()) return (left <=> right) == 0;
    return left.value_ == right.value_;
}

std::ostream& operator<<(std::ostream& output, const Json& value)
{
    return output << value.dump();
}
}
