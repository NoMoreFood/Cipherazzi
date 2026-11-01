#pragma once

#include <compare>
#include <concepts>
#include <cstdint>
#include <iosfwd>
#include <limits>
#include <map>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace Cipherazzi
{
// JSON values for public protocol evidence, configuration, and endpoint reports.
class Json
{
public:
    using Array = std::vector<Json>;
    using Object = std::map<std::string, Json, std::less<>>;

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool value) : value_(value) {}
    template<std::integral T> requires (!std::same_as<T, bool>)
    Json(T value)
    {
        if constexpr (std::is_unsigned_v<T>) value_ = static_cast<uint64_t>(value);
        else value_ = static_cast<int64_t>(value);
    }
    Json(double value);
    template<class T> requires std::is_enum_v<T>
    Json(T value) : Json(std::to_underlying(value)) {}
    Json(std::string value) : value_(std::move(value)) {}
    Json(std::string_view value) : value_(std::string(value)) {}
    Json(const char* value) : Json(value ? Json(std::string(value)) : Json()) {}
    Json(std::initializer_list<Json> values);
    template<std::ranges::input_range T>
        requires (!std::convertible_to<T, std::string_view> && !std::same_as<T, Json>)
    Json(const T& values) : value_(Array{})
    {
        auto& result = std::get<Array>(value_);
        for (const auto& value : values)
            result.emplace_back(value);
    }

    static Json object();
    static Json array(std::initializer_list<Json> values = {});
    static Json parse(std::string_view text, size_t maximumDepth = 64, bool rejectDuplicates = false);
    static Json parse(std::istream& input, size_t maximumDepth = 64, bool rejectDuplicates = false);
    std::string dump(bool replaceInvalidUtf8 = false) const;
    size_t memory() const;

    bool is_null() const { return std::holds_alternative<std::monostate>(value_); }
    bool is_object() const { return std::holds_alternative<Object>(value_); }
    bool is_array() const { return std::holds_alternative<Array>(value_); }
    bool is_string() const { return std::holds_alternative<std::string>(value_); }
    bool is_number_unsigned() const { return std::holds_alternative<uint64_t>(value_); }
    bool is_number_integer() const { return std::holds_alternative<int64_t>(value_) || is_number_unsigned(); }
    size_t size() const;
    bool empty() const { return size() == 0; }

    Json& operator[](std::string_view key);
    const Json& operator[](std::string_view key) const { return at(key); }
    Json& operator[](size_t index) { return elements().at(index); }
    const Json& operator[](size_t index) const { return elements().at(index); }
    Json& at(std::string_view key);
    const Json& at(std::string_view key) const;
    Json* find(std::string_view key);
    const Json* find(std::string_view key) const;
    bool contains(std::string_view key) const { return find(key) != nullptr; }
    void erase(std::string_view key);
    void update(const Json& value);
    void push_back(Json value);
    Json& back() { return elements().back(); }
    const Json& back() const { return elements().back(); }
    Object& items();
    const Object& items() const;
    Array& elements();
    const Array& elements() const;
    const std::string& string() const;
    auto begin() { return elements().begin(); }
    auto end() { return elements().end(); }
    auto begin() const { return elements().begin(); }
    auto end() const { return elements().end(); }

    template<class T> T get() const
    {
        if constexpr (std::same_as<T, Json>) return *this;
        else if constexpr (std::same_as<T, std::string>) return string();
        else
        {
            if constexpr (std::same_as<T, bool>)
            {
                if (const auto value = std::get_if<bool>(&value_)) return *value;
            }
            else if constexpr (std::integral<T>)
            {
                if (const auto value = std::get_if<int64_t>(&value_))
                {
                    if constexpr (std::is_unsigned_v<T>)
                    {
                        if (*value >= 0 && static_cast<uint64_t>(*value) <= std::numeric_limits<T>::max())
                            return static_cast<T>(*value);
                    }
                    else if (*value >= std::numeric_limits<T>::min() && *value <= std::numeric_limits<T>::max())
                        return static_cast<T>(*value);
                }
                if (const auto value = std::get_if<uint64_t>(&value_))
                    if (*value <= static_cast<uint64_t>(std::numeric_limits<T>::max()))
                        return static_cast<T>(*value);
            }
            else if constexpr (std::same_as<T, double>)
            {
                if (const auto value = std::get_if<double>(&value_)) return *value;
                if (const auto value = std::get_if<int64_t>(&value_)) return static_cast<double>(*value);
                if (const auto value = std::get_if<uint64_t>(&value_)) return static_cast<double>(*value);
            }
            else static_assert(sizeof(T) == 0, "Unsupported JSON conversion");
            throw std::runtime_error("Invalid JSON value type or numeric range");
        }
    }

    template<class T> T value(std::string_view key, T fallback) const
    {
        if (!is_object())
            throw std::runtime_error("Expected a JSON object for field: " + std::string(key));
        const auto found = find(key);
        return found ? found->get<T>() : std::move(fallback);
    }
    std::string value(std::string_view key, const char* fallback) const
    {
        return value(key, std::string(fallback));
    }

    friend bool operator==(const Json& left, const Json& right);
    friend std::partial_ordering operator<=>(const Json& left, const Json& right);
    friend std::ostream& operator<<(std::ostream& output, const Json& value);

private:
    using Storage = std::variant<std::monostate, bool, int64_t, uint64_t, double, std::string, Array, Object>;
    void write(std::string& output, bool replaceInvalidUtf8, size_t depth) const;
    bool numeric() const { return is_number_integer() || std::holds_alternative<double>(value_); }
    Storage value_;
};
}
