#pragma once

#include "Crypto.h"

namespace Cipherazzi
{
struct DatabaseNegotiation
{
    enum class Kind { None, PostgreSql, MySql } kind{};
    enum class Encryption { None, SslRequest, GssRequest, Tls } encryption{};
    int client{-1};
    uint32_t capabilities{};
    uint8_t sequence{};
    std::string authentication;
    bool finished{};
};

class DatabaseStream
{
public:
    using Sink = std::function<bool(Bytes, const nlohmann::json&, bool)>;
    DatabaseStream(DatabaseNegotiation& negotiation, int direction) : state_(negotiation), direction_(direction) {}
    static DatabaseNegotiation::Kind recognizes(Bytes bytes);
    bool feed(Bytes bytes, const Sink& sink);
    size_t memory() const { return sizeof(*this) + buffer_.capacity(); }
    bool limited() const { return limited_; }
    bool finished() const { return state_.finished; }

private:
    DatabaseNegotiation& state_;
    int direction_{};
    std::vector<uint8_t> buffer_;
    bool started_{}, limited_{};
};
}
