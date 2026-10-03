#pragma once

#include "Crypto.h"

namespace Cipherazzi
{
struct SshMessage
{
    enum class Type : uint8_t { Banner, KexInit, NewKeys, KeyReply };
    Type type{};
    std::string banner;
    std::array<std::string, 10> algorithms;
    Bytes reply;
};

class SshStream
{
public:
    using Sink = std::function<void(const SshMessage&)>;
    bool feed(Bytes bytes, const Sink& sink);
    size_t memory() const { return buffer_.capacity(); }
    bool finished() const { return finished_; }
    bool limited() const { return limited_; }

private:
    std::vector<uint8_t> buffer_;
    size_t scanned_{};
    bool identified_{}, kexInit_{}, finished_{}, limited_{}, skipGuess_{};
};

class PayloadSample
{
public:
    static constexpr size_t Minimum = 4096, Maximum = 8192;
    void feed(Bytes bytes);
    bool complete() const { return bytes_ == Maximum; }
    bool classify(Observation& observation, int direction) const;

private:
    std::array<uint32_t, 256> counts_{};
    std::array<uint8_t, 8> prefix_{};
    size_t bytes_{};
};

void applySsh(Observation& observation, int peer, const SshMessage& message);
CryptoSummary summarizeProtocol(const Observation& observation);
}
