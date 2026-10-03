#pragma once

#include "KeyLog.h"
#include <windows.h>
#include <bcrypt.h>
#include <deque>
#include <functional>
#include <memory>
#include <string>

namespace Cipherazzi
{
// Opens records protected by AES-GCM or ChaCha20-Poly1305.
class Aead
{
public:
    enum class Kind : uint8_t { None, AesGcm, ChaCha };
    Aead() = default;
    Aead(Kind kind, Bytes key);
    bool open(Bytes nonce, Bytes aad, Bytes sealed, std::vector<uint8_t>& plain) const;
    explicit operator bool() const { return kind_ != Kind::None; }

private:
    struct KeyCloser { void operator()(BCRYPT_KEY_HANDLE key) const { BCryptDestroyKey(key); } };
    Kind kind_{};
    std::unique_ptr<std::remove_pointer_t<BCRYPT_KEY_HANDLE>, KeyCloser> handle_;
    std::array<uint8_t, 32> key_{};
};

// Follows one TLS 1.2 or 1.3 connection from its cleartext hellos and decrypts application data using secrets that
// the application exported. Directions are numbered 0 for client to server and 1 for server to client.
class TlsDecryptor
{
public:
    enum class State : uint8_t { Running, Unsupported, Failed };
    using Sink = std::function<void(int direction, Bytes plaintext, int64_t timestampUs)>;
    TlsDecryptor(const KeyLog& keys, size_t queueLimit);
    void feed(int direction, Bytes bytes, int64_t timestampUs, const Sink& sink);

    // Looks for secrets again when the key log has grown since the last attempt.
    void retry(const Sink& sink);
    State state() const { return state_; }
    bool finished() const { return state_ == State::Unsupported || state_ == State::Failed; }
    bool waiting() const { return !sides_[0].queue.empty() || !sides_[1].queue.empty(); }
    std::string reason() const;
    const std::string& serverName() const { return serverName_; }
    const std::string& alpn() const { return alpn_; }
    uint16_t version() const { return version_; }
    uint16_t cipher() const { return cipher_; }
    int64_t timestampUs() const { return recordUs_; }
    size_t memory() const;

private:
    enum class Result : uint8_t { Done, NeedSecrets };
    struct Suite
    {
        Aead::Kind kind{};
        size_t keyBytes{}, ivBytes{};
        bool sha384{};
    };
    struct Record { std::vector<uint8_t> bytes; int64_t timestampUs{}; };
    struct Side
    {
        std::vector<uint8_t> buffer, handshake;
        std::deque<Record> queue;
        size_t queued{};
        Aead aead;
        std::array<uint8_t, 12> iv{};
        std::vector<uint8_t> secret;
        uint64_t sequence{};
        bool protectedRecords{}, application{};
    };
    void record(int direction, uint8_t type, Bytes fragment, const Sink& sink);
    void drain(const Sink& sink);
    Result handle(int direction, uint8_t type, Bytes fragment, const Sink& sink);
    Result openRecord(int direction, uint8_t type, Bytes fragment, const Sink& sink);
    bool clearHandshake(int direction);
    bool handshakeMessages(int direction, bool encrypted);
    bool parseClientHello(Bytes body);
    bool parseServerHello(Bytes body);
    bool secretsFor(int direction);
    bool install13(Side& side, Bytes secret);
    void fail(State state, std::string reason);
    const KeyLog& keys_;
    size_t queueLimit_;
    Side sides_[2];
    std::optional<TlsSecrets> secrets_;
    std::vector<uint8_t> keyBlock_;
    std::array<uint8_t, 32> clientRandom_{}, serverRandom_{};
    std::string serverName_, alpn_, reason_;
    uint64_t generation_{};
    int64_t recordUs_{};
    uint16_t version_{}, cipher_{};
    Suite suite_;
    State state_{State::Running};
    bool haveClient_{}, haveServer_{}, tls13_{};
};
}
