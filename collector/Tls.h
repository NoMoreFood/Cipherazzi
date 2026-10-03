#pragma once

#include "Model.h"
#include <functional>

namespace Cipherazzi
{
struct Hello
{
    uint8_t type{};
    bool client{};
    bool retry{};
    bool ech{};
    uint16_t version{};
    uint16_t cipher{};
    uint16_t dtlsVersion{};
    std::string sni;
    std::string versions;
    std::string ciphers;
    std::string alpn;
    Observation::Crypto crypto;
    NegotiationStage stage;
    std::vector<uint8_t> body;
};

void applyHello(Observation& observation, const Hello& hello, int64_t timestampUs);
bool parseHello(Bytes bytes, Hello& hello, bool dtls = false);

bool parseKeyExchange(Bytes bytes, uint16_t version, uint16_t cipher, Observation::Crypto& crypto);

class TlsStream
{
public:
    using Sink = std::function<void(const Hello&)>;
    bool feed(Bytes bytes, const Sink& sink);
    bool feedHandshake(Bytes bytes, const Sink& sink);
    size_t memory() const;
    bool malformed() const { return malformed_; }
    bool limited() const { return limited_; }

    // The bounded plaintext scan ended without finding a record, so the stream held no handshake to lose.
    bool unmatched() const { return unmatched_; }
    bool finished() const { return finished_; }
    void selectVersion(uint16_t version) { version_ = version; }
    void expectTls() { knownTls_ = true; }

private:
    bool parseHandshake(const Sink& sink);
    std::vector<uint8_t> records_;
    std::vector<uint8_t> handshake_;
    size_t scanned_{};
    bool synchronized_{};
    bool knownTls_{};
    bool finished_{};
    bool malformed_{};
    bool limited_{};
    bool unmatched_{};
    bool afterCcs_{};
    uint16_t version_{};
};
}
