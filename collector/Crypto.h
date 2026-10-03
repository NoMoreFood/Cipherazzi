#pragma once

#include "Model.h"
#include <deque>
#include <functional>
#include <unordered_map>
#include <nlohmann/json.hpp>

namespace Cipherazzi
{
struct CryptoSummary
{
    struct CertificateReference
    {
        nlohmann::json certificateMetadata(Bytes bytes);
std::string signatureClass(int id);
std::string sha256;
        std::string role;
        size_t position{};
    };
    std::string json, group, exchange, encryption, hash, authentication, psk, certificate;
    std::vector<CertificateReference> certificates;
    int keyBits{};
};

class CryptoCatalog
{
public:
    using CertificateSink = std::function<void(const std::string&, const std::string&, Bytes)>;
    CryptoSummary summarize(const Observation& observation, const CertificateSink& sink);
    void forget(const std::string& hash);

private:
    std::unordered_map<std::string, std::string> certificates_;
    std::deque<std::string> order_;
    size_t certificateBytes_{};
};

nlohmann::json certificateMetadata(Bytes bytes);
std::string signatureClass(int id);
std::string sha256(Bytes bytes);
std::string alertName(int code);
}
