#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <memory>
#include <vector>

namespace Cipherazzi
{
namespace Tests { struct CertificateAccess; }

// Generates a temporary root CA for transparent HTTPS interception, installs it in the machine's Trusted Root
// store, and creates leaf certificates on demand. Everything is removed when the object is destroyed, and a root
// that a killed collector left behind is removed when the next one starts.
class CertAuthority
{
public:
    CertAuthority();
    ~CertAuthority();
    CertAuthority(const CertAuthority&) = delete;
    CertAuthority& operator=(const CertAuthority&) = delete;

    // Returns a certificate for the given hostname, signed by the root CA and backed by the shared leaf key.
    // Callers retain their certificate context through cache eviction and CA renewal. Thread-safe.
    std::shared_ptr<const CERT_CONTEXT> leaf(const std::string& hostname);

    // Leaf certificates created afterwards name this URL as their revocation list, so that clients which check
    // revocation can verify them. The caller serves revocationList() there: an empty list signed by the root.
    void setRevocationUrl(std::string url);
    std::vector<BYTE> revocationList();
    void check();

private:
    friend struct Tests::CertificateAccess;
    void create();
    void renew(FILETIME now);
    void release() noexcept;
    static void removeAbandoned();
    PCCERT_CONTEXT generate(const std::string& hostname);
    std::vector<BYTE> encodeSubject(const std::wstring& cn);
    std::vector<BYTE> encodeSan(const std::wstring& dns);

    HCRYPTPROV caProvider_{}, leafProvider_{};
    PCCERT_CONTEXT caCert_{};
    HCERTSTORE machineRoot_{};
    std::vector<BYTE> leafPublicKeyInfo_;
    std::mutex mutex_;
    uint32_t serial_{};
    std::string revocationUrl_;
    std::vector<BYTE> revocationList_;

    struct CertFree { void operator()(const CERT_CONTEXT* c) const { if (c) CertFreeCertificateContext(c); } };
    std::unordered_map<std::string, std::shared_ptr<const CERT_CONTEXT>> cache_;
    std::wstring caContainerName_, leafContainerName_;
};

}
