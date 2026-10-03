#include "CertAuthority.h"

#include <iostream>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);

struct CertificateAccess
{
    static std::shared_ptr<const CERT_CONTEXT> root(CertAuthority& authority)
    {
        return {CertDuplicateCertificateContext(authority.caCert_), CertFreeCertificateContext};
    }
    static void renew(CertAuthority& authority, FILETIME now)
    {
        std::lock_guard lock(authority.mutex_);
        authority.renew(now);
    }
    static std::vector<std::wstring> containers(CertAuthority& authority)
    {
        return {authority.caContainerName_, authority.leafContainerName_};
    }
};

static FILETIME shifted(FILETIME time, int64_t seconds)
{
    ULARGE_INTEGER ticks{{time.dwLowDateTime, time.dwHighDateTime}};
    ticks.QuadPart += seconds * 10000000;
    return {ticks.LowPart, ticks.HighPart};
}

static bool trusted(HCERTSTORE store, PCCERT_CONTEXT certificate)
{
    require(CertControlStore(store, 0, CERT_STORE_CTRL_RESYNC, nullptr), "Could not refresh the trusted root store");
    const auto found = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING,
        certificate, nullptr);
    if (found)
        CertFreeCertificateContext(found);
    return found != nullptr;
}

static void verifyLeaf(PCCERT_CONTEXT leaf, FILETIME now, HCERTSTORE additional)
{
    CERT_CHAIN_PARA parameters{sizeof(parameters)};
    PCCERT_CHAIN_CONTEXT raw{};
    require(CertGetCertificateChain(HCCE_LOCAL_MACHINE, leaf, &now, additional, &parameters,
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
        CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY, nullptr, &raw), "Could not build the renewed certificate chain");
    const std::unique_ptr<const CERT_CHAIN_CONTEXT, decltype(&CertFreeCertificateChain)> chain(raw,
        CertFreeCertificateChain);
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{sizeof(ssl)};
    ssl.dwAuthType = AUTHTYPE_SERVER;
    ssl.pwszServerName = const_cast<wchar_t*>(L"renewal.test");
    CERT_CHAIN_POLICY_PARA policy{sizeof(policy)};
    policy.pvExtraPolicyPara = &ssl;
    CERT_CHAIN_POLICY_STATUS status{sizeof(status)};
    require(CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain.get(), &policy, &status) && !status.dwError,
        "The renewed certificate failed Windows TLS name, trust, time, or revocation validation");
}

void certificateRenewalCoverage()
{
    // This check installs a temporary machine root and must run elevated in the lab.
    const auto closeStore = [](void* store) { if (store) CertCloseStore(store, 0); };
    const std::unique_ptr<void, decltype(closeStore)> roots(CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"ROOT"), closeStore);
    const std::unique_ptr<void, decltype(closeStore)> lists(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr),
        closeStore);
    require(roots && lists, "Certificate test stores could not be opened");
    std::vector<std::shared_ptr<const CERT_CONTEXT>> issuedRoots;
    std::vector<std::wstring> containers;
    {
        CertAuthority authority;
        authority.setRevocationUrl("http://127.0.0.1/renewal-test.crl");
        containers = CertificateAccess::containers(authority);
        auto oldLeaf = authority.leaf("renewal.test");
        auto root = CertificateAccess::root(authority);
        issuedRoots.push_back(root);
        require(trusted(roots.get(), root.get()), "The initial root was not installed");
        CertificateAccess::renew(authority, shifted(root->pCertInfo->NotAfter, -6 * 60));
        require(authority.leaf("renewal.test") == oldLeaf, "The CA renewed before its renewal window");

        // Advance only the authority's input time, then exercise real trust-store, leaf, and CRL operations.
        for (int cycle = 0; cycle < 2; ++cycle)
        {
            const auto due = shifted(root->pCertInfo->NotAfter, -5 * 60);
            CertificateAccess::renew(authority, due);
            const auto renewed = CertificateAccess::root(authority);
            const auto leaf = authority.leaf("renewal.test");
            issuedRoots.push_back(renewed);
            require(leaf != oldLeaf && CompareFileTime(&leaf->pCertInfo->NotAfter, &root->pCertInfo->NotAfter) > 0,
                "Renewal returned a cached leaf with the old expiry");
            require(CertComparePublicKeyInfo(X509_ASN_ENCODING, &root->pCertInfo->SubjectPublicKeyInfo,
                &renewed->pCertInfo->SubjectPublicKeyInfo), "Renewal changed the CA signing key");
            require(!trusted(roots.get(), root.get()) && trusted(roots.get(), renewed.get()),
                "Renewal left an obsolete root trusted or failed to install its replacement");
            const auto encoded = authority.revocationList();
            const std::unique_ptr<const CRL_CONTEXT, decltype(&CertFreeCRLContext)> list(
                CertCreateCRLContext(X509_ASN_ENCODING, encoded.data(), static_cast<DWORD>(encoded.size())),
                CertFreeCRLContext);
            require(list && CompareFileTime(&list->pCrlInfo->NextUpdate, &renewed->pCertInfo->NotAfter) == 0 &&
                CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL,
                    const_cast<PCRL_CONTEXT>(list.get()), CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
                    const_cast<PCERT_CONTEXT>(renewed.get()), 0, nullptr),
                "The renewed revocation list has the wrong expiry or signature");
            require(CertAddCRLContextToStore(lists.get(), list.get(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr),
                "Could not load the renewed revocation list");
            verifyLeaf(oldLeaf.get(), due, lists.get());
            verifyLeaf(leaf.get(), shifted(root->pCertInfo->NotAfter, 60), lists.get());
            root = renewed;
            oldLeaf = leaf;
        }
    }
    for (const auto& root : issuedRoots)
        require(!trusted(roots.get(), root.get()), "The authority left a root trusted after shutdown");
    for (const auto& name : containers)
    {
        HCRYPTPROV provider{};
        const bool exists = CryptAcquireContextW(&provider, name.c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
            CRYPT_MACHINE_KEYSET);
        if (exists)
            CryptReleaseContext(provider, 0);
        require(!exists, "The authority left a private key container after shutdown");
    }
    std::cout << "Certificate renewal, cached leaves, revocation, and cleanup checks passed.\n";
}
}
