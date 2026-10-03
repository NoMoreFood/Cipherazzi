#include "CertAuthority.h"
#include <ws2tcpip.h>

#include <bcrypt.h>
#include <array>
#include <cstdlib>
#include <iterator>
#include <stdexcept>

namespace Cipherazzi
{

// DER-encode a CN=value subject name. A UTF-8 string value is supplied as UTF-16 text.
std::vector<BYTE> CertAuthority::encodeSubject(const std::wstring& cn)
{
    CERT_RDN_ATTR attr{};
    attr.pszObjId = const_cast<char*>(szOID_COMMON_NAME);
    attr.dwValueType = CERT_RDN_UTF8_STRING;
    attr.Value.cbData = static_cast<DWORD>(cn.size() * sizeof(wchar_t));
    attr.Value.pbData = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(cn.data()));
    CERT_RDN rdn{1, &attr};
    CERT_NAME_INFO nameInfo{1, &rdn};
    DWORD size = 0;
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &nameInfo, 0, nullptr, nullptr, &size);
    std::vector<BYTE> result(size);
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &nameInfo, 0, nullptr, result.data(), &size))
        throw std::runtime_error("CertAuthority: failed to encode subject name");
    result.resize(size);
    return result;
}

// DER-encode a SubjectAlternativeName extension with one DNS entry.
std::vector<BYTE> CertAuthority::encodeSan(const std::wstring& dns)
{
    std::array<BYTE, 16> address{};
    CERT_ALT_NAME_ENTRY entry{};
    const auto sizeBytes = InetPtonW(AF_INET, dns.c_str(), address.data()) == 1 ? 4 :
        InetPtonW(AF_INET6, dns.c_str(), address.data()) == 1 ? 16 : 0;
    if (sizeBytes)
    {
        entry.dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
        entry.IPAddress = {static_cast<DWORD>(sizeBytes), address.data()};
    }
    else
    {
        entry.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
        entry.pwszDNSName = const_cast<wchar_t*>(dns.c_str());
    }
    CERT_ALT_NAME_INFO sanInfo{1, &entry};
    DWORD size = 0;
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &sanInfo, 0, nullptr, nullptr, &size);
    std::vector<BYTE> result(size);
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &sanInfo, 0, nullptr, result.data(), &size))
        throw std::runtime_error("CertAuthority: failed to encode SAN");
    result.resize(size);
    return result;
}

static std::vector<BYTE> encodeExtension(LPCSTR oid, const void* structure)
{
    DWORD size = 0;
    CryptEncodeObjectEx(X509_ASN_ENCODING, oid, structure, 0, nullptr, nullptr, &size);
    std::vector<BYTE> result(size);
    CryptEncodeObjectEx(X509_ASN_ENCODING, oid, structure, 0, nullptr, result.data(), &size);
    result.resize(size);
    return result;
}

constexpr wchar_t CaName[] = L"Cipherazzi HTTP Spy CA", CaContainerPrefix[] = L"Cipherazzi-CA-";

// Deletes a machine key container; a missing container is not an error.
static void deleteContainer(const std::wstring& name)
{
    HCRYPTPROV ignored{};
    CryptAcquireContextW(&ignored, name.c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
        CRYPT_MACHINE_KEYSET | CRYPT_DELETEKEYSET);
}

// A collector that was killed leaves its root trusted until the certificate expires. Remove each self-signed
// root of this kind whose key container names a process that is no longer running.
void CertAuthority::removeAbandoned()
{
    const auto store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"ROOT");
    if (!store)
        return;
    PCCERT_CONTEXT found = nullptr;
    while ((found = CertEnumCertificatesInStore(store, found)))
    {
        DWORD size = 0;
        CertGetCertificateContextProperty(found, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size);
        std::vector<BYTE> property(size);
        if (!size || !CertGetCertificateContextProperty(found, CERT_KEY_PROV_INFO_PROP_ID, property.data(), &size) ||
            !CertCompareCertificateName(X509_ASN_ENCODING, &found->pCertInfo->Subject, &found->pCertInfo->Issuer))
            continue;
        const auto* provider = reinterpret_cast<const CRYPT_KEY_PROV_INFO*>(property.data());
        const std::wstring container = provider->pwszContainerName ? provider->pwszContainerName : L"";
        if (!container.starts_with(CaContainerPrefix))
            continue;

        // The process named by the container owns the root, unless a process that started after the root was
        // issued has since reused its identifier.
        const auto pid = static_cast<DWORD>(std::wcstoul(container.c_str() + std::size(CaContainerPrefix) - 1,
            nullptr, 10));
        const std::unique_ptr<void, decltype(&CloseHandle)> owner(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid), CloseHandle);
        FILETIME created{}, exited{}, kernel{}, user{};
        const bool running = owner && WaitForSingleObject(owner.get(), 0) == WAIT_TIMEOUT &&
            GetProcessTimes(owner.get(), &created, &exited, &kernel, &user) &&
            CompareFileTime(&created, &found->pCertInfo->NotBefore) <= 0;
        if (pid == GetCurrentProcessId() || running)
            continue;
        CertDeleteCertificateFromStore(CertDuplicateCertificateContext(found));
        deleteContainer(container);
    }
    CertCloseStore(store, 0);
}

CertAuthority::CertAuthority()
{
    // A constructor that fails never runs the destructor, so release whatever exists before rethrowing.
    try { create(); }
    catch (...)
    {
        release();
        throw;
    }
}

void CertAuthority::create()
{
    removeAbandoned();
    auto suffix = std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    caContainerName_ = CaContainerPrefix + suffix;
    leafContainerName_ = L"Cipherazzi-Leaf-" + suffix;

    // CA signing key (AT_SIGNATURE)
    if (!CryptAcquireContextW(&caProvider_, caContainerName_.c_str(), MS_ENH_RSA_AES_PROV_W,
        PROV_RSA_AES, CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET))
        throw std::runtime_error("CertAuthority: failed to create CA key container (" +
            std::to_string(GetLastError()) + ")");
    HCRYPTKEY caKey{};
    if (!CryptGenKey(caProvider_, AT_SIGNATURE, (2048 << 16), &caKey))
        throw std::runtime_error("CertAuthority: failed to generate CA key (" +
            std::to_string(GetLastError()) + ")");
    CryptDestroyKey(caKey);

    // Leaf TLS key (AT_KEYEXCHANGE for Schannel server credentials)
    if (!CryptAcquireContextW(&leafProvider_, leafContainerName_.c_str(), MS_ENH_RSA_AES_PROV_W,
        PROV_RSA_AES, CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET))
        throw std::runtime_error("CertAuthority: failed to create leaf key container");
    HCRYPTKEY leafKey{};
    if (!CryptGenKey(leafProvider_, AT_KEYEXCHANGE, (2048 << 16), &leafKey))
        throw std::runtime_error("CertAuthority: failed to generate leaf key");
    CryptDestroyKey(leafKey);

    // Export the leaf public key info for embedding in leaf certificates.
    DWORD pubSize = 0;
    CryptExportPublicKeyInfo(leafProvider_, AT_KEYEXCHANGE, X509_ASN_ENCODING, nullptr, &pubSize);
    leafPublicKeyInfo_.resize(pubSize);
    if (!CryptExportPublicKeyInfo(leafProvider_, AT_KEYEXCHANGE, X509_ASN_ENCODING,
        reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(leafPublicKeyInfo_.data()), &pubSize))
        throw std::runtime_error("CertAuthority: failed to export leaf public key");

    // Install the temporary root before accepting intercepted connections.
    machineRoot_ = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"ROOT");
    if (!machineRoot_)
        throw std::runtime_error("CertAuthority: failed to open Trusted Root store; run as administrator");
    check();
}

void CertAuthority::check()
{
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    std::lock_guard lock(mutex_);
    renew(now);
}

void CertAuthority::renew(FILETIME now)
{
    // Renew with the same key before expiry so active connections and cached revocation lists remain usable.
    ULARGE_INTEGER ticks{{now.dwLowDateTime, now.dwHighDateTime}};
    if (caCert_)
    {
        const auto& end = caCert_->pCertInfo->NotAfter;
        ULARGE_INTEGER expires{{end.dwLowDateTime, end.dwHighDateTime}};
        if (ticks.QuadPart + 5ULL * 60 * 10000000 < expires.QuadPart)
            return;
    }

    // CA certificate extensions
    CERT_BASIC_CONSTRAINTS2_INFO bc{TRUE, TRUE, 0};
    auto bcEnc = encodeExtension(X509_BASIC_CONSTRAINTS2, &bc);
    BYTE usageByte = CERT_KEY_CERT_SIGN_KEY_USAGE | CERT_CRL_SIGN_KEY_USAGE;
    CRYPT_BIT_BLOB usageBlob{1, &usageByte, 0};
    auto kuEnc = encodeExtension(X509_KEY_USAGE, &usageBlob);
    CERT_EXTENSION extensions[] = {
        {const_cast<char*>(szOID_BASIC_CONSTRAINTS2), TRUE,
            {static_cast<DWORD>(bcEnc.size()), bcEnc.data()}},
        {const_cast<char*>(szOID_KEY_USAGE), TRUE,
            {static_cast<DWORD>(kuEnc.size()), kuEnc.data()}}
    };
    CERT_EXTENSIONS exts{2, extensions};

    // Self-signed CA certificate valid for one day
    auto subject = encodeSubject(CaName);
    CERT_NAME_BLOB subjectBlob{static_cast<DWORD>(subject.size()), subject.data()};
    CRYPT_KEY_PROV_INFO provInfo{};
    provInfo.pwszContainerName = const_cast<wchar_t*>(caContainerName_.c_str());
    provInfo.pwszProvName = const_cast<wchar_t*>(MS_ENH_RSA_AES_PROV_W);
    provInfo.dwProvType = PROV_RSA_AES;
    provInfo.dwKeySpec = AT_SIGNATURE;
    provInfo.dwFlags = CRYPT_MACHINE_KEYSET;
    CRYPT_ALGORITHM_IDENTIFIER sigAlg{};
    sigAlg.pszObjId = const_cast<char*>(szOID_RSA_SHA256RSA);
    SYSTEMTIME start{}, end{};
    FileTimeToSystemTime(&now, &start);
    ticks.QuadPart += 24ULL * 3600 * 10000000;
    FILETIME expires{ticks.LowPart, ticks.HighPart};
    FileTimeToSystemTime(&expires, &end);
    std::unique_ptr<const CERT_CONTEXT, CertFree> certificate(
        CertCreateSelfSignCertificate(caProvider_, &subjectBlob, 0, &provInfo, &sigAlg, &start, &end, &exts));
    if (!certificate)
        throw std::runtime_error("CertAuthority: failed to create CA certificate (" +
            std::to_string(GetLastError()) + ")");

    // Prepare the matching revocation list before changing the trusted root.
    CRYPT_ALGORITHM_IDENTIFIER algorithm{};
    algorithm.pszObjId = const_cast<char*>(szOID_RSA_SHA256RSA);
    CRL_INFO list{};
    list.dwVersion = CRL_V1;
    list.SignatureAlgorithm = algorithm;
    list.Issuer = certificate->pCertInfo->Subject;
    list.ThisUpdate = certificate->pCertInfo->NotBefore;
    list.NextUpdate = certificate->pCertInfo->NotAfter;
    DWORD size = 0;
    if (!CryptSignAndEncodeCertificate(caProvider_, AT_SIGNATURE, X509_ASN_ENCODING, X509_CERT_CRL_TO_BE_SIGNED,
        &list, &algorithm, nullptr, nullptr, &size))
        throw std::runtime_error("CertAuthority: failed to measure the revocation list");
    std::vector<BYTE> encoded(size);
    if (!CryptSignAndEncodeCertificate(caProvider_, AT_SIGNATURE, X509_ASN_ENCODING, X509_CERT_CRL_TO_BE_SIGNED,
        &list, &algorithm, nullptr, encoded.data(), &size))
        throw std::runtime_error("CertAuthority: failed to sign the revocation list");
    encoded.resize(size);

    PCCERT_CONTEXT installed{};
    if (!CertAddCertificateContextToStore(machineRoot_, certificate.get(), CERT_STORE_ADD_NEW, &installed))
        throw std::runtime_error("CertAuthority: failed to install CA in Trusted Root store (" +
            std::to_string(GetLastError()) + ")");
    if (caCert_)
    {
        const auto previous = CertFindCertificateInStore(machineRoot_, X509_ASN_ENCODING, 0,
            CERT_FIND_EXISTING, caCert_, nullptr);
        if (previous && !CertDeleteCertificateFromStore(previous))
        {
            CertDeleteCertificateFromStore(installed);
            throw std::runtime_error("CertAuthority: failed to remove the previous CA certificate");
        }
        CertFreeCertificateContext(caCert_);
    }
    CertFreeCertificateContext(installed);
    caCert_ = certificate.release();
    revocationList_ = std::move(encoded);
    cache_.clear();
}

CertAuthority::~CertAuthority() { release(); }

void CertAuthority::release() noexcept
{
    cache_.clear();
    if (machineRoot_ && caCert_)
        if (auto found = CertFindCertificateInStore(machineRoot_, X509_ASN_ENCODING, 0,
            CERT_FIND_EXISTING, caCert_, nullptr))
            CertDeleteCertificateFromStore(found);
    if (machineRoot_)
        CertCloseStore(machineRoot_, 0);
    if (caCert_)
        CertFreeCertificateContext(caCert_);
    if (leafProvider_)
        CryptReleaseContext(leafProvider_, 0);
    if (caProvider_)
        CryptReleaseContext(caProvider_, 0);
    machineRoot_ = nullptr;
    caCert_ = nullptr;
    leafProvider_ = caProvider_ = 0;
    if (!caContainerName_.empty())
        deleteContainer(caContainerName_);
    if (!leafContainerName_.empty())
        deleteContainer(leafContainerName_);
}

void CertAuthority::setRevocationUrl(std::string url)
{
    std::lock_guard lock(mutex_);
    cache_.clear();
    revocationUrl_ = std::move(url);
}

std::vector<BYTE> CertAuthority::revocationList()
{
    check();
    std::lock_guard lock(mutex_);
    return revocationList_;
}

std::shared_ptr<const CERT_CONTEXT> CertAuthority::leaf(const std::string& hostname)
{
    check();

    // Callers hold their certificate, so the cache can be dropped when a flood of names fills it.
    std::lock_guard lock(mutex_);
    if (auto it = cache_.find(hostname); it != cache_.end())
        return it->second;
    if (cache_.size() >= 512)
        cache_.clear();
    std::shared_ptr<const CERT_CONTEXT> cert(generate(hostname), CertFree{});
    cache_.emplace(hostname, cert);
    return cert;
}

PCCERT_CONTEXT CertAuthority::generate(const std::string& hostname)
{
    CERT_INFO info{};
    info.dwVersion = CERT_V3;

    // Monotonic serial
    ++serial_;
    BYTE serialBytes[4];
    memcpy(serialBytes, &serial_, sizeof(serialBytes));
    info.SerialNumber = {sizeof(serialBytes), serialBytes};

    CRYPT_ALGORITHM_IDENTIFIER sigAlg{};
    sigAlg.pszObjId = const_cast<char*>(szOID_RSA_SHA256RSA);
    info.SignatureAlgorithm = sigAlg;
    info.Issuer = caCert_->pCertInfo->Subject;
    info.NotBefore = caCert_->pCertInfo->NotBefore;
    info.NotAfter = caCert_->pCertInfo->NotAfter;

    // A common name holds at most 64 characters; the subject alternative name carries the whole host name.
    const auto wideHost = std::wstring(hostname.begin(), hostname.end());
    auto subject = encodeSubject(wideHost.substr(0, 64));
    info.Subject = {static_cast<DWORD>(subject.size()), subject.data()};
    info.SubjectPublicKeyInfo = *reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(leafPublicKeyInfo_.data());

    // Extensions: BasicConstraints(CA=FALSE), KeyUsage, ExtKeyUsage(serverAuth), SAN
    CERT_BASIC_CONSTRAINTS2_INFO bc{FALSE, FALSE, 0};
    auto bcEnc = encodeExtension(X509_BASIC_CONSTRAINTS2, &bc);
    BYTE usageByte = CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE;
    CRYPT_BIT_BLOB usageBlob{1, &usageByte, 0};
    auto kuEnc = encodeExtension(X509_KEY_USAGE, &usageBlob);
    LPSTR serverAuth = const_cast<char*>(szOID_PKIX_KP_SERVER_AUTH);
    CERT_ENHKEY_USAGE eku{1, &serverAuth};
    auto ekuEnc = encodeExtension(X509_ENHANCED_KEY_USAGE, &eku);
    auto sanEnc = encodeSan(wideHost);

    std::vector<CERT_EXTENSION> extensions = {
        {const_cast<char*>(szOID_BASIC_CONSTRAINTS2), FALSE,
            {static_cast<DWORD>(bcEnc.size()), bcEnc.data()}},
        {const_cast<char*>(szOID_KEY_USAGE), TRUE,
            {static_cast<DWORD>(kuEnc.size()), kuEnc.data()}},
        {const_cast<char*>(szOID_ENHANCED_KEY_USAGE), FALSE,
            {static_cast<DWORD>(ekuEnc.size()), ekuEnc.data()}},
        {const_cast<char*>(szOID_SUBJECT_ALT_NAME2), FALSE,
            {static_cast<DWORD>(sanEnc.size()), sanEnc.data()}}
    };

    // Point revocation-checking clients at the list that the proxy serves.
    const std::wstring wideUrl(revocationUrl_.begin(), revocationUrl_.end());
    CERT_ALT_NAME_ENTRY urlEntry{};
    urlEntry.dwAltNameChoice = CERT_ALT_NAME_URL;
    urlEntry.pwszURL = const_cast<wchar_t*>(wideUrl.c_str());
    CRL_DIST_POINT distributionPoint{};
    distributionPoint.DistPointName.dwDistPointNameChoice = CRL_DIST_POINT_FULL_NAME;
    distributionPoint.DistPointName.FullName.cAltEntry = 1;
    distributionPoint.DistPointName.FullName.rgAltEntry = &urlEntry;
    CRL_DIST_POINTS_INFO distributionPoints{1, &distributionPoint};
    std::vector<BYTE> cdpEnc;
    if (!revocationUrl_.empty())
    {
        cdpEnc = encodeExtension(X509_CRL_DIST_POINTS, &distributionPoints);
        extensions.push_back({const_cast<char*>(szOID_CRL_DIST_POINTS), FALSE,
            {static_cast<DWORD>(cdpEnc.size()), cdpEnc.data()}});
    }
    info.cExtension = static_cast<DWORD>(extensions.size());
    info.rgExtension = extensions.data();

    // Sign with the CA key
    DWORD encodedSize = 0;
    if (!CryptSignAndEncodeCertificate(caProvider_, AT_SIGNATURE, X509_ASN_ENCODING,
        X509_CERT_TO_BE_SIGNED, &info, &sigAlg, nullptr, nullptr, &encodedSize))
        throw std::runtime_error("CertAuthority: failed to measure leaf certificate");
    std::vector<BYTE> encoded(encodedSize);
    if (!CryptSignAndEncodeCertificate(caProvider_, AT_SIGNATURE, X509_ASN_ENCODING,
        X509_CERT_TO_BE_SIGNED, &info, &sigAlg, nullptr, encoded.data(), &encodedSize))
        throw std::runtime_error("CertAuthority: failed to sign leaf certificate");

    auto cert = CertCreateCertificateContext(X509_ASN_ENCODING, encoded.data(), encodedSize);
    if (!cert)
        throw std::runtime_error("CertAuthority: failed to create leaf context");

    // Associate the leaf private key so Schannel can use it.
    CRYPT_KEY_PROV_INFO leafProv{};
    leafProv.pwszContainerName = const_cast<wchar_t*>(leafContainerName_.c_str());
    leafProv.pwszProvName = const_cast<wchar_t*>(MS_ENH_RSA_AES_PROV_W);
    leafProv.dwProvType = PROV_RSA_AES;
    leafProv.dwKeySpec = AT_KEYEXCHANGE;
    leafProv.dwFlags = CRYPT_MACHINE_KEYSET;
    if (!CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &leafProv))
    {
        CertFreeCertificateContext(cert);
        throw std::runtime_error("CertAuthority: failed to bind the leaf key");
    }
    return cert;
}

}
