#include "Crypto.h"
#include "Protocols.h"
#include "Vpn.h"
#include <windows.h>
#include <wincrypt.h>
#include <algorithm>
#include <bit>
#include <cstdio>
#include <stdexcept>

namespace Cipherazzi
{
#include "TlsRegistry.inc"

template<size_t Size>
std::string registryName(const std::pair<uint32_t, std::string_view> (&values)[Size], uint16_t id)
{
    const auto found = std::lower_bound(std::begin(values), std::end(values), id,
        [](const auto& entry, uint16_t value) { return entry.first < value; });
    return found != std::end(values) && found->first == id ? std::string(found->second) : hex16(id);
}

std::string cipherName(uint16_t id) { return registryName(CipherNames, id); }
int cipherId(std::string_view name)
{
    const auto found = std::ranges::find_if(CipherNames, [&](const auto& entry) { return name == entry.second; });
    return found == std::end(CipherNames) ? -1 : static_cast<int>(found->first);
}
std::string groupName(uint16_t id) { return registryName(GroupNames, id); }
std::string signatureName(uint16_t id) { return registryName(SignatureNames, id); }

size_t NegotiationStage::memory() const
{
    size_t bytes = sni.capacity() + alpn.capacity() + keyShares.capacity() * sizeof(KeyShare);
    for (const auto* values : {&versions, &ciphers, &groups, &signatures, &certificateSignatures, &extensions})
        bytes += values->capacity() * sizeof(uint16_t);
    return bytes;
}

size_t Observation::Crypto::memory() const
{
    size_t bytes = clientSession.capacity() + serverSession.capacity() + stages.capacity() * sizeof(NegotiationStage) +
        srtpProfiles.capacity() * sizeof(uint16_t);
    for (const auto& stage : stages)
        bytes += stage.memory();
    for (const auto* value : {&offeredGroups, &offeredSignatures, &offeredCertificateSignatures, &offeredKeyShares,
        &clientExtensions, &serverExtensions, &offeredPskModes, &group, &keyExchange, &signature, &clientSignature,
        &downgrade, &alertSide})
        bytes += value->capacity();
    for (const auto* chain : {&serverCertificates, &clientCertificates})
        for (const auto& certificate : *chain)
            bytes += certificate->capacity() + sizeof(certificate);
    return bytes;
}

size_t Observation::memory() const
{
    size_t bytes = sizeof(*this) + crypto.memory() + (ssh ? sizeof(Ssh) + ssh->memory() : 0) +
        (vpn ? sizeof(VpnEvidence) + vpn->retainedBytes : 0) +
        (application ? sizeof(VpnEvidence) + application->retainedBytes : 0) +
        sourceOwner.memory() + destinationOwner.memory() - 2 * sizeof(Owner);
    for (const auto* value : {&sni, &offeredVersions, &offeredCiphers, &offeredAlpn, &selectedAlpn, &state, &detail,
        &closeReason, &quicOriginalId, &quicClientId, &quicServerId, &quicRetryId})
        bytes += value->capacity();
    return bytes + quicPaths.capacity() * sizeof(QuicPath);
}

std::string sha256(Bytes bytes)
{
    std::array<BYTE, 32> digest{};
    DWORD size = static_cast<DWORD>(digest.size());
    if (!CryptHashCertificate2(L"SHA256", 0, nullptr, bytes.data(), static_cast<DWORD>(bytes.size()),
        digest.data(), &size))
        throw std::runtime_error("Could not hash public certificate data");
    std::string result;
    result.reserve(64);
    constexpr char digits[] = "0123456789abcdef";
    for (auto value : digest)
    {
        result += digits[value >> 4];
        result += digits[value & 15];
    }
    return result;
}

std::string alertName(int code)
{
    switch (code)
    {
    case 0: return "close_notify";
    case 10: return "unexpected_message";
    case 20: return "bad_record_mac";
    case 21: return "decryption_failed";
    case 22: return "record_overflow";
    case 40: return "handshake_failure";
    case 42: return "bad_certificate";
    case 43: return "unsupported_certificate";
    case 44: return "certificate_revoked";
    case 45: return "certificate_expired";
    case 46: return "certificate_unknown";
    case 47: return "illegal_parameter";
    case 48: return "unknown_ca";
    case 49: return "access_denied";
    case 50: return "decode_error";
    case 51: return "decrypt_error";
    case 70: return "protocol_version";
    case 71: return "insufficient_security";
    case 80: return "internal_error";
    case 86: return "inappropriate_fallback";
    case 90: return "user_canceled";
    case 109: return "missing_extension";
    case 110: return "unsupported_extension";
    case 112: return "unrecognized_name";
    case 115: return "unknown_psk_identity";
    case 116: return "certificate_required";
    case 120: return "no_application_protocol";
    default: return code < 0 ? "" : std::to_string(code);
    }
}

std::string signatureClass(int id)
{
    if (id < 0)
        return "Not reported";
    if ((id >= 0x0904 && id <= 0x0906) || (id >= 0x0911 && id <= 0x091c))
        return "Post-quantum";
    return signatureName(static_cast<uint16_t>(id)) != hex16(static_cast<uint16_t>(id)) ? "Classical" : "Unknown";
}

std::pair<std::string, std::string> certificateAlgorithm(std::string_view oid)
{
    static constexpr const char* names[]
    {
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    };
    for (int i = 0; i < std::size(names); ++i)
        if (oid == "2.16.840.1.101.3.4.3." + std::to_string(17 + i))
            return {names[i], "Post-quantum"};
    for (const auto* classical : {"1.2.840.113549.1.1.1", "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.10",
        "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13", "1.2.840.10045.2.1",
        "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4", "1.3.101.112", "1.3.101.113",
        "1.2.840.10040.4.1", "2.16.840.1.101.3.4.3.2"})
        if (oid == classical)
            return {"", "Classical"};
    return {"", "Unknown"};
}

size_t EndpointReport::memory() const
{
    size_t bytes = sizeof(*this) + alpn.capacity() + quicId.capacity() + algorithm.capacity() + mode.capacity() +
        peerName.capacity() + owner.memory() - sizeof(Owner);
    for (const auto* chain : {&serverCertificates, &clientCertificates})
    {
        bytes += chain->capacity() * sizeof(std::shared_ptr<const std::vector<uint8_t>>);
        for (const auto& certificate : *chain)
            bytes += certificate->capacity();
    }
    return bytes;
}

nlohmann::json certificateMetadata(Bytes bytes)
{
    // Decode public metadata without fetching chains, contacting revocation servers, or trusting the certificate.
    using Certificate = std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)>;
    Certificate certificate(CertCreateCertificateContext(X509_ASN_ENCODING, bytes.data(),
        static_cast<DWORD>(bytes.size())), CertFreeCertificateContext);
    if (!certificate)
        return {{"decode_status", "Invalid or unsupported X.509 certificate"}};
    const auto& info = *certificate->pCertInfo;
    auto name = [](CERT_NAME_BLOB blob)
    {
        const auto size = CertNameToStrW(X509_ASN_ENCODING, &blob, CERT_X500_NAME_STR, nullptr, 0);
        std::wstring result(size, L'\0');
        if (size)
            CertNameToStrW(X509_ASN_ENCODING, &blob, CERT_X500_NAME_STR, result.data(), size);
        if (!result.empty())
            result.pop_back();
        return utf8(result);
    };
    auto oid = [](const char* identifier)
    {
        const auto* found = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, const_cast<char*>(identifier), 0);
        return found && found->pwszName ? utf8(found->pwszName) : std::string(identifier);
    };
    auto timestamp = [](FILETIME value)
    {
        const uint64_t ticks = (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
        return (static_cast<int64_t>(ticks) - 116444736000000000LL) / 10;
    };
    std::string serial;
    for (size_t index = info.SerialNumber.cbData; index > 0; --index)
    {
        char value[3]{};
        sprintf_s(value, "%02X", info.SerialNumber.pbData[index - 1]);
        serial += value;
    }
    nlohmann::json result{
        {"decode_status", "Decoded"}, {"subject", name(info.Subject)}, {"issuer", name(info.Issuer)},
        {"serial", serial}, {"signature_algorithm", oid(info.SignatureAlgorithm.pszObjId)},
        {"signature_oid", info.SignatureAlgorithm.pszObjId},
        {"public_key_type", oid(info.SubjectPublicKeyInfo.Algorithm.pszObjId)},
        {"public_key_oid", info.SubjectPublicKeyInfo.Algorithm.pszObjId},
        {"not_before_us", timestamp(info.NotBefore)}, {"not_after_us", timestamp(info.NotAfter)},
        {"trust", "Not evaluated; certificate presentation only"}, {"dns_names", nlohmann::json::array()}
    };
    const auto keyAlgorithm = certificateAlgorithm(info.SubjectPublicKeyInfo.Algorithm.pszObjId);
    const auto signatureAlgorithm = certificateAlgorithm(info.SignatureAlgorithm.pszObjId);
    result["public_key_class"] = keyAlgorithm.second;
    result["certificate_signature_class"] = signatureAlgorithm.second;
    if (!keyAlgorithm.first.empty())
        result["public_key_type"] = keyAlgorithm.first;
    if (!signatureAlgorithm.first.empty())
        result["signature_algorithm"] = signatureAlgorithm.first;
    const auto bits = CertGetPublicKeyLength(X509_ASN_ENCODING,
        const_cast<PCERT_PUBLIC_KEY_INFO>(&info.SubjectPublicKeyInfo));
    result["public_key_bits"] = bits ? nlohmann::json(bits) : nlohmann::json(nullptr);
    BYTE* raw = nullptr;
    DWORD size = 0;
    if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &info.SubjectPublicKeyInfo,
        CRYPT_ENCODE_ALLOC_FLAG, nullptr, &raw, &size))
    {
        std::unique_ptr<void, decltype(&LocalFree)> encoded(raw, LocalFree);
        result["spki_sha256"] = sha256(Bytes(raw, size));
    }
    const auto* extension = CertFindExtension(szOID_SUBJECT_ALT_NAME2, info.cExtension, info.rgExtension);
    CERT_ALT_NAME_INFO* names = nullptr;
    if (extension && CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, extension->Value.pbData,
        extension->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &names, &size))
    {
        std::unique_ptr<void, decltype(&LocalFree)> decoded(names, LocalFree);
        for (DWORD index = 0; index < names->cAltEntry && index < 256; ++index)
        {
            const auto& entry = names->rgAltEntry[index];
            if (entry.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME && entry.pwszDNSName)
                result["dns_names"].push_back(utf8(entry.pwszDNSName));
        }
    }
    return result;
}

void addNegotiationEvidence(nlohmann::json& data, const Observation::Crypto& crypto)
{
    // Classify assigned numeric identifiers; unknown values never inherit a class from their display names.
    struct PqGroup
    {
        uint16_t id;
        const char* first;
        const char* second;
        const char* standardization;
        const char* reference;
    };
    static constexpr PqGroup groups[]
    {
        {0x0200, "ML-KEM-512", "", "Draft", "draft-ietf-tls-mlkem-10"},
        {0x0201, "ML-KEM-768", "", "Draft", "draft-ietf-tls-mlkem-10"},
        {0x0202, "ML-KEM-1024", "", "Draft", "draft-ietf-tls-mlkem-10"},
        {0x11e9, "secp256r1", "ML-KEM-512", "Draft", "draft-rosomakho-tls-ecdhe-mlkem512-00"},
        {0x11ea, "ML-KEM-512", "X25519", "Draft", "draft-rosomakho-tls-ecdhe-mlkem512-00"},
        {0x11eb, "secp256r1", "ML-KEM-768", "Standardized", "RFC 10024"},
        {0x11ec, "ML-KEM-768", "X25519", "Standardized", "RFC 10024"},
        {0x11ed, "secp384r1", "ML-KEM-1024", "Standardized", "RFC 10024"},
        {0x11ee, "SM2", "ML-KEM-768", "Draft", "draft-yang-tls-hybrid-sm2-mlkem-03"},
        {0x6399, "X25519", "Kyber768Draft00", "Obsolete", "RFC 10024"},
        {0x639a, "secp256r1", "Kyber768Draft00", "Obsolete", "RFC 10024"}
    };
    data["classification_rule_version"] = 1;
    data["group_components"] = nlohmann::json::array();
    data["group_reference"] = "";
    data["group_class"] = crypto.groupId < 0 ? "Not observed" : "Unknown";
    data["group_standardization"] = crypto.groupId < 0 ? "Not observed" : "Unknown";
    const auto id = crypto.groupId;
    const auto found = std::ranges::find(groups, id, &PqGroup::id);
    if (found != std::end(groups))
    {
        data["group_class"] = *found->second ? "Hybrid post-quantum" : "Post-quantum";
        data["group_standardization"] = found->standardization;
        data["group_reference"] = found->reference;
        data["group_components"].push_back(found->first);
        if (*found->second)
            data["group_components"].push_back(found->second);
    }
    else if ((id >= 1 && id <= 41) || (id >= 256 && id <= 260) || id == 65281 || id == 65282)
    {
        data["group_class"] = "Classical";
        data["group_standardization"] = id <= 8 || (id >= 15 && id <= 21) ? "Deprecated" : "Assigned";
        data["group_reference"] = "IANA TLS Supported Groups";
        data["group_components"].push_back(groupName(static_cast<uint16_t>(id)));
    }
    else if (id >= 0 && (id & 0x0f0f) == 0x0a0a && (id >> 8) == (id & 0xff))
    {
        data["group_standardization"] = "GREASE";
        data["group_reference"] = "RFC 8701";
    }
    else if ((id >= 508 && id <= 511) || (id >= 65024 && id <= 65279))
        data["group_standardization"] = "Private use";
    else if (id < 0 && crypto.dhBits >= 0)
    {
        data["group_class"] = "Classical";
        data["group_standardization"] = "Not applicable";
        data["group_components"].push_back("Finite-field Diffie-Hellman");
    }

    // Persist bounded, ordered metadata without retaining key-share contents or session secrets.
    data["negotiation_stages"] = nlohmann::json::array();
    data["negotiation_stages_dropped"] = crypto.stagesDropped;
    data["negotiation_history_truncated"] = crypto.stagesDropped != 0;
    for (const auto& stage : crypto.stages)
    {
        auto numeric = [](int value) { return value < 0 ? nlohmann::json(nullptr) : nlohmann::json(value); };
        nlohmann::json entry{
            {"type", stage.type == NegotiationStage::Type::ClientHello ? "ClientHello" :
                stage.type == NegotiationStage::Type::HelloRetryRequest ? "HelloRetryRequest" : "ServerHello"},
            {"ordinal", data["negotiation_stages"].size() + 1}, {"timestamp_us", stage.timestampUs},
            {"handshake_bytes", stage.handshakeBytes}, {"legacy_version", stage.legacyVersion},
            {"selected_version", numeric(stage.selectedVersion)}, {"cipher_id", numeric(stage.cipherId)},
            {"selected_group_id", numeric(stage.selectedGroupId)}, {"ech_offered", stage.ech},
            {"sni", stage.sni}, {"alpn", stage.alpn}, {"offered_version_ids", stage.versions},
            {"cipher_ids", stage.ciphers}, {"group_ids", stage.groups}, {"signature_ids", stage.signatures},
            {"certificate_signature_ids", stage.certificateSignatures}, {"extension_ids", stage.extensions},
            {"key_shares", nlohmann::json::array()}
        };
        for (const auto& share : stage.keyShares)
            entry["key_shares"].push_back({{"group_id", share.group}, {"bytes", share.bytes}});
        data["negotiation_stages"].push_back(std::move(entry));
    }
}

void CryptoCatalog::forget(const std::string& hash)
{
    const auto found = certificates_.find(hash);
    if (found == certificates_.end())
        return;
    certificateBytes_ -= found->second.size();
    certificates_.erase(found);
    std::erase(order_, hash);
}

CryptoSummary CryptoCatalog::summarize(const Observation& observation, const CertificateSink& sink)
{
    if (observation.protocol != Observation::Protocol::Tls)
        return summarizeProtocol(observation);
    const auto& c = observation.crypto;
    const bool tls13 = observation.serverHello && observation.version >= 0x0304;
    CryptoSummary summary;
    summary.group = c.group;
    auto numeric = [](int64_t value) { return value < 0 ? nlohmann::json(nullptr) : nlohmann::json(value); };
    auto presentTime = [](int64_t value) { return value ? nlohmann::json(value) : nlohmann::json(nullptr); };
    nlohmann::json data{
        {"protocol", observation.dtlsVersion ? "DTLS" : "TLS"},
        {"transport", observation.quic ? "QUIC" : observation.udp ? "UDP" : "TCP"},
        {"dtls_version", observation.dtlsVersion}, {"dtls_cookie_exchange", observation.dtlsCookie},
        {"srtp_offered_profiles", c.srtpProfiles},
        {"srtp_selected_profile", c.selectedSrtpProfile >= 0 ? nlohmann::json(c.selectedSrtpProfile) : nlohmann::json(nullptr)},
        {"srtp_evidence", "Protection profiles only; media use and authentication not established"},
        {"dtls_visibility", observation.dtlsVersion ? "Cleartext epoch only; encrypted records unavailable" : ""},
        {"quic_version", observation.quic ? nlohmann::json(observation.quicVersion) : nlohmann::json(nullptr)},
        {"quic_original_dcid", observation.quicOriginalId}, {"quic_client_scid", observation.quicClientId},
        {"quic_server_scid", observation.quicServerId}, {"quic_retry", observation.quicRetry},
        {"quic_retry_scid", observation.quicRetryId}, {"quic_retry_us", presentTime(observation.quicRetryUs)},
        {"quic_visibility", observation.quic ? "Initial hellos only; Handshake and application data encrypted" : ""},
        {"evidence_source", "Packet"}, {"handshake_confirmation", "Not confirmed by endpoint"},
        {"client_hello_visibility", observation.echOffered ? "Outer ClientHello; inner offers unavailable" :
            "Visible ClientHello"}, {"offered_groups", c.offeredGroups}, {"offered_key_shares", c.offeredKeyShares},
        {"offered_signatures", c.offeredSignatures}, {"offered_certificate_signatures", c.offeredCertificateSignatures},
        {"client_extensions", c.clientExtensions}, {"server_extensions", c.serverExtensions},
        {"selected_group_id", numeric(c.groupId)}, {"selected_group", c.group}, {"dh_parameter_bits", numeric(c.dhBits)},
        {"handshake_signature", c.signature}, {"client_handshake_signature", c.clientSignature},
        {"offered_psk_modes", c.offeredPskModes}, {"psk_offers", numeric(c.pskOffers)},
        {"selected_psk_index", numeric(c.selectedPsk)}, {"early_data_offered", numeric(c.earlyDataOffered)},
        {"early_data_accepted", tls13 ? "Encrypted; unknown" : "Not applicable"},
        {"ems_offered", numeric(c.emsOffered)}, {"ems_selected", numeric(c.emsSelected)},
        {"secure_renegotiation", numeric(c.secureRenegotiation)}, {"session_ticket_offered", numeric(c.ticketOffered)},
        {"compression_method", numeric(c.compression)}, {"downgrade_marker", c.downgrade},
        {"certificate_requested", numeric(c.certificateRequested)},
        {"client_certificate_presented", numeric(c.clientCertificatePresented)},
        {"alert_code", numeric(c.alertCode)}, {"alert_level", numeric(c.alertLevel)},
        {"alert_name", alertName(c.alertCode)}, {"alert_sender", c.alertSide}, {"alert_us", presentTime(c.alertUs)},
        {"client_hello_us", presentTime(c.clientHelloUs)}, {"server_hello_us", presentTime(c.serverHelloUs)},
        {"retry_us", presentTime(c.retryUs)},
        {"retry_group", c.retryGroupId < 0 ? "" : groupName(static_cast<uint16_t>(c.retryGroupId))},
        {"server_certificates", nlohmann::json::array()}, {"client_certificates", nlohmann::json::array()}
    };

    // CID matching associates visible paths without asserting encrypted path validation.
    data["quic_paths"] = nlohmann::json::array();
    for (const auto& path : observation.quicPaths)
        data["quic_paths"].push_back({{"source_address", path.source.text()}, {"source_port", path.source.port},
            {"destination_address", path.destination.text()}, {"destination_port", path.destination.port},
            {"first_us", path.firstUs}, {"last_us", path.lastUs}, {"packets", path.packets}});
    data["quic_paths_dropped"] = observation.quicPathsDropped;
    data["quic_path_evidence"] = observation.quic ? "Visible connection ID; path validation unverified" : "";

    // Separate symmetric encryption, record MAC, key derivation, and authentication.
    const auto name = observation.serverHello ? cipherName(observation.cipher) : "";
    if (const auto with = name.find("_WITH_"); with != std::string::npos)
    {
        summary.exchange = name.substr(4, with - 4);
        if (summary.exchange.find("ECDSA") != std::string::npos)
            summary.authentication = "ECDSA";
        else if (summary.exchange.find("RSA") != std::string::npos)
            summary.authentication = "RSA";
        else if (summary.exchange.find("DSS") != std::string::npos)
            summary.authentication = "DSA";
        else if (summary.exchange.find("PSK") != std::string::npos)
            summary.authentication = "PSK";
        else if (summary.exchange.find("anon") != std::string::npos)
            summary.authentication = "Anonymous";
    }
    const bool aead = tls13 || name.find("_GCM") != std::string::npos || name.find("_CCM") != std::string::npos ||
        name.find("POLY1305") != std::string::npos;
    for (const auto [token, bits] : {std::pair{"AES_128", 128}, {"AES_256", 256}, {"CHACHA20", 256},
        {"CAMELLIA_128", 128}, {"CAMELLIA_256", 256}, {"ARIA_128", 128}, {"ARIA_256", 256},
        {"SM4", 128}, {"RC4_128", 128}, {"3DES_EDE", 168}, {"DES40", 40}, {"DES_CBC", 56}})
    {
        if (name.find(token) == std::string::npos)
            continue;
        summary.encryption = token;
        summary.keyBits = bits;
        break;
    }
    if (name.find("_WITH_NULL_") != std::string::npos)
        summary.encryption = "NULL";
    for (const auto* mode : {"GCM", "CCM_8", "CCM", "CBC", "POLY1305"})
        if (name.find(mode) != std::string::npos)
        {
            data["encryption_mode"] = mode;
            break;
        }
    for (const auto* hash : {"SHA512", "SHA384", "SHA256", "SHA", "MD5", "SM3"})
        if (name.ends_with(std::string("_") + hash))
        {
            summary.hash = std::string(hash) == "SHA" ? "SHA1" : hash;
            break;
        }
    data["record_mac"] = aead ? "AEAD" : summary.hash;
    const bool knownPrf = summary.hash == "SHA384" || summary.hash == "SHA256" ||
        summary.hash == "SHA1" || summary.hash == "MD5" || name.find("_CCM") != std::string::npos;
    data["prf_hash"] = observation.serverHello && !tls13 && knownPrf ?
        (observation.version == 0x0303 ? (summary.hash == "SHA384" ? "SHA384" : "SHA256") :
            "Legacy protocol PRF") : "";
    data["hkdf_hash"] = tls13 ? summary.hash : "";
    if (tls13)
    {
        data["ems_selected"] = nullptr;
        data["secure_renegotiation"] = nullptr;
        summary.psk = c.selectedPsk >= 0 ? (c.groupId >= 0 ? "PSK + asymmetric" : "PSK only") :
            "PSK not selected";
        summary.exchange = c.groupId >= 0 ? (c.selectedPsk >= 0 ? "PSK + " : "") + c.group :
            c.selectedPsk >= 0 ? "PSK only" : "";
        summary.authentication = c.selectedPsk >= 0 ? "PSK selected" : "Encrypted; unknown";
        const auto encrypted = observation.dtlsVersion ? "Encrypted in DTLS 1.3" : "Encrypted in TLS 1.3";
        data["certificate_visibility"] = encrypted;
        data["handshake_signature_visibility"] = encrypted;
        data["client_authentication"] = "Encrypted; unknown";
        data["resumption"] = c.selectedPsk >= 0 ? "PSK selected; external PSK or resumption" : "PSK not selected";
    }
    else
    {
        data["certificate_visibility"] = "Visible messages only; absent or missed certificates remain unknown";
        data["client_authentication"] = c.clientCertificatePresented == 1 ? "Certificate presented; not confirmed" :
            c.clientCertificatePresented == 0 ? "Empty client certificate list" :
            c.certificateRequested == 1 ? "Requested; presentation not observed" : "Not observed";
        data["resumption"] = !c.clientSession.empty() && c.clientSession == c.serverSession ?
            "Server echoed session ID; resumption selected" : "Not established from visible session IDs";
    }
    addNegotiationEvidence(data, c);
    if (observation.application)
        data.update(observation.application->fields);
    data["key_exchange"] = summary.exchange;
    data["authentication"] = summary.authentication;
    data["encryption"] = summary.encryption;
    data["symmetric_key_bits"] = summary.keyBits ? nlohmann::json(summary.keyBits) : nlohmann::json(nullptr);
    data["psk_mode"] = summary.psk;

    // Deduplicate certificate parsing and persistence; retained cache and chain lengths are bounded.
    for (const auto [chain, field] : {
        std::pair{&c.serverCertificates, "server_certificates"}, {&c.clientCertificates, "client_certificates"}})
    {
        size_t position = 0;
        for (const auto& bytes : *chain)
        {
            const auto fingerprint = sha256(*bytes);
            auto found = certificates_.find(fingerprint);
            if (found == certificates_.end())
            {
                auto metadata = certificateMetadata(*bytes);
                metadata["sha256"] = fingerprint;
                auto text = metadata.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
                sink(fingerprint, text, *bytes);
                while (!order_.empty() && (certificates_.size() >= 2048 ||
                    certificateBytes_ + text.size() > 16 * 1024 * 1024))
                {
                    certificateBytes_ -= certificates_.at(order_.front()).size();
                    certificates_.erase(order_.front());
                    order_.pop_front();
                }
                order_.push_back(fingerprint);
                certificateBytes_ += text.size();
                certificates_.emplace(fingerprint, std::move(text));
            }
            data[field].push_back(fingerprint);
            summary.certificates.push_back({fingerprint, chain == &c.serverCertificates ? "server" : "client",
                position++});
            if (chain == &c.serverCertificates && summary.certificate.empty())
                summary.certificate = fingerprint;
        }
    }
    summary.json = data.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    return summary;
}
}
