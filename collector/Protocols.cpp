#include "Protocols.h"
#include "Vpn.h"

#include <algorithm>
#include <cmath>
#include <sstream>
#include <tuple>

namespace Cipherazzi
{
bool SshStream::feed(Bytes bytes, const Sink& sink)
{
    if (finished_)
        return true;
    if (!identified_ && buffer_.empty() && !bytes.empty() &&
        ((bytes[0] < 32 && bytes[0] != '\r' && bytes[0] != '\n') || bytes[0] > 126))
    {
        finished_ = true;
        return true;
    }
    if (buffer_.size() + bytes.size() > 131072)
    {
        limited_ = true;
        return false;
    }
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
    size_t consumed = 0;

    // Accept bounded printable pre-banner lines; binary protocols leave this parser immediately.
    while (!identified_)
    {
        const auto start = buffer_.begin() + consumed;
        const auto end = std::find(start, buffer_.end(), '\n');
        const size_t length = static_cast<size_t>(end - start);
        if (std::any_of(start, end, [](uint8_t value)
        {
            return value != '\r' && (value < 32 || value > 126);
        }) || length > 254 || scanned_ + length > 8192)
        {
            finished_ = true;
            std::vector<uint8_t>().swap(buffer_);
            return true;
        }
        if (end == buffer_.end())
            break;
        std::string line(start, end);
        if (line.ends_with('\r'))
            line.pop_back();
        consumed += length + 1;
        scanned_ += length + 1;
        if (!line.starts_with("SSH-"))
            continue;
        if ((!line.starts_with("SSH-2.0-") && !line.starts_with("SSH-1.99-")) ||
            line.size() <= (line.starts_with("SSH-2.0-") ? 8 : 9) || line.find('\r') != std::string::npos)
        {
            finished_ = true;
            std::vector<uint8_t>().swap(buffer_);
            return true;
        }
        identified_ = true;
        SshMessage message;
        message.type = SshMessage::Type::Banner;
        message.banner = std::move(line);
        sink(message);
    }

    // Initial SSH packets are unencrypted and aligned to eight bytes; stop at each direction's NEWKEYS.
    while (identified_ && buffer_.size() - consumed >= 5)
    {
        const auto pending = Bytes(buffer_).subspan(consumed);
        const size_t length = be32(pending, 0);
        const size_t padding = pending[4];
        if (length < 12 || length > 65536 || (length + 4) % 8 || padding < 4 || padding + 2 > length)
            return false;
        if (pending.size() < length + 4)
            break;
        const auto payload = pending.subspan(5, length - padding - 1);
        if (skipGuess_)
            skipGuess_ = false;
        else if (payload[0] == 20)
        {
            if (kexInit_ || payload.size() < 22)
                return false;
            SshMessage message;
            message.type = SshMessage::Type::KexInit;
            size_t offset = 17;
            for (size_t index = 0; index < message.algorithms.size(); ++index)
            {
                if (offset + 4 > payload.size())
                    return false;
                const size_t size = be32(payload, offset);
                offset += 4;
                if (size > 8192 || size > payload.size() - offset || (index < 8 && !size))
                    return false;
                const auto names = payload.subspan(offset, size);
                if (std::any_of(names.begin(), names.end(), [](uint8_t value) { return value < 33 || value > 126; }))
                    return false;
                auto& value = message.algorithms[index];
                value.assign(names.begin(), names.end());
                if (value.starts_with(',') || value.ends_with(',') || value.find(",,") != std::string::npos)
                    return false;
                offset += size;
            }
            if (offset + 5 != payload.size() || payload[offset] > 1 || be32(payload, offset + 1))
                return false;
            kexInit_ = true;
            skipGuess_ = payload[offset] != 0;
            sink(message);
        }
        else if (payload[0] == 21)
        {
            if (!kexInit_ || payload.size() != 1)
                return false;
            SshMessage message;
            message.type = SshMessage::Type::NewKeys;
            sink(message);
            finished_ = true;
        }
        else if (kexInit_ && (payload[0] == 31 || payload[0] == 33))
        {
            SshMessage message;
            message.type = SshMessage::Type::KeyReply;
            message.reply = payload;
            sink(message);
        }
        else if (payload[0] == 1)
            finished_ = true;
        consumed += length + 4;
        if (finished_)
            break;
    }
    buffer_.erase(buffer_.begin(), buffer_.begin() + consumed);
    if (finished_)
        std::vector<uint8_t>().swap(buffer_);
    return true;
}

void applySsh(Observation& observation, int peer, const SshMessage& message)
{
    observation.protocol = Observation::Protocol::Ssh;
    if (!observation.ssh)
        observation.ssh = std::make_shared<Observation::Ssh>();
    else if (observation.ssh.use_count() != 1)
        observation.ssh = std::make_shared<Observation::Ssh>(*observation.ssh);
    auto& ssh = *observation.ssh;
    ssh.observed = true;
    auto& side = ssh.peers[peer];
    if (message.type == SshMessage::Type::Banner)
        side.banner = message.banner;
    else if (message.type == SshMessage::Type::KexInit)
    {
        side.algorithms = message.algorithms;
        side.kexInit = true;
    }
    else if (message.type == SshMessage::Type::NewKeys)
        side.newKeys = true;
    if (!ssh.rolesKnown || !ssh.peers[0].kexInit || !ssh.peers[1].kexInit)
        return;

    // Infer initial selections from both preference lists; AEAD ciphers provide their own authentication.
    auto common = [](const std::string& client, const std::string& server)
    {
        std::istringstream offered(client);
        std::string name;
        const auto allowed = "," + server + ",";
        while (std::getline(offered, name, ','))
            if (name != "ext-info-c" && name != "ext-info-s" && !name.starts_with("kex-strict-") &&
                allowed.find("," + name + ",") != std::string::npos)
                return name;
        return std::string{};
    };
    ssh.noCommon.clear();
    const char* categories[]{"key exchange", "host key", "client-to-server cipher", "server-to-client cipher",
        "client-to-server MAC", "server-to-client MAC", "client-to-server compression",
        "server-to-client compression"};
    for (size_t index = 0; index < ssh.selected.size(); ++index)
    {
        ssh.selected[index] = common(ssh.peers[0].algorithms[index], ssh.peers[1].algorithms[index]);
        if (index == 4 || index == 5)
        {
            const auto& cipher = ssh.selected[index - 2];
            if (cipher.ends_with("-gcm@openssh.com") || cipher == "chacha20-poly1305@openssh.com")
                ssh.selected[index] = "AEAD";
        }
        if (ssh.selected[index].empty())
            ssh.noCommon += (ssh.noCommon.empty() ? "" : ", ") + std::string(categories[index]);
    }
    if (!ssh.noCommon.empty())
        ssh.selected.fill({});
    if (message.type != SshMessage::Type::KeyReply || peer != 1 || !ssh.noCommon.empty() ||
        !ssh.hostKeySha256.empty())
        return;
    const auto& exchange = ssh.selected[0];
    const bool groupExchange = exchange.starts_with("diffie-hellman-group-exchange-");
    const bool knownExchange = groupExchange || exchange.starts_with("diffie-hellman-group14-") ||
        exchange.starts_with("diffie-hellman-group16-") || exchange.starts_with("diffie-hellman-group18-") ||
        exchange.starts_with("curve25519-") || exchange.starts_with("ecdh-sha2-") ||
        exchange.starts_with("sntrup761x25519-") || exchange.starts_with("mlkem768x25519-");
    if (!knownExchange || message.reply.empty() || message.reply[0] != (groupExchange ? 33 : 31))
        return;
    auto takeString = [](Bytes& source, Bytes& value)
    {
        if (source.size() < 4)
            return false;
        const auto size = be32(source, 0);
        if (size > source.size() - 4)
            return false;
        value = source.subspan(4, size);
        source = source.subspan(4 + size);
        return true;
    };
    auto text = [](Bytes value) { return std::string(reinterpret_cast<const char*>(value.data()), value.size()); };
    auto remaining = message.reply.subspan(1);
    Bytes host, ephemeral, signature;
    if (!takeString(remaining, host) || host.empty() || host.size() > 65536 ||
        !takeString(remaining, ephemeral) || ephemeral.empty() ||
        !takeString(remaining, signature) || !remaining.empty())
        return;
    auto keyFields = host;
    Bytes keyType, keyValue, extra;
    if (!takeString(keyFields, keyType))
        return;
    const auto type = text(keyType);
    constexpr std::string_view certificateSuffix = "-cert-v01@openssh.com";
    const bool certificate = type.ends_with(certificateSuffix);
    const auto plainType = certificate ? type.substr(0, type.size() - certificateSuffix.size()) : type;
    const auto& negotiated = ssh.selected[1];
    const auto signatureAlgorithm = certificate && negotiated.ends_with(certificateSuffix) ?
        negotiated.substr(0, negotiated.size() - certificateSuffix.size()) : negotiated;
    if (type != negotiated && !(plainType == "ssh-rsa" &&
        certificate == negotiated.ends_with(certificateSuffix) &&
        (signatureAlgorithm == "rsa-sha2-256" || signatureAlgorithm == "rsa-sha2-512")))
        return;
    if (certificate && !takeString(keyFields, extra))
        return;
    const auto publicFields = keyFields;
    if (!takeString(keyFields, keyValue))
        return;
    int bits = 0;
    if (plainType == "ssh-ed25519" && keyValue.size() == 32)
        bits = 256;
    else if (plainType == "ssh-rsa" && !keyValue.empty() && !(keyValue[0] & 0x80) &&
        takeString(keyFields, extra) && !extra.empty() && !(extra[0] & 0x80))
    {
        while (!extra.empty() && extra[0] == 0)
            extra = extra.subspan(1);
        if (!extra.empty())
        {
            auto leading = extra[0];
            bits = static_cast<int>((extra.size() - 1) * 8);
            while (leading)
            {
                ++bits;
                leading >>= 1;
            }
        }
    }
    else if (plainType.starts_with("ecdsa-sha2-") && plainType == "ecdsa-sha2-" + text(keyValue) &&
        takeString(keyFields, extra) && !extra.empty() && extra[0] == 4)
    {
        const auto curve = text(keyValue);
        bits = curve == "nistp256" && extra.size() == 65 ? 256 :
            curve == "nistp384" && extra.size() == 97 ? 384 :
            curve == "nistp521" && extra.size() == 133 ? 521 : 0;
    }
    if (!bits || (!certificate && !keyFields.empty()))
        return;

    // Inventory certificate identity and CA provenance without asserting validity or host trust.
    std::string certificateJson;
    std::vector<uint8_t> plainKey;
    if (certificate)
    {
        const auto keyLength = publicFields.size() - keyFields.size();
        plainKey = {0, 0, 0, static_cast<uint8_t>(plainType.size())};
        plainKey.insert(plainKey.end(), plainType.begin(), plainType.end());
        plainKey.insert(plainKey.end(), publicFields.begin(), publicFields.begin() + keyLength);
        if (keyFields.size() < 12)
            return;
        auto number64 = [](Bytes source, size_t offset)
        {
            return (static_cast<uint64_t>(be32(source, offset)) << 32) | be32(source, offset + 4);
        };
        const auto serial = number64(keyFields, 0);
        const auto usage = be32(keyFields, 8);
        keyFields = keyFields.subspan(12);
        Bytes keyId, principals, critical, extensions, reserved, authority, certificateSignature;
        if ((usage != 1 && usage != 2) || !takeString(keyFields, keyId) || keyId.size() > 4096 ||
            !takeString(keyFields, principals) || keyFields.size() < 16)
            return;
        const auto validAfter = number64(keyFields, 0), validBefore = number64(keyFields, 8);
        keyFields = keyFields.subspan(16);
        if (!takeString(keyFields, critical) || !takeString(keyFields, extensions) ||
            !takeString(keyFields, reserved) || !takeString(keyFields, authority) || authority.empty() ||
            !takeString(keyFields, certificateSignature) || !keyFields.empty())
            return;
        nlohmann::json details{{"serial", serial}, {"type", usage == 2 ? "Host" : "User"},
            {"key_id", text(keyId)}, {"valid_after", validAfter}, {"valid_before", validBefore},
            {"sha256", sha256(host)}, {"authority_sha256", sha256(authority)},
            {"trust", "Not verified"}, {"principals", nlohmann::json::array()}};
        while (!principals.empty())
        {
            Bytes principal;
            if (details["principals"].size() >= 256 || !takeString(principals, principal) ||
                principal.empty() || principal.size() > 4096)
                return;
            details["principals"].push_back(text(principal));
        }
        for (auto item : {std::pair{"critical_options", critical}, std::pair{"extensions", extensions}})
        {
            auto& names = details[item.first] = nlohmann::json::array();
            std::string previous;
            while (!item.second.empty())
            {
                Bytes name, value;
                if (names.size() >= 256 || !takeString(item.second, name) || name.empty() || name.size() > 4096 ||
                    !takeString(item.second, value) || (!previous.empty() && text(name) <= previous))
                    return;
                previous = text(name);
                names.push_back(previous);
            }
        }
        Bytes authorityType, signingType, signingValue;
        if (!takeString(authority, authorityType) || authority.empty() ||
            text(authorityType).find("-cert-") != std::string::npos ||
            !takeString(certificateSignature, signingType) ||
            !takeString(certificateSignature, signingValue) || signingValue.empty() || !certificateSignature.empty())
            return;
        details["authority_key_type"] = text(authorityType);
        details["signature_algorithm"] = text(signingType);
        certificateJson = details.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    }
    Bytes signatureType, signatureValue;
    if (!takeString(signature, signatureType) || !takeString(signature, signatureValue) ||
        signatureValue.empty() || !signature.empty() || text(signatureType) != signatureAlgorithm)
        return;
    ssh.hostKeyType = type;
    ssh.hostKeyBits = bits;
    ssh.hostKeySha256 = sha256(certificate ? Bytes(plainKey) : host);
    ssh.exchangeSignature = text(signatureType);
    ssh.hostCertificate = std::move(certificateJson);
}

void PayloadSample::feed(Bytes bytes)
{
    bytes = bytes.first(std::min(bytes.size(), Maximum - bytes_));
    for (const auto byte : bytes)
    {
        if (bytes_ < prefix_.size())
            prefix_[bytes_] = byte;
        ++counts_[byte];
        ++bytes_;
    }
}

bool PayloadSample::classify(Observation& observation, int direction) const
{
    if (bytes_ < Minimum)
        return false;

    // Recognizable compressed containers are excluded; unidentified compression can still look encrypted.
    const auto* p = prefix_.data();
    if ((p[0] == 0x1f && p[1] == 0x8b) || (p[0] == 'P' && p[1] == 'K') ||
        (p[0] == 'B' && p[1] == 'Z' && p[2] == 'h') ||
        (p[0] == 0xfd && p[1] == '7' && p[2] == 'z' && p[3] == 'X' && p[4] == 'Z') ||
        (p[0] == 0x28 && p[1] == 0xb5 && p[2] == 0x2f && p[3] == 0xfd) ||
        ((p[0] & 15) == 8 && (p[0] >> 4) <= 7 && ((p[0] << 8) + p[1]) % 31 == 0))
        return false;
    double entropy = 0;
    for (const auto count : counts_)
        if (count)
        {
            const double probability = static_cast<double>(count) / bytes_;
            entropy -= probability * std::log2(probability);
        }
    if (entropy < 7.8)
        return false;
    if (observation.raw.possibleEncryption && entropy <= observation.raw.entropy)
        return false;
    observation.protocol = Observation::Protocol::Unknown;
    observation.raw = {bytes_, entropy, direction, true};
    return true;
}

CryptoSummary summarizeProtocol(const Observation& observation)
{
    CryptoSummary summary;
    nlohmann::json data{{"transport", observation.udp ? "UDP" : "TCP"},
        {"protocol", observation.protocol == Observation::Protocol::Ssh ? "SSH" : "Unknown"},
        {"evidence_source", observation.protocol == Observation::Protocol::Ssh ? "Packet" : "Statistical estimate"},
        {"handshake_confirmation", "Not confirmed by endpoint"}, {"selected_group_id", nullptr},
        {"group_class", "Not observed"}, {"server_certificates", nlohmann::json::array()},
        {"client_certificates", nlohmann::json::array()}};
    if (observation.vpn)
    {
        data.update(observation.vpn->fields);
        data["protocol"] = protocolName(observation.protocol);
        data["evidence_source"] = "Packet";
        data["vpn_authentication"] = "Unverified";
        data["handshake_confirmation"] = "Protocol messages observed; authentication and completion unverified";
        if (observation.protocol == Observation::Protocol::WireGuard)
        {
            summary.exchange = "Curve25519";
            summary.encryption = "ChaCha20-Poly1305";
            summary.keyBits = 256;
            summary.hash = "BLAKE2s";
            data["group_class"] = "Classical";
        }
        else if (observation.protocol == Observation::Protocol::Ike)
        {
            const auto selected = data.find("ike_selection");
            if (selected != data.end() && selected->is_array() && selected->size() == 1)
                for (const auto& transform : (*selected)[0]["transforms"])
                {
                    const auto type = transform.value("type", 0);
                    if (type == 1)
                    {
                        summary.encryption = transform.value("name", "");
                        summary.keyBits = transform.value("key_bits", 0);
                    }
                    else if (type == 2)
                        summary.hash = transform.value("name", "");
                    else if (type == 4)
                        summary.exchange = transform.value("name", "");
                }
        }
        else if (observation.clientHello || observation.serverHello)
        {
            auto inner = observation;
            inner.protocol = Observation::Protocol::Tls;
            inner.vpn.reset();
            CryptoCatalog catalog;
            const auto tls = catalog.summarize(inner, [](const std::string&, const std::string&, Bytes) {});
            data["openvpn_tls"] = nlohmann::json::parse(tls.json);
            data["openvpn_tls"]["transport"] = observation.udp ? "OpenVPN control over UDP" : "OpenVPN control over TCP";
            data["openvpn_tls"]["offered_ciphers"] = observation.offeredCiphers;
            data["openvpn_tls"]["offered_versions"] = observation.offeredVersions;
            data["openvpn_tls"]["offered_alpn"] = observation.offeredAlpn;
            data["openvpn_tls"]["selected_cipher"] = observation.serverHello ?
                cipherName(observation.cipher) : "Not selected";
            data["openvpn_tls_sni"] = observation.sni;
            data["openvpn_tls_version"] = observation.serverHello ? versionName(observation.version) : "Not selected";
        }
        data["key_exchange"] = summary.exchange;
        data["encryption"] = summary.encryption;
        data["symmetric_key_bits"] = summary.keyBits ? nlohmann::json(summary.keyBits) : nlohmann::json(nullptr);
        data["protocol_hash"] = summary.hash;
    }
    else if (observation.application)
    {
        data.update(observation.application->fields);
        data["protocol"] = protocolName(observation.protocol);
        data["evidence_source"] = "Packet";
        data["handshake_confirmation"] = "Protocol framing observed; authentication and completion unverified";

        // Name an explicitly selected SMB cipher without treating negotiation as proof of encrypted traffic.
        if (observation.protocol == Observation::Protocol::Smb)
        {
            const auto selected = data.find("smb_selected_cipher");
            if (selected != data.end() && selected->is_array() && selected->size() == 1 && (*selected)[0].is_string())
                for (const auto [id, name, bits] : {std::tuple{"0x0001", "AES-128-CCM", 128},
                    {"0x0002", "AES-128-GCM", 128}, {"0x0003", "AES-256-CCM", 256}, {"0x0004", "AES-256-GCM", 256}})
                    if ((*selected)[0] == id)
                    {
                        summary.encryption = name;
                        summary.keyBits = bits;
                        data["encryption"] = name;
                        data["encryption_mode"] = std::string_view(name).ends_with("GCM") ? "GCM" : "CCM";
                        data["symmetric_key_bits"] = bits;
                        break;
                    }
        }
    }
    else if (observation.protocol == Observation::Protocol::Unknown)
    {
        data["classification"] = "Possible encryption";
        data["sample_bytes"] = observation.raw.sampleBytes;
        data["sample_entropy"] = observation.raw.entropy;
        data["sample_direction"] = observation.raw.direction == 0 ? "Source to destination" : "Destination to source";
        data["classification_limit"] =
            "High entropy also occurs in compressed or random data; cipher and key size unknown";
        data["minimum_sample_bytes"] = PayloadSample::Minimum;
        data["maximum_sample_bytes"] = PayloadSample::Maximum;
        data["entropy_threshold"] = 7.8;
    }
    else
    {
        const auto& ssh = *observation.ssh;
        data["ssh_roles_known"] = ssh.rolesKnown;
        data["ssh_host_key_type"] = ssh.hostKeyType;
        data["ssh_host_key_sha256"] = ssh.hostKeySha256;
        data["ssh_host_key_bits"] = ssh.hostKeyBits ? nlohmann::json(ssh.hostKeyBits) : nlohmann::json(nullptr);
        data["ssh_exchange_signature"] = ssh.exchangeSignature;
        data["ssh_host_key_trust"] = "Not verified";
        if (!ssh.hostCertificate.empty())
            data["ssh_host_certificate"] = nlohmann::json::parse(ssh.hostCertificate);
        data["ssh_peers"] = nlohmann::json::array();
        const char* names[] = {"key_exchange", "host_key", "cipher_c2s", "cipher_s2c", "mac_c2s", "mac_s2c",
            "compression_c2s", "compression_s2c", "languages_c2s", "languages_s2c"};
        for (const auto& peer : ssh.peers)
        {
            nlohmann::json entry{{"banner", peer.banner}, {"kexinit_observed", peer.kexInit},
                {"newkeys_observed", peer.newKeys}};
            for (size_t index = 0; index < peer.algorithms.size(); ++index)
                entry[names[index]] = peer.algorithms[index];
            data["ssh_peers"].push_back(std::move(entry));
        }
        data["ssh_selection"] = nlohmann::json::object();
        for (size_t index = 0; index < ssh.selected.size(); ++index)
            data["ssh_selection"][names[index]] = ssh.selected[index];
        data["ssh_no_common_algorithm"] = ssh.noCommon;
        data["ssh_selection_evidence"] = "Initial algorithm selection inferred from both KEXINIT lists and TCP roles";
        data["ssh_visibility"] =
            "Initial exchange only; authentication, application data, and later rekeying are encrypted";
        if (ssh.peers[0].newKeys && ssh.peers[1].newKeys)
            data["handshake_confirmation"] = "SSH NEWKEYS observed; authentication outcome unknown";
        summary.exchange = ssh.selected[0];
        summary.authentication = ssh.selected[1];
        data["key_exchange"] = summary.exchange;
        if (!summary.exchange.empty())
            data["group_class"] = summary.exchange.starts_with("mlkem768x25519-") ||
                summary.exchange.starts_with("sntrup761x25519-") ? "Hybrid post-quantum" :
                summary.exchange.starts_with("curve25519-") || summary.exchange.starts_with("ecdh-sha2-") ||
                summary.exchange.starts_with("diffie-hellman-") ? "Classical" : "Unknown";
        const auto& cipher = ssh.selected[2];
        for (const auto [prefix, algorithm, bits] : {std::tuple{"aes128-", "AES_128", 128},
            {"aes192-", "AES_192", 192}, {"aes256-", "AES_256", 256},
            {"chacha20-poly1305@openssh.com", "CHACHA20", 256}, {"3des-cbc", "3DES_EDE", 168},
            {"arcfour", "RC4_128", 128}})
            if (cipher.starts_with(prefix) && cipher == ssh.selected[3])
            {
                summary.encryption = algorithm;
                summary.keyBits = bits;
                break;
            }
        data["encryption"] = summary.encryption;
        data["encryption_mode"] = cipher != ssh.selected[3] ? "" : cipher.ends_with("-ctr") ? "CTR" :
            cipher.ends_with("-gcm@openssh.com") ? "GCM" : cipher.ends_with("-cbc") ? "CBC" :
            cipher == "chacha20-poly1305@openssh.com" ? "POLY1305" : "";
        data["symmetric_key_bits"] = summary.keyBits ? nlohmann::json(summary.keyBits) : nlohmann::json(nullptr);
        data["record_mac"] = ssh.selected[4] == ssh.selected[5] ? ssh.selected[4] : "";
    }
    summary.json = data.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    return summary;
}

size_t Observation::Ssh::memory() const
{
    size_t bytes = noCommon.capacity() + hostKeyType.capacity() + hostKeySha256.capacity() +
        exchangeSignature.capacity() + hostCertificate.capacity();
    for (const auto& peer : peers)
    {
        bytes += peer.banner.capacity();
        for (const auto& value : peer.algorithms)
            bytes += value.capacity();
    }
    for (const auto& value : selected)
        bytes += value.capacity();
    return bytes;
}
}
