#include "Vpn.h"

#include <algorithm>
#include <optional>
#include <utility>

namespace Cipherazzi
{
void ProtocolEvidence::measure()
{
    // Budget retained containers, capacity, and allocation overhead without creating a serialized copy.
    const auto memory = [](const auto& visit, const nlohmann::json& value) -> size_t
    {
        if (value.is_object())
        {
            const auto& object = value.get_ref<const nlohmann::json::object_t&>();
            size_t bytes = sizeof(object) + 32 + (object.size() + 1) *
                (sizeof(nlohmann::json::object_t::value_type) + 4 * sizeof(void*) + 32);
            for (const auto& [key, child] : object)
                bytes += key.capacity() + 1 + 32 + visit(visit, child);
            return bytes;
        }
        if (value.is_array())
        {
            const auto& array = value.get_ref<const nlohmann::json::array_t&>();
            size_t bytes = sizeof(array) + 32 + array.capacity() * sizeof(nlohmann::json);
            for (const auto& child : array)
                bytes += visit(visit, child);
            return bytes;
        }
        if (value.is_string())
        {
            const auto& text = value.get_ref<const nlohmann::json::string_t&>();
            return sizeof(text) + text.capacity() + 1 + 32;
        }
        if (value.is_binary())
            return sizeof(nlohmann::json::binary_t) + value.get_binary().capacity() + 32;
        return 0;
    };
    retainedBytes = memory(memory, fields) + 128;
}

std::string protocolName(Observation::Protocol protocol)
{
    switch (protocol)
    {
    case Observation::Protocol::Ssh: return "SSH 2.0";
    case Observation::Protocol::Unknown: return "Unknown";
    case Observation::Protocol::WireGuard: return "WireGuard";
    case Observation::Protocol::Ike: return "IKEv2";
    case Observation::Protocol::IkeV1: return "IKEv1";
    case Observation::Protocol::OpenVpn: return "OpenVPN";
    case Observation::Protocol::Smb: return "SMB";
    case Observation::Protocol::Rdp: return "RDP";
    case Observation::Protocol::Tds: return "TDS";
    case Observation::Protocol::Kerberos: return "Kerberos";
    case Observation::Protocol::Ldap: return "LDAP";
    case Observation::Protocol::Http: return "HTTP";
    case Observation::Protocol::Rpc: return "DCE/RPC";
    case Observation::Protocol::Smtp: return "SMTP";
    case Observation::Protocol::Imap: return "IMAP";
    case Observation::Protocol::Pop3: return "POP3";
    case Observation::Protocol::Ftp: return "FTP";
    case Observation::Protocol::PostgreSql: return "PostgreSQL";
    case Observation::Protocol::MySql: return "MySQL";
    case Observation::Protocol::Ipsec: return "IPsec";
    default: return "TLS";
    }
}

namespace VpnDetail
{
bool nonzero(Bytes value)
{
    return std::any_of(value.begin(), value.end(), [](uint8_t byte) { return byte != 0; });
}

// WireGuard handshake headers identify a fixed suite; encrypted fields and MACs remain unverified.
std::optional<VpnPacket> wireGuard(Bytes bytes)
{
    VpnPacket packet;
    const size_t expected = bytes[0] == 1 ? 148 : bytes[0] == 2 ? 92 : 64;
    if (bytes.size() != expected || (bytes[0] < 3 && !nonzero(bytes.subspan(bytes[0] == 1 ? 8 : 12, 32))))
        return {};
    packet.protocol = Observation::Protocol::WireGuard;
    packet.client = bytes[0] == 1;
    packet.fields = {{"wireguard_message_type", bytes[0]}, {"wireguard_packet_bytes", bytes.size()},
        {"wireguard_sender_index", bytes[0] < 3 ? nlohmann::json(little32(bytes, 4)) : nlohmann::json(nullptr)},
        {"wireguard_receiver_index", bytes[0] == 1 ? nlohmann::json(nullptr) :
            nlohmann::json(little32(bytes, bytes[0] == 3 ? 4 : 8))},
        {"vpn_algorithm_evidence", "Fixed by WireGuard protocol; packet authentication is unverified"},
        {"vpn_visibility", "Handshake format only; encrypted identities, timestamps, and MACs are not verified"}};
    return packet;
}

// Only IKE_SA_INIT is cleartext: its proposals, key exchange group, and nonce are validated together.
std::optional<VpnPacket> ike(Bytes bytes, bool marker)
{
    VpnPacket packet;
    if (be32(bytes, 24) != bytes.size() || bytes.size() > 65535 || be32(bytes, 20) ||
        (bytes[19] & ~0x38) || (!(bytes[19] & 0x20) && !(bytes[19] & 0x08)))
        return {};
    const bool response = (bytes[19] & 0x20) != 0;
    if ((response && (!nonzero(bytes.subspan(8, 8)) || (bytes[19] & 8))) ||
        (!response && nonzero(bytes.subspan(8, 8))))
        return {};
    nlohmann::json proposals = nlohmann::json::array();
    uint16_t keyGroup = 0;
    bool nonce = false;
    size_t offset = 28;
    uint8_t kind = bytes[16];
    for (size_t count = 0; kind && count < 32; ++count)
    {
        if (offset + 4 > bytes.size())
            return {};
        const auto length = be16(bytes, offset + 2);
        if (length < 4 || length > bytes.size() - offset)
            return {};
        const auto body = bytes.subspan(offset + 4, length - 4);
        if (kind == 33)
        {
            if (!proposals.empty())
                return {};
            size_t position = 0;
            while (position < body.size())
            {
                if (position + 8 > body.size() || proposals.size() >= 16)
                    return {};
                const auto proposal = body.subspan(position);
                const size_t size = be16(proposal, 2);
                if (size < 8 || size > proposal.size() || proposal[5] != 1 || proposal[6] ||
                    !proposal[4] || !proposal[7] || proposal[7] > 64 ||
                    proposal[0] != (size == proposal.size() ? 0 : 2))
                    return {};
                nlohmann::json transforms = nlohmann::json::array();
                size_t transformOffset = 8;
                for (int index = 0; index < proposal[7]; ++index)
                {
                    if (transformOffset + 8 > size)
                        return {};
                    const auto transform = proposal.subspan(transformOffset, size - transformOffset);
                    const size_t transformLength = be16(transform, 2);
                    if (transformLength < 8 || transformLength > transform.size() ||
                        transform[0] != (index + 1 == proposal[7] ? 0 : 3))
                        return {};
                    const int type = transform[4], id = be16(transform, 6);
                    int bits = 0;
                    for (size_t attribute = 8; attribute < transformLength;)
                    {
                        if (attribute + 4 > transformLength)
                            return {};
                        const auto format = be16(transform, attribute), value = be16(transform, attribute + 2);
                        if ((format & 0x7fff) == 14)
                        {
                            if (!(format & 0x8000) || bits)
                                return {};
                            bits = value;
                        }
                        attribute += 4;
                        if (!(format & 0x8000))
                        {
                            if (value > transformLength - attribute)
                                return {};
                            attribute += value;
                        }
                    }
                    std::string name = hex16(static_cast<uint16_t>(id));
                    if (type == 1)
                        name = id == 12 ? "AES-CBC" : id == 13 ? "AES-CTR" : id == 18 ? "AES-GCM-8" :
                            id == 19 ? "AES-GCM-12" : id == 20 ? "AES-GCM-16" :
                            id == 28 ? "ChaCha20-Poly1305" : name;
                    else if (type == 2)
                        name = id == 2 ? "HMAC-SHA1" : id == 5 ? "HMAC-SHA256" :
                            id == 6 ? "HMAC-SHA384" : id == 7 ? "HMAC-SHA512" : name;
                    else if (type == 4)
                        name = id == 14 ? "MODP-2048" : id == 19 ? "secp256r1" :
                            id == 20 ? "secp384r1" : id == 31 ? "X25519" : name;
                    transforms.push_back({{"type", type}, {"id", id}, {"name", name}, {"key_bits", bits}});
                    transformOffset += transformLength;
                }
                if (transformOffset != size)
                    return {};
                proposals.push_back({{"number", proposal[4]}, {"protocol_id", proposal[5]},
                    {"transforms", std::move(transforms)}});
                position += size;
            }
        }
        else if (kind == 34)
        {
            if (body.size() < 5 || keyGroup)
                return {};
            keyGroup = be16(body, 0);
            if (keyGroup == 14 && body.size() != 260)
                return {};
        }
        else if (kind == 40)
        {
            if (body.size() < 16 || body.size() > 256 || nonce)
                return {};
            nonce = true;
        }
        kind = bytes[offset];
        offset += length;
    }
    if (kind || offset != bytes.size() || proposals.empty() || !keyGroup || !nonce ||
        (response && proposals.size() != 1))
        return {};
    bool exchangeOffered = false;
    for (const auto& proposal : proposals)
    {
        std::array<int, 5> types{};
        for (const auto& transform : proposal["transforms"])
        {
            const int type = transform["type"], id = transform["id"];
            if (type < 1 || type > 4 || (response && ++types[type] > 1))
                return {};
            if (!response)
                ++types[type];
            exchangeOffered |= type == 4 && id == keyGroup;
        }
        if (!types[1] || !types[2] || !types[4])
            return {};
    }
    if (!exchangeOffered)
        return {};
    packet.protocol = Observation::Protocol::Ike;
    packet.client = !response;
    packet.fields = {{"ike_initiator_spi", hex(bytes.first(8))}, {"ike_responder_spi", hex(bytes.subspan(8, 8))},
        {"ike_response", response}, {"ike_message_id", be32(bytes, 20)}, {"ike_exchange", "IKE_SA_INIT"},
        {"ike_non_esp_marker", marker}, {"ike_key_exchange_group_id", keyGroup},
        {response ? "ike_selection" : "ike_offers", std::move(proposals)},
        {"vpn_algorithm_evidence", response ? "Responder SA_INIT selection; authentication is not established" :
            "Initiator SA_INIT proposals; no algorithm selection is established"},
        {"vpn_visibility", "Initial proposals and key exchange only; IKE_AUTH and tunnel traffic are encrypted"}};
    return packet;
}

// IKEv1 exposes phase-one SA and clear payload headers; protected payload bodies stay opaque.
std::optional<VpnPacket> ikeV1(Bytes bytes, bool marker)
{
    if (bytes.size() < 28 || bytes.size() > 65535 || be32(bytes, 24) != bytes.size() ||
        !nonzero(bytes.first(8)) || bytes[17] != 0x10 || !bytes[16] || (bytes[19] & ~uint8_t{3}) ||
        (bytes[18] != 2 && bytes[18] != 4 && bytes[18] != 32) ||
        (bytes[18] == 32 ? !be32(bytes, 20) : be32(bytes, 20)))
        return {};
    const bool responderCookie = nonzero(bytes.subspan(8, 8));
    if (bytes[18] == 32 || (bytes[19] & 1))
    {
        if (!responderCookie || bytes.size() < 36 || (bytes[18] == 32 && !(bytes[19] & 1)))
            return {};
        VpnPacket packet;
        packet.protocol = Observation::Protocol::IkeV1;
        packet.roleKnown = false;
        packet.fields = {{"ikev1_initiator_cookie", hex(bytes.first(8))},
            {"ikev1_responder_cookie", hex(bytes.subspan(8, 8))},
            {"ikev1_exchange", bytes[18] == 32 ? "Quick Mode" : bytes[18] == 2 ? "Main Mode" :
                "Aggressive Mode"},
            {"ikev1_non_esp_marker", marker}, {"ikev1_message_id", be32(bytes, 20)},
            {"ikev1_first_payload_type", bytes[16]}, {"ikev1_ciphertext_bytes", bytes.size() - 28},
            {bytes[18] == 32 ? "ikev1_quick_mode_observed" : "ikev1_encrypted_payload_observed", true},
            {"vpn_algorithm_evidence", "Visible IKEv1 header only; authentication is unverified"},
            {"vpn_visibility", "Protected IKEv1 payload bodies and tunnel traffic are not decrypted"}};
        return packet;
    }
    if (bytes[18] == 32 || bytes.size() < 36)
        return {};

    const bool response = responderCookie;
    nlohmann::json transforms = nlohmann::json::array();
    bool sawSa = false, keyExchange = false, nonce = false, identity = false, auth = false;
    size_t keyBytes = 0, nonceBytes = 0, idBytes = 0, authBytes = 0, natDiscoveryCount = 0;
    uint8_t idType = 0;
    std::string authType;
    size_t offset = 28;
    uint8_t kind = bytes[16];
    for (size_t count = 0; kind && count < 16; ++count)
    {
        if (bytes.size() - offset < 4)
            return {};
        const auto length = be16(bytes, offset + 2);
        if (length < 4 || length > bytes.size() - offset || bytes[offset + 1])
            return {};
        const auto body = bytes.subspan(offset + 4, length - 4);
        if (kind == 1)
        {
            if (sawSa || offset != 28 || body.size() < 16 || be32(body, 0) != 1 || be32(body, 4) != 1)
                return {};
            sawSa = true;
            size_t proposalOffset = 8;
            while (proposalOffset < body.size())
            {
                const auto proposal = body.subspan(proposalOffset);
                if (proposal.size() < 8)
                    return {};
                const size_t proposalLength = be16(proposal, 2);
                if (proposalLength < 16 || proposalLength > proposal.size() || proposal[1] || proposal[5] != 1 ||
                    proposal[6] > 16 || !proposal[7] || proposal[7] > 32 ||
                    proposal[0] != (proposalLength == proposal.size() ? 0 : 2))
                    return {};
                size_t transformOffset = 8 + proposal[6];
                if (transformOffset >= proposalLength)
                    return {};
                for (size_t index = 0; index < proposal[7]; ++index)
                {
                    const auto transform = proposal.subspan(transformOffset, proposalLength - transformOffset);
                    if (transform.size() < 8)
                        return {};
                    const size_t transformLength = be16(transform, 2);
                    if (transformLength < 12 || transformLength > transform.size() || transform[1] ||
                        transform[5] != 1 || transform[6] || transform[7] ||
                        transform[0] != (index + 1 == proposal[7] ? 0 : 3))
                        return {};
                    nlohmann::json attributes = nlohmann::json::object();
                    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> normalizedAttributes;
                    for (size_t attribute = 8; attribute < transformLength;)
                    {
                        if (transformLength - attribute < 4)
                            return {};
                        const auto type = be16(transform, attribute), value = be16(transform, attribute + 2);
                        attribute += 4;
                        const auto number = type & 0x7fff;
                        if (number < 1 || number > 16 || normalizedAttributes.size() >= 64)
                            return {};
                        std::vector<uint8_t> normalizedValue;
                        if (!(type & 0x8000))
                        {
                            const bool basic = number <= 5 || number == 11 || number == 13 ||
                                number == 14 || number == 15;
                            if (!value || value > 4096 || value > transformLength - attribute || basic)
                                return {};
                            normalizedValue.assign(transform.begin() + attribute,
                                transform.begin() + attribute + value);
                            attribute += value;
                            size_t leading = 0;
                            while (normalizedValue.size() - leading > 2 && normalizedValue[leading] == 0)
                                ++leading;
                            normalizedValue.erase(normalizedValue.begin(), normalizedValue.begin() + leading);
                            if (normalizedValue.size() == 1)
                                normalizedValue.insert(normalizedValue.begin(), 0);
                        }
                        else
                        {
                            normalizedValue = {static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
                        }
                        if ((number == 15 || number == 16) &&
                            std::ranges::all_of(normalizedValue, [](uint8_t byte) { return byte == 0; }))
                            return {};
                        if (number == 1 || number == 2 || number == 3 || number == 4 || number == 14)
                        {
                            if (attributes.contains(std::to_string(number)))
                                return {};
                            attributes[std::to_string(number)] = value;
                        }
                        normalizedAttributes.emplace_back(static_cast<uint16_t>(number),
                            std::move(normalizedValue));
                    }
                    if (!attributes.contains("1") || !attributes.contains("2") || !attributes.contains("3") ||
                        !attributes.contains("4"))
                        return {};

                    // Compare transform attributes by value, independent of order and short variable encoding.
                    std::sort(normalizedAttributes.begin(), normalizedAttributes.end());
                    std::vector<uint8_t> normalizedBytes;
                    for (const auto& [number, value] : normalizedAttributes)
                    {
                        normalizedBytes.insert(normalizedBytes.end(), {static_cast<uint8_t>(number >> 8),
                            static_cast<uint8_t>(number), static_cast<uint8_t>(value.size() >> 8),
                            static_cast<uint8_t>(value.size())});
                        normalizedBytes.insert(normalizedBytes.end(), value.begin(), value.end());
                    }
                    transforms.push_back({{"proposal", proposal[4]}, {"number", transform[4]},
                        {"encryption_id", attributes["1"]}, {"hash_id", attributes["2"]},
                        {"authentication_id", attributes["3"]}, {"group_id", attributes["4"]},
                        {"key_bits", attributes.value("14", 0)},
                        {"attribute_sha256", sha256(normalizedBytes)}});
                    transformOffset += transformLength;
                }
                if (transformOffset != proposalLength)
                    return {};
                proposalOffset += proposalLength;
            }
        }
        else if (kind == 4)
        {
            if (keyExchange || body.size() < 16 || body.size() > 4096 || !nonzero(body))
                return {};
            keyExchange = true;
            keyBytes = body.size();
        }
        else if (kind == 10)
        {
            if (nonce || body.size() < 8 || body.size() > 4096)
                return {};
            nonce = true;
            nonceBytes = body.size();
        }
        else if (kind == 5)
        {
            if (identity || body.size() < 5 || body.size() > 4096)
                return {};
            identity = true;
            idType = body[0];
            idBytes = body.size();
        }
        else if (kind == 8 || kind == 9)
        {
            if (auth || body.size() < 8 || body.size() > 4096)
                return {};
            auth = true;
            authType = kind == 8 ? "HASH" : "Signature";
            authBytes = body.size();
        }
        else if (kind == 20)
        {
            if (body.size() < 16 || body.size() > 64 || ++natDiscoveryCount > 8)
                return {};
        }
        else if (kind != 6 && kind != 7 && kind != 13)
            return {};
        kind = bytes[offset];
        offset += length;
    }
    if (kind || offset != bytes.size() || (sawSa && (transforms.empty() ||
        (response && transforms.size() != 1))) || (!sawSa && !responderCookie) ||
        (bytes[18] == 2 ? (sawSa ? keyExchange || nonce || identity || auth : !keyExchange || !nonce) :
            (sawSa ? !keyExchange || !nonce || !identity : !auth)))
        return {};
    VpnPacket packet;
    packet.protocol = Observation::Protocol::IkeV1;
    packet.client = sawSa && !response;
    packet.roleKnown = sawSa;
    packet.fields = {{"ikev1_initiator_cookie", hex(bytes.first(8))},
        {"ikev1_responder_cookie", hex(bytes.subspan(8, 8))},
        {"ikev1_exchange", bytes[18] == 2 ? "Main Mode" : "Aggressive Mode"},
        {"ikev1_non_esp_marker", marker},
        {"vpn_algorithm_evidence", sawSa ? (response ?
            "Responder phase-one SA selection; authentication is unverified" :
            "Initiator phase-one SA proposals; no algorithm selection is established") :
            "Clear phase-one payloads observed; authentication is unverified"},
        {"vpn_visibility", "Clear phase-one payload metadata only; protected payloads and tunnel traffic "
            "are not decrypted"}};
    if (sawSa)
        packet.fields[response ? "ikev1_selection" : "ikev1_offers"] = std::move(transforms);
    if (keyExchange)
        packet.fields["ikev1_key_exchange_bytes"] = keyBytes;
    if (nonce)
        packet.fields["ikev1_nonce_payload_bytes"] = nonceBytes;
    if (identity)
    {
        packet.fields["ikev1_id_type_octet"] = idType;
        packet.fields["ikev1_identity_payload_bytes"] = idBytes;
    }
    if (auth)
    {
        packet.fields["ikev1_auth_payload_type"] = authType;
        packet.fields["ikev1_auth_payload_bytes"] = authBytes;
    }
    if (natDiscoveryCount)
        packet.fields["ikev1_nat_discovery_payloads"] = natDiscoveryCount;
    return packet;
}

// Parse the clear OpenVPN reliability envelope before accepting reset, acknowledgment, or TLS bytes.
std::optional<VpnPacket> openVpn(Bytes bytes)
{
    VpnPacket packet;
    if (bytes.size() < 10 || !nonzero(bytes.subspan(1, 8)))
        return {};
    const auto opcode = bytes[0] >> 3;
    if (opcode != 4 && opcode != 5 && opcode != 7 && opcode != 8)
        return {};
    const size_t acknowledgments = bytes[9];
    size_t offset = 10 + acknowledgments * 4 + (acknowledgments ? 8 : 0);
    if (acknowledgments > 32 || offset > bytes.size() || (opcode == 5 && offset != bytes.size()))
        return {};
    if (opcode != 5)
    {
        if (offset + 4 > bytes.size())
            return {};
        packet.packetId = be32(bytes, offset);
        offset += 4;
    }
    packet.reset = opcode == 7 || opcode == 8;
    if (packet.reset && (offset != bytes.size() || packet.packetId))
        return {};
    packet.protocol = Observation::Protocol::OpenVpn;
    packet.client = opcode != 8;
    packet.tls = bytes.subspan(offset);
    if (opcode == 4 && packet.tls.size() >= 6 && packet.tls[0] == 22 && packet.tls[5] == 2)
        packet.client = false;
    packet.fields = {{"openvpn_opcode", opcode}, {"openvpn_key_id", bytes[0] & 7},
        {"openvpn_session_id", hex(bytes.subspan(1, 8))}, {"openvpn_packet_id", packet.packetId},
        {"openvpn_acknowledgments", acknowledgments},
        {"vpn_algorithm_evidence", "Visible control envelope; data-channel cipher is not established"},
        {"vpn_visibility", "Clear control packets only; tls-auth, tls-crypt, data traffic, and authentication "
            "are not decrypted"}};
    if (acknowledgments)
        packet.fields["openvpn_remote_session_id"] = hex(bytes.subspan(10 + acknowledgments * 4, 8));
    return packet;
}
}
using namespace VpnDetail;

std::optional<VpnPacket> parseVpn(Bytes bytes)
{
    if (bytes.size() >= 4 && bytes[0] >= 1 && bytes[0] <= 3 && !bytes[1] && !bytes[2] && !bytes[3])
        return wireGuard(bytes);

    // IKEv2 can carry a four-byte non-ESP marker on NAT traversal transports, independent of port number.
    const bool marker = bytes.size() >= 32 && !nonzero(bytes.first(4)) &&
        (bytes[21] == 0x20 || bytes[21] == 0x10);
    const auto message = marker ? bytes.subspan(4) : bytes;
    if (message.size() >= 28 && message[17] == 0x20 && message[18] == 34 && nonzero(message.first(8)))
        return ike(message, marker);
    if (message.size() >= 28 && message[17] == 0x10 && nonzero(message.first(8)))
        return ikeV1(message, marker);
    return openVpn(bytes);
}

void applyVpn(Observation& observation, const VpnPacket& packet)
{
    auto evidence = std::make_shared<ProtocolEvidence>();
    if (observation.vpn)
        evidence->fields = observation.vpn->fields;
    evidence->fields.update(packet.fields);
    if (packet.protocol == Observation::Protocol::WireGuard && packet.fields["wireguard_message_type"] == 1)
        evidence->fields["wireguard_initiator_index"] = packet.fields["wireguard_sender_index"];
    evidence->measure();
    observation.vpn = std::move(evidence);
    observation.protocol = packet.protocol;
}

bool OpenVpnStream::feed(const VpnPacket& packet, const TlsStream::Sink& sink)
{
    if (packet.reset || packet.tls.empty() || packet.packetId < next_)
        return true;
    if (packet.packetId - next_ > 64 || pending_.size() >= 64 || memory() + packet.tls.size() > 262144)
        return false;
    pending_.try_emplace(packet.packetId, packet.tls.begin(), packet.tls.end());
    for (;;)
    {
        const auto found = pending_.find(next_);
        if (found == pending_.end())
            break;
        if (!tls_.feed(found->second, sink))
            return false;
        pending_.erase(found);
        ++next_;
    }
    return true;
}

size_t OpenVpnStream::memory() const
{
    size_t bytes = sizeof(*this) + tls_.memory();
    for (const auto& [id, value] : pending_)
        bytes += sizeof(id) + sizeof(value) + value.capacity() + 4 * sizeof(void*);
    return bytes;
}
}
