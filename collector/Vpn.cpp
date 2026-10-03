#include "Vpn.h"

#include <algorithm>
#include <optional>

namespace Cipherazzi
{
std::string protocolName(Observation::Protocol protocol)
{
    switch (protocol)
    {
    case Observation::Protocol::Ssh: return "SSH 2.0";
    case Observation::Protocol::Unknown: return "Unknown";
    case Observation::Protocol::WireGuard: return "WireGuard";
    case Observation::Protocol::Ike: return "IKEv2";
    case Observation::Protocol::OpenVpn: return "OpenVPN";
    case Observation::Protocol::Smb: return "SMB";
    case Observation::Protocol::Rdp: return "RDP";
    case Observation::Protocol::Tds: return "TDS";
    case Observation::Protocol::Kerberos: return "Kerberos";
    default: return "TLS";
    }
}

std::optional<VpnPacket> parseVpn(Bytes bytes)
{
    VpnPacket packet;
    auto nonzero = [](Bytes value)
    {
        return std::any_of(value.begin(), value.end(), [](uint8_t byte) { return byte != 0; });
    };
    auto hex = [](Bytes value)
    {
        constexpr char digits[] = "0123456789abcdef";
        std::string result;
        for (const auto byte : value)
        {
            result += digits[byte >> 4];
            result += digits[byte & 15];
        }
        return result;
    };
    auto little = [&](size_t offset)
    {
        return uint32_t(bytes[offset]) | uint32_t(bytes[offset + 1]) << 8 |
            uint32_t(bytes[offset + 2]) << 16 | uint32_t(bytes[offset + 3]) << 24;
    };

    // WireGuard handshake headers identify a fixed suite; encrypted fields and MACs remain unverified.
    if (bytes.size() >= 4 && bytes[0] >= 1 && bytes[0] <= 3 && !bytes[1] && !bytes[2] && !bytes[3])
    {
        const size_t expected = bytes[0] == 1 ? 148 : bytes[0] == 2 ? 92 : 64;
        if (bytes.size() != expected || (bytes[0] < 3 && !nonzero(bytes.subspan(bytes[0] == 1 ? 8 : 12, 32))))
            return {};
        packet.protocol = Observation::Protocol::WireGuard;
        packet.client = bytes[0] == 1;
        packet.fields = {{"wireguard_message_type", bytes[0]}, {"wireguard_packet_bytes", bytes.size()},
            {"wireguard_sender_index", bytes[0] < 3 ? nlohmann::json(little(4)) : nlohmann::json(nullptr)},
            {"wireguard_receiver_index", bytes[0] == 1 ? nlohmann::json(nullptr) :
                nlohmann::json(little(bytes[0] == 3 ? 4 : 8))},
            {"vpn_algorithm_evidence", "Fixed by WireGuard protocol; packet authentication is unverified"},
            {"vpn_visibility", "Handshake format only; encrypted identities, timestamps, and MACs are not verified"}};
        return packet;
    }

    // IKEv2 can carry a four-byte non-ESP marker on NAT traversal transports, independent of port number.
    bool marker = bytes.size() >= 32 && !nonzero(bytes.first(4)) && bytes[21] == 0x20;
    if (marker)
        bytes = bytes.subspan(4);
    if (bytes.size() >= 28 && bytes[17] == 0x20 && bytes[18] == 34 && nonzero(bytes.first(8)))
    {
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

    // Parse the clear OpenVPN reliability envelope before accepting reset, acknowledgment, or TLS bytes.
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
        {"vpn_visibility", "Clear control packets only; tls-auth, tls-crypt, data traffic, and authentication are not decrypted"}};
    if (acknowledgments)
        packet.fields["openvpn_remote_session_id"] = hex(bytes.subspan(10 + acknowledgments * 4, 8));
    return packet;
}

void applyVpn(Observation& observation, const VpnPacket& packet)
{
    auto evidence = std::make_shared<VpnEvidence>();
    if (observation.vpn)
        evidence->fields = observation.vpn->fields;
    evidence->fields.update(packet.fields);
    if (packet.protocol == Observation::Protocol::WireGuard && packet.fields["wireguard_message_type"] == 1)
        evidence->fields["wireguard_initiator_index"] = packet.fields["wireguard_sender_index"];
    evidence->retainedBytes = evidence->fields.dump().size() * 3 + 1024;
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
