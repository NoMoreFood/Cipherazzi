#include "Rpc.h"
#include <utility>

namespace Cipherazzi
{
static uint16_t rpc16(Bytes bytes, size_t offset, bool little)
{
    return little ? static_cast<uint16_t>(bytes[offset] | bytes[offset + 1] << 8) :
        static_cast<uint16_t>(bytes[offset] << 8 | bytes[offset + 1]);
}

static uint32_t rpc32(Bytes bytes, size_t offset, bool little)
{
    return little ? uint32_t(bytes[offset]) | uint32_t(bytes[offset + 1]) << 8 |
        uint32_t(bytes[offset + 2]) << 16 | uint32_t(bytes[offset + 3]) << 24 :
        uint32_t(bytes[offset]) << 24 | uint32_t(bytes[offset + 1]) << 16 |
        uint32_t(bytes[offset + 2]) << 8 | bytes[offset + 3];
}

static const char* authType(uint8_t type)
{
    switch (type)
    {
    case 0: return "None";
    case 1: return "DCE private key";
    case 2: return "DCE public key";
    case 4: return "DEC public key";
    case 9: return "SPNEGO";
    case 10: return "NTLM";
    case 14: return "Schannel";
    case 16: return "Kerberos";
    case 17: return "DPA";
    case 18: return "MSN";
    case 21: return "Digest";
    case 30: return "NegoEx";
    case 68: return "Netlogon";
    case 100: return "MSMQ";
    case 255: return "Default";
    default: return "Unknown";
    }
}

static const char* authLevel(uint8_t level)
{
    switch (level)
    {
    case 0: return "Default";
    case 1: return "None";
    case 2: return "Connect";
    case 3: return "Call";
    case 4: return "Packet";
    case 5: return "Packet integrity";
    case 6: return "Packet privacy";
    default: return "Unknown";
    }
}

bool parseRpcBind(Bytes pdu, nlohmann::json& fields)
{
    // A complete version 5.0 PDU has a 16-byte common header; only bind requests have the context-list body.
    if (pdu.size() < 16 || pdu[0] != 5 || pdu[1] != 0 || (pdu[4] != 0x10 && pdu[4] != 0))
        return false;
    const bool little = pdu[4] == 0x10;
    const size_t length = rpc16(pdu, 8, little), authLength = rpc16(pdu, 10, little);
    if (length != pdu.size() || authLength > length - 16)
        return false;
    if (pdu[2] != 11 && pdu[2] != 14)
        return true;
    if (length < 28)
        return false;

    // Each context contains its abstract syntax and a counted list of transfer syntaxes.
    const size_t trailer = authLength ? length - authLength - 8 : length;
    if (trailer < 28)
        return false;
    size_t offset = 28;
    for (size_t context = 0; context < pdu[24]; ++context)
    {
        if (trailer - offset < 24)
            return false;
        const size_t transfers = pdu[offset + 2];
        offset += 24;
        if (!transfers || transfers > (trailer - offset) / 20)
            return false;
        offset += transfers * 20;
    }

    // The security trailer precedes the opaque authentication token; no identity or token bytes are retained.
    nlohmann::json bind{{"kind", pdu[2] == 11 ? "Bind" : "Alter context"},
        {"call_id", rpc32(pdu, 12, little)}};
    if (!authLength)
    {
        if (offset != length)
            return false;
        bind["authentication_type"] = "None";
        bind["protection_level"] = "None";
        bind["authentication_trailer_present"] = false;
    }
    else
    {
        if (offset > trailer || trailer - offset != pdu[trailer + 2] || pdu[trailer + 2] > 15)
            return false;
        bind["authentication_type"] = authType(pdu[trailer]);
        bind["authentication_type_id"] = pdu[trailer];
        bind["protection_level"] = authLevel(pdu[trailer + 1]);
        bind["protection_level_id"] = pdu[trailer + 1];
        bind["authentication_context_id"] = rpc32(pdu, trailer + 4, little);
        bind["authentication_trailer_present"] = true;
    }
    fields["rpc_bind"] = std::move(bind);
    return true;
}
}
