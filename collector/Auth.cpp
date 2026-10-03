#include "Auth.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <string_view>

namespace Cipherazzi
{
namespace
{
using Json = nlohmann::json;

uint16_t little16(Bytes bytes, size_t offset)
{
    return static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
}

uint32_t little32(Bytes bytes, size_t offset)
{
    return little16(bytes, offset) | (static_cast<uint32_t>(little16(bytes, offset + 2)) << 16);
}

// Only definite, minimally encoded lengths and single-byte tags are accepted; `whole` receives the full element.
bool derRead(Bytes& input, uint8_t& tag, Bytes& value, Bytes* whole = nullptr)
{
    if (input.size() < 2 || (input[0] & 0x1f) == 0x1f)
        return false;
    size_t length = input[1], header = 2;
    if (length & 0x80)
    {
        const size_t count = length & 0x7f;
        if (!count || count > 4 || input.size() < 2 + count || !input[2])
            return false;
        length = 0;
        for (size_t index = 0; index < count; ++index)
            length = (length << 8) | input[2 + index];
        if (length < 128)
            return false;
        header += count;
    }
    if (length > input.size() - header)
        return false;
    tag = input[0];
    value = input.subspan(header, length);
    if (whole)
        *whole = input.first(header + length);
    input = input.subspan(header + length);
    return true;
}

bool derExpect(Bytes& input, uint8_t expected, Bytes& value)
{
    uint8_t tag;
    return derRead(input, tag, value) && tag == expected;
}

// The input must hold exactly one element of the expected type.
bool derOnly(Bytes input, uint8_t expected, Bytes& value)
{
    return derExpect(input, expected, value) && input.empty();
}

bool derInteger(Bytes value, int64_t& result)
{
    if (value.empty() || value.size() > 8 ||
        (value.size() > 1 && ((value[0] == 0 && !(value[1] & 0x80)) || (value[0] == 0xff && (value[1] & 0x80)))))
        return false;
    uint64_t accumulated = value[0] & 0x80 ? ~uint64_t{} : 0;
    for (const auto byte : value)
        accumulated = (accumulated << 8) | byte;
    result = static_cast<int64_t>(accumulated);
    return true;
}

// Context-tagged members of a SEQUENCE: each at most once and in ascending order.
struct Members
{
    std::array<Bytes, 32> item;
    uint32_t present{};
    bool has(size_t index) const { return (present >> index) & 1; }
    bool get(size_t index, uint8_t tag, Bytes& value) const { return has(index) && derOnly(item[index], tag, value); }
    bool integer(size_t index, int64_t& value) const
    {
        Bytes raw;
        return get(index, 0x02, raw) && derInteger(raw, value);
    }
};

bool derMembers(Bytes content, Members& members)
{
    int previous = -1;
    while (!content.empty())
    {
        uint8_t tag;
        Bytes value;
        if (!derRead(content, tag, value) || (tag & 0xe0) != 0xa0 || static_cast<int>(tag & 0x1f) <= previous)
            return false;
        const size_t index = tag & 0x1f;
        previous = static_cast<int>(index);
        members.item[index] = value;
        members.present |= 1u << index;
    }
    return true;
}

bool derSequence(Bytes element, Members& members)
{
    Bytes content;
    return derOnly(element, 0x30, content) && derMembers(content, members);
}

std::string etypeName(int64_t type)
{
    switch (type)
    {
    case 1: return "des-cbc-crc";
    case 2: return "des-cbc-md4";
    case 3: return "des-cbc-md5";
    case 5: return "des3-cbc-md5";
    case 7: return "des3-cbc-sha1";
    case 16: return "des3-cbc-sha1-kd";
    case 17: return "aes128-cts-hmac-sha1-96";
    case 18: return "aes256-cts-hmac-sha1-96";
    case 19: return "aes128-cts-hmac-sha256-128";
    case 20: return "aes256-cts-hmac-sha384-192";
    case 23: return "rc4-hmac";
    case 24: return "rc4-hmac-exp";
    case 25: return "camellia128-cts-cmac";
    case 26: return "camellia256-cts-cmac";
    case -128: return "rc4-md4";
    case -133: return "rc4-hmac-old";
    case -135: return "rc4-hmac-old-exp";
    default: return std::format("etype {}", type);
    }
}

std::string preauthName(int64_t type)
{
    switch (type)
    {
    case 1: return "PA-TGS-REQ";
    case 2: return "PA-ENC-TIMESTAMP";
    case 3: return "PA-PW-SALT";
    case 11: return "PA-ETYPE-INFO";
    case 15: return "PA-ENC-UNIX-TIME";
    case 16: return "PA-PK-AS-REQ";
    case 17: return "PA-PK-AS-REP";
    case 19: return "PA-ETYPE-INFO2";
    case 128: return "PA-PAC-REQUEST";
    case 129: return "PA-FOR-USER";
    case 130: return "PA-S4U-X509-USER";
    case 133: return "PA-FX-COOKIE";
    case 136: return "PA-FX-FAST";
    case 137: return "PA-FX-ERROR";
    case 138: return "PA-ENCRYPTED-CHALLENGE";
    case 149: return "PA-REQ-ENC-PA-REP";
    case 150: return "PA-AS-FRESHNESS";
    case 161: return "PA-KERB-KEY-LIST-REQ";
    case 162: return "PA-KERB-KEY-LIST-REP";
    case 165: return "PA-SUPPORTED-ENCTYPES";
    case 167: return "PA-PAC-OPTIONS";
    default: return std::format("PA-DATA {}", type);
    }
}

const char* errorName(int64_t code)
{
    switch (code)
    {
    case 6: return "KDC_ERR_C_PRINCIPAL_UNKNOWN";
    case 7: return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
    case 14: return "KDC_ERR_ETYPE_NOSUPP";
    case 15: return "KDC_ERR_SUMTYPE_NOSUPP";
    case 16: return "KDC_ERR_PADATA_TYPE_NOSUPP";
    case 18: return "KDC_ERR_CLIENT_REVOKED";
    case 23: return "KDC_ERR_KEY_EXPIRED";
    case 24: return "KDC_ERR_PREAUTH_FAILED";
    case 25: return "KDC_ERR_PREAUTH_REQUIRED";
    case 29: return "KDC_ERR_SVC_UNAVAILABLE";
    case 31: return "KRB_AP_ERR_BAD_INTEGRITY";
    case 32: return "KRB_AP_ERR_TKT_EXPIRED";
    case 34: return "KRB_AP_ERR_REPEAT";
    case 37: return "KRB_AP_ERR_SKEW";
    case 41: return "KRB_AP_ERR_MODIFIED";
    case 52: return "KRB_ERR_RESPONSE_TOO_BIG";
    case 60: return "KRB_ERR_GENERIC";
    case 62: return "KDC_ERR_CLIENT_NOT_TRUSTED";
    case 63: return "KDC_ERR_KDC_NOT_TRUSTED";
    case 64: return "KDC_ERR_INVALID_SIG";
    case 65: return "KDC_ERR_KEY_TOO_WEAK";
    case 68: return "KDC_ERR_WRONG_REALM";
    default: return nullptr;
    }
}

bool isKerberosTag(uint8_t tag)
{
    return (tag >= 0x6a && tag <= 0x6d) || tag == 0x7e;
}

// Name components are retained as service identity only when they are plain printable ASCII.
bool principal(Bytes element, std::string& text)
{
    Members name;
    Bytes strings;
    int64_t type;
    if (!derSequence(element, name) || !name.integer(0, type) || !name.get(1, 0x30, strings))
        return false;
    text.clear();
    bool printable = true;
    for (size_t count = 0; !strings.empty(); ++count)
    {
        uint8_t tag;
        Bytes value;
        if (count == 8 || !derRead(strings, tag, value) || (tag != 0x1b && tag != 0x0c) || value.empty() ||
            value.size() > 255)
            return false;
        printable &= std::ranges::all_of(value, [](uint8_t byte) { return byte > 0x20 && byte < 0x7f; });
        if (count)
            text += '/';
        text.append(value.begin(), value.end());
    }
    if (text.empty())
        return false;
    if (!printable)
        text.clear();
    return true;
}

bool encryptedData(Bytes element, int64_t& type)
{
    Members data;
    Bytes cipher;
    int64_t version;
    return derSequence(element, data) && data.integer(0, type) && type >= INT32_MIN && type <= INT32_MAX &&
        (!data.has(1) || data.integer(1, version)) && data.get(2, 0x04, cipher);
}

struct TicketInfo
{
    int64_t type{};
    std::string service;
};

bool ticket(Bytes element, TicketInfo& info)
{
    Bytes content, realm;
    Members fields;
    int64_t version;
    return derOnly(element, 0x61, content) && derSequence(content, fields) && fields.integer(0, version) &&
        version == 5 && fields.get(1, 0x1b, realm) && principal(fields.item[2], info.service) &&
        encryptedData(fields.item[3], info.type);
}

struct ApRequest
{
    TicketInfo ticket;
    int64_t authenticator{};
    bool mutual{}, userToUser{};
};

bool apRequest(Bytes element, ApRequest& result)
{
    Bytes content, options;
    Members fields;
    int64_t version, type;
    if (!derOnly(element, 0x6e, content) || !derSequence(content, fields) || !fields.integer(0, version) ||
        version != 5 || !fields.integer(1, type) || type != 14 || !fields.get(2, 0x03, options) ||
        options.size() < 5 || options[0] > 7 || !ticket(fields.item[3], result.ticket) ||
        !encryptedData(fields.item[4], result.authenticator))
        return false;
    result.userToUser = (options[1] & 0x40) != 0;
    result.mutual = (options[1] & 0x20) != 0;
    return true;
}

// Calls `visit` for each PA-DATA entry and records the entry names in order.
template <class Visit>
bool preauthentication(Bytes element, Json& names, Visit&& visit)
{
    Bytes content;
    if (!derOnly(element, 0x30, content))
        return false;
    names = Json::array();
    while (!content.empty())
    {
        uint8_t tag;
        Bytes entry, value;
        Members data;
        int64_t type;
        if (names.size() == 32 || !derRead(content, tag, entry) || tag != 0x30 || !derMembers(entry, data) ||
            !data.integer(1, type) || !data.get(2, 0x04, value) || !visit(type, value))
            return false;
        names.push_back(preauthName(type));
    }
    return true;
}

bool encryptionList(Bytes element, Json& names)
{
    Bytes content;
    if (!derOnly(element, 0x30, content))
        return false;
    names = Json::array();
    while (!content.empty())
    {
        Bytes value;
        int64_t type;
        if (names.size() == 32 || !derExpect(content, 0x02, value) || !derInteger(value, type) ||
            type < INT32_MIN || type > INT32_MAX)
            return false;
        names.push_back(etypeName(type));
    }
    return !names.empty();
}

bool kdcRequest(Bytes element, bool tgs, Json& fields)
{
    Members request, body;
    Bytes options, realm;
    int64_t version, type, nonce;
    Json out = Json::object(), names;
    std::string service;
    if (!derSequence(element, request) || !request.integer(1, version) || version != 5 ||
        !request.integer(2, type) || type != (tgs ? 12 : 10) || !request.has(4) ||
        !derSequence(request.item[4], body) || !body.get(0, 0x03, options) || options.size() < 5 ||
        !body.get(2, 0x1b, realm) || !body.integer(7, nonce) || !body.has(8) ||
        !encryptionList(body.item[8], out["offered_encryption_types"]) ||
        (body.has(3) && !principal(body.item[3], service)))
        return false;
    if (!service.empty())
        out["service_principal"] = service;

    // Additional tickets (user-to-user, constrained delegation) expose the encryption of the key they were issued under.
    if (body.has(11))
    {
        Bytes list;
        if (!derOnly(body.item[11], 0x30, list))
            return false;
        for (size_t count = 0; !list.empty(); ++count)
        {
            uint8_t tag;
            Bytes value, whole;
            TicketInfo info;
            if (count == 4 || !derRead(list, tag, value, &whole) || !ticket(whole, info))
                return false;
            if (!count)
                out["additional_ticket_encryption"] = etypeName(info.type);
        }
    }
    if (request.has(3))
    {
        ApRequest ap;
        bool hasAp = false;
        int64_t timestamp = 0;
        bool hasTimestamp = false;
        if (!preauthentication(request.item[3], names, [&](int64_t kind, Bytes value)
            {
                if (kind == 1 && tgs)
                    return hasAp = apRequest(value, ap);
                if (kind == 2 || kind == 138)
                    return hasTimestamp = encryptedData(value, timestamp);
                return true;
            }))
            return false;
        if (!names.empty())
            out["preauthentication"] = std::move(names);
        if (hasAp)
        {
            out["ticket_granting_ticket_encryption"] = etypeName(ap.ticket.type);
            out["authenticator_encryption"] = etypeName(ap.authenticator);
        }
        if (hasTimestamp)
            out["preauthentication_encryption"] = etypeName(timestamp);
    }
    fields[tgs ? "krb_tgs_request" : "krb_as_request"] = std::move(out);
    return true;
}

bool kdcReply(Bytes element, bool tgs, Json& fields)
{
    Members reply;
    Bytes realm;
    int64_t version, type, replyType;
    TicketInfo info;
    std::string client;
    Json out = Json::object(), names;
    if (!derSequence(element, reply) || !reply.integer(0, version) || version != 5 ||
        !reply.integer(1, type) || type != (tgs ? 13 : 11) || !reply.get(3, 0x1b, realm) ||
        !principal(reply.item[4], client) || !ticket(reply.item[5], info) || !encryptedData(reply.item[6], replyType) ||
        (reply.has(2) && !preauthentication(reply.item[2], names, [](int64_t, Bytes) { return true; })))
        return false;
    out["ticket_encryption"] = etypeName(info.type);
    out["reply_encryption"] = etypeName(replyType);
    if (!info.service.empty())
        out["service_principal"] = info.service;
    if (!names.empty())
        out["preauthentication"] = std::move(names);
    fields[tgs ? "krb_tgs_reply" : "krb_as_reply"] = std::move(out);
    return true;
}

bool kerberosError(Bytes element, Json& fields, Bytes* errorData = nullptr)
{
    Members error;
    Bytes stime, realm;
    int64_t version, type, microseconds, code;
    std::string service;
    if (!derSequence(element, error) || !error.integer(0, version) || version != 5 || !error.integer(1, type) ||
        type != 30 || !error.get(4, 0x18, stime) || !error.integer(5, microseconds) || !error.integer(6, code) ||
        code < INT32_MIN || code > INT32_MAX || !error.get(9, 0x1b, realm) ||
        (error.has(10) && !principal(error.item[10], service)))
        return false;
    Bytes text, data;
    if ((error.has(11) && !error.get(11, 0x1b, text)) || (error.has(12) && !error.get(12, 0x04, data)))
        return false;
    Json out{{"code", code}};
    if (const auto name = errorName(code))
        out["name"] = name;
    if (!service.empty())
        out["service_principal"] = service;

    // The error data depends on the error code, so a different encoding is ignored rather than rejected.
    Json names, supported = Json::array();
    if (!data.empty() && preauthentication(data, names, [&](int64_t kind, Bytes value)
        {
            if (kind != 11 && kind != 19)
                return true;
            Bytes list;
            if (!derOnly(value, 0x30, list))
                return false;
            while (!list.empty())
            {
                uint8_t tag;
                Bytes entry;
                Members item;
                int64_t etype;
                if (supported.size() == 32 || !derRead(list, tag, entry) || tag != 0x30 || !derMembers(entry, item) ||
                    !item.integer(0, etype) || etype < INT32_MIN || etype > INT32_MAX)
                    return false;
                const auto label = etypeName(etype);
                if (std::find(supported.begin(), supported.end(), label) == supported.end())
                    supported.push_back(label);
            }
            return true;
        }))
    {
        if (!names.empty())
            out["preauthentication"] = std::move(names);
        if (!supported.empty())
            out["supported_encryption_types"] = std::move(supported);
    }
    fields["krb_error"] = std::move(out);
    if (errorData)
        *errorData = data;
    return true;
}

bool apReply(Bytes element, int64_t& encryption)
{
    Bytes content;
    Members reply;
    int64_t version, type;
    return derOnly(element, 0x6f, content) && derSequence(content, reply) && reply.integer(0, version) &&
        version == 5 && reply.integer(1, type) && type == 15 && encryptedData(reply.item[2], encryption);
}

// KRB-PRIV protects the new password and the result code; only its encryption type is cleartext.
bool privateMessage(Bytes element, int64_t& encryption)
{
    Bytes content;
    Members message;
    int64_t version, type;
    return derOnly(element, 0x75, content) && derSequence(content, message) && message.integer(0, version) &&
        version == 5 && message.integer(1, type) && type == 21 && encryptedData(message.item[3], encryption);
}

const char* passwordResultName(uint16_t code)
{
    static constexpr const char* names[] = {"KRB5_KPASSWD_SUCCESS", "KRB5_KPASSWD_MALFORMED",
        "KRB5_KPASSWD_HARDERROR", "KRB5_KPASSWD_AUTHERROR", "KRB5_KPASSWD_SOFTERROR", "KRB5_KPASSWD_ACCESSDENIED",
        "KRB5_KPASSWD_BAD_VERSION", "KRB5_KPASSWD_INITIAL_FLAG_NEEDED"};
    return code < std::size(names) ? names[code] : nullptr;
}

constexpr uint8_t SpnegoOid[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
constexpr uint8_t IakerbOid[] = {0x2b, 0x06, 0x01, 0x05, 0x02, 0x05};
constexpr uint8_t KerberosOid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02};
constexpr uint8_t MicrosoftKerberosOid[] = {0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02};
constexpr uint8_t KerberosUserOid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03};
constexpr uint8_t NtlmOid[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};
constexpr uint8_t NegoExOid[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e};

template <size_t N>
bool sameOid(Bytes value, const uint8_t (&known)[N])
{
    return value.size() == N && std::equal(value.begin(), value.end(), known);
}

bool oidName(Bytes oid, std::string& name)
{
    if (oid.empty() || oid.size() > 32 || oid[0] >= 128)
        return false;
    if (sameOid(oid, SpnegoOid)) name = "SPNEGO";
    else if (sameOid(oid, IakerbOid)) name = "IAKerb";
    else if (sameOid(oid, KerberosOid)) name = "Kerberos";
    else if (sameOid(oid, MicrosoftKerberosOid)) name = "Microsoft Kerberos";
    else if (sameOid(oid, KerberosUserOid)) name = "Kerberos user-to-user";
    else if (sameOid(oid, NtlmOid)) name = "NTLM";
    else if (sameOid(oid, NegoExOid)) name = "NegoEx";
    else
    {
        // Unlisted mechanisms are reported by their dotted object identifier.
        name = std::format("{}.{}", oid[0] / 40 > 2 ? 2 : oid[0] / 40, oid[0] >= 80 ? oid[0] - 80 : oid[0] % 40);
        uint64_t arc = 0;
        for (size_t index = 1; index < oid.size(); ++index)
        {
            if (arc > (UINT64_MAX >> 7))
                return false;
            arc = (arc << 7) | (oid[index] & 0x7f);
            if (!(oid[index] & 0x80))
            {
                name += std::format(".{}", arc);
                arc = 0;
            }
            else if (index + 1 == oid.size() || (arc == 0 && oid[index] == 0x80))
                return false;
        }
    }
    return true;
}

bool mechanismList(Bytes element, Json& names)
{
    Bytes content;
    if (!derOnly(element, 0x30, content))
        return false;
    names = Json::array();
    while (!content.empty())
    {
        Bytes oid;
        std::string name;
        if (names.size() == 16 || !derExpect(content, 0x06, oid) || !oidName(oid, name))
            return false;
        names.push_back(std::move(name));
    }
    return !names.empty();
}

constexpr std::string_view NtlmSignature{"NTLMSSP\0", 8};

std::string hex32(uint32_t value)
{
    return std::format("0x{:08X}", value);
}

Json ntlmFlagNames(uint32_t flags)
{
    static constexpr std::pair<uint32_t, const char*> table[] = {
        {0x10, "Sign"}, {0x20, "Seal"}, {0x40, "Datagram"}, {0x80, "LM key"}, {0x200, "NTLM"},
        {0x800, "Anonymous"}, {0x8000, "Always sign"}, {0x80000, "Extended session security"},
        {0x100000, "Identify"}, {0x400000, "Non-NT session key"}, {0x800000, "Target info"},
        {0x20000000, "128-bit"}, {0x40000000, "Key exchange"}, {0x80000000, "56-bit"}};
    Json names = Json::array();
    for (const auto& [bit, name] : table)
        if (flags & bit)
            names.push_back(name);
    return names;
}

const char* attributeName(uint16_t id)
{
    switch (id)
    {
    case 1: return "NetBIOS computer name";
    case 2: return "NetBIOS domain name";
    case 3: return "DNS computer name";
    case 4: return "DNS domain name";
    case 5: return "DNS tree name";
    case 6: return "Flags";
    case 7: return "Timestamp";
    case 8: return "Single host";
    case 9: return "Target name";
    case 10: return "Channel bindings";
    default: return nullptr;
    }
}

struct Attributes
{
    Json names = Json::array();
    uint32_t flags{};
    bool channelBindings{};
};

// AV_PAIR lists end with MsvAvEOL; the NTLMv2 client challenge may be followed by up to four zero bytes.
bool avPairs(Bytes list, bool trailing, Attributes& result)
{
    for (size_t count = 0; count < 32; ++count)
    {
        if (list.size() < 4)
            return false;
        const auto id = little16(list, 0);
        const size_t length = little16(list, 2);
        if (length > list.size() - 4)
            return false;
        const auto value = list.subspan(4, length);
        list = list.subspan(4 + length);
        if (!id)
            return !length && (list.empty() || (trailing && list.size() <= 4 &&
                std::ranges::all_of(list, [](uint8_t byte) { return byte == 0; })));
        if ((id == 6 && length != 4) || (id == 7 && length != 8))
            return false;
        if (id == 6)
            result.flags = little32(value, 0);
        else if (id == 10)
            result.channelBindings = length == 16 &&
                std::ranges::any_of(value, [](uint8_t byte) { return byte != 0; });
        const auto name = attributeName(id);
        result.names.push_back(name ? std::string(name) : std::format("AV pair {}", id));
    }
    return false;
}

// A security buffer descriptor is length, maximum length, and an offset from the start of the message.
bool ntlmBuffer(Bytes message, size_t at, size_t minimum, Bytes& value)
{
    const size_t length = little16(message, at), offset = little32(message, at + 4);
    if (!length)
    {
        value = {};
        return true;
    }
    if (offset < minimum || offset > message.size() || length > message.size() - offset)
        return false;
    value = message.subspan(offset, length);
    return true;
}

bool allZero(Bytes value)
{
    return std::ranges::all_of(value, [](uint8_t byte) { return byte == 0; });
}

bool ntlmMessage(Bytes message, bool response, Json& found)
{
    if (message.size() < 16 || std::memcmp(message.data(), NtlmSignature.data(), 8) != 0)
        return false;
    const auto type = little32(message, 8);
    Bytes buffer;
    if (type == 1)
    {
        if (response)
            return false;
        const auto flags = little32(message, 12);

        // The domain and workstation descriptors are optional in very old clients.
        if (message.size() >= 32 &&
            (!ntlmBuffer(message, 16, 32, buffer) || !ntlmBuffer(message, 24, 32, buffer)))
            return false;
        found["ntlm_negotiate"] = {{"flags", hex32(flags)}, {"flag_names", ntlmFlagNames(flags)}};
        return true;
    }
    if (type == 2)
    {
        if (!response || message.size() < 48)
            return false;
        const auto flags = little32(message, 20);
        const size_t header = (flags & 0x02000000) ? 56 : 48;
        Attributes attributes;
        if (message.size() < header || !ntlmBuffer(message, 12, header, buffer) ||
            !ntlmBuffer(message, 40, header, buffer) || (!buffer.empty() && !avPairs(buffer, false, attributes)))
            return false;
        Json out{{"flags", hex32(flags)}, {"flag_names", ntlmFlagNames(flags)}};
        if (!attributes.names.empty())
            out["target_info_attributes"] = std::move(attributes.names);
        found["ntlm_challenge"] = std::move(out);
        return true;
    }
    if (type != 3 || response || message.size() < 64)
        return false;
    const auto flags = little32(message, 60);
    const size_t header = (flags & 0x02000000) ? 72 : 64;
    Bytes lm, nt, domain, user, workstation, sessionKey;
    if (message.size() < header || !ntlmBuffer(message, 12, header, lm) || !ntlmBuffer(message, 20, header, nt) ||
        !ntlmBuffer(message, 28, header, domain) || !ntlmBuffer(message, 36, header, user) ||
        !ntlmBuffer(message, 44, header, workstation) || !ntlmBuffer(message, 52, header, sessionKey))
        return false;

    // NTLMv2 responses carry a client-challenge structure whose AV pairs show MIC and channel binding use.
    Json out{{"flags", hex32(flags)}, {"flag_names", ntlmFlagNames(flags)}};
    Attributes attributes;
    const bool v2 = nt.size() >= 48 && nt[16] == 1 && nt[17] == 1;
    if (nt.empty())
        out["nt_response"] = "absent";
    else if (nt.size() == 24)
        out["nt_response"] = (flags & 0x80000) ? "NTLMv1 with extended session security" : "NTLMv1";
    else if (v2 && avPairs(nt.subspan(44), true, attributes))
    {
        out["nt_response"] = "NTLMv2";
        out["attributes"] = std::move(attributes.names);
    }
    else
        return false;
    if (lm.empty())
        out["lm_response"] = "absent";
    else if (allZero(lm))
        out["lm_response"] = "zero-filled";
    else if (lm.size() != 24)
        return false;
    else if (v2)
        out["lm_response"] = "LMv2";
    else if ((flags & 0x80000) && allZero(lm.subspan(8)))
        out["lm_response"] = "NTLM2 session client challenge";
    else
        out["lm_response"] = "LM";
    out["message_integrity_code"] = (attributes.flags & 2) != 0;
    out["channel_bindings"] = attributes.channelBindings;
    out["encrypted_session_key"] = !sessionKey.empty();
    out["anonymous"] = user.empty() && nt.empty();
    found["ntlm_authenticate"] = std::move(out);
    return true;
}

// A GSS-API Kerberos token is a two-byte token identifier followed by the DER message.
bool kerberosToken(Bytes content, bool response, Json& found)
{
    if (content.size() < 3)
        return false;
    const auto id = static_cast<uint16_t>((content[0] << 8) | content[1]);
    const auto message = content.subspan(2);
    if (id == 0x0100)
    {
        ApRequest ap;
        if (response || !apRequest(message, ap))
            return false;
        Json out{{"ticket_encryption", etypeName(ap.ticket.type)},
            {"authenticator_encryption", etypeName(ap.authenticator)},
            {"mutual_authentication_required", ap.mutual}, {"user_to_user", ap.userToUser}};
        if (!ap.ticket.service.empty())
            out["service_principal"] = ap.ticket.service;
        found["krb_ap_request"] = std::move(out);
        return true;
    }
    if (id == 0x0200)
    {
        int64_t encryption;
        if (!response || !apReply(message, encryption))
            return false;
        found["krb_ap_reply"] = {{"encryption", etypeName(encryption)}};
        return true;
    }
    return response && id == 0x0300 && message[0] == 0x7e && parseKerberos(message, found);
}

// Application tokens are either raw NTLMSSP or a GSS-API wrapped Kerberos token.
bool applicationToken(Bytes token, bool response, Json& found)
{
    if (token.size() >= 8 && std::memcmp(token.data(), NtlmSignature.data(), 8) == 0)
        return ntlmMessage(token, response, found);
    Bytes content, oid;
    return derOnly(token, 0x60, content) && derExpect(content, 0x06, oid) &&
        (sameOid(oid, KerberosOid) || sameOid(oid, MicrosoftKerberosOid)) && kerberosToken(content, response, found);
}

// An unrecognized or malformed inner token keeps the valid SPNEGO evidence and is flagged instead.
bool innerToken(const Members& members, bool response, Json& found)
{
    Bytes token;
    if (!members.has(2))
        return true;
    if (!members.get(2, 0x04, token))
        return false;
    if (!applicationToken(token, response, found))
        found["spnego_token_undecoded"] = true;
    return true;
}

bool negotiationToken(Bytes content, bool response, Json& found)
{
    const std::string side = response ? "spnego_server_" : "spnego_client_";
    uint8_t tag;
    Bytes value;
    Members members;
    if (!derRead(content, tag, value) || !content.empty() || !derSequence(value, members))
        return false;
    if (tag == 0xa0)
    {
        Json mechanisms;
        if (!members.has(0) || !mechanismList(members.item[0], mechanisms))
            return false;
        found[side + "mechanisms"] = std::move(mechanisms);
        return innerToken(members, response, found);
    }
    if (tag != 0xa1)
        return false;
    if (members.has(0))
    {
        Bytes state;
        static constexpr const char* names[] = {"accept-completed", "accept-incomplete", "reject", "request-mic"};
        if (!members.get(0, 0x0a, state) || state.size() != 1 || state[0] > 3)
            return false;
        found[side + "state"] = names[state[0]];
    }
    if (members.has(1))
    {
        Bytes oid;
        std::string name;
        if (!members.get(1, 0x06, oid) || !oidName(oid, name))
            return false;
        found[side + "selected_mechanism"] = std::move(name);
    }
    if (members.has(3))
    {
        Bytes mic;
        if (!members.get(3, 0x04, mic))
            return false;
        found[side + "mech_list_mic"] = true;
    }
    return innerToken(members, response, found);
}

bool securityToken(Bytes buffer, bool response, Json& found)
{
    if (buffer.size() >= 8 && std::memcmp(buffer.data(), NtlmSignature.data(), 8) == 0)
        return ntlmMessage(buffer, response, found);
    Bytes content, oid;
    if (buffer[0] == 0xa1)
    {
        // Later SPNEGO messages omit the GSS-API wrapper.
        return negotiationToken(buffer, response, found);
    }
    if (!derOnly(buffer, 0x60, content) || !derExpect(content, 0x06, oid))
        return false;
    if (sameOid(oid, SpnegoOid))
        return negotiationToken(content, response, found);
    return (sameOid(oid, KerberosOid) || sameOid(oid, MicrosoftKerberosOid)) && kerberosToken(content, response, found);
}
}

size_t kerberosMessageSize(Bytes prefix, bool* incomplete)
{
    if (prefix.size() < 2 || !isKerberosTag(prefix[0]))
        return 0;
    size_t length = prefix[1], header = 2;
    if (length & 0x80)
    {
        // Three length bytes describe messages beyond 64 KiB; the caller bounds the total it will buffer.
        const size_t count = length & 0x7f;
        if (!count || count > 3)
            return 0;
        if (prefix.size() < 2 + count)
        {
            if (incomplete)
                *incomplete = true;
            return 0;
        }
        if (!prefix[2])
            return 0;
        length = 0;
        for (size_t index = 0; index < count; ++index)
            length = (length << 8) | prefix[2 + index];
        if (length < 128)
            return 0;
        header += count;
    }
    return header + length;
}

bool parseKerberos(Bytes message, nlohmann::json& fields)
{
    Bytes remaining = message, value;
    uint8_t tag;
    if (!derRead(remaining, tag, value) || !remaining.empty() || !isKerberosTag(tag))
        return false;
    Json found = Json::object();
    const bool valid = tag == 0x6a ? kdcRequest(value, false, found) : tag == 0x6c ? kdcRequest(value, true, found) :
        tag == 0x6b ? kdcReply(value, false, found) : tag == 0x6d ? kdcReply(value, true, found) :
        kerberosError(value, found);
    if (valid)
        fields.update(found);
    return valid;
}

size_t passwordMessageSize(Bytes prefix, bool* incomplete)
{
    // The header is the message length, the protocol version, and the length of the AP-REQ or AP-REP.
    if (prefix.size() < 4)
        return 0;
    const size_t length = be16(prefix, 0), version = be16(prefix, 2);
    if (length < 8 || (version != 1 && version != 0xff80))
        return 0;
    if (prefix.size() < 7)
    {
        if (incomplete)
            *incomplete = true;
        return 0;
    }

    // A reply without an AP-REP carries a KRB-ERROR instead of a KRB-PRIV.
    const size_t exchange = be16(prefix, 4);
    if (exchange > length - 7 || (exchange ? prefix[6] != 0x6e && prefix[6] != 0x6f : prefix[6] != 0x7e))
        return 0;
    return length;
}

bool parsePasswordChange(Bytes message, nlohmann::json& fields)
{
    if (message.size() < 8 || passwordMessageSize(message) != message.size())
        return false;
    const auto exchange = message.subspan(6, be16(message, 4));
    const auto protectedPart = message.subspan(6 + exchange.size());
    Json found = Json::object();
    int64_t encryption;
    if (!exchange.empty() && exchange[0] == 0x6e)
    {
        // Version 1 changes the caller's own password; 0xff80 also lets an administrator set another principal's.
        ApRequest ap;
        if (!apRequest(exchange, ap) || !privateMessage(protectedPart, encryption))
            return false;
        Json out{{"operation", be16(message, 2) == 1 ? "Change password" : "Set or change password"},
            {"ticket_encryption", etypeName(ap.ticket.type)},
            {"authenticator_encryption", etypeName(ap.authenticator)},
            {"private_message_encryption", etypeName(encryption)}};
        if (!ap.ticket.service.empty())
            out["service_principal"] = ap.ticket.service;
        found["krb_password_request"] = std::move(out);
    }
    else if (!exchange.empty())
    {
        int64_t reply;
        if (!apReply(exchange, reply) || !privateMessage(protectedPart, encryption))
            return false;
        found["krb_password_reply"] = {{"reply_encryption", etypeName(reply)},
            {"private_message_encryption", etypeName(encryption)}};
    }
    else
    {
        // An unauthenticated failure states its result code in clear; the accompanying text is not retained.
        Bytes remaining = protectedPart, value, data;
        uint8_t tag;
        if (!derRead(remaining, tag, value) || !remaining.empty() || tag != 0x7e || !kerberosError(value, found, &data))
            return false;
        Json out = Json::object();
        if (data.size() >= 2)
        {
            const auto code = be16(data, 0);
            out["result_code"] = code;
            if (const auto name = passwordResultName(code))
                out["result"] = name;
        }
        found["krb_password_reply"] = std::move(out);
    }
    fields.update(found);
    return true;
}

void parseSecurityBuffer(Bytes buffer, bool response, nlohmann::json& fields)
{
    if (buffer.empty())
        return;
    Json found = Json::object();
    if (securityToken(buffer, response, found))
        fields.update(found);
    else
        fields["spnego_token_undecoded"] = true;
}
}
