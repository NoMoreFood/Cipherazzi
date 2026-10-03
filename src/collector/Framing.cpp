#include "Framing.h"
#include "Auth.h"
#include "Rpc.h"
#include "SmbPipe.h"
#include "Vpn.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <string_view>
#include <windows.h>

namespace Cipherazzi
{
namespace FramingDetail
{
constexpr size_t FramingLimit = 262144;
constexpr char NoResponse[] = "not a challenge response";

bool rdp(Bytes bytes, nlohmann::json& fields)
{
    if (bytes.size() < 11 || bytes[0] != 3 || bytes[1] || bytes[4] + 5u != bytes.size() || bytes[10] ||
        (bytes[5] != 0xe0 && bytes[5] != 0xd0))
        return false;
    const bool request = bytes[5] == 0xe0;
    auto payload = bytes.subspan(11);

    // A routing token or cookie precedes negotiation; retain its presence without storing its identifier.
    if (request && !payload.empty() && payload[0] != 1)
    {
        size_t end = 0;
        while (end + 1 < payload.size() && !(payload[end] == '\r' && payload[end + 1] == '\n'))
        {
            if (payload[end] < 32 || payload[end] > 126)
                return false;
            ++end;
        }
        if (end + 1 == payload.size())
            return false;
        fields["rdp_routing_cookie_observed"] = true;
        payload = payload.subspan(end + 2);
    }
    fields[request ? "rdp_x224_request_observed" : "rdp_x224_response_observed"] = true;
    fields[request ? "rdp_request_negotiation_observed" : "rdp_response_negotiation_observed"] = !payload.empty();
    if (payload.empty())
        return true;
    if (payload.size() < 8 || little16(payload, 2) != 8 ||
        (request ? payload[0] != 1 : payload[0] != 2 && payload[0] != 3))
        return false;
    const auto type = payload[0], flags = payload[1];
    fields[type == 1 ? "rdp_requested_protocols" : type == 2 ? "rdp_selected_protocol" : "rdp_failure_code"] =
        little32(payload, 4);
    if (type == 3 && flags)
        return false;
    fields[request ? "rdp_request_flags" : "rdp_response_flags"] = flags;
    if (type != 3)
    {
        fields[request ? "rdp_restricted_admin_required" : "rdp_restricted_admin_supported"] =
            (flags & (request ? 1 : 8)) != 0;
        fields[request ? "rdp_credential_guard_required" : "rdp_credential_guard_supported"] =
            (flags & (request ? 2 : 16)) != 0;
        if (!request)
        {
            fields["rdp_extended_client_data_supported"] = (flags & 1) != 0;
            fields["rdp_graphics_protocol_supported"] = (flags & 2) != 0;
        }
    }
    payload = payload.subspan(8);
    if (!request || !(flags & 8))
        return payload.empty();

    // The correlation structure follows the request rather than replacing its trailing negotiation fields.
    if (payload.size() != 36 || payload[0] != 6 || payload[1] || little16(payload, 2) != 36 ||
        std::any_of(payload.begin() + 20, payload.end(), [](uint8_t value) { return value != 0; }))
        return false;
    fields["rdp_correlation_id"] = hex(payload.subspan(4, 16));
    return true;
}

// Standard RDP Security announces its encryption choice in the cleartext MCS Connect PDUs (MS-RDPBCGR 2.2.1.3-4).
bool berValue(Bytes& bytes, uint8_t tag, Bytes& value)
{
    if (bytes.size() < 2 || bytes[0] != tag)
        return false;
    size_t length = bytes[1], offset = 2;
    if (length & 0x80)
    {
        const size_t count = length & 0x7f;
        if (!count || count > 2 || bytes.size() < offset + count)
            return false;
        length = 0;
        for (size_t index = 0; index < count; ++index)
            length = (length << 8) | bytes[offset++];
    }
    if (length > bytes.size() - offset)
        return false;
    value = bytes.subspan(offset, length);
    bytes = bytes.subspan(offset + length);
    return true;
}

bool perLength(Bytes& bytes, size_t& length)
{
    if (bytes.empty() || (bytes[0] & 0xc0) == 0xc0)
        return false;
    if (!(bytes[0] & 0x80))
    {
        length = bytes[0];
        bytes = bytes.subspan(1);
        return true;
    }
    if (bytes.size() < 2)
        return false;
    length = (static_cast<size_t>(bytes[0] & 0x3f) << 8) | bytes[1];
    bytes = bytes.subspan(2);
    return true;
}

// The certificate is public key metadata only; its signature and chain are not verified.
void rdpServerCertificate(Bytes certificate, nlohmann::json& fields)
{
    // Distinguish proprietary RDP public keys from X.509 certificate chains.
    if (certificate.size() < 4)
        return;
    const auto version = little32(certificate, 0) & 0x7fffffffu;
    if (version == 1)
    {
        if (certificate.size() < 36 || little32(certificate, 4) != 1 || little32(certificate, 8) != 1 ||
            little16(certificate, 12) != 6)
            return;
        const size_t blob = little16(certificate, 14);
        if (blob < 20 || blob > certificate.size() - 16 ||
            std::string_view(reinterpret_cast<const char*>(certificate.data()) + 16, 4) != "RSA1")
            return;
        const uint64_t keyLength = little32(certificate, 20), bits = little32(certificate, 24);
        if (keyLength != blob - 20 || !bits || bits > keyLength * 8)
            return;
        fields["rdp_server_certificate_type"] = "Proprietary";
        fields["rdp_server_key_bits"] = bits;
    }
    else if (version == 2)
    {
        if (certificate.size() < 8)
            return;
        const auto count = little32(certificate, 4);
        size_t offset = 8;
        if (!count || count > 32)
            return;
        for (uint32_t index = 0; index < count; ++index)
        {
            if (certificate.size() - offset < 4)
                return;
            const size_t size = little32(certificate, offset);
            offset += 4;
            if (size > certificate.size() - offset)
                return;
            offset += size;
        }
        fields["rdp_server_certificate_type"] = "X.509 chain";
        fields["rdp_server_certificate_count"] = count;
    }
}

bool rdpMcs(Bytes bytes, bool request, nlohmann::json& fields)
{
    // The X.224 data header precedes the BER-encoded Connect-Initial or Connect-Response.
    const uint8_t tag = request ? 0x65 : 0x66;
    if (bytes.size() < 10 || bytes[0] != 3 || bytes[1] || bytes[4] != 2 || bytes[5] != 0xf0 || bytes[6] != 0x80 ||
        bytes[7] != 0x7f || bytes[8] != tag)
        return false;
    auto outer = bytes.subspan(8);
    Bytes content, value, userData;
    if (!berValue(outer, tag, content) || !outer.empty())
        return false;
    if (request)
    {
        if (!berValue(content, 4, value) || !berValue(content, 4, value) || !berValue(content, 1, value) ||
            value.size() != 1 || !berValue(content, 0x30, value) || !berValue(content, 0x30, value) ||
            !berValue(content, 0x30, value) || !berValue(content, 4, userData) || !content.empty())
            return false;
    }
    else
    {
        Bytes result;
        if (!berValue(content, 0x0a, result) || result.size() != 1 || !berValue(content, 2, value) ||
            !berValue(content, 0x30, value) || !berValue(content, 4, userData) || !content.empty())
            return false;
        if (result[0])
        {
            fields["rdp_mcs_connect_response_observed"] = true;
            return true;
        }
    }
    fields[request ? "rdp_mcs_connect_request_observed" : "rdp_mcs_connect_response_observed"] = true;

    // Servers disagree about the connectPDU length, so only the block length bounds the user data.
    constexpr std::array<uint8_t, 7> gcc{0, 5, 0, 0x14, 0x7c, 0, 1};
    size_t length{};
    if (userData.size() < gcc.size() || !std::equal(gcc.begin(), gcc.end(), userData.begin()))
        return true;
    userData = userData.subspan(gcc.size());
    if (!perLength(userData, length))
        return false;
    if (request)
    {
        constexpr std::array<uint8_t, 12> header{0, 8, 0, 0x10, 0, 1, 0xc0, 0, 'D', 'u', 'c', 'a'};
        if (userData.size() < header.size() || !std::equal(header.begin(), header.end(), userData.begin()))
            return true;
        userData = userData.subspan(header.size());
    }
    else
    {
        if (userData.size() < 13 || userData[0] != 0x14 || userData[3] != 1 || userData[5] || userData[6] != 1 ||
            userData[7] != 0xc0 || userData[8] ||
            std::string_view(reinterpret_cast<const char*>(userData.data()) + 9, 4) != "McDn")
            return true;
        userData = userData.subspan(13);
    }
    if (!perLength(userData, length) || length > userData.size())
        return false;
    auto blocks = userData.first(length);

    bool seen = false;
    while (!blocks.empty())
    {
        if (blocks.size() < 4)
            return false;
        const size_t type = little16(blocks, 0), size = little16(blocks, 2);
        if (size < 4 || size > blocks.size())
            return false;
        const auto block = blocks.first(size);
        blocks = blocks.subspan(size);
        if (type != (request ? 0xc002u : 0x0c02u))
            continue;
        if (seen)
            return false;
        seen = true;
        if (request)
        {
            if (size != 8 && size != 12)
                return false;
            const auto methods = little32(block, 4);
            nlohmann::json names = nlohmann::json::array();
            for (const auto& [flag, name] : {std::pair{0x01u, "RC4 40-bit"}, {0x02u, "RC4 128-bit"},
                {0x08u, "RC4 56-bit"}, {0x10u, "FIPS 3DES"}})
                if (methods & flag)
                    names.push_back(name);
            if (methods & ~0x1bu)
                names.push_back(hex32(methods & ~0x1bu));
            fields["rdp_client_encryption_methods"] = std::move(names);
            continue;
        }
        if (size < 12)
            return false;
        const auto method = little32(block, 4), level = little32(block, 8);
        const uint32_t methods[]{0, 1, 2, 8, 0x10};
        const char* const methodNames[]{"None", "RC4 40-bit", "RC4 128-bit", "RC4 56-bit", "FIPS 3DES"};
        const char* const levelNames[]{"None", "Low", "Client compatible", "High", "FIPS"};
        const auto found = std::find(std::begin(methods), std::end(methods), method);
        fields["rdp_server_encryption_method"] = found == std::end(methods) ? hex32(method) :
            methodNames[found - std::begin(methods)];
        fields["rdp_server_encryption_level"] = level < 5 ? std::string(levelNames[level]) : hex32(level);

        // Enhanced security reports no encryption and carries neither a server random nor a certificate.
        if (!method && !level)
        {
            if (size != 12)
                return false;
            continue;
        }
        if (size < 52 || little32(block, 12) != 32 || little32(block, 16) != size - 52)
            return false;
        rdpServerCertificate(block.subspan(52), fields);
    }
    return true;
}

bool rdpSecurityExchange(Bytes bytes, nlohmann::json& fields)
{
    if (bytes.size() < 8 || bytes[0] != 3 || bytes[1] || be16(bytes, 2) != bytes.size() ||
        bytes[4] != 2 || bytes[5] != 0xf0 || bytes[6] != 0x80)
        return false;
    if (bytes[7] != 0x64)
        return true;
    if (bytes.size() < 14)
        return false;
    auto userData = bytes.subspan(13);
    size_t length{};
    if (!perLength(userData, length) || length != userData.size() || length < 4)
        return false;
    const auto flags = little16(userData, 0);
    if (!(flags & 1))
        return true;

    // The client random is RSA encrypted; only the public packet shape and ciphertext length are retained.
    if (userData.size() < 48 || little16(userData, 2) || little32(userData, 4) != userData.size() - 8 ||
        std::any_of(userData.end() - 8, userData.end(), [](uint8_t byte) { return byte != 0; }))
        return false;
    fields["rdp_client_security_exchange_observed"] = true;
    fields["rdp_encrypted_client_random_bytes"] = userData.size() - 16;
    fields["rdp_key_exchange"] = "RSA encrypted client random";
    return true;
}

bool tdsPrelogin(Bytes bytes, nlohmann::json& fields)
{
    if (bytes.empty() || bytes[0] != 0)
        return false;

    // Validate the entire option table before exposing public negotiation values.
    struct Option { uint8_t token; size_t offset, length; };
    std::vector<Option> options;
    size_t position = 0;
    while (position < bytes.size() && bytes[position] != 0xff)
    {
        if (bytes.size() - position < 5 || options.size() >= 64 ||
            std::ranges::any_of(options, [&](const auto& option) { return option.token == bytes[position]; }))
            return false;
        options.push_back({bytes[position], be16(bytes, position + 1), be16(bytes, position + 3)});
        position += 5;
    }
    if (position == bytes.size())
        return false;
    ++position;
    for (size_t index = 0; index < options.size(); ++index)
    {
        const auto& option = options[index];
        if (option.offset < position || option.offset > bytes.size() || option.length > bytes.size() - option.offset)
            return false;
        for (size_t previous = 0; previous < index; ++previous)
            if (option.length && options[previous].length &&
                option.offset < options[previous].offset + options[previous].length &&
                options[previous].offset < option.offset + option.length)
                return false;
        const auto value = bytes.subspan(option.offset, option.length);
        if (option.token == 0)
        {
            if (value.size() != 6)
                return false;
            fields["product_version"] = std::to_string(value[0]) + "." + std::to_string(value[1]) + "." +
                std::to_string(be16(value, 2)) + "." + std::to_string(be16(value, 4));
        }
        else if (option.token == 1)
        {
            if (value.size() != 1)
                return false;
            fields["encryption"] = value[0];
            fields["client_certificate_requested"] = (value[0] & 0x80) != 0;
        }
        else if (option.token == 4 || option.token == 6)
        {
            if (value.size() != 1 || value[0] > 1)
                return false;
            fields[option.token == 4 ? "mars_enabled" : "federated_auth_required"] = value[0] != 0;
        }
    }
    return true;
}

bool tdsLogin7(Bytes bytes, nlohmann::json& fields)
{
    // LOGIN7 keeps variable fields at offsets from the start of the login stream. Only the SSPI token is read;
    // user names and obfuscated SQL passwords are never retained.
    if (bytes.size() < 82 || little32(bytes, 0) != bytes.size())
        return false;
    const bool integrated = (bytes[25] & 0x80) != 0;
    size_t sspiLength = little16(bytes, 80);
    if (sspiLength == 0xffff && bytes.size() >= 94 && little32(bytes, 90))
        sspiLength = little32(bytes, 90);
    const size_t sspiOffset = little16(bytes, 78);
    if (sspiLength && (sspiOffset < 82 || sspiOffset > bytes.size() ||
        sspiLength > bytes.size() - sspiOffset))
        return false;
    fields["tds_unencrypted_login_observed"] = true;
    fields["tds_login_integrated_security"] = integrated;
    if (sspiLength)
    {
        fields["tds_login_sspi_observed"] = true;
        parseSecurityBuffer(bytes.subspan(sspiOffset, sspiLength), false, fields);
    }
    return true;
}

bool tdsLoginResponseToken(uint8_t type)
{
    return type == 0xe3 || type == 0xaa || type == 0xab || type == 0xad || type == 0xed;
}

bool tdsSspiResponse(Bytes bytes, nlohmann::json& fields, bool& observed)
{
    // Login response tokens with a USHORT length may precede the server's SSPI token.
    observed = false;
    for (size_t count = 0; count < 16 && !bytes.empty(); ++count)
    {
        if (!tdsLoginResponseToken(bytes[0]))
            return true;
        if (bytes.size() < 3)
            return false;
        const size_t length = little16(bytes, 1);
        if (!length || length > bytes.size() - 3)
            return false;
        if (bytes[0] == 0xed)
        {
            parseSecurityBuffer(bytes.subspan(3, length), true, fields);
            observed = true;
            return true;
        }
        bytes = bytes.subspan(3 + length);
    }
    return true;
}

}
using namespace FramingDetail;

void resolveNegotiation(nlohmann::json& fields)
{
    // An SMB1 reply selects a dialect by its position in the client's offer.
    fields.erase("smb_legacy_selected_dialect");
    if (fields.contains("smb_legacy_offered_dialects") && fields.contains("smb_legacy_selected_dialect_index"))
    {
        const auto& offered = fields["smb_legacy_offered_dialects"];
        const auto index = fields["smb_legacy_selected_dialect_index"].get<size_t>();
        if (index < offered.size())
            fields["smb_legacy_selected_dialect"] = offered[index].get<std::string>();
    }

    // SMB1 password fields hold challenge responses only when the server negotiated them and they have that form.
    for (const auto* outcome : {"smb_legacy_nt_response", "smb_legacy_lm_response", "smb_legacy_plaintext_password",
        "smb_legacy_anonymous_session"})
        fields.erase(outcome);
    if (const auto setup = fields.find("smb_legacy_session_setup"); setup != fields.end())
    {
        const auto lm = setup->value("case_insensitive_form", "absent");
        const auto nt = setup->value("case_sensitive_form", "absent");
        const bool supplied = lm != "absent" || nt != "absent", named = setup->value("account_named", true);
        if (supplied && (!fields.value("smb_legacy_encrypted_passwords", true) || lm == NoResponse || nt == NoResponse))
            fields["smb_legacy_plaintext_password"] = true;
        else if (supplied)
        {
            fields["smb_legacy_nt_response"] = nt;
            fields["smb_legacy_lm_response"] = lm;
        }
        else if (!named)
            fields["smb_legacy_anonymous_session"] = true;
    }

    // An LDAP session is protected only by a SASL security layer, which shows in how the messages after an accepted
    // bind are framed. An anonymous bind establishes no session to assess.
    fields.erase("ldap_session_protection");
    const auto request = fields.find("ldap_bind_request"), response = fields.find("ldap_bind_response");
    const auto later = fields.value("ldap_messages_after_bind", "");
    if (request != fields.end() && response != fields.end() && !later.empty() &&
        response->value("result_code", -1) == 0 && request->value("form", "Password") == "Password")
        fields["ldap_session_protection"] = later == "Plain" ? "None" : later;

    // Either TDS peer can turn encryption on; one without support leaves even the login unencrypted (MS-TDS 2.2.6.5).
    fields.erase("tds_negotiated_encryption");
    if (!fields.contains("tds_client_prelogin") || !fields.contains("tds_server_prelogin") ||
        !fields["tds_client_prelogin"].contains("encryption") || !fields["tds_server_prelogin"].contains("encryption"))
        return;
    const auto client = fields["tds_client_prelogin"]["encryption"].get<unsigned>() & 0x7f;
    const auto server = fields["tds_server_prelogin"]["encryption"].get<unsigned>() & 0x7f;
    if (client > 3 || server > 3)
        return;
    const bool unsupported = client == 2 || server == 2, wanted = ((client | server) & 1) != 0;
    fields["tds_negotiated_encryption"] = unsupported ? wanted ? "Incompatible settings" : "None" :
        wanted ? "Entire session" : "Login only";
}

bool FramedStream::feed(Bytes bytes, const Sink& sink)
{
    auto databaseSink = [&](Bytes payload, const nlohmann::json& fields, bool tls)
    {
        return sink({tls ? FramedMessage::Kind::Tls :
            databaseState_->kind == DatabaseNegotiation::Kind::PostgreSql ? FramedMessage::Kind::PostgreSql :
            FramedMessage::Kind::MySql, payload, fields});
    };
    if (database_)
        return database_->feed(bytes, databaseSink);
    if (iwarp_)
        return iwarp_->feed(
            bytes, [&](const nlohmann::json& fields) { return sink({FramedMessage::Kind::Smb, {}, fields}); });
    const auto httpSink = [&](const nlohmann::json& fields) { return sink({FramedMessage::Kind::Http, {}, fields}); };
    if (http2_)
        return http2_->feed(bytes, httpSink);
    if (mode_ == Mode::Finished || (http_ && http_->upgrade == HttpState::Upgrade::Other))
        return true;
    if (http_ && http_->upgrade == HttpState::Upgrade::Tunnel && mode_ == Mode::Text)
        mode_ = Mode::Direct;
    if (mode_ == Mode::Direct)
        return sink({FramedMessage::Kind::Tls, bytes, {}});
    if (bytes.size() > FramingLimit - buffer_.size() - tdsMessage_.size())
    {
        limited_ = true;
        return false;
    }
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());

    // The client preface or an accepted h2c upgrade establishes binary HTTP framing in both directions.
    if (http_ && (mode_ == Mode::Probe || (mode_ == Mode::Text && textProtocol_ == CleartextProtocol::Http &&
            !textBodyRemaining_ && !textChunked_)))
    {
        constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const std::string_view prefix(reinterpret_cast<const char*>(buffer_.data()),
            std::min(buffer_.size(), preface.size()));
        if (http_->http2Client < 0 && !prefix.empty() && preface.starts_with(prefix))
        {
            if (buffer_.size() < preface.size())
                return true;
            http_->http2Client = httpDirection_;
        }
        if (http_->http2Client >= 0)
        {
            http2_ = std::make_unique<Http2Stream>(*http_, httpDirection_);
            const bool valid = http2_->feed(buffer_, httpSink);
            std::vector<uint8_t>().swap(buffer_);
            return valid;
        }
        if (mode_ == Mode::Probe && buffer_.size() >= 9 && buffer_[3] == 4 && !(buffer_[4] & 1) &&
            !(buffer_[5] & 127) && !buffer_[6] && !buffer_[7] && !buffer_[8])
            return true;
    }

    // Database startup identifies the peer framing before switching both directions into TLS.
    if (mode_ == Mode::Probe && databaseState_)
    {
        const auto kind = DatabaseStream::recognizes(buffer_);
        if (databaseState_->kind == DatabaseNegotiation::Kind::None && kind != DatabaseNegotiation::Kind::None)
        {
            databaseState_->kind = kind;
            databaseState_->client = kind == DatabaseNegotiation::Kind::PostgreSql ?
                databaseDirection_ : 1 - databaseDirection_;
        }
        if (databaseState_->kind != DatabaseNegotiation::Kind::None)
        {
            database_ = std::make_unique<DatabaseStream>(*databaseState_, databaseDirection_);
            const bool valid = database_->feed(buffer_, databaseSink);
            std::vector<uint8_t>().swap(buffer_);
            return valid;
        }
    }

    // iWARP negotiation identifies an RDMA stream before SMB Direct's first Send message.
    if (mode_ == Mode::Probe && !buffer_.empty() && buffer_[0] == 'M')
    {
        constexpr std::string_view request = "MPA ID Req Frame", response = "MPA ID Rep Frame";
        const std::string_view prefix(reinterpret_cast<const char*>(buffer_.data()),
            std::min(size_t{16}, buffer_.size()));
        if (request.starts_with(prefix) || response.starts_with(prefix))
        {
            if (buffer_.size() < 20)
                return true;
            iwarp_ = std::make_unique<IwarpStream>();
            const bool valid = iwarp_->feed(
                buffer_, [&](const nlohmann::json& fields) { return sink({FramedMessage::Kind::Smb, {}, fields}); });
            std::vector<uint8_t>().swap(buffer_);
            return valid;
        }
    }
    const bool textPrefix = !buffer_.empty() &&
        (std::isalpha(buffer_[0]) || buffer_[0] == '+' || buffer_[0] == '*' ||
            (buffer_[0] >= '2' && buffer_[0] <= '5'));
    const bool tlsPrefix = buffer_.size() >= 3 && buffer_[0] >= 20 && buffer_[0] <= 23 && buffer_[1] == 3;
    if (mode_ == Mode::Probe && databaseState_ && buffer_.size() < 8 && !tlsPrefix)
        return true;
    if (mode_ == Mode::Probe && !buffer_.empty() && buffer_[0] != 0 && buffer_[0] != 3 &&
        buffer_[0] != 4 && buffer_[0] != 5 && buffer_[0] != 0x10 && buffer_[0] != 0x12 &&
        buffer_[0] != 0x30 &&
        !textPrefix && !(buffer_[0] >= 0x81 && buffer_[0] <= 0x85))
    {
        mode_ = Mode::Direct;
        const bool valid = sink({FramedMessage::Kind::Tls, buffer_, {}});
        std::vector<uint8_t>().swap(buffer_);
        return valid;
    }
    size_t consumed = 0;
    while (buffer_.size() - consumed >= (mode_ == Mode::Text ? 1u : 4u))
    {
        auto pending = Bytes(buffer_).subspan(consumed);
        if (mode_ == Mode::Text)
        {
            // The same connection can upgrade to TLS after a text protocol's STARTTLS command.
            if (!textBodyRemaining_ && !textChunked_ && !textAuthStep_ && pending.size() >= 2 &&
                ((pending[0] >= 20 && pending[0] <= 23 && pending[1] == 3) || (pending[0] & 0x80)))
            {
                mode_ = Mode::Direct;
                const bool valid = sink({FramedMessage::Kind::Tls, pending, {}});
                std::vector<uint8_t>().swap(buffer_);
                return valid;
            }
            if (textBodyRemaining_)
            {
                const size_t size = std::min(textBodyRemaining_, pending.size());
                textBodyRemaining_ -= size;
                consumed += size;
                continue;
            }
            if (textChunked_)
            {
                if (textChunkRemaining_)
                {
                    const size_t size = std::min(textChunkRemaining_, pending.size());
                    textChunkRemaining_ -= size;
                    consumed += size;
                    if (!textChunkRemaining_)
                        textChunkCrLf_ = true;
                    continue;
                }
                if (textChunkCrLf_)
                {
                    if (pending.size() < 2)
                        break;
                    if (pending[0] != '\r' || pending[1] != '\n')
                        return false;
                    consumed += 2;
                    textChunkCrLf_ = false;
                    continue;
                }
                constexpr std::array<uint8_t, 2> endOfLine{'\r', '\n'};
                const auto end = std::search(pending.begin(), pending.end(), endOfLine.begin(), endOfLine.end());
                if (end == pending.end())
                {
                    if (pending.size() > 8192)
                        return false;
                    break;
                }
                const size_t lineSize = end - pending.begin();
                if (textChunkLast_)
                {
                    consumed += lineSize + 2;
                    if (!lineSize)
                        textChunked_ = textChunkLast_ = false;
                    continue;
                }
                const auto line = std::string_view(reinterpret_cast<const char*>(pending.data()), lineSize);
                const auto extension = line.find(';');
                size_t size{};
                const auto result = std::from_chars(line.data(), line.data() +
                    (extension == std::string_view::npos ? line.size() : extension), size, 16);
                if (result.ec != std::errc{} || result.ptr != line.data() +
                    (extension == std::string_view::npos ? line.size() : extension))
                    return false;
                consumed += lineSize + 2;
                textChunkRemaining_ = size;
                textChunkLast_ = !size;
                continue;
            }
            FramedMessage message;
            if (textProtocol_ == CleartextProtocol::Http)
            {
                constexpr std::array<uint8_t, 4> endOfHeaders{'\r', '\n', '\r', '\n'};
                const auto end = std::search(pending.begin(), pending.end(), endOfHeaders.begin(),
                    endOfHeaders.end());
                if (end == pending.end())
                {
                    if (pending.size() > 32768)
                    {
                        limited_ = true;
                        return false;
                    }
                    break;
                }
                const size_t size = end - pending.begin() + endOfHeaders.size();
                if (size > 32768)
                {
                    limited_ = true;
                    return false;
                }
                const std::string_view header(reinterpret_cast<const char*>(pending.data()), size);
                const bool response = header.starts_with("HTTP/1.");
                const auto request = response && http_ && !http_->requests.empty() ?
                    http_->requests.front() : HttpMethod::Other;
                bool closeDelimited = false;
                if (!parseHttpHeaders(pending.first(size), message.fields, textBodyRemaining_, textChunked_,
                    closeDelimited, request, http_))
                    return false;
                message.kind = FramedMessage::Kind::Http;
                consumed += size;

                // Pair response framing with the request; a successful CONNECT transfers both streams to TLS.
                const bool tunnel = response && request == HttpMethod::Connect && header[9] == '2';
                if (response && header[9] >= '2' && http_ && !http_->requests.empty())
                    http_->requests.erase(http_->requests.begin());
                else if (!response && http_)
                {
                    if (http_->requests.size() >= 64)
                    {
                        limited_ = true;
                        return false;
                    }
                    http_->requests.push_back(header.starts_with("CONNECT ") ? HttpMethod::Connect :
                        header.starts_with("HEAD ") ? HttpMethod::Head : HttpMethod::Other);
                }
                if (tunnel)
                {
                    message.fields["http_tunnel_established"] = true;
                    http_->upgrade = HttpState::Upgrade::Tunnel;
                    if (!sink(message))
                        return false;
                    mode_ = Mode::Direct;
                    const bool valid = consumed == buffer_.size() ||
                        sink({FramedMessage::Kind::Tls, Bytes(buffer_).subspan(consumed), {}});
                    std::vector<uint8_t>().swap(buffer_);
                    return valid;
                }
                if (message.fields.value("http_upgrade_observed", false))
                {
                    if (http_ && message.fields.value("http_upgrade_protocol", "") == "h2c")
                    {
                        http_->http2Client = 1 - httpDirection_;
                        http_->requests.clear();
                        if (http_->upgradeSettings)
                            http_->settings[httpDirection_] = *http_->upgradeSettings;
                        http2_ = std::make_unique<Http2Stream>(*http_, httpDirection_);
                        const bool valid = sink(message) &&
                            http2_->feed(Bytes(buffer_).subspan(consumed), httpSink);
                        std::vector<uint8_t>().swap(buffer_);
                        return valid;
                    }
                    if (http_)
                        http_->upgrade = HttpState::Upgrade::Other;
                    mode_ = Mode::Finished;
                }
                else if (closeDelimited)
                    mode_ = Mode::Finished;
            }
            else
            {
                constexpr std::array<uint8_t, 2> endOfLine{'\r', '\n'};
                const auto end = std::search(pending.begin(), pending.end(), endOfLine.begin(), endOfLine.end());
                if (end == pending.end())
                {
                    if (pending.size() > 8192)
                    {
                        limited_ = true;
                        return false;
                    }
                    break;
                }
                const size_t size = end - pending.begin();
                if (!parseMailLine(pending.first(size), textProtocol_, textAuthStep_, message.fields))
                    return false;
                message.kind = textProtocol_ == CleartextProtocol::Smtp ? FramedMessage::Kind::Smtp :
                    textProtocol_ == CleartextProtocol::Imap ? FramedMessage::Kind::Imap :
                    textProtocol_ == CleartextProtocol::Pop3 ? FramedMessage::Kind::Pop3 :
                    FramedMessage::Kind::Ftp;
                if (textProtocol_ == CleartextProtocol::Smtp && size == 4 &&
                    std::toupper(pending[0]) == 'D' && std::toupper(pending[1]) == 'A' &&
                    std::toupper(pending[2]) == 'T' && std::toupper(pending[3]) == 'A')
                    mode_ = Mode::Finished;
                consumed += size + 2;
            }
            if (!message.fields.empty() && !sink(message))
                return false;
            if (mode_ == Mode::Finished)
            {
                std::vector<uint8_t>().swap(buffer_);
                return true;
            }
            continue;
        }
        if (mode_ == Mode::Probe)
        {
            bool partial = false;

            // A NetBIOS control packet holds at most two 255-byte names; a longer one is other framing, such as
            // an SSL 2.0 record.
            if (pending[0] >= 0x81 && pending[0] <= 0x85 && pending[1] <= 1 && pending[2] <= 1)
            {
                netbios_ = true;
                mode_ = Mode::Smb;
            }
            else if (pending.size() < 8)
                break;
            else if (pending[0] == 0 && pending[4] >= 0xfc &&
                pending[5] == 'S' && pending[6] == 'M' && pending[7] == 'B')
                mode_ = Mode::Smb;
            else if (pending[0] == 0x30 && ldapMessageSize(pending, &partial))
                mode_ = Mode::Ldap;
            else if (pending[0] == 5 && pending[1] == 0 && (pending[2] == 11 || pending[2] == 14))
            {
                if (pending.size() < 16)
                    break;
                mode_ = Mode::Rpc;
            }
            else if (!partial && be32(pending, 0) &&
                (kerberosMessageSize(pending.subspan(4), &partial) == be32(pending, 0) ||
                    (be16(pending, 4) == be32(pending, 0) &&
                        passwordMessageSize(pending.subspan(4), &partial) == be32(pending, 0))))
                mode_ = Mode::Kerberos;

            // An LDAP message ID, a long Kerberos length, or a change-password header needs more bytes before it
            // can be recognized.
            else if (partial)
                break;
            else if (pending[0] == 3 && pending[1] == 0 && pending[4] >= 6 &&
                (pending[5] == 0xe0 || pending[5] == 0xd0))
                mode_ = Mode::Rdp;
            else if ((pending[0] == 0x12 || pending[0] == 4 || pending[0] == 0x10) &&
                !(pending[1] & ~0x1b) && be16(pending, 2) >= 8 && pending[7] == 0)
                mode_ = Mode::Tds;
            else if ((textProtocol_ = identifyCleartext(pending, servicePort_)) != CleartextProtocol::None)
            {
                mode_ = Mode::Text;
                continue;
            }
            else if (be16(pending, 0) >= 14 && (pending[2] >> 3 == 7 || pending[2] >> 3 == 8))
                mode_ = Mode::OpenVpn;
            else if (textPrefix && pending.size() <= 8192 &&
                std::string_view(reinterpret_cast<const char*>(pending.data()), pending.size()).find("\r\n") ==
                    std::string_view::npos)
                break;
            else
            {
                mode_ = Mode::Direct;
                const bool valid = sink({FramedMessage::Kind::Tls, pending, {}});
                std::vector<uint8_t>().swap(buffer_);
                return valid;
            }
        }
        if (mode_ == Mode::Tds && pending[0] >= 20 && pending[0] <= 23 && pending[1] == 3)
        {
            if (!tdsMessage_.empty())
                return false;
            mode_ = Mode::Direct;
            const bool valid = sink({FramedMessage::Kind::Tls, pending, {}});
            std::vector<uint8_t>().swap(buffer_);
            return valid;
        }

        // TLS follows RDP negotiation, and follows LDAP's StartTLS as bytes that are neither a message nor, once
        // this peer has sent a bind, a SASL buffer.
        if ((mode_ == Mode::RdpData && pending[0] != 3) ||
            (mode_ == Mode::Ldap && pending[0] != 0x30 && (pending[0] || !ldapBound_)))
        {
            mode_ = Mode::Direct;
            const bool valid = sink({FramedMessage::Kind::Tls, pending, {}});
            std::vector<uint8_t>().swap(buffer_);
            return valid;
        }
        if (mode_ == Mode::Ldap)
        {
            // Inspection ends with the first message after this peer's bind: its framing shows whether a SASL
            // security layer protects the session, and how.
            FramedMessage message;
            message.kind = FramedMessage::Kind::Ldap;
            bool partial = false;
            LdapMessageInfo ldap;
            const size_t size = pending[0] ? ldapMessageSize(pending, &partial) : 0;
            if (!pending[0])
            {
                if (pending.size() < std::min<size_t>(size_t{be32(pending, 0)} + 4, 36))
                    break;
                message.fields["ldap_messages_after_bind"] = saslProtection(pending);
            }
            else if (!size || size > FramingLimit)
            {
                if (partial)
                    break;
                limited_ = size > FramingLimit;
                return false;
            }
            else if (pending.size() < size)
                break;
            else if (!parseLdap(pending.first(size), message.fields, &ldap, ldapStartTlsResponseId_))
                return false;
            else if (!ldap.bind && ldapBound_ && !message.fields.contains("ldap_starttls_requested") &&
                message.fields.value("ldap_starttls_result", "") != "success")
                message.fields["ldap_messages_after_bind"] = "Plain";
            message.ldapMessageId = ldap.id;
            if (ldap.operation == 0x78 && ldap.id == ldapStartTlsResponseId_)
                ldapStartTlsResponseId_ = 0;
            if (message.fields.contains("ldap_messages_after_bind"))
                mode_ = Mode::Finished;
            ldapBound_ = ldapBound_ || ldap.bind;
            if (!message.fields.empty() && !sink(message))
                return false;
            if (mode_ == Mode::Finished)
            {
                std::vector<uint8_t>().swap(buffer_);
                return true;
            }
            consumed += size;
            continue;
        }
        if (mode_ == Mode::Rpc && pending.size() < 16)
            break;
        const size_t length = mode_ == Mode::OpenVpn ? be16(pending, 0) + 2 :
            mode_ == Mode::Smb ? (static_cast<size_t>(pending[1]) << 16) + be16(pending, 2) + 4 :
            mode_ == Mode::Kerberos ? static_cast<size_t>(be32(pending, 0)) + 4 :
            mode_ == Mode::Rpc ? (pending[4] == 0x10 ? little16(pending, 8) : be16(pending, 8)) :
            be16(pending, 2);
        const size_t minimum = mode_ == Mode::OpenVpn ? 3 : mode_ == Mode::Smb ? 4 :
            mode_ == Mode::Kerberos ? 6 : mode_ == Mode::Rpc ? 16 : 8;
        if (length < minimum || length > FramingLimit)
        {
            limited_ = length > FramingLimit;
            return false;
        }
        if (pending.size() < length)
            break;
        pending = pending.first(length);
        FramedMessage message;
        if (mode_ == Mode::OpenVpn)
        {
            const auto opcode = pending[2] >> 3;
            if (opcode == 6 || opcode == 9)
            {
                consumed += length;
                continue;
            }
            const auto parsed = parseVpn(pending.subspan(2));
            if (!parsed || parsed->protocol != Observation::Protocol::OpenVpn)
                return false;
            message.kind = FramedMessage::Kind::OpenVpn;
            message.payload = pending.subspan(2);
        }
        else if (mode_ == Mode::Smb)
        {
            if (netbios_ && pending[1] > 1)
                return false;

            // NetBIOS session control packets carry no SMB crypto evidence of their own.
            if (pending[0] != 0)
            {
                if ((pending[0] == 0x82 || pending[0] == 0x85) ? length != 4 :
                    pending[0] == 0x83 ? length != 5 : pending[0] == 0x84 ? length != 10 :
                    pending[0] != 0x81)
                    return false;
                if (pending[0] == 0x81)
                {
                    size_t offset = 4;
                    for (int name = 0; name < 2; ++name)
                    {
                        const auto start = offset;
                        if (offset == length || pending[offset++] != 32 || length - offset < 33 ||
                            std::any_of(pending.begin() + offset, pending.begin() + offset + 32,
                                [](uint8_t value) { return value < 'A' || value > 'P'; }))
                            return false;
                        offset += 32;
                        while (pending[offset])
                        {
                            const size_t label = pending[offset++];
                            if (label > 63 || label >= length - offset || offset + label - start > 255)
                                return false;
                            offset += label;
                        }
                        ++offset;
                    }
                    if (offset != length)
                        return false;
                }
                consumed += length;
                if (pending[0] == 0x83 || pending[0] == 0x84)
                {
                    mode_ = Mode::Finished;
                    std::vector<uint8_t>().swap(buffer_);
                    return true;
                }
                continue;
            }
            if (!parseSmb(pending.subspan(4), message.fields, limited_))
                return false;
            message.kind = FramedMessage::Kind::Smb;
            if (smbPipes_)
                smbPipes_->feed(pending.subspan(4), smbDirection_, message.fields);
            if (message.fields.empty())
            {
                consumed += length;
                continue;
            }
            message.fields["smb_transport_framing"] = netbios_ ? "NetBIOS over TCP" : "TCP session framing";
            if (message.fields.contains("smb_encrypted_transform_observed"))
                mode_ = Mode::Finished;
        }
        else if (mode_ == Mode::Kerberos)
        {
            // KDC and change-password messages over TCP are a four-byte length followed by one message.
            const auto body = pending.subspan(4);
            if (!(passwordMessageSize(body) == body.size() ? parsePasswordChange(body, message.fields) :
                parseKerberos(body, message.fields)))
                return false;
            message.kind = FramedMessage::Kind::Kerberos;
        }
        else if (mode_ == Mode::Rpc)
        {
            if (!parseRpcBind(pending, message.fields))
                return false;
            message.kind = FramedMessage::Kind::Rpc;
            if (message.fields.empty())
            {
                consumed += length;
                continue;
            }
        }
        else if (mode_ == Mode::Rdp)
        {
            if (!rdp(pending, message.fields))
                return false;
            message.kind = FramedMessage::Kind::Rdp;

            // TLS follows enhanced security, while standard security continues with an MCS Connect PDU.
            rdpRequest_ = message.fields.contains("rdp_x224_request_observed");
            mode_ = message.fields.contains("rdp_failure_code") ? Mode::Finished : Mode::RdpData;
        }
        else if (mode_ == Mode::RdpData)
        {
            if (!rdpMcsSeen_)
            {
                if (!rdpMcs(pending, rdpRequest_, message.fields))
                    return false;
                rdpMcsSeen_ = true;
                if (!rdpRequest_)
                    mode_ = Mode::Finished;
            }
            else if (!rdpSecurityExchange(pending, message.fields))
                return false;
            message.kind = FramedMessage::Kind::Rdp;
            if (message.fields.contains("rdp_client_security_exchange_observed") || ++rdpPackets_ == 32)
                mode_ = Mode::Finished;
        }
        else
        {
            const bool login = pending[0] == 0x10 && !tdsTls_;
            const auto payload = pending.subspan(8);
            const bool continuation = pending[0] == 0x11 && tdsLoginSeen_ && !tdsTls_;
            const bool responseToken = pending[0] == 4 && !tdsTls_ &&
                (!tdsMessage_.empty() ? tdsLoginResponseToken(tdsMessage_[0]) :
                    !payload.empty() && tdsLoginResponseToken(payload[0]));
            const bool tlsRecord = !tdsTls_ && !login && !continuation && !responseToken &&
                !payload.empty() && payload[0] >= 20 && payload[0] <= 23;
            if (tdsMessage_.empty() && ((tdsLoginSeen_ && !continuation) ||
                (tdsPreloginSeen_ && !tdsTls_ && !login && !continuation && !responseToken && !tlsRecord) ||
                (tdsSspiMessages_ && !tdsTls_ && !login && !continuation && !responseToken && !tlsRecord)))
            {
                mode_ = Mode::Finished;
                std::vector<uint8_t>().swap(buffer_);
                return true;
            }
            if ((pending[0] != 0x12 && pending[0] != 4 && !login && !continuation) ||
                pending[7] || (pending[1] & ~0x1b))
                return false;
            message.kind = FramedMessage::Kind::Tds;
            message.fields["tds_packet_framing_observed"] = true;
            if (!tdsMessage_.empty())
            {
                if (pending[0] != tdsPacketType_ || pending[6] != static_cast<uint8_t>(tdsPacketId_ + 1))
                    return false;
            }
            else if (tlsRecord)
                tdsTls_ = true;
            if (tdsTls_)
                message.payload = payload;
            else
            {
                // Complete a PRELOGIN, LOGIN7, or SSPI message before interpreting its public fields.
                if (payload.empty())
                    return false;
                tdsPacketId_ = pending[6];
                tdsPacketType_ = pending[0];
                tdsMessage_.insert(tdsMessage_.end(), payload.begin(), payload.end());
                if (!(pending[1] & 1))
                {
                    consumed += length;
                    continue;
                }
                if (login)
                {
                    if (!tdsLogin7(tdsMessage_, message.fields))
                        return false;
                    tdsLoginSeen_ = message.fields.value("tds_login_integrated_security", false) &&
                        message.fields.value("tds_login_sspi_observed", false);
                    if (!tdsLoginSeen_)
                        mode_ = Mode::Finished;
                }
                else if (continuation || responseToken)
                {
                    bool observed = continuation;
                    if (responseToken)
                    {
                        if (!tdsSspiResponse(tdsMessage_, message.fields, observed))
                            return false;
                    }
                    if (continuation)
                        parseSecurityBuffer(tdsMessage_, false, message.fields);
                    if (observed)
                    {
                        message.fields[continuation ? "tds_sspi_continuation_observed" :
                            "tds_sspi_response_observed"] = true;
                        if (++tdsSspiMessages_ == 32)
                            mode_ = Mode::Finished;
                    }
                    else
                        mode_ = Mode::Finished;
                }
                else
                {
                    if (!tdsPrelogin(tdsMessage_, message.fields["tds_prelogin"]))
                        return false;
                    message.fields["tds_prelogin_observed"] = true;
                    tdsPreloginSeen_ = true;
                }
                std::vector<uint8_t>().swap(tdsMessage_);
            }
        }
        if (!sink(message))
            return false;
        if (mode_ == Mode::Finished)
        {
            std::vector<uint8_t>().swap(buffer_);
            return true;
        }
        consumed += length;
    }
    buffer_.erase(buffer_.begin(), buffer_.begin() + consumed);
    if (mode_ == Mode::Tds && (tdsLoginSeen_ || tdsSspiMessages_) && buffer_.empty())
        std::vector<uint8_t>().swap(buffer_);
    return true;
}

size_t FramedConnection::memory() const
{
    return streams_[0].memory() + streams_[1].memory() + smbPipes_.memory() +
        http_.requests.capacity() * sizeof(HttpMethod) + database_.authentication.capacity() +
        (http_.pendingSettings[0].capacity() + http_.pendingSettings[1].capacity()) * sizeof(Http2Settings);
}

bool FramedConnection::feed(int direction, Bytes bytes, const Sink& sink)
{
    auto receive = [&](int peer, const FramedMessage& message)
    {
        if (message.kind == FramedMessage::Kind::Ldap && message.ldapMessageId &&
            message.fields.contains("ldap_starttls_requested"))
            streams_[1 - peer].ldapStartTlsResponseId_ = message.ldapMessageId;
        return sink(peer, message);
    };
    if (!streams_[direction].feed(bytes, [&](const FramedMessage& message) { return receive(direction, message); }))
        return false;

    // A peer's declaration can release bytes buffered before HTTP/2 or MPA negotiation was complete.
    const bool mpa = streams_[0].iwarp_ && streams_[1].iwarp_ &&
        streams_[0].iwarp_->flags() && streams_[1].iwarp_->flags();
    if (mpa)
        for (int peer = 0; peer < 2; ++peer)
            streams_[peer].iwarp_->configurePeer(*streams_[1 - peer].iwarp_->flags());
    if (http_.http2Client >= 0 || mpa)
        for (int peer = 0; peer < 2; ++peer)
            if (!streams_[peer].feed({}, [&](const FramedMessage& message) { return receive(peer, message); }))
                return false;
    return true;
}
}
