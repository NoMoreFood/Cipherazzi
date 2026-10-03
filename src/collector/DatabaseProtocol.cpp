#include "DatabaseProtocol.h"
#include "Auth.h"
#include <algorithm>

namespace Cipherazzi
{
static uint32_t databaseLittle(Bytes bytes, size_t offset, size_t count)
{
    uint32_t result{};
    for (size_t index = 0; index < count; ++index)
        result |= static_cast<uint32_t>(bytes[offset + index]) << (index * 8);
    return result;
}

static bool databaseString(Bytes bytes, size_t& offset, std::string* publicValue = nullptr)
{
    if (offset >= bytes.size())
        return false;
    const auto end = std::find(bytes.begin() + offset, bytes.end(), 0);
    if (end == bytes.end())
        return false;
    const size_t size = end - bytes.begin() - offset;
    if (publicValue)
    {
        if (size > 128 || std::any_of(bytes.begin() + offset, end,
            [](uint8_t value) { return value < 33 || value > 126; }))
            return false;
        publicValue->assign(reinterpret_cast<const char*>(bytes.data() + offset), size);
    }
    offset += size + 1;
    return true;
}

DatabaseNegotiation::Kind DatabaseStream::recognizes(Bytes bytes)
{
    if (bytes.size() >= 8 && be32(bytes, 0) >= 8 && be32(bytes, 0) <= 262144 &&
        (be32(bytes, 4) == 196608 || (be32(bytes, 0) == 8 &&
            (be32(bytes, 4) == 80877103 || be32(bytes, 4) == 80877104))))
        return DatabaseNegotiation::Kind::PostgreSql;
    if (bytes.size() >= 8 && bytes[3] == 0 && bytes[4] == 10 &&
        databaseLittle(bytes, 0, 3) >= 20 && databaseLittle(bytes, 0, 3) <= 262144 &&
        bytes[5] >= '0' && bytes[5] <= '9')
        return DatabaseNegotiation::Kind::MySql;
    return DatabaseNegotiation::Kind::None;
}

bool DatabaseStream::feed(Bytes bytes, const Sink& sink)
{
    // Bound startup inspection and release it before application requests can enter the parser.
    if (state_.finished)
        return true;
    if (state_.encryption == DatabaseNegotiation::Encryption::Tls)
        return sink(bytes, {}, true);
    if (bytes.size() > 262144 - buffer_.size())
    {
        limited_ = true;
        return false;
    }
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
    size_t consumed{};
    while (consumed < buffer_.size())
    {
        auto pending = Bytes(buffer_).subspan(consumed);
        nlohmann::json fields = nlohmann::json::object();
        size_t length{};
        const bool client = direction_ == state_.client;
        if (state_.kind == DatabaseNegotiation::Kind::PostgreSql)
        {
            // PostgreSQL answers encryption requests with a single byte before its normal startup framing.
            if (!client && pending[0] != 'E' &&
                (state_.encryption == DatabaseNegotiation::Encryption::SslRequest ||
                    state_.encryption == DatabaseNegotiation::Encryption::GssRequest))
            {
                const bool tls = state_.encryption == DatabaseNegotiation::Encryption::SslRequest;
                if (pending[0] != 'N' && pending[0] != (tls ? 'S' : 'G'))
                    return false;
                const bool accepted = pending[0] != 'N';
                fields[tls ? "postgresql_tls_accepted" : "postgresql_gss_encryption_accepted"] = accepted;
                state_.encryption = accepted && tls ? DatabaseNegotiation::Encryption::Tls :
                    DatabaseNegotiation::Encryption::None;
                state_.finished = accepted && !tls;
                length = 1;
            }
            else if (client && !started_)
            {
                if (pending.size() < 8)
                    break;
                length = be32(pending, 0);
                if (length < 8 || length > 262144)
                {
                    limited_ = length > 262144;
                    return false;
                }
                if (pending.size() < length)
                    break;
                const auto code = be32(pending, 4);
                if (code == 80877103 || code == 80877104)
                {
                    if (length != 8 || state_.encryption != DatabaseNegotiation::Encryption::None)
                        return false;
                    state_.encryption = code == 80877103 ? DatabaseNegotiation::Encryption::SslRequest :
                        DatabaseNegotiation::Encryption::GssRequest;
                    fields[code == 80877103 ? "postgresql_tls_requested" :
                        "postgresql_gss_encryption_requested"] = true;
                }
                else if (code == 196608 && length >= 9 && pending[length - 1] == 0)
                {
                    fields["postgresql_unencrypted_startup_observed"] = true;
                    started_ = true;
                }
                else
                    return false;
            }
            else
            {
                if (pending.size() < 5)
                    break;
                length = static_cast<size_t>(be32(pending, 1)) + 1;
                if (length < 5 || length > 262144)
                {
                    limited_ = length > 262144;
                    return false;
                }
                if (pending.size() < length)
                    break;
                const auto payload = pending.subspan(5, length - 5);
                if (!client && pending[0] == 'R')
                {
                    if (payload.size() < 4)
                        return false;
                    const auto method = be32(payload, 0);
                    if (method == 0)
                    {
                        fields["postgresql_server_authentication_result"] = "Accepted";
                        state_.finished = true;
                    }
                    else if (method != 8 && method != 11 && method != 12)
                    {
                        fields["postgresql_authentication_method_id"] = method;
                        state_.authentication = method == 3 ? "Cleartext password" : method == 5 ? "MD5" :
                            method == 7 ? "GSSAPI" : method == 9 ? "SSPI" : method == 10 ? "SASL" : "Unknown";
                        fields["postgresql_authentication_method"] = state_.authentication;
                        if (method == 10)
                        {
                            size_t offset = 4;
                            auto mechanisms = nlohmann::json::array();
                            while (offset < payload.size() && payload[offset])
                            {
                                std::string mechanism;
                                if (mechanisms.size() >= 16 || !databaseString(payload, offset, &mechanism))
                                    return false;
                                mechanisms.push_back(mechanism);
                            }
                            if (offset + 1 != payload.size())
                                return false;
                            fields["postgresql_sasl_mechanisms"] = std::move(mechanisms);
                        }
                    }
                    else if (method == 8)
                        parseSecurityBuffer(payload.subspan(4), true, fields);
                }
                else if (client && pending[0] == 'p')
                {
                    if (state_.authentication == "Cleartext password" && !payload.empty() && payload.back() == 0)
                        fields["postgresql_cleartext_password_observed"] = true;
                    else if (state_.authentication == "SASL")
                    {
                        size_t offset{};
                        std::string mechanism;
                        if (!databaseString(payload, offset, &mechanism) || payload.size() - offset < 4)
                            return false;
                        const auto responseLength = be32(payload, offset);
                        if (responseLength != 0xffffffff && responseLength != payload.size() - offset - 4)
                            return false;
                        fields["postgresql_sasl_selected"] = mechanism;
                        state_.authentication = "SASL continuation";
                    }
                    else if (state_.authentication == "GSSAPI" || state_.authentication == "SSPI")
                        parseSecurityBuffer(payload, false, fields);
                }
                else if (!client && pending[0] == 'E')
                {
                    if (state_.authentication.empty())
                        fields["postgresql_startup_rejected"] = true;
                    else
                        fields["postgresql_server_authentication_result"] = "Rejected";
                    state_.finished = true;
                }
            }
        }
        else
        {
            // MySQL classic protocol lengths exclude the four-byte packet header.
            if (pending.size() < 4)
                break;
            length = databaseLittle(pending, 0, 3) + 4;
            if (length > 262144)
            {
                limited_ = true;
                return false;
            }
            if (pending.size() < length)
                break;
            if (pending[3] != state_.sequence++)
                return false;
            const auto payload = pending.subspan(4, length - 4);
            if (!client && !started_)
            {
                size_t offset = 1;
                if (payload.empty() || payload[0] != 10 || !databaseString(payload, offset) ||
                    payload.size() - offset < 15)
                    return false;
                offset += 13;
                state_.capabilities = databaseLittle(payload, offset, 2);
                offset += 2;
                if (payload.size() - offset >= 16)
                {
                    state_.capabilities |= databaseLittle(payload, offset + 3, 2) << 16;
                    const auto authLength = payload[offset + 5];
                    offset += 16;
                    if (state_.capabilities & 0x8000)
                    {
                        const size_t rest = std::max(13, static_cast<int>(authLength) - 8);
                        if (rest > payload.size() - offset)
                            return false;
                        offset += rest;
                    }
                    if (state_.capabilities & 0x80000)
                    {
                        if (!databaseString(payload, offset, &state_.authentication))
                            return false;
                        fields["mysql_server_authentication_plugin"] = state_.authentication;
                    }
                }
                fields["mysql_server_capabilities"] = state_.capabilities;
                fields["mysql_tls_supported"] = (state_.capabilities & 0x800) != 0;
                started_ = true;
            }
            else if (client && !started_)
            {
                if (payload.size() < 32)
                    return false;
                const auto capabilities = databaseLittle(payload, 0, 4);
                fields["mysql_client_capabilities"] = capabilities;
                if (capabilities & 0x800)
                {
                    if (payload.size() != 32 || !(state_.capabilities & 0x800))
                        return false;
                    fields["mysql_tls_requested"] = true;
                    state_.encryption = DatabaseNegotiation::Encryption::Tls;
                }
                else
                {
                    size_t offset = 32;
                    if (!databaseString(payload, offset) || offset >= payload.size())
                        return false;
                    size_t authLength{};
                    if (capabilities & 0x200000)
                    {
                        authLength = payload[offset++];
                        const size_t count = authLength == 0xfc ? 2 : authLength == 0xfd ? 3 : 0;
                        if (authLength >= 0xfb && !count)
                            return false;
                        if (count)
                        {
                            if (count > payload.size() - offset)
                                return false;
                            authLength = databaseLittle(payload, offset, count);
                            offset += count;
                        }
                    }
                    else if (capabilities & 0x8000)
                        authLength = payload[offset++];
                    else
                    {
                        const auto start = offset;
                        if (!databaseString(payload, offset))
                            return false;
                        authLength = offset - start;
                        offset = start;
                    }
                    if (authLength > payload.size() - offset)
                        return false;
                    offset += authLength;
                    if ((capabilities & 8) && !databaseString(payload, offset))
                        return false;
                    if ((capabilities & 0x80000) && !databaseString(payload, offset, &state_.authentication))
                        return false;
                    fields["mysql_unencrypted_login_observed"] = true;
                    fields["mysql_client_authentication_plugin"] = state_.authentication;
                    if (state_.authentication == "mysql_clear_password" && authLength)
                        fields["mysql_cleartext_password_observed"] = true;
                }
                started_ = true;
            }
            else if (!client && !payload.empty())
            {
                if (payload[0] == 0xfe)
                {
                    size_t offset = 1;
                    if (!databaseString(payload, offset, &state_.authentication))
                        return false;
                    fields["mysql_authentication_switch"] = state_.authentication;
                }
                else if (payload[0] == 0 || payload[0] == 0xff)
                {
                    fields["mysql_server_authentication_result"] = payload[0] == 0 ? "Accepted" : "Rejected";
                    state_.finished = true;
                }
            }
            else if (client && state_.authentication == "mysql_clear_password" && !payload.empty())
                fields["mysql_cleartext_password_observed"] = true;
        }
        consumed += length;
        if (!fields.empty() && !sink({}, fields, false))
            return false;
        if (state_.finished || state_.encryption == DatabaseNegotiation::Encryption::Tls)
        {
            const bool valid = state_.finished || consumed == buffer_.size() ||
                sink(Bytes(buffer_).subspan(consumed), {}, true);
            std::vector<uint8_t>().swap(buffer_);
            return valid;
        }
    }
    buffer_.erase(buffer_.begin(), buffer_.begin() + consumed);
    return true;
}
}
