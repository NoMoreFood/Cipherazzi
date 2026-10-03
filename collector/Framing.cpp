#include "Framing.h"
#include "Auth.h"
#include "Vpn.h"

#include <algorithm>
#include <array>
#include <format>
#include <string_view>
#include <windows.h>

namespace Cipherazzi
{
namespace
{
constexpr size_t FramingLimit = 262144;

uint16_t little16(Bytes bytes, size_t offset)
{
    return static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
}

uint32_t little32(Bytes bytes, size_t offset)
{
    return little16(bytes, offset) | (static_cast<uint32_t>(little16(bytes, offset + 2)) << 16);
}

bool smbDecompress(Bytes bytes, uint16_t algorithm, size_t size, std::vector<uint8_t>& output)
{
    if (!size || size > FramingLimit - output.size())
        return false;
    const auto start = output.size();
    output.resize(start + size);

    // LZ4 blocks use bounded literal runs and backward references within the current segment.
    if (algorithm == 5)
    {
        size_t consumed = 0, produced = start;
        auto extend = [&](size_t& length)
        {
            if (length != 15)
                return true;
            uint8_t value;
            do
            {
                if (consumed == bytes.size() || length > size)
                    return false;
                value = bytes[consumed++];
                length += value;
            } while (value == 255);
            return length <= size;
        };
        while (consumed < bytes.size())
        {
            const auto token = bytes[consumed++];
            size_t literals = token >> 4;
            if (!extend(literals) || literals > bytes.size() - consumed || literals > output.size() - produced)
                return false;
            std::copy_n(bytes.begin() + consumed, literals, output.begin() + produced);
            consumed += literals;
            produced += literals;
            if (consumed == bytes.size())
                return produced == output.size();
            if (bytes.size() - consumed < 2)
                return false;
            const auto offset = little16(bytes, consumed);
            consumed += 2;
            size_t match = token & 15;
            if (!offset || offset > produced - start || !extend(match) || match + 4 > output.size() - produced)
                return false;
            for (size_t count = 0; count < match + 4; ++count, ++produced)
                output[produced] = output[produced - offset];
        }
        return false;
    }

    // Windows supplies the LZNT1, XPRESS, and XPRESS Huffman codecs used by SMB.
    using WorkspaceSize = LONG(WINAPI*)(USHORT, PULONG, PULONG);
    using Decompress = LONG(WINAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);
    static const auto module = GetModuleHandleW(L"ntdll.dll");
    static const auto workspaceSize = reinterpret_cast<WorkspaceSize>(
        GetProcAddress(module, "RtlGetCompressionWorkSpaceSize"));
    static const auto decompress = reinterpret_cast<Decompress>(GetProcAddress(module, "RtlDecompressBufferEx"));
    ULONG compressionWorkspace{}, fragmentWorkspace{}, actual{};
    const USHORT format = algorithm == 1 ? 2 : algorithm == 2 ? 3 : algorithm == 3 ? 4 : 0;
    if (!format || !workspaceSize || !decompress ||
        workspaceSize(format, &compressionWorkspace, &fragmentWorkspace) < 0 || fragmentWorkspace > 1048576)
        return false;
    std::vector<uint8_t> workspace(fragmentWorkspace);
    return decompress(format, output.data() + start, static_cast<ULONG>(size),
        const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), &actual, workspace.data()) >= 0 &&
        actual == size;
}

// SMB1 is retained as public NEGOTIATE evidence only; its later messages are framed without being interpreted.
bool smbLegacy(Bytes bytes, nlohmann::json& fields)
{
    constexpr size_t HeaderSize = 32;
    if (bytes.size() < HeaderSize + 3)
        return false;
    const bool response = (bytes[9] & 0x80) != 0;
    if (bytes[4] != 0x72 || (response && little32(bytes, 5) != 0))
        return true;

    // Parameters and data must account for the entire frame before negotiation values are exposed.
    const size_t words = bytes[HeaderSize];
    if (bytes.size() < HeaderSize + 3 + words * 2)
        return false;
    const auto parameters = bytes.subspan(HeaderSize + 1, words * 2);
    const size_t dataSize = little16(bytes, HeaderSize + 1 + words * 2);
    const auto data = bytes.subspan(HeaderSize + 3 + words * 2);
    if (data.size() != dataSize)
        return false;

    if (!response)
    {
        if (words || data.empty())
            return false;
        nlohmann::json dialects = nlohmann::json::array();
        bool smb2 = false;
        for (size_t position = 0; position < data.size();)
        {
            if (dialects.size() == 32 || data[position] != 2)
                return false;
            const auto start = ++position;
            while (position < data.size() && data[position])
                ++position;
            const auto name = data.subspan(start, position - start);
            if (position == data.size() || name.empty() || name.size() > 64 ||
                std::any_of(name.begin(), name.end(), [](uint8_t value) { return value < 32 || value > 126; }))
                return false;
            dialects.push_back(std::string(name.begin(), name.end()));
            const auto& dialect = dialects.back().get_ref<const std::string&>();
            smb2 |= dialect == "SMB 2.002" || dialect == "SMB 2.???";
            ++position;
        }
        fields["smb_legacy_offered_dialects"] = std::move(dialects);
        fields["smb_legacy_smb2_dialect_offered"] = smb2;
        return true;
    }

    // The response layout identifies the dialect family; the selected index is retained as sent.
    const auto index = parameters.size() >= 2 ? little16(parameters, 0) : 0;
    if (words == 1)
    {
        if (!data.empty())
            return false;
        fields["smb_legacy_selected_dialect_index"] = index;
        if (index == 0xffff)
            fields["smb_legacy_dialect_rejected"] = true;
        else
            fields["smb_legacy_response_format"] = "Core";
        return true;
    }
    if (index == 0xffff || (words != 13 && words != 17))
        return false;
    const auto mode = words == 17 ? parameters[2] : little16(parameters, 2);
    if (mode & (words == 17 ? ~0x0f : ~0x03))
        return false;
    fields["smb_legacy_selected_dialect_index"] = index;
    fields["smb_legacy_response_format"] = words == 17 ? "NT LM 0.12" : "LAN Manager";
    fields["smb_legacy_user_level_security"] = (mode & 1) != 0;
    fields["smb_legacy_encrypted_passwords"] = (mode & 2) != 0;
    if (words == 13)
        return true;

    // Only NT LM 0.12 can advertise message signing; capabilities use the SMB1 bit layout.
    const auto capabilities = little32(parameters, 19);
    const bool extended = (capabilities & 0x80000000u) != 0;
    if (extended ? parameters[33] != 0 || data.size() < 16 : parameters[33] > data.size())
        return false;
    fields["smb_server_signing_enabled"] = (mode & 4) != 0;
    fields["smb_server_signing_required"] = (mode & 8) != 0;
    fields["smb_legacy_server_capabilities"] = capabilities;
    fields["smb_legacy_extended_security"] = extended;
    return true;
}

// SESSION_SETUP carries the SPNEGO exchange; status and session flags are reported as sent, not as proof of authentication.
bool smbSessionSetup(Bytes bytes, bool response, nlohmann::json& fields)
{
    const auto status = little32(bytes, 8);
    size_t offset, length;
    if (response)
    {
        fields["smb_session_setup_status"] = std::format("0x{:08X}", status);

        // Other error statuses use the generic error layout, which has no security buffer.
        if (status != 0 && status != 0xc0000016)
            return true;
        if (bytes.size() < 72 || little16(bytes, 64) != 9 || (little16(bytes, 66) & ~7))
            return false;
        if (!status)
        {
            fields["smb_session_guest"] = (little16(bytes, 66) & 1) != 0;
            fields["smb_session_anonymous"] = (little16(bytes, 66) & 2) != 0;
            fields["smb_session_encryption_required"] = (little16(bytes, 66) & 4) != 0;
        }
        offset = little16(bytes, 68);
        length = little16(bytes, 70);
    }
    else
    {
        if (bytes.size() < 88 || little16(bytes, 64) != 25)
            return false;
        offset = little16(bytes, 76);
        length = little16(bytes, 78);
    }
    if (length && (offset < (response ? 72u : 88u) || offset > bytes.size() || length > bytes.size() - offset))
        return false;
    parseSecurityBuffer(bytes.subspan(offset, length), response, fields);
    return true;
}

bool smb(Bytes bytes, nlohmann::json& fields, bool& limited)
{
    if (bytes.size() < 4 || bytes[1] != 'S' || bytes[2] != 'M' || bytes[3] != 'B')
        return false;
    if (bytes[0] == 0xff)
        return smbLegacy(bytes, fields);

    // Decode compressed framing within the same bound as ordinary SMB messages; retain no file payload.
    if (bytes[0] == 0xfc)
    {
        if (bytes.size() < 16 || !little32(bytes, 4) || little16(bytes, 10) > 1)
            return false;
        const size_t original = little32(bytes, 4);
        const bool chained = little16(bytes, 10) == 1;
        size_t offset = chained ? 8 : 16 + static_cast<size_t>(little32(bytes, 12));
        if (offset > bytes.size())
            return false;
        if (original > FramingLimit || (!chained && offset - 16 > FramingLimit - original))
        {
            limited = true;
            return false;
        }
        std::vector<uint8_t> decoded;
        nlohmann::json algorithms = nlohmann::json::array();
        bool supported = true;
        if (!chained)
        {
            const auto algorithm = little16(bytes, 8);
            if (!algorithm || algorithm == 4 || offset == bytes.size())
                return false;
            algorithms.push_back(hex16(algorithm));
            decoded.assign(bytes.begin() + 16, bytes.begin() + offset);
            supported = algorithm <= 5;
            if (supported && !smbDecompress(bytes.subspan(offset), algorithm, original, decoded))
                return false;
        }
        else
        {
            for (size_t count = 0; offset < bytes.size(); ++count)
            {
                if (count >= 256 || bytes.size() - offset < 8)
                    return false;
                const auto algorithm = little16(bytes, offset);
                const auto flags = little16(bytes, offset + 2);
                const size_t length = little32(bytes, offset + 4);
                offset += 8;
                if (flags != (count == 0 ? 1 : 0) || !length || length > bytes.size() - offset)
                    return false;
                const auto payload = bytes.subspan(offset, length);
                algorithms.push_back(hex16(algorithm));
                size_t expanded = length;
                if (algorithm == 4)
                {
                    if (length != 8 || payload[1] || little16(payload, 2))
                        return false;
                    expanded = little32(payload, 4);
                }
                else if (algorithm)
                {
                    if (length < 5)
                        return false;
                    expanded = little32(payload, 0);
                }
                if (!expanded || expanded > original - decoded.size())
                    return false;
                supported &= algorithm <= 5;
                if (!algorithm)
                    decoded.insert(decoded.end(), payload.begin(), payload.end());
                else if (algorithm == 4)
                    decoded.insert(decoded.end(), expanded, payload[0]);
                else if (algorithm <= 5 && !smbDecompress(payload.subspan(4), algorithm, expanded, decoded))
                    return false;
                else if (algorithm > 5)
                    decoded.resize(decoded.size() + expanded);
                offset += length;
            }
            if (decoded.size() != original)
                return false;
        }
        if (supported && (decoded.size() < 4 || decoded[0] != 0xfe || !parseSmb(decoded, fields, limited)))
            return false;
        fields["smb_compressed_transform_observed"] = true;
        fields["smb_compression_chained"] = chained;
        fields["smb_compression_algorithms"] = std::move(algorithms);
        fields["smb_compression_decoded"] = supported;
        return true;
    }
    if (bytes[0] == 0xfd)
    {
        if (bytes.size() < 52 || little16(bytes, 40) != 0 || little16(bytes, 42) != 1 ||
            little32(bytes, 36) != bytes.size() - 52)
            return false;
        fields["smb_encrypted_transform_observed"] = true;
        return true;
    }
    if (bytes[0] != 0xfe || bytes.size() < 64 || little16(bytes, 4) != 64)
        return false;

    // The signed flag establishes framing evidence without asserting cryptographic verification.
    if (little32(bytes, 16) & 8)
        fields["smb_signed_message_observed"] = true;
    const auto command = little16(bytes, 12);
    const bool response = (little32(bytes, 16) & 1) != 0;
    if (command == 1)
        return smbSessionSetup(bytes, response, fields);
    if (response && little32(bytes, 8) != 0)
        return true;

    // READ/WRITE channel metadata describes protected RDMA payloads without exposing buffer tokens or file data.
    if ((command == 9 && !response) || (command == 8 && response))
    {
        const bool write = command == 9;
        const size_t fixed = write ? 112 : 80;
        if (bytes.size() < fixed || little16(bytes, 64) != (write ? 49 : 17))
            return false;
        if (write ? little32(bytes, 96) != 3 : !(little32(bytes, 76) & 1))
            return true;
        const size_t offset = write ? little16(bytes, 104) : bytes[66];
        const size_t length = write ? little16(bytes, 106) : little32(bytes, 68);
        if (!little32(bytes, write ? 100 : 72) || offset < fixed || offset > bytes.size() ||
            length > bytes.size() - offset || length < 24)
            return false;
        const auto data = bytes.subspan(offset, length);
        const size_t descriptorOffset = little16(data, 0), descriptorLength = little16(data, 2);
        const auto channel = little32(data, 4);
        const auto type = little16(data, 16);
        const size_t signature = little16(data, 18), nonce = little16(data, 20);
        const size_t end = 24 + signature + nonce;

        // Encrypted RDMA transforms require an encrypted SMB message, whose contents remain opaque here.
        if (channel > 2 || little16(data, 8) != 1 || type != 2 || signature > 16 || end > data.size())
            return false;
        if (channel ? descriptorOffset < ((end + 7) & ~size_t{7}) || descriptorOffset % 8 ||
            descriptorLength < 16 || descriptorLength % 16 || descriptorOffset > data.size() ||
            descriptorLength != data.size() - descriptorOffset :
            data.size() != end && data.size() != ((end + 7) & ~size_t{7}))
            return false;
        fields[write ? "smb_rdma_write_transform" : "smb_rdma_read_transform"] =
            {{"type", "Signing"}, {"signature_length", signature}, {"nonce_length", nonce},
                {"channel", channel}, {"descriptor_count", channel ? descriptorLength / 16 : 0}};
        fields["smb_rdma_signed_payload_observed"] = true;
        return true;
    }
    if (command != 0)
        return true;
    if (little32(bytes, 20) != 0)
        return false;
    const size_t fixed = response ? 128 : 100;
    if (bytes.size() < fixed || little16(bytes, 64) != (response ? 65 : 36))
        return false;
    const auto security = little16(bytes, response ? 66 : 68);
    if (security & ~3)
        return false;
    fields[response ? "smb_server_signing_enabled" : "smb_client_signing_enabled"] = (security & 1) != 0;
    fields[response ? "smb_server_signing_required" : "smb_client_signing_required"] = (security & 2) != 0;
    fields[response ? "smb_server_capabilities" : "smb_client_capabilities"] = little32(bytes, response ? 88 : 72);
    bool contexts = false;
    size_t contextOffset = 0, contextCount = 0;
    if (response)
    {
        const auto dialect = little16(bytes, 68);
        fields["smb_selected_dialect"] = hex16(dialect);
        contexts = dialect == 0x0311;
        contextOffset = little32(bytes, 124);
        contextCount = little16(bytes, 70);
        const auto securityOffset = little16(bytes, 120);
        const auto securityLength = little16(bytes, 122);
        if (securityLength && (securityOffset < fixed || securityOffset > bytes.size() ||
            securityLength > bytes.size() - securityOffset))
            return false;
        if (contexts && securityLength && contextOffset < securityOffset + securityLength)
            return false;
        if (securityLength)
            parseSecurityBuffer(bytes.subspan(securityOffset, securityLength), true, fields);
    }
    else
    {
        const auto count = little16(bytes, 66);
        if (!count || count > 256 || count * 2u > bytes.size() - fixed)
            return false;
        fields["smb_offered_dialects"] = nlohmann::json::array();
        for (size_t index = 0; index < count; ++index)
        {
            const auto dialect = little16(bytes, fixed + index * 2);
            fields["smb_offered_dialects"].push_back(hex16(dialect));
            contexts |= dialect == 0x0311;
        }
        contextOffset = little32(bytes, 92);
        contextCount = little16(bytes, 96);
        if (contexts && contextCount && contextOffset < fixed + count * 2u)
            return false;
    }
    if (!contexts)
        return true;
    if (!contextCount || contextCount > 32 || contextOffset < fixed || contextOffset % 8)
        return false;
    std::vector<uint16_t> seen;
    for (size_t index = 0; index < contextCount; ++index)
    {
        if (contextOffset > bytes.size() || bytes.size() - contextOffset < 8)
            return false;
        const auto type = little16(bytes, contextOffset);
        const auto length = little16(bytes, contextOffset + 2);
        if (little32(bytes, contextOffset + 4) || length > bytes.size() - contextOffset - 8 ||
            std::ranges::find(seen, type) != seen.end())
            return false;
        seen.push_back(type);
        const auto data = bytes.subspan(contextOffset + 8, length);

        // Negotiated compression capabilities are independent of compressed message framing.
        if (type == 3)
        {
            if (data.size() < 8 || little32(data, 4) > 1)
                return false;
            const auto count = little16(data, 0);
            if (!count || count > 256 || data.size() != 8 + count * 2u)
                return false;
            const auto name = response ? "smb_server_compression_algorithms" : "smb_client_compression_algorithms";
            fields[name] = nlohmann::json::array();
            for (size_t item = 0; item < count; ++item)
                fields[name].push_back(hex16(little16(data, 8 + item * 2)));
            fields[response ? "smb_server_chained_compression" : "smb_client_chained_compression"] =
                little32(data, 4) == 1;
        }
        else if (type == 7)
        {
            if (data.size() < 8)
                return false;
            const auto count = little16(data, 0);
            if (!count || count > 256 || data.size() != 8 + count * 2u)
                return false;
            const auto name = response ? "smb_selected_rdma_transforms" : "smb_offered_rdma_transforms";
            fields[name] = nlohmann::json::array();
            for (size_t item = 0; item < count; ++item)
            {
                const auto id = hex16(little16(data, 8 + item * 2));
                if (std::find(fields[name].begin(), fields[name].end(), id) != fields[name].end())
                    return false;
                fields[name].push_back(id);
            }
        }
        else if (type == 2 || type == 8)
        {
            if (data.size() < 2)
                return false;
            const auto count = little16(data, 0);
            if (!count || count > 256 || data.size() != 2 + count * 2u || (response && count != 1))
                return false;
            const auto name = type == 2 ? response ? "smb_selected_cipher" : "smb_offered_ciphers" :
                response ? "smb_selected_signing_algorithm" : "smb_offered_signing_algorithms";
            fields[name] = nlohmann::json::array();
            for (size_t item = 0; item < count; ++item)
                fields[name].push_back(hex16(little16(data, 2 + item * 2)));
        }
        contextOffset += 8 + length;
        if (index + 1 < contextCount)
            contextOffset = (contextOffset + 7) & ~size_t{7};
    }
    return true;
}

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
    constexpr char digits[] = "0123456789abcdef";
    std::string id(32, '0');
    for (size_t index = 0; index < 16; ++index)
    {
        id[index * 2] = digits[payload[index + 4] >> 4];
        id[index * 2 + 1] = digits[payload[index + 4] & 15];
    }
    fields["rdp_correlation_id"] = std::move(id);
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

std::string rdpHex32(uint32_t value)
{
    return std::format("0x{:08X}", value);
}

// The certificate is public key metadata only; its signature and chain are not verified.
void rdpServerCertificate(Bytes certificate, nlohmann::json& fields)
{
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
            userData[7] != 0xc0 || userData[8] || std::string_view(reinterpret_cast<const char*>(userData.data()) + 9, 4) != "McDn")
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
                names.push_back(rdpHex32(methods & ~0x1bu));
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
        fields["rdp_server_encryption_method"] = found == std::end(methods) ? rdpHex32(method) :
            methodNames[found - std::begin(methods)];
        fields["rdp_server_encryption_level"] = level < 5 ? std::string(levelNames[level]) : rdpHex32(level);

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
}

bool parseSmb(Bytes bytes, nlohmann::json& fields, bool& limited)
{
    // Compound command offsets are relative to each SMB header; publish evidence only after every part is valid.
    nlohmann::json parsed = nlohmann::json::object();
    for (size_t count = 0; count < 64; ++count)
    {
        const size_t next = bytes.size() >= 64 && bytes[0] == 0xfe ? little32(bytes, 20) : 0;
        if (next && (next < 64 || next % 8 || next >= bytes.size()))
            return false;
        nlohmann::json part = nlohmann::json::object();
        if (!smb(next ? bytes.first(next) : bytes, part, limited))
            return false;
        parsed.update(part);
        if (!next)
        {
            fields.update(parsed);
            return true;
        }
        bytes = bytes.subspan(next);
    }
    return false;
}

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
    if (iwarp_)
        return iwarp_->feed(bytes, [&](const nlohmann::json& fields)
            { return sink({FramedMessage::Kind::Smb, {}, fields}); });
    if (mode_ == Mode::Finished)
        return true;
    if (mode_ == Mode::Direct)
        return sink({FramedMessage::Kind::Tls, bytes, {}});
    if (bytes.size() > FramingLimit - buffer_.size() - tdsMessage_.size())
    {
        limited_ = true;
        return false;
    }
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());

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
            const bool valid = iwarp_->feed(buffer_, [&](const nlohmann::json& fields)
                { return sink({FramedMessage::Kind::Smb, {}, fields}); });
            std::vector<uint8_t>().swap(buffer_);
            return valid;
        }
    }
    if (mode_ == Mode::Probe && !buffer_.empty() && buffer_[0] != 0 && buffer_[0] != 3 &&
        buffer_[0] != 4 && buffer_[0] != 0x12 && !(buffer_[0] >= 0x81 && buffer_[0] <= 0x85))
    {
        mode_ = Mode::Direct;
        const bool valid = sink({FramedMessage::Kind::Tls, buffer_, {}});
        std::vector<uint8_t>().swap(buffer_);
        return valid;
    }
    size_t consumed = 0;
    while (buffer_.size() - consumed >= 4)
    {
        auto pending = Bytes(buffer_).subspan(consumed);
        if (mode_ == Mode::Probe)
        {
            bool partial = false;
            if (pending[0] >= 0x81 && pending[0] <= 0x85 && pending[1] <= 1)
            {
                netbios_ = true;
                mode_ = Mode::Smb;
            }
            else if (pending.size() < 8)
                break;
            else if (pending[0] == 0 && pending[4] >= 0xfc &&
                pending[5] == 'S' && pending[6] == 'M' && pending[7] == 'B')
                mode_ = Mode::Smb;
            else if (be32(pending, 0) && (kerberosMessageSize(pending.subspan(4), &partial) == be32(pending, 0) ||
                (be16(pending, 4) == be32(pending, 0) &&
                    passwordMessageSize(pending.subspan(4), &partial) == be32(pending, 0))))
                mode_ = Mode::Kerberos;

            // A long Kerberos length or a change-password header needs more bytes before it can be recognized.
            else if (partial)
                break;
            else if (pending[0] == 3 && pending[1] == 0 && pending[4] >= 6 &&
                (pending[5] == 0xe0 || pending[5] == 0xd0))
                mode_ = Mode::Rdp;
            else if ((pending[0] == 0x12 || pending[0] == 4) && !(pending[1] & ~0x1b) &&
                be16(pending, 2) >= 8 && pending[7] == 0)
                mode_ = Mode::Tds;
            else if (be16(pending, 0) >= 14 && (pending[2] >> 3 == 7 || pending[2] >> 3 == 8))
                mode_ = Mode::OpenVpn;
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
        if (mode_ == Mode::RdpData && pending[0] != 3)
        {
            mode_ = Mode::Direct;
            const bool valid = sink({FramedMessage::Kind::Tls, pending, {}});
            std::vector<uint8_t>().swap(buffer_);
            return valid;
        }
        if (mode_ == Mode::Tds && tdsPreloginSeen_ && tdsMessage_.empty() && !tdsTls_ && pending[0] == 0x10)
        {
            // A LOGIN7 packet outside TLS shows that the login was not encrypted; its contents are not read.
            FramedMessage login;
            login.kind = FramedMessage::Kind::Tds;
            if (!(pending[1] & ~0x1b) && be16(pending, 2) > 8)
                login.fields["tds_unencrypted_login_observed"] = true;
            mode_ = Mode::Finished;
            std::vector<uint8_t>().swap(buffer_);
            return login.fields.empty() || sink(login);
        }
        const size_t length = mode_ == Mode::OpenVpn ? be16(pending, 0) + 2 :
            mode_ == Mode::Smb ? (static_cast<size_t>(pending[1]) << 16) + be16(pending, 2) + 4 :
            mode_ == Mode::Kerberos ? static_cast<size_t>(be32(pending, 0)) + 4 : be16(pending, 2);
        const size_t minimum = mode_ == Mode::OpenVpn ? 3 : mode_ == Mode::Smb ? 4 : mode_ == Mode::Kerberos ? 6 : 8;
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
            if (!smb(pending.subspan(4), message.fields, limited_))
                return false;
            message.kind = FramedMessage::Kind::Smb;
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
            if (!rdpMcs(pending, rdpRequest_, message.fields))
                return false;
            message.kind = FramedMessage::Kind::Rdp;
            mode_ = Mode::Finished;
        }
        else
        {
            if ((pending[0] != 0x12 && pending[0] != 4) || pending[7] || (pending[1] & ~0x1b))
                return false;
            message.kind = FramedMessage::Kind::Tds;
            message.fields["tds_packet_framing_observed"] = true;
            auto payload = pending.subspan(8);
            if (!tdsMessage_.empty())
            {
                if (pending[0] != tdsPacketType_ || pending[6] != static_cast<uint8_t>(tdsPacketId_ + 1))
                    return false;
            }
            else if (!payload.empty() && payload[0] >= 20 && payload[0] <= 23)
                tdsTls_ = true;
            else if (tdsPreloginSeen_ && !tdsTls_ && tdsMessage_.empty())
            {
                mode_ = Mode::Finished;
                std::vector<uint8_t>().swap(buffer_);
                return true;
            }
            if (tdsTls_)
                message.payload = payload;
            else
            {
                // Complete the public option message before allowing TLS or another PRELOGIN message.
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
                if (!tdsPrelogin(tdsMessage_, message.fields["tds_prelogin"]))
                    return false;
                message.fields["tds_prelogin_observed"] = true;
                tdsPreloginSeen_ = true;
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
        if (mode_ == Mode::Direct && consumed < buffer_.size())
        {
            const bool valid = sink({FramedMessage::Kind::Tls, Bytes(buffer_).subspan(consumed), {}});
            std::vector<uint8_t>().swap(buffer_);
            return valid;
        }
    }
    buffer_.erase(buffer_.begin(), buffer_.begin() + consumed);
    return true;
}
}
