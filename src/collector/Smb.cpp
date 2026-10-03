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
namespace SmbDetail
{
constexpr size_t FramingLimit = 262144;
constexpr char NoResponse[] = "not a challenge response";

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

// SMB1 is retained as public NEGOTIATE and SESSION_SETUP evidence; its other messages are framed without being read.
bool smbLegacy(Bytes bytes, nlohmann::json& fields)
{
    constexpr size_t HeaderSize = 32;
    if (bytes.size() < HeaderSize + 3)
        return false;

    // The header flag reports signed traffic for every SMB1 command, including commands not decoded below.
    if (little16(bytes, 10) & 4)
        fields["smb_signed_message_observed"] = true;
    const bool response = (bytes[9] & 0x80) != 0, setup = bytes[4] == 0x73;
    const auto status = little32(bytes, 5);
    if ((bytes[4] != 0x72 && !setup) || (!setup && response && status != 0))
        return true;

    // Parameters and data must lie within the frame before their values are exposed; only a session setup chains on.
    const size_t words = bytes[HeaderSize];
    if (bytes.size() < HeaderSize + 3 + words * 2)
        return false;
    const auto parameters = bytes.subspan(HeaderSize + 1, words * 2);
    const size_t dataSize = little16(bytes, HeaderSize + 1 + words * 2);
    auto data = bytes.subspan(HeaderSize + 3 + words * 2);
    if (setup ? data.size() < dataSize : data.size() != dataSize)
        return false;
    data = data.first(dataSize);

    // A session setup reply reports its status and guest logon as sent, keeping an NT status apart from a DOS error.
    if (setup && response)
    {
        if (!status || (little16(bytes, 10) & 0x4000))
            fields["smb_session_setup_status"] = hex32(status);
        else
            fields["smb_legacy_session_setup_error"] = "DOS class " + std::to_string(bytes[5]) + ", code " +
                std::to_string(little16(bytes, 7));
        if ((status && status != 0xc0000016) || (words != 3 && words != 4))
            return true;
        if (!status)
            fields["smb_session_guest"] = (little16(parameters, 4) & 1) != 0;
        const size_t blob = words == 4 ? little16(parameters, 6) : 0;
        if (blob > data.size())
            return false;
        parseSecurityBuffer(data.first(blob), true, fields);
        return true;
    }

    // An extended-security request carries the security blob SMB2 uses; older layouts carry the password fields.
    if (setup)
    {
        if (words != 10 && words != 12 && words != 13)
            return true;
        const size_t first = little16(parameters, 14), second = words == 13 ? little16(parameters, 16) : 0;
        if (first + second > data.size())
            return false;
        if (words == 12)
        {
            parseSecurityBuffer(data.first(first), false, fields);
            return true;
        }

        // Only each field's form is kept: a challenge response has a fixed shape, and anything else is a password.
        const auto insensitive = data.first(first), sensitive = data.subspan(first, second);
        const bool version2 = sensitive.size() >= 48 && sensitive[16] == 1 && sensitive[17] == 1;
        const bool blank = insensitive.empty() || (insensitive.size() == 1 && !insensitive[0]);
        const char* nt = sensitive.empty() ? "absent" : sensitive.size() == 24 ? "NTLMv1" :
            version2 ? "NTLMv2" : NoResponse;
        const char* lm = blank ? "absent" : insensitive.size() != 24 ? NoResponse :
            std::ranges::none_of(insensitive, [](uint8_t value) { return value != 0; }) ? "zero-filled" :
            std::ranges::equal(insensitive, sensitive) ? "same as NT response" : version2 ? "LMv2" : "LM";

        // The account name follows the passwords, aligned to an even offset when strings are Unicode.
        const bool unicode = (little16(bytes, 10) & 0x8000) != 0;
        const size_t account = first + second +
            (unicode && (HeaderSize + 3 + words * 2 + first + second) % 2 ? 1 : 0);
        const bool named = account < data.size() &&
            (data[account] || (unicode && account + 1 < data.size() && data[account + 1]));
        fields["smb_legacy_session_setup"] = {{"case_insensitive_password_bytes", first},
            {"case_sensitive_password_bytes", second}, {"case_insensitive_form", lm}, {"case_sensitive_form", nt},
            {"account_named", named}};
        return true;
    }

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

// SESSION_SETUP carries the SPNEGO exchange; status and session flags are reported as sent, not as proof of
// authentication.
bool smbSessionSetup(Bytes bytes, bool response, nlohmann::json& fields)
{
    const auto status = little32(bytes, 8);
    size_t offset, length;
    if (response)
    {
        fields["smb_session_setup_status"] = hex32(status);

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

    // An empty buffer has no meaningful offset.
    if (!length)
        return true;
    if (offset < (response ? 72u : 88u) || offset > bytes.size() || length > bytes.size() - offset)
        return false;
    parseSecurityBuffer(bytes.subspan(offset, length), response, fields);
    return true;
}

// Decode compressed framing within the same bound as ordinary SMB messages; retain no file payload.
bool smbCompressed(Bytes bytes, nlohmann::json& fields, bool& limited)
{
    // Validate compression envelopes and bound every decompressed segment before inspecting SMB.
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

// READ/WRITE channel metadata describes protected RDMA payloads without exposing buffer tokens or file data.
bool smbChannel(Bytes bytes, bool write, nlohmann::json& fields)
{
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

// NEGOTIATE states each peer's dialects and signing requirements, and for SMB 3.1.1 its negotiation contexts.
bool smbNegotiate(Bytes bytes, bool response, nlohmann::json& fields)
{
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

bool smb(Bytes bytes, nlohmann::json& fields, bool& limited)
{
    if (bytes.size() < 4 || bytes[1] != 'S' || bytes[2] != 'M' || bytes[3] != 'B')
        return false;
    if (bytes[0] == 0xff)
        return smbLegacy(bytes, fields);

    if (bytes[0] == 0xfc)
        return smbCompressed(bytes, fields, limited);
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

    if ((command == 9 && !response) || (command == 8 && response))
        return smbChannel(bytes, command == 9, fields);
    return command != 0 || smbNegotiate(bytes, response, fields);
}

}
using namespace SmbDetail;

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

}
