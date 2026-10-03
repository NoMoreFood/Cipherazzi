#pragma once

#include "Engine.h"
#include "Auth.h"
#include "Crypto.h"
#include <algorithm>
#include <fstream>
#include <random>
#include <stdexcept>
#include <tuple>
#include <windows.h>

namespace Cipherazzi::Tests
{
using Buffer = std::vector<uint8_t>;
void require(bool result, const char* message);
void word(Buffer& bytes, uint16_t value);
void append(Buffer& bytes, Bytes value);
Buffer hello(bool client, uint16_t version, bool retry, bool ech, Bytes extensions);
Buffer record(Bytes payload, uint8_t type);
Buffer fromHex(const std::string& text);
Buffer ipTransport(Bytes payload, bool ipv6, bool udp = true, bool client = true);
Buffer ipFragment(Bytes datagram, bool ipv6, size_t offset, size_t length, bool more, uint16_t id = 100);

namespace NetworkFixtures
{
// Replays one TCP connection through the engine with roles learned from the handshake, delivering each message
// in turn as segments of at most the given size.
struct Message
{
    bool fromServer{};
    Buffer bytes;
};

inline std::vector<Observation> replayExchange(const std::vector<Message>& messages, uint16_t port, size_t segment,
    Counters& health)
{
    std::vector<Observation> output;
    Engine engine(health, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            output.push_back(std::move(observation));
    });
    auto packet = [port](Bytes payload, bool fromServer, uint32_t sequence, uint8_t flags = 0x18)
    {
        TransportPacket value;
        value.source.address[0] = value.destination.address[0] = 10;
        value.source.address[3] = fromServer ? 2 : 1;
        value.destination.address[3] = fromServer ? 1 : 2;
        value.source.port = fromServer ? port : 50123;
        value.destination.port = fromServer ? 50123 : port;
        value.sequence = sequence;
        value.flags = flags;
        value.payload = payload;
        return value;
    };
    engine.tcp(packet({}, false, 1000, 2), 1);
    engine.tcp(packet({}, true, 9000, 0x12), 2);
    uint32_t sequence[2]{1001, 9001};
    int64_t timestamp = 3;
    for (const auto& message : messages)
        for (size_t offset = 0; offset < message.bytes.size(); offset += segment)
        {
            const auto part = Bytes(message.bytes).subspan(offset, std::min(segment, message.bytes.size() - offset));
            engine.tcp(packet(part, message.fromServer, sequence[message.fromServer]), timestamp++);
            sequence[message.fromServer] += static_cast<uint32_t>(part.size());
        }
    engine.expire(1000000, true);
    return output;
}

inline std::vector<Observation> replayConnection(
    const Buffer& client, const Buffer& server, uint16_t port, Counters& health)
{
    return replayExchange({{false, client}, {true, server}}, port, SIZE_MAX, health);
}

inline nlohmann::json summarized(const Observation& observation)
{
    CryptoCatalog catalog;
    return nlohmann::json::parse(catalog.summarize(observation, [](auto&, auto&, Bytes) {}).json);
}

inline Buffer concat(std::initializer_list<Buffer> parts)
{
    Buffer result;
    for (const auto& part : parts)
        append(result, part);
    return result;
}

inline Buffer little(uint64_t value, size_t size)
{
    Buffer bytes;
    for (size_t index = 0; index < size; ++index)
        bytes.push_back(static_cast<uint8_t>(value >> (index * 8)));
    return bytes;
}

inline Buffer ascii(std::string_view text)
{
    return Buffer(text.begin(), text.end());
}

inline Buffer utf16(std::string_view text)
{
    Buffer bytes;
    for (const char character : text)
    {
        bytes.push_back(static_cast<uint8_t>(character));
        bytes.push_back(0);
    }
    return bytes;
}

// Definite-length DER with minimal length encoding.
inline Buffer der(uint8_t tag, const Buffer& content)
{
    Buffer result{tag};
    if (content.size() < 128)
        result.push_back(static_cast<uint8_t>(content.size()));
    else
    {
        const size_t count = content.size() > 65535 ? 3 : content.size() > 255 ? 2 : 1;
        result.push_back(static_cast<uint8_t>(0x80 | count));
        for (size_t shift = count; shift--;)
            result.push_back(static_cast<uint8_t>(content.size() >> (shift * 8)));
    }
    append(result, content);
    return result;
}

inline Buffer derInt(int64_t value)
{
    Buffer content;
    for (int shift = 56; shift >= 0; shift -= 8)
        content.push_back(static_cast<uint8_t>(value >> shift));
    while (content.size() > 1 && ((content[0] == 0 && !(content[1] & 0x80)) ||
        (content[0] == 0xff && (content[1] & 0x80))))
        content.erase(content.begin());
    return der(2, content);
}

inline Buffer context(unsigned index, const Buffer& inner)
{
    return der(static_cast<uint8_t>(0xa0 | index), inner);
}

inline Buffer sequence(std::initializer_list<Buffer> parts)
{
    return der(0x30, concat(parts));
}

inline Buffer sequenceOf(const std::vector<Buffer>& items)
{
    Buffer content;
    for (const auto& item : items)
        append(content, item);
    return der(0x30, content);
}

using Names = std::vector<std::string_view>;

inline Buffer kerberosName(const Names& parts)
{
    Buffer strings;
    for (const auto part : parts)
        append(strings, der(0x1b, ascii(part)));
    return sequence({context(0, derInt(1)), context(1, der(0x30, strings))});
}

inline Buffer kerberosEncrypted(int64_t type)
{
    return sequence({context(0, derInt(type)), context(1, derInt(3)), context(2, der(4, Buffer(32, 0x5a)))});
}

inline const Names KdcService{"krbtgt", "EXAMPLE.TEST"}, FileService{"cifs", "server.example.test"};

inline Buffer kerberosTicket(int64_t type, const Names& service)
{
    return der(0x61, sequence({context(0, derInt(5)), context(1, der(0x1b, ascii("EXAMPLE.TEST"))),
        context(2, kerberosName(service)), context(3, kerberosEncrypted(type))}));
}

inline Buffer preauthData(int64_t type, const Buffer& value)
{
    return sequence({context(1, derInt(type)), context(2, der(4, value))});
}

inline Buffer kdcRequest(bool tgs, const std::vector<int64_t>& types, const std::vector<Buffer>& padata = {},
    const Buffer& additional = {}, const Names& service = {})
{
    Buffer etypes;
    for (const auto type : types)
        append(etypes, derInt(type));
    auto body = concat({context(0, der(3, Buffer{0, 0x40, 0x81, 0, 0x10})), context(1, kerberosName({"alice"})),
        context(2, der(0x1b, ascii("EXAMPLE.TEST"))),
        context(3, kerberosName(!service.empty() ? service : tgs ? FileService : KdcService)),
        context(7, derInt(1234567)), context(8, der(0x30, etypes))});
    if (!additional.empty())
        append(body, context(11, der(0x30, additional)));
    auto fields = concat({context(1, derInt(5)), context(2, derInt(tgs ? 12 : 10))});
    if (!padata.empty())
        append(fields, context(3, sequenceOf(padata)));
    append(fields, context(4, der(0x30, body)));
    return der(tgs ? 0x6c : 0x6a, der(0x30, fields));
}

inline Buffer kdcReply(bool tgs, int64_t ticketType, int64_t replyType, const std::vector<Buffer>& padata = {})
{
    auto fields = concat({context(0, derInt(5)), context(1, derInt(tgs ? 13 : 11))});
    if (!padata.empty())
        append(fields, context(2, sequenceOf(padata)));
    append(fields, concat({context(3, der(0x1b, ascii("EXAMPLE.TEST"))), context(4, kerberosName({"alice"})),
        context(5, kerberosTicket(ticketType, tgs ? FileService : KdcService)),
        context(6, kerberosEncrypted(replyType))}));
    return der(tgs ? 0x6d : 0x6b, der(0x30, fields));
}

inline Buffer kerberosError(int64_t code, const Buffer& data = {}, bool service = true)
{
    auto fields = concat({context(0, derInt(5)), context(1, derInt(30)),
        context(4, der(0x18, ascii("20261010000000Z"))), context(5, derInt(1)), context(6, derInt(code)),
        context(9, der(0x1b, ascii("EXAMPLE.TEST")))});
    if (service)
        append(fields, context(10, kerberosName(KdcService)));
    if (!data.empty())
        append(fields, context(12, der(4, data)));
    return der(0x7e, der(0x30, fields));
}

inline Buffer apRequest(
    int64_t ticketType, int64_t authenticatorType, uint8_t options, const Names& service = FileService)
{
    return der(0x6e, sequence({context(0, derInt(5)), context(1, derInt(14)),
        context(2, der(3, Buffer{0, options, 0, 0, 0})), context(3, kerberosTicket(ticketType, service)),
        context(4, kerberosEncrypted(authenticatorType))}));
}

inline Buffer apReply(int64_t type)
{
    return der(0x6f, sequence({context(0, derInt(5)), context(1, derInt(15)), context(2, kerberosEncrypted(type))}));
}

inline Buffer privateMessage(int64_t type, int64_t messageType = 21)
{
    return der(0x75, sequence({context(0, derInt(5)), context(1, derInt(messageType)),
        context(3, kerberosEncrypted(type))}));
}

// RFC 3244 messages state their length, protocol version, and AP-REQ or AP-REP length before both parts.
inline Buffer passwordMessage(uint16_t version, const Buffer& exchange, const Buffer& protectedPart)
{
    Buffer message;
    word(message, static_cast<uint16_t>(6 + exchange.size() + protectedPart.size()));
    word(message, version);
    word(message, static_cast<uint16_t>(exchange.size()));
    append(message, exchange);
    append(message, protectedPart);
    return message;
}

// KDC and change-password messages over TCP are preceded by a four-byte length.
inline Buffer kdcFrame(const Buffer& message)
{
    Buffer frame{0, static_cast<uint8_t>(message.size() >> 16)};
    word(frame, static_cast<uint16_t>(message.size()));
    append(frame, message);
    return frame;
}

inline Buffer patched(Buffer bytes, const char* from, const char* to)
{
    const auto old = fromHex(from), replacement = fromHex(to);
    const auto found = std::search(bytes.begin(), bytes.end(), old.begin(), old.end());
    require(found != bytes.end() && old.size() == replacement.size(), "A test fixture patch pattern was missing");
    std::copy(replacement.begin(), replacement.end(), found);
    return bytes;
}

inline const char* const SpnegoOid = "2b0601050502";
inline const char* const KerberosOid = "2a864886f712010202";
inline const char* const MicrosoftKerberosOid = "2a864882f712010202";
inline const char* const NtlmOid = "2b06010401823702020a";
inline const char* const NegoExOid = "2b06010401823702021e";

inline Buffer oid(const char* hex)
{
    return der(6, fromHex(hex));
}

inline Buffer kerberosGss(uint16_t tokenId, const Buffer& message, const char* mechanism = KerberosOid)
{
    auto content = oid(mechanism);
    word(content, tokenId);
    append(content, message);
    return der(0x60, content);
}

inline Buffer negotiationInit(std::initializer_list<const char*> mechanisms, const Buffer& token = {})
{
    Buffer list;
    for (const auto* mechanism : mechanisms)
        append(list, oid(mechanism));
    auto fields = context(0, der(0x30, list));
    if (!token.empty())
        append(fields, context(2, der(4, token)));
    return der(0x60, concat({oid(SpnegoOid), context(0, der(0x30, fields))}));
}

inline Buffer negotiationResponse(int state, const char* mechanism, const Buffer& token = {}, bool mic = false)
{
    Buffer fields;
    if (state >= 0)
        append(fields, context(0, der(0x0a, Buffer{static_cast<uint8_t>(state)})));
    if (mechanism)
        append(fields, context(1, oid(mechanism)));
    if (!token.empty())
        append(fields, context(2, der(4, token)));
    if (mic)
        append(fields, context(3, der(4, Buffer(16, 0x33))));
    return context(1, der(0x30, fields));
}

inline const Buffer NtlmSignature{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

// Security buffer descriptors reference payload that follows the fixed header.
inline void ntlmField(Buffer& message, Buffer& payload, size_t header, const Buffer& value)
{
    append(message, little(value.size(), 2));
    append(message, little(value.size(), 2));
    append(message, little(header + payload.size(), 4));
    append(payload, value);
}

inline Buffer ntlmType1(uint32_t flags)
{
    auto message = concat({NtlmSignature, little(1, 4), little(flags, 4)});
    Buffer payload;
    ntlmField(message, payload, 40, {});
    ntlmField(message, payload, 40, {});
    append(message, Buffer(8, 0));
    return message;
}

inline Buffer ntlmType2(uint32_t flags, const Buffer& targetInfo, bool version = true)
{
    const size_t header = version ? 56 : 48;
    auto message = concat({NtlmSignature, little(2, 4)});
    Buffer payload;
    ntlmField(message, payload, header, utf16("SERVER"));
    append(message, concat({little(flags, 4), Buffer(8, 0x77), Buffer(8, 0)}));
    ntlmField(message, payload, header, targetInfo);
    if (version)
        append(message, Buffer(8, 0));
    append(message, payload);
    return message;
}

inline Buffer ntlmType3(uint32_t flags, const Buffer& lm, const Buffer& nt, std::string_view user = "someone",
    bool sessionKey = true, size_t header = 88)
{
    auto message = concat({NtlmSignature, little(3, 4)});
    Buffer payload;
    ntlmField(message, payload, header, lm);
    ntlmField(message, payload, header, nt);
    ntlmField(message, payload, header, utf16("DOMAIN"));
    ntlmField(message, payload, header, utf16(user));
    ntlmField(message, payload, header, utf16("WORKSTATION"));
    ntlmField(message, payload, header, sessionKey ? Buffer(16, 0x44) : Buffer{});
    append(message, little(flags, 4));
    message.resize(header, 0);
    append(message, payload);
    return message;
}

inline Buffer avPair(uint16_t id, const Buffer& value)
{
    return concat({little(id, 2), little(value.size(), 2), value});
}

inline Buffer attributeList(const Buffer& pairs)
{
    return concat({pairs, avPair(0, {})});
}

inline Buffer ntlmV2Response(const Buffer& pairs, size_t trailing = 0, uint8_t type = 1)
{
    return concat({Buffer(16, 0x11), Buffer{type, 1, 0, 0, 0, 0, 0, 0}, Buffer(8, 0x22), Buffer(8, 0x33),
        Buffer(4, 0), attributeList(pairs), Buffer(trailing, 0)});
}

inline Buffer smb2Frame(uint16_t command, bool response, uint32_t status, const Buffer& body)
{
    auto message = concat({Buffer{0xfe, 'S', 'M', 'B'}, little(64, 2), little(0, 2), little(status, 4),
        little(command, 2), little(1, 2), little(response ? 1 : 0, 4), little(0, 4), little(7, 8), little(0, 8),
        little(0x1234, 8), Buffer(16, 0)});
    append(message, body);
    Buffer frame{0, static_cast<uint8_t>(message.size() >> 16)};
    word(frame, static_cast<uint16_t>(message.size()));
    append(frame, message);
    return frame;
}

inline Buffer negotiateResponse(const Buffer& security)
{
    auto body = concat({little(65, 2), little(1, 2), little(0x0210, 2), little(0, 2), Buffer(16, 9), little(7, 4),
        little(65536, 4), little(65536, 4), little(65536, 4), Buffer(16, 0), little(128, 2),
        little(security.size(), 2), little(0, 4)});
    append(body, security);
    return smb2Frame(0, true, 0, body);
}

inline Buffer sessionSetupRequest(const Buffer& security, uint16_t structure = 25, uint16_t offset = 88)
{
    auto body = concat({little(structure, 2), Buffer{0, 1}, little(0, 4), little(0, 4), little(offset, 2),
        little(security.size(), 2), little(0, 8)});
    append(body, security);
    return smb2Frame(1, false, 0, body);
}

inline Buffer sessionSetupResponse(uint32_t status, uint16_t flags, const Buffer& security, size_t declared = SIZE_MAX,
    uint16_t offset = 72)
{
    auto body = concat({little(9, 2), little(flags, 2), little(offset, 2),
        little(declared == SIZE_MAX ? security.size() : declared, 2)});
    append(body, security);
    return smb2Frame(1, true, status, body);
}

// Recorded exchanges: an MIT Kerberos KDC and a Samba SMB2 server (NTLMv2 logon with MIC), as sent on the wire.
struct Recorded
{
    Buffer asRequest, preauthRequired, tgsRequest, kerberoastReply, negotiateToken, ntlmNegotiate, ntlmChallenge,
        ntlmAuthenticate, sessionFinal;
};

inline const Recorded& recordedVectors()
{
    static const Recorded value{
        fromHex(
            "000000b96a81b63081b3a103020105a20302010aa31a3018300aa10402020096a2020400300aa10402020095a2020400a4"
            "818a308187a00703050000000010a1123010a003020101a10930071b05616c696365a20e1b0c4558414d504c452e544553"
            "54a321301fa003020102a11830161b066b72627467741b0c4558414d504c452e54455354a511180f323032363130313032"
            "33353131305aa70602044646428ba81a301802011202011102011402011302011002011702011902011a"),
        fromHex(
            "000000ed7e81ea3081e7a003020105a10302011ea411180f32303236313030393233353132345aa50502030be900a60302"
            "0119a70e1b0c4558414d504c452e54455354a8123010a003020101a10930071b05616c696365a90e1b0c4558414d504c45"
            "2e54455354aa21301fa003020102a11830161b066b72627467741b0c4558414d504c452e54455354ab101b0e4e45454445"
            "445f50524541555448ac530451304f300aa10402020088a20204003027a103020113a220041e301c301aa003020112a113"
            "1b114558414d504c452e54455354616c6963653009a103020102a2020400300da10402020085a20504034d4954"),
        fromHex(
            "000003f06c8203ec308203e8a103020105a20302010ca38203683082036430820284a103020101a282027b048202776e82"
            "02733082026fa003020105a10302010ea20703050000000000a382019c6182019830820194a003020105a10e1b0c455841"
            "4d504c452e54455354a221301fa003020102a11830161b066b72627467741b0c4558414d504c452e54455354a382015830"
            "820154a003020112a103020101a2820146048201423c5f75e83be4c33719a8efa392d89247d4a07ce0c67dc0bba92d40f0"
            "46f98856fb7027252c5e63a923758c13f8ea1715b00aee4deade1adaa30d7bfd357d11d027dba9f8205a27e629b8af05f9"
            "c17d6e5b15ae3a1a6c73197a1a0445ca2b249ee3e46971e1d6c0aa06cc351531046a01e7edc3f510636d717b44af4d7902"
            "579e8032065fc5b7523653de685b34cf7c8081d85388a58bfde13a6c90b87052997b89dbddd05ed4e20984cb73bdb60e0e"
            "75e61651f2baaa06fa8a633e272cf4b445a1aea5ff5ad8a349bade4749a42b05a88fc77e2791f0204860cef71adac17d52"
            "c77f2ec82ecc6530d047eac3ddc3d64b84e58065a9822b3ff04d7f694129da0d8b68c951a0e57a15303b787577d0986908"
            "6d0bbc660be2b0b79a559c26be8d829ed8fdea25cde24472fbefeceb11e2d53351ffcde29edf9d15806026fffc9ed2eb2e"
            "a481b93081b6a003020112a281ae0481aba0abad31aee3a50c4fe9a04bfd70a1a9e9b9b2ed9d77ac2879eafb26f8380e93"
            "a08713556e6d10db0f38c323c3f749b22060fc868e316819a0b432319a211f64a5af078027b1157ad03602f669b0ab5e79"
            "e1b3ed36a8f47765e656ab34a67be87b7014a7a53444c6c474f66f4b21ce15c0c07dc425304e2f973c9e24f4faf8cc8d1e"
            "5604ddc1f6cdb43d92c0559a70a7d66da87c48a799e76c64d4c3fd5500bd4af572799b8be8bd2e9cda3081d9a104020200"
            "88a281d00481cda081ca3081c7a1173015a003020110a10e040cde5044f4a2fda4d9584c9b4ea281ab3081a8a003020112"
            "a281a004819d1b48b173f3dc8897f675ba29452f9d74a9e64f4e7fa9dbdad6d9d5d75dc86f3ababe395f7a44ae0052a492"
            "5546f5b64af117f72f97f79fac22104fd4c399ad30c2b9a93e577c3af81e064c35d0ae70d19d52c0e7343b1366141d8db6"
            "c1c23aa7cf03022982e5a82add3be2f6d3e831792c1b4060351288a8051db6abe4330c9b03007819406c11b479e1245561"
            "22cbb2b0bbfe63956506db772eace107a470306ea00703050000010000a20e1b0c4558414d504c452e54455354a31c301a"
            "a003020101a11330111b04636966731b096c6f63616c686f7374a511180f32303236313031303233353231375aa7060204"
            "379ca82fa81a301802011202011102011402011302011002011702011902011a"),
        fromHex(
            "000003d06d8203cc308203c8a003020105a10302010da281dc3081d93081d6a10402020088a281cd0481caa081c73081c4"
            "a081c13081bea003020112a281b60481b34b0d997331c21def43d9c3745a1ad1e99ad8470f1c3b1390058b5c6c32b9753d"
            "8a6987d5ed7024d6dec5ad8205bcd2be3870bbbdeee6a691a7fde71257125d37f21aba3971aa13446e686f472e5c24d4e7"
            "d68eb9497ff5a443b16396d0f5e31b3f65803f028f20691282ba7359bb41a3b450e4e0f777ffc5ad0a25e6172f0eb60cde"
            "3a2961842f69a91c48d169026bf50bfc583cf1cafe6d7b0920ae15f5c31d9c3ca3c7c9f11c407724f14f5c7d753efa6bf9"
            "a30e1b0c4558414d504c452e54455354a4123010a003020101a10930071b05616c696365a58201ca618201c6308201c2a0"
            "03020105a10e1b0c4558414d504c452e54455354a2263024a003020101a11d301b1b04686f73741b137263347376632e65"
            "78616d706c652e74657374a38201813082017da003020117a103020101a282016f0482016b12e277e3ecafcd71112501d4"
            "362ad9e28852bfecccc1c90b968636abd0386caa8ff9e47cf245aaa2325a396139fdfc7d5d1fdda01051fbdbaa16329f42"
            "a4dd08fa240f7b182c22392d31cf791d6c86d6a51e0f587ea74c589f0df766c722f030c388679fc84d66b106cfc976ef3e"
            "996ed154b80135ec69317e4691a5e5194df73f01f6f67cfcdc60b044e92058075acdeff98601430b1e7eab83e9d66df0bf"
            "1ccc9543a2efa5278db521593a9059a8960db7d93802862c2063a111b0bb7ccb40fdd5b29fd34450e8b2c350a2dd29fcd1"
            "52326aa73a43fcb37af0023966a6c884b12f85792020e2c4db5055db2bd590aecccec5065f759577aa2270a1a32c51d8eb"
            "5a61761d7a223e63b541bc9813b9c0db1de8699d2739d929cac4e1bce47bd79b7ae3122da4903c4bf1e0db6b868b9e7a60"
            "851d6f1a5386849a61b33b8f689d84f89b0cf0765f623a224612132d6240b0e0635a37afe0cf662bcd6e34a54c9e9948c4"
            "fea228514179c52ba681ea3081e7a003020112a281df0481dc4e7629a985ceb90a0eb52e41792fa1e0b7f8e490c89059b6"
            "cf84d92d4e783baff4ab5e5acb396069dab722601ebee784275d1b19400b73c3999216e3703b32e1425cc8c5d6f495f728"
            "41be590bae187f8346ba5d7abba5f36e8dd37615e43acd01f83159a4a50fe871ea37db54b3e85ea262ede0ec0a4ba0f800"
            "e48fd21deecc2129258b2e80fac775c6bce18547c1dca7ab84ba91e6ab868ff43524a54aee9b9ce7143532693a80cb7f0b"
            "e9dbe95072f8147037397b2ff1b30a4314bfaa8c3849d70c41c9252ef427c59a329472efe6a2f4491b1008c266effbf227"),
        fromHex(
            "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e6564"
            "5f696e5f5246433431373840706c656173655f69676e6f7265"),
        fromHex(
            "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000158208"
            "6200000000280000000000000028000000060100000000000f"),
        fromHex(
            "a18181307fa0030a0101a10c060a2b06010401823702020aa26a04684e544c4d5353500002000000040004003800000015"
            "828a62ee340552f90ba10700000000000000002c002c003c000000060100000000000f56004d000200040056004d000100"
            "040056004d00040000000300040076006d0007000800f868ba594958dd0100000000"),
        fromHex(
            "a182018830820184a282016c048201684e544c4d53535000030000001800180058000000c800c800700000000e000e0038"
            "0100000e000e00460100000400040054010000100010005801000015820862060100000000000fd327069c6fddb85eb4dd"
            "53cb144fe11f00000000000000000000000000000000000000000000000016bed43b34365fb9f0a6ffc3180a232c010100"
            "0000000000f868ba594958dd01d323eaad736575e6000000000200040056004d000100040056004d000400000003000400"
            "76006d0007000800f868ba594958dd01060004000200000008003000300000000000000000000000000000002e70b67a5e"
            "83adfdaaa3277864ec56bc31b29d1ba1ee1f39b98239aa27a112510a001000000000000000000000000000000000000900"
            "1c0063006900660073002f003100320037002e0030002e0030002e00310000000000540045005300540047005200500073"
            "006d006200750073006500720056004d00e5593b35d2acf5ea96e39c192621b740a3120410010000003ff2f919270439aa"
            "00000000"),
        fromHex(
            "a11b3019a0030a0100a312041001000000ad00516c3edac27200000000")};
    return value;
}

struct Outcome
{
    bool valid{true}, finished{};
    std::vector<nlohmann::json> reports;
    std::vector<FramedMessage::Kind> kinds;
    size_t passthrough{}, memory{};
    bool limited{};
};

inline Outcome observe(const Buffer& bytes, bool split)
{
    FramedStream framing;
    Outcome outcome;
    auto sink = [&](const FramedMessage& message)
    {
        if (message.fields.empty())
            outcome.passthrough += message.payload.size();
        else
        {
            outcome.reports.push_back(message.fields);
            outcome.kinds.push_back(message.kind);
        }
        return true;
    };
    if (split)
        for (size_t offset = 0; outcome.valid && offset < bytes.size(); ++offset)
            outcome.valid = framing.feed(Bytes(bytes).subspan(offset, 1), sink);
    else
        outcome.valid = framing.feed(bytes, sink);
    outcome.finished = framing.finished();
    outcome.memory = framing.memory();
    outcome.limited = framing.limited();
    return outcome;
}

inline nlohmann::json securityEvidence(const Buffer& token, bool response)
{
    nlohmann::json fields = nlohmann::json::object();
    parseSecurityBuffer(token, response, fields);
    return fields;
}

inline nlohmann::json ntlmEvidence(const Buffer& message, bool response, const char* name)
{
    const auto fields = securityEvidence(message, response);
    require(fields.size() == 1 && fields.contains(name), "An NTLM message produced unexpected evidence");
    return fields[name];
}

inline bool undecoded(const Buffer& token, bool response)
{
    const auto fields = securityEvidence(token, response);
    return fields == nlohmann::json{{"spnego_token_undecoded", true}};
}
}
}
