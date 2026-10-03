#include "NetworkFixtures.h"

namespace Cipherazzi::Tests
{
using namespace NetworkFixtures;

// Standard RDP Security states its encryption choice in cleartext MCS Connect PDUs; TLS flows are unaffected.
void rdpStandardCoverage()
{
    // Recorded xrdp and FreeRDP exchange: Standard Security, 128-bit RC4, and a proprietary 2048-bit RSA key.
    const auto clientRequest = fromHex(
        "030000241fe00000000000436f6f6b69653a206d737473686173683d6e6f626f64790d0a");
    const auto serverConfirm = fromHex(
        "0300000b06d00000123400");
    const auto negotiatedRequest = fromHex(
        "0300002c27e00000000000436f6f6b69653a206d737473686173683d6e6f626f64790d0a0100080003000000");
    const auto negotiatedConfirm = fromHex(
        "030000130ed000001234000201080000000000");
    const auto connectInitial = fromHex(
        "030001c302f0807f658201b70401010401010101ff301a020122020102020100020101020100020101020300ffff0201"
        "023019020101020101020101020101020100020101020204200201023020020300ffff020300fc17020300ffff020101"
        "020100020101020300ffff02010204820151000500147c00018148000800100001c00044756361813a01c0ea000c0008"
        "000004000301ca03aa09040000bb47000076006d00000000000000000000000000000000000000000000000000000000"
        "0004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000001ca01000000000018000f00e3050000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000007000000000000000000000000000000000000000000000004c00c000d0000000000000002"
        "c00c001b0000000000000003c03800040000007264706472000000000080c0726470736e640000000000c0636c697072"
        "6472000000a0c0647264796e766300000080c0");
    const auto connectResponse = fromHex(
        "0300020d02f0807f668202010a0100020100301a020116020103020100020101020100020101020300fff80201020482"
        "01db000500147c00012a14760a01010001c0004d63446e81c4010c080004000800030c1000eb030400ec03ed03ee03ef"
        "03020cac01020000000300000020000000780100004b842dbf8ed1d8c776e65ff96641a4f97ef18fd9ac67b4f95a0af2"
        "0af12822be01000000010000000100000006001c01525341310801000000080000ff00000001000100dd34cd9e77fbfc"
        "0e738ba6b51f109eb5ff936e2e7299ce6b44310c4c07b58609b6eff3e032e1f766e33c026c29552a9ef87955fd322def"
        "c93119d3467cecbd49052ed0f23e9d8ecd2a26f35b67eb4b51211429696a07e3e5de022438a86137a18e0c6c3aca0f88"
        "b88062ef38835d9dd3ed43c169cfe43a3d5653a061396422d1eaa127389a1e6b9bca8d71d20454c3d62cd98193d878e6"
        "5c001c950d3b331fbea95d25a6501ca78174d15d6d9253368654c371a298b6f5f7f2d3b260c841bd2a7e1368ffd6c07f"
        "67a68f047e11a63254cc0cfa7c3f1ab57234c9b2a71989bc4a179e7dd256d87b70bfcbd546ab23e8420754f8472a6b1a"
        "7b03191de0e8d66aba000000000000000008004800ab86d368e337c00c48758c9963078083dbe9e9af510e188b5197fe"
        "bf409c2c4e8b97a86aa759a6033e41ce55a6e4fabe1f4dff9e01635ea3b3046980bfbfbc470000000000000000");
    Buffer securityExchange{3, 0, 0, 94, 2, 0xf0, 0x80, 0x64, 0, 6, 3, 0xeb, 0x70, 0x50,
        1, 2, 0, 0, 72, 0, 0, 0};
    securityExchange.insert(securityExchange.end(), 64, 0x42);
    securityExchange.insert(securityExchange.end(), 8, 0);
    struct Outcome
    {
        std::vector<nlohmann::json> reports;
        size_t tlsBytes{}, memory{};
        bool valid{}, finished{};
    };
    auto run = [](const Buffer& bytes, bool split)
    {
        FramedStream framing;
        Outcome outcome;
        auto sink = [&](const FramedMessage& message)
        {
            if (message.kind == FramedMessage::Kind::Rdp)
                outcome.reports.push_back(message.fields);
            else
                outcome.tlsBytes += message.payload.size();
            return true;
        };
        outcome.valid = true;
        if (split)
            for (size_t offset = 0; outcome.valid && offset < bytes.size(); ++offset)
                outcome.valid = framing.feed(Bytes(bytes).subspan(offset, 1), sink);
        else
            outcome.valid = framing.feed(bytes, sink);
        outcome.finished = framing.finished();
        outcome.memory = framing.memory();
        return outcome;
    };
    auto join = [](Buffer first, const Buffer& second)
    {
        append(first, second);
        return first;
    };
    const nlohmann::json expectedRequest{
        {"rdp_client_encryption_methods", {"RC4 40-bit", "RC4 128-bit", "RC4 56-bit", "FIPS 3DES"}},
        {"rdp_mcs_connect_request_observed", true}};
    const nlohmann::json expectedResponse{
        {"rdp_mcs_connect_response_observed", true}, {"rdp_server_certificate_type", "Proprietary"},
        {"rdp_server_encryption_level", "High"}, {"rdp_server_encryption_method", "RC4 128-bit"},
        {"rdp_server_key_bits", 2048}};
    for (const bool split : {false, true})
    {
        // The client continues through its Security Exchange PDU after MCS, while the server stops at MCS.
        const char* const clientFault = "RDP Standard Security client evidence was lost or retained storage";
        const char* const serverFault = "RDP Standard Security server evidence was lost or retained storage";
        for (const auto& [x224, mcs, expected, fault] : {
            std::tuple{clientRequest, connectInitial, expectedRequest, clientFault},
            {negotiatedRequest, connectInitial, expectedRequest, clientFault},
            {serverConfirm, connectResponse, expectedResponse, serverFault},
            {negotiatedConfirm, connectResponse, expectedResponse, serverFault}})
        {
            auto stream = join(x224, mcs);
            if (x224 == clientRequest || x224 == negotiatedRequest)
                append(stream, securityExchange);
            const auto outcome = run(stream, split);
            const bool client = x224 == clientRequest || x224 == negotiatedRequest;
            require(outcome.valid && outcome.reports.size() == (client ? 3u : 2u) &&
                outcome.reports[1] == expected &&
                (!client || (outcome.reports[2].value("rdp_client_security_exchange_observed", false) &&
                    outcome.reports[2]["rdp_encrypted_client_random_bytes"] == 64)) &&
                outcome.finished && outcome.memory == 0 && outcome.tlsBytes == 0, fault);
        }
    }
    {
        auto malformed = securityExchange;
        malformed[18] = 71;
        const auto outcome = run(join(join(clientRequest, connectInitial), malformed), false);
        require(!outcome.valid && outcome.reports.size() == 2,
            "An RDP Security Exchange PDU with an inconsistent random length was accepted");
    }
    {
        const auto negotiated = run(join(negotiatedConfirm, connectResponse), false);
        require(negotiated.reports[0]["rdp_selected_protocol"] == 0 &&
            !negotiated.reports[0].contains("rdp_server_encryption_method"),
            "A selected Standard RDP Security protocol was merged into MCS evidence");

        // A negotiation failure ends the connection attempt, so nothing further is inspected.
        const Buffer failure{3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 3, 0, 8, 0, 5, 0, 0, 0};
        const auto failed = run(failure, true);
        require(failed.valid && failed.reports.size() == 1 && failed.reports[0]["rdp_failure_code"] == 5 &&
            failed.finished && failed.memory == 0, "An RDP negotiation failure continued inspection");

        // A legacy X.224 response without negotiation waits for the MCS PDU before releasing inspection storage.
        FramedStream legacy;
        require(legacy.feed(serverConfirm, [](const FramedMessage&) { return true; }) && !legacy.finished(),
            "A legacy X.224 response ended inspection before the MCS PDU");
        require(legacy.feed(connectResponse, [](const FramedMessage&) { return true; }) && legacy.finished() &&
            legacy.memory() == 0, "Legacy RDP MCS traffic retained inspection storage");
    }

    // Enhanced security continues with TLS in both directions and never reaches the MCS parser.
    for (const auto& x224 : {clientRequest, negotiatedRequest, serverConfirm, negotiatedConfirm})
    {
        const Buffer tlsStart{0x16, 3, 1, 0, 5, 1, 2, 3, 4, 5};
        const auto outcome = run(join(x224, tlsStart), true);
        require(
            outcome.valid && outcome.reports.size() == 1 && outcome.tlsBytes == tlsStart.size() && !outcome.finished,
            "TLS after an X.224 exchange was withheld or parsed as MCS");
    }

    // Assemble MCS PDUs around chosen user-data blocks to cover selections absent from the recordings.
    auto littleWord = [](Buffer& bytes, uint32_t value, int count)
    {
        for (int index = 0; index < count; ++index)
            bytes.push_back(static_cast<uint8_t>(value >> (index * 8)));
    };
    auto block = [&](uint16_t type, const Buffer& data)
    {
        Buffer result;
        littleWord(result, type, 2);
        littleWord(result, static_cast<uint32_t>(data.size() + 4), 2);
        append(result, data);
        return result;
    };
    auto ber = [](Buffer prefix, const Buffer& value)
    {
        prefix.push_back(0x82);
        word(prefix, static_cast<uint16_t>(value.size()));
        append(prefix, value);
        return prefix;
    };
    auto per = [](Buffer& bytes, size_t length)
    {
        word(bytes, static_cast<uint16_t>(0x8000 | length));
    };
    auto wrap = [&](bool request, const Buffer& content)
    {
        Buffer payload{2, 0xf0, 0x80, 0x7f, static_cast<uint8_t>(request ? 0x65 : 0x66)};
        append(payload, ber({}, content));
        Buffer result{3, 0};
        word(result, static_cast<uint16_t>(payload.size() + 4));
        append(result, payload);
        return result;
    };
    const Buffer requestHead{4, 1, 1, 4, 1, 1, 1, 1, 0xff, 0x30, 0, 0x30, 0, 0x30, 0};
    const Buffer responseHead{0x0a, 1, 0, 2, 1, 0, 0x30, 0};
    auto pdu = [&](bool request, const Buffer& userData)
    {
        auto content = request ? requestHead : responseHead;
        append(content, ber({4}, userData));
        return wrap(request, content);
    };
    auto gcc = [&](bool request, const Buffer& blocks, std::ptrdiff_t adjust = 0)
    {
        Buffer data{0, 5, 0, 0x14, 0x7c, 0, 1, 0x2a};
        if (request)
            data = {0, 5, 0, 0x14, 0x7c, 0, 1, 0x2a, 0, 8, 0, 0x10, 0, 1, 0xc0, 0, 'D', 'u', 'c', 'a'};
        else
            append(data, Buffer{0x14, 0x76, 0x0a, 1, 1, 0, 1, 0xc0, 0, 'M', 'c', 'D', 'n'});
        per(data, static_cast<size_t>(static_cast<std::ptrdiff_t>(blocks.size()) + adjust));
        append(data, blocks);
        return data;
    };
    auto serverBlock = [&](uint32_t method, uint32_t level, const Buffer& certificate)
    {
        Buffer data;
        littleWord(data, method, 4);
        littleWord(data, level, 4);
        if (method || level)
        {
            littleWord(data, 32, 4);
            littleWord(data, static_cast<uint32_t>(certificate.size()), 4);
            data.insert(data.end(), 32, 0x55);
            append(data, certificate);
        }
        return block(0x0c02, data);
    };
    auto proprietary = [&](uint32_t bits, uint32_t keyLength)
    {
        Buffer certificate;
        for (const uint32_t value : {1u, 1u, 1u})
            littleWord(certificate, value, 4);
        littleWord(certificate, 6, 2);
        littleWord(certificate, keyLength + 20, 2);
        append(certificate, Buffer{'R', 'S', 'A', '1'});
        for (const uint32_t value : {keyLength, bits, keyLength - 1, 65537u})
            littleWord(certificate, value, 4);
        certificate.insert(certificate.end(), keyLength, 0xaa);
        append(certificate, Buffer{8, 0, 4, 0, 1, 2, 3, 4});
        return certificate;
    };
    auto chain = [&](uint32_t count)
    {
        Buffer certificate;
        littleWord(certificate, 2, 4);
        littleWord(certificate, count, 4);
        for (uint32_t index = 0; index < count; ++index)
        {
            littleWord(certificate, 6, 4);
            certificate.insert(certificate.end(), 6, 0x30);
        }
        return certificate;
    };
    auto response = [&](const Buffer& blocks) { return join(serverConfirm, pdu(false, gcc(false, blocks))); };
    auto request = [&](const Buffer& blocks) { return join(clientRequest, pdu(true, gcc(true, blocks))); };
    auto second = [&](const Outcome& outcome)
    { return outcome.reports.size() == 2 ? outcome.reports[1] : nlohmann::json{}; };

    // Method and level are reported as selected; unknown values retain their numeric identity.
    for (const auto& [method, level, methodName, levelName] : {
        std::tuple{1u, 1u, "RC4 40-bit", "Low"}, {1u, 2u, "RC4 40-bit", "Client compatible"},
        {8u, 3u, "RC4 56-bit", "High"}, {0x10u, 4u, "FIPS 3DES", "FIPS"}, {2u, 2u, "RC4 128-bit", "Client compatible"},
        {4u, 3u, "0x00000004", "High"}, {2u, 5u, "RC4 128-bit", "0x00000005"}, {2u, 9u, "RC4 128-bit", "0x00000009"},
        {0u, 3u, "None", "High"}})
    {
        const auto outcome = run(response(serverBlock(method, level, proprietary(1024, 136))), true);
        const auto fields = second(outcome);
        require(outcome.valid && fields["rdp_server_encryption_method"] == methodName &&
            fields["rdp_server_encryption_level"] == levelName && fields["rdp_server_key_bits"] == 1024,
            "RDP server encryption selection was misreported");
    }
    {
        // Enhanced security reports neither encryption nor key material in the MCS response.
        const auto fields = second(run(response(serverBlock(0, 0, {})), false));
        require(fields["rdp_server_encryption_method"] == "None" && fields["rdp_server_encryption_level"] == "None" &&
            !fields.contains("rdp_server_certificate_type"), "Enhanced-security MCS evidence implied key material");

        // Other blocks and X.509 chains do not displace the security selection.
        auto blocks = block(0x0c01, Buffer{4, 0, 8, 0});
        append(blocks, serverBlock(2, 3, chain(2)));
        append(blocks, block(0x0c03, Buffer{0xeb, 3, 0, 0}));
        const auto chained = second(run(response(blocks), true));
        require(chained["rdp_server_certificate_type"] == "X.509 chain" &&
                chained["rdp_server_certificate_count"] == 2 && !chained.contains("rdp_server_key_bits") &&
                chained["rdp_server_encryption_method"] == "RC4 128-bit",
            "An RDP X.509 certificate chain was misreported");

        // The most significant version bit marks a temporary certificate and does not change its layout.
        auto temporary = proprietary(2048, 264);
        temporary[3] = 0x80;
        auto temporaryChain = chain(1);
        temporaryChain[3] = 0x80;
        const auto marked = second(run(response(serverBlock(2, 3, temporary)), false));
        const auto markedChain = second(run(response(serverBlock(2, 3, temporaryChain)), false));
        require(marked["rdp_server_certificate_type"] == "Proprietary" && marked["rdp_server_key_bits"] == 2048 &&
                markedChain["rdp_server_certificate_type"] == "X.509 chain" &&
                markedChain["rdp_server_certificate_count"] == 1,
            "A temporary RDP certificate was not recognized");

        // A damaged or unrecognized certificate withholds key metadata without discarding the selection.
        auto damagedProprietary = [&](size_t offset, uint8_t value)
        {
            auto certificate = proprietary(2048, 264);
            certificate[offset] = value;
            return certificate;
        };
        auto truncated = proprietary(2048, 264);
        truncated.resize(100);
        auto keyLength = proprietary(2048, 264);
        keyLength[20] ^= 1;
        auto oversizedEntry = chain(2);
        oversizedEntry[8] = 0xff;
        auto truncatedChain = chain(2);
        truncatedChain.resize(20);
        for (const auto& certificate : {damagedProprietary(16, 'X'), damagedProprietary(0, 3), damagedProprietary(4, 2),
                 damagedProprietary(8, 2), damagedProprietary(12, 7), proprietary(2048, 100), proprietary(0, 264),
                 truncated, keyLength, oversizedEntry, truncatedChain, chain(0), chain(33), Buffer{}, Buffer{1, 0},
                 Buffer{1, 0, 0, 0}, Buffer{2, 0, 0, 0}})
        {
            const auto damaged = second(run(response(serverBlock(2, 3, certificate)), false));
            require(damaged["rdp_server_encryption_method"] == "RC4 128-bit" &&
                !damaged.contains("rdp_server_certificate_type") && !damaged.contains("rdp_server_key_bits") &&
                !damaged.contains("rdp_server_certificate_count"), "A damaged RDP certificate fabricated key metadata");
        }
    }

    // Client offers list each recognized method and retain unrecognized bits.
    for (const auto& [methods, expected] : {
        std::tuple{0u, nlohmann::json::array()}, {2u, nlohmann::json::array({"RC4 128-bit"})},
        {0x1bu, expectedRequest["rdp_client_encryption_methods"]},
        {0x24u, nlohmann::json::array({"0x00000024"})}, {0x12u, nlohmann::json::array({"RC4 128-bit", "FIPS 3DES"})}})
    {
        Buffer data;
        littleWord(data, methods, 4);
        littleWord(data, 0, 4);
        const auto fields = second(run(request(block(0xc002, data)), true));
        require(fields["rdp_client_encryption_methods"] == expected, "RDP client encryption offers were misreported");

        // Clients predating extended methods send only the legacy field.
        data.resize(4);
        const auto legacy = second(run(request(block(0xc002, data)), false));
        require(
            legacy["rdp_client_encryption_methods"] == expected, "A legacy RDP client security block was misreported");
    }

    // Unknown user-data layouts and failed conferences report framing only, never fabricated selections.
    {
        const nlohmann::json observedResponse{{"rdp_mcs_connect_response_observed", true}};
        const nlohmann::json observedRequest{{"rdp_mcs_connect_request_observed", true}};

        // Every fixed byte of the GCC wrapper must match before the user data is interpreted.
        for (const bool isRequest : {false, true})
        {
            const auto good =
                gcc(isRequest, isRequest ? block(0xc002, Buffer(8, 2)) : serverBlock(2, 3, proprietary(2048, 264)));
            for (size_t offset = 0; offset < (isRequest ? 20u : 21u); ++offset)
            {
                // The connectPDU length and unchecked ASN.1 header bytes vary between implementations.
                if (offset == 7 || (!isRequest && (offset == 9 || offset == 10 || offset == 12)))
                    continue;
                auto data = good;
                data[offset] ^= 1;
                const auto outcome = run(join(isRequest ? clientRequest : serverConfirm, pdu(isRequest, data)), false);
                require(outcome.valid && second(outcome) == (isRequest ? observedRequest : observedResponse),
                    "An unrecognized GCC layout produced security evidence");
            }

            // A complete GCC prefix without its length is malformed, while shorter user data is merely unrecognized.
            for (const size_t length : {0u, 3u, 6u, 7u, 8u, 12u, 16u})
            {
                const auto outcome = run(join(isRequest ? clientRequest : serverConfirm,
                    pdu(isRequest, Buffer(good.begin(), good.begin() + length))), false);
                require(length == 7 ? !outcome.valid : outcome.valid &&
                    second(outcome) == (isRequest ? observedRequest : observedResponse),
                    "Truncated GCC user data produced security evidence");
            }
        }

        // A failed conference result is reported without interpreting the user data it carries.
        auto failed = pdu(false, gcc(false, serverBlock(2, 3, proprietary(2048, 264))));
        failed[14] = 1;
        const auto rejected = run(join(serverConfirm, failed), false);
        require(rejected.valid && second(rejected) == observedResponse && rejected.finished,
            "A failed MCS connection produced security evidence");
        const auto noSecurity = run(response(block(0x0c03, Buffer{0xeb, 3, 0, 0})), false);
        require(noSecurity.valid && second(noSecurity) == nlohmann::json{{"rdp_mcs_connect_response_observed", true}},
            "An MCS response without a security block produced evidence");
    }

    // Truncation emits nothing, and malformed PDUs are rejected without exposing partial evidence.
    {
        const auto valid = join(serverConfirm, connectResponse);
        for (size_t length = serverConfirm.size(); length < valid.size(); ++length)
        {
            const auto outcome = run(Buffer(valid.begin(), valid.begin() + length), false);
            require(outcome.valid && outcome.reports.size() == 1 && !outcome.finished,
                "A truncated MCS response produced evidence");
        }
        auto rejects = [&](Buffer bytes)
        {
            const auto outcome = run(bytes, false);
            return !outcome.valid && outcome.reports.size() == 1;
        };
        const size_t base = serverConfirm.size();
        auto mutate = [&](size_t offset, uint8_t value)
        {
            auto copy = valid;
            copy[base + offset] = value;
            return copy;
        };
        require(rejects(mutate(1, 1)), "An MCS response with a corrupt TPKT header was accepted");
        require(rejects(mutate(5, 0)), "An MCS response with the wrong X.224 data header was accepted");
        require(rejects(mutate(6, 0)), "An MCS response with the wrong X.224 data header was accepted");
        require(rejects(mutate(8, 0x65)), "A Connect-Initial tag was accepted in a response");
        require(rejects(mutate(9, 0x81)), "A BER length that disagrees with the TPKT was accepted");
        require(rejects(mutate(12, 0x02)), "A Connect-Response with the wrong result tag was accepted");

        // BER lengths, flags and trailing content are validated within each Connect PDU.
        auto raw = [&](bool isRequest, const Buffer& tail, const Buffer* head = nullptr)
        {
            auto content = head ? *head : isRequest ? requestHead : responseHead;
            append(content, tail);
            return join(isRequest ? clientRequest : serverConfirm, wrap(isRequest, content));
        };
        for (const bool isRequest : {false, true})
        {
            const nlohmann::json observed{
                {isRequest ? "rdp_mcs_connect_request_observed" : "rdp_mcs_connect_response_observed", true}};
            const auto empty = run(raw(isRequest, Buffer{4, 0}), false);
            require(empty.valid && second(empty) == observed, "A Connect PDU without user data was rejected");
            for (const auto& tail :
                {Buffer{4, 0x80}, Buffer{4, 0x83, 0, 0, 0}, Buffer{4, 0x82, 0}, Buffer{4, 5, 0}, Buffer{4, 0, 0}})
                require(rejects(raw(isRequest, tail)), "A malformed Connect PDU user-data length was accepted");
        }
        const Buffer wideUpward{4, 1, 1, 4, 1, 1, 1, 2, 0xff, 0xff, 0x30, 0, 0x30, 0, 0x30, 0};
        const Buffer wideResult{0x0a, 2, 0, 0, 2, 1, 0, 0x30, 0};
        require(rejects(raw(true, Buffer{4, 0}, &wideUpward)), "A Connect-Initial with a multi-byte flag was accepted");
        require(
            rejects(raw(false, Buffer{4, 0}, &wideResult)), "A Connect-Response with a multi-byte result was accepted");
        auto padded = pdu(false, Buffer{});
        padded.push_back(0);
        padded[3] += 1;
        require(rejects(join(serverConfirm, padded)), "An MCS response with trailing bytes was accepted");

        // Block structure is validated within the declared user-data length.
        require(rejects(join(serverConfirm, pdu(false, gcc(false, serverBlock(2, 3, proprietary(2048, 264)), 1)))),
            "User-data blocks longer than the PDU were accepted");
        require(rejects(join(serverConfirm, pdu(false, gcc(false, serverBlock(2, 3, proprietary(2048, 264)), -1)))),
            "A truncated final user-data block was accepted");
        auto tiny = block(0x0c03, Buffer{});
        tiny[2] = 0;
        require(rejects(response(tiny)), "A user-data block smaller than its header was accepted");
        auto twice = serverBlock(2, 3, proprietary(2048, 264));
        append(twice, serverBlock(2, 3, proprietary(2048, 264)));
        require(rejects(response(twice)), "Duplicate RDP security blocks were accepted");
        auto shortBlock = block(0x0c02, Buffer{2, 0, 0, 0});
        require(rejects(response(shortBlock)), "A short RDP security block was accepted");
        auto badRandom = serverBlock(2, 3, proprietary(2048, 264));
        badRandom[4 + 8] = 31;
        require(rejects(response(badRandom)), "An RDP server random of the wrong size was accepted");
        auto badCertificate = serverBlock(2, 3, proprietary(2048, 264));
        badCertificate[4 + 12] ^= 1;
        require(rejects(response(badCertificate)), "An RDP certificate length outside its block was accepted");
        auto overflow = block(0x0c03, Buffer{});
        overflow[2] = 0xff;
        require(rejects(response(overflow)), "A user-data block beyond its container was accepted");
        require(rejects(response(Buffer{0x02, 0x0c, 0x03})), "A truncated user-data block header was accepted");
        auto enhancedWithKey = serverBlock(0, 0, {});
        enhancedWithKey[2] = 20;
        enhancedWithKey.insert(enhancedWithKey.end(), 8, 0);
        require(rejects(response(enhancedWithKey)), "An enhanced-security block carrying key material was accepted");
        require(rejects(request(block(0xc002, Buffer{1, 0}))), "A short client security block was accepted");
        require(rejects(request(block(0xc002, Buffer(9, 0)))), "An oversized client security block was accepted");
    }
}
}
