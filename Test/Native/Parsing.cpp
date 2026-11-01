#include "NetworkFixtures.h"
#include "Hpack.h"
#include "Json.h"
#include <limits>
#include <sstream>

namespace Cipherazzi::Tests
{
void parsingCoverage()
{
    // Public reports preserve integer identities, Unicode, nulls, and floating-point types across storage.
    const auto report = Json::parse(R"({"pid":4294967295,"timestamp":253402300799999999,
        "minimum":-9223372036854775808,"maximum":18446744073709551615,"negative":-0.5,
        "fraction":772.0,"exponent":2.5e2,"success":true,"absent":null,
        "certificates":["\u00e9\ud83d\udd12","\u0000\b\f\n\r\t\"\\\/"]})");
    require(report["pid"].get<uint32_t>() == 4294967295 &&
        report["timestamp"].get<int64_t>() == 253402300799999999 &&
        report["minimum"].get<int64_t>() == std::numeric_limits<int64_t>::min() &&
        report["maximum"].get<uint64_t>() == std::numeric_limits<uint64_t>::max() &&
        report["certificates"][0] == "\xc3\xa9\xf0\x9f\x94\x92" &&
        report["certificates"][1].string() == std::string("\0\b\f\n\r\t\"\\/", 9) &&
        !report["fraction"].is_number_integer() && Json::parse(report.dump()) == report,
        "JSON storage changed a public report's numbers, types, or escaped Unicode");
    std::istringstream input("\xef\xbb\xbf" + report.dump());
    require(Json::parse(input) == report && Json::parse("{\"x\":1,\"x\":2}")["x"] == 2,
        "JSON stream parsing lost a BOM or duplicate-key replacement");
    Json emptyEvidence;
    emptyEvidence.update(Json::object());
    require(emptyEvidence.is_object() && !emptyEvidence.value("ldap_starttls_result", false),
        "An empty protocol-evidence update did not initialize an object");

    // Malformed input, duplicate options, and excessive nesting cannot become usable report fields.
    auto rejects = [](const auto& action)
    {
        try { action(); return false; }
        catch (const std::exception&) { return true; }
    };
    for (const auto* malformed : {"", " ", "[1,]", "{\"x\":1,}", "{x:1}", "{\"x\" 1}", "[1 2]",
        "true false", "nullx", "01", "+1", "-", "1.", "1e", "1e+", "1e309", "NaN", "Infinity",
        "\"\n\"", "\"\\v\"", "\"\\uD800\"", "\"\\uDC00\"", "\"\\uD800\\u0041\"",
        "\"\\u12xz\"", "\"\xc0\xaf\"", "\"\xed\xa0\x80\"", "\"\xf4\x90\x80\x80\""})
        require(rejects([&] { Json::parse(malformed); }), "Malformed JSON was accepted");
    require(rejects([] { Json::parse("{\"db\":1,\"db\":2}", 4, true); }) &&
        rejects([] { Json::parse("{\"x\":{\"db\":1,\"db\":2}}", 4, true); }) &&
        rejects([] { Json::parse("[[[0]]]", 2); }) &&
        rejects([] { Json::parse(std::string(10000, '[')); }) &&
        Json::parse("[[0]]", 2).is_array(), "JSON duplicate or depth limits were bypassed");
    require(rejects([&] { report["maximum"].get<int64_t>(); }) &&
        rejects([&] { report["minimum"].get<uint64_t>(); }) &&
        rejects([&] { report["pid"].get<uint8_t>(); }) &&
        rejects([&] { report["fraction"].get<int>(); }) &&
        rejects([&] { report["success"].get<int>(); }) &&
        rejects([&] { report.value("success", 1); }), "JSON numeric coercion fabricated an identity");
    require(Json(9007199254740993ULL) != Json(9007199254740992.0) &&
        Json(std::numeric_limits<uint64_t>::max()) < Json(0x1p64) &&
        Json(std::numeric_limits<int64_t>::min()) == Json(-0x1p63) &&
        Json(-1) < Json(0U) && Json(1U) == Json(1), "JSON comparisons lost integer precision or signs");
    const Json invalidUtf8(std::string("a\xffz"));
    require(rejects([&] { invalidUtf8.dump(); }) &&
        Json::parse(invalidUtf8.dump(true)) == "a\xef\xbf\xbdz",
        "JSON output did not reject or replace malformed UTF-8");

    // Independent HPACK examples cover plain and Huffman strings with table reuse across requests.
    const std::string_view requests[][3] = {
        {"828684410f7777772e6578616d706c652e636f6d", "828684be58086e6f2d6361636865",
            "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"},
        {"828684418cf1e3c2e5f23a6ba0ab90f4ff", "828684be5886a8eb10649cbf",
            "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"}};
    const Json expected[] = {{{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
        {":authority", "www.example.com"}},
        {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"},
            {"cache-control", "no-cache"}},
        {{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"}, {":authority", "www.example.com"},
            {"custom-key", "custom-value"}}};
    for (const auto& sequence : requests)
    {
        HpackDecoder decoder;
        for (size_t index = 0; index < std::size(sequence); ++index)
        {
            Json fields = Json::object();
            require(decoder.decode(fromHex(std::string(sequence[index])), [&](auto name, auto value)
            {
                fields[name] = value;
                return true;
            }) && fields == expected[index], "HPACK request decoding or dynamic-table reuse failed");
        }
    }

    // Referenced names survive insertion that evicts their original table entry.
    const auto discard = [](auto, auto) { return true; };
    HpackDecoder eviction;
    std::string retainedName, retainedValue;
    require(eviction.setTableLimit(64) &&
        eviction.decode(fromHex("3f2140016101627e1e" + std::string(60, '6')), discard) &&
        eviction.decode(fromHex("be"), [&](auto name, auto value)
        {
            retainedName = name;
            retainedValue = value;
            return true;
        }) && retainedName == "a" && retainedValue == std::string(30, 'f'),
        "HPACK evicted a literal's indexed name before preserving it");

    // A reduction remains mandatory even if the allowed size is raised before the next block.
    HpackDecoder settings;
    require(settings.setTableLimit(64) && settings.setTableLimit(128) &&
        !settings.decode(fromHex("3f6182"), discard), "HPACK skipped the smallest required table-size update");
    HpackDecoder changed;
    require(changed.setTableLimit(64) && changed.setTableLimit(128) &&
        changed.decode(fromHex("3f213f6182"), discard) && changed.setTableLimit(0) &&
        !changed.decode(fromHex("82"), discard) && changed.decode(fromHex("2082"), discard),
        "HPACK did not apply acknowledged table-size changes");

    // Invalid indices, truncated literals, overflow, EOS, padding, and misplaced updates fail closed.
    for (const auto* malformed : {"80", "be", "ff", "ffffffffffff", "00", "000161", "01036162",
        "0181ff", "018100", "0184ffffffff", "8220", "3fe21f82"})
    {
        HpackDecoder decoder;
        require(!decoder.decode(fromHex(malformed), discard), "Malformed HPACK was accepted");
    }
    HpackDecoder countLimit, sizeLimit, tableLimit;
    require(!countLimit.decode(Buffer(257, 0x82), discard) && countLimit.limited() &&
        !sizeLimit.decode(fromHex("8286"), discard, 256, 10) && sizeLimit.limited() &&
        !tableLimit.setTableLimit(262145) && tableLimit.limited(), "HPACK exceeded its resource limits");

    // Random wire data must either fail or round-trip into well-formed, bounded internal values.
    std::mt19937 random(9173);
    for (int iteration = 0; iteration < 2000; ++iteration)
    {
        std::string text(random() % 128, '\0');
        for (auto& ch : text) ch = static_cast<char>(random());
        std::optional<Json> parsed;
        try { parsed = Json::parse(text); }
        catch (const std::runtime_error&) {}
        if (parsed)
            require(Json::parse(parsed->dump()) == *parsed, "JSON fuzz input did not round-trip");
        HpackDecoder decoder;
        decoder.decode({reinterpret_cast<const uint8_t*>(text.data()), text.size()}, discard);
        require(decoder.memory() <= 262144, "Malformed HPACK escaped its memory budget");
    }
}
}
