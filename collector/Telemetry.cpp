#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <algorithm>
#include "Telemetry.h"
#include "Processes.h"
#include <fstream>
#include <limits>
#include <unordered_map>

namespace Cipherazzi
{
using EventHandle = std::unique_ptr<std::remove_pointer_t<EVT_HANDLE>, decltype(&EvtClose)>;

int64_t javaTimestamp(const std::string& value)
{
    // JFR JSON uses ISO timestamps; retain microseconds and the explicit offset.
    if (value.size() < 20)
        throw std::runtime_error("Invalid JFR timestamp");
    SYSTEMTIME time{};
    auto number = [&](size_t at, size_t length)
    {
        const auto part = value.substr(at, length);
        if (part.size() != length || part.find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("Invalid JFR timestamp");
        return static_cast<WORD>(std::stoi(part));
    };
    time.wYear = number(0, 4);
    time.wMonth = number(5, 2);
    time.wDay = number(8, 2);
    time.wHour = number(11, 2);
    time.wMinute = number(14, 2);
    time.wSecond = number(17, 2);
    FILETIME encoded{};
    if (!SystemTimeToFileTime(&time, &encoded))
        throw std::runtime_error("Invalid JFR timestamp");
    int64_t result = static_cast<int64_t>((static_cast<uint64_t>(encoded.dwHighDateTime) << 32) |
        encoded.dwLowDateTime) / 10 - 11644473600000000LL;
    size_t at = 19;
    if (value[at] == '.')
    {
        ++at;
        int scale = 100000;
        while (at < value.size() && value[at] >= '0' && value[at] <= '9')
        {
            result += (value[at++] - '0') * scale;
            scale /= 10;
        }
    }
    if (at >= value.size())
        throw std::runtime_error("JFR timestamp has no timezone");
    if (value[at] == '+' || value[at] == '-')
    {
        const auto offset = (number(at + 1, 2) * 60 + number(at + 4, 2)) * 60000000LL;
        result += value[at] == '+' ? -offset : offset;
    }
    else if (value[at] != 'Z')
        throw std::runtime_error("JFR timestamp has an unsupported timezone");
    return result;
}

size_t Telemetry::importJava(const std::filesystem::path& file, Storage& storage,
    const std::function<bool(const std::string&)>& accept)
{
    const auto size = std::filesystem::file_size(file);
    if (size > 16 * 1024 * 1024)
        throw std::runtime_error("JFR export exceeds 16 MiB; use a shorter recording window");
    std::ifstream input(file, std::ios::binary);
    if (!input)
        throw std::ios_base::failure("Cannot open JFR export");
    std::string text(static_cast<size_t>(size) + 1, '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (static_cast<uintmax_t>(input.gcount()) != size)
        throw std::ios_base::failure("JFR export changed during reading; publish JSON files atomically");
    text.resize(static_cast<size_t>(size));
    auto document = nlohmann::json::parse(text, [](int depth, nlohmann::json::parse_event_t, nlohmann::json&)
    {
        if (depth > 32)
            throw std::runtime_error("JFR export nesting exceeds the limit");
        return true;
    });
    const uint32_t pid = document.value("pid", uint32_t{});
    const auto lifetime = document.value("process_started_us", nlohmann::json(0));
    if (!lifetime.is_number_integer() || lifetime < 0 || lifetime > 253402300799999999LL)
        throw std::runtime_error("JFR export contains an invalid process lifetime");
    const auto processStarted = lifetime.get<int64_t>();
    if (document.value("process_name", "").size() > 256 || document.value("process_path", "").size() > 4096)
        throw std::runtime_error("JFR process identity exceeds the field limits");
    auto owner = pid ? Processes::describe(pid, processStarted, "JFR process lifetime") : Owner{};
    if (processStarted > 0 && owner.name.empty())
    {
        owner.pid = pid;
        owner.startedUs = processStarted;
        owner.name = document.value("process_name", "");
        owner.path = document.value("process_path", "");
    }
    const auto& events = document.at("recording").at("events");
    if (!events.is_array() || events.size() > 50000)
        throw std::runtime_error("JFR export has too many events");
    size_t count = 0;
    for (const auto& item : events)
    {
        const auto kind = item.value("type", "");
        if (kind != "jdk.TLSHandshake" && kind != "jdk.X509Certificate" && kind != "jdk.X509Validation")
            continue;
        const auto& values = item.at("values");
        EndpointEvent event;
        event.provider = "Java Flight Recorder";
        event.kind = kind;
        event.pid = pid;
        event.timestampUs = javaTimestamp(values.at("startTime").get<std::string>());
        event.peer = values.value("peerHost", "");
        event.port = static_cast<uint16_t>(std::clamp(values.value("peerPort", 0), 0, 65535));
        event.protocol = values.value("protocolVersion", "");
        event.cipher = values.value("cipherSuite", "");
        if (values.contains("certificateId"))
            event.certificateId = values["certificateId"].dump();
        event.result = kind == "jdk.TLSHandshake" ? "Endpoint reported TLS handshake" :
            kind == "jdk.X509Validation" ? "JDK validation-chain event" : "JDK parsed certificate";
        event.detail = values.dump();
        const auto identity = kind + ":" + std::to_string(pid) + ":" + event.detail;
        event.id = sha256(Bytes(reinterpret_cast<const uint8_t*>(identity.data()), identity.size()));
        if (accept && !accept(event.id))
            continue;
        normalizeProvider(event, owner);
        storage.enqueue(std::move(event), true);
        ++count;
    }
    return count;
}

void Telemetry::normalizeProvider(EndpointEvent& event, const Owner& owner)
{
    const bool java = event.kind == "jdk.TLSHandshake";
    const bool windows = event.provider == "Schannel" &&
        (event.kind == "Event 36880" || event.kind == "Event 36887" || event.kind == "Event 36888");
    if (!java && !windows)
        return;

    // Provider events retain unknown roles and sockets; diagnostics cannot imply peer verification.
    auto detail = nlohmann::json::parse(event.detail);
    const auto fields = windows ? detail.value("fields", nlohmann::json::object()) : detail;
    auto text = [&](const char* key) { return fields.contains(key) ? fields.at(key).is_string() ?
        fields.at(key).get<std::string>() : fields.at(key).dump() : std::string{}; };
    auto number = [&](const char* key)
    {
        const auto value = text(key);
        if (value.empty())
            return 0;
        size_t end = 0;
        try
        {
            const auto result = std::stoi(value, &end, value.starts_with("0x") ? 16 : 10);
            return end == value.size() && result >= 0 && result <= 65535 ? result : 0;
        }
        catch (const std::exception&) { return 0; }
    };
    auto report = std::make_shared<EndpointReport>();
    report->partial = true;
    const auto role = text("Type");
    report->roleKnown = windows && (_stricmp(role.c_str(), "client") == 0 || _stricmp(role.c_str(), "server") == 0);
    report->client = report->roleKnown && _stricmp(role.c_str(), "client") == 0;
    report->success = java || event.kind == "Event 36880";
    report->startedUs = std::max(int64_t{1}, event.timestampUs - 120000000);
    report->owner = owner.startedUs <= event.timestampUs ? owner : Owner{};
    report->processStartedUs = report->owner.startedUs;
    report->peerName = java ? text("peerHost") : text("TargetName");
    report->remote.port = static_cast<uint16_t>(java ? number("peerPort") : number("RemotePort"));
    const auto address = java ? report->peerName : text("RemoteAddress");
    report->remote.family = address.find(':') == std::string::npos ? 4 : 6;
    if (InetPtonA(report->remote.family == 4 ? AF_INET : AF_INET6, address.c_str(), report->remote.address.data()) != 1)
        report->remote = {{}, report->remote.port, 4};
    auto protocol = java ? text("protocolVersion") : text("Protocol");
    for (const auto [name, version] : {std::pair{"TLSv1", 769}, {"TLSv1.0", 769}, {"TLSv1.1", 770},
        {"TLSv1.2", 771}, {"TLSv1.3", 772}, {"TLS 1.0", 769}, {"TLS 1.1", 770},
        {"TLS 1.2", 771}, {"TLS 1.3", 772}, {"SSLv3", 768}})
        if (protocol == name)
            report->version = version;
    if (!java && !report->version && number("Protocol") >= 768 && number("Protocol") <= 772)
        report->version = number("Protocol");
    const auto cipher = java ? cipherId(text("cipherSuite")) : number("CipherSuite");
    report->cipher = std::max(0, cipher);
    detail["schema"] = "cipherazzi.provider/1";
    detail["transport"] = "TCP";
    detail["role"] = report->roleKnown ? report->client ? "client" : "server" : "unknown";
    detail["success"] = report->success;
    detail["tls_version"] = report->version;
    detail["cipher_id"] = report->cipher;
    detail["peer_name"] = report->peerName;
    detail["process_started_us"] = report->processStartedUs;
    detail["correlation"] = "Awaiting a unique provider, process-lifetime, peer, timing, and parameter match";
    detail["server_certificates"] = nlohmann::json::array();
    detail["client_certificates"] = nlohmann::json::array();
    event.protocol = report->version ? versionName(static_cast<uint16_t>(report->version)) : event.protocol;
    event.cipher = report->cipher ? cipherName(static_cast<uint16_t>(report->cipher)) : event.cipher;
    event.peer = report->peerName.empty() ? address : report->peerName;
    event.port = report->remote.port;
    event.detail = detail.dump();
    event.report = std::move(report);
}

size_t Telemetry::importEndpoint(const std::filesystem::path& file, Storage& storage,
    const std::function<bool(const std::string&)>& accept)
{
    // Adapters publish public results atomically; missing socket identity never establishes a packet association.
    const auto size = std::filesystem::file_size(file);
    if (size > 2 * 1024 * 1024)
        throw std::runtime_error("Endpoint report exceeds 2 MiB");
    std::ifstream input(file, std::ios::binary);
    if (!input)
        throw std::ios_base::failure("Cannot open endpoint report");
    std::string text(static_cast<size_t>(size) + 1, '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (static_cast<uintmax_t>(input.gcount()) != size)
        throw std::ios_base::failure("Endpoint report changed during reading");
    text.resize(static_cast<size_t>(size));
    auto document = nlohmann::json::parse(text, [](int depth, nlohmann::json::parse_event_t, nlohmann::json&)
    {
        if (depth > 16)
            throw std::runtime_error("Endpoint report nesting exceeds the limit");
        return true;
    });
    const bool raw = document.at("schema") == "cipherazzi.raw/1";
    if (!raw && document.at("schema") != "cipherazzi.endpoint/1")
        throw std::runtime_error("Unsupported endpoint report schema");
    auto integer = [](const nlohmann::json& value, int64_t minimum, int64_t maximum)
    {
        if (!value.is_number_integer() || (value.is_number_unsigned() &&
            value.get<uint64_t>() > static_cast<uint64_t>(maximum)))
            throw std::runtime_error("Endpoint report requires bounded integer fields");
        const auto result = value.get<int64_t>();
        if (result < minimum || result > maximum)
            throw std::runtime_error("Endpoint report requires bounded integer fields");
        return result;
    };
    auto report = std::make_shared<EndpointReport>();
    report->raw = raw;
    const auto transport = document.at("transport").get<std::string>();
    auto endpoint = [&](const nlohmann::json& value, bool allowWildcard = false)
    {
        if (raw && (value.size() != 2 || !value.contains("address") || !value.contains("port")))
            throw std::runtime_error("Raw endpoint sockets accept addresses and ports only");
        Endpoint result;
        const auto address = value.at("address").get<std::string>();
        const auto port = integer(value.at("port"), 1, 65535);
        result.family = address.find(':') == std::string::npos ? 4 : 6;
        if (port < 1 || port > 65535 || InetPtonA(result.family == 4 ? AF_INET : AF_INET6,
            address.c_str(), result.address.data()) != 1 ||
            (!allowWildcard && std::ranges::all_of(result.address, [](uint8_t byte) { return byte == 0; })))
            throw std::runtime_error("Endpoint report requires concrete IP addresses and ports");
        // Normalize dual-stack socket addresses to the IP family seen in captured packets.
        if (result.family == 6 && result.address[10] == 255 && result.address[11] == 255 &&
            std::ranges::all_of(Bytes(result.address).first(10), [](uint8_t byte) { return byte == 0; }))
        {
            std::copy_n(result.address.begin() + 12, 4, result.address.begin());
            std::fill(result.address.begin() + 4, result.address.end(), uint8_t{});
            result.family = 4;
            if (!allowWildcard && std::ranges::all_of(result.address, [](uint8_t byte) { return byte == 0; }))
                throw std::runtime_error("Endpoint report requires concrete IP addresses and ports");
        }
        result.port = static_cast<uint16_t>(port);
        return result;
    };
    if (document.contains("local")) report->local = endpoint(document.at("local"), !raw && transport == "QUIC");
    if (document.contains("remote")) report->remote = endpoint(document.at("remote"));
    const auto role = document.at("role").get<std::string>();
    const auto processScope = document.value("process_scope", "endpoint");
    if ((role != "client" && role != "server" && (raw || role != "unknown")) ||
        (raw ? transport != "TCP" && transport != "UDP" :
            transport != "TCP" && transport != "QUIC" && transport != "DTLS" && transport != "Unknown") ||
        (processScope != "endpoint" && processScope != "application") ||
        (raw && (!document.contains("local") || !document.contains("remote"))) ||
        (document.contains("local") && document.contains("remote") && report->local.family != report->remote.family))
        throw std::runtime_error("Invalid endpoint role or transport");
    report->roleKnown = role != "unknown";
    report->client = role == "client";
    report->quic = transport == "QUIC";
    report->udp = transport == "UDP" || transport == "DTLS";
    report->success = document.at("success").get<bool>();
    // Keep public timestamps representable by the database viewers and leave room for correlation tolerances.
    constexpr int64_t maximumTimestampUs = 253402300799999999;
    report->processStartedUs = integer(document.at("process_started_us"), 1, maximumTimestampUs);
    report->startedUs = integer(document.at(raw ? "operation_started_us" : "handshake_started_us"),
        1, maximumTimestampUs);
    if (raw)
    {
        // Accept public operation metadata only; socket correlation never establishes the algorithm from ciphertext.
        const std::initializer_list<std::string_view> fields{"schema", "provider", "pid", "process_started_us",
            "operation_started_us", "timestamp_us", "local", "remote", "role", "transport", "success",
            "algorithm", "mode", "key_bits"};
        for (const auto& item : document.items())
            if (std::ranges::find(fields, item.key()) == fields.end())
                throw std::runtime_error("Raw endpoint reports accept public operation fields only");
        report->algorithm = document.at("algorithm").get<std::string>();
        report->mode = document.at("mode").get<std::string>();
        report->keyBits = static_cast<int>(integer(document.at("key_bits"), 1, 65536));
        if (report->algorithm.empty() || report->algorithm.size() > 128 || report->mode.empty() ||
            report->mode.size() > 64 || std::ranges::any_of(report->algorithm + report->mode,
            [](unsigned char value) { return value < 32 || value > 126; }))
            throw std::runtime_error("Invalid raw endpoint algorithm or mode");
    }
    report->version = static_cast<int>(integer(document.value("tls_version", nlohmann::json(0)), 0, 65535));
    if (report->quic && report->version && report->version < 772)
        throw std::runtime_error("QUIC reports cannot select TLS versions older than TLS 1.3");
    if (transport == "DTLS")
    {
        report->dtlsVersion = static_cast<uint16_t>(report->version);
        report->version = report->version == 0xfeff ? 770 : report->version == 0xfefd ? 771 :
            report->version == 0xfefc ? 772 : 0;
        if (report->success && !report->version)
            throw std::runtime_error("DTLS reports require a supported DTLS wire version");
    }
    report->cipher = static_cast<int>(integer(document.value("cipher_id", nlohmann::json(0)), 0, 65535));
    report->signature = static_cast<int>(integer(document.value("signature_scheme", nlohmann::json(-1)), -1, 65535));
    report->localSignature = static_cast<int>(integer(
        document.value("local_signature_scheme", nlohmann::json(-1)), -1, 65535));
    report->group = static_cast<int>(integer(document.value("group_id", nlohmann::json(-1)), -1, 65535));
    report->peerVerified = document.contains("peer_verified") ? (document.at("peer_verified").get<bool>() ? 1 : 0) : -1;
    report->alpn = document.value("selected_alpn", "");
    if (!raw)
        report->peerName = document.value("server_name", "");
    report->quicId = document.value("quic_original_dcid", "");
    if (report->quicId.size() > 40 || (report->quicId.size() & 1) ||
        report->quicId.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("Invalid QUIC original destination connection ID");
    const bool localKnown = !std::ranges::all_of(report->local.address, [](uint8_t byte) { return byte == 0; });
    const bool remoteKnown = document.contains("remote");
    report->correlatable = localKnown && remoteKnown && report->roleKnown && transport != "Unknown" &&
        processScope == "endpoint" && (!report->quic || !report->quicId.empty());
    const auto errorCode = integer(document.value("error_code", nlohmann::json(0)), INT32_MIN, INT32_MAX);
    const auto errorName = document.value("error_name", "");
    if (errorName.size() > 128 || errorName.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") !=
        std::string::npos)
        throw std::runtime_error("Invalid public endpoint error name");
    EndpointEvent event;
    event.provider = document.at("provider").get<std::string>();
    event.kind = raw ? "Raw encryption operation" : "TLS handshake";
    event.pid = static_cast<uint32_t>(integer(document.at("pid"), 1, std::numeric_limits<uint32_t>::max()));
    if (document.value("process_name", "").size() > 256 || document.value("process_path", "").size() > 4096)
        throw std::runtime_error("Endpoint process identity exceeds the field limits");
    report->owner = Processes::describe(event.pid, report->processStartedUs, "Endpoint process lifetime");
    if (report->owner.name.empty())
    {
        report->owner.name = document.value("process_name", "");
        report->owner.path = document.value("process_path", "");
    }
    event.timestampUs = integer(document.at("timestamp_us"), 1, maximumTimestampUs);
    if (!event.pid || event.provider.empty() || event.provider.size() > 128 || report->alpn.size() > 255 ||
        report->peerName.size() > 253 || std::ranges::any_of(report->peerName, [](unsigned char value)
        { return value <= 32 || value == 127; }) ||
        report->processStartedUs > report->startedUs ||
        report->startedUs > event.timestampUs || event.timestampUs - report->startedUs > 120000000 ||
        (!raw && report->success && ((!report->version && !report->quic) || !report->cipher)))
        throw std::runtime_error("Invalid endpoint process, timing, or negotiated parameters");
    event.peer = remoteKnown ? report->remote.text() : report->peerName;
    event.port = report->remote.port;
    event.protocol = raw ? "Raw cryptography" : report->dtlsVersion ? versionName(report->dtlsVersion) :
        report->udp ? "DTLS" : report->version ? versionName(static_cast<uint16_t>(report->version)) :
        report->quic ? "QUIC" : "TLS";
    event.cipher = raw ? report->algorithm + " " + std::to_string(report->keyBits) + " " + report->mode :
        report->cipher ? cipherName(static_cast<uint16_t>(report->cipher)) : "";
    event.result = raw ? (report->success ? "Endpoint reported encryption" : "Endpoint reported encryption failure") :
        report->success ? "Endpoint reported handshake completion" : "Endpoint reported handshake failure";
    if (!report->success && !errorName.empty()) event.result += ": " + errorName;
    nlohmann::json detail{
        {"schema", "cipherazzi.endpoint/1"}, {"transport", transport}, {"role", role}, {"process_scope", processScope},
        {"process_role", processScope == "application" ? "unknown" : role},
        {"local_address", localKnown ? report->local.text() : ""}, {"local_port", report->local.port},
        {"remote_address", remoteKnown ? report->remote.text() : ""}, {"remote_port", report->remote.port},
        {"process_started_us", report->processStartedUs}, {"handshake_started_us", report->startedUs},
        {"timestamp_us", event.timestampUs}, {"success", report->success}, {"tls_version", report->version},
        {"dtls_version", report->dtlsVersion},
        {"quic_original_dcid", report->quicId}, {"cipher_id", report->cipher},
        {"signature_scheme", report->signature}, {"local_signature_scheme", report->localSignature},
        {"group_id", report->group},
        {"peer_verified", report->peerVerified}, {"selected_alpn", report->alpn},
        {"correlation", report->correlatable ? "Awaiting exact socket and process-lifetime match" :
            report->quic ? "QUIC source address or original connection ID unavailable; no packet association asserted" :
            "Socket, transport, or socket-process identity unavailable; no packet association asserted"},
        {"server_certificates", nlohmann::json::array()}, {"client_certificates", nlohmann::json::array()}
    };
    if (!localKnown && document.contains("local"))
        detail["local_binding_address"] = report->local.text();
    if (document.contains("error_code")) detail["error_code"] = errorCode;
    if (!errorName.empty()) detail["error_name"] = errorName;
    if (raw)
    {
        detail["schema"] = "cipherazzi.raw/1";
        detail["operation_started_us"] = report->startedUs;
        detail["algorithm"] = report->algorithm;
        detail["mode"] = report->mode;
        detail["key_bits"] = report->keyBits;
        for (const auto* field : {"handshake_started_us", "tls_version", "cipher_id", "signature_scheme",
            "local_signature_scheme", "group_id", "peer_verified", "selected_alpn", "quic_original_dcid"})
            detail.erase(field);
    }
    else
    {
        detail["peer_name"] = report->peerName;
        if (document.contains("session_resumed"))
            detail["session_resumed"] = document.at("session_resumed").get<bool>();
    }
    size_t certificateBytes = 0;
    for (const auto [chain, field, reference] : {
        std::tuple{&report->serverCertificates, "server_certificates_der", "server_certificates"},
        std::tuple{&report->clientCertificates, "client_certificates_der", "client_certificates"}})
    {
        if (!document.contains(field))
            continue;
        const auto& certificates = document.at(field);
        if (!certificates.is_array() || certificates.size() > 16)
            throw std::runtime_error("Endpoint certificate chain exceeds the limit");
        for (const auto& certificate : certificates)
        {
            const auto encoded = certificate.get<std::string>();
            DWORD length = 0;
            if (encoded.size() > 350000 || !CryptStringToBinaryA(encoded.data(), static_cast<DWORD>(encoded.size()),
                CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, nullptr, &length, nullptr, nullptr) ||
                !length || length > 262144 || certificateBytes + length > 1048576)
                throw std::runtime_error("Invalid or oversized endpoint certificate");
            auto der = std::make_shared<std::vector<uint8_t>>(length);
            if (!CryptStringToBinaryA(encoded.data(), static_cast<DWORD>(encoded.size()),
                CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, der->data(), &length, nullptr, nullptr))
                throw std::runtime_error("Invalid endpoint certificate encoding");
            certificateBytes += length;
            detail[reference].push_back(sha256(*der));
            chain->push_back(std::move(der));
        }
    }
    event.detail = detail.dump();
    const auto identity = event.provider + ":" + std::to_string(event.pid) + ":" + event.detail;
    event.id = sha256(Bytes(reinterpret_cast<const uint8_t*>(identity.data()), identity.size()));
    event.report = std::move(report);
    if (accept && !accept(event.id))
        return 0;
    storage.enqueue(std::move(event), true);
    return 1;
}

void Telemetry::report(std::string provider, std::string result)
{
    EndpointEvent event;
    event.provider = std::move(provider);
    event.kind = "Source status";
    event.result = std::move(result);
    event.timestampUs = nowUs();
    event.id = std::to_string(event.timestampUs) + "-" + std::to_string(GetCurrentProcessId()) + "-" + event.provider;
    event.detail = "{}";
    storage_.enqueue(std::move(event));
}

Telemetry::Telemetry(Storage& storage, Counters& counters, bool schannel, std::filesystem::path javaDirectory,
    std::filesystem::path endpointDirectory) :
    storage_(storage), counters_(counters)
{
    if (!javaDirectory.empty() && !std::filesystem::is_directory(javaDirectory))
        throw std::runtime_error("The Java telemetry directory does not exist");
    if (!endpointDirectory.empty() && !std::filesystem::is_directory(endpointDirectory))
        throw std::runtime_error("The endpoint report directory does not exist");
    // Subscribe without changing machine-wide event logging settings.
    if (schannel)
    {
        for (const auto* channel : {L"System", L"Microsoft-Windows-CAPI2/Operational"})
        {
            const auto query = std::wstring_view(channel) == L"System" ?
                L"*[System[Provider[@Name='Schannel']]]" : L"*";
            auto subscription = EvtSubscribe(nullptr, nullptr, channel, query, nullptr, this,
                eventCallback, EvtSubscribeToFutureEvents);
            if (subscription)
                subscriptions_.emplace_back(subscription, EvtClose);
            else
                report("Windows events", "Subscription unavailable: " + utf8(channel) +
                    " (error " + std::to_string(GetLastError()) + ")");
        }
        report("Windows events", "Subscribed to emitted Schannel/CAPI2 events; channel settings determine coverage");
    }
    if (javaDirectory.empty() && endpointDirectory.empty())
        return;
    thread_ = std::thread([this, javaDirectory = std::move(javaDirectory),
        endpointDirectory = std::move(endpointDirectory)]
    {
        // Each completed directory pass replaces the record of files already read, so removed files leave it
        // and files that remain are not read again. Names are kept as hashes; the bound matches the largest
        // directory an adapter retains.
        using Files = std::unordered_map<size_t, std::filesystem::file_time_type>;
        constexpr size_t FileLimit = 65536;
        std::array<Files, 2> known, visited;
        std::unordered_set<std::string> seen;
        std::deque<std::string> order;
        auto accept = [&](const std::string& id)
        {
            if (stopped_ || seen.contains(id))
                return false;
            if (order.size() >= 100000)
            {
                seen.erase(order.front());
                order.pop_front();
            }
            seen.insert(id);
            order.push_back(id);
            return true;
        };
        if (!javaDirectory.empty())
            report("Java Flight Recorder", "Watching atomic JFR JSON exports");
        if (!endpointDirectory.empty())
            report("Endpoint adapters", "Watching public endpoint reports; exact matching required");
        const std::array directories{javaDirectory, endpointDirectory};
        std::array<std::filesystem::directory_iterator, 2> scans;
        const std::filesystem::directory_iterator end;
        while (!stopped_)
        {
            for (size_t index = 0; index < directories.size(); ++index)
            {
                const auto& directory = directories[index];
                auto& scan = scans[index];
                if (directory.empty())
                    continue;
                try
                {
                    // Resume bounded scans so large directories and unrelated files cannot starve later reports.
                    if (scan == end)
                        scan = std::filesystem::directory_iterator(directory);
                    for (size_t count = 0; scan != end && count < 1024 && !stopped_; ++count)
                    {
                        const auto entry = *scan;
                        ++scan;
                        if (entry.path().extension() != L".json")
                            continue;
                        const auto name = std::hash<std::wstring>{}(entry.path().filename().native());
                        std::optional<std::filesystem::file_time_type> timestamp;
                        try
                        {
                            if (!entry.is_regular_file())
                                continue;
                            timestamp = entry.last_write_time();
                            const auto previous = known[index].find(name);
                            if (previous == known[index].end() || previous->second != *timestamp)
                            {
                                if (directory == endpointDirectory)
                                    importEndpoint(entry.path(), storage_, accept);
                                else
                                    importJava(entry.path(), storage_, accept);
                            }
                        }
                        catch (const std::exception& error)
                        {
                            if (dynamic_cast<const std::system_error*>(&error))
                                timestamp.reset();
                            ++counters_.telemetryLost;
                            report(directory == endpointDirectory ? "Endpoint adapters" : "Java Flight Recorder",
                                error.what());
                        }
                        if (timestamp && visited[index].size() < FileLimit)
                            visited[index][name] = *timestamp;
                    }
                    if (scan == end)
                        known[index] = std::exchange(visited[index], {});
                }
                catch (const std::exception& error)
                {
                    // Keep what the interrupted pass read; the next pass starts from the beginning.
                    for (const auto& [name, timestamp] : visited[index])
                        known[index][name] = timestamp;
                    visited[index].clear();
                    scan = {};
                    ++counters_.telemetryLost;
                    report("Endpoint telemetry", error.what());
                }
            }
            for (int wait = 0; wait < 10 && !stopped_; ++wait)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}

DWORD WINAPI Telemetry::eventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, void* context, EVT_HANDLE event)
{
    auto& self = *static_cast<Telemetry*>(context);
    if (action == EvtSubscribeActionError)
    {
        ++self.counters_.telemetryLost;
        return ERROR_SUCCESS;
    }
    try { self.event(event); }
    catch (...) { ++self.counters_.telemetryLost; }
    return ERROR_SUCCESS;
}

void Telemetry::event(EVT_HANDLE event)
{
    EventHandle context(EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem), EvtClose);
    DWORD bytes = 0, count = 0;
    EvtRender(context.get(), event, EvtRenderEventValues, 0, nullptr, &bytes, &count);
    if (bytes == 0 || bytes > 65536)
        throw std::runtime_error("Invalid event metadata size");
    std::vector<BYTE> buffer(bytes);
    if (!EvtRender(context.get(), event, EvtRenderEventValues, bytes, buffer.data(), &bytes, &count))
        throw std::runtime_error("Could not read event metadata");
    const auto* values = reinterpret_cast<const EVT_VARIANT*>(buffer.data());
    if (count <= EvtSystemProcessID)
        return;
    EndpointEvent row;
    row.provider = utf8(values[EvtSystemProviderName].StringVal);
    const auto id = values[EvtSystemEventID].UInt16Val;
    row.kind = "Event " + std::to_string(id);
    row.pid = values[EvtSystemProcessID].Type == EvtVarTypeNull ? 0 : values[EvtSystemProcessID].UInt32Val;
    row.timestampUs = static_cast<int64_t>(values[EvtSystemTimeCreated].FileTimeVal / 10) - 11644473600000000LL;
    row.result = row.provider == "Schannel" && id == 36880 ? "Endpoint confirmed handshake completion" :
        row.provider == "Schannel" && (id == 36887 || id == 36888) ? "Endpoint reported fatal TLS alert" :
        "Provider diagnostic; inspect event details";
    row.id = row.provider + "-" + std::to_string(values[EvtSystemEventRecordId].UInt64Val) + "-" +
        std::to_string(row.timestampUs);
    EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &bytes, &count);
    if (bytes > 65536)
        throw std::runtime_error("Event XML exceeds the metadata limit");
    std::wstring xml(bytes / sizeof(wchar_t), L'\0');
    if (bytes && EvtRender(nullptr, event, EvtRenderEventXml, bytes, xml.data(), &bytes, &count))
        xml.resize(wcsnlen_s(xml.data(), xml.size()));
    else
        xml.clear();
    EventHandle publisher(EvtOpenPublisherMetadata(nullptr, values[EvtSystemProviderName].StringVal,
        nullptr, 0, 0), EvtClose);
    DWORD length = 0;
    EvtFormatMessage(publisher.get(), event, 0, 0, nullptr, EvtFormatMessageEvent, 0, nullptr, &length);
    std::wstring message(std::min<DWORD>(length, 16384), L'\0');
    if (!message.empty() && EvtFormatMessage(publisher.get(), event, 0, 0, nullptr, EvtFormatMessageEvent,
        static_cast<DWORD>(message.size()), message.data(), &length))
        message.resize(wcsnlen_s(message.data(), message.size()));
    else
        message.clear();
    row.detail = nlohmann::json{{"message", utf8(message)}, {"xml", utf8(xml)},
        {"correlation", "Provider event; no packet connection association asserted"},
        {"pid_evidence", "Windows event emitting process"}}.dump(-1, ' ', false,
            nlohmann::json::error_handler_t::replace);
    if (row.provider == "Schannel")
    {
        // Read named event fields through the provider's rendered values instead of parsing display text.
        constexpr const wchar_t* names[]{L"Protocol", L"CipherSuite", L"RemoteAddress", L"RemotePort", L"TargetName",
            L"Type", L"CallerProcessId"};
        std::vector<std::wstring> queries;
        std::vector<const wchar_t*> paths;
        for (const auto* name : names)
            queries.push_back(std::wstring(L"Event/EventData/Data[@Name='") + name + L"']");
        for (const auto& query : queries)
            paths.push_back(query.c_str());
        EventHandle fieldsContext(EvtCreateRenderContext(static_cast<DWORD>(paths.size()), paths.data(),
            EvtRenderContextValues), EvtClose);
        bytes = count = 0;
        if (fieldsContext)
            EvtRender(fieldsContext.get(), event, EvtRenderEventValues, 0, nullptr, &bytes, &count);
        if (bytes && bytes <= 65536)
        {
            std::vector<BYTE> fields(bytes);
            if (EvtRender(fieldsContext.get(), event, EvtRenderEventValues, bytes, fields.data(), &bytes, &count))
            {
                const auto* rendered = reinterpret_cast<const EVT_VARIANT*>(fields.data());
                auto detail = nlohmann::json::parse(row.detail);
                detail["fields"] = nlohmann::json::object();
                for (size_t index = 0; index < std::min<size_t>(count, std::size(names)); ++index)
                {
                    const auto& field = rendered[index];
                    if (field.Type == EvtVarTypeString && field.StringVal)
                        detail["fields"][utf8(names[index])] = utf8(field.StringVal);
                    else if (field.Type == EvtVarTypeUInt16)
                        detail["fields"][utf8(names[index])] = field.UInt16Val;
                    else if (field.Type == EvtVarTypeUInt32 || field.Type == EvtVarTypeHexInt32)
                        detail["fields"][utf8(names[index])] = field.UInt32Val;
                }
                row.detail = detail.dump();
            }
        }
        const auto detail = nlohmann::json::parse(row.detail);
        if (detail.contains("fields") && detail["fields"].contains("CallerProcessId"))
        {
            const auto& caller = detail["fields"]["CallerProcessId"];
            if (caller.is_number_unsigned())
                row.pid = caller.get<uint32_t>();
            else if (caller.is_string())
            {
                try { row.pid = static_cast<uint32_t>(std::stoul(caller.get<std::string>())); }
                catch (const std::exception&) {}
            }
        }
        auto owner = row.pid ? Processes::describe(row.pid, 0, "Windows event process lifetime") : Owner{};
        normalizeProvider(row, owner);
    }
    storage_.enqueue(std::move(row));
}

Telemetry::~Telemetry() { stop(); }

void Telemetry::stop()
{
    stopped_ = true;
    subscriptions_.clear();
    if (thread_.joinable())
        thread_.join();
}
}
