#include "Capture.h"
#include "CertAuthority.h"
#include "HttpSpyStore.h"
#include "KeyLog.h"
#include "Proxy.h"
#include "Processes.h"
#include "Service.h"
#include "Storage.h"
#include "Telemetry.h"
#include "Configuration.h"

#include <array>
#include <atomic>
#include <iostream>
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace Cipherazzi
{
namespace MainDetail
{
std::atomic<bool> Stopped{};

BOOL WINAPI controlHandler(DWORD event)
{
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT)
        return FALSE;
    Stopped.store(true);
    return TRUE;
}

void printHelp()
{
    std::cout <<
        "Cipherazzi network cryptography collector\n\n"
        "  Cipherazzi.Collector.exe --db <file> [--duration <seconds>]\n"
        "  Cipherazzi.Collector.exe --db <file> --replay <capture.pcap>\n"
        "  Cipherazzi.Collector.exe --list-sources\n"
        "  Cipherazzi.Collector.exe --install [--db <file>] [capture options]\n"
        "  Cipherazzi.Collector.exe --uninstall\n\n"
        "Options:\n"
        "  --config <file>    Load JSON command options; relative paths resolve beside the file\n"
        "  --endpoint-only    Collect endpoint evidence without packet capture\n"
        "  --source <id>       Capture a specific Packet Monitor component; repeatable\n"
        "  --loopback-only     Capture same-host TCP/UDP using the packaged signed driver\n"
        "  --no-loopback       Capture network sources without same-host traffic\n"
        "  --max-flows <n>     Maximum tracked connections (default 32768)\n"
        "  --buffer-mb <n>     Reassembly memory budget (default 128 MiB)\n"
        "  --retention-days <n> Retain completed metadata for 30 days by default; 0 disables age cleanup\n"
        "  --retention-mb <n>  Target live journal size (default 512 MiB); 0 disables size cleanup\n"
        "  --replication-required Protect metadata until a relay acknowledges upload\n"
        "  --no-process       Disable local process attribution\n\n"
        "  --no-http          Disable general HTTP monitoring; retain authentication and tunnel evidence\n"
        "  --classify-raw     Flag high-entropy unknown TCP/UDP samples as possible encryption\n\n"
        "  --httpspy         Decode HTTP and HTTPS requests and responses (HTTP Spy) into <db folder>\\HttpSpy\n"
        "  --keylog <file>    Read exported TLS secrets; tail the file during passive live capture\n"
        "  --httpspy-host <pattern> Intercept matching SNI/IP only; * and ? wildcards; repeatable\n"
        "  --httpspy-process <name/pid> Intercept matching processes only; repeatable\n"
        "  --httpspy-port <ports> Intercept comma-separated HTTPS ports (default 443)\n"
        "  --httpspy-body-kb <n> Keep up to n KiB of each body (default 64); 0 keeps headers only\n"
        "  --httpspy-credentials Keep cookies, Authorization, and token header values (masked by default)\n"
        "  --httpspy-retention-days <n> Keep decoded messages 7 days by default; 0 disables age cleanup\n"
        "  --httpspy-retention-mb <n> Target decoded message store size (default 1024 MiB); 0 disables\n\n"
        "  --schannel         Subscribe to emitted Schannel and CAPI2 Windows events\n"
        "  --jfr-directory <dir> Watch atomic Java Flight Recorder JSON exports\n"
        "  --endpoint-directory <dir> Watch atomic TLS/raw socket JSON reports\n"
        "  --import-jfr <file> Import a JFR JSON export without packet capture\n\n"
        "Service installation requires elevation, copies the executable into System32, and starts\n"
        "the Cipherazzi service with automatic startup under LocalSystem. The default service\n"
        "journal is ProgramData\\Cipherazzi\\capture.db; --db persists an absolute custom path.\n"
        "Use sc.exe start Cipherazzi / sc.exe stop Cipherazzi to control the service.\n"
        "Uninstall preserves journals and logs. A running installer image is retired until reboot.\n"
        "Restart the service to apply changes to --config. Uninstall before replacing its binary or CLI options.\n\n"
        "Live capture requires an elevated console; network capture also requires Packet Monitor streaming APIs.\n"
        "Default sources are network interfaces; use --list-sources for other capture layers.\n"
        "Observes SSL 3.0 and TLS 1.0-1.3 over TCP, including STARTTLS on any port.\n"
        "Observes QUIC v1/v2 Initial hello messages over UDP, including Retry.\n"
        "Observes initial SSH 2.0 identification, algorithm negotiation, and NEWKEYS messages.\n"
        "Records supported visible SSH host-key metadata without establishing host trust.\n"
        "Observes UDP WireGuard handshakes, IKEv1 exchanges, IKEv2 SA_INIT, and clear OpenVPN control TLS.\n"
        "Supports OpenVPN TCP, SMB negotiation, RDP security exchange, and TDS-wrapped TLS.\n"
        "Observes HTTP/1.x and cleartext HTTP/2 metadata, clear authentication, and HTTP upgrades on any TCP port.\n"
        "Observes DCE/RPC bind protection and SMTP, IMAP, POP3, and FTP logins.\n"
        "Supports SMB NetBIOS, compressed framing, and SMB Direct over iWARP/RoCE.\n"
        "Records visible DTLS-SRTP profiles; media use and authentication remain unverified.\n"
        "VPN authentication, tunnel completion, and encrypted data are not established.\n"
        "Raw classification is optional; compression and random data can also have high entropy.\n"
        "Samples below 4096 bytes are not classified; raw cipher and key size remain unknown.\n"
        "Records server hello selections, not proof of a completed handshake.\n"
        "Observes DTLS 1.0/1.2/1.3 cleartext hellos, cookies, and bounded handshake fragments.\n"
        "Reassembles complete IPv4/IPv6 fragments; rejects conflicting or overlapping fragments.\n"
        "Tracks QUIC paths by visible IDs; encrypted ID rotation and path validation are unknown.\n"
        "Observes SSL 2.0 hellos, cipher choices, and errors at connection start or after STARTTLS.\n"
        "ECH inner SNI and TLS 1.3 selected ALPN are encrypted and cannot be read.\n"
        "Live capture includes network sources and same-host TCP/UDP by default.\n"
        "The signed loopback driver starts on demand with administrator privileges.\n"
        "Process attribution is best effort; missing packets leave incomplete evidence.\n"
        "Endpoint adapter directories must be writable only by trusted reporters.\n"
        "Adapter results retain provider provenance; the collector does not independently validate trust.\n"
        "Retention protects active flows and every registered relay's pending uploads.\n"
        "A protected backlog may exceed the size target; retention_state reports blocked cleanup.\n"
        "Without --keylog, live HTTP Spy intercepts selected IPv4/IPv6 TCP ports (default 443). It trusts a temporary\n"
        "root certificate in the machine Trusted Root store (removed on exit), validates each real server's\n"
        "certificate, terminates TLS 1.2 with the client, and relays HTTP/1.1. Applications that pin certificates or\n"
        "present client certificates can refuse interception. Host/process mismatches retain their original TLS.\n"
        "With --keylog, live capture and replay open TLS 1.2/1.3 (including HTTP/2) using exported secrets without\n"
        "interception. Live capture tails the file; it may be created after capture starts. Use SSLKEYLOGFILE in the\n"
        "target application's environment before launching it. This preserves pinning and mutual TLS. Secrets must be\n"
        "exported by the application; Schannel applications, QUIC/HTTP/3, and TLS 1.0/1.1 cannot be\n"
        "decoded. Decoded messages contain credentials and personal data: an elevated collector makes the store\n"
        "readable only by Administrators and SYSTEM.\n"
        "Persists protocol metadata, sample statistics, and public certificates. Press Ctrl+C to drain and stop.\n";
}

struct Options
{
    std::filesystem::path database = L"cipherazzi.db";
    std::filesystem::path replay;
    std::vector<uint32_t> sources;
    EngineLimits limits;
    RetentionLimits retention;
    uint64_t duration = 0;
    bool list = false;
    bool process = true;
    bool service = false;
    bool schannel = false;
    bool httpSpy = false;
    std::filesystem::path keylog;
    HttpSpyOptions plus;
    ProxyTargets targets;
    bool targeted{};
    int httpDays = 7;
    uint64_t httpMegabytes = 1024;
    std::filesystem::path javaDirectory;
    std::filesystem::path javaImport;
    std::filesystem::path endpointDirectory;
    bool endpointOnly = false;
    CaptureMode captureMode = CaptureMode::Combined;
};

void collect(const Options& options)
{
    Counters counters;
    std::unique_ptr<Processes> processes;
    if (options.process && options.replay.empty())
        processes = std::make_unique<Processes>(counters);
    serviceProgress(ServicePhase::Starting);
    std::cout << "Opening database: " << utf8(std::filesystem::absolute(options.database).wstring()) << std::endl;

    // Windows versions before Server 2022 have no Packet Monitor streaming. Same-host capture, process
    // attribution, and endpoint sources still work there, so the default selection continues with those.
    auto mode = options.captureMode;
    if (mode == CaptureMode::Combined && options.replay.empty() && !options.endpointOnly && options.sources.empty() &&
        !Capture::networkAvailable())
    {
        mode = CaptureMode::Loopback;
        std::cout << "Packet Monitor streaming is unavailable on this Windows version; "
            "capturing same-host traffic only." << std::endl;
    }
    const auto captureSource = mode != options.captureMode ?
        "Loopback / WinDivert / TCP+UDP; network capture is unavailable on this Windows version" :
        mode == CaptureMode::Loopback ? "Loopback / WinDivert / TCP+UDP" :
        mode == CaptureMode::Network ? "Packet Monitor / TCP+UDP+IPsec" :
        "Packet Monitor + WinDivert loopback / TCP+UDP+IPsec";
    IpsecAssociations associations;

    // A supplied key log selects passive decryption; otherwise live HTTP Spy intercepts TLS.
    KeyLog keys;
    std::unique_ptr<HttpSpy> plus;
    std::unique_ptr<CertAuthority> certAuthority;
    std::unique_ptr<Proxy> proxy;
    std::atomic<Proxy*> counted{};
    HttpSpyStorage httpStorage;
    if (options.httpSpy)
    {
        httpStorage = {HttpSpyStore::pathFor(std::filesystem::absolute(options.database)), {},
            options.httpDays, options.httpMegabytes * 1024 * 1024};
        if (!options.replay.empty() || !options.keylog.empty())
        {
            auto passiveOptions = options.plus;
            if (options.replay.empty())
                passiveOptions.secretWaitUs = 5000000;
            plus = std::make_unique<HttpSpy>(passiveOptions, keys, [&]
            {
                if (options.replay.empty())
                    keys.tail(options.keylog);
            });
            httpStorage.statistics = [&plus]
            {
                return std::array<uint64_t, 7>{plus->tlsFlows, plus->decoded, plus->withoutSecrets, plus->unsupported,
                    plus->failed, plus->exchanges, plus->keys().count()};
            };
            if (options.keylog.empty())
                std::cout << "No key log was supplied; only cleartext HTTP can be decoded." << std::endl;
            else if (!options.replay.empty())
                keys.load(options.keylog);
            else
            {
                keys.tail(options.keylog);
                std::cout << "HTTP Spy passive capture; tailing TLS key log: " << utf8(options.keylog.wstring())
                    << std::endl;
            }
        }
        else if (!options.endpointOnly)
        {
            std::cout << "HTTP Spy store: " << utf8(httpStorage.path.wstring()) << std::endl;
            httpStorage.statistics = [&counted]
            {
                const auto* live = counted.load();
                return live ? std::array<uint64_t, 7>{live->connections, live->intercepted, 0, 0,
                    live->failed, live->exchanges, 0} : std::array<uint64_t, 7>{};
            };
        }
    }
    Storage storage(options.database, counters, (options.endpointOnly ? "Endpoint telemetry" :
        options.replay.empty() ? captureSource : "PCAP: " + utf8(options.replay.wstring())) +
        (options.httpSpy ? (options.replay.empty() && options.keylog.empty() && !options.endpointOnly ?
            "; HTTP Spy proxy" : "; HTTP Spy passive") : ""),
        processes ? processes->status() : "Process attribution disabled for this session",
        options.replay.empty() ? Storage::Enricher([&](Observation& observation)
        {
            if (processes)
            {
                if (auto* live = counted.load()) live->attribute(observation, *processes);
                else processes->recheck(observation);
            }
            associations.enrich(observation);
        }) : Storage::Enricher{}, options.retention, processes != nullptr,
        processes ? Storage::OwnerChanges([&] { return processes->changes(); }) : Storage::OwnerChanges{},
        httpStorage);
    if (plus)
        plus->sink([&](HttpExchange exchange) { storage.enqueue(std::move(exchange), !options.replay.empty()); });

    // The proxy feeds the storage, so it stops first when the scope unwinds.
    struct StopProxy
    {
        std::unique_ptr<Proxy>& proxy;
        ~StopProxy() { if (proxy) proxy->stop(); }
    } stopProxy{proxy};
    if (options.httpSpy && options.keylog.empty() && options.replay.empty() && !options.endpointOnly)
    {
        certAuthority = std::make_unique<CertAuthority>();
        proxy = std::make_unique<Proxy>(*certAuthority, options.plus,
            [&](HttpExchange exchange) { storage.enqueue(std::move(exchange), false); }, options.targets);
        counted = proxy.get();
        std::cout << "HTTP Spy proxy active; root CA installed in machine Trusted Root store." << std::endl;
    }
    Telemetry telemetry(storage, counters, options.schannel, options.javaDirectory, options.endpointDirectory);
    serviceProgress(ServicePhase::Starting);
    Engine engine(counters, [&](Observation observation)
    {
        storage.enqueue(std::move(observation), !options.replay.empty());
    }, options.limits);
    engine.httpSpy(plus.get());
    try
    {
        if (!options.replay.empty())
            replayPcap(options.replay, engine, Stopped);
        else
        {
            std::unique_ptr<Capture> capture;
            if (!options.endpointOnly)
            {
                std::cout << "Starting packet capture..." << std::endl;
                capture = std::make_unique<Capture>(engine, counters, options.sources, mode);
                capture->check();
            }
            storage.check();
            serviceProgress(ServicePhase::Running);
            const auto readyName = L"Local\\Cipherazzi-Ready-" + std::to_wstring(GetCurrentProcessId());
            std::unique_ptr<void, decltype(&CloseHandle)> ready(
                CreateEventW(nullptr, TRUE, TRUE, readyName.c_str()), CloseHandle);
            std::cout << (options.endpointOnly ? "Collecting endpoint telemetry. " :
                "Capturing TLS, HTTP, SSH, VPN, and QUIC Initial handshakes. ")
                << (options.service ? "Stop using Services.\n" : "Press Ctrl+C to stop.\n")
                << (processes ? processes->status() : "Process attribution disabled") << std::endl;
            const auto started = GetTickCount64();
            auto refresh = started + 10000;
            auto report = started + 5000;
            while (!Stopped.load() && (!options.duration || GetTickCount64() - started < options.duration * 1000))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (plus && !options.keylog.empty())
                    keys.tail(options.keylog);
                if (capture)
                    capture->check();
                if (proxy)
                    proxy->check();
                storage.check();
                const auto tick = GetTickCount64();
                if (tick >= refresh)
                {
                    if (capture)
                        capture->refreshSources();
                    refresh = tick + 10000;
                }
                if (!options.service && tick >= report)
                {
                    std::cout << "Packets " << counters.packets << ", observations " << counters.observations
                        << ", capture/queue losses " << counters.captureLost + counters.queueLost << '\n';
                    report = tick + 5000;
                }
            }
            serviceProgress(ServicePhase::Stopping);
            if (capture)
            {
                if (plus && !options.keylog.empty())
                    keys.tail(options.keylog);
                capture->stop();
                capture->check();
            }
        }

        // Drain queued ETW events before persisting final process ownership and loss counters.
        serviceProgress(ServicePhase::Stopping);
        if (proxy) proxy->stop();
        if (processes)
            processes->stop();
        telemetry.stop();
        serviceProgress(ServicePhase::Stopping);
        storage.finish();
    }
    catch (const std::exception& error)
    {
        serviceProgress(ServicePhase::Stopping);
        engine.expire(nowUs(), true);
        if (proxy) proxy->stop();
        if (processes)
            processes->stop();
        telemetry.stop();
        serviceProgress(ServicePhase::Stopping);
        storage.finish(std::string("failed: ") + error.what());
        throw;
    }
    std::cout << "Saved metadata. Packets: " << counters.packets << "; observations: " << counters.observations
        << "; capture losses: " << counters.captureLost << "; queue losses: " << counters.queueLost
        << "; storage losses: " << counters.storageLost << '\n';
    if (plus)
        std::cout << "HTTP Spy: " << plus->exchanges << " messages from " << plus->decoded << " of " << plus->tlsFlows
            << " TLS connections; without logged secrets " << plus->withoutSecrets << ", unsupported "
            << plus->unsupported << ", failed " << plus->failed << ".\n";
    if (proxy)
    {
        std::cout << "HTTP Spy: " << proxy->exchanges << " messages; " << proxy->intercepted << " intercepted, "
            << proxy->relayed << " relayed, " << proxy->failed << " failed.\n";
        for (const auto& failure : proxy->failures())
            std::cout << "HTTP Spy not intercepted: " << failure << '\n';
    }
}

int run(int argc, wchar_t** argv)
{
    const auto arguments = configurationArguments({argv, static_cast<size_t>(argc)});
    Options options;
    bool install = false, uninstall = false, databaseSpecified = false;
    int serviceActions = 0;
    for (size_t i = 1; i < arguments.size(); ++i)
    {
        const auto& arg = arguments[i];
        if (arg == L"--help" || arg == L"-h")
        {
            printHelp();
            return 0;
        }
        if (arg == L"--list-sources")
            options.list = true;
        else if (arg == L"--no-process")
            options.process = false;
        else if (arg == L"--no-http")
            options.limits.http = false;
        else if (arg == L"--classify-raw")
            options.limits.raw = true;
        else if (arg == L"--schannel")
            options.schannel = true;
        else if (arg == L"--endpoint-only")
            options.endpointOnly = true;
        else if (arg == L"--httpspy")
            options.httpSpy = true;
        else if (arg == L"--httpspy-credentials")
            options.plus.credentials = true;
        else if (arg == L"--loopback-only" || arg == L"--no-loopback")
        {
            if (options.captureMode != CaptureMode::Combined)
                throw std::runtime_error("Choose one loopback capture mode");
            options.captureMode = arg == L"--loopback-only" ? CaptureMode::Loopback : CaptureMode::Network;
        }
        else if (arg == L"--replication-required")
            options.retention.replicationRequired = true;
        else if (arg == L"--install" || arg == L"--uninstall" || arg == L"--service")
        {
            install = arg == L"--install";
            uninstall = arg == L"--uninstall";
            options.service = arg == L"--service";
            if (++serviceActions > 1)
                throw std::runtime_error("Choose one service operation");
        }
        else
        {
            constexpr std::wstring_view valued[]{L"--db", L"--replay", L"--endpoint-directory", L"--jfr-directory",
                L"--import-jfr", L"--duration", L"--source", L"--max-flows", L"--buffer-mb", L"--retention-days",
                L"--retention-mb", L"--keylog", L"--httpspy-body-kb", L"--httpspy-retention-days",
                L"--httpspy-retention-mb", L"--httpspy-host", L"--httpspy-process", L"--httpspy-port"};
            if (std::ranges::find(valued, arg) == std::end(valued))
                throw std::runtime_error("Unknown option: " + utf8(arg) + "; use --help");
            if (++i == arguments.size())
                throw std::runtime_error("Missing option value; use --help");
            const auto& value = arguments[i];
            if (value.empty())
                throw std::runtime_error("Option values cannot be empty");
            if (arg == L"--db")
            {
                options.database = value;
                databaseSpecified = true;
            }
            else if (arg == L"--replay")
                options.replay = value;
            else if (arg == L"--endpoint-directory")
                options.endpointDirectory = std::filesystem::absolute(value).lexically_normal();
            else if (arg == L"--jfr-directory")
                options.javaDirectory = std::filesystem::absolute(value).lexically_normal();
            else if (arg == L"--import-jfr")
                options.javaImport = value;
            else if (arg == L"--keylog")
                options.keylog = value;
            else if (arg == L"--httpspy-host" || arg == L"--httpspy-process" || arg == L"--httpspy-port")
            {
                const auto text = utf8(value);
                if (text.size() > 1024 || std::ranges::any_of(text, [&](unsigned char c)
                    { return c < 32 || (c == ' ' && arg != L"--httpspy-process"); }))
                    throw std::runtime_error("HTTP Spy targets must be nonempty names, patterns, PIDs, or ports");
                if (arg == L"--httpspy-port")
                    options.targets.setPorts(text);
                else
                    (arg == L"--httpspy-host" ? options.targets.hosts : options.targets.processes).push_back(text);
                options.targeted = true;
            }
            else
            {
                if (value.find_first_not_of(L"0123456789") != std::wstring::npos)
                    throw std::runtime_error("Expected a whole number for " + utf8(arg));
                const auto number = value.size() > 10 ? UINT64_MAX : std::stoull(value);
                if ((number == 0 && arg != L"--retention-days" && arg != L"--retention-mb" &&
                    !arg.starts_with(L"--httpspy-")) || number > 1000000000)
                    throw std::runtime_error("Option value is out of range");
                if (arg == L"--duration")
                    options.duration = number;
                else if (arg == L"--source")
                    options.sources.push_back(static_cast<uint32_t>(number));
                else if (arg == L"--max-flows" && number <= 1000000)
                    options.limits.flows = static_cast<size_t>(number);
                else if (arg == L"--buffer-mb" && number <= 4096)
                    options.limits.bytes = static_cast<size_t>(number * 1024 * 1024);
                else if (arg == L"--retention-days" && number <= 36500)
                    options.retention.days = static_cast<uint32_t>(number);
                else if (arg == L"--retention-mb" && number <= 1048576)
                    options.retention.bytes = number * 1024 * 1024;
                else if (arg == L"--httpspy-body-kb" && number <= 16384)
                    options.plus.bodyBytes = static_cast<size_t>(number * 1024);
                else if (arg == L"--httpspy-retention-days" && number <= 36500)
                    options.httpDays = static_cast<int>(number);
                else if (arg == L"--httpspy-retention-mb" && number <= 1048576)
                    options.httpMegabytes = number;
                else
                    throw std::runtime_error("Option value is out of range: " + utf8(arg));
            }
        }
    }
    if (options.captureMode != CaptureMode::Combined && (options.endpointOnly || !options.replay.empty() ||
        !options.javaImport.empty() || options.list))
        throw std::runtime_error("Loopback capture options require live packet collection");
    if (options.captureMode == CaptureMode::Loopback && !options.sources.empty())
        throw std::runtime_error("Loopback-only capture cannot select network sources");
    if (!options.httpSpy && (!options.keylog.empty() || options.plus.credentials))
        throw std::runtime_error("HTTP Spy options require --httpspy");
    if (options.targeted && (!options.httpSpy || !options.keylog.empty() || !options.replay.empty()))
        throw std::runtime_error("HTTP Spy target filters apply to live interception without --keylog");
    if (options.httpSpy && (options.endpointOnly || options.list || !options.javaImport.empty()))
        throw std::runtime_error("HTTP Spy decodes captured or replayed packets and cannot be combined with "
            "endpoint-only collection, source listing, or JFR import");
    if (options.endpointOnly && (!options.replay.empty() || options.list || !options.javaImport.empty() ||
        !options.sources.empty() ||
        (!options.schannel && options.javaDirectory.empty() && options.endpointDirectory.empty())))
        throw std::runtime_error("Endpoint-only mode requires an endpoint source and cannot capture or replay packets");
    if (uninstall)
    {
        if (arguments.size() != 2)
            throw std::runtime_error("--uninstall does not accept capture options");
        uninstallService();
        return 0;
    }
    if (install || options.service)
    {
        if (!options.replay.empty() || options.duration || options.list || !options.javaImport.empty())
            throw std::runtime_error("Service mode requires continuous live capture; "
                "replay, duration, and listing are unavailable");
        options.database = databaseSpecified ? std::filesystem::absolute(options.database).lexically_normal() :
            serviceDatabase();
        if (install)
        {
            // Preserve the configuration reference so every service start reads current settings.
            std::vector<std::wstring> persisted;
            for (int index = 1; index < argc; ++index)
            {
                const std::wstring_view argument = argv[index];
                if (argument == L"--install")
                    continue;
                persisted.emplace_back(argument);
                if (argument == L"--config" || argument == L"--db" || argument == L"--jfr-directory" ||
                    argument == L"--endpoint-directory" || argument == L"--keylog")
                    persisted.push_back(std::filesystem::absolute(argv[++index]).lexically_normal().wstring());
            }
            installService(persisted);
            return 0;
        }
        collect(options);
        return 0;
    }
    if (!options.javaImport.empty())
    {
        if (!options.replay.empty() || options.list || options.schannel || !options.javaDirectory.empty() ||
            !options.endpointDirectory.empty() || options.duration)
            throw std::runtime_error("JFR import cannot be combined with capture options");
        Counters counters;
        Storage storage(options.database, counters, "Java Flight Recorder import", "PID from export, when supplied",
            {}, options.retention);
        const auto count = Telemetry::importJava(options.javaImport, storage);
        storage.finish();
        std::cout << "Imported " << count << " endpoint events.\n";
        return 0;
    }
    if (((options.replay.empty() && !options.endpointOnly) || options.list) && !elevated())
        throw std::runtime_error("Live capture requires administrator privileges. Run from an elevated console.");
    if (options.list)
    {
        Capture::listSources();
        return 0;
    }
    SetConsoleCtrlHandler(controlHandler, TRUE);
    collect(options);
    return 0;
}
}
using namespace MainDetail;
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        // Register with SCM before reading service configuration or starting capture workers.
        if (std::any_of(argv + 1, argv + argc,
            [](const wchar_t* argument) { return std::wstring_view(argument) == L"--service"; }))
            return Cipherazzi::runService(Cipherazzi::Stopped, [&] { Cipherazzi::run(argc, argv); });
        return Cipherazzi::run(argc, argv);
    }
    catch (const std::exception& error)
    {
        std::cerr << "Cipherazzi: " << error.what() << '\n';
        return 1;
    }
}
