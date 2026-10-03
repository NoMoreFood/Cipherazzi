#include "Capture.h"
#include "Processes.h"
#include "Service.h"
#include "Storage.h"
#include "Telemetry.h"
#include "Configuration.h"

#include <iostream>
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace Cipherazzi
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
        "  --classify-raw     Flag high-entropy unknown TCP/UDP samples as possible encryption\n\n"
        "  --schannel         Subscribe to emitted Schannel and CAPI2 Windows events\n"
        "  --jfr-directory <dir> Watch atomic Java Flight Recorder JSON exports\n"
        "  --endpoint-directory <dir> Watch atomic TLS/raw socket JSON reports\n"
        "  --import-jfr <file> Import a JFR JSON export without packet capture\n\n"
        "Service installation requires elevation, copies the executable into System32, and starts\n"
        "the Cipherazzi service with automatic startup under LocalSystem. The default service\n"
        "journal is ProgramData\\Cipherazzi\\capture.db; --db persists an absolute custom path.\n"
        "Use sc.exe start Cipherazzi / sc.exe stop Cipherazzi to control the service.\n"
        "Uninstall preserves journals and logs. A running installer image is retired until reboot.\n"
        "Uninstall before installing a different binary or changing capture options.\n\n"
        "Live capture requires an elevated console; network capture also requires Packet Monitor streaming APIs.\n"
        "Default sources are network interfaces; use --list-sources for other capture layers.\n"
        "Observes SSL 3.0 and TLS 1.0-1.3 over TCP, including STARTTLS on any port.\n"
        "Observes QUIC v1/v2 Initial hello messages over UDP, including Retry.\n"
        "Observes initial SSH 2.0 identification, algorithm negotiation, and NEWKEYS messages.\n"
        "Records supported visible SSH host-key metadata without establishing host trust.\n"
        "Observes UDP WireGuard handshake formats, IKEv2 SA_INIT, and clear OpenVPN control TLS.\n"
        "Supports clear OpenVPN TCP framing, SMB negotiation, RDP negotiation, and TDS-wrapped TLS.\n"
        "Supports SMB NetBIOS, compressed framing, and SMB Direct over iWARP/RoCE.\n"
        "Records visible DTLS-SRTP profiles; media use and authentication remain unverified.\n"
        "VPN authentication, tunnel completion, and encrypted data are not established.\n"
        "Raw classification is optional; compression and random data can also have high entropy.\n"
        "Samples below 4096 bytes are not classified; raw cipher and key size remain unknown.\n"
        "Records server hello selections, not proof of a completed handshake.\n"
        "Observes DTLS 1.0/1.2/1.3 cleartext hellos, cookies, and bounded handshake fragments.\n"
        "Reassembles complete IPv4/IPv6 fragments; rejects conflicting or overlapping fragments.\n"
        "Tracks QUIC paths by visible IDs; encrypted ID rotation and path validation are unknown.\n"
        "SSL 2.0 is not supported.\n"
        "ECH inner SNI and TLS 1.3 selected ALPN are encrypted and cannot be read.\n"
        "Live capture includes network sources and same-host TCP/UDP by default.\n"
        "The signed loopback driver starts on demand with administrator privileges.\n"
        "Process attribution is best effort; missing packets leave incomplete evidence.\n"
        "Endpoint adapter directories must be writable only by trusted reporters.\n"
        "Adapter results retain provider provenance; the collector does not independently validate trust.\n"
        "Retention protects active flows and every registered relay's pending uploads.\n"
        "A protected backlog may exceed the size target; retention_state reports blocked cleanup.\n"
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
    std::filesystem::path javaDirectory;
    std::filesystem::path javaImport;
    std::filesystem::path endpointDirectory;
    bool endpointOnly = false;
    CaptureMode captureMode = CaptureMode::Combined;
};

void collect(const Options& options)
{
    const auto& [database, replay, sources, limits, retention, duration, list, process, service,
        schannel, javaDirectory, javaImport, endpointDirectory, endpointOnly, captureMode] = options;
    Counters counters;
    std::unique_ptr<Processes> processes;
    if (process && replay.empty())
        processes = std::make_unique<Processes>(counters);
    serviceProgress(ServicePhase::Starting);
    std::cout << "Opening database: " << utf8(std::filesystem::absolute(database).wstring()) << std::endl;
    const auto captureSource = captureMode == CaptureMode::Loopback ? "Loopback / WinDivert / TCP+UDP" :
        captureMode == CaptureMode::Network ? "Packet Monitor / TCP+UDP" :
            "Packet Monitor + WinDivert loopback / TCP+UDP";
    Storage storage(database, counters, endpointOnly ? "Endpoint telemetry" :
        replay.empty() ? captureSource : "PCAP: " + utf8(replay.wstring()),
        processes ? processes->status() : "Process attribution disabled for this session",
        processes ? Storage::Enricher([&](Observation& observation) { processes->enrich(observation); }) :
            Storage::Enricher{}, retention);
    Telemetry telemetry(storage, counters, schannel, javaDirectory, endpointDirectory);
    serviceProgress(ServicePhase::Starting);
    Engine engine(counters, [&](Observation observation)
    {
        storage.enqueue(std::move(observation), !replay.empty());
    }, limits);
    try
    {
        if (!replay.empty())
            replayPcap(replay, engine, Stopped);
        else
        {
            std::unique_ptr<Capture> capture;
            if (!endpointOnly)
            {
                std::cout << "Starting packet capture..." << std::endl;
                capture = std::make_unique<Capture>(engine, counters, sources, captureMode);
                capture->check();
            }
            storage.check();
            serviceProgress(ServicePhase::Running);
            std::cout << (endpointOnly ? "Collecting endpoint telemetry. " :
                "Capturing TLS, SSH, VPN, and QUIC Initial handshakes. ")
                << (service ? "Stop using Services.\n" : "Press Ctrl+C to stop.\n")
                << (processes ? processes->status() : "Process attribution disabled") << std::endl;
            const auto started = GetTickCount64();
            auto refresh = started + 10000;
            auto report = started + 5000;
            while (!Stopped.load() && (!duration || GetTickCount64() - started < duration * 1000))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (capture)
                    capture->check();
                storage.check();
                const auto tick = GetTickCount64();
                if (tick >= refresh)
                {
                    if (capture)
                        capture->refreshSources();
                    refresh = tick + 10000;
                }
                if (!service && tick >= report)
                {
                    std::cout << "Packets " << counters.packets << ", observations " << counters.observations
                        << ", capture/queue losses " << counters.captureLost + counters.queueLost << '\n';
                    report = tick + 5000;
                }
            }
            serviceProgress(ServicePhase::Stopping);
            if (capture)
            {
                capture->stop();
                capture->check();
            }
        }

        // Drain queued ETW events before persisting final process ownership and loss counters.
        serviceProgress(ServicePhase::Stopping);
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
}

int run(int argc, wchar_t** argv)
{
    auto configured = configurationArguments({argv, static_cast<size_t>(argc)});
    std::vector<wchar_t*> pointers;
    for (auto& argument : configured)
        pointers.push_back(argument.data());
    argc = static_cast<int>(pointers.size());
    argv = pointers.data();
    Options options;
    auto& [database, replay, sources, limits, retention, duration, list, process, service,
        schannel, javaDirectory, javaImport, endpointDirectory, endpointOnly, captureMode] = options;
    bool install = false, uninstall = false, databaseSpecified = false;
    int serviceActions = 0;
    for (int i = 1; i < argc; ++i)
    {
        const std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"-h")
        {
            printHelp();
            return 0;
        }
        if (arg == L"--list-sources")
            list = true;
        else if (arg == L"--no-process")
            process = false;
        else if (arg == L"--classify-raw")
            limits.raw = true;
        else if (arg == L"--schannel")
            schannel = true;
        else if (arg == L"--endpoint-only")
            endpointOnly = true;
        else if (arg == L"--loopback-only" || arg == L"--no-loopback")
        {
            if (captureMode != CaptureMode::Combined)
                throw std::runtime_error("Choose one loopback capture mode");
            captureMode = arg == L"--loopback-only" ? CaptureMode::Loopback : CaptureMode::Network;
        }
        else if (arg == L"--replication-required")
            retention.replicationRequired = true;
        else if (arg == L"--install" || arg == L"--uninstall" || arg == L"--service")
        {
            install = arg == L"--install";
            uninstall = arg == L"--uninstall";
            service = arg == L"--service";
            if (++serviceActions > 1)
                throw std::runtime_error("Choose one service operation");
        }
        else
        {
            if (++i == argc)
                throw std::runtime_error("Missing option value; use --help");
            const std::wstring value = argv[i];
            if (value.empty())
                throw std::runtime_error("Option values cannot be empty");
            if (arg == L"--db")
            {
                database = value;
                databaseSpecified = true;
            }
            else if (arg == L"--replay")
                replay = value;
            else if (arg == L"--endpoint-directory")
                endpointDirectory = std::filesystem::absolute(value).lexically_normal();
            else if (arg == L"--jfr-directory")
                javaDirectory = std::filesystem::absolute(value).lexically_normal();
            else if (arg == L"--import-jfr")
                javaImport = value;
            else
            {
                size_t end = 0;
                if (value.empty() || value[0] == L'-')
                    throw std::runtime_error("Expected a positive option value");
                const auto number = std::stoull(value, &end);
                if (end != value.size() || (number == 0 && arg != L"--retention-days" &&
                    arg != L"--retention-mb") || number > 1000000000)
                    throw std::runtime_error("Option value is out of range");
                if (arg == L"--duration")
                    duration = number;
                else if (arg == L"--source")
                    sources.push_back(static_cast<uint32_t>(number));
                else if (arg == L"--max-flows" && number <= 1000000)
                    limits.flows = static_cast<size_t>(number);
                else if (arg == L"--buffer-mb" && number <= 4096)
                    limits.bytes = static_cast<size_t>(number * 1024 * 1024);
                else if (arg == L"--retention-days" && number <= 36500)
                    retention.days = static_cast<uint32_t>(number);
                else if (arg == L"--retention-mb" && number <= 1048576)
                    retention.bytes = number * 1024 * 1024;
                else
                    throw std::runtime_error("Unknown option or out-of-range value: " + utf8(arg));
            }
        }
    }
    if (captureMode != CaptureMode::Combined && (endpointOnly || !replay.empty() || !javaImport.empty() || list))
        throw std::runtime_error("Loopback capture options require live packet collection");
    if (captureMode == CaptureMode::Loopback && !sources.empty())
        throw std::runtime_error("Loopback-only capture cannot select network sources");
    if (endpointOnly && (!replay.empty() || list || !javaImport.empty() || !sources.empty() ||
        (!schannel && javaDirectory.empty() && endpointDirectory.empty())))
        throw std::runtime_error("Endpoint-only mode requires an endpoint source and cannot capture or replay packets");
    if (uninstall)
    {
        if (argc != 2)
            throw std::runtime_error("--uninstall does not accept capture options");
        uninstallService();
        return 0;
    }
    if (install || service)
    {
        if (!replay.empty() || duration || list || !javaImport.empty())
            throw std::runtime_error("Service mode requires continuous live capture; "
                "replay, duration, and listing are unavailable");
        database = databaseSpecified ? std::filesystem::absolute(database).lexically_normal() : serviceDatabase();
        if (install)
        {
            std::vector<std::wstring> arguments{L"--db", database.wstring(),
                L"--max-flows", std::to_wstring(limits.flows), L"--buffer-mb", std::to_wstring(limits.bytes / 1048576),
                L"--retention-days", std::to_wstring(retention.days),
                L"--retention-mb", std::to_wstring(retention.bytes / 1048576)};
            if (retention.replicationRequired)
                arguments.push_back(L"--replication-required");
            for (const auto source : sources)
                arguments.insert(arguments.end(), {L"--source", std::to_wstring(source)});
            if (!process)
                arguments.push_back(L"--no-process");
            if (limits.raw)
                arguments.push_back(L"--classify-raw");
            if (schannel)
                arguments.push_back(L"--schannel");
            if (endpointOnly)
                arguments.push_back(L"--endpoint-only");
            if (captureMode != CaptureMode::Combined)
                arguments.push_back(captureMode == CaptureMode::Loopback ? L"--loopback-only" : L"--no-loopback");
            if (!javaDirectory.empty())
                arguments.insert(arguments.end(), {L"--jfr-directory", javaDirectory.wstring()});
            if (!endpointDirectory.empty())
                arguments.insert(arguments.end(), {L"--endpoint-directory", endpointDirectory.wstring()});
            installService(arguments);
            return 0;
        }
        collect(options);
        return 0;
    }
    if (!javaImport.empty())
    {
        if (!replay.empty() || list || schannel || !javaDirectory.empty() || !endpointDirectory.empty() || duration)
            throw std::runtime_error("JFR import cannot be combined with capture options");
        Counters counters;
        Storage storage(database, counters, "Java Flight Recorder import", "PID from export, when supplied",
            {}, retention);
        const auto count = Telemetry::importJava(javaImport, storage);
        storage.finish();
        std::cout << "Imported " << count << " endpoint events.\n";
        return 0;
    }
    if (((replay.empty() && !endpointOnly) || list) && !elevated())
        throw std::runtime_error("Live capture requires administrator privileges. Run from an elevated console.");
    if (list)
    {
        Capture::listSources();
        return 0;
    }
    SetConsoleCtrlHandler(controlHandler, TRUE);
    collect(options);
    return 0;
}
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
