#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <objbase.h>
#include <frida-core.h>
#include <cmath>
#include <utility>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <vector>
#include <thread>

#include "BrowserControl.h"
#include "ChromiumControl.h"

namespace Cipherazzi
{
#include "../collector/TlsRegistry.inc"
using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
template<typename T> using FridaObject = std::unique_ptr<T, decltype(&frida_unref)>;
std::atomic<bool> AdapterStopped{};

std::string utf8(std::wstring_view value)
{
    if (value.empty())
        return {};
    const auto length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!length)
        throw std::runtime_error("A path could not be converted to UTF-8.");
    std::string result(length, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        result.data(), length, nullptr, nullptr);
    return result;
}

std::string adapterResource(WORD id)
{
    const auto resource = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    const auto loaded = resource ? LoadResource(nullptr, resource) : nullptr;
    const auto bytes = loaded ? static_cast<const char*>(LockResource(loaded)) : nullptr;
    const auto size = resource ? SizeofResource(nullptr, resource) : 0;
    if (!bytes || !size)
        throw std::runtime_error("The bundled endpoint observer is unavailable.");
    const auto bom = size >= 3 && static_cast<unsigned char>(bytes[0]) == 0xef &&
        static_cast<unsigned char>(bytes[1]) == 0xbb && static_cast<unsigned char>(bytes[2]) == 0xbf ? 3 : 0;
    return {bytes + bom, size - bom};
}

void requireFrida(GError*& error)
{
    if (!error)
        return;
    std::unique_ptr<GError, decltype(&g_error_free)> owned(error, g_error_free);
    error = nullptr;
    throw std::runtime_error(owned->message);
}

BOOL WINAPI adapterControl(DWORD event)
{
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT)
        return FALSE;
    AdapterStopped = true;
    return TRUE;
}

struct AdapterOptions
{
    DWORD pid{};
    std::filesystem::path program, output;
    std::filesystem::path browserProfile;
    std::vector<std::string> arguments;
    std::string provider = "auto";
    std::string browserUrl;
    uint32_t duration{}, maxFiles = 4096, maxAge = 86400;
    uint64_t maxBytes = 128 * 1024 * 1024;
    bool children = true;
};

AdapterOptions options(int count, wchar_t** arguments)
{
    AdapterOptions result;
    for (int index = 1; index < count; ++index)
    {
        const std::wstring argument(arguments[index]);
        if (argument == L"--no-children")
        {
            result.children = false;
            continue;
        }
        if (argument == L"--")
        {
            if (result.program.empty())
                throw std::runtime_error("Application arguments require --spawn.");
            while (++index < count)
                result.arguments.push_back(utf8(arguments[index]));
            break;
        }
        if (index + 1 == count)
            throw std::runtime_error("An option value is missing.");
        const std::wstring value(arguments[++index]);
        auto number = [&](uint64_t minimum, uint64_t maximum)
        {
            if (value.empty() || value.find_first_not_of(L"0123456789") != std::wstring::npos)
                throw std::runtime_error("Options require bounded whole numbers.");
            const auto parsed = std::stoull(value);
            if (parsed < minimum || parsed > maximum)
                throw std::runtime_error("An option value is outside its supported range.");
            return parsed;
        };
        if (argument == L"--pid") result.pid = static_cast<DWORD>(number(1, MAXDWORD));
        else if (argument == L"--spawn") result.program = std::filesystem::absolute(value);
        else if (argument == L"--output") result.output = std::filesystem::absolute(value);
        else if (argument == L"--provider") result.provider = utf8(value);
        else if (argument == L"--browser-profile") result.browserProfile = std::filesystem::absolute(value);
        else if (argument == L"--url") result.browserUrl = utf8(value);
        else if (argument == L"--duration") result.duration = static_cast<uint32_t>(number(0, 86400));
        else if (argument == L"--max-files") result.maxFiles = static_cast<uint32_t>(number(1, 65536));
        else if (argument == L"--max-age") result.maxAge = static_cast<uint32_t>(number(1, 2592000));
        else if (argument == L"--max-mb") result.maxBytes = number(4, 4096) * 1024 * 1024;
        else throw std::runtime_error("Unknown endpoint adapter option.");
    }
    if ((result.pid != 0) == !result.program.empty() || result.output.empty() ||
        (result.provider != "auto" && result.provider != "openssl" && result.provider != "boringssl" &&
        result.provider != "nss" && result.provider != "firefox" && result.provider != "chromium"))
        throw std::runtime_error("Specify --output and either --pid or --spawn; choose a supported provider.");
    if ((result.provider == "firefox" || result.provider == "chromium") && result.program.empty())
        throw std::runtime_error("Browser observation starts a dedicated browser with --spawn.");
    if (result.provider != "firefox" && result.provider != "chromium" &&
        (!result.browserProfile.empty() || !result.browserUrl.empty()))
        throw std::runtime_error("Browser profile and URL options require a browser provider.");
    if (!result.program.empty())
    {
        if (!std::filesystem::is_regular_file(result.program))
            throw std::runtime_error("The application executable does not exist.");
        result.arguments.insert(result.arguments.begin(), utf8(result.program.wstring()));
    }
    std::filesystem::create_directories(result.output);
    return result;
}

class AdapterRun
{
    struct ObservedProcess
    {
        AdapterRun& owner;
        DWORD pid{};
        Handle process{nullptr, CloseHandle};
        int64_t started{};
        std::string name, path;
        FridaObject<FridaSession> session{nullptr, frida_unref};
        FridaObject<FridaScript> script{nullptr, frida_unref};
        std::atomic<bool> detached{};
        bool gated{};
        gulong detachedSignal{}, messageSignal{};
    };
    struct PendingChild
    {
        DWORD pid{};
        bool afterStartup{}, resumed{};
        std::chrono::steady_clock::time_point ready;
        Handle process{nullptr, CloseHandle};
    };

public:
    explicit AdapterRun(AdapterOptions configured) : configured_(std::move(configured))
    {
        frida_init();
        loop_.reset(g_main_loop_new(nullptr, FALSE));
        manager_.reset(frida_device_manager_new());
        GUID id{};
        wchar_t text[40]{};
        if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id, text, static_cast<int>(std::size(text))))
            throw std::runtime_error("An endpoint report identifier could not be created.");
        prefix_ = L"cipherazzi-endpoint-" + std::wstring(text + 1, text + 37) + L"-";
        // Coordinate reporters that publish to the same directory.
        auto directory = std::filesystem::weakly_canonical(configured_.output).wstring();
        CharUpperBuffW(directory.data(), static_cast<DWORD>(directory.size()));
        const auto encoded = utf8(directory);
        std::unique_ptr<gchar, decltype(&g_free)> hash(g_compute_checksum_for_string(G_CHECKSUM_SHA256,
            encoded.c_str(), static_cast<gssize>(encoded.size())), g_free);
        const auto name = L"Local\\Cipherazzi.EndpointReports." +
            std::wstring(hash.get(), hash.get() + std::strlen(hash.get()));
        directoryMutex_.reset(CreateMutexW(nullptr, FALSE, name.c_str()));
        if (!directoryMutex_)
            throw std::runtime_error("The endpoint report directory could not be coordinated.");
    }

    ~AdapterRun()
    {
        // Release instrumentation without stopping an attached or resumed application.
        stopping_ = true;
        if (timer_)
            g_source_remove(timer_);
        if (device_)
        {
            g_signal_handlers_disconnect_by_data(device_.get(), this);
            FridaObject<FridaChildList> pending(frida_device_enumerate_pending_children_sync(
                device_.get(), nullptr, nullptr), frida_unref);
            if (pending)
                for (int index = 0; index < frida_child_list_size(pending.get()); ++index)
                {
                    FridaObject<FridaChild> child(frida_child_list_get(pending.get(), index), frida_unref);
                    if (gatedPids_.contains(frida_child_get_parent_pid(child.get())))
                        frida_device_resume_sync(device_.get(), frida_child_get_pid(child.get()), nullptr, nullptr);
                }
        }
        for (const auto& process : processes_)
            release(*process);
        if (spawned_ && !resumed_ && device_)
            frida_device_kill_sync(device_.get(), pid_, nullptr, nullptr);
        if (manager_)
            frida_device_manager_close_sync(manager_.get(), nullptr, nullptr);
        processes_.clear();
        root_.reset();
        device_.reset();
        manager_.reset();
        loop_.reset();
        frida_deinit();
        if (browserSockets_)
            WSACleanup();
    }

    int run()
    {
        // Attach before a spawned application executes its TLS code.
        GError* error{};
        device_.reset(frida_device_manager_get_device_by_type_sync(manager_.get(),
            FRIDA_DEVICE_TYPE_LOCAL, 5000, nullptr, &error));
        requireFrida(error);
        if (configured_.provider == "firefox")
            return runFirefox();
        if (configured_.provider == "chromium")
            return runChromium();
        g_signal_connect(device_.get(), "child-added", G_CALLBACK(childAdded), this);
        pid_ = configured_.pid;
        if (!configured_.program.empty())
        {
            FridaObject<FridaSpawnOptions> spawn(frida_spawn_options_new(), frida_unref);
            std::vector<gchar*> argv;
            for (auto& argument : configured_.arguments)
                argv.push_back(argument.data());
            frida_spawn_options_set_argv(spawn.get(), argv.data(), static_cast<gint>(argv.size()));
            frida_spawn_options_set_stdio(spawn.get(), FRIDA_STDIO_INHERIT);
            const auto program = utf8(configured_.program.wstring());
            pid_ = frida_device_spawn_sync(device_.get(), program.c_str(), spawn.get(), nullptr, &error);
            requireFrida(error);
            spawned_ = true;
        }
        // Use the bundled observer; application buffers and key material never enter the report path.
        source_ = "const adapterOptions = " +
            nlohmann::json{{"provider", configured_.provider}}.dump() + ";\n";
        source_ += adapterResource(101);
        root_ = instrument(identity(pid_));
        if (!spawned_ && configured_.children)
        {
            try { discoverChildren(); }
            catch (const std::exception& error)
            {
                incomplete_ = true;
                std::cerr << "Existing child observation is incomplete: " << error.what() << '\n';
            }
        }
        started_ = std::chrono::steady_clock::now();
        timer_ = g_timeout_add(100, poll, this);
        if (spawned_)
        {
            frida_device_resume_sync(device_.get(), pid_, nullptr, &error);
            requireFrida(error);
            resumed_ = true;
        }
        if (!failed_)
            g_main_loop_run(loop_.get());
        std::cout << "Endpoint observation stopped; " << reports_ << " reports written.\n";
        if (!adapters_)
            std::cerr << "No supported public endpoint APIs were observed.\n";
        if (failed_)
            return 1;
        if (spawned_ && WaitForSingleObject(root_->process.get(), 0) == WAIT_OBJECT_0)
        {
            DWORD status{};
            if (GetExitCodeProcess(root_->process.get(), &status))
            {
                std::cout << "Application exit code: " << status << '\n';
                if (status)
                    return static_cast<int>(status);
            }
        }
        return adapters_ && !incomplete_ ? 0 : 2;
    }

private:
    AdapterOptions configured_;
    Handle directoryMutex_{nullptr, CloseHandle};
    FridaObject<FridaDeviceManager> manager_{nullptr, frida_unref};
    FridaObject<FridaDevice> device_{nullptr, frida_unref};
    std::vector<std::shared_ptr<ObservedProcess>> processes_;
    std::shared_ptr<ObservedProcess> root_;
    std::set<DWORD> gatedPids_;
    std::vector<PendingChild> children_;
    std::unique_ptr<GMainLoop, decltype(&g_main_loop_unref)> loop_{nullptr, g_main_loop_unref};
    std::mutex outputMutex_;
    DWORD pid_{};
    std::string source_;
    std::wstring prefix_;
    std::atomic<bool> failed_{}, stopping_{}, incomplete_{};
    std::atomic<uint64_t> reports_{}, adapters_{};
    bool spawned_{}, resumed_{};
    bool browserSockets_{};
    guint timer_{};
    std::chrono::steady_clock::time_point started_;
    std::chrono::steady_clock::time_point lastPruned_;

    std::shared_ptr<ObservedProcess> identity(DWORD pid, Handle retained = {nullptr, CloseHandle})
    {
        // Retain each process identity independently before observing its public endpoint APIs.
        auto process = std::make_shared<ObservedProcess>(*this);
        process->pid = pid;
        process->process = retained ? std::move(retained) :
            Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid), CloseHandle);
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!process->process || GetProcessId(process->process.get()) != pid ||
            !GetProcessTimes(process->process.get(), &created, &exited, &kernel, &user))
            throw std::runtime_error("The target process identity could not be read.");
        const auto ticks = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        process->started = (static_cast<int64_t>(ticks) - 116444736000000000LL) / 10;
        std::wstring path(32768, L'\0');
        DWORD length = static_cast<DWORD>(path.size());
        if (QueryFullProcessImageNameW(process->process.get(), 0, path.data(), &length))
        {
            path.resize(length);
            process->path = utf8(path);
            process->name = utf8(std::filesystem::path(path).filename().wstring());
        }
        return process;
    }

    std::shared_ptr<ObservedProcess> instrument(std::shared_ptr<ObservedProcess> process)
    {
        const auto pid = process->pid;
        if (WaitForSingleObject(process->process.get(), 0) != WAIT_TIMEOUT)
            throw std::runtime_error("The target process exited before observation.");

        // Respect process protections that prohibit the observer's DLL or public API hooks.
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCode{};
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signatures{};
        if (GetProcessMitigationPolicy(process->process.get(), ProcessDynamicCodePolicy,
            &dynamicCode, sizeof(dynamicCode)) && dynamicCode.ProhibitDynamicCode)
            throw std::runtime_error("The process prohibits dynamic code; its endpoint APIs remain unobserved.");
        if (GetProcessMitigationPolicy(process->process.get(), ProcessSignaturePolicy,
            &signatures, sizeof(signatures)) && (signatures.MicrosoftSignedOnly || signatures.StoreSignedOnly))
            throw std::runtime_error("The process restricts DLL signatures; its endpoint APIs remain unobserved.");
        GError* error{};
        try
        {
            process->session.reset(frida_device_attach_sync(device_.get(), pid, nullptr, nullptr, &error));
            requireFrida(error);
            if (WaitForSingleObject(process->process.get(), 0) != WAIT_TIMEOUT)
                throw std::runtime_error("The target process exited during attachment.");
            process->detachedSignal = g_signal_connect_data(process->session.get(), "detached", G_CALLBACK(detached),
                new std::shared_ptr<ObservedProcess>(process), destroyContext, G_CONNECT_DEFAULT);
            if (configured_.children)
            {
                {
                    std::lock_guard lock(outputMutex_);
                    gatedPids_.insert(pid);
                }
                frida_session_enable_child_gating_sync(process->session.get(), nullptr, &error);
                requireFrida(error);
                process->gated = true;
            }
            FridaObject<FridaScriptOptions> scriptOptions(frida_script_options_new(), frida_unref);
            frida_script_options_set_name(scriptOptions.get(), "Cipherazzi endpoint observer");
            frida_script_options_set_runtime(scriptOptions.get(), FRIDA_SCRIPT_RUNTIME_QJS);
            process->script.reset(frida_session_create_script_sync(process->session.get(), source_.c_str(),
                scriptOptions.get(), nullptr, &error));
            requireFrida(error);
            process->messageSignal = g_signal_connect_data(process->script.get(), "message", G_CALLBACK(message),
                new std::shared_ptr<ObservedProcess>(process), destroyContext, G_CONNECT_DEFAULT);
            frida_script_load_sync(process->script.get(), nullptr, &error);
            requireFrida(error);
            process->detached = frida_session_is_detached(process->session.get());
            processes_.push_back(process);
            std::cout << "Observing PID " << pid << "; reports: " << utf8(configured_.output.wstring()) << '\n'
                << std::flush;
            return process;
        }
        catch (...)
        {
            release(*process);
            throw;
        }
    }

    static bool consoleHost(const ObservedProcess& process)
    {
        // The trusted Windows console host handles display and input, without owning application TLS sessions.
        wchar_t directory[MAX_PATH]{};
        const auto length = GetSystemDirectoryW(directory, static_cast<UINT>(std::size(directory)));
        if (!length || length >= std::size(directory))
            return false;
        const auto expected = utf8((std::filesystem::path(directory) / L"conhost.exe").wstring());
        return _stricmp(process.path.c_str(), expected.c_str()) == 0;
    }

    void discoverChildren()
    {
        // Seed observation with living descendants whose creation times fit the retained parent identities.
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), CloseHandle);
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (snapshot.get() == INVALID_HANDLE_VALUE || !Process32FirstW(snapshot.get(), &entry))
            throw std::runtime_error("The process inventory could not be read.");
        std::multimap<DWORD, DWORD> descendants;
        do
        {
            if (descendants.size() >= 65536)
                throw std::runtime_error("The process inventory exceeds its bound.");
            descendants.emplace(entry.th32ParentProcessID, entry.th32ProcessID);
        } while (Process32NextW(snapshot.get(), &entry));
        if (GetLastError() != ERROR_NO_MORE_FILES)
            throw std::runtime_error("The process inventory could not be completed.");
        std::vector<std::pair<DWORD, int64_t>> parents{{root_->pid, root_->started}};
        std::set<DWORD> visited{root_->pid};
        for (size_t index = 0; index < parents.size(); ++index)
        {
            const auto [parentId, parentStarted] = parents[index];
            const auto [first, last] = descendants.equal_range(parentId);
            for (auto child = first; child != last; ++child)
            {
                const auto pid = child->second;
                if (!visited.insert(pid).second)
                    continue;
                Handle handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid), CloseHandle);
                if (!handle)
                {
                    if (GetLastError() != ERROR_INVALID_PARAMETER)
                    {
                        incomplete_ = true;
                        std::cerr << "PID " << pid << " has no readable descendant identity.\n";
                    }
                    continue;
                }
                if (WaitForSingleObject(handle.get(), 0) == WAIT_OBJECT_0)
                    continue;
                std::shared_ptr<ObservedProcess> process;
                try { process = identity(pid, std::move(handle)); }
                catch (const std::exception& error)
                {
                    incomplete_ = true;
                    std::cerr << "PID " << pid << " could not be identified: " << error.what() << '\n';
                    continue;
                }
                if (process->started < parentStarted)
                    continue;

                // Running workers retain their handles; gated notifications keep their existing queue entries.
                std::lock_guard lock(outputMutex_);
                const auto pending = std::ranges::any_of(children_, [&](const auto& value)
                {
                    return value.pid == pid;
                });
                if (!pending && !consoleHost(*process))
                {
                    if (parents.size() >= 64 || children_.size() >= 128)
                        throw std::runtime_error("Existing child observation reached its process bound.");
                    PendingChild queued{pid, false, true};
                    queued.process = std::move(process->process);
                    children_.push_back(std::move(queued));
                }
                parents.emplace_back(pid, process->started);
            }
        }
    }

    int runChromium()
    {
        // Own an isolated browser and authenticate its control endpoint before reading public security metadata.
        WSADATA sockets{};
        if (WSAStartup(MAKEWORD(2, 2), &sockets))
            throw std::runtime_error("The browser control transport could not be initialized.");
        browserSockets_ = true;
        ChromiumControl control;
        const auto profile = configured_.browserProfile.empty() ? configured_.output / "chromium-profile" :
            configured_.browserProfile;
        const auto marker = profile / "cipherazzi-profile.json", endpoint = profile / "DevToolsActivePort";
        for (const auto& path : {profile, marker, endpoint})
            if (const auto attributes = GetFileAttributesW(path.c_str());
                attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
                throw std::runtime_error("Browser profile paths cannot redirect to another directory or file.");
        if (std::filesystem::exists(profile) && !std::filesystem::is_empty(profile))
        {
            std::ifstream owned(marker);
            const auto value = nlohmann::json::parse(owned, nullptr, false);
            if (!value.is_object() || value.value("owner", "") != "Cipherazzi" ||
                value.value("provider", "") != "chromium")
                throw std::runtime_error("Choose an empty browser profile or one created by Cipherazzi for Chromium.");
        }
        std::filesystem::create_directories(profile);
        std::filesystem::remove(endpoint);
        {
            std::ofstream owned(marker);
            owned.exceptions(std::ios::badbit | std::ios::failbit);
            owned << "{\"owner\":\"Cipherazzi\",\"provider\":\"chromium\"}";
        }
        auto arguments = configured_.arguments;
        for (size_t index = 1; index < arguments.size(); ++index)
            if (arguments[index].starts_with("--user-data-dir") ||
                arguments[index].starts_with("--profile-directory") ||
                arguments[index].starts_with("--remote-debugging"))
                throw std::runtime_error("Chromium mode owns its profile and browser control options.");
        arguments.insert(arguments.end(), {"--user-data-dir=" + utf8(profile.wstring()), "--remote-debugging-port=0",
            "--remote-debugging-address=127.0.0.1", "--no-first-run", "--no-default-browser-check", "about:blank"});
        std::vector<gchar*> argv;
        for (auto& argument : arguments) argv.push_back(argument.data());
        FridaObject<FridaSpawnOptions> spawn(frida_spawn_options_new(), frida_unref);
        frida_spawn_options_set_argv(spawn.get(), argv.data(), static_cast<gint>(argv.size()));
        frida_spawn_options_set_stdio(spawn.get(), FRIDA_STDIO_INHERIT);
        GError* error{};
        const auto program = utf8(configured_.program.wstring());
        pid_ = frida_device_spawn_sync(device_.get(), program.c_str(), spawn.get(), nullptr, &error);
        requireFrida(error);
        spawned_ = true;
        root_ = identity(pid_);
        const auto launched = root_;
        Handle job(CreateJobObjectW(nullptr, nullptr), CloseHandle);
        Handle owned(OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid_), CloseHandle);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!job || !owned || !SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
            &limits, sizeof(limits)) || !AssignProcessToJobObject(job.get(), owned.get()))
            throw std::runtime_error("The dedicated browser lifetime could not be bounded.");
        frida_device_resume_sync(device_.get(), pid_, nullptr, &error);
        requireFrida(error);
        resumed_ = true;
        bool connected = false;
        try
        {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
            uint16_t port{};
            std::string path;
            while (!port)
            {
                std::ifstream file(endpoint);
                std::string number;
                if (std::getline(file, number) && std::getline(file, path) && number.size() <= 5 &&
                    number.find_first_not_of("0123456789") == std::string::npos &&
                    path.starts_with("/devtools/browser/") && path.size() <= 256)
                {
                    const auto value = std::stoul(number);
                    if (value && value <= 65535) port = static_cast<uint16_t>(value);
                }
                if (!port && (AdapterStopped || std::chrono::steady_clock::now() >= deadline))
                    throw std::runtime_error("The dedicated browser control endpoint did not start.");
                if (!port) std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            const auto pid = BrowserControl{}.owner(port);
            if (pid != root_->pid)
            {
                auto browser = identity(pid);
                if (browser->path != launched->path || browser->started < launched->started || parentPid(pid) != pid_)
                    throw std::runtime_error("The browser control endpoint did not match the launched application.");
                root_ = std::move(browser);
            }
            control.connect(port, std::wstring(path.begin(), path.end()));
            connected = true;
            control.command("Browser.getVersion");
            control.command("Target.setAutoAttach", {{"autoAttach", true}, {"waitForDebuggerOnStart", false},
                {"flatten", true}, {"filter", nlohmann::json::array({{{"type", "page"}, {"exclude", false}},
                    {{"exclude", true}}})}});
            const auto target = control.command("Target.createTarget", {{"url", "about:blank"}})
                .at("targetId").get<std::string>();
            std::string session;
            const auto attachDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (session.empty())
            {
                for (const auto& page : control.pages(incomplete_))
                    if (page.target == target) session = page.session;
                if (session.empty() && (AdapterStopped || std::chrono::steady_clock::now() >= attachDeadline))
                    throw std::runtime_error("The dedicated browser tab could not be observed.");
                if (session.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            control.command("Security.enable", nlohmann::json::object(), session);
            ++adapters_;
            started_ = std::chrono::steady_clock::now();
            std::cout << "Observing Chromium PID " << root_->pid << "; reports: " <<
                utf8(configured_.output.wstring()) << '\n' << std::flush;
            nlohmann::json requested = nlohmann::json::object();
            int64_t requestedStarted{}, requestedFinished{};
            if (!configured_.browserUrl.empty())
            {
                requestedStarted = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                requested = control.command("Page.navigate", {{"url", configured_.browserUrl}}, session);
                requestedFinished = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
            }
            auto errorName = requested.value("errorText", "");
            if (errorName.starts_with("net::")) errorName.erase(0, 5);
            const bool tlsFailure = errorName.starts_with("ERR_CERT_") || errorName.starts_with("ERR_SSL_") ||
                errorName.starts_with("ERR_BAD_SSL_");
            bool failureWritten = false;

            // Pair each page's current security state with its isolated navigation timing, excluding application data.
            std::set<std::string> seen;
            while (!AdapterStopped && WaitForSingleObject(root_->process.get(), 0) == WAIT_TIMEOUT &&
                (!configured_.duration || std::chrono::steady_clock::now() - started_ <
                    std::chrono::seconds(configured_.duration)))
            {
                for (const auto& page : control.pages(incomplete_))
                {
                    const auto& pageSession = page.session;
                    if (!page.observing &&
                        control.command("Security.enable", nlohmann::json::object(), pageSession).is_null()) continue;
                    auto pending = control.state(pageSession);
                    const bool pendingFailure = pageSession == session && tlsFailure && !failureWritten;
                    if ((!pending || !pending->contains("certificateSecurityState")) && !pendingFailure) continue;
                    if (control.command("Security.disable", nlohmann::json::object(), pageSession).is_null()) continue;
                    control.state(pageSession, true);
                    const auto tree = control.command("Page.getFrameTree", nlohmann::json::object(), pageSession);
                    if (!tree.contains("frameTree")) continue;
                    const auto frame = tree.at("frameTree").at("frame");
                    nlohmann::json timing;
                    if (!pendingFailure)
                    {
                        const auto context = control.command("Page.createIsolatedWorld",
                            {{"frameId", frame.at("id")}, {"worldName", "CipherazziTlsMetadata"}}, pageSession);
                        if (!context.contains("executionContextId")) continue;
                        timing = control.command("Runtime.evaluate", {{"contextId", context.at("executionContextId")},
                            {"returnByValue", true}, {"expression", "JSON.stringify({timeOrigin:performance.timeOrigin,"
                            "navigation:performance.getEntriesByType('navigation').map(e=>({secureConnectionStart:"
                            "e.secureConnectionStart,connectEnd:e.connectEnd,nextHopProtocol:e.nextHopProtocol}))})"}},
                            pageSession);
                        if (!timing.contains("result")) continue;
                    }
                    if (control.command("Security.enable", nlohmann::json::object(), pageSession).is_null()) continue;
                    pending = control.state(pageSession);
                    const auto refreshed = control.command("Page.getFrameTree", nlohmann::json::object(), pageSession);
                    if (!refreshed.contains("frameTree")) continue;
                    const auto current = refreshed.at("frameTree").at("frame");
                    // Failed navigations retain the bounded request interval and its actual failed destination.
                    if (pendingFailure && frame == current &&
                        frame.at("id") == requested.at("frameId") && frame.contains("unreachableUrl") &&
                        frame.at("loaderId") == requested.at("loaderId"))
                    {
                        nlohmann::json report{{"schema", "cipherazzi.endpoint/1"}, {"provider", "Chromium/BoringSSL"},
                            {"pid", root_->pid}, {"role", "client"}, {"process_scope", "application"},
                            {"transport", "Unknown"}, {"success", false}, {"error_name", errorName},
                            {"handshake_started_us", requestedStarted}, {"timestamp_us", requestedFinished}};
                        if (errorName.starts_with("ERR_CERT_")) report["peer_verified"] = false;
                        chromiumReport(pending.value_or(nlohmann::json::object()),
                            frame.at("unreachableUrl").get<std::string>(), nlohmann::json::object(),
                            nlohmann::json::object(), seen, std::move(report));
                        failureWritten = true;
                    }
                    else if (!pendingFailure && pending && pending->contains("certificateSecurityState") &&
                        frame == current && timing.at("result").contains("value"))
                    {
                        const auto performance = nlohmann::json::parse(
                            timing.at("result").at("value").get<std::string>());
                        if (!performance.at("navigation").empty())
                            chromiumReport(*pending, frame.at("url").get<std::string>(), performance,
                                performance.at("navigation").at(0), seen);
                    }
                }
                if (std::chrono::steady_clock::now() - lastPruned_ >=
                    std::chrono::seconds(std::min(configured_.maxAge, 60u)))
                {
                    const auto acquired = WaitForSingleObject(directoryMutex_.get(), 10000);
                    if (acquired != WAIT_OBJECT_0 && acquired != WAIT_ABANDONED)
                        throw std::runtime_error("The endpoint report directory is busy.");
                    std::unique_ptr<void, decltype(&ReleaseMutex)> release(directoryMutex_.get(), ReleaseMutex);
                    prune(0);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (tlsFailure && !failureWritten) incomplete_ = true;
            if (WaitForSingleObject(root_->process.get(), 0) == WAIT_TIMEOUT) control.command("Browser.close");
        }
        catch (...)
        {
            if (connected) { try { control.command("Browser.close"); } catch (...) {} }
            throw;
        }
        if (incomplete_) std::cerr << "Browser observation was incomplete.\n";
        std::cout << "Browser observation stopped; " << reports_ << " reports written.\n";
        return incomplete_ ? 2 : 0;
    }

    void chromiumReport(const nlohmann::json& state, const std::string& url, const nlohmann::json& performance,
        const nlohmann::json& navigation, std::set<std::string>& seen, nlohmann::json report = {})
    {
        // Preserve known cryptographic evidence without asserting the browser's networking process or a TLS signature.
        const auto security = state.value("certificateSecurityState", nlohmann::json::object());
        const auto version = security.value("protocol", "");
        const auto alpn = navigation.value("nextHopProtocol", "");
        const bool quic = version == "QUIC" && alpn.starts_with("h3");
        const int wire = version == "TLS 1.3" ? 772 : version == "TLS 1.2" ? 771 : 0;
        const bool success = report.empty();
        const auto start = navigation.value("secureConnectionStart", 0.0);
        const auto end = navigation.value("connectEnd", 0.0);
        if (success && ((!wire && !quic) || start <= 0 || end < start ||
            security.contains("certificateNetworkError"))) return;
        auto cipher = security.value("cipher", "");
        const auto mac = security.value("mac", cipher.find("AES_256") != std::string::npos ? "SHA384" : "SHA256");
        cipher = wire >= 772 || quic ? "TLS_" + cipher + "_" + mac :
            "TLS_" + security.value("keyExchange", "") + "_WITH_" + cipher + "_" +
                (mac == "SHA1" ? "SHA" : mac);
        const auto match = std::ranges::find_if(CipherNames, [&](const auto& value) { return value.second == cipher; });
        if (success)
        {
            if (match == std::end(CipherNames)) { incomplete_ = true; return; }
            const auto origin = performance.at("timeOrigin").get<double>();
            if (!std::isfinite(origin) || !std::isfinite(start) || !std::isfinite(end) || origin <= 0 ||
                origin + end > 253402300799999.0) return;
            const auto started = static_cast<int64_t>(std::llround((origin + start) * 1000));
            const auto timestamp = static_cast<int64_t>(std::llround((origin + end) * 1000));
            if (started < root_->started || timestamp - started > 120000000) return;
            const auto key = std::to_string(started) + ':' + url + ':' + cipher;
            if (seen.contains(key)) return;
            seen.insert(key);
            if (seen.size() > 4096) seen.erase(seen.begin());
            report = {{"schema", "cipherazzi.endpoint/1"}, {"provider", "Chromium/BoringSSL"},
                {"pid", root_->pid}, {"role", "client"}, {"process_scope", "application"},
                {"transport", quic ? "QUIC" : "TCP"}, {"success", true},
                {"handshake_started_us", started}, {"timestamp_us", timestamp}, {"selected_alpn", alpn}};
            if (state.value("securityState", "") == "secure") report["peer_verified"] = true;
        }
        if (match != std::end(CipherNames)) report["cipher_id"] = match->first;
        report["server_certificates_der"] = nlohmann::json::array();
        size_t bytes{};
        for (const auto& certificate : security.value("certificate", nlohmann::json::array()))
        {
            const auto encoded = certificate.get<std::string>();
            bytes += encoded.size() * 3 / 4;
            if (encoded.empty() || encoded.size() > 350000 || bytes > 1048576 ||
                report["server_certificates_der"].size() >= 16) { incomplete_ = true; break; }
            report["server_certificates_der"].push_back(encoded);
        }
        if (wire) report["tls_version"] = wire;
        const auto group = security.value("keyExchangeGroup", "");
        for (const auto& value : GroupNames)
            if (_stricmp(std::string(value.second).c_str(), group.c_str()) == 0) report["group_id"] = value.first;
        const std::wstring address(url.begin(), url.end());
        URL_COMPONENTS parts{};
        parts.dwStructSize = sizeof(parts);
        parts.dwHostNameLength = static_cast<DWORD>(-1);
        if (WinHttpCrackUrl(address.c_str(), static_cast<DWORD>(address.size()), 0, &parts))
            report["server_name"] = utf8(std::wstring_view(parts.lpszHostName, parts.dwHostNameLength));
        write(*root_, std::move(report));
    }

    int runFirefox()
    {
        // Start an isolated browser profile whose automation endpoint belongs to this observation.
        WSADATA sockets{};
        if (WSAStartup(MAKEWORD(2, 2), &sockets))
            throw std::runtime_error("The browser control transport could not be initialized.");
        browserSockets_ = true;
        BrowserControl control;
        SOCKET reservation = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int length = sizeof(address);
        if (reservation == INVALID_SOCKET || bind(reservation, reinterpret_cast<sockaddr*>(&address), length) ||
            getsockname(reservation, reinterpret_cast<sockaddr*>(&address), &length))
        {
            if (reservation != INVALID_SOCKET) closesocket(reservation);
            throw std::runtime_error("A browser control port could not be reserved.");
        }
        const auto port = ntohs(address.sin_port);
        closesocket(reservation);
        auto profile = configured_.browserProfile.empty() ? configured_.output / "browser-profile" :
            configured_.browserProfile;
        const auto marker = profile / "cipherazzi-profile.json";
        for (const auto& path : {profile, marker, profile / "user.js"})
            if (const auto attributes = GetFileAttributesW(path.c_str());
                attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
                throw std::runtime_error("Browser profile paths cannot redirect to another directory or file.");
        if (std::filesystem::exists(profile) && !std::filesystem::is_empty(profile))
        {
            std::ifstream owned(marker);
            const auto value = nlohmann::json::parse(owned, nullptr, false);
            if (!value.is_object() || value.value("owner", "") != "Cipherazzi")
                throw std::runtime_error("Choose an empty browser profile or one created by Cipherazzi.");
        }
        std::filesystem::create_directories(profile);
        {
            // Preserve ownership and configure only the dedicated browser control endpoint.
            std::ofstream owned(marker);
            owned.exceptions(std::ios::failbit | std::ios::badbit);
            owned << "{\"owner\":\"Cipherazzi\"}";
            std::ofstream preferences(profile / "user.js", std::ios::binary | std::ios::app);
            preferences.exceptions(std::ios::failbit | std::ios::badbit);
            preferences << "\nuser_pref(\"marionette.port\", " << port << ");\n"
                "user_pref(\"browser.shell.checkDefaultBrowser\", false);\n"
                "user_pref(\"browser.aboutwelcome.enabled\", false);\n";
        }
        std::vector<std::string> arguments = configured_.arguments;
        for (size_t index = 1; index < arguments.size(); ++index)
            if (arguments[index].starts_with("-profile") || arguments[index].starts_with("--profile") ||
                arguments[index].find("marionette") != std::string::npos ||
                arguments[index].find("remote-") != std::string::npos)
                throw std::runtime_error("Firefox mode owns its profile and browser control options.");
        arguments.insert(arguments.end(), {"--no-remote", "--profile", utf8(profile.wstring()), "--marionette",
            "--remote-allow-system-access", "about:blank"});
        std::vector<gchar*> argv;
        for (auto& argument : arguments)
            argv.push_back(argument.data());
        FridaObject<FridaSpawnOptions> spawn(frida_spawn_options_new(), frida_unref);
        frida_spawn_options_set_argv(spawn.get(), argv.data(), static_cast<gint>(argv.size()));
        frida_spawn_options_set_stdio(spawn.get(), FRIDA_STDIO_INHERIT);
        GError* error{};
        const auto program = utf8(configured_.program.wstring());
        pid_ = frida_device_spawn_sync(device_.get(), program.c_str(), spawn.get(), nullptr, &error);
        requireFrida(error);
        spawned_ = true;
        root_ = identity(pid_);
        const auto launched = root_;
        frida_device_resume_sync(device_.get(), pid_, nullptr, &error);
        requireFrida(error);
        resumed_ = true;
        bool connected = false, observing = false;
        try
        {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
            while (!(connected = control.connect(port)))
            {
                if (AdapterStopped || std::chrono::steady_clock::now() >= deadline)
                    throw std::runtime_error("The dedicated browser control endpoint did not start.");
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            const auto session = control.command("WebDriver:NewSession",
                {{"capabilities", {{"alwaysMatch", {{"acceptInsecureCerts", false}}}}}});
            const auto browserPid = session.at("capabilities").at("moz:processID").get<DWORD>();
            if (control.owner(port) != browserPid)
                throw std::runtime_error("The browser control listener does not belong to the reported process.");
            if (browserPid != pid_)
            {
                auto browser = identity(browserPid);
                if (browser->path != launched->path || browser->started < launched->started ||
                    parentPid(browserPid) != pid_)
                    throw std::runtime_error("The browser control endpoint did not match the launched application.");
                root_ = std::move(browser);
            }
            control.command("Marionette:SetContext", {{"value", "chrome"}});
            if (!control.script(adapterResource(102))
                .value("active", false))
                throw std::runtime_error("The public browser observer could not be started.");
            observing = true;
            ++adapters_;
            started_ = std::chrono::steady_clock::now();
            std::cout << "Observing Firefox PID " << root_->pid << "; reports: " <<
                utf8(configured_.output.wstring()) << '\n' << std::flush;
            if (!configured_.browserUrl.empty())
            {
                control.command("Marionette:SetContext", {{"value", "content"}});
                if (control.command("WebDriver:Navigate", {{"url", configured_.browserUrl}}, true)
                    .value("navigation_failed", false))
                    std::cerr << "The initial navigation failed; browser observation remains active.\n";
                control.command("Marionette:SetContext", {{"value", "chrome"}});
            }
            while (!AdapterStopped && WaitForSingleObject(root_->process.get(), 0) == WAIT_TIMEOUT &&
                (!configured_.duration || std::chrono::steady_clock::now() - started_ <
                    std::chrono::seconds(configured_.duration)))
            {
                browserReports(control.script("return globalThis.cipherazziCapture.drain();"));
                if (std::chrono::steady_clock::now() - lastPruned_ >=
                    std::chrono::seconds(std::min(configured_.maxAge, 60u)))
                {
                    const auto acquired = WaitForSingleObject(directoryMutex_.get(), 10000);
                    if (acquired != WAIT_OBJECT_0 && acquired != WAIT_ABANDONED)
                        throw std::runtime_error("The endpoint report directory is busy.");
                    std::unique_ptr<void, decltype(&ReleaseMutex)> release(directoryMutex_.get(), ReleaseMutex);
                    prune(0);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (WaitForSingleObject(root_->process.get(), 0) == WAIT_TIMEOUT)
            {
                browserReports(control.script("return globalThis.cipherazziCapture.stop();"));
                observing = false;
                control.command("Marionette:Quit", {{"flags", nlohmann::json::array({"eForceQuit"})}});
            }
        }
        catch (...)
        {
            if (connected)
            {
                try
                {
                    if (observing) control.script("return globalThis.cipherazziCapture.stop();");
                    control.command("Marionette:Quit", {{"flags", nlohmann::json::array({"eForceQuit"})}});
                }
                catch (...) {}
            }
            throw;
        }
        std::cout << "Browser observation stopped; " << reports_ << " reports written.\n";
        return incomplete_ ? 2 : 0;
    }

    static DWORD parentPid(DWORD pid)
    {
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), CloseHandle);
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (snapshot.get() != INVALID_HANDLE_VALUE && Process32FirstW(snapshot.get(), &entry))
            do
            {
                if (entry.th32ProcessID == pid) return entry.th32ParentProcessID;
            } while (Process32NextW(snapshot.get(), &entry));
        return 0;
    }

    void browserReports(const nlohmann::json& captured)
    {
        // Resolve public TLS names and retain the reported distinction between application and socket identity.
        if (captured.value("dropped", 0) || captured.value("unavailable", 0))
        {
            incomplete_ = true;
            std::cerr << "Some public browser handshake evidence was unavailable or exceeded its queue bound.\n";
        }
        for (auto report : captured.at("reports"))
        {
            const auto pid = report.at("pid").get<DWORD>();
            auto process = pid == root_->pid ? root_ : identity(pid);
            if (pid != root_->pid && (parentPid(pid) != root_->pid || process->path != root_->path ||
                process->started < root_->started))
                throw std::runtime_error("The reported socket process does not belong to the observed browser.");
            const auto cipher = report.value("cipher_name", "");
            const auto selected = std::ranges::find_if(CipherNames, [&](const auto& value)
            {
                return value.second == cipher;
            });
            if (report.value("success", false) && selected == std::end(CipherNames))
            {
                incomplete_ = true;
                continue;
            }
            if (selected != std::end(CipherNames)) report["cipher_id"] = selected->first;
            const auto group = report.value("group_name", "");
            const auto negotiated = std::ranges::find_if(GroupNames, [&](const auto& value)
            {
                return _stricmp(std::string(value.second).c_str(), group.c_str()) == 0;
            });
            if (negotiated != std::end(GroupNames) && (!report.value("session_resumed", false) ||
                report.at("tls_version").get<int>() >= 772))
                report["group_id"] = negotiated->first;
            const auto signature = report.value("signature_name", "");
            static const std::pair<std::string_view, uint32_t> signatures[]
            {
                {"RSA-PSS-SHA256", 0x0804}, {"RSA-PSS-SHA384", 0x0805}, {"RSA-PSS-SHA512", 0x0806},
                {"ECDSA-SHA256", 0x0403}, {"ECDSA-SHA384", 0x0503}, {"ECDSA-SHA512", 0x0603},
                {"RSA-PKCS1-SHA256", 0x0401}, {"RSA-PKCS1-SHA384", 0x0501}, {"RSA-PKCS1-SHA512", 0x0601},
                {"Ed25519", 0x0807}, {"Ed448", 0x0808}, {"ML-DSA-44", 0x0904}, {"ML-DSA-65", 0x0905},
                {"ML-DSA-87", 0x0906}
            };
            const auto scheme = std::ranges::find_if(signatures, [&](const auto& value)
            {
                return value.first == signature;
            });
            if (scheme != std::end(signatures) && !report.value("session_resumed", false))
            {
                auto selectedSignature = scheme->second;
                if (selectedSignature >= 0x0804 && selectedSignature <= 0x0806)
                {
                    // Distinguish RSA key encodings using the peer's public certificate algorithm.
                    const auto& certificates = report.at("server_certificates_der");
                    DWORD bytes{};
                    selectedSignature = 0;
                    if (!certificates.empty())
                    {
                        const auto encoded = certificates[0].get<std::string>();
                        if (CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()),
                            CRYPT_STRING_BASE64, nullptr, &bytes, nullptr, nullptr) && bytes <= 262144)
                        {
                            std::vector<BYTE> der(bytes);
                            if (CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()),
                                CRYPT_STRING_BASE64, der.data(), &bytes, nullptr, nullptr))
                            {
                                std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)> certificate(
                                    CertCreateCertificateContext(X509_ASN_ENCODING, der.data(), bytes),
                                    CertFreeCertificateContext);
                                if (certificate)
                                {
                                    const auto oid = certificate->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
                                    if (oid && std::strcmp(oid, szOID_RSA_RSA) == 0)
                                        selectedSignature = scheme->second;
                                    else if (oid && std::strcmp(oid, szOID_RSA_SSA_PSS) == 0)
                                        selectedSignature = scheme->second + 5;
                                }
                            }
                        }
                    }
                }
                if (selectedSignature) report["signature_scheme"] = selectedSignature;
            }
            report.erase("cipher_name");
            report.erase("group_name");
            report.erase("signature_name");
            write(*process, std::move(report));
        }
    }

    void release(ObservedProcess& process)
    {
        // Remove signal closures before releasing their retained process and instrumentation.
        if (process.messageSignal)
            g_signal_handler_disconnect(process.script.get(), process.messageSignal);
        if (process.detachedSignal)
            g_signal_handler_disconnect(process.session.get(), process.detachedSignal);
        process.messageSignal = process.detachedSignal = 0;
        if (process.session && !frida_session_is_detached(process.session.get()))
        {
            if (process.gated)
                frida_session_disable_child_gating_sync(process.session.get(), nullptr, nullptr);
            if (process.script)
                frida_script_unload_sync(process.script.get(), nullptr, nullptr);
            frida_session_detach_sync(process.session.get(), nullptr, nullptr);
        }
        {
            std::lock_guard lock(outputMutex_);
            gatedPids_.erase(process.pid);
        }
        process.script.reset();
        process.session.reset();
    }

    static void destroyContext(gpointer context, GClosure*)
    {
        delete static_cast<std::shared_ptr<ObservedProcess>*>(context);
    }

    static void childAdded(FridaDevice* device, FridaChild* child, gpointer context)
    {
        auto& self = *static_cast<AdapterRun*>(context);
        std::lock_guard lock(self.outputMutex_);
        if (!self.gatedPids_.contains(frida_child_get_parent_pid(child)))
            return;

        // Firefox performs TLS in its browser or socket process; leave sandboxed non-network roles untouched.
        const auto path = frida_child_get_path(child);
        int count{};
        const auto arguments = frida_child_get_argv(child, &count);
        bool afterStartup = false;
        if (path && _stricmp(std::filesystem::path(path).filename().string().c_str(), "firefox.exe") == 0 &&
            count > 0 && count <= 128 && arguments && arguments[count - 1])
        {
            const std::string_view role(arguments[count - 1]);
            const auto content = std::ranges::any_of(std::span(arguments, count), [](const auto argument)
            {
                return argument && std::strcmp(argument, "-contentproc") == 0;
            });
            if (content && (role == "tab" || role == "gpu" || role == "rdd" || role == "gmp" ||
                role == "utility" || role == "vr"))
            {
                frida_device_resume(device, frida_child_get_pid(child), nullptr, nullptr, nullptr);
                return;
            }
            afterStartup = content && role == "socket";
        }
        if (self.stopping_ || self.children_.size() >= 128)
        {
            frida_device_resume(device, frida_child_get_pid(child), nullptr, nullptr, nullptr);
            if (!self.stopping_)
            {
                self.failed_ = true;
                std::cerr << "Endpoint child observation reached its pending-process bound.\n";
                g_main_loop_quit(self.loop_.get());
            }
            return;
        }
        PendingChild pending{frida_child_get_pid(child), afterStartup};
        pending.process.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pending.pid));
        self.children_.push_back(std::move(pending));
    }

    void prune(uint64_t incoming)
    {
        // Bound reporter-owned artifacts by count, size, and age while the directory lock is held.
        struct Artifact { std::filesystem::path path; std::filesystem::file_time_type time; uint64_t bytes; };
        std::vector<Artifact> artifacts;
        uint64_t total = 0;
        const auto now = std::filesystem::file_time_type::clock::now();
        for (const auto& entry : std::filesystem::directory_iterator(configured_.output))
        {
            const auto name = entry.path().filename().wstring();
            if (!name.starts_with(L"cipherazzi-endpoint-") || entry.path().extension() != L".json" ||
                !std::filesystem::is_regular_file(entry.symlink_status()))
                continue;
            std::error_code ignored;
            const auto time = entry.last_write_time(ignored);
            if (ignored)
                continue;
            const auto bytes = entry.file_size(ignored);
            if (ignored)
                continue;
            if (now - time > std::chrono::seconds(configured_.maxAge) &&
                std::filesystem::remove(entry.path(), ignored))
                continue;
            artifacts.push_back({entry.path(), time, bytes});
            total += bytes;
        }
        std::ranges::sort(artifacts, {}, &Artifact::time);
        size_t remaining = artifacts.size();
        const auto additional = incoming ? 1 : 0;
        for (const auto& artifact : artifacts)
        {
            if (remaining + additional <= configured_.maxFiles && total + incoming <= configured_.maxBytes)
                break;
            std::error_code ignored;
            if (std::filesystem::remove(artifact.path, ignored))
            {
                --remaining;
                total -= artifact.bytes;
            }
        }
        if (remaining + additional > configured_.maxFiles || total + incoming > configured_.maxBytes)
            throw std::runtime_error("The endpoint report directory could not stay within its storage limits.");
        lastPruned_ = std::chrono::steady_clock::now();
    }

    void write(const ObservedProcess& process, nlohmann::json report)
    {
        // Stamp identity from the retained process handle and publish complete files atomically.
        if (!report.is_object() || report.value("schema", "") != "cipherazzi.endpoint/1" ||
            report.at("pid").get<uint64_t>() != process.pid)
            throw std::runtime_error("The observer emitted an invalid report identity.");
        report["process_started_us"] = process.started;
        if (process.name.size() <= 256) report["process_name"] = process.name;
        if (process.path.size() <= 4096) report["process_path"] = process.path;
        const auto data = report.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        if (data.size() > 2 * 1024 * 1024)
            throw std::runtime_error("The public endpoint report exceeds its storage bound.");

        // Retain only endpoint-adapter artifacts; other providers keep their own storage policy.
        const auto acquired = WaitForSingleObject(directoryMutex_.get(), 10000);
        if (acquired != WAIT_OBJECT_0 && acquired != WAIT_ABANDONED)
            throw std::runtime_error("The endpoint report directory is busy.");
        std::unique_ptr<void, decltype(&ReleaseMutex)> release(directoryMutex_.get(), ReleaseMutex);
        prune(data.size());
        const auto target = configured_.output / (prefix_ + std::to_wstring(reports_.load() + 1) + L".json");
        const auto temporary = std::filesystem::path(target.wstring() + L".tmp");
        try
        {
            std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
            file.exceptions(std::ios::failbit | std::ios::badbit);
            file.write(data.data(), static_cast<std::streamsize>(data.size()));
            file.close();
            if (!MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("The endpoint report could not be published atomically.");
        }
        catch (...)
        {
            std::error_code ignored;
            std::filesystem::remove(temporary, ignored);
            throw;
        }
        ++reports_;
    }

    static void message(FridaScript*, const gchar* message, GBytes*, gpointer context)
    {
        const auto process = *static_cast<std::shared_ptr<ObservedProcess>*>(context);
        auto& self = process->owner;
        try
        {
            const auto value = nlohmann::json::parse(message);
            if (value.value("type", "") == "error")
                throw std::runtime_error("The endpoint observer could not run in this application.");
            if (value.value("type", "") != "send")
                return;
            const auto& payload = value.at("payload");
            const auto kind = payload.value("kind", "");
            std::lock_guard lock(self.outputMutex_);
            if (self.stopping_)
                return;
            if (kind == "report") self.write(*process, payload.at("report"));
            else if (kind == "adapter")
            {
                ++self.adapters_;
                std::cout << payload.at("provider").get<std::string>() << " public APIs observed in "
                    << payload.at("module").get<std::string>() << '\n' << std::flush;
            }
            else if (kind == "diagnostic")
                std::cerr << payload.at("message").get<std::string>() << '\n';
        }
        catch (const std::exception& error)
        {
            self.failed_ = true;
            std::cerr << "Endpoint observation failed: " << error.what() << '\n';
            g_main_loop_quit(self.loop_.get());
        }
    }

    static void detached(FridaSession*, FridaSessionDetachReason reason, FridaCrash*, gpointer context)
    {
        const auto process = *static_cast<std::shared_ptr<ObservedProcess>*>(context);
        auto& self = process->owner;
        if (reason != FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED && !self.stopping_)
        {
            std::lock_guard lock(self.outputMutex_);
            self.incomplete_ = true;
            std::cerr << "Endpoint observation was disconnected from PID " << process->pid << ".\n";
        }
        process->detached = true;
    }

    static gboolean poll(gpointer context)
    {
        auto& self = *static_cast<AdapterRun*>(context);
        if (AdapterStopped || self.failed_ ||
            (self.configured_.duration && std::chrono::steady_clock::now() - self.started_ >=
                std::chrono::seconds(self.configured_.duration)))
        {
            g_main_loop_quit(self.loop_.get());
            return G_SOURCE_CONTINUE;
        }

        // Observe suspended descendants on the application loop, outside Frida's signal callbacks.
        std::vector<PendingChild> children;
        {
            std::lock_guard lock(self.outputMutex_);
            children.swap(self.children_);
        }
        for (auto& child : children)
        {
            std::shared_ptr<ObservedProcess> process;
            try
            {
                if (std::ranges::any_of(self.processes_, [&](const auto& process)
                {
                    return process->pid == child.pid && !process->detached &&
                        WaitForSingleObject(process->process.get(), 0) == WAIT_TIMEOUT;
                }))
                {
                    if (!child.resumed)
                        frida_device_resume_sync(self.device_.get(), child.pid, nullptr, nullptr);
                    continue;
                }
                if (!child.process)
                    throw std::runtime_error("The child process identity could not be read.");

                // Let Firefox's broker establish its socket sandbox and load NSS before observing it.
                if (child.afterStartup)
                {
                    if (!child.resumed)
                    {
                        frida_device_resume_sync(self.device_.get(), child.pid, nullptr, nullptr);
                        child.resumed = true;
                        child.ready = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                    }
                    if (WaitForSingleObject(child.process.get(), 0) != WAIT_TIMEOUT)
                        continue;
                    Handle modules(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                        child.pid), CloseHandle);
                    bool loaded = false;
                    if (modules.get() != INVALID_HANDLE_VALUE)
                    {
                        MODULEENTRY32W entry{};
                        entry.dwSize = sizeof(entry);
                        if (Module32FirstW(modules.get(), &entry))
                            do
                            {
                                loaded = _wcsicmp(entry.szModule, L"nss3.dll") == 0;
                            } while (!loaded && Module32NextW(modules.get(), &entry));
                    }
                    else if (GetLastError() != ERROR_BAD_LENGTH && GetLastError() != ERROR_PARTIAL_COPY)
                        throw std::runtime_error("The Firefox socket process does not permit observation.");
                    if (!loaded)
                    {
                        if (std::chrono::steady_clock::now() >= child.ready)
                            throw std::runtime_error("The Firefox socket APIs did not become observable.");
                        std::lock_guard lock(self.outputMutex_);
                        self.children_.push_back(std::move(child));
                        continue;
                    }
                }
                process = self.identity(child.pid, std::move(child.process));
                if (WaitForSingleObject(process->process.get(), 0) == WAIT_OBJECT_0)
                    continue;
                if (consoleHost(*process))
                {
                    if (!child.resumed)
                        frida_device_resume_sync(self.device_.get(), child.pid, nullptr, nullptr);
                    continue;
                }
                if (self.processes_.size() >= 64)
                    throw std::runtime_error("Endpoint observation reached its active-process bound.");
                self.instrument(process);
            }
            catch (const std::exception& error)
            {
                if (process && WaitForSingleObject(process->process.get(), 0) == WAIT_OBJECT_0)
                    continue;
                self.incomplete_ = true;
                std::cerr << "PID " << child.pid;
                if (process)
                    std::cerr << " (" << utf8(std::filesystem::path(process->path).filename().wstring()) << ')';
                std::cerr << " could not be observed: " << error.what() << '\n';
            }
            if (!child.resumed)
                frida_device_resume_sync(self.device_.get(), child.pid, nullptr, nullptr);
        }
        std::erase_if(self.processes_, [&](const auto& process)
        {
            if (!process->detached && WaitForSingleObject(process->process.get(), 0) != WAIT_OBJECT_0)
                return false;
            self.release(*process);
            return true;
        });
        {
            std::lock_guard lock(self.outputMutex_);
            if (self.processes_.empty() && self.children_.empty())
                g_main_loop_quit(self.loop_.get());
        }
        if (std::chrono::steady_clock::now() - self.lastPruned_ >=
            std::chrono::seconds(std::min(self.configured_.maxAge, 60u)))
        {
            try
            {
                std::lock_guard lock(self.outputMutex_);
                const auto acquired = WaitForSingleObject(self.directoryMutex_.get(), 0);
                if (acquired == WAIT_OBJECT_0 || acquired == WAIT_ABANDONED)
                {
                    std::unique_ptr<void, decltype(&ReleaseMutex)> release(self.directoryMutex_.get(), ReleaseMutex);
                    self.prune(0);
                }
            }
            catch (const std::exception& error)
            {
                self.failed_ = true;
                std::cerr << "Endpoint retention failed: " << error.what() << '\n';
                g_main_loop_quit(self.loop_.get());
            }
        }
        return G_SOURCE_CONTINUE;
    }
};
}

int wmain(int count, wchar_t** arguments)
{
    if (count == 1 || (count == 2 && std::wstring_view(arguments[1]) == L"--help"))
    {
        std::cout << "Cipherazzi public endpoint adapter\n\n"
            "  Cipherazzi.EndpointAdapter.exe --pid <pid> --output <directory>\n"
            "  Cipherazzi.EndpointAdapter.exe --spawn <application.exe> --output <directory> -- <arguments>\n\n"
            "  --provider auto|openssl|boringssl|nss  Select library APIs (default auto)\n"
            "  --duration <seconds>                 Stop observation; 0 waits for observed processes\n"
            "  --no-children                        Observe only the specified process\n"
            "  --max-files <n>                      Retained report count (default 4096)\n"
            "  --max-mb <n>                         Retained report storage (default 128 MiB)\n"
            "  --max-age <seconds>                  Retained report age (default 86400)\n\n"
            "  --provider firefox                  Use public Firefox HTTPS metadata in a dedicated profile\n"
            "  --provider chromium                 Use public Chrome/Edge security metadata in a dedicated profile\n"
            "  --browser-profile <directory>       Empty or Cipherazzi-owned browser profile\n"
            "  --url <https://...>                  Open after the browser observer starts\n\n"
            "Browser modes close their dedicated browser when observation stops.\n"
            "Firefox failures and HTTP/3 evidence remain independent when socket identity is unavailable.\n\n"
            "Collect with Cipherazzi.Collector.exe --endpoint-only --endpoint-directory <directory> --db <file>.\n"
            "Existing and new descendants are observed automatically. Attach before the handshakes of interest.\n"
            "Public API availability depends on the application build.\n";
        return 0;
    }
    try
    {
        auto configured = Cipherazzi::options(count, arguments);
        std::cout << "Starting endpoint observation...\n" << std::flush;
        SetConsoleCtrlHandler(Cipherazzi::adapterControl, TRUE);
        Cipherazzi::AdapterRun adapter(std::move(configured));
        return adapter.run();
    }
    catch (const std::exception& error)
    {
        std::cerr << "Endpoint adapter failed: " << error.what() << '\n';
        return 1;
    }
}
