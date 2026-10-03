#include "Service.h"
#include "Capture.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <system_error>

namespace Cipherazzi
{
namespace ServiceSupport
{
constexpr wchar_t Name[] = L"Cipherazzi";
using Manager = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, decltype(&CloseServiceHandle)>;
using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;

void require(bool success, const char* operation)
{
    if (!success)
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), operation);
}

std::filesystem::path executable(bool installed)
{
    std::wstring buffer(32768, L'\0');
    const auto length = installed ? GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size())) :
        GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    require(length != 0 && length < buffer.size(), "Resolve executable path");
    buffer.resize(length);
    return installed ? std::filesystem::path(buffer) / L"Cipherazzi.Collector.exe" : std::filesystem::path(buffer);
}

void protect(const std::filesystem::path& path, bool directory)
{
    // Administrators and SYSTEM can write; ordinary users can read the journal and run the viewer.
    const auto attributes = GetFileAttributesW(path.c_str());
    require(attributes != INVALID_FILE_ATTRIBUTES, "Inspect installation path");
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) || bool(attributes & FILE_ATTRIBUTE_DIRECTORY) != directory)
        throw std::runtime_error("Installation paths must be ordinary files and directories");
    PSECURITY_DESCRIPTOR raw = nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(directory ?
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)" :
        L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)", SDDL_REVISION_1, &raw, nullptr), "Build permissions");
    std::unique_ptr<void, decltype(&LocalFree)> security(raw, LocalFree);
    PACL acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(raw, &present, &acl, &defaulted) != FALSE, "Read permissions");
    const auto error = SetNamedSecurityInfoW(const_cast<PWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    if (error)
        throw std::system_error(static_cast<int>(error), std::system_category(), "Apply permissions");
}

std::wstring quote(const std::wstring& value)
{
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (const auto character : value)
    {
        if (character == L'\\')
        {
            ++slashes;
            continue;
        }
        result.append(character == L'\"' ? slashes * 2 + 1 : slashes, L'\\');
        result += character;
        slashes = 0;
    }
    result.append(slashes * 2, L'\\');
    return result + L'\"';
}

bool sameImage(const std::filesystem::path& first, const std::filesystem::path& second)
{
    if (!std::filesystem::exists(second) || std::filesystem::file_size(first) != std::filesystem::file_size(second))
        return false;
    std::ifstream left(first, std::ios::binary), right(second, std::ios::binary);
    std::array<char, 65536> a{}, b{};
    while (left && right)
    {
        left.read(a.data(), a.size());
        right.read(b.data(), b.size());
        if (left.gcount() != right.gcount() || !std::equal(a.begin(), a.begin() + left.gcount(), b.begin()))
            return false;
    }
    return left.eof() && right.eof();
}

std::vector<uint8_t> configuration(SC_HANDLE service)
{
    DWORD size = 0;
    QueryServiceConfigW(service, nullptr, 0, &size);
    require(size != 0 && size <= 65536, "Read service configuration");
    std::vector<uint8_t> buffer(size);
    require(QueryServiceConfigW(service, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data()), size, &size),
        "Read service configuration");
    const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(buffer.data());
    int count = 0;
    auto* raw = CommandLineToArgvW(config->lpBinaryPathName, &count);
    std::unique_ptr<void, decltype(&LocalFree)> arguments(raw, LocalFree);
    if (!raw || count < 2 || _wcsicmp(raw[0], executable(true).c_str()) != 0 ||
        std::wstring_view(raw[1]) != L"--service" || config->dwServiceType != SERVICE_WIN32_OWN_PROCESS)
        throw std::runtime_error("An unrelated service already uses the Cipherazzi name");
    return buffer;
}

SERVICE_STATUS_PROCESS status(SC_HANDLE service)
{
    SERVICE_STATUS_PROCESS result{};
    DWORD size = 0;
    require(QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&result),
        sizeof(result), &size), "Read service status");
    return result;
}

void start(SC_HANDLE service)
{
    if (status(service).dwCurrentState == SERVICE_RUNNING)
        return;
    if (!StartServiceW(service, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        require(false, "Start service");
    const auto deadline = GetTickCount64() + 60000;
    for (;;)
    {
        const auto current = status(service);
        if (current.dwCurrentState == SERVICE_RUNNING)
            return;
        if (current.dwCurrentState == SERVICE_STOPPED || GetTickCount64() >= deadline)
            throw std::runtime_error("Service startup failed; inspect ProgramData\\Cipherazzi\\service.log");
        Sleep(100);
    }
}

void stop(SC_HANDLE service)
{
    const auto deadline = GetTickCount64() + 60000;
    Handle process(nullptr, CloseHandle);
    for (;;)
    {
        const auto current = status(service);
        if (current.dwProcessId && !process)
        {
            process.reset(OpenProcess(SYNCHRONIZE, FALSE, current.dwProcessId));
            if (!process && GetLastError() != ERROR_INVALID_PARAMETER)
                require(false, "Wait for collector process");
        }
        if (current.dwCurrentState == SERVICE_STOPPED)
            break;
        if (current.dwCurrentState == SERVICE_RUNNING || current.dwCurrentState == SERVICE_PAUSED)
        {
            SERVICE_STATUS ignored{};
            if (!ControlService(service, SERVICE_CONTROL_STOP, &ignored) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
                require(false, "Stop service");
        }
        if (GetTickCount64() >= deadline)
            throw std::runtime_error("Service did not stop; installation was left intact");
        Sleep(100);
    }
    if (process && WaitForSingleObject(process.get(), 10000) != WAIT_OBJECT_0)
        throw std::runtime_error("Collector process did not exit; installation was left intact");
}

void removeImage(const std::filesystem::path& path)
{
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES)
    {
        if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("The installed executable is not an ordinary file; it was left intact");
        if (attributes & FILE_ATTRIBUTE_READONLY)
            require(SetFileAttributesW(path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY),
                "Remove read-only attribute");
    }
    if (DeleteFileW(path.c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND)
        return;
    const auto error = GetLastError();
    if (error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED)
        require(false, "Remove installed executable");

    // Rename a running image before scheduling deletion so a reinstall survives the next reboot.
    auto retired = path;
    retired += L"." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64()) + L".remove";
    require(MoveFileExW(path.c_str(), retired.c_str(), 0), "Retire installed executable");
    if (!MoveFileExW(retired.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT))
    {
        const auto failure = GetLastError();
        MoveFileExW(retired.c_str(), path.c_str(), 0);
        SetLastError(failure);
        require(false, "Schedule executable cleanup");
    }
    std::cout << "The retired executable will be deleted at the next restart.\n";
}

Handle setupMutex()
{
    Handle mutex(CreateMutexW(nullptr, FALSE, L"Global\\Cipherazzi.Setup"), CloseHandle);
    require(bool(mutex), "Open installation lock");
    const auto result = WaitForSingleObject(mutex.get(), 30000);
    if (result != WAIT_OBJECT_0 && result != WAIT_ABANDONED)
        throw std::runtime_error("Another installation operation is still running");
    return mutex;
}

void log(std::string_view message) noexcept
{
    try
    {
        const auto path = serviceDatabase().parent_path() / L"service.log";
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        std::ofstream output(path, !error && size > 1024 * 1024 ? std::ios::trunc : std::ios::app);
        SYSTEMTIME time{};
        GetSystemTime(&time);
        char timestamp[32]{};
        sprintf_s(timestamp, "%04u-%02u-%02uT%02u:%02u:%02uZ", time.wYear, time.wMonth, time.wDay,
            time.wHour, time.wMinute, time.wSecond);
        output << timestamp << "  PID " << GetCurrentProcessId() << "  " << message << '\n';
    }
    catch (...) {}
}

struct Runtime
{
    std::atomic<bool>& stopped;
    std::function<void()> work;
    std::atomic<int> result{};
    SERVICE_STATUS_HANDLE handle{};
    SERVICE_STATUS current{SERVICE_WIN32_OWN_PROCESS, SERVICE_START_PENDING};
    std::mutex mutex;
    static Runtime* active;

    void progress(ServicePhase phase)
    {
        std::lock_guard lock(mutex);
        if (!handle || current.dwCurrentState == SERVICE_STOPPED)
            return;
        if (phase == ServicePhase::Running && current.dwCurrentState != SERVICE_STOP_PENDING)
        {
            current.dwCurrentState = SERVICE_RUNNING;
            current.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN;
            current.dwCheckPoint = current.dwWaitHint = 0;
        }
        else
        {
            current.dwCurrentState = phase == ServicePhase::Starting ? SERVICE_START_PENDING : SERVICE_STOP_PENDING;
            current.dwControlsAccepted = 0;
            ++current.dwCheckPoint;
            current.dwWaitHint = 30000;
        }
        SetServiceStatus(handle, &current);
    }

    static DWORD WINAPI control(DWORD code, DWORD, void*, void* context) noexcept
    {
        auto& self = *static_cast<Runtime*>(context);
        if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN || code == SERVICE_CONTROL_PRESHUTDOWN)
        {
            self.stopped.store(true);
            self.progress(ServicePhase::Stopping);
            return NO_ERROR;
        }
        if (code == SERVICE_CONTROL_INTERROGATE)
        {
            std::lock_guard lock(self.mutex);
            if (self.handle && self.current.dwCurrentState != SERVICE_STOPPED)
                SetServiceStatus(self.handle, &self.current);
            return NO_ERROR;
        }
        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    static void WINAPI main(DWORD, wchar_t**)
    {
        auto& self = *active;
        self.handle = RegisterServiceCtrlHandlerExW(Name, control, &self);
        if (!self.handle)
        {
            self.result.store(1);
            log("Service control registration failed");
            return;
        }
        self.progress(ServicePhase::Starting);
        log("Starting capture service");
        try
        {
            self.work();
            log("Capture stopped; queues drained");
        }
        catch (const std::exception& error)
        {
            self.result.store(1);
            log(error.what());
        }
        catch (...)
        {
            self.result.store(1);
            log("Capture service failed");
        }

        // Publish STOPPED once, after the collector and every worker have released their resources.
        SERVICE_STATUS finalStatus{};
        SERVICE_STATUS_HANDLE handle;
        {
            std::lock_guard lock(self.mutex);
            self.current.dwCurrentState = SERVICE_STOPPED;
            self.current.dwControlsAccepted = self.current.dwCheckPoint = self.current.dwWaitHint = 0;
            self.current.dwWin32ExitCode = self.result.load() ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
            self.current.dwServiceSpecificExitCode = static_cast<DWORD>(self.result.load());
            finalStatus = self.current;
            handle = self.handle;
        }
        SetServiceStatus(handle, &finalStatus);
    }
};
Runtime* Runtime::active = nullptr;
}

std::filesystem::path serviceDatabase()
{
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &raw)))
        throw std::runtime_error("Could not resolve ProgramData");
    std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> path(raw, CoTaskMemFree);
    return std::filesystem::path(raw) / L"Cipherazzi" / L"capture.db";
}

void installService(const std::vector<std::wstring>& arguments)
{
    using namespace ServiceSupport;
    if (!elevated())
        throw std::runtime_error("Service installation requires an elevated console");
    auto mutex = setupMutex();
    std::unique_ptr<void, decltype(&ReleaseMutex)> release(mutex.get(), ReleaseMutex);
    Manager manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE),
        CloseServiceHandle);
    require(bool(manager), "Open Service Control Manager");
    const auto source = executable(false), destination = executable(true);
    const auto packageSource = source.parent_path() / L"CipherazziLoopback";
    const auto packageDestination = destination.parent_path() / L"CipherazziLoopback";
    const bool loopback = std::ranges::find(arguments, L"--endpoint-only") == arguments.end() &&
        std::ranges::find(arguments, L"--no-loopback") == arguments.end();
    const std::array<std::wstring_view, 3> packageFiles{L"WinDivert.dll", L"WinDivert64.sys", L"LICENSE"};
    std::vector<std::filesystem::path> packageCopied;

    // Validate the capture package before changing the installed service or its files.
    if (loopback)
    {
        const auto sourceAttributes = GetFileAttributesW(packageSource.c_str());
        if (sourceAttributes == INVALID_FILE_ATTRIBUTES || !(sourceAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            sourceAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            throw std::runtime_error("The loopback capture package must be an ordinary directory");
        for (const auto name : packageFiles)
        {
            const auto input = packageSource / name, output = packageDestination / name;
            const auto attributes = GetFileAttributesW(input.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || attributes &
                (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
                throw std::runtime_error("The complete CipherazziLoopback package is required beside the collector");
            const auto installed = GetFileAttributesW(output.c_str());
            if (installed != INVALID_FILE_ATTRIBUTES && (installed &
                (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) || !sameImage(input, output)))
                throw std::runtime_error("A different loopback capture package is installed; it was left intact");
        }
        const auto attributes = GetFileAttributesW(packageDestination.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("The installed loopback package directory is not an ordinary directory");
    }
    auto copyPackage = [&]
    {
        if (!loopback)
            return;
        std::filesystem::create_directory(packageDestination);
        protect(packageDestination, true);
        for (const auto name : packageFiles)
        {
            const auto input = packageSource / name, output = packageDestination / name;
            if (!std::filesystem::exists(output))
            {
                require(CopyFileW(input.c_str(), output.c_str(), TRUE), "Install loopback capture package");
                packageCopied.push_back(output);
            }
            protect(output, false);
        }
    };
    std::wstring command = quote(destination.wstring()) + L" --service";
    for (const auto& argument : arguments)
        command += L" " + quote(argument);
    Manager service(OpenServiceW(manager.get(), Name, SERVICE_ALL_ACCESS), CloseServiceHandle);
    if (service)
    {
        const auto buffer = configuration(service.get());
        const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (command != config->lpBinaryPathName || config->dwStartType != SERVICE_AUTO_START ||
            _wcsicmp(config->lpServiceStartName, L"LocalSystem") != 0 || !sameImage(source, destination))
            throw std::runtime_error("Cipherazzi is already installed; "
                "uninstall before replacing its binary or options");
        copyPackage();
        start(service.get());
        std::cout << "Cipherazzi is already installed and running.\n";
        return;
    }
    require(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST, "Inspect existing service");
    const bool exists = std::filesystem::exists(destination);
    if (exists && !sameImage(source, destination))
        throw std::runtime_error("System32 already contains a different Cipherazzi.Collector.exe; it was left intact");
    const auto directory = serviceDatabase().parent_path();
    std::filesystem::create_directory(directory);
    protect(directory, true);
    std::filesystem::path staged;
    bool copied = false;
    try
    {
        copyPackage();
        if (!exists)
        {
            wchar_t temporary[MAX_PATH]{};
            require(GetTempFileNameW(destination.parent_path().c_str(), L"CZA", 0, temporary) != 0,
                "Stage collector in System32");
            staged = temporary;
            require(CopyFileW(source.c_str(), staged.c_str(), FALSE), "Copy collector into System32");
            protect(staged, false);
            require(MoveFileExW(staged.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH),
                "Install collector image");
            copied = true;
            staged.clear();
        }
        else
            protect(destination, false);
        service.reset(CreateServiceW(manager.get(), Name, L"Cipherazzi Network Cryptography Monitor",
            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
            command.c_str(), nullptr, nullptr, L"Tcpip\0", nullptr, nullptr));
        require(bool(service), "Register capture service");
        SERVICE_DESCRIPTIONW description{
            const_cast<PWSTR>(L"Records TCP TLS handshake metadata and local process ownership.")};
        require(ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, &description),
            "Describe capture service");
        SERVICE_PRESHUTDOWN_INFO shutdown{30000};
        require(ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_PRESHUTDOWN_INFO, &shutdown), "Configure shutdown");
        start(service.get());

        // Retry failed runs without restarting an intentionally stopped collector.
        SC_ACTION actions[]{{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 15000}, {SC_ACTION_RESTART, 60000},
            {SC_ACTION_NONE, 0}};
        SERVICE_FAILURE_ACTIONSW failure{86400, nullptr, nullptr, 4, actions};
        SERVICE_FAILURE_ACTIONS_FLAG failures{TRUE};
        require(ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &failure) &&
            ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failures), "Configure recovery");
    }
    catch (...)
    {
        if (service)
        {
            stop(service.get());
            require(DeleteService(service.get()), "Roll back service registration");
            service.reset();
        }
        if (!staged.empty())
            DeleteFileW(staged.c_str());
        if (copied)
            removeImage(destination);
        for (const auto& path : packageCopied)
            removeImage(path);
        if (!packageCopied.empty())
            RemoveDirectoryW(packageDestination.c_str());
        throw;
    }
    std::cout << "Installed and started Cipherazzi: " << utf8(destination.wstring())
        << "\nAutomatic startup; LocalSystem account. Use Services or sc.exe to start and stop it.\n";
}

void uninstallService()
{
    using namespace ServiceSupport;
    if (!elevated())
        throw std::runtime_error("Service removal requires an elevated console");
    auto mutex = setupMutex();
    std::unique_ptr<void, decltype(&ReleaseMutex)> release(mutex.get(), ReleaseMutex);
    Manager manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT), CloseServiceHandle);
    require(bool(manager), "Open Service Control Manager");
    Manager service(OpenServiceW(manager.get(), Name,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE),
        CloseServiceHandle);
    const auto destination = executable(true);
    if (service)
    {
        configuration(service.get());
        stop(service.get());
        require(DeleteService(service.get()), "Remove service registration");
        service.reset();
    }
    else
    {
        require(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST, "Open capture service");
        if (std::filesystem::exists(destination) && !sameImage(executable(false), destination))
            throw std::runtime_error("The service is absent and the different System32 executable was left intact");
    }
    removeImage(destination);
    const auto package = destination.parent_path() / L"CipherazziLoopback";
    for (const auto name : {L"WinDivert.dll", L"WinDivert64.sys", L"LICENSE"})
        removeImage(package / name);
    RemoveDirectoryW(package.c_str());
    std::cout << "Cipherazzi service and installed executable removed. Capture databases and logs were preserved.\n";
}

int runService(std::atomic<bool>& stopped, std::function<void()> work)
{
    ServiceSupport::Runtime runtime{stopped, std::move(work)};
    ServiceSupport::Runtime::active = &runtime;
    SERVICE_TABLE_ENTRYW table[]{
        {const_cast<PWSTR>(ServiceSupport::Name), ServiceSupport::Runtime::main}, {nullptr, nullptr}};
    const auto started = StartServiceCtrlDispatcherW(table);
    ServiceSupport::Runtime::active = nullptr;
    ServiceSupport::require(started != FALSE, "Service mode must be launched by the Service Control Manager");
    return runtime.result.load();
}

void serviceProgress(ServicePhase phase)
{
    if (ServiceSupport::Runtime::active)
        ServiceSupport::Runtime::active->progress(phase);
}
}
