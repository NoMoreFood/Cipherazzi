#include <winsock2.h>
#include <ws2tcpip.h>
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
#include <deque>
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

#include "AdapterOptions.h"

namespace Cipherazzi
{
extern std::atomic<bool> AdapterStopped;

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
        else if (argument == L"--rustls-symbols") result.rustlsSymbols = std::filesystem::absolute(value);
        else if (argument == L"--rustls-profile") result.rustlsProfile = std::filesystem::absolute(value);
        else if (argument == L"--rustls-profile-out") result.rustlsProfileOutput = std::filesystem::absolute(value);
        else if (argument == L"--browser-profile") result.browserProfile = std::filesystem::absolute(value);
        else if (argument == L"--browser-port") result.browserPort = static_cast<uint16_t>(number(1, 65535));
        else if (argument == L"--url") result.browserUrl = utf8(value);
        else if (argument == L"--duration") result.duration = static_cast<uint32_t>(number(0, 86400));
        else if (argument == L"--max-files") result.maxFiles = static_cast<uint32_t>(number(1, 65536));
        else if (argument == L"--max-age") result.maxAge = static_cast<uint32_t>(number(1, 2592000));
        else if (argument == L"--max-mb") result.maxBytes = number(4, 4096) * 1024 * 1024;
        else throw std::runtime_error("Unknown endpoint adapter option.");
    }
    if ((result.pid != 0) == !result.program.empty() || result.output.empty() ||
        (result.provider != "auto" && result.provider != "openssl" && result.provider != "boringssl" &&
        result.provider != "nss" && result.provider != "schannel" && result.provider != "firefox" &&
        result.provider != "chromium" && result.provider != "go" && result.provider != "rustls"))
        throw std::runtime_error("Specify --output and either --pid or --spawn; choose a supported provider.");
    if ((result.provider == "firefox" || result.provider == "chromium") && result.pid &&
        (!result.browserPort || !result.browserProfile.empty()))
        throw std::runtime_error(
            "Attaching to a browser requires --pid and --browser-port, without --browser-profile.");
    if (result.browserPort && !result.pid)
        throw std::runtime_error("A browser control port requires --pid.");
    if (result.provider != "firefox" && result.provider != "chromium" &&
        (!result.browserProfile.empty() || !result.browserUrl.empty() || result.browserPort))
        throw std::runtime_error("Browser profile, port, and URL options require a browser provider.");

    // Load bounded observation metadata before starting or attaching to the application.
    if (result.provider != "auto" && result.provider != "rustls" &&
        (!result.rustlsSymbols.empty() || !result.rustlsProfile.empty() || !result.rustlsProfileOutput.empty()))
        throw std::runtime_error("Rustls symbol and observation profile options require auto or rustls provider.");
    if (!result.rustlsSymbols.empty() && !std::filesystem::is_directory(result.rustlsSymbols))
        throw std::runtime_error("The rustls symbol directory does not exist.");
    if (!result.rustlsProfile.empty())
    {
        if (!result.rustlsProfileOutput.empty() || !result.rustlsSymbols.empty())
            throw std::runtime_error("Choose a rustls observation profile or matching symbols, not both.");
        if (!std::filesystem::is_regular_file(result.rustlsProfile))
            throw std::runtime_error("The rustls observation profile does not exist.");
        const auto size = std::filesystem::file_size(result.rustlsProfile);
        if (!size || size > 16 * 1024 * 1024)
            throw std::runtime_error("The rustls observation profile exceeds its size bound.");
        std::ifstream file(result.rustlsProfile, std::ios::binary);
        file.exceptions(std::ios::failbit | std::ios::badbit);
        std::string bytes(static_cast<size_t>(size), '\0');
        file.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        result.rustlsMetadata = nlohmann::json::parse(bytes, [](int depth, auto, auto&)
        {
            if (depth > 32) throw std::runtime_error("The rustls observation profile exceeds its nesting bound.");
            return true;
        });
        if (!result.rustlsMetadata.is_object() ||
            result.rustlsMetadata.value("schema", "") != "cipherazzi.rustls-profile/1")
            throw std::runtime_error("The rustls observation profile schema is unsupported.");
    }
    if (!result.rustlsProfileOutput.empty() && std::filesystem::exists(result.rustlsProfileOutput))
        throw std::runtime_error("Choose a new file for the rustls observation profile.");
    if (!result.program.empty())
    {
        if (!std::filesystem::is_regular_file(result.program))
            throw std::runtime_error("The application executable does not exist.");
        result.arguments.insert(result.arguments.begin(), utf8(result.program.wstring()));
    }
    std::filesystem::create_directories(result.output);
    return result;
}

}

int wmain(int count, wchar_t** arguments)
{
    if (count == 1 || (count == 2 && std::wstring_view(arguments[1]) == L"--help"))
    {
        std::cout << "Cipherazzi public endpoint adapter\n\n"
            "  Cipherazzi.EndpointAdapter.exe --pid <pid> --output <directory>\n"
            "  Cipherazzi.EndpointAdapter.exe --spawn <application.exe> --output <directory> -- <arguments>\n\n"
            "  --provider auto|openssl|boringssl|nss|schannel|go|rustls  Select a TLS runtime (default auto)\n"
            "  --duration <seconds>                 Stop observation; 0 waits for observed processes\n"
            "  --no-children                        Observe only the specified process\n"
            "  --max-files <n>                      Retained report count (default 4096)\n"
            "  --max-mb <n>                         Retained report storage (default 128 MiB)\n"
            "  --max-age <seconds>                  Retained report age (default 86400)\n\n"
            "  --rustls-symbols <directory>         Matching local PDBs for unmodified rustls executables\n"
            "  --rustls-profile <file>              Exact-build observation profile; no runtime PDB required\n"
            "  --rustls-profile-out <new-file>      Save a reusable profile from matching type symbols\n\n"
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
        return Cipherazzi::runAdapter(std::move(configured));
    }
    catch (const std::exception& error)
    {
        std::cerr << "Endpoint adapter failed: " << error.what() << '\n';
        return 1;
    }
}
