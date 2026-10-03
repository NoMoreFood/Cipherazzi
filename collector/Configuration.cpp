#include "Configuration.h"
#include "Model.h"
#include <filesystem>
#include <fstream>
#include <unordered_set>
#include <nlohmann/json.hpp>
#include <windows.h>

namespace Cipherazzi
{
std::vector<std::wstring> configurationArguments(std::span<wchar_t*> arguments)
{
    std::vector<std::wstring> result;
    bool loaded = false;
    for (size_t index = 0; index < arguments.size(); ++index)
    {
        if (std::wstring_view(arguments[index]) != L"--config")
        {
            result.emplace_back(arguments[index]);
            continue;
        }
        if (loaded || ++index == arguments.size())
            throw std::runtime_error("Supply one configuration file");
        loaded = true;
        const auto path = std::filesystem::absolute(arguments[index]).lexically_normal();
        if (std::filesystem::file_size(path) > 256 * 1024)
            throw std::runtime_error("Configuration exceeds 256 KiB");
        std::ifstream input(path, std::ios::binary);
        std::unordered_set<std::string> names;
        const auto document = nlohmann::json::parse(input, [&](int depth, nlohmann::json::parse_event_t event,
            nlohmann::json& value)
        {
            if (depth > 4 || (event == nlohmann::json::parse_event_t::key &&
                !names.insert(value.get<std::string>()).second))
                throw std::runtime_error("Configuration contains duplicate options or excessive nesting");
            return true;
        });
        if (!document.is_object())
            throw std::runtime_error("Configuration must be a JSON object of command options");
        for (const auto& [key, value] : document.items())
        {
            if (key.empty() || key.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-") != std::string::npos ||
                key == "config" || key == "service" || key == "install" || key == "uninstall" || key == "help")
                throw std::runtime_error("Configuration contains an invalid option");
            if (value == false)
                continue;
            const auto option = L"--" + std::wstring(key.begin(), key.end());
            if (value == true)
            {
                result.push_back(option);
                continue;
            }
            const auto entries = value.is_array() ? value : nlohmann::json::array({value});
            for (const auto& entry : entries)
            {
                if (!entry.is_string() && !entry.is_number_unsigned())
                    throw std::runtime_error("Configuration values must be strings, positive integers, or booleans");
                const auto text = entry.is_string() ? entry.get<std::string>() : entry.dump();
                const auto size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                    static_cast<int>(text.size()), nullptr, 0);
                if (!size)
                    throw std::runtime_error("Configuration contains an invalid or empty value");
                std::wstring wide(size, L'\0');
                MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                    wide.data(), size);
                if (key == "db" || key == "endpoint-directory" || key == "jfr-directory" ||
                    key == "replay" || key == "import-jfr")
                    wide = std::filesystem::absolute(path.parent_path() / wide).lexically_normal().wstring();
                result.insert(result.end(), {option, std::move(wide)});
            }
        }
    }
    return result;
}
}
