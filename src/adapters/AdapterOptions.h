#pragma once

#include <windows.h>
#include <frida-core.h>
#include <filesystem>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace Cipherazzi
{
struct AdapterOptions
{
    DWORD pid{};
    std::filesystem::path program, output;
    std::filesystem::path browserProfile;
    std::filesystem::path rustlsSymbols, rustlsProfile, rustlsProfileOutput;
    nlohmann::json rustlsMetadata;
    std::vector<std::string> arguments;
    std::string provider = "auto";
    std::string browserUrl;
    uint32_t duration{}, maxFiles = 4096, maxAge = 86400;
    uint16_t browserPort{};
    uint64_t maxBytes = 128 * 1024 * 1024;
    bool children = true;
};

std::string utf8(std::wstring_view value);
std::string adapterResource(WORD id);
void requireFrida(GError*& error);
AdapterOptions options(int count, wchar_t** arguments);
int runAdapter(AdapterOptions configured);
}
