#include "KeyLog.h"

#include <fstream>
#include <stdexcept>
#include <windows.h>

namespace Cipherazzi
{
namespace KeyLogDetail
{
constexpr size_t MaximumSecrets = 32768, MaximumLine = 4096;

bool decode(std::string_view text, std::vector<uint8_t>& bytes)
{
    if (text.size() % 2)
        return false;
    auto digit = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
        c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; };
    bytes.clear();
    for (size_t i = 0; i + 1 < text.size(); i += 2)
    {
        const auto high = digit(text[i]), low = digit(text[i + 1]);
        if (high < 0 || low < 0)
            return false;
        bytes.push_back(static_cast<uint8_t>(high * 16 + low));
    }
    return true;
}
}
using namespace KeyLogDetail;

void KeyLog::ingest(std::string_view line)
{
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
        line.remove_suffix(1);
    const auto first = line.find(' ');
    const auto second = first == std::string_view::npos ? first : line.find(' ', first + 1);
    if (second == std::string_view::npos || line.size() > MaximumLine)
        return;
    const auto label = line.substr(0, first);
    std::vector<uint8_t> random, secret;
    if (!decode(line.substr(first + 1, second - first - 1), random) || random.size() != 32 ||
        !decode(line.substr(second + 1), secret) || secret.empty() || secret.size() > 96)
        return;
    const std::string key(random.begin(), random.end());
    std::lock_guard lock(mutex_);
    auto [found, inserted] = secrets_.try_emplace(key);
    if (inserted)
    {
        order_.push_back(key);
        for (; order_.size() > MaximumSecrets; order_.pop_front())
            secrets_.erase(order_.front());
        found = secrets_.find(key);
    }
    auto& entry = found->second;
    if (label == "CLIENT_RANDOM") entry.master = std::move(secret);
    else if (label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET") entry.clientHandshake = std::move(secret);
    else if (label == "SERVER_HANDSHAKE_TRAFFIC_SECRET") entry.serverHandshake = std::move(secret);
    else if (label == "CLIENT_TRAFFIC_SECRET_0") entry.clientTraffic = std::move(secret);
    else if (label == "SERVER_TRAFFIC_SECRET_0") entry.serverTraffic = std::move(secret);
    else if (label == "CLIENT_EARLY_TRAFFIC_SECRET") entry.clientEarly = std::move(secret);
    else
        return;
    count_.fetch_add(1, std::memory_order_relaxed);
    generation_.fetch_add(1, std::memory_order_release);
}

void KeyLog::load(const std::filesystem::path& file)
{
    std::ifstream input(file, std::ios::binary);
    if (!input)
        throw std::runtime_error("The key log could not be opened: " + utf8(file.wstring()));
    for (std::string line; std::getline(input, line);)
        ingest(line);
}

void KeyLog::tail(const std::filesystem::path& file)
{
    std::lock_guard lock(tailMutex_);
    // Reopen with sharing so applications may append, truncate, or replace their key log while capture runs.
    const auto opened = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (opened == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
            error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION)
            return;
        throw std::runtime_error("The live TLS key log could not be opened (" + std::to_string(error) + ")");
    }
    std::unique_ptr<void, decltype(&CloseHandle)> handle(opened, CloseHandle);
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(opened, &info))
        throw std::runtime_error("Could not inspect the live TLS key log");
    const std::array<uint32_t, 3> identity{info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow};
    const auto size = uint64_t(info.nFileSizeHigh) << 32 | info.nFileSizeLow;
    if (identity != fileId_ || size < fileOffset_)
    {
        fileId_ = identity;
        fileOffset_ = 0;
        pending_.clear();
        droppingLine_ = false;
    }
    LARGE_INTEGER position{};
    position.QuadPart = fileOffset_;
    if (!SetFilePointerEx(opened, position, nullptr, FILE_BEGIN))
        throw std::runtime_error("Could not seek the live TLS key log");

    // Limit each poll and each pending line; a writer may stop halfway through any line.
    std::array<char, 16384> buffer{};
    for (size_t total = 0; total < 1024 * 1024 && fileOffset_ < size;)
    {
        DWORD read{};
        if (!ReadFile(opened, buffer.data(), DWORD(std::min<uint64_t>(buffer.size(), size - fileOffset_)),
            &read, nullptr))
        {
            if (GetLastError() == ERROR_LOCK_VIOLATION)
                return;
            throw std::runtime_error("Could not read the live TLS key log");
        }
        if (!read)
            break;
        fileOffset_ += read;
        total += read;
        for (DWORD index = 0; index < read; ++index)
        {
            const auto c = buffer[index];
            if (c == '\n')
            {
                if (!droppingLine_)
                    ingest(pending_);
                pending_.clear();
                droppingLine_ = false;
            }
            else if (!droppingLine_)
            {
                if (pending_.size() < MaximumLine)
                    pending_ += c;
                else
                {
                    pending_.clear();
                    droppingLine_ = true;
                }
            }
        }
    }
}

std::optional<TlsSecrets> KeyLog::find(Bytes clientRandom) const
{
    const std::string key(clientRandom.begin(), clientRandom.end());
    std::lock_guard lock(mutex_);
    const auto found = secrets_.find(key);
    if (found == secrets_.end())
        return {};
    return found->second;
}
}
