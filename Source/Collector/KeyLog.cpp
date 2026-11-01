#include "KeyLog.h"

#include <fstream>
#include <limits>
#include <stdexcept>
#include <windows.h>

namespace Cipherazzi
{
namespace KeyLogDetail
{
constexpr size_t MaximumSecrets = 32768, MaximumLine = 4096;
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
    if (label != "CLIENT_RANDOM" && label != "CLIENT_HANDSHAKE_TRAFFIC_SECRET" &&
        label != "SERVER_HANDSHAKE_TRAFFIC_SECRET" && label != "CLIENT_TRAFFIC_SECRET_0" &&
        label != "SERVER_TRAFFIC_SECRET_0")
        return;
    std::vector<uint8_t> random, secret;
    if (!unhex(line.substr(first + 1, second - first - 1), random) || random.size() != 32 ||
        !unhex(line.substr(second + 1), secret) || secret.size() > 96)
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
    count_.fetch_add(1, std::memory_order_relaxed);
    generation_.fetch_add(1, std::memory_order_release);
}

void KeyLog::load(const std::filesystem::path& file)
{
    std::ifstream input(file, std::ios::binary);
    if (!input)
        throw std::runtime_error("The key log could not be opened: " + utf8(file.wstring()));

    // Discard oversized lines without allocating their contents, including a damaged file without newlines.
    std::array<char, MaximumLine + 2> line{};
    while (!input.eof())
    {
        input.getline(line.data(), line.size());
        if (input.bad())
            break;
        if (!input.fail())
            ingest({line.data(), static_cast<size_t>(input.gcount()) - (input.eof() ? 0 : 1)});
        else if (!input.eof())
        {
            input.clear();
            input.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
    }
    if (input.bad())
        throw std::runtime_error("The key log could not be read: " + utf8(file.wstring()));
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
