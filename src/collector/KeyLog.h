#pragma once

#include "Model.h"
#include <atomic>
#include <deque>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>

namespace Cipherazzi
{
// Secrets an application exported in the NSS key log format, found by the random in the connection's ClientHello.
struct TlsSecrets
{
    std::vector<uint8_t> master, clientHandshake, serverHandshake, clientTraffic, serverTraffic, clientEarly;
};

class KeyLog
{
public:
    // Adds one key log line; anything that is not a well-formed secret is ignored.
    void ingest(std::string_view line);

    // Reads a complete file, as for a replay.
    void load(const std::filesystem::path& file);
    // Reads appended complete lines; a file that has not been created yet is allowed during live capture.
    void tail(const std::filesystem::path& file);
    std::optional<TlsSecrets> find(Bytes clientRandom) const;

    // Changes whenever a secret arrives, so waiting connections know to look again.
    uint64_t generation() const { return generation_.load(std::memory_order_relaxed); }
    uint64_t count() const { return count_.load(std::memory_order_relaxed); }

private:
    mutable std::mutex mutex_;
    std::mutex tailMutex_;
    std::unordered_map<std::string, TlsSecrets> secrets_;
    std::deque<std::string> order_;
    std::atomic<uint64_t> generation_{}, count_{};
    std::array<uint32_t, 3> fileId_{};
    uint64_t fileOffset_{};
    std::string pending_;
    bool droppingLine_{};
};
}
