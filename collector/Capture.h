#pragma once

#include "Engine.h"
#include <filesystem>
#include <memory>

namespace Cipherazzi
{
enum class CaptureMode { Combined, Network, Loopback };

class Capture
{
public:
    Capture(Engine& engine, Counters& counters, const std::vector<uint32_t>& sources,
        CaptureMode mode = CaptureMode::Combined);
    ~Capture();
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;
    void check();
    void refreshSources();
    void stop();
    static void listSources();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

void replayPcap(const std::filesystem::path& path, Engine& engine, const std::atomic<bool>& stopped);
bool elevated();
}
