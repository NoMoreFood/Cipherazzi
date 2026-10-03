#pragma once

#include "Storage.h"
#include <windows.h>
#include <winevt.h>
#include <unordered_set>

namespace Cipherazzi
{
class Telemetry
{
public:
    Telemetry(Storage& storage, Counters& counters, bool schannel, std::filesystem::path javaDirectory,
        std::filesystem::path endpointDirectory = {});
    ~Telemetry();
    void stop();
    static size_t importJava(const std::filesystem::path& file, Storage& storage,
        const std::function<bool(const std::string&)>& accept = {});

    static size_t importEndpoint(const std::filesystem::path& file, Storage& storage,
        const std::function<bool(const std::string&)>& accept = {});
    static void normalizeProvider(EndpointEvent& event, const Owner& owner);

private:
    static DWORD WINAPI eventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, void* context, EVT_HANDLE event);
    void event(EVT_HANDLE event);
    void report(std::string provider, std::string result);
    Storage& storage_;
    Counters& counters_;
    std::vector<std::unique_ptr<std::remove_pointer_t<EVT_HANDLE>, decltype(&EvtClose)>> subscriptions_;
    std::atomic<bool> stopped_{};
    std::thread thread_;
};
}
