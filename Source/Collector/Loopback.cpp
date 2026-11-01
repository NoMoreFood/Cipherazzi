#include "Loopback.h"

#include <winsock2.h>
#include <windows.h>
#include <windivert.h>
#include <filesystem>
#include <stdexcept>
#include <thread>

namespace Cipherazzi
{
static_assert(LoopbackCaptureLimit == WINDIVERT_MTU_MAX && sizeof(WINDIVERT_ADDRESS) == 80);

struct LoopbackCapture::Impl
{
    Sink sink;
    Counters& counters;
    HMODULE module{};
    HANDLE handle{};
    decltype(&WinDivertOpen) open{};
    decltype(&WinDivertRecvEx) receive{};
    decltype(&WinDivertShutdown) shutdown{};
    decltype(&WinDivertClose) close{};
    decltype(&WinDivertSetParam) parameter{};
    std::atomic<bool> stopping{};
    std::atomic<DWORD> fatal{};
    std::thread reader;

    Impl(Sink output, Counters& stats) : sink(std::move(output)), counters(stats) {}
    ~Impl()
    {
        stop();
        if (module)
            FreeLibrary(module);
    }

    void start()
    {
        // Load only the packaged capture library and its system dependencies.
        std::wstring executable(32768, L'\0');
        const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (!length || length >= executable.size())
            throw std::runtime_error("Could not locate the loopback capture package");
        executable.resize(length);
        const auto path = std::filesystem::path(executable).parent_path() / L"CipherazziLoopback" / L"WinDivert.dll";
        module = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module)
            throw std::runtime_error("Loopback capture package is unavailable; restore CipherazziLoopback "
                "beside the collector or select --no-loopback");
        auto load = [&](auto& function, const char* name)
        {
            function = reinterpret_cast<std::remove_reference_t<decltype(function)>>(GetProcAddress(module, name));
            if (!function)
                throw std::runtime_error("The loopback capture package exposes an incompatible API");
        };
        load(open, "WinDivertOpen");
        load(receive, "WinDivertRecvEx");
        load(shutdown, "WinDivertShutdown");
        load(close, "WinDivertClose");
        load(parameter, "WinDivertSetParam");

        // Sniff only same-host TCP/UDP copies, including traffic addressed to local network interfaces.
        const auto opened = open("loopback and (tcp or udp)", WINDIVERT_LAYER_NETWORK, 0,
            WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
        if (opened == INVALID_HANDLE_VALUE)
            throw std::runtime_error("Loopback capture driver could not start (" + std::to_string(GetLastError()) +
                "); use an elevated console and allow the signed driver, or select --no-loopback");
        handle = opened;
        if (!parameter(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384) ||
            !parameter(handle, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX) ||
            !parameter(handle, WINDIVERT_PARAM_QUEUE_TIME, 1000))
            throw std::runtime_error("Could not configure loopback capture buffering");

        // Preserve the driver's capture time when converting its monotonic timestamps to Unix microseconds.
        LARGE_INTEGER frequency{};
        if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0)
            throw std::runtime_error("Could not read the loopback capture clock");
        reader = std::thread([this, frequency]
        {
            // Fit a maximum-size packet without pinning a large mostly empty buffer on every receive.
            std::vector<uint8_t> packets(LoopbackCaptureLimit);
            std::array<WINDIVERT_ADDRESS, 64> addresses;
            LARGE_INTEGER clock{};
            QueryPerformanceCounter(&clock);
            auto epoch = nowUs();
            auto refreshed = clock.QuadPart;
            size_t reads = 0;
            bool queued = false;
            for (;;)
            {
                // Sample the queue periodically; avoid locking a batch-length output for mostly empty queues.
                const bool batch = queued || (++reads % 64 == 0);
                UINT length{}, addressLength = batch ? sizeof(addresses) : sizeof(WINDIVERT_ADDRESS);
                if (!receive(handle, packets.data(), static_cast<UINT>(packets.size()), &length, 0,
                    addresses.data(), batch ? &addressLength : nullptr, nullptr))
                {
                    const auto error = GetLastError();
                    if (stopping && (error == ERROR_NO_DATA || error == ERROR_OPERATION_ABORTED ||
                        error == ERROR_INVALID_HANDLE))
                        break;
                    if (error == ERROR_INSUFFICIENT_BUFFER)
                    {
                        ++counters.truncated;
                        continue;
                    }
                    fatal = error ? error : ERROR_OPERATION_ABORTED;
                    break;
                }
                if (!addressLength || addressLength > sizeof(addresses) ||
                    addressLength % sizeof(WINDIVERT_ADDRESS) || length > packets.size())
                {
                    fatal = ERROR_INVALID_DATA;
                    break;
                }
                const size_t count = addressLength / sizeof(WINDIVERT_ADDRESS);
                queued = count > 1;

                // Receive already queued packets together, retaining each packet's own address and capture time.
                size_t offset = 0;
                for (size_t index = 0; index < count; ++index)
                {
                    const auto remaining = Bytes(packets).subspan(offset, length - offset);
                    const auto version = remaining.empty() ? 0 : remaining[0] >> 4;
                    const size_t header = version == 4 ? 20 : version == 6 ? 40 : 0;
                    const size_t size = count == 1 ? length : remaining.size() < header || !header ? 0 : version == 4 ?
                        (size_t{remaining[2]} << 8) | remaining[3] :
                        40 + (size_t{remaining[4]} << 8) + remaining[5];
                    if (!size || (count > 1 && size < header) || size > remaining.size() ||
                        size > LoopbackCaptureLimit)
                    {
                        fatal = ERROR_INVALID_DATA;
                        break;
                    }
                    offset += size;
                    const auto& address = addresses[index];
                    if (address.Layer != WINDIVERT_LAYER_NETWORK || address.Event != WINDIVERT_EVENT_NETWORK_PACKET ||
                        !address.Loopback || !address.Sniffed || !address.Outbound)
                    {
                        ++counters.unsupported;
                        continue;
                    }
                    const auto elapsed = address.Timestamp - clock.QuadPart;
                    const auto timestamp = epoch + elapsed / frequency.QuadPart * 1000000 +
                        elapsed % frequency.QuadPart * 1000000 / frequency.QuadPart;
                    sink(remaining.first(size), timestamp);
                }
                if (fatal || offset != length)
                {
                    fatal = ERROR_INVALID_DATA;
                    break;
                }
                LARGE_INTEGER current{};
                QueryPerformanceCounter(&current);
                if (current.QuadPart - refreshed >= frequency.QuadPart)
                {
                    clock = current;
                    epoch = nowUs();
                    refreshed = current.QuadPart;
                }
            }
        });
    }

    void stop()
    {
        // Stop new captures and drain packets already queued before releasing the driver handle.
        if (!handle)
            return;
        stopping = true;
        const auto ended = shutdown(handle, WINDIVERT_SHUTDOWN_RECV);
        if (!ended)
            close(handle);
        if (reader.joinable())
            reader.join();
        if (ended)
            close(handle);
        handle = nullptr;
    }
};

LoopbackCapture::LoopbackCapture(Sink sink, Counters& counters) :
    impl_(std::make_unique<Impl>(std::move(sink), counters))
{
    impl_->start();
}

LoopbackCapture::~LoopbackCapture() = default;
void LoopbackCapture::stop() { impl_->stop(); }
void LoopbackCapture::check()
{
    if (const auto error = impl_->fatal.load())
        throw std::runtime_error("Loopback capture stopped (" + std::to_string(error) + ")");
}
}
