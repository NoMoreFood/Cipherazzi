#pragma once

#include <winhttp.h>
#include <array>
#include <atomic>
#include <condition_variable>
#include <map>
#include <optional>
#include <vector>

namespace Cipherazzi
{
class ChromiumControl
{
public:
    struct Page
    {
        std::string session, target;
        bool observing{}, networking{};
        std::string type;
    };

    ~ChromiumControl()
    {
        reader_.request_stop();
        socket_.reset();
        if (reader_.joinable()) reader_.join();
    }

    void connect(uint16_t port, std::wstring path)
    {
        // Use Windows' WebSocket client only against the authenticated loopback browser endpoint.
        session_.reset(WinHttpOpen(L"Cipherazzi", WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
        if (!session_ || !WinHttpSetTimeouts(session_.get(), 5000, 5000, 15000, 15000))
            throw std::runtime_error("The browser control session could not be initialized.");
        connection_.reset(WinHttpConnect(session_.get(), L"127.0.0.1", port, 0));
        if (path.empty())
        {
            // Discover only the WebSocket path on the listener whose process identity was checked by the caller.
            InternetHandle version(WinHttpOpenRequest(connection_.get(), L"GET", L"/json/version", nullptr,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0), WinHttpCloseHandle);
            DWORD redirects = WINHTTP_DISABLE_REDIRECTS;
            if (!version || !WinHttpSetOption(version.get(), WINHTTP_OPTION_DISABLE_FEATURE,
                &redirects, sizeof(redirects)) || !WinHttpSendRequest(version.get(), WINHTTP_NO_ADDITIONAL_HEADERS,
                    0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(version.get(), nullptr))
                throw std::runtime_error("The browser control endpoint could not be discovered.");
            std::string body;
            std::array<char, 4096> buffer{};
            DWORD bytes{};
            do
            {
                if (!WinHttpReadData(version.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytes) ||
                    body.size() + bytes > 65536)
                    throw std::runtime_error("The browser control response was unavailable or exceeded its bound.");
                body.append(buffer.data(), bytes);
            } while (bytes);
            const auto url = nlohmann::json::parse(body).at("webSocketDebuggerUrl").get<std::string>();
            const auto prefix = "ws://127.0.0.1:" + std::to_string(port);
            if (!url.starts_with(prefix + "/devtools/browser/") || url.size() > 512)
                throw std::runtime_error("The browser reported an unexpected control endpoint.");
            path.assign(url.begin() + prefix.size(), url.end());
        }
        InternetHandle request(WinHttpOpenRequest(connection_.get(), L"GET", path.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0), WinHttpCloseHandle);
        if (!connection_ || !request ||
            !WinHttpSetOption(request.get(), WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) ||
            !WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request.get(), nullptr))
            throw std::runtime_error("The browser control connection could not be established.");
        socket_.reset(WinHttpWebSocketCompleteUpgrade(request.get(), 0));
        if (!socket_) throw std::runtime_error("The browser WebSocket upgrade failed.");
        const auto socket = socket_.get();
        reader_ = std::jthread([this, socket](std::stop_token stopping)
        {
            // Retain bounded page identities and their current public security state.
            try
            {
                std::array<char, 8192> buffer{};
                std::string frame;
                while (!stopping.stop_requested())
                {
                    DWORD bytes{};
                    WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
                    if (WinHttpWebSocketReceive(socket, buffer.data(), static_cast<DWORD>(buffer.size()),
                        &bytes, &type) || type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE)
                        break;
                    if ((type != WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE &&
                        type != WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) || frame.size() + bytes > 4 * 1024 * 1024)
                        throw std::runtime_error("The browser emitted an unsupported control frame.");
                    frame.append(buffer.data(), bytes);
                    if (type != WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) continue;
                    auto message = nlohmann::json::parse(frame);
                    frame.clear();
                    std::lock_guard locked(mutex_);
                    if (message.contains("id"))
                    {
                        if (message.at("id") != expected_ || response_)
                            throw std::runtime_error("The browser emitted an unexpected command response.");
                        response_ = std::move(message);
                        ready_.notify_all();
                    }
                    else if (message.value("method", "") == "Target.attachedToTarget")
                    {
                        const auto& parameters = message.at("params");
                        const auto& target = parameters.at("targetInfo");
                        const auto targetType = target.at("type").get<std::string>();
                        if (targetType != "page" && targetType != "iframe" && targetType != "worker" &&
                            targetType != "shared_worker" && targetType != "service_worker") continue;
                        const auto session = parameters.at("sessionId").get<std::string>();
                        if (pages_.size() >= 64 || session.size() > 256 ||
                            target.at("targetId").get_ref<const std::string&>().size() > 256)
                            throw std::runtime_error("The browser observation target limit was reached.");
                        else
                            pages_.try_emplace(session,
                                PageState{{session, target.at("targetId").get<std::string>(),
                                    false, false, targetType}});
                    }
                    else if (message.value("method", "") == "Target.detachedFromTarget")
                    {
                        const auto session = message.at("params").at("sessionId").get<std::string>();
                        const auto found = pages_.find(session);
                        if (found != pages_.end())
                        {
                            retained_ -= found->second.bytes;
                            pages_.erase(found);
                        }
                        std::erase_if(requests_, [&](const auto& entry)
                        { return entry.first.starts_with(session + ':'); });
                    }
                    else if (message.value("method", "") == "Network.requestWillBeSent")
                    {
                        const auto& parameters = message.at("params");
                        const auto key = message.value("sessionId", "") + ':' +
                            parameters.at("requestId").get<std::string>();
                        const auto& url = parameters.at("request").at("url").get_ref<const std::string&>();
                        if (!url.starts_with("https://"))
                        {
                            requests_.erase(key);
                            continue;
                        }
                        auto origin = url.substr(8, url.find_first_of("/?#", 8) - 8);
                        if (const auto credentials = origin.rfind('@'); credentials != std::string::npos)
                            origin.erase(0, credentials + 1);
                        if (requests_.size() >= 4096 || key.size() > 512 ||
                            parameters.value("frameId", "").size() > 256 ||
                            parameters.value("loaderId", "").size() > 256)
                            dropped_ = true;
                        else if (!origin.empty() && origin.size() <= 512)
                            requests_[key] = {parameters.at("timestamp").get<double>(),
                                parameters.at("wallTime").get<double>(), "https://" + origin,
                                parameters.value("frameId", ""), parameters.value("loaderId", ""),
                                parameters.value("type", "") == "Document"};
                    }
                    else if (message.value("method", "") == "Network.loadingFailed")
                    {
                        const auto& parameters = message.at("params");
                        const auto session = message.value("sessionId", "");
                        const auto key = session + ':' + parameters.at("requestId").get<std::string>();
                        const auto request = requests_.find(key);
                        if (request == requests_.end()) continue;
                        auto error = parameters.value("errorText", "");
                        if (error.starts_with("net::")) error.erase(0, 5);

                        // Report explicit TLS errors without treating cancellation, HTTP, or CORS failures as TLS.
                        if (error.size() <= 128 && !parameters.value("canceled", false) &&
                            (error.starts_with("ERR_CERT_") || error.starts_with("ERR_SSL_") ||
                                error.starts_with("ERR_BAD_SSL_") || error == "ERR_ALPN_NEGOTIATION_FAILED" ||
                                error == "ERR_TLS13_DOWNGRADE_DETECTED" || error == "ERR_ECH_NOT_NEGOTIATED" ||
                                error == "ERR_ECH_FALLBACK_CERTIFICATE_INVALID"))
                        {
                            const auto& started = request->second;
                            enqueue({{"error", error}, {"request", key}, {"session", session},
                                {"frame", started.frame}, {"loader", started.loader},
                                {"document", started.document}, {"url", started.origin},
                                {"origin_ms", started.wall * 1000}, {"start_ms", 0},
                                {"end_ms", (parameters.at("timestamp").get<double>() - started.monotonic) * 1000}});
                        }
                        requests_.erase(request);
                    }
                    else if (message.value("method", "") == "Network.loadingFinished" ||
                        message.value("method", "") == "Network.requestServedFromCache")
                    {
                        requests_.erase(message.value("sessionId", "") + ':' +
                            message.at("params").at("requestId").get<std::string>());
                    }
                    else if (message.value("method", "") == "Network.responseReceived")
                    {
                        const auto& parameters = message.at("params");
                        const auto session = message.value("sessionId", "");
                        const auto request = requests_.find(session + ':' +
                            parameters.at("requestId").get<std::string>());
                        const auto page = pages_.find(session);
                        const auto& response = parameters.at("response");
                        if (request == requests_.end() || page == pages_.end() ||
                            !response.contains("securityDetails") || response.value("connectionId", 0.0) <= 0 ||
                            response.value("fromDiskCache", false) || response.value("fromPrefetchCache", false) ||
                            response.value("fromServiceWorker", false)) continue;
                        const auto timing = response.value("timing", nlohmann::json::object());
                        const bool handshake = !response.value("connectionReused", true) &&
                            timing.value("sslStart", -1.0) >= 0 &&
                            timing.value("sslEnd", -1.0) >= timing.at("sslStart").get<double>();

                        // Keep only connection security and timing, excluding headers, bodies, and request data.
                        nlohmann::json security = nlohmann::json::object();
                        for (const auto* field : {"protocol", "cipher", "mac", "keyExchange", "keyExchangeGroup",
                            "serverSignatureAlgorithm"})
                            if (response.at("securityDetails").contains(field))
                                security[field] = response.at("securityDetails").at(field);
                        nlohmann::json observation{{"security", std::move(security)},
                            {"session", session}, {"frame", parameters.value("frameId", "")},
                            {"loader", parameters.value("loaderId", "")},
                            {"document", parameters.value("type", "") == "Document"},
                            {"url", response.at("url")}, {"connection_id", response.at("connectionId")},
                            {"remote_address", response.value("remoteIPAddress", "")},
                            {"remote_port", response.value("remotePort", 0)},
                            {"alpn", response.value("protocol", "")},
                            {"verified", response.value("securityState", "") == "secure"},
                            {"handshake", handshake},
                            {"origin_ms", (request->second.wall + (handshake ? timing.at("requestTime") :
                                parameters.at("timestamp")).get<double>() -
                                request->second.monotonic) * 1000},
                            {"start_ms", handshake ? timing.at("sslStart") : nlohmann::json(0)},
                            {"end_ms", handshake ? timing.at("sslEnd") : nlohmann::json(0)}};
                        enqueue(std::move(observation));
                    }
                    else if (message.value("method", "") == "Security.visibleSecurityStateChanged")
                    {
                        const auto found = pages_.find(message.value("sessionId", ""));
                        if (found == pages_.end()) continue;
                        auto& page = found->second;
                        auto state = message.at("params").at("visibleSecurityState");
                        const auto size = state.dump().size();
                        retained_ -= page.bytes;
                        page.bytes = 0;
                        page.state.reset();
                        if (retained_ + size > 4 * 1024 * 1024)
                            dropped_ = true;
                        else
                        {
                            retained_ += page.bytes = size;
                            page.state = std::move(state);
                        }
                    }
                }
            }
            catch (...) {}
            std::lock_guard locked(mutex_);
            closed_ = true;
            ready_.notify_all();
        });
    }

    nlohmann::json command(std::string_view method, nlohmann::json parameters = nlohmann::json::object(),
        std::string_view session = {})
    {
        std::unique_lock locked(mutex_);
        nlohmann::json request{{"id", ++expected_}, {"method", method}, {"params", std::move(parameters)}};
        if (!session.empty()) request["sessionId"] = session;
        const auto body = request.dump();
        response_.reset();
        if (closed_ || WinHttpWebSocketSend(socket_.get(), WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
            const_cast<char*>(body.data()), static_cast<DWORD>(body.size())) ||
            !ready_.wait_for(locked, std::chrono::seconds(15), [this] { return closed_ || response_.has_value(); }) ||
            !response_)
            throw std::runtime_error("The browser did not acknowledge its observation command.");
        if (response_->contains("error"))
        {
            // Tab closure and navigation can invalidate a session, frame, or isolated context between commands.
            const auto code = response_->at("error").value("code", 0);
            const auto message = response_->at("error").value("message", "");
            if (!session.empty() && (code == -32001 || !pages_.contains(session) ||
                (method == "Page.createIsolatedWorld" && message == "No frame for given id found") ||
                (method == "Runtime.evaluate" && (message == "Cannot find context with specified id" ||
                    message == "Execution context was destroyed.")) ||
                (code == -32000 && message == "Not attached to an active page"))) return nullptr;
            throw std::runtime_error("The browser did not acknowledge its observation command.");
        }
        if (const auto found = pages_.find(session); found != pages_.end())
        {
            if (method == "Network.enable") found->second.page.networking = true;
            if (method == "Security.enable") found->second.page.observing = true;
            if (method == "Security.disable") found->second.page.observing = false;
            if (method == "Page.getFrameTree" && response_->at("result").contains("frameTree"))
                found->second.mainFrame = response_->at("result").at("frameTree").at("frame").at("id");
        }
        return std::move(response_->at("result"));
    }

    std::vector<Page> pages(std::atomic<bool>& incomplete)
    {
        std::lock_guard locked(mutex_);
        if (closed_) throw std::runtime_error("The browser observation connection closed.");
        if (dropped_) incomplete = true;
        std::vector<Page> result;
        for (const auto& [session, state] : pages_) result.push_back(state.page);
        return result;
    }

    std::optional<nlohmann::json> state(std::string_view session, bool clear = false)
    {
        std::lock_guard locked(mutex_);
        const auto found = pages_.find(session);
        if (found == pages_.end()) return std::nullopt;
        if (!clear) return found->second.state;
        retained_ -= found->second.bytes;
        found->second.bytes = 0;
        return std::exchange(found->second.state, {});
    }

    std::vector<nlohmann::json> network()
    {
        std::lock_guard locked(mutex_);
        networkBytes_ = 0;
        for (auto& observation : network_)
        {
            const auto found = pages_.find(observation.at("session").template get<std::string>());
            observation["navigation"] = observation.at("document") == true && found != pages_.end() &&
                found->second.page.type == "page" && observation.at("frame") == found->second.mainFrame;
        }
        return std::exchange(network_, {});
    }

    void detach()
    {
        // Release targets paused by this observer before ending its automatic attachment.
        std::atomic<bool> incomplete{};
        for (const auto& page : pages(incomplete))
            command("Runtime.runIfWaitingForDebugger", nlohmann::json::object(), page.session);
        command("Target.setAutoAttach", {{"autoAttach", false}, {"waitForDebuggerOnStart", false}, {"flatten", true}});
    }

private:
    void enqueue(nlohmann::json observation)
    {
        const auto size = observation.dump().size();
        if (network_.size() >= 1024 || size > 16384 || networkBytes_ + size > 2 * 1024 * 1024)
            dropped_ = true;
        else
        {
            networkBytes_ += size;
            network_.push_back(std::move(observation));
        }
    }

    using InternetHandle = std::unique_ptr<void, decltype(&WinHttpCloseHandle)>;
    InternetHandle session_{nullptr, WinHttpCloseHandle}, connection_{nullptr, WinHttpCloseHandle},
        socket_{nullptr, WinHttpCloseHandle};
    std::jthread reader_;
    std::mutex mutex_;
    std::condition_variable ready_;
    std::optional<nlohmann::json> response_;
    struct PageState
    {
        Page page;
        std::optional<nlohmann::json> state;
        std::string mainFrame;
        size_t bytes{};
    };
    std::map<std::string, PageState, std::less<>> pages_;
    struct RequestState
    {
        double monotonic{}, wall{};
        std::string origin, frame, loader;
        bool document{};
    };
    std::map<std::string, RequestState> requests_;
    std::vector<nlohmann::json> network_;
    size_t retained_{}, networkBytes_{};
    uint32_t expected_{};
    bool closed_{}, dropped_{};
};
}
