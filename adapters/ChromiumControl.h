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
        bool observing{};
    };

    ~ChromiumControl()
    {
        reader_.request_stop();
        socket_.reset();
        if (reader_.joinable()) reader_.join();
    }

    void connect(uint16_t port, const std::wstring& path)
    {
        // Use Windows' WebSocket client only against the authenticated loopback browser endpoint.
        session_.reset(WinHttpOpen(L"Cipherazzi", WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
        if (!session_ || !WinHttpSetTimeouts(session_.get(), 5000, 5000, 15000, 15000))
            throw std::runtime_error("The browser control session could not be initialized.");
        connection_.reset(WinHttpConnect(session_.get(), L"127.0.0.1", port, 0));
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
                        if (target.at("type") != "page") continue;
                        const auto session = parameters.at("sessionId").get<std::string>();
                        if (pages_.size() >= 64 || session.size() > 256 ||
                            target.at("targetId").get_ref<const std::string&>().size() > 256)
                            dropped_ = true;
                        else
                            pages_.try_emplace(session,
                                PageState{{session, target.at("targetId").get<std::string>(), false}});
                    }
                    else if (message.value("method", "") == "Target.detachedFromTarget")
                    {
                        const auto found = pages_.find(message.at("params").at("sessionId").get<std::string>());
                        if (found != pages_.end())
                        {
                            retained_ -= found->second.bytes;
                            pages_.erase(found);
                        }
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
            if (method == "Security.enable") found->second.page.observing = true;
            if (method == "Security.disable") found->second.page.observing = false;
        }
        return std::move(response_->at("result"));
    }

    std::vector<Page> pages(std::atomic<bool>& incomplete)
    {
        std::lock_guard locked(mutex_);
        if (dropped_ || closed_) incomplete = true;
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

private:
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
        size_t bytes{};
    };
    std::map<std::string, PageState, std::less<>> pages_;
    size_t retained_{};
    uint32_t expected_{};
    bool closed_{}, dropped_{};
};
}
