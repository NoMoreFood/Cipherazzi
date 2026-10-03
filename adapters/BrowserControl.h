#pragma once

namespace Cipherazzi
{
class BrowserControl
{
public:
    ~BrowserControl() { if (socket_ != INVALID_SOCKET) closesocket(socket_); }

    bool connect(uint16_t port)
    {
        socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_ == INVALID_SOCKET)
            throw std::runtime_error("The browser control socket could not be created.");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        if (::connect(socket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)))
        {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
            return false;
        }
        DWORD timeout = 15000;
        setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        const auto hello = receive();
        if (hello.value("applicationType", "") != "gecko" || hello.value("marionetteProtocol", 0) < 3)
            throw std::runtime_error("The browser control protocol is unavailable.");
        return true;
    }

    nlohmann::json command(std::string_view name, nlohmann::json parameters = nlohmann::json::object(),
        bool allowNavigationFailure = false)
    {
        const auto body = nlohmann::json::array({0, ++sequence_, name, std::move(parameters)}).dump();
        const auto framed = std::to_string(body.size()) + ":" + body;
        size_t offset = 0;
        while (offset < framed.size())
        {
            const auto written = send(socket_, framed.data() + offset, static_cast<int>(framed.size() - offset), 0);
            if (written <= 0)
                throw std::runtime_error("The browser control connection was closed.");
            offset += written;
        }
        auto response = receive();
        if (!response.is_array() || response.size() != 4 || response[0] != 1 || response[1] != sequence_)
            throw std::runtime_error("The browser rejected an observation command.");
        if (!response[2].is_null())
        {
            if (!allowNavigationFailure || name != "WebDriver:Navigate" || !response[2].is_object())
                throw std::runtime_error("The browser rejected an observation command.");
            return {{"navigation_failed", true}};
        }
        return std::move(response[3]);
    }

    nlohmann::json script(const std::string& source, nlohmann::json arguments = nlohmann::json::array())
    {
        return command("WebDriver:ExecuteScript", {{"script", source}, {"args", std::move(arguments)},
            {"sandbox", "cipherazzi"}, {"newSandbox", false}}).at("value");
    }

    DWORD owner(uint16_t port) const
    {
        // Authenticate the control listener with Windows' socket ownership table.
        ULONG bytes{};
        if (GetExtendedTcpTable(nullptr, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) !=
            ERROR_INSUFFICIENT_BUFFER || bytes > 4 * 1024 * 1024)
            return 0;
        std::vector<BYTE> buffer(bytes);
        if (GetExtendedTcpTable(buffer.data(), &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0))
            return 0;
        const auto table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        DWORD result{};
        for (DWORD index = 0; index < table->dwNumEntries; ++index)
        {
            const auto& row = table->table[index];
            if (ntohs(static_cast<u_short>(row.dwLocalPort)) != port)
                continue;
            if (result && result != row.dwOwningPid) return 0;
            result = row.dwOwningPid;
        }
        return result;
    }

private:
    SOCKET socket_ = INVALID_SOCKET;
    uint32_t sequence_{};

    nlohmann::json receive()
    {
        // Accept bounded, length-prefixed JSON from the browser's loopback control endpoint.
        std::string prefix;
        char next{};
        while (recv(socket_, &next, 1, 0) == 1 && next != ':')
        {
            if (next < '0' || next > '9' || prefix.size() >= 8)
                throw std::runtime_error("The browser emitted an invalid control frame.");
            prefix += next;
        }
        if (next != ':' || prefix.empty())
            throw std::runtime_error("The browser control connection was closed.");
        const auto size = std::stoul(prefix);
        if (!size || size > 8 * 1024 * 1024)
            throw std::runtime_error("The browser control frame exceeds its storage bound.");
        std::string body(size, '\0');
        size_t offset = 0;
        while (offset < body.size())
        {
            const auto read = recv(socket_, body.data() + offset, static_cast<int>(body.size() - offset), 0);
            if (read <= 0)
                throw std::runtime_error("The browser control connection was closed.");
            offset += read;
        }
        return nlohmann::json::parse(body);
    }
};

}
