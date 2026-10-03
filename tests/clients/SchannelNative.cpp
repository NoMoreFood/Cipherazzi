#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>
#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>
#include <schannel.h>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

int wmain(int count, wchar_t** arguments)
{
    if (count != 6) return 2;
    WSADATA sockets{};
    if (WSAStartup(MAKEWORD(2, 2), &sockets)) return 2;
    CredHandle credentials{};
    CtxtHandle context{};
    SecInvalidateHandle(&credentials);
    SecInvalidateHandle(&context);
    SOCKET socket = INVALID_SOCKET;
    auto cleanup = [&](void*)
    {
        if (SecIsValidHandle(&context)) DeleteSecurityContext(&context);
        if (SecIsValidHandle(&credentials)) FreeCredentialsHandle(&credentials);
        if (socket != INVALID_SOCKET) closesocket(socket);
        WSACleanup();
    };
    std::unique_ptr<void, decltype(cleanup)> guard(&credentials, cleanup);
    try
    {
        // Exercise public SSPI with an actual TCP or connected UDP socket and explicit validation policy.
        const std::wstring protocol(arguments[2]), host(arguments[4]);
        const bool datagram = protocol == L"DTLSv1.2";
        const auto family = host.find(':') == std::wstring::npos ? AF_INET : AF_INET6;
        socket = ::socket(family, datagram ? SOCK_DGRAM : SOCK_STREAM, datagram ? IPPROTO_UDP : IPPROTO_TCP);
        if (socket == INVALID_SOCKET) throw std::runtime_error("Socket creation failed");
        DWORD timeout = 10000;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        sockaddr_storage address{};
        address.ss_family = static_cast<ADDRESS_FAMILY>(family);
        if (family == AF_INET)
        {
            auto& target = reinterpret_cast<sockaddr_in&>(address);
            InetPtonW(family, host.c_str(), &target.sin_addr);
            target.sin_port = htons(static_cast<u_short>(std::stoul(arguments[1])));
        }
        else
        {
            auto& target = reinterpret_cast<sockaddr_in6&>(address);
            InetPtonW(family, host.c_str(), &target.sin6_addr);
            target.sin6_port = htons(static_cast<u_short>(std::stoul(arguments[1])));
        }
        if (connect(socket, reinterpret_cast<sockaddr*>(&address),
            family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)))
            throw std::runtime_error("Socket connection failed");
        TLS_PARAMETERS parameters{};
        const auto enabled = datagram ? SP_PROT_DTLS1_2_CLIENT :
            protocol == L"TLSv1.3" ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
        parameters.grbitDisabledProtocols = (SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT |
            SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT | SP_PROT_DTLS1_0_CLIENT | SP_PROT_DTLS1_2_CLIENT) & ~enabled;
        SCH_CREDENTIALS settings{};
        settings.dwVersion = SCH_CREDENTIALS_VERSION;
        settings.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO |
            (std::wstring_view(arguments[5]) == L"manual" ? SCH_CRED_MANUAL_CRED_VALIDATION :
                SCH_CRED_AUTO_CRED_VALIDATION);
        settings.cTlsParameters = 1;
        settings.pTlsParameters = &parameters;
        SCHANNEL_CRED datagramSettings{};
        datagramSettings.dwVersion = SCHANNEL_CRED_VERSION;
        datagramSettings.dwFlags = settings.dwFlags;
        datagramSettings.grbitEnabledProtocols = SP_PROT_DTLS1_2_CLIENT;
        TimeStamp expiry{};
        auto status = AcquireCredentialsHandleW(nullptr, const_cast<wchar_t*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
            nullptr, datagram ? static_cast<void*>(&datagramSettings) : &settings,
            nullptr, nullptr, &credentials, &expiry);
        if (status != SEC_E_OK) throw std::runtime_error("Credential acquisition failed: " + std::to_string(status));
        const ULONG requested = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
            ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | (datagram ? ISC_REQ_DATAGRAM : ISC_REQ_STREAM);
        std::vector<char> incoming(131072);
        size_t available{};
        bool started = false;
        SEC_DTLS_MTU mtu{1200};
        for (unsigned iteration = 0; iteration < 128; ++iteration)
        {
            SecBuffer input[]{{static_cast<ULONG>(available), SECBUFFER_TOKEN, incoming.data()},
                {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc inputDescriptor{SECBUFFER_VERSION, 2, input};
            SecBuffer mtuBuffer{sizeof(mtu), SECBUFFER_DTLS_MTU, &mtu};
            SecBufferDesc mtuDescriptor{SECBUFFER_VERSION, 1, &mtuBuffer};
            SecBuffer output{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc outputDescriptor{SECBUFFER_VERSION, 1, &output};
            ULONG returned{};
            status = InitializeSecurityContextW(&credentials, started ? &context : nullptr, arguments[3], requested,
                0, SECURITY_NATIVE_DREP, available ? &inputDescriptor : datagram && !started ? &mtuDescriptor : nullptr,
                0, &context, &outputDescriptor, &returned, &expiry);
            std::unique_ptr<void, decltype(&FreeContextBuffer)> token(output.pvBuffer, FreeContextBuffer);
            started = SecIsValidHandle(&context);
            for (ULONG offset = 0; offset < output.cbBuffer;)
            {
                const auto written = send(socket, static_cast<const char*>(output.pvBuffer) + offset,
                    static_cast<int>(output.cbBuffer - offset), 0);
                if (written <= 0) throw std::runtime_error("Handshake send failed");
                offset += written;
            }
            if (status == SEC_E_OK) break;
            if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_INCOMPLETE_MESSAGE &&
                status != SEC_I_MESSAGE_FRAGMENT)
                throw std::runtime_error("Handshake failed: " + std::to_string(status));
            if (status != SEC_E_INCOMPLETE_MESSAGE)
            {
                const auto extra = input[1].BufferType == SECBUFFER_EXTRA ? input[1].cbBuffer : 0;
                if (extra > available) throw std::runtime_error("Invalid handshake remainder");
                std::memmove(incoming.data(), incoming.data() + available - extra, extra);
                available = extra;
            }
            if (status == SEC_I_MESSAGE_FRAGMENT || (available && status != SEC_E_INCOMPLETE_MESSAGE)) continue;
            const auto received = recv(socket, incoming.data() + available,
                static_cast<int>(incoming.size() - available), 0);
            if (received <= 0) throw std::runtime_error("Handshake receive failed");
            available += received;
        }
        if (status != SEC_E_OK) throw std::runtime_error("Handshake did not complete");
        SecPkgContext_CipherInfo cipher{};
        cipher.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
        if (QueryContextAttributesW(&context, SECPKG_ATTR_CIPHER_INFO, &cipher) != SEC_E_OK)
            throw std::runtime_error("Connection metadata unavailable");
        int size = sizeof(address);
        if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &size))
            throw std::runtime_error("Local socket metadata unavailable");
        std::cout << "{\"protocol\":" << cipher.dwProtocol << ",\"cipher\":" << cipher.dwCipherSuite <<
            ",\"local_port\":" << ntohs(reinterpret_cast<sockaddr_in&>(address).sin_port) << "}\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
