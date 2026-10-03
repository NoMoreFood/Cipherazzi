#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/pool.h>
#endif
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

int runTlsClient(int argc, char** argv)
{
    if (argc != 5) return 1;
    WSADATA sockets{};
    if (WSAStartup(MAKEWORD(2, 2), &sockets)) return 1;

    // Authenticate a real TLS exchange using the test authority and public library APIs.
    const auto port = static_cast<unsigned short>(std::stoul(argv[1]));
    const auto version = static_cast<uint16_t>(std::stoul(argv[3]));
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!context || !SSL_CTX_set_min_proto_version(context.get(), version) ||
        !SSL_CTX_set_max_proto_version(context.get(), version) ||
        !SSL_CTX_load_verify_locations(context.get(), argv[2], nullptr)) return 1;
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    std::unique_ptr<SSL, decltype(&SSL_free)> session(SSL_new(context.get()), SSL_free);
    if (!session || !SSL_set1_host(session.get(), argv[4]) ||
        !SSL_set_tlsext_host_name(session.get(), argv[4])) return 1;
    const unsigned char protocols[]{2, 'h', '2'};
    if (SSL_set_alpn_protos(session.get(), protocols, sizeof(protocols))) return 1;
    const auto transport = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(port);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (transport == INVALID_SOCKET || connect(transport, reinterpret_cast<sockaddr*>(&peer), sizeof(peer)) ||
        !SSL_set_fd(session.get(), static_cast<int>(transport))) return 1;
    const auto connected = SSL_connect(session.get());
    if (connected != 1)
    {
        std::printf("TLS error %d\n", SSL_get_error(session.get(), connected));
        return 1;
    }

    // Exercise application traffic and independently query the public negotiation metadata.
    const char payload[] = "cipherazzi-private-application-data-sentinel";
    char reply[2]{};
    if (SSL_write(session.get(), payload, sizeof(payload) - 1) != sizeof(payload) - 1 ||
        SSL_read(session.get(), reply, sizeof(reply)) != sizeof(reply) || std::memcmp(reply, "ok", 2)) return 1;
    const auto cipher = SSL_get_current_cipher(session.get());
    const unsigned char* alpn{};
    unsigned int alpnLength{};
    SSL_get0_alpn_selected(session.get(), &alpn, &alpnLength);
    std::printf("TLS %d cipher %u role %d finished %d fd %d verified %ld resumed %d SNI %s ALPN %.*s\n",
        SSL_version(session.get()), SSL_CIPHER_get_protocol_id(cipher), SSL_is_server(session.get()),
        SSL_is_init_finished(session.get()), SSL_get_fd(session.get()), SSL_get_verify_result(session.get()),
        SSL_session_reused(session.get()), SSL_get_servername(session.get(), TLSEXT_NAMETYPE_host_name),
        alpnLength, alpn);
#ifdef OPENSSL_IS_BORINGSSL
    const auto chain = SSL_get0_peer_certificates(session.get());
    const auto leaf = chain && sk_CRYPTO_BUFFER_num(chain) ? sk_CRYPTO_BUFFER_value(chain, 0) : nullptr;
    std::printf("Group %u signature %u certificate %zu\n", SSL_get_group_id(session.get()),
        SSL_get_peer_signature_algorithm(session.get()),
        leaf && CRYPTO_BUFFER_data(leaf) ? CRYPTO_BUFFER_len(leaf) : 0);
#else
    const char* signature{};
    SSL_get0_peer_signature_name(session.get(), &signature);
    std::printf("Library %lu group %s signature %s certificate %d\n", OpenSSL_version_num(),
        SSL_get0_group_name(session.get()), signature,
        i2d_X509(SSL_get0_peer_certificate(session.get()), nullptr));
#endif
    int shutdown = SSL_shutdown(session.get());
    if (!shutdown) shutdown = SSL_shutdown(session.get());
    session.reset();
    closesocket(transport);
    WSACleanup();
    return shutdown == 1 ? 0 : 1;
}

#ifdef STATIC_TLS_DLL
extern "C" __declspec(dllexport) int RunTlsClient(int argc, char** argv)
{
    return runTlsClient(argc, argv);
}
#else
int main(int argc, char** argv)
{
    return runTlsClient(argc, argv);
}
#endif
