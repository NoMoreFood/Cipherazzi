#include "Engine.h"
#include "Storage.h"

#include <sqlite3.h>

namespace Cipherazzi::Tests
{
using Buffer = std::vector<uint8_t>;
void require(bool result, const char* message);
int scalar(sqlite3* database, const char* sql);
Buffer hello(bool client, uint16_t version, bool retry, bool ech, Bytes additionalExtensions);
Buffer record(Bytes payload, uint8_t type);

void vpnCoverage()
{
    auto udp = [](Bytes payload, bool client, uint16_t port)
    {
        Buffer packet(28, 0);
        packet[0] = 0x45;
        const auto total = static_cast<uint16_t>(payload.size() + 28);
        packet[2] = static_cast<uint8_t>(total >> 8);
        packet[3] = static_cast<uint8_t>(total);
        packet[9] = 17;
        packet[12] = packet[16] = 10;
        packet[15] = client ? 1 : 2;
        packet[19] = client ? 2 : 1;
        const uint16_t source = client ? 42000 : port, destination = client ? port : 42000;
        packet[20] = static_cast<uint8_t>(source >> 8);
        packet[21] = static_cast<uint8_t>(source);
        packet[22] = static_cast<uint8_t>(destination >> 8);
        packet[23] = static_cast<uint8_t>(destination);
        const auto length = static_cast<uint16_t>(payload.size() + 8);
        packet[24] = static_cast<uint8_t>(length >> 8);
        packet[25] = static_cast<uint8_t>(length);
        packet.insert(packet.end(), payload.begin(), payload.end());
        return packet;
    };
    Counters counters;
    std::vector<Observation> observations;
    Engine engine(counters, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            observations.push_back(std::move(observation));
    });
    int64_t timestamp = nowUs();
    auto send = [&](Bytes payload, bool client, uint16_t port)
    {
        engine.packet(udp(payload, client, port), PacketKind::Ip, ++timestamp);
    };

    // Fixed WireGuard suites require complete handshake framing and matching response indices.
    Buffer initiation(148, 0x42), response(92, 0x43);
    initiation[0] = 1;
    response[0] = 2;
    std::fill_n(initiation.begin() + 1, 3, 0);
    std::fill_n(response.begin() + 1, 3, 0);
    std::fill_n(response.begin() + 8, 4, 0x42);
    send(initiation, true, 35001);
    const auto first = observations.back();
    response[8] = 0;
    const auto count = observations.size();
    send(response, false, 35001);
    require(observations.size() == count, "WireGuard accepted a response for another initiator");
    response[8] = 0x42;
    send(response, false, 35001);
    require(observations.back().state == "wireguard_response" &&
        first.vpn->fields["wireguard_message_type"] == 1,
        "WireGuard response matching or immutable evidence failed");
    const auto wg = observations.back();
    Buffer cookie(64, 0x44);
    cookie[0] = 3;
    std::fill_n(cookie.begin() + 1, 3, 0);
    std::fill_n(cookie.begin() + 4, 4, 0x42);
    send(cookie, false, 35001);
    require(observations.back().state == "wireguard_cookie_reply",
        "A WireGuard cookie reply was reported as an initiation");
    initiation[4] = 0x41;
    send(initiation, true, 35001);
    require(observations.back().flowId != wg.flowId &&
        observations.back().state == "wireguard_initiation", "WireGuard socket reuse retained stale evidence");
    auto invalid = initiation;
    invalid[1] = 1;
    require(!parseVpn(invalid) && !parseVpn(Bytes(initiation).first(147)),
        "WireGuard accepted a reserved byte or truncated handshake");

    // IKEv2 proposals remain offers until a matching SA_INIT response selects their transforms.
    Buffer ike{1,2,3,4,5,6,7,8, 0,0,0,0,0,0,0,0, 33,0x20,34,8, 0,0,0,0, 0,0,1,0x70,
        34,0,0,40, 0,0,0,36,1,1,0,3,
        3,0,0,12,1,0,0,20, 0x80,14,1,0,
        3,0,0,8,2,0,0,5, 0,0,0,8,4,0,0,14,
        40,0,1,8,0,14,0,0};
    ike.insert(ike.end(), 256, 0x42);
    ike.insert(ike.end(), {0,0,0,36});
    ike.insert(ike.end(), 32, 0x43);
    require(ike.size() == 368 && parseVpn(ike).has_value(), "Valid IKEv2 SA_INIT was rejected");
    send(ike, true, 35002);
    CryptoCatalog catalog;
    const auto offered = catalog.summarize(observations.back(), [](const auto&, const auto&, Bytes) {});
    require(offered.encryption.empty() && nlohmann::json::parse(offered.json).contains("ike_offers"),
        "IKEv2 offers were reported as selected encryption");
    auto selected = ike;
    std::fill_n(selected.begin() + 8, 8, 0x44);
    selected[19] = 0x20;
    selected[47] = 12;
    const auto beforeResponse = observations.size();
    send(selected, false, 35002);
    require(observations.size() == beforeResponse, "IKEv2 accepted an unoffered response transform");
    selected[47] = 20;
    Buffer natt(4, 0);
    natt.insert(natt.end(), selected.begin(), selected.end());
    send(natt, false, 35002);
    require(observations.back().state == "ike_sa_selection", "NAT traversal IKEv2 response was not associated");
    const auto sa = observations.back();
    const auto ikeSummary = catalog.summarize(sa, [](const auto&, const auto&, Bytes) {});
    require(ikeSummary.keyBits == 256 && ikeSummary.encryption == "AES-GCM-16" &&
        ikeSummary.exchange == "MODP-2048", "IKEv2 selected transforms were not summarized");
    for (size_t length = 0; length < ike.size(); ++length)
        require(!parseVpn(Bytes(ike).first(length)), "A truncated IKEv2 payload was recognized");
    invalid = ike;
    invalid[35] = 35;
    require(!parseVpn(invalid), "An inconsistent IKEv2 proposal length was accepted");
    invalid = ike;
    invalid[73] = 19;
    require(!parseVpn(invalid), "An IKEv2 KE group absent from proposals was accepted");

    // OpenVPN reliability ordering and retransmission preserve the encapsulated ClientHello exactly once.
    auto control = [](Bytes bytes, uint32_t id, bool reset = false, uint8_t session = 0x42)
    {
        Buffer packet{static_cast<uint8_t>(reset ? 0x38 : 0x20)};
        packet.insert(packet.end(), 8, session);
        packet.push_back(0);
        packet.insert(packet.end(), {static_cast<uint8_t>(id >> 24), static_cast<uint8_t>(id >> 16),
            static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id)});
        packet.insert(packet.end(), bytes.begin(), bytes.end());
        return packet;
    };
    send(control({}, 0, true), true, 35003);
    const auto tls = record(hello(true, 0x0304, false, false, {}), 22);
    auto tcpFrame = [](Bytes payload)
    {
        Buffer framed{static_cast<uint8_t>(payload.size() >> 8), static_cast<uint8_t>(payload.size())};
        framed.insert(framed.end(), payload.begin(), payload.end());
        return framed;
    };
    Buffer tcpControl = tcpFrame(control({}, 0, true));
    const auto tcpHello = tcpFrame(control(tls, 1));
    tcpControl.insert(tcpControl.end(), tcpHello.begin(), tcpHello.end());
    Counters tcpHealth;
    std::vector<Observation> tcpObservations;
    Engine tcpEngine(tcpHealth, [&](Observation observation)
    {
        if (!observation.lifecycleOnly)
            tcpObservations.push_back(std::move(observation));
    });
    TcpPacket tcpPacket;
    tcpPacket.source.address[0] = tcpPacket.destination.address[0] = 10;
    tcpPacket.source.address[3] = 1;
    tcpPacket.destination.address[3] = 2;
    tcpPacket.source.port = 43000;
    tcpPacket.destination.port = 1194;
    tcpPacket.sequence = 100;
    tcpPacket.flags = 2;
    tcpEngine.tcp(tcpPacket, timestamp);
    tcpPacket.flags = 0x18;
    for (size_t offset = 0; offset < tcpControl.size(); ++offset)
    {
        tcpPacket.sequence = static_cast<uint32_t>(101 + offset);
        tcpPacket.payload = Bytes(tcpControl).subspan(offset, 1);
        tcpEngine.tcp(tcpPacket, timestamp + offset + 1);
    }
    tcpEngine.expire(timestamp + 1000000, true);
    require(!tcpObservations.empty() && tcpObservations.back().protocol == Observation::Protocol::OpenVpn &&
        tcpObservations.back().clientHello && !tcpObservations.back().udp && tcpHealth.bufferedBytes == 0 &&
        tcpHealth.malformed == 0, "OpenVPN TCP framing lost hello evidence or leaked flow memory");
    require(nlohmann::json::parse(catalog.summarize(tcpObservations.back(),
        [](const auto&, const auto&, Bytes) {}).json)["openvpn_tls"]["transport"] == "OpenVPN control over TCP",
        "OpenVPN TCP evidence was labeled UDP");
    send(control(Bytes(tls).subspan(13), 2), true, 35003);
    send(control(Bytes(tls).first(13), 1, false, 0x41), true, 35003);
    require(!observations.back().clientHello, "OpenVPN combined TLS bytes from different sessions");
    send(control(Bytes(tls).first(13), 1), true, 35003);
    send(control(tls, 1), true, 35003);
    const auto vpn = observations.back();
    const auto open = catalog.summarize(vpn, [](const auto&, const auto&, Bytes) {});
    require(vpn.state == "openvpn_tls_client_hello" && vpn.sni == "service.example.test" &&
        nlohmann::json::parse(open.json)["openvpn_tls"]["offered_ciphers"].get<std::string>().find("0x1301") !=
            std::string::npos &&
        vpn.crypto.stages.size() == 1, "OpenVPN control reassembly lost or duplicated its ClientHello");
    send(control({}, 0, true, 0x41), true, 35003);
    require(observations.back().flowId != vpn.flowId && !observations.back().clientHello,
        "OpenVPN socket reuse retained a previous session's TLS evidence");
    const auto parsed = parseVpn(control({}, 0, true));
    OpenVpnStream limited;
    auto distant = *parsed;
    distant.reset = false;
    distant.packetId = 100;
    distant.tls = tls;
    require(!limited.feed(distant, [](const Hello&) {}), "OpenVPN packet ordering escaped its bound");
    invalid = control({}, 0, true);
    invalid[9] = 33;
    require(!parseVpn(invalid), "OpenVPN accepted an oversized ACK array");
    engine.expire(timestamp + 1000000, true);
    require(counters.activeFlows == 0 && counters.bufferedBytes == 0 && counters.malformed == 0,
        "VPN expiration leaked memory or contaminated packet health counters");
    Counters budget;
    Engine bounded(budget, [](Observation) {}, {.bytes = 1});
    bounded.packet(udp(initiation, true, 35001), PacketKind::Ip, timestamp);
    require(budget.reassemblyLimit == 1 && budget.bufferedBytes == 0, "VPN evidence escaped the shared memory limit");

    // Persist VPN records without inventing TLS selections or claiming authenticated tunnels.
    const auto path = std::filesystem::temp_directory_path() /
        ("cipherazzi-vpn-" + std::to_string(GetCurrentProcessId()) + ".db");
    std::filesystem::remove(path);
    {
        Storage storage(path.string(), counters, "VPN controls", "Packet evidence", [](Observation&) {});
        storage.enqueue(wg);
        storage.enqueue(sa);
        storage.enqueue(vpn);
        storage.finish();
        sqlite3* reader = nullptr;
        require(sqlite3_open_v2(path.string().c_str(), &reader, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK,
            "Could not read VPN control storage");
        require(scalar(reader, "SELECT count(*) FROM connections WHERE tls_version IS NULL AND cipher_id IS NULL "
            "AND json_extract(crypto_json,'$.vpn_authentication')='Unverified'") == 3,
            "VPN storage assigned TLS selections or authenticated a tunnel");
        sqlite3_close(reader);
    }
    std::filesystem::remove(path);
}
}
