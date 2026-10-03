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
    std::fill_n(initiation.begin() + 1, 3, uint8_t{0});
    std::fill_n(response.begin() + 1, 3, uint8_t{0});
    std::fill_n(response.begin() + 8, 4, uint8_t{0x42});
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
    std::fill_n(cookie.begin() + 1, 3, uint8_t{0});
    std::fill_n(cookie.begin() + 4, 4, uint8_t{0x42});
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
    std::fill_n(selected.begin() + 8, 8, uint8_t{0x44});
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

    // IKEv1 phase-one SA transforms remain offers until the responder selects one from the same cookie pair.
    Buffer ike1{1,2,3,4,5,6,7,8, 0,0,0,0,0,0,0,0, 1,0x10,2,0, 0,0,0,0, 0,0,0,76,
        0,0,0,48, 0,0,0,1, 0,0,0,1,
        0,0,0,36, 1,1,0,1,
        0,0,0,28, 1,1,0,0,
        0x80,1,0,5, 0x80,2,0,2, 0x80,3,0,1, 0x80,4,0,2, 0x80,14,0,168};
    const auto parsedIke1 = parseVpn(ike1);
    require(ike1.size() == 76 && parsedIke1 && parsedIke1->protocol == Observation::Protocol::IkeV1,
        "Valid IKEv1 phase-one SA was rejected");
    send(ike1, true, 35004);
    const auto ike1Offer = catalog.summarize(observations.back(), [](const auto&, const auto&, Bytes) {});
    require(ike1Offer.encryption.empty() && observations.back().state == "ikev1_sa_offers",
        "IKEv1 proposals were treated as selected encryption");
    auto ike1Selected = ike1;
    std::fill_n(ike1Selected.begin() + 8, 8, uint8_t{0x55});
    ike1Selected[59] = 7;
    const auto beforeIke1Response = observations.size();
    send(ike1Selected, false, 35004);
    require(observations.size() == beforeIke1Response, "IKEv1 accepted an unoffered selection");
    ike1Selected[59] = 5;
    send(ike1Selected, false, 35004);
    const auto ike1Summary = catalog.summarize(observations.back(), [](const auto&, const auto&, Bytes) {});
    require(observations.back().state == "ikev1_sa_selection" && ike1Summary.encryption == "3DES_EDE" &&
        ike1Summary.exchange == "MODP-1024", "IKEv1 responder selection was not paired or summarized");

    // Main Mode reveals both key exchange and nonce payload sizes before protected authentication messages.
    auto ike1KeyExchange = ike1Selected;
    ike1KeyExchange.resize(28);
    ike1KeyExchange[16] = 4;
    ike1KeyExchange[27] = 180;
    ike1KeyExchange.insert(ike1KeyExchange.end(), {10,0,0,132});
    ike1KeyExchange.insert(ike1KeyExchange.end(), 128, 0x41);
    ike1KeyExchange.insert(ike1KeyExchange.end(), {0,0,0,20});
    ike1KeyExchange.insert(ike1KeyExchange.end(), 16, 0x42);
    require(ike1KeyExchange.size() == 180 && parseVpn(ike1KeyExchange) &&
        !parseVpn(ike1KeyExchange)->roleKnown, "IKEv1 Main Mode key exchange was not parsed");
    send(ike1KeyExchange, true, 35004);
    require(observations.back().state == "ikev1_key_exchange" &&
        observations.back().vpn->fields.value("ikev1_initiator_key_exchange_bytes", 0) == 128 &&
        observations.back().vpn->fields.value("ikev1_initiator_nonce_payload_bytes", 0) == 16,
        "IKEv1 initiator key exchange did not retain its direction");
    ike1KeyExchange[159] = 0x43;
    send(ike1KeyExchange, false, 35004);
    require(observations.back().vpn->fields.value("ikev1_responder_key_exchange_bytes", 0) == 128,
        "IKEv1 responder key exchange was treated as an initiator SA");
    auto ike1NatDiscovery = ike1KeyExchange;
    ike1NatDiscovery[27] = 228;
    ike1NatDiscovery[160] = 20;
    ike1NatDiscovery.insert(ike1NatDiscovery.end(), {20,0,0,24});
    ike1NatDiscovery.insert(ike1NatDiscovery.end(), 20, 0x71);
    ike1NatDiscovery.insert(ike1NatDiscovery.end(), {0,0,0,24});
    ike1NatDiscovery.insert(ike1NatDiscovery.end(), 20, 0x72);
    const auto parsedNatDiscovery = parseVpn(ike1NatDiscovery);
    require(parsedNatDiscovery && parsedNatDiscovery->fields.value("ikev1_nat_discovery_payloads", 0) == 2 &&
        parsedNatDiscovery->fields.value("ikev1_key_exchange_bytes", 0) == 128,
        "IKEv1 NAT discovery hid clear key exchange metadata");

    auto ike1Protected = ike1Selected;
    ike1Protected.resize(28);
    ike1Protected[16] = 5;
    ike1Protected[19] = 1;
    ike1Protected[27] = 44;
    ike1Protected.insert(ike1Protected.end(), 16, 0x63);
    send(ike1Protected, true, 35004);
    require(observations.back().state == "ikev1_protected_exchange" &&
        observations.back().vpn->fields.value("ikev1_initiator_encrypted_payload_observed", false) &&
        ike1Summary.encryption == "3DES_EDE", "IKEv1 protected phase-one header was lost");
    auto ike1Quick = ike1Protected;
    ike1Quick[16] = 8;
    ike1Quick[18] = 32;
    ike1Quick[23] = 1;
    send(ike1Quick, false, 35004);
    require(observations.back().state == "ikev1_quick_mode" &&
        observations.back().vpn->fields.value("ikev1_phase_two_exchange", "") == "Quick Mode" &&
        observations.back().vpn->fields.value("ikev1_exchange", "") == "Main Mode",
        "IKEv1 Quick Mode header replaced phase-one metadata");
    auto ike1CommittedQuick = ike1Quick;
    ike1CommittedQuick[19] = 3;
    require(parseVpn(ike1CommittedQuick).has_value(), "IKEv1 Quick Mode rejected a valid Commit flag");
    invalid = ike1Quick;
    invalid[19] = 0;
    require(!parseVpn(invalid), "IKEv1 accepted a clear Quick Mode packet as opaque ciphertext");
    invalid = ike1KeyExchange;
    std::fill_n(invalid.begin() + 8, 8, uint8_t{0});
    require(!parseVpn(invalid), "IKEv1 accepted a key exchange before receiving a responder cookie");

    // Aggressive Mode carries visible ID payload metadata and clear authentication payloads.
    auto ike1Aggressive = ike1;
    ike1Aggressive[18] = 4;
    ike1Aggressive[28] = 4;
    ike1Aggressive[27] = 244;
    ike1Aggressive.insert(ike1Aggressive.end(), {10,0,0,132});
    ike1Aggressive.insert(ike1Aggressive.end(), 128, 0x51);
    ike1Aggressive.insert(ike1Aggressive.end(), {5,0,0,20});
    ike1Aggressive.insert(ike1Aggressive.end(), 16, 0x52);
    ike1Aggressive.insert(ike1Aggressive.end(), {0,0,0,16, 2,0,0,0,
        'v','p','n','.','t','e','s','t'});
    require(ike1Aggressive.size() == 244 && parseVpn(ike1Aggressive),
        "Valid IKEv1 Aggressive Mode first packet was rejected");
    send(ike1Aggressive, true, 35006);
    require(observations.back().vpn->fields.value("ikev1_initiator_id_type_octet", 0) == 2 &&
        observations.back().vpn->fields.value("ikev1_initiator_identity_payload_bytes", 0) == 12,
        "IKEv1 clear ID payload metadata was lost");
    auto ike1PublicKey = ike1Aggressive;
    ike1PublicKey[67] = 4;
    send(ike1PublicKey, true, 35007);
    require(!observations.back().vpn->fields.contains("ikev1_initiator_id_type_octet") &&
        observations.back().vpn->fields.value("ikev1_initiator_identity_payload_bytes", 0) == 12,
        "IKEv1 interpreted a possibly encrypted public-key ID body as a clear identity");
    auto ike1AggressiveResponse = ike1Aggressive;
    std::fill_n(ike1AggressiveResponse.begin() + 8, 8, uint8_t{0x77});
    ike1AggressiveResponse[27] = 12;
    ike1AggressiveResponse[26] = 1;
    ike1AggressiveResponse[228] = 8;
    ike1AggressiveResponse.insert(ike1AggressiveResponse.end(), {0,0,0,24});
    ike1AggressiveResponse.insert(ike1AggressiveResponse.end(), 20, 0x54);
    send(ike1AggressiveResponse, false, 35006);
    require(observations.back().state == "ikev1_auth_payload" &&
        observations.back().vpn->fields.value("ikev1_responder_auth_payload_type", "") == "HASH",
        "IKEv1 Aggressive Mode responder authentication payload was not observed");
    auto ike1AggressiveFinal = ike1AggressiveResponse;
    ike1AggressiveFinal.resize(28);
    ike1AggressiveFinal[16] = 8;
    ike1AggressiveFinal[26] = 0;
    ike1AggressiveFinal[27] = 52;
    ike1AggressiveFinal.insert(ike1AggressiveFinal.end(), {0,0,0,24});
    ike1AggressiveFinal.insert(ike1AggressiveFinal.end(), 20, 0x55);
    send(ike1AggressiveFinal, true, 35006);
    require(observations.back().vpn->fields.value("ikev1_initiator_auth_payload_type", "") == "HASH" &&
        observations.back().vpn->fields.value("ikev1_responder_cookie", "") ==
            hex(Bytes(ike1AggressiveFinal).subspan(8, 8)),
        "IKEv1 Aggressive Mode final client payload lost its role or cookies");
    invalid = ike1;
    invalid[31] = 47;
    require(!parseVpn(invalid), "IKEv1 accepted an inconsistent SA length");

    // Phase-one attributes are matched by type and value, including equivalent short encodings.
    auto withIke1Attributes = [&](Bytes extra)
    {
        auto packet = ike1;
        packet.insert(packet.end(), extra.begin(), extra.end());
        for (const size_t offset : {size_t{27}, size_t{31}, size_t{43}, size_t{51}})
            packet[offset] += static_cast<uint8_t>(extra.size());
        return packet;
    };
    const Buffer offeredAttributes{0x80,11,0,1, 0,12,0,2, 0x0e,0x10};
    const Buffer selectedAttributes{0x80,12,0x0e,0x10, 0x80,11,0,1};
    auto orderedOffer = withIke1Attributes(offeredAttributes);
    auto reorderedSelection = withIke1Attributes(selectedAttributes);
    std::fill_n(reorderedSelection.begin() + 8, 8, uint8_t{0x66});
    const auto parsedOffer = parseVpn(orderedOffer), parsedSelection = parseVpn(reorderedSelection);
    require(parsedOffer && parsedSelection &&
        parsedOffer->fields["ikev1_offers"][0]["attribute_sha256"] ==
            parsedSelection->fields["ikev1_selection"][0]["attribute_sha256"],
        "Equivalent IKEv1 attribute encodings were not normalized");
    send(orderedOffer, true, 35005);
    const auto beforeReorderedSelection = observations.size();
    reorderedSelection[79] = 0x11;
    send(reorderedSelection, false, 35005);
    require(observations.size() == beforeReorderedSelection,
        "IKEv1 accepted a selection with changed optional attributes");
    reorderedSelection[79] = 0x10;
    send(reorderedSelection, false, 35005);
    require(observations.back().state == "ikev1_sa_selection" &&
        observations.back().vpn->fields.contains("ikev1_selection"),
        "IKEv1 missed a selection with reordered equivalent attributes");

    const Buffer fieldAndOrder{0x80,15,0,155, 0,16,0,4, 0,0,0,7};
    auto extendedIke1 = withIke1Attributes(fieldAndOrder);
    require(parseVpn(extendedIke1).has_value(), "IKEv1 field size or group order was rejected");
    std::fill_n(extendedIke1.begin() + 84, 4, uint8_t{0});
    require(!parseVpn(extendedIke1), "IKEv1 accepted a zero group order");

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
    TransportPacket tcpPacket;
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

    // The non-ESP marker precedes IKE alone: zeros before an OpenVPN reset do not make an OpenVPN packet.
    const Buffer reset{0x38, 1, 2, 3, 4, 5, 6, 7, 8, 2, 0, 0, 0, 1, 0, 0, 0, 0x20,
        9, 9, 9, 9, 9, 9, 9, 9, 0, 0, 0, 0};
    Buffer shifted(4, 0);
    shifted.insert(shifted.end(), reset.begin(), reset.end());
    require(parseVpn(reset).has_value() && !parseVpn(shifted), "A non-ESP marker shifted OpenVPN parsing");
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
