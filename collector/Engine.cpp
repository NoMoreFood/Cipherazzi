#include "Engine.h"
#include "Auth.h"

#include <algorithm>
#include <bit>

namespace Cipherazzi
{
std::optional<TcpPacket> decodePacket(Bytes packet, PacketKind kind, Counters& counters, PacketOrigin origin)
{
    const bool captureLimit = origin == PacketOrigin::PacketMonitor && packet.size() >= PacketMonitorCaptureLimit;
    // Strip link headers without trusting lengths supplied by the capture source.
    if (kind == PacketKind::Ethernet)
    {
        if (packet.size() < 14)
        {
            ++counters.malformed;
            return {};
        }
        auto protocol = be16(packet, 12);
        packet = packet.subspan(14);
        for (int vlan = 0; vlan < 2 && (protocol == 0x8100 || protocol == 0x88a8); ++vlan)
        {
            if (packet.size() < 4)
            {
                ++counters.malformed;
                return {};
            }
            protocol = be16(packet, 2);
            packet = packet.subspan(4);
        }
        if (protocol != 0x0800 && protocol != 0x86dd)
        {
            ++counters.unsupported;
            return {};
        }
    }
    else if (kind != PacketKind::Ip)
    {
        ++counters.unsupported;
        return {};
    }
    if (packet.empty())
    {
        ++counters.malformed;
        return {};
    }

    TcpPacket result;
    size_t offset = 0;
    size_t total = 0;
    uint8_t protocol = 0;
    bool offloadLength = false;
    const auto family = packet[0] >> 4;
    if (family == 4 && packet.size() >= 20)
    {
        offset = (packet[0] & 15) * 4;
        total = be16(packet, 2);

        // Packet Monitor exposes LSOv2 buffers before the NIC assigns their IP lengths.
        if (!total && origin == PacketOrigin::PacketMonitor)
        {
            total = packet.size();
            offloadLength = true;
        }
        if (offset < 20 || offset > packet.size() || total < offset)
        {
            ++counters.malformed;
            return {};
        }
        if (be16(packet, 6) & 0x3fff)
        {
            ++counters.fragments;
            return {};
        }
        protocol = packet[9];
        std::copy_n(packet.begin() + 12, 4, result.source.address.begin());
        std::copy_n(packet.begin() + 16, 4, result.destination.address.begin());
    }
    else if (family == 6 && packet.size() >= 40)
    {
        result.source.family = result.destination.family = 6;
        std::copy_n(packet.begin() + 8, 16, result.source.address.begin());
        std::copy_n(packet.begin() + 24, 16, result.destination.address.begin());
        total = 40ULL + be16(packet, 4);
        offset = 40;
        protocol = packet[6];

        // Walk bounded IPv6 extension chains, accepting atomic fragments only.
        for (int extension = 0; protocol != 6 && protocol != 17 && extension < 8; ++extension)
        {
            if (protocol != 0 && protocol != 43 && protocol != 60 && protocol != 44 && protocol != 51)
                break;
            if (offset + 8 > std::min(total, packet.size()))
            {
                ++counters.malformed;
                return {};
            }
            if (protocol == 44 && (be16(packet, offset + 2) & 0xfff9))
            {
                ++counters.fragments;
                return {};
            }
            const size_t length = protocol == 44 ? 8 : protocol == 51 ?
                (packet[offset + 1] + 2ULL) * 4 : (packet[offset + 1] + 1ULL) * 8;
            protocol = packet[offset];
            offset += length;
        }
    }
    else
    {
        ++counters.malformed;
        return {};
    }
    if (protocol != 6 && protocol != 17)
    {
        ++counters.unsupported;
        return {};
    }

    // Captured TCP prefixes remain useful; sequence numbers preserve gaps beyond the capture limit.
    result.truncated = total > packet.size() || (offloadLength && captureLimit);
    if (result.truncated)
        ++counters.truncated;
    packet = packet.first(std::min(total, packet.size()));
    if (protocol == 17)
    {
        if (offloadLength || offset + 8 > packet.size())
        {
            ++counters.malformed;
            return {};
        }
        const size_t length = be16(packet, offset + 4);
        if (length < 8 || length > total - offset)
        {
            ++counters.malformed;
            return {};
        }
        if (length > packet.size() - offset)
        {
            if (!result.truncated)
                ++counters.truncated;
            return {};
        }
        result.protocol = 17;
        result.source.port = be16(packet, offset);
        result.destination.port = be16(packet, offset + 2);
        result.payload = packet.subspan(offset + 8, length - 8);
        return result;
    }
    if (offset + 20 > packet.size())
    {
        ++counters.malformed;
        return {};
    }

    // Offload can make checksums appear invalid at this capture layer.
    const size_t header = (packet[offset + 12] >> 4) * 4;
    if (header < 20 || offset + header > packet.size())
    {
        ++counters.malformed;
        return {};
    }
    if (offloadLength && ((packet[offset + 13] & 0x26) || be16(packet, offset + 18)))
    {
        ++counters.malformed;
        return {};
    }
    result.source.port = be16(packet, offset);
    result.destination.port = be16(packet, offset + 2);
    result.sequence = be32(packet, offset + 4);
    result.flags = packet[offset + 13];
    result.payload = packet.subspan(offset + header);
    return result;
}

void TcpStream::begin(uint32_t sequence)
{
    if (!initialized_)
    {
        next_ = sequence;
        initialized_ = true;
    }
}

bool TcpStream::feed(uint32_t sequence, Bytes bytes, const Sink& sink)
{
    if (bytes.empty())
        return true;
    begin(sequence);
    auto distance = std::bit_cast<int32_t>(sequence - next_);
    if (distance > 0)
    {
        // Keep a small sparse window; retransmissions do not consume additional entries.
        if (distance > 262144 || pending_.size() >= 64 || memory() + bytes.size() > 524288)
        {
            limited_ = true;
            return false;
        }
        for (auto& segment : pending_)
        {
            if (segment.sequence == sequence)
            {
                if (segment.bytes.size() < bytes.size())
                    segment.bytes.assign(bytes.begin(), bytes.end());
                return true;
            }
        }
        pending_.push_back({sequence, {bytes.begin(), bytes.end()}});
        return true;
    }
    const auto overlap = static_cast<uint32_t>(next_ - sequence);
    if (overlap >= bytes.size())
        return true;
    bytes = bytes.subspan(overlap);
    if (!sink(bytes))
        return false;
    next_ += static_cast<uint32_t>(bytes.size());

    // Sequence differences remain signed across the TCP sequence-number wrap.
    while (!pending_.empty())
    {
        const auto found = std::ranges::min_element(pending_, [this](const Segment& a, const Segment& b)
        {
            return std::bit_cast<int32_t>(a.sequence - next_) < std::bit_cast<int32_t>(b.sequence - next_);
        });
        distance = std::bit_cast<int32_t>(found->sequence - next_);
        if (distance > 0)
            break;
        const auto skipped = static_cast<uint32_t>(next_ - found->sequence);
        if (skipped < found->bytes.size())
        {
            const Bytes remaining = Bytes(found->bytes).subspan(skipped);
            if (!sink(remaining))
                return false;
            next_ += static_cast<uint32_t>(remaining.size());
        }
        pending_.erase(found);
    }
    return true;
}

size_t TcpStream::memory() const
{
    size_t result = pending_.capacity() * sizeof(Segment);
    for (const auto& segment : pending_)
        result += segment.bytes.capacity();
    return result;
}

Engine::Engine(Counters& counters, Sink sink, EngineLimits limits) :
    counters_(counters), sink_(std::move(sink)), limits_(limits), fragments_(counters), roce_(counters)
{
    flows_.reserve(limits.flows);
}

void Engine::packet(Bytes bytes, PacketKind kind, int64_t timestampUs, PacketOrigin origin)
{
    ++counters_.packets;
    counters_.bytes.fetch_add(bytes.size(), std::memory_order_relaxed);
    if (timestampUs >= nextExpiry_)
        expire(timestampUs);

    // RoCE needs complete wire headers for its invariant CRC and a queue-pair key rather than a UDP flow key.
    auto inspectRoce = [&]
    {
        const auto retained = memory() - roce_.memory();
        const auto count = flowCount() - roce_.count();
        const bool consumed = roce_.feed(bytes, kind == PacketKind::Ethernet, timestampUs, nextId_,
            limits_.bytes > retained ? limits_.bytes - retained : 0,
            limits_.flows > count ? limits_.flows - count : 0, [&](Observation observation)
            {
                if (observation.lifecycleOnly)
                    sink_(std::move(observation));
                else
                    emit(observation);
            });
        if (consumed)
        {
            counters_.activeFlows.store(count + roce_.count(), std::memory_order_relaxed);
            counters_.bufferedBytes.store(retained + roce_.memory(), std::memory_order_relaxed);
        }
        return consumed;
    };
    if ((kind == PacketKind::Ethernet || kind == PacketKind::Ip) && inspectRoce())
        return;
    std::vector<uint8_t> assembled;
    const auto retained = memory() - fragments_.memory();
    if (fragments_.feed(bytes, kind == PacketKind::Ethernet, timestampUs,
        std::min(size_t{4 * 1024 * 1024}, limits_.bytes > retained ? limits_.bytes - retained : 0),
        limits_.flows, assembled))
    {
        counters_.bufferedBytes.store(retained + fragments_.memory(), std::memory_order_relaxed);
        if (assembled.empty())
            return;
        bytes = assembled;
        kind = PacketKind::Ip;
        if (inspectRoce())
            return;
    }
    if (const auto decoded = decodePacket(bytes, kind, counters_, origin))
    {
        if (decoded->protocol == 17)
            udp(*decoded, timestampUs);
        else
            tcp(*decoded, timestampUs);
    }
}

void Engine::emit(Observation& observation, std::string_view reason)
{
    if (observation.vpn)
    {
        const auto& fields = observation.vpn->fields;
        if (observation.protocol == Observation::Protocol::WireGuard)
            observation.state = fields.value("wireguard_message_type", 0) == 2 ? "wireguard_response" :
                fields.value("wireguard_message_type", 0) == 3 ? "wireguard_cookie_reply" : "wireguard_initiation";
        else if (observation.protocol == Observation::Protocol::Ike)
            observation.state = fields.contains("ike_selection") ? "ike_sa_selection" : "ike_sa_offers";
        else
            observation.state = observation.clientHello && observation.serverHello ? "openvpn_tls_hellos" :
                observation.clientHello ? "openvpn_tls_client_hello" : "openvpn_control";
    }
    else if (observation.protocol == Observation::Protocol::Ssh && (observation.ssh && observation.ssh->observed))
    {
        const auto& ssh = *observation.ssh;
        observation.state = !ssh.noCommon.empty() ? "ssh_no_common_algorithm" :
            ssh.peers[0].newKeys && ssh.peers[1].newKeys ? "ssh_newkeys_observed" :
            ssh.rolesKnown && !ssh.selected[0].empty() ? "ssh_kex_selection" :
            ssh.peers[0].kexInit || ssh.peers[1].kexInit ? "ssh_kex_offers" : "ssh_identification";
    }
    else if (observation.application && observation.protocol != Observation::Protocol::Tls)
    {
        // Keep observed protected SMB frames distinct from negotiation capabilities.
        const auto& fields = observation.application->fields;
        if (observation.protocol == Observation::Protocol::Smb)
            observation.state = fields.value("smb_encrypted_transform_observed", false) ? "smb_encrypted_transform" :
                fields.value("smb_rdma_signed_payload_observed", false) ? "smb_rdma_signed_payload" :
                fields.value("smb_compressed_transform_observed", false) ? "smb_compressed_transform" :
                fields.value("smb_signed_message_observed", false) ? "smb_signed_message" :
                fields.contains("smb_session_setup_status") ? "smb_authentication" : "smb_negotiation";
        else if (observation.protocol == Observation::Protocol::Kerberos)
            observation.state = fields.contains("krb_error") ? "kerberos_error" :
                fields.contains("krb_as_reply") || fields.contains("krb_tgs_reply") ||
                fields.contains("krb_password_reply") ? "kerberos_reply" : "kerberos_request";
        else
            observation.state = observation.protocol == Observation::Protocol::Rdp ? "rdp_negotiation" :
                fields.value("tds_prelogin_observed", false) ? "tds_prelogin" : "tds_framing";
    }
    else if (observation.protocol == Observation::Protocol::Unknown && observation.raw.possibleEncryption)
        observation.state = "possible_encryption";
    else
    {
        if (!observation.clientHello && !observation.serverHello && !observation.retrySeen)
            return;
        observation.state = observation.clientHello && observation.serverHello ? "hellos_observed" :
            observation.serverHello ? "server_hello_only" :
                observation.clientHello ? "client_hello_only" : "retry_only";
    }
    if (!reason.empty())
        observation.detail = reason;
    sink_(observation);
    ++counters_.observations;
}

void Engine::retire(Flow& flow, std::string_view reason)
{
    if (!flow.inspection)
        return;
    auto& inspection = *flow.inspection;
    if (!inspection.observation.clientHello && !inspection.observation.serverHello &&
        !inspection.observation.application && !inspection.observation.vpn &&
        !(inspection.observation.ssh && inspection.observation.ssh->observed))
        for (int direction = 0; direction < 2; ++direction)
            if (inspection.samples[direction])
                inspection.samples[direction]->classify(inspection.observation,
                    direction == inspection.sourceDirection ? 0 : 1);
    const auto retained = flow.inspection->memory();
    flow.observed = flow.observed || flow.inspection->observation.clientHello ||
        flow.inspection->observation.serverHello || flow.inspection->observation.retrySeen ||
        flow.inspection->observation.application || flow.inspection->observation.vpn ||
        (flow.inspection->observation.ssh && flow.inspection->observation.ssh->observed) ||
        flow.inspection->observation.raw.possibleEncryption;
    emit(flow.inspection->observation, reason);
    buffered_ -= retained;
    flow.inspection.reset();
}

void Engine::close(Flow& flow, std::string_view reason)
{
    retire(flow, flow.inspection && (!flow.inspection->observation.clientHello ||
        !flow.inspection->observation.serverHello) ? reason : std::string_view{});
    if (!flow.observed)
        return;
    Observation update;
    update.flowId = flow.id;
    update.lifecycleOnly = true;
    update.endedUs = flow.lastUs;
    update.closeReason = reason;
    sink_(std::move(update));
}

void Engine::tcp(const TcpPacket& packet, int64_t timestampUs)
{
    if (timestampUs >= nextExpiry_)
        expire(timestampUs);
    const auto key = FlowKey::make(packet.source, packet.destination);
    const int direction = packet.source == key.a ? 0 : 1;
    auto found = flows_.find(key);
    const bool syn = (packet.flags & 2) != 0;
    if (found != flows_.end() && syn && !(packet.flags & 16) &&
        (!found->second.syn[direction] || *found->second.syn[direction] != packet.sequence))
    {
        close(found->second, "Connection tuple reused");
        flows_.erase(found);
        found = flows_.end();
    }
    if (found == flows_.end())
    {
        if (!syn && packet.payload.empty())
            return;
        if (flowCount() >= limits_.flows)
        {
            ++counters_.flowLimit;
            return;
        }
        Flow flow;
        flow.inspection = std::make_unique<Inspection>();
        flow.id = flow.inspection->observation.flowId = ++nextId_;
        flow.inspection->observation.firstUs = timestampUs;
        buffered_ += flow.inspection->memory();
        found = flows_.emplace(key, std::move(flow)).first;
    }
    auto& flow = found->second;
    flow.lastUs = std::max(flow.lastUs, timestampUs);
    if (syn)
        flow.syn[direction] = packet.sequence;
    if (flow.inspection)
    {
        auto& inspection = *flow.inspection;
        auto& stream = inspection.streams[direction];
        auto& observation = inspection.observation;
        observation.lastUs = flow.lastUs;
        const auto previousBytes = inspection.memory();
        if (syn)
        {
            stream.begin(packet.sequence + 1);
            if (!(packet.flags & 16) || inspection.sourceDirection < 0)
            {
                inspection.sourceDirection = packet.flags & 16 ? 1 - direction : direction;
                observation.source = inspection.sourceDirection == 0 ? key.a : key.b;
                observation.destination = inspection.sourceDirection == 0 ? key.b : key.a;
                inspection.rolesKnown = true;
            }
        }
        if (inspection.sourceDirection < 0)
        {
            inspection.sourceDirection = direction;
            observation.source = packet.source;
            observation.destination = packet.destination;
        }
        bool updated = false;
        bool conflictingRoles = false;
        auto applyApplication = [&](int frameDirection, const FramedMessage& framed)
        {
            if (framed.fields.empty())
                return;

            // SMB Direct negotiation establishes initiator roles even when TCP setup was not captured.
            if (framed.fields.contains("smb_direct_client_negotiation") ||
                framed.fields.contains("smb_direct_server_negotiation"))
            {
                const int client = framed.fields.contains("smb_direct_client_negotiation") ?
                    frameDirection : 1 - frameDirection;
                if (inspection.rolesKnown && client != inspection.sourceDirection)
                {
                    conflictingRoles = true;
                    return;
                }
                inspection.sourceDirection = client;
                inspection.rolesKnown = true;
                observation.source = client == 0 ? key.a : key.b;
                observation.destination = client == 0 ? key.b : key.a;
            }
            auto evidence = std::make_shared<VpnEvidence>();
            if (observation.application)
                evidence->fields = observation.application->fields;
            auto fields = framed.fields;
            if (fields.contains("tds_prelogin"))
            {
                const bool source = frameDirection == inspection.sourceDirection;
                if (!inspection.rolesKnown)
                {
                    fields["tds_prelogin"]["socket_address"] = (frameDirection == 0 ? key.a : key.b).text();
                    fields["tds_prelogin"]["socket_port"] = (frameDirection == 0 ? key.a : key.b).port;
                }
                fields[inspection.rolesKnown ? source ? "tds_client_prelogin" : "tds_server_prelogin" :
                    frameDirection == 0 ? "tds_peer_a_prelogin" : "tds_peer_b_prelogin"] = fields["tds_prelogin"];
                fields["tds_roles_known"] = inspection.rolesKnown;
                fields.erase("tds_prelogin");
            }
            evidence->fields.update(fields);
            resolveNegotiation(evidence->fields);
            if (!observation.application || observation.application->fields != evidence->fields)
            {
                evidence->retainedBytes = evidence->fields.dump().size() * 3 + 1024;
                observation.application = std::move(evidence);
                if (!observation.clientHello && !observation.serverHello)
                    observation.protocol = framed.kind == FramedMessage::Kind::Smb ?
                        Observation::Protocol::Smb : framed.kind == FramedMessage::Kind::Rdp ?
                        Observation::Protocol::Rdp : framed.kind == FramedMessage::Kind::Kerberos ?
                        Observation::Protocol::Kerberos : Observation::Protocol::Tds;
                updated = true;
            }
        };
        bool valid = stream.feed(packet.sequence + (syn ? 1 : 0), packet.payload, [&](Bytes bytes)
        {
            // Reassembly delivers each byte once to the protocol parsers and optional bounded sample.
            if (limits_.raw && !observation.clientHello && !observation.serverHello &&
                !observation.application && !observation.vpn &&
                !(observation.ssh && observation.ssh->observed))
            {
                if (!inspection.samples[direction])
                    inspection.samples[direction] = std::make_unique<PayloadSample>();
                inspection.samples[direction]->feed(bytes);
            }
            if (!observation.clientHello && !observation.serverHello)
            {
                if (!inspection.ssh[direction].feed(bytes, [&](const SshMessage& message)
                {
                    applySsh(observation, direction == inspection.sourceDirection ? 0 : 1, message);
                    observation.ssh->rolesKnown = inspection.rolesKnown;
                    updated = true;
                }))
                    return false;
                if ((observation.ssh && observation.ssh->observed))
                    return true;
            }
            return inspection.framing[direction].feed(bytes, [&](const FramedMessage& framed)
            {
                if (framed.kind == FramedMessage::Kind::OpenVpn)
                {
                    auto parsed = parseVpn(framed.payload);
                    if (!parsed || !inspection.rolesKnown)
                        return true;
                    const bool client = direction == inspection.sourceDirection;
                    if (parsed->reset && parsed->client != client)
                        return false;
                    const auto own = client ? "openvpn_client_session_id" : "openvpn_server_session_id";
                    const auto peer = client ? "openvpn_server_session_id" : "openvpn_client_session_id";
                    if (observation.vpn)
                    {
                        const auto& fields = observation.vpn->fields;
                        if ((fields.contains(own) && fields[own] != parsed->fields["openvpn_session_id"]) ||
                            (fields.contains(peer) && parsed->fields.contains("openvpn_remote_session_id") &&
                                fields[peer] != parsed->fields["openvpn_remote_session_id"]) ||
                            fields["openvpn_key_id"] != parsed->fields["openvpn_key_id"])
                            return false;
                    }
                    parsed->fields[own] = parsed->fields["openvpn_session_id"];
                    applyVpn(observation, *parsed);
                    if (!inspection.vpnStreams)
                        inspection.vpnStreams = std::make_unique<std::array<OpenVpnStream, 2>>();
                    updated = true;
                    return (*inspection.vpnStreams)[direction].feed(*parsed, [&](const Hello& hello)
                    {
                        if ((hello.type == 1 || hello.type == 2) && hello.client == client)
                            applyHello(observation, hello, timestampUs);
                        for (auto& vpnStream : *inspection.vpnStreams)
                            vpnStream.selectVersion(observation.version);
                    });
                }
                applyApplication(direction, framed);
                if (framed.kind == FramedMessage::Kind::Smb || framed.kind == FramedMessage::Kind::Rdp ||
                    framed.kind == FramedMessage::Kind::Kerberos)
                    return true;
                return inspection.tls[direction].feed(framed.payload, [&](const Hello& hello)
            {
                auto& crypto = observation.crypto;
                if (hello.type != 1 && hello.type != 2)
                {
                    if (!observation.clientHello && !observation.serverHello)
                        return;
                    const bool client = packet.source == observation.source;
                    if (hello.type == 254)
                    {
                        crypto.alertCode = hello.crypto.alertCode;
                        crypto.alertLevel = hello.crypto.alertLevel;
                        crypto.alertUs = timestampUs;
                        crypto.alertSide = client ? "Client" : "Server";
                    }
                    else if (hello.type == 253)
                        (client ? crypto.clientCleartextEnded : crypto.serverCleartextEnded) = true;
                    else if (observation.version < 0x0304)
                    {
                        if (hello.type == 11)
                        {
                            (client ? crypto.clientCertificates : crypto.serverCertificates) =
                                hello.crypto.serverCertificates;
                            if (client)
                                crypto.clientCertificatePresented = hello.crypto.serverCertificates.empty() ? 0 : 1;
                        }
                        else if (hello.type == 12 && !client)
                        {
                            if (!parseKeyExchange(hello.body, observation.version, observation.cipher, crypto))
                                conflictingRoles = true;
                        }
                        else if (hello.type == 13 && !client)
                            crypto.certificateRequested = 1;
                        else if (hello.type == 14 && !client && crypto.certificateRequested < 0)
                            crypto.certificateRequested = 0;
                        else if (hello.type == 15 && client && observation.version == 0x0303)
                        {
                            if (hello.body.size() < 4 || be16(hello.body, 2) != hello.body.size() - 4)
                                conflictingRoles = true;
                            else
                                crypto.clientSignature = signatureName(be16(hello.body, 0));
                        }
                    }
                    updated = true;
                    return;
                }
                const auto source = hello.client ? packet.source : packet.destination;
                const auto destination = hello.client ? packet.destination : packet.source;
                if ((observation.clientHello || observation.serverHello || observation.retrySeen) &&
                    observation.source != source)
                {
                    conflictingRoles = true;
                    return;
                }
                observation.source = source;
                observation.destination = destination;
                observation.protocol = Observation::Protocol::Tls;

                applyHello(observation, hello, timestampUs);
                for (auto& directionStream : inspection.tls)
                {
                    directionStream.expectTls();
                    if (!hello.client)
                        directionStream.selectVersion(hello.version);
                }
                updated = true;
            });
            });
        });
        // Both MPA declarations determine framing; drain bytes held while the peer declaration was pending.
        if (valid && inspection.framing[0].mpaFlags() && inspection.framing[1].mpaFlags())
        {
            for (int peer = 0; peer < 2; ++peer)
                inspection.framing[peer].configureMpa(*inspection.framing[1 - peer].mpaFlags());
            for (int peer = 0; peer < 2 && valid; ++peer)
                valid = inspection.framing[peer].feed({}, [&](const FramedMessage& framed)
                    { applyApplication(peer, framed); return true; });
        }
        buffered_ = buffered_ - previousBytes + inspection.memory();
        if (!valid || conflictingRoles ||
            memory() > limits_.bytes)
        {
            const bool framingLimited = inspection.framing[0].limited() || inspection.framing[1].limited();
            const bool malformed = inspection.tls[direction].malformed() || conflictingRoles ||
                (!valid && !framingLimited && !stream.limited() && observation.application) ||
                ((observation.ssh && observation.ssh->observed) &&
                    !inspection.ssh[direction].limited() && !stream.limited());

            // A stream whose scanned prefix held no handshake ends inspection without evidence being lost.
            const bool unrecognized = !malformed && memory() <= limits_.bytes &&
                inspection.tls[direction].unmatched() && !observation.clientHello && !observation.serverHello &&
                !observation.retrySeen && !observation.application && !observation.vpn &&
                !(observation.ssh && observation.ssh->observed);
            if (malformed)
                ++counters_.malformed;
            else if (!unrecognized)
                ++counters_.reassemblyLimit;
            retire(flow, malformed ? "Malformed handshake" :
                unrecognized ? "No handshake in the inspected data" : "Reassembly or inspection limit reached");
        }
        else if ((observation.application &&
            (observation.application->fields.value("smb_encrypted_transform_observed", false) ||
                observation.application->fields.contains("rdp_failure_code"))) ||
            (inspection.framing[0].finished() && inspection.framing[1].finished()) ||
            (observation.clientHello && observation.serverHello && observation.version >= 0x0304) ||
            ((observation.ssh && observation.ssh->observed) ?
                inspection.ssh[0].finished() && inspection.ssh[1].finished() :
                inspection.tls[0].finished() && inspection.tls[1].finished()))
        {
            retire(flow, {});
        }
        else if (updated)
        {
            flow.observed = observation.clientHello || observation.serverHello || observation.retrySeen ||
                observation.application || observation.vpn ||
                (observation.ssh && observation.ssh->observed);
            const auto beforeEmit = inspection.memory();
            emit(observation);
            buffered_ = buffered_ - beforeEmit + inspection.memory();
        }
    }
    if (packet.flags & 1)
        flow.fin[direction] = true;
    if ((packet.flags & 4) || (flow.fin[0] && flow.fin[1]))
    {
        close(flow, packet.flags & 4 ? "TCP reset observed" : "TCP close observed");
        flows_.erase(found);
    }
    counters_.activeFlows.store(flowCount(), std::memory_order_relaxed);
    counters_.bufferedBytes.store(memory(),
        std::memory_order_relaxed);
}

void Engine::udp(const TcpPacket& packet, int64_t timestampUs)
{
    if (timestampUs >= nextExpiry_)
        expire(timestampUs);
    if (observeQuic(packet, timestampUs) || inspectDtls(packet, timestampUs) ||
        inspectVpn(packet, timestampUs) || inspectKerberos(packet, timestampUs))
    {
        counters_.activeFlows.store(flowCount(), std::memory_order_relaxed);
        counters_.bufferedBytes.store(memory(),
            std::memory_order_relaxed);
        return;
    }
    const auto key = FlowKey::make(packet.source, packet.destination);
    auto bytes = packet.payload;
    for (size_t coalesced = 0; !bytes.empty() && coalesced < 32; ++coalesced)
    {
        const auto header = quicHeader(bytes);
        if (!header)
        {
            if (!coalesced && limits_.raw && !quic_.contains(key))
                sampleUdp(packet, timestampUs);
            if ((bytes[0] & 0x80) && bytes.size() >= 7)
            {
                const auto version = be32(bytes, 1);
                if (version == 1 || version == 0x6b3343cf)
                    ++counters_.malformed;
                else
                    ++counters_.unsupported;
            }
            break;
        }
        bytes = bytes.subspan(header->packet.size());
        if (!header->initial() && !header->retry())
            continue;
        const auto dcid = cidText(header->destinationId);
        const auto scid = cidText(header->sourceId);
        auto found = quic_.find(key);
        QuicFlow* flow = nullptr;
        bool client = true;
        if (found != quic_.end())
        {
            for (const auto& candidate : found->second)
            {
                const auto& o = candidate->observation;
                if (header->version != o.quicVersion)
                    continue;
                client = packet.source == o.source;
                if ((client && !header->retry() && scid == o.quicClientId &&
                    (dcid == o.quicOriginalId || dcid == o.quicServerId || dcid == o.quicRetryId)) ||
                    (!client && dcid == o.quicClientId &&
                        (header->retry() || !candidate->serverInitialSeen || scid == o.quicServerId)))
                {
                    flow = candidate.get();
                    break;
                }
            }
        }
        if (!flow)
        {
            auto* candidate = findQuic(header->destinationId, client);
            if (candidate && candidate->observation.quicVersion == header->version &&
                (header->retry() || (client ? scid == candidate->observation.quicClientId :
                    !candidate->serverInitialSeen || scid == candidate->observation.quicServerId)))
                flow = candidate;
        }
        std::unique_ptr<QuicFlow> created;
        if (!flow)
        {
            if (!header->initial())
                continue;
            if (flowCount() >= limits_.flows ||
                (found != quic_.end() && found->second.size() >= 16))
            {
                ++counters_.flowLimit;
                continue;
            }
            if (memory() + 16384 > limits_.bytes)
            {
                ++counters_.reassemblyLimit;
                continue;
            }
            created = std::make_unique<QuicFlow>();
            flow = created.get();
            auto& o = flow->observation;
            o.quic = true;
            o.quicVersion = header->version;
            o.quicOriginalId = dcid;
            o.quicClientId = scid;
            o.source = packet.source;
            o.destination = packet.destination;
            o.firstUs = timestampUs;
            flow->inspection = std::make_unique<QuicConnection>(header->destinationId, header->version);
            client = true;
        }
        auto& o = flow->observation;
        if (!flow->inspection)
        {
            quicPath(*flow, packet, client, timestampUs);
            continue;
        }
        const auto previousBytes = flow->memory();
        if (header->retry())
        {
            if (!flow->inspection->retry(*header))
            {
                ++counters_.malformed;
                continue;
            }
            if (o.quicRetry)
                continue;
            o.quicRetry = true;
            o.quicRetryUs = timestampUs;
            o.quicRetryId = scid;
            flow->serverInitialSeen = false;
        }
        else
        {
            bool updated = false, invalid = false;
            const bool valid = flow->inspection->feed(*header, client, [&](const Hello& hello)
            {
                if ((hello.type != 1 && hello.type != 2) || hello.client != client ||
                    (!hello.client && hello.version != 0x0304))
                {
                    invalid = true;
                    return;
                }
                applyHello(o, hello, timestampUs);
                updated = true;
            });
            if (!valid || invalid)
            {
                if (flow->inspection->limited())
                    ++counters_.reassemblyLimit;
                else
                    ++counters_.malformed;
                if (created)
                    continue;
            }
            else if (!client)
            {
                o.quicServerId = scid;
                flow->serverInitialSeen = true;
            }
            if (created)
            {
                o.flowId = ++nextId_;
                quic_[key].push_back(std::move(created));
                ++quicFlows_;
            }
            else
                quicBytes_ -= previousBytes;
            flow->lastUs = o.lastUs = std::max(o.lastUs, timestampUs);
            flow->observed |= updated;
            if (updated)
                emit(o);
            if (flow->inspection->closed())
            {
                o.detail = "QUIC Initial CONNECTION_CLOSE: " + std::to_string(flow->inspection->closeError());
                emit(o);
                flow->inspection.reset();
            }
            else if ((o.clientHello && o.serverHello) || invalid || flow->inspection->limited() ||
                memory() + flow->memory() > limits_.bytes)
            {
                if (!o.serverHello)
                    emit(o, invalid ? "Invalid QUIC Initial handshake" : "QUIC inspection limit reached");
                flow->inspection.reset();
            }
            quicBytes_ += flow->memory();
            indexQuic(*flow);
            quicPath(*flow, packet, client, timestampUs);
            continue;
        }
        flow->lastUs = o.lastUs = std::max(o.lastUs, timestampUs);
        emit(o);
        quicBytes_ = quicBytes_ - previousBytes + flow->memory();
        indexQuic(*flow);
        quicPath(*flow, packet, client, timestampUs);
    }
    counters_.activeFlows.store(flowCount(), std::memory_order_relaxed);
    counters_.bufferedBytes.store(memory(),
        std::memory_order_relaxed);
}

bool Engine::inspectKerberos(const TcpPacket& packet, int64_t timestampUs)
{
    // A KDC or change-password datagram contains one complete message, independent of the configured UDP port.
    const bool password = passwordMessageSize(packet.payload) == packet.payload.size();
    if (packet.truncated || packet.payload.empty() ||
        (!password && kerberosMessageSize(packet.payload) != packet.payload.size()))
        return false;
    auto evidence = std::make_shared<VpnEvidence>();
    if (!(password ? parsePasswordChange(packet.payload, evidence->fields) :
        parseKerberos(packet.payload, evidence->fields)))
    {
        ++counters_.malformed;
        return true;
    }
    evidence->retainedBytes = evidence->fields.dump().size() * 3 + 1024;

    // Preserve each datagram independently; encrypted reply nonces cannot establish request correlation.
    const bool client = evidence->fields.contains("krb_as_request") || evidence->fields.contains("krb_tgs_request") ||
        evidence->fields.contains("krb_password_request");
    Observation observation;
    observation.protocol = Observation::Protocol::Kerberos;
    observation.udp = true;
    observation.source = client ? packet.source : packet.destination;
    observation.destination = client ? packet.destination : packet.source;
    observation.firstUs = observation.lastUs = observation.endedUs = timestampUs;
    observation.closeReason = "UDP datagram observed; connection outcome unknown";
    observation.application = std::move(evidence);
    const bool flowLimit = flowCount() >= limits_.flows;
    if (flowLimit || memory() + observation.memory() > limits_.bytes)
    {
        ++(flowLimit ? counters_.flowLimit : counters_.reassemblyLimit);
        return true;
    }
    observation.flowId = ++nextId_;
    emit(observation);
    return true;
}

bool Engine::inspectVpn(const TcpPacket& packet, int64_t timestampUs)
{
    auto parsed = parseVpn(packet.payload);
    if (!parsed)
        return false;
    const auto key = FlowKey::make(packet.source, packet.destination);
    auto found = raw_.find(key);
    if ((found == raw_.end() || !found->second.observation.vpn) &&
        parsed->protocol == Observation::Protocol::OpenVpn && !parsed->reset &&
        (parsed->tls.size() < 6 || parsed->tls[0] != 22 || parsed->tls[1] != 3))
        return false;
    if (found != raw_.end())
    {
        const auto& previous = found->second.observation;
        const nlohmann::json empty;
        const auto& fields = previous.vpn ? previous.vpn->fields : empty;
        const bool replacement = !previous.vpn || (parsed->client && (previous.protocol != parsed->protocol ||
            (parsed->protocol == Observation::Protocol::Ike &&
                fields["ike_initiator_spi"] != parsed->fields["ike_initiator_spi"]) ||
            (parsed->protocol == Observation::Protocol::WireGuard &&
                fields.contains("wireguard_initiator_index") &&
                fields["wireguard_initiator_index"] != parsed->fields["wireguard_sender_index"]) ||
            (parsed->protocol == Observation::Protocol::OpenVpn && parsed->reset &&
                fields.contains("openvpn_client_session_id") &&
                fields["openvpn_client_session_id"] != parsed->fields["openvpn_session_id"])));
        if (replacement)
        {
            if (found->second.observed)
            {
                Observation update;
                update.flowId = previous.flowId;
                update.lifecycleOnly = true;
                update.endedUs = found->second.lastUs;
                update.closeReason = "UDP session replaced; connection outcome unknown";
                sink_(std::move(update));
            }
            rawBytes_ -= found->second.memory();
            raw_.erase(found);
            found = raw_.end();
        }
    }
    if (found == raw_.end())
    {
        // Initial recognition requires a structured handshake, independent of UDP port assignments.
        RawFlow created;
        const bool flowLimit = flowCount() >= limits_.flows;
        if (flowLimit ||
            memory() + created.memory() > limits_.bytes)
        {
            ++(flowLimit ? counters_.flowLimit : counters_.reassemblyLimit);
            return true;
        }
        found = raw_.emplace(key, std::move(created)).first;
        auto& observation = found->second.observation;
        observation.flowId = ++nextId_;
        observation.udp = true;
        observation.firstUs = timestampUs;
        observation.source = parsed->client ? packet.source : packet.destination;
        observation.destination = parsed->client ? packet.destination : packet.source;
        rawBytes_ += found->second.memory();
    }
    auto& flow = found->second;
    auto& observation = flow.observation;
    const auto retained = flow.memory();
    if (!observation.vpn)
    {
        observation.raw = {};
        observation.source = parsed->client ? packet.source : packet.destination;
        observation.destination = parsed->client ? packet.destination : packet.source;
    }
    const int direction = packet.source == observation.source ? 0 : 1;
    if (observation.vpn && observation.protocol != parsed->protocol)
        return true;
    if ((parsed->protocol == Observation::Protocol::Ike || parsed->protocol == Observation::Protocol::WireGuard) &&
        parsed->client != (direction == 0))
        return true;
    if (observation.vpn && parsed->protocol == Observation::Protocol::Ike &&
        observation.vpn->fields.value("ike_initiator_spi", "") != parsed->fields.value("ike_initiator_spi", ""))
        return true;
    if (observation.vpn && parsed->protocol == Observation::Protocol::WireGuard && !parsed->client &&
        observation.vpn->fields.contains("wireguard_initiator_index") &&
        observation.vpn->fields["wireguard_initiator_index"] != parsed->fields["wireguard_receiver_index"])
        return true;
    if (observation.vpn && parsed->protocol == Observation::Protocol::Ike && !parsed->client &&
        observation.vpn->fields.contains("ike_offers"))
    {
        const auto& selection = parsed->fields["ike_selection"][0];
        const auto& offers = observation.vpn->fields["ike_offers"];
        const bool offered = std::any_of(offers.begin(), offers.end(), [&](const auto& proposal)
        {
            if (proposal["number"] != selection["number"])
                return false;
            const auto& transforms = proposal["transforms"];
            return std::all_of(selection["transforms"].begin(), selection["transforms"].end(),
                [&](const auto& transform)
            {
                return std::find(transforms.begin(), transforms.end(), transform) != transforms.end();
            });
        });
        if (!offered)
            return true;
    }
    if (parsed->protocol == Observation::Protocol::OpenVpn)
    {
        const auto own = direction == 0 ? "openvpn_client_session_id" : "openvpn_server_session_id";
        const auto peer = direction == 0 ? "openvpn_server_session_id" : "openvpn_client_session_id";
        if (observation.vpn)
        {
            const auto& fields = observation.vpn->fields;
            if ((fields.contains(own) && fields[own] != parsed->fields["openvpn_session_id"]) ||
                (fields.contains(peer) && parsed->fields.contains("openvpn_remote_session_id") &&
                    fields[peer] != parsed->fields["openvpn_remote_session_id"]) ||
                fields["openvpn_key_id"] != parsed->fields["openvpn_key_id"])
                return true;
        }
        parsed->fields[own] = parsed->fields["openvpn_session_id"];
    }

    // Retain immutable public metadata; control retransmissions are deduplicated before TLS reassembly.
    flow.lastUs = observation.lastUs = std::max(flow.lastUs, timestampUs);
    applyVpn(observation, *parsed);
    if (parsed->protocol == Observation::Protocol::OpenVpn)
    {
        if (!flow.vpnStreams)
            flow.vpnStreams = std::make_unique<std::array<OpenVpnStream, 2>>();
        if (!(*flow.vpnStreams)[direction].feed(*parsed, [&](const Hello& hello)
        {
            if (hello.client != (direction == 0))
                return;
            applyHello(observation, hello, timestampUs);
            for (auto& stream : *flow.vpnStreams)
                stream.selectVersion(observation.version);
        }))
        {
            ++counters_.reassemblyLimit;
            flow.vpnStreams.reset();
        }
    }
    emit(observation);
    const auto current = flow.memory();
    if (memory() - retained + current > limits_.bytes)
    {
        ++counters_.reassemblyLimit;
        rawBytes_ -= retained;
        raw_.erase(found);
        return true;
    }
    flow.observed = true;
    rawBytes_ = rawBytes_ - retained + current;
    return true;
}

void Engine::sampleUdp(const TcpPacket& packet, int64_t timestampUs)
{
    if (packet.payload.empty())
        return;
    const auto key = FlowKey::make(packet.source, packet.destination);
    auto found = raw_.find(key);
    if (found == raw_.end())
    {
        RawFlow created;
        created.observation.state = "possible_encryption";
        const bool flowLimit = flowCount() >= limits_.flows;
        if (flowLimit ||
            memory() + created.memory() > limits_.bytes)
        {
            ++(flowLimit ? counters_.flowLimit : counters_.reassemblyLimit);
            return;
        }
        found = raw_.emplace(key, std::move(created)).first;
        auto& flow = found->second;
        flow.observation.protocol = Observation::Protocol::Unknown;
        flow.observation.udp = true;
        flow.observation.flowId = ++nextId_;
        flow.observation.firstUs = timestampUs;
        flow.observation.source = packet.source;
        flow.observation.destination = packet.destination;
        rawBytes_ += flow.memory();
    }
    auto& flow = found->second;
    if (flow.observation.vpn)
        return;
    const auto retained = flow.memory();
    flow.lastUs = flow.observation.lastUs = std::max(flow.lastUs, timestampUs);
    const int direction = packet.source == flow.observation.source ? 0 : 1;
    auto& sample = flow.samples[direction];
    sample.feed(packet.payload);
    if (sample.complete() && sample.classify(flow.observation, direction))
    {
        emit(flow.observation);
        flow.observed = true;
    }
    rawBytes_ = rawBytes_ - retained + flow.memory();
}

void Engine::expire(int64_t timestampUs, bool all)
{
    // RDMA state shares the capture memory and flow budgets, including pending connection management.
    roce_.expire(timestampUs, all, limits_.idleUs, [&](Observation observation)
    {
        if (observation.lifecycleOnly)
            sink_(std::move(observation));
        else
            emit(observation);
    });
    for (auto it = flows_.begin(); it != flows_.end();)
    {
        if (all || timestampUs - it->second.lastUs > limits_.idleUs)
        {
            close(it->second, all ? "Capture ended; connection outcome unknown" : "Idle timeout; outcome unknown");
            it = flows_.erase(it);
        }
        else
        {
            if (it->second.inspection &&
                timestampUs - it->second.inspection->observation.firstUs > 30000000)
                retire(it->second, "Cleartext handshake inspection window ended");
            ++it;
        }
    }
    // Unknown UDP samples are bounded by the same flow budget and idle lifetime as protocol inspection.
    for (auto it = raw_.begin(); it != raw_.end();)
    {
        auto& flow = it->second;
        if (!all && timestampUs - flow.lastUs <= limits_.idleUs)
        {
            ++it;
            continue;
        }
        const auto retained = flow.memory();
        bool updated = false;
        if (!flow.observation.vpn)
            for (int direction = 0; direction < 2; ++direction)
                updated |= flow.samples[direction].classify(flow.observation, direction);
        if (updated)
        {
            emit(flow.observation);
            flow.observed = true;
        }
        if (flow.observed)
        {
            Observation update;
            update.flowId = flow.observation.flowId;
            update.lifecycleOnly = true;
            update.endedUs = flow.lastUs;
            update.closeReason = "UDP inspection ended; connection outcome unknown";
            sink_(std::move(update));
        }
        rawBytes_ -= retained;
        it = raw_.erase(it);
    }
    // Expire bounded datagram state independently of transport lifetime.
    fragments_.expire(timestampUs, all);
    for (auto it = dtls_.begin(); it != dtls_.end();)
    {
        auto& flow = it->second;
        if (!all && timestampUs - flow.lastUs <= limits_.idleUs)
        {
            if (flow.streams && timestampUs - flow.observation.firstUs > 30000000)
            {
                const auto retained = flow.memory();
                emit(flow.observation, "DTLS cleartext inspection window ended");
                flow.streams.reset();
                dtlsBytes_ = dtlsBytes_ - retained + flow.memory();
            }
            ++it;
            continue;
        }
        if (flow.observed)
        {
            emit(flow.observation);
            Observation update;
            update.flowId = flow.observation.flowId;
            update.lifecycleOnly = true;
            update.endedUs = flow.lastUs;
            update.closeReason = "DTLS observation window ended; connection outcome unknown";
            sink_(std::move(update));
        }
        dtlsBytes_ -= flow.memory();
        it = dtls_.erase(it);
    }
    // Retain visible QUIC paths until idle expiry; encrypted shutdown remains unknown.
    for (auto it = quic_.begin(); it != quic_.end();)
    {
        auto& entries = it->second;
        for (auto entry = entries.begin(); entry != entries.end();)
        {
            auto& flow = **entry;
            if (all || timestampUs - flow.lastUs > limits_.idleUs)
            {
                const auto retained = flow.memory();
                if (flow.inspection || flow.observed)
                    emit(flow.observation, flow.inspection ? "QUIC Initial inspection ended; outcome unknown" : "");
                if (flow.observed)
                {
                    Observation update;
                    update.flowId = flow.observation.flowId;
                    update.lifecycleOnly = true;
                    update.endedUs = flow.lastUs;
                    update.closeReason = "QUIC observation window ended; connection outcome unknown";
                    sink_(std::move(update));
                }
                indexQuic(flow, true);
                quicBytes_ -= retained;
                --quicFlows_;
                entry = entries.erase(entry);
            }
            else
            {
                if (flow.inspection && timestampUs - flow.observation.firstUs > 30000000)
                {
                    const auto previous = flow.memory();
                    emit(flow.observation, "QUIC Initial inspection window ended");
                    flow.inspection.reset();
                    quicBytes_ = quicBytes_ - previous + flow.memory();
                }
                ++entry;
            }
        }
        if (entries.empty())
            it = quic_.erase(it);
        else
            ++it;
    }
    nextExpiry_ = timestampUs + 1000000;
    counters_.activeFlows.store(flowCount(), std::memory_order_relaxed);
    counters_.bufferedBytes.store(memory(),
        std::memory_order_relaxed);
}
}
