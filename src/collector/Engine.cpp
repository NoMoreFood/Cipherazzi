#include "Engine.h"
#include "Auth.h"

#include <algorithm>
#include <bit>

namespace Cipherazzi
{
Engine::Engine(Counters& counters, Sink sink, EngineLimits limits) :
    counters_(counters), sink_(std::move(sink)), limits_(limits), fragments_(counters), roce_(counters),
    ipsec_(counters)
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
        if (decoded->ipsecSpi)
            inspectIpsec(*decoded, timestampUs);
        if (decoded->protocol == 50 || decoded->protocol == 51)
            return;
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
        else if (observation.protocol == Observation::Protocol::IkeV1)
            observation.state = fields.value("ikev1_quick_mode_observed", false) ? "ikev1_quick_mode" :
                fields.value("ikev1_encrypted_payload_observed", false) ? "ikev1_protected_exchange" :
                fields.contains("ikev1_initiator_auth_payload_type") ||
                    fields.contains("ikev1_responder_auth_payload_type") ? "ikev1_auth_payload" :
                fields.contains("ikev1_initiator_key_exchange_bytes") ||
                    fields.contains("ikev1_responder_key_exchange_bytes") ? "ikev1_key_exchange" :
                fields.contains("ikev1_selection") ? "ikev1_sa_selection" : "ikev1_sa_offers";
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
                fields.contains("rpc_binds") ? "smb_rpc_bind" :
                fields.value("smb_rdma_signed_payload_observed", false) ? "smb_rdma_signed_payload" :
                fields.value("smb_compressed_transform_observed", false) ? "smb_compressed_transform" :
                fields.value("smb_signed_message_observed", false) ? "smb_signed_message" :
                fields.contains("smb_session_setup_status") ? "smb_authentication" : "smb_negotiation";
        else if (observation.protocol == Observation::Protocol::Kerberos)
            observation.state = fields.contains("krb_error") ? "kerberos_error" :
                fields.contains("krb_as_reply") || fields.contains("krb_tgs_reply") ||
                fields.contains("krb_password_reply") ? "kerberos_reply" : "kerberos_request";
        else if (observation.protocol == Observation::Protocol::Ldap)
            observation.state = fields.contains("ldap_bind_response") ? "ldap_bind_response" :
                fields.contains("ldap_bind_request") ? "ldap_bind_request" :
                fields.contains("ldap_datagram_observed") ? "ldap_datagram" : "ldap_starttls";
        else if (observation.protocol == Observation::Protocol::Ipsec)
            observation.state = "ipsec_headers_observed";
        else if (observation.protocol == Observation::Protocol::Http)
            observation.state = fields.value("http_tunnel_established", false) ? "http_tunnel"
                : fields.contains("http_basic_auth_observed") || fields.contains("http_basic_challenge_observed") ||
                    fields.contains("http_ntlm_auth_observed") || fields.contains("http_ntlm_challenge_observed") ||
                    fields.contains("http_negotiate_auth_observed") ||
                    fields.contains("http_negotiate_challenge_observed")
                ? "http_authentication"
                : "http_observed";
        else if (observation.protocol == Observation::Protocol::PostgreSql ||
            observation.protocol == Observation::Protocol::MySql)
            observation.state = "database_negotiation";
        else if (observation.protocol == Observation::Protocol::Rpc)
            observation.state = "rpc_bind";
        else if (observation.protocol == Observation::Protocol::Smtp ||
            observation.protocol == Observation::Protocol::Imap ||
            observation.protocol == Observation::Protocol::Pop3 ||
            observation.protocol == Observation::Protocol::Ftp)
            observation.state = "cleartext_login";
        else
            observation.state = observation.protocol == Observation::Protocol::Rdp ?
                fields.value("rdp_client_security_exchange_observed", false) ?
                    "rdp_security_exchange" : "rdp_negotiation" :
                fields.value("tds_unencrypted_login_observed", false) ||
                fields.value("tds_sspi_response_observed", false) ||
                fields.value("tds_sspi_continuation_observed", false) ? "tds_authentication" :
                fields.value("tds_prelogin_observed", false) ? "tds_prelogin" : "tds_framing";
    }
    else if (observation.protocol == Observation::Protocol::Unknown && observation.raw.possibleEncryption)
        observation.state = "possible_encryption";
    else
    {
        if (!observation.clientHello && !observation.serverHello && !observation.retrySeen &&
            observation.crypto.ssl2ErrorCode < 0)
            return;
        observation.state = observation.crypto.ssl2ErrorCode >= 0 ? "ssl2_error" :
            observation.clientHello && observation.serverHello ? "hellos_observed" :
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
    inspection.finishSamples();
    const auto retained = flow.inspection->memory();
    flow.observed = flow.observed || inspection.observation.recognized() || inspection.observation.retrySeen ||
        inspection.observation.raw.possibleEncryption;
    emit(flow.inspection->observation, reason);
    buffered_ -= retained;
    flow.inspection.reset();
}

void Engine::followHttp(Flow& flow, const TransportPacket& packet, int64_t timestampUs)
{
    // HTTP decoding follows the connection through its whole life, after handshake inspection has retired.
    const auto retained = memory() - flow.plusBytes;
    const bool active = flow.plus->feed(packet, timestampUs, limits_.bytes > retained ? limits_.bytes - retained : 0);
    plusBytes_ = plusBytes_ - flow.plusBytes + (active ? flow.plus->memory() : 0);
    flow.plusBytes = active ? flow.plus->memory() : 0;
    if (!active)
        flow.plus.reset();
}

void Engine::releaseHttp(Flow& flow, int64_t timestampUs, std::string_view reason)
{
    flow.plus->finish(timestampUs, reason);
    plusBytes_ -= flow.plusBytes;
    flow.plusBytes = 0;
    flow.plus.reset();
}

void Engine::close(Flow& flow, std::string_view reason)
{
    if (flow.plus && flow.plus->waiting() && plus_->options().secretWaitUs > 0)
    {
        closedHttp_.push_back({std::move(flow.plus), flow.plusBytes, flow.lastUs, std::string(reason)});
        flow.plusBytes = 0;
    }
    else if (flow.plus)
        releaseHttp(flow, flow.lastUs, reason);
    retire(flow, flow.inspection && (!flow.inspection->observation.clientHello ||
        !flow.inspection->observation.serverHello) ? reason : std::string_view{});
    if (flow.observed)
        end(flow.id, flow.lastUs, reason);
}

void Engine::end(uint64_t flowId, int64_t endedUs, std::string_view reason)
{
    Observation update;
    update.flowId = flowId;
    update.lifecycleOnly = true;
    update.endedUs = endedUs;
    update.closeReason = reason;
    sink_(std::move(update));
}

void Engine::publishUsage()
{
    counters_.activeFlows.store(flowCount(), std::memory_order_relaxed);
    counters_.bufferedBytes.store(memory(), std::memory_order_relaxed);
}

void Engine::tcp(const TransportPacket& packet, int64_t timestampUs)
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
        flow.id = ++nextId_;
        flow.inspection = std::make_unique<TcpInspection>(key, flow.id, timestampUs, limits_.raw, limits_.http);
        buffered_ += flow.inspection->memory();
        if (plus_)
        {
            flow.plus = plus_->open(key, flow.id, timestampUs);
            flow.plusBytes = flow.plus->memory();
            plusBytes_ += flow.plusBytes;
        }
        found = flows_.emplace(key, std::move(flow)).first;
    }
    auto& flow = found->second;
    flow.lastUs = std::max(flow.lastUs, timestampUs);
    if (syn)
        flow.syn[direction] = packet.sequence;
    if (flow.plus)
        followHttp(flow, packet, timestampUs);
    if (flow.inspection)
    {
        auto& inspection = *flow.inspection;
        auto& observation = inspection.observation;
        const auto previousBytes = inspection.memory();
        const auto retained = memory() - previousBytes;
        const auto result = inspection.feed(packet, timestampUs,
            limits_.bytes > retained ? limits_.bytes - retained : 0);
        buffered_ = buffered_ - previousBytes + inspection.memory();

        // Parser state belongs to the inspection; admission, memory pressure, and retirement belong to the engine.
        const bool malformed = result == TcpInspection::Result::Malformed;
        const bool limited = result == TcpInspection::Result::Limited;
        if (malformed || limited || result == TcpInspection::Result::Unrecognized)
        {
            if (malformed)
                ++counters_.malformed;
            else if (limited)
                ++counters_.reassemblyLimit;
            retire(flow, malformed ? "Malformed handshake" : limited ? "Reassembly or inspection limit reached" :
                "No handshake in the inspected data");
        }
        else if (result == TcpInspection::Result::Complete)
            retire(flow, {});
        else if (result == TcpInspection::Result::Updated)
        {
            flow.observed = observation.recognized() || observation.retrySeen;
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
    publishUsage();
}

void Engine::udp(const TransportPacket& packet, int64_t timestampUs)
{
    if (timestampUs >= nextExpiry_)
        expire(timestampUs);

    // UDP encapsulation distinguishes ESP from IKE's zero marker and one-byte NAT keepalives.
    if ((packet.source.port == 4500 || packet.destination.port == 4500) && packet.payload.size() >= 10 &&
        be32(packet.payload, 0) >= 256)
    {
        auto esp = packet;
        esp.ipsecProtocol = 50;
        esp.ipsecSpi = be32(packet.payload, 0);
        esp.ipsecSequence = be32(packet.payload, 4);
        inspectIpsec(esp, timestampUs);
        return;
    }
    if (observeQuic(packet, timestampUs) || inspectDtls(packet, timestampUs) ||
        inspectVpn(packet, timestampUs) || inspectKerberos(packet, timestampUs) ||
        inspectLdap(packet, timestampUs))
    {
        publishUsage();
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
        const auto dcid = hex(header->destinationId);
        const auto scid = hex(header->sourceId);
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
        o.loopback |= packet.loopback;
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
    publishUsage();
}

bool Engine::inspectKerberos(const TransportPacket& packet, int64_t timestampUs)
{
    // A KDC or change-password datagram contains one complete message, independent of the configured UDP port.
    const bool password = passwordMessageSize(packet.payload) == packet.payload.size();
    if (packet.truncated || packet.payload.empty() ||
        (!password && kerberosMessageSize(packet.payload) != packet.payload.size()))
        return false;
    auto evidence = std::make_shared<ProtocolEvidence>();
    if (!(password ? parsePasswordChange(packet.payload, evidence->fields) :
        parseKerberos(packet.payload, evidence->fields)))
    {
        ++counters_.malformed;
        return true;
    }
    evidence->measure();

    // Pair a reply only when its direction and message family identify one outstanding request on the same tuple.
    // Reply nonces are encrypted, so concurrent requests of the same family remain separate observations.
    const bool client = evidence->fields.contains("krb_as_request") || evidence->fields.contains("krb_tgs_request") ||
        evidence->fields.contains("krb_password_request");
    const auto kind = evidence->fields.contains("krb_as_request") || evidence->fields.contains("krb_as_reply") ?
        PendingKerberos::Kind::As : evidence->fields.contains("krb_tgs_request") ||
            evidence->fields.contains("krb_tgs_reply") ? PendingKerberos::Kind::Tgs :
            PendingKerberos::Kind::Password;
    const bool error = evidence->fields.contains("krb_error") && !evidence->fields.contains("krb_password_reply");
    const auto key = FlowKey::make(packet.source, packet.destination);
    auto found = kerberos_.find(key);
    std::string requestDigest;
    if (client)
    {
        // A byte-identical request on the same tuple is a UDP retransmission, not a second outstanding exchange.
        // Retain only its digest so credential-bearing packet bytes are never held for correlation.
        requestDigest = sha256(packet.payload);
        if (found != kerberos_.end())
            for (auto& pending : found->second)
                if (pending.kind == kind && pending.observation.source == packet.source &&
                    pending.observation.destination == packet.destination && pending.requestDigest == requestDigest)
                {
                    pending.observation.lastUs = std::max(pending.observation.lastUs, timestampUs);
                    return true;
                }
    }
    if (!client && found != kerberos_.end())
    {
        size_t match = 0, matches = 0;
        auto& pending = found->second;
        for (size_t index = 0; index < pending.size(); ++index)
            if (pending[index].observation.source == packet.destination &&
                pending[index].observation.destination == packet.source &&
                (error || pending[index].kind == kind))
            {
                match = index;
                ++matches;
            }
        if (matches == 1)
        {
            auto observation = pending[match].observation;
            auto merged = std::make_shared<ProtocolEvidence>();
            merged->fields = observation.application->fields;
            merged->fields.update(evidence->fields);
            merged->measure();
            observation.application = std::move(merged);
            observation.lastUs = observation.endedUs = timestampUs;
            observation.closeReason = "UDP request and reply observed; authentication outcome unknown";
            const auto retained = pending[match].memory();
            if (memory() - retained + observation.memory() > limits_.bytes)
            {
                ++counters_.reassemblyLimit;
                return true;
            }
            kerberosBytes_ -= retained;
            --kerberosFlows_;
            pending.erase(pending.begin() + match);
            if (pending.empty())
                kerberos_.erase(found);
            emit(observation);
            return true;
        }
    }
    Observation observation;
    observation.loopback = packet.loopback;
    observation.protocol = Observation::Protocol::Kerberos;
    observation.udp = true;
    observation.source = client ? packet.source : packet.destination;
    observation.destination = client ? packet.destination : packet.source;
    observation.firstUs = observation.lastUs = timestampUs;
    if (!client)
    {
        observation.endedUs = timestampUs;
        observation.closeReason = "UDP reply observed; matching request unknown";
    }
    observation.application = std::move(evidence);
    const bool flowLimit = flowCount() >= limits_.flows ||
        (client && found != kerberos_.end() && found->second.size() >= 8);
    if (flowLimit || memory() + observation.memory() > limits_.bytes)
    {
        ++(flowLimit ? counters_.flowLimit : counters_.reassemblyLimit);
        return true;
    }
    observation.flowId = ++nextId_;
    emit(observation);
    if (client)
    {
        PendingKerberos pending;
        pending.kind = kind;
        pending.observation = std::move(observation);
        pending.requestDigest = std::move(requestDigest);
        kerberosBytes_ += pending.memory();
        ++kerberosFlows_;
        kerberos_[key].push_back(std::move(pending));
    }
    return true;
}

bool Engine::inspectLdap(const TransportPacket& packet, int64_t timestampUs)
{
    // Connectionless LDAP carries one complete BER message in each datagram.
    if (packet.truncated || packet.payload.empty() || ldapMessageSize(packet.payload) != packet.payload.size())
        return false;
    auto evidence = std::make_shared<ProtocolEvidence>();
    if (!parseLdap(packet.payload, evidence->fields))
    {
        ++counters_.malformed;
        return true;
    }
    evidence->fields["ldap_datagram_observed"] = true;
    evidence->measure();
    const bool client = evidence->fields.contains("ldap_bind_request") ||
        evidence->fields.contains("ldap_starttls_requested");
    Observation observation;
    observation.loopback = packet.loopback;
    observation.protocol = Observation::Protocol::Ldap;
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

bool Engine::inspectVpn(const TransportPacket& packet, int64_t timestampUs)
{
    auto parsed = parseVpn(packet.payload);
    if (!parsed)
        return false;
    const auto key = FlowKey::make(packet.source, packet.destination);
    auto found = raw_.find(key);
    if (parsed->protocol == Observation::Protocol::IkeV1 && !parsed->roleKnown &&
        (found == raw_.end() || !found->second.observation.vpn))
        return false;
    if ((found == raw_.end() || !found->second.observation.vpn) &&
        parsed->protocol == Observation::Protocol::OpenVpn && !parsed->reset &&
        (parsed->tls.size() < 6 || parsed->tls[0] != 22 || parsed->tls[1] != 3))
        return false;
    if (found != raw_.end())
    {
        const auto& previous = found->second.observation;
        const nlohmann::json empty;
        const auto& fields = previous.vpn ? previous.vpn->fields : empty;
        const bool replacement = !previous.vpn || (parsed->roleKnown && parsed->client &&
            (previous.protocol != parsed->protocol ||
            (parsed->protocol == Observation::Protocol::Ike &&
                fields["ike_initiator_spi"] != parsed->fields["ike_initiator_spi"]) ||
            (parsed->protocol == Observation::Protocol::IkeV1 &&
                fields.value("ikev1_initiator_cookie", "") !=
                    parsed->fields.value("ikev1_initiator_cookie", "")) ||
            (parsed->protocol == Observation::Protocol::WireGuard &&
                fields.contains("wireguard_initiator_index") &&
                fields["wireguard_initiator_index"] != parsed->fields["wireguard_sender_index"]) ||
            (parsed->protocol == Observation::Protocol::OpenVpn && parsed->reset &&
                fields.contains("openvpn_client_session_id") &&
                fields["openvpn_client_session_id"] != parsed->fields["openvpn_session_id"])));
        if (replacement)
        {
            if (found->second.observed)
                end(previous.flowId, found->second.lastUs, "UDP session replaced; connection outcome unknown");
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
    observation.loopback |= packet.loopback;
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
    if (parsed->protocol == Observation::Protocol::IkeV1 && !parsed->roleKnown)
        parsed->client = direction == 0;
    if ((parsed->protocol == Observation::Protocol::Ike || parsed->protocol == Observation::Protocol::IkeV1 ||
        parsed->protocol == Observation::Protocol::WireGuard) &&
        parsed->client != (direction == 0))
        return true;
    if (observation.vpn && parsed->protocol == Observation::Protocol::Ike &&
        observation.vpn->fields.value("ike_initiator_spi", "") != parsed->fields.value("ike_initiator_spi", ""))
        return true;
    if (observation.vpn && parsed->protocol == Observation::Protocol::IkeV1)
    {
        const auto& fields = observation.vpn->fields;
        if (fields.value("ikev1_initiator_cookie", "") !=
                parsed->fields.value("ikev1_initiator_cookie", "") ||
            (fields.contains("ikev1_selection") && parsed->fields.contains("ikev1_offers")) ||
            (fields.contains("ikev1_offers") && parsed->fields.contains("ikev1_offers") &&
                fields["ikev1_offers"] != parsed->fields["ikev1_offers"]) ||
            (fields.contains("ikev1_selection") && parsed->fields.contains("ikev1_selection") &&
                fields["ikev1_selection"] != parsed->fields["ikev1_selection"]) ||
            (!parsed->roleKnown && !fields.contains("ikev1_selection")) ||
            (parsed->fields.value("ikev1_exchange", "") != "Quick Mode" &&
                fields.value("ikev1_exchange", "") != parsed->fields.value("ikev1_exchange", "")) ||
            (fields.contains("ikev1_selection") &&
                fields.value("ikev1_responder_cookie", "") !=
                    parsed->fields.value("ikev1_responder_cookie", "")))
            return true;
    }
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
    if (observation.vpn && parsed->protocol == Observation::Protocol::IkeV1 &&
        parsed->fields.contains("ikev1_selection") && observation.vpn->fields.contains("ikev1_offers"))
    {
        const auto& selection = parsed->fields["ikev1_selection"][0];
        const auto& offers = observation.vpn->fields["ikev1_offers"];
        const bool offered = std::any_of(offers.begin(), offers.end(), [&](const auto& offer)
        {
            return offer["encryption_id"] == selection["encryption_id"] &&
                offer["hash_id"] == selection["hash_id"] &&
                offer["authentication_id"] == selection["authentication_id"] &&
                offer["group_id"] == selection["group_id"] && offer["key_bits"] == selection["key_bits"] &&
                offer["attribute_sha256"] == selection["attribute_sha256"];
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

    // IKEv1 phase-one follow-ups use the same cookie pair in both directions.
    if (parsed->protocol == Observation::Protocol::IkeV1)
    {
        // Public-key authentication can encrypt ID payload bodies while leaving their headers visible.
        if (parsed->fields.contains("ikev1_id_type_octet"))
        {
            const auto& fields = observation.vpn ? observation.vpn->fields : parsed->fields;
            const auto& methods = parsed->fields.contains("ikev1_selection") ?
                parsed->fields["ikev1_selection"] : fields.contains("ikev1_selection") ?
                fields["ikev1_selection"] : fields["ikev1_offers"];
            if (!std::ranges::all_of(methods, [](const auto& transform)
            {
                const int authentication = transform.value("authentication_id", 0);
                return authentication >= 1 && authentication <= 3;
            }))
                parsed->fields.erase("ikev1_id_type_octet");
        }
        const std::string side = direction == 0 ? "ikev1_initiator_" : "ikev1_responder_";
        for (const char* name : {"key_exchange_bytes", "nonce_payload_bytes", "id_type_octet",
            "identity_payload_bytes", "auth_payload_type", "auth_payload_bytes", "nat_discovery_payloads"})
        {
            const std::string fieldName = std::string("ikev1_") + name;
            if (parsed->fields.contains(fieldName))
            {
                parsed->fields[side + name] = std::move(parsed->fields[fieldName]);
                parsed->fields.erase(fieldName);
            }
        }
        if (parsed->fields.contains("ikev1_encrypted_payload_observed"))
            parsed->fields[side + "encrypted_payload_observed"] = true;
        if (parsed->fields.value("ikev1_exchange", "") == "Quick Mode")
        {
            parsed->fields["ikev1_phase_two_exchange"] = "Quick Mode";
            parsed->fields.erase("ikev1_exchange");
        }
        if (observation.vpn && observation.vpn->fields.contains("ikev1_selection"))
            parsed->fields.erase("vpn_algorithm_evidence");
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

void Engine::sampleUdp(const TransportPacket& packet, int64_t timestampUs)
{
    // Keep a bounded payload sample for otherwise unrecognized datagram flows.
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
    flow.observation.loopback |= packet.loopback;
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
    ipsec_.expire(timestampUs, all, limits_.idleUs, [&](Observation observation)
    {
        if (observation.lifecycleOnly) sink_(std::move(observation));
        else emit(observation);
    });

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
            // HTTP metadata remains observable on persistent connections within the shared memory and idle limits.
            const auto* inspection = it->second.inspection.get();
            if (inspection && inspection->expired(timestampUs))
                retire(it->second, "Cleartext handshake inspection window ended");

            // Connections waiting for logged TLS secrets look again once the key log has grown.
            if (auto& plus = it->second.plus; plus && plus->waiting())
            {
                plus->tick(timestampUs);
                const auto bytes = plus->memory();
                plusBytes_ = plusBytes_ - it->second.plusBytes + bytes;
                it->second.plusBytes = bytes;
                if (!plus->active())
                {
                    plusBytes_ -= it->second.plusBytes;
                    it->second.plusBytes = 0;
                    plus.reset();
                }
            }
            ++it;
        }
    }

    // Short-lived connections remain decryptable when the application's key-log flush trails their close.
    for (auto it = closedHttp_.begin(); it != closedHttp_.end();)
    {
        it->flow->tick(it->endedUs);
        const auto bytes = it->flow->memory();
        plusBytes_ = plusBytes_ - it->bytes + bytes;
        it->bytes = bytes;
        if (all || !it->flow->waiting() || timestampUs - it->endedUs >= plus_->options().secretWaitUs)
        {
            it->flow->finish(it->endedUs, it->reason);
            plusBytes_ -= it->bytes;
            it = closedHttp_.erase(it);
        }
        else
            ++it;
    }

    // Unmatched Kerberos UDP requests retain only short-lived metadata for an unambiguous reply.
    for (auto it = kerberos_.begin(); it != kerberos_.end();)
    {
        auto& pending = it->second;
        for (auto request = pending.begin(); request != pending.end();)
            if (all || timestampUs - request->observation.lastUs > 30000000)
            {
                end(request->observation.flowId, request->observation.lastUs,
                    "UDP request ended; matching reply unknown");
                kerberosBytes_ -= request->memory();
                --kerberosFlows_;
                request = pending.erase(request);
            }
            else
                ++request;
        if (pending.empty())
            it = kerberos_.erase(it);
        else
            ++it;
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
            end(flow.observation.flowId, flow.lastUs, "UDP inspection ended; connection outcome unknown");
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
            end(flow.observation.flowId, flow.lastUs, "DTLS observation window ended; connection outcome unknown");
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
                    end(flow.observation.flowId, flow.lastUs,
                        "QUIC observation window ended; connection outcome unknown");
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
    publishUsage();
}
}
