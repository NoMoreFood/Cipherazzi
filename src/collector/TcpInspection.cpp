#include "TcpInspection.h"
#include <algorithm>

namespace Cipherazzi
{
TcpInspection::TcpInspection(const FlowKey& key, uint64_t id, int64_t timestampUs, bool raw, bool http) :
    key_(key), rawEnabled_(raw), httpEnabled_(http), framing(key.a.port, key.b.port), handshakeStartedUs(timestampUs)
{
    observation.flowId = id;
    observation.firstUs = timestampUs;
}

size_t TcpInspection::memory() const
{
    return sizeof(*this) - sizeof(observation) + streams[0].memory() + streams[1].memory() +
        tls[0].memory() + tls[1].memory() + ssh[0].memory() + ssh[1].memory() + observation.memory() +
        framing.memory() + (vpnStreams ? (*vpnStreams)[0].memory() + (*vpnStreams)[1].memory() : 0) +
        (samples[0] ? sizeof(PayloadSample) : 0) + (samples[1] ? sizeof(PayloadSample) : 0);
}

void TcpInspection::finishSamples()
{
    if (!observation.recognized())
        for (int direction = 0; direction < 2; ++direction)
            if (samples[direction])
                samples[direction]->classify(observation, direction == sourceDirection ? 0 : 1);
}

bool TcpInspection::expired(int64_t timestampUs) const
{
    return !(httpEnabled_ && observation.protocol == Observation::Protocol::Http && !framing.tunnel()) &&
        timestampUs - handshakeStartedUs > 30000000;
}

bool TcpInspection::applyApplication(int frameDirection, const FramedMessage& framed,
    int64_t timestampUs, bool& updated)
{
    auto fields = framed.fields;
    if (framed.kind == FramedMessage::Kind::Http)
    {
        if (fields.value("http_tunnel_established", false))
            handshakeStartedUs = timestampUs;

        // HTTP start lines establish client/server roles even when capture missed the TCP handshake.
        const int client = fields.contains("http_response_versions") ? 1 - frameDirection : frameDirection;
        if (rolesKnown && client != sourceDirection)
            return false;
        sourceDirection = client;
        rolesKnown = true;
        observation.source = client == 0 ? key_.a : key_.b;
        observation.destination = client == 0 ? key_.b : key_.a;
        if (!httpEnabled_)
            for (const auto* name : {"http_request_observed", "http_response_observed", "http_request_versions",
                "http_response_versions", "http_methods", "http_hosts", "http_status_codes",
                "http_upgrade_observed", "http_upgrade_protocol"})
                fields.erase(name);
    }
    if (fields.empty())
        return true;

    // Database startup identifies client roles even when capture begins with a server greeting.
    if (framed.kind == FramedMessage::Kind::PostgreSql || framed.kind == FramedMessage::Kind::MySql)
    {
        const int client = framing.databaseClient();
        if (rolesKnown && client != sourceDirection)
            return false;
        sourceDirection = client;
        rolesKnown = true;
        observation.source = client == 0 ? key_.a : key_.b;
        observation.destination = client == 0 ? key_.b : key_.a;
    }

    // SMB Direct negotiation establishes initiator roles even when TCP setup was not captured.
    if (framed.fields.contains("smb_direct_client_negotiation") ||
        framed.fields.contains("smb_direct_server_negotiation"))
    {
        const int client = framed.fields.contains("smb_direct_client_negotiation") ?
            frameDirection : 1 - frameDirection;
        if (rolesKnown && client != sourceDirection)
            return false;
        sourceDirection = client;
        rolesKnown = true;
        observation.source = client == 0 ? key_.a : key_.b;
        observation.destination = client == 0 ? key_.b : key_.a;
    }
    static const auto empty = nlohmann::json::object();
    const auto& previous = observation.application ? observation.application->fields : empty;

    // Store distinct HTTP facts once per connection, with a fixed bound on every accumulated set.
    if (framed.kind == FramedMessage::Kind::Http)
    {
        if (!previous.contains("http_host") && fields.contains("http_hosts"))
            fields["http_host"] = fields["http_hosts"][0];
        for (const auto* name : {"http_hosts", "http_methods", "http_status_codes",
            "http_request_versions", "http_response_versions"})
        {
            if (!fields.contains(name))
                continue;
            auto values = previous.value(name, nlohmann::json::array());
            for (const auto& value : fields[name])
                if (values.size() < 16 && std::find(values.begin(), values.end(), value) == values.end())
                    values.push_back(value);
            fields[name] = std::move(values);
        }
    }
    if (fields.contains("rpc_bind") || fields.contains("rpc_bind_events"))
    {
        nlohmann::json binds = previous.value("rpc_binds", nlohmann::json::array());
        auto addBind = [&](const nlohmann::json& bind)
        {
            if (binds.size() < 64)
                binds.push_back(bind);
            else
                fields["rpc_binds_dropped"] = fields.value("rpc_binds_dropped",
                    previous.value("rpc_binds_dropped", 0)) + 1;
        };
        if (fields.contains("rpc_bind"))
            addBind(fields["rpc_bind"]);
        if (fields.contains("rpc_bind_events"))
            for (const auto& bind : fields["rpc_bind_events"])
                addBind(bind);
        if (fields.contains("rpc_bind_events_dropped"))
            fields["rpc_binds_dropped"] = fields.value("rpc_binds_dropped",
                previous.value("rpc_binds_dropped", 0)) + fields["rpc_bind_events_dropped"].get<int>();
        fields.erase("rpc_bind");
        fields.erase("rpc_bind_events");
        fields.erase("rpc_bind_events_dropped");
        fields["rpc_binds"] = std::move(binds);
    }
    if (fields.contains("tds_prelogin"))
    {
        const bool source = frameDirection == sourceDirection;
        if (!rolesKnown)
        {
            fields["tds_prelogin"]["socket_address"] = (frameDirection == 0 ? key_.a : key_.b).text();
            fields["tds_prelogin"]["socket_port"] = (frameDirection == 0 ? key_.a : key_.b).port;
        }
        fields[rolesKnown ? source ? "tds_client_prelogin" : "tds_server_prelogin" :
            frameDirection == 0 ? "tds_peer_a_prelogin" : "tds_peer_b_prelogin"] = fields["tds_prelogin"];
        fields["tds_roles_known"] = rolesKnown;
        fields.erase("tds_prelogin");
    }

    // Repeated facts leave the shared immutable snapshot intact without copying its complete JSON tree.
    if (observation.application && std::ranges::all_of(fields.items(), [&](const auto& field)
    {
        const auto found = previous.find(field.key());
        return found != previous.end() && *found == field.value();
    }))
        return true;
    auto evidence = std::make_shared<ProtocolEvidence>();
    evidence->fields = previous;
    evidence->fields.update(fields);
    resolveNegotiation(evidence->fields);
    if (!observation.application || observation.application->fields != evidence->fields)
    {
        evidence->measure();
        observation.application = std::move(evidence);
        if (!observation.clientHello && !observation.serverHello)
            observation.protocol = framed.kind == FramedMessage::Kind::Smb ?
                Observation::Protocol::Smb : framed.kind == FramedMessage::Kind::Rdp ?
                Observation::Protocol::Rdp : framed.kind == FramedMessage::Kind::Kerberos ?
                Observation::Protocol::Kerberos : framed.kind == FramedMessage::Kind::Ldap ?
                Observation::Protocol::Ldap : framed.kind == FramedMessage::Kind::Http ?
                Observation::Protocol::Http : framed.kind == FramedMessage::Kind::Rpc ?
                Observation::Protocol::Rpc : framed.kind == FramedMessage::Kind::Smtp ?
                Observation::Protocol::Smtp : framed.kind == FramedMessage::Kind::Imap ?
                Observation::Protocol::Imap : framed.kind == FramedMessage::Kind::Pop3 ?
                Observation::Protocol::Pop3 : framed.kind == FramedMessage::Kind::Ftp ?
                Observation::Protocol::Ftp : framed.kind == FramedMessage::Kind::PostgreSql ?
                Observation::Protocol::PostgreSql : framed.kind == FramedMessage::Kind::MySql ?
                Observation::Protocol::MySql : Observation::Protocol::Tds;
        updated = true;
    }
    return true;
}

TcpInspection::Result TcpInspection::feed(const TransportPacket& packet, int64_t timestampUs, size_t budget)
{
    const int direction = packet.source == key_.a ? 0 : 1;
    const bool syn = (packet.flags & 2) != 0;
    auto& stream = streams[direction];
    observation.loopback |= packet.loopback;
    observation.lastUs = std::max(observation.lastUs, timestampUs);
    if (syn)
    {
        stream.begin(packet.sequence + 1);
        if (!(packet.flags & 16) || sourceDirection < 0)
        {
            sourceDirection = packet.flags & 16 ? 1 - direction : direction;
            observation.source = sourceDirection == 0 ? key_.a : key_.b;
            observation.destination = sourceDirection == 0 ? key_.b : key_.a;
            rolesKnown = true;
        }
    }
    if (sourceDirection < 0)
    {
        sourceDirection = direction;
        observation.source = packet.source;
        observation.destination = packet.destination;
    }
    bool updated = false;
    bool invalid = false;
    bool valid = stream.feed(packet.sequence + (syn ? 1 : 0), packet.payload, [&](Bytes bytes)
    {
        // Reassembly delivers each byte once to the protocol parsers and optional bounded sample.
        if (rawEnabled_ && !observation.recognized())
        {
            if (!samples[direction])
                samples[direction] = std::make_unique<PayloadSample>();
            samples[direction]->feed(bytes);
        }
        if (!observation.clientHello && !observation.serverHello)
        {
            if (!ssh[direction].feed(bytes, [&](const SshMessage& message)
            {
                applySsh(observation, direction == sourceDirection ? 0 : 1, message);
                observation.ssh->rolesKnown = rolesKnown;
                updated = true;
            }))
                return false;
            if ((observation.ssh && observation.ssh->observed))
                return true;
        }
        return framing.feed(direction, bytes, [&](int frameDirection, const FramedMessage& framed)
        {
            if (framed.kind == FramedMessage::Kind::OpenVpn)
            {
                auto parsed = parseVpn(framed.payload);
                if (!parsed || !rolesKnown)
                    return true;
                const bool client = frameDirection == sourceDirection;
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
                if (!vpnStreams)
                    vpnStreams = std::make_unique<std::array<OpenVpnStream, 2>>();
                updated = true;
                return (*vpnStreams)[frameDirection].feed(*parsed, [&](const Hello& hello)
                {
                    if ((hello.type == 1 || hello.type == 2) && hello.client == client)
                        applyHello(observation, hello, timestampUs);
                    for (auto& vpnStream : *vpnStreams)
                        vpnStream.selectVersion(observation.version);
                });
            }
            invalid |= !applyApplication(frameDirection, framed, timestampUs, updated);
            if (framed.kind == FramedMessage::Kind::Smb || framed.kind == FramedMessage::Kind::Rdp ||
                framed.kind == FramedMessage::Kind::Kerberos || framed.kind == FramedMessage::Kind::Ldap ||
                framed.kind == FramedMessage::Kind::Http || framed.kind == FramedMessage::Kind::Rpc ||
                framed.kind == FramedMessage::Kind::Smtp || framed.kind == FramedMessage::Kind::Imap ||
                framed.kind == FramedMessage::Kind::Pop3 || framed.kind == FramedMessage::Kind::Ftp ||
                framed.kind == FramedMessage::Kind::PostgreSql || framed.kind == FramedMessage::Kind::MySql)
                return true;
            return tls[frameDirection].feed(framed.payload, [&](const Hello& hello)
            {
                if (hello.type != 1 && hello.type != 2)
                {
                    if (!observation.clientHello && !observation.serverHello && hello.type != Ssl2Error)
                        return;
                    if (hello.type == Ssl2Error)
                        observation.protocol = Observation::Protocol::Tls;
                    if (!applyHandshake(observation, hello,
                        (frameDirection == 0 ? key_.a : key_.b) == observation.source,
                        observation.version < 0x0304, timestampUs))
                        invalid = true;
                    updated = true;
                    return;
                }
                const auto source = (hello.client ? frameDirection : 1 - frameDirection) == 0 ? key_.a : key_.b;
                const auto destination = (hello.client ? frameDirection : 1 - frameDirection) == 0 ? key_.b : key_.a;
                if ((observation.clientHello || observation.serverHello || observation.retrySeen) &&
                    observation.source != source)
                {
                    invalid = true;
                    return;
                }
                observation.source = source;
                observation.destination = destination;
                observation.protocol = Observation::Protocol::Tls;

                applyHello(observation, hello, timestampUs);
                for (auto& directionStream : tls)
                {
                    directionStream.expectTls();
                    if (!hello.client)
                        directionStream.selectVersion(hello.version);
                }
                updated = true;
            });
        });
    });

    // Report parser outcomes; the engine applies its shared memory budget and owns flow retirement.
    const bool framingLimited = framing.limited();
    const bool malformed = stream.malformed() || tls[direction].malformed() || invalid ||
        (!valid && !framingLimited && !stream.limited() && observation.application) ||
        ((observation.ssh && observation.ssh->observed) &&
            !ssh[direction].limited() && !stream.limited());

    if (!valid || invalid || memory() > budget)
    {
        if (malformed)
            return Result::Malformed;
        // A stream whose scanned prefix held no handshake ends inspection without evidence being lost.
        if (memory() <= budget && tls[direction].unmatched() && !observation.recognized() && !observation.retrySeen)
            return Result::Unrecognized;
        return Result::Limited;
    }
    if ((observation.application &&
        (observation.application->fields.value("smb_encrypted_transform_observed", false) ||
            observation.application->fields.contains("rdp_failure_code"))) ||
        framing.finished() ||
        (observation.clientHello && observation.serverHello && observation.version >= 0x0304) ||
        ((observation.ssh && observation.ssh->observed) ?
            ssh[0].finished() && ssh[1].finished() :
            tls[0].finished() && tls[1].finished()))
        return Result::Complete;
    return updated ? Result::Updated : Result::Unchanged;
}
}
