#include "Engine.h"
#include <algorithm>

namespace Cipherazzi
{
bool Engine::inspectDtls(const TcpPacket& packet, int64_t timestampUs)
{
    const auto key = FlowKey::make(packet.source, packet.destination);
    auto found = dtls_.find(key);
    if (found == dtls_.end())
    {
        if (!DtlsStream::recognizes(packet.payload))
            return false;
        const bool flowLimit = flowCount() >= limits_.flows;
        if (flowLimit ||
            memory() + 16384 > limits_.bytes)
        {
            ++(flowLimit ? counters_.flowLimit : counters_.reassemblyLimit);
            return true;
        }
        found = dtls_.try_emplace(key).first;
        auto& flow = found->second;
        flow.streams = std::make_unique<std::array<DtlsStream, 2>>();
        auto& observation = flow.observation;
        observation.flowId = ++nextId_;
        observation.firstUs = timestampUs;
        observation.source = packet.source;
        observation.destination = packet.destination;
        observation.udp = true;
        observation.dtlsVersion = be16(packet.payload, 1);
        dtlsBytes_ += flow.memory();
    }
    auto& flow = found->second;
    auto& observation = flow.observation;
    flow.lastUs = observation.lastUs = std::max(flow.lastUs, timestampUs);
    if (!flow.streams)
        return true;
    const auto retained = flow.memory();
    const auto direction = packet.source == key.a ? 0 : 1;
    bool updated = false, invalid = false;
    const bool valid = (*flow.streams)[direction].feed(packet.payload, [&](const Hello& hello)
    {
        if (hello.type == 1 || hello.type == 2)
        {
            const auto source = hello.client ? packet.source : packet.destination;
            if ((observation.clientHello || observation.serverHello) && observation.source != source)
            {
                invalid = true;
                return;
            }
            observation.source = source;
            observation.destination = hello.client ? packet.destination : packet.source;
            applyHello(observation, hello, timestampUs);
        }
        else if (hello.type == 3)
        {
            observation.dtlsCookie = true;
            observation.retrySeen = true;
            observation.crypto.retryUs = timestampUs;
        }
        else
        {
            const bool client = packet.source == observation.source;
            auto& crypto = observation.crypto;
            if (hello.type == 254)
            {
                crypto.alertLevel = hello.crypto.alertLevel;
                crypto.alertCode = hello.crypto.alertCode;
                crypto.alertSide = client ? "Client" : "Server";
                crypto.alertUs = timestampUs;
            }
            else if (hello.type == 253)
                (client ? crypto.clientCleartextEnded : crypto.serverCleartextEnded) = true;
            else if (observation.serverHello && observation.version < 0x0304)
            {
                if (hello.type == 11)
                {
                    (client ? crypto.clientCertificates : crypto.serverCertificates) = hello.crypto.serverCertificates;
                    if (client)
                        crypto.clientCertificatePresented = hello.crypto.serverCertificates.empty() ? 0 : 1;
                }
                else if (hello.type == 12 && !client)
                    invalid |= !parseKeyExchange(hello.body, observation.version, observation.cipher, crypto);
                else if (hello.type == 13 && !client)
                    crypto.certificateRequested = 1;
                else if (hello.type == 14 && !client && crypto.certificateRequested < 0)
                    crypto.certificateRequested = 0;
                else if (hello.type == 15 && client && observation.version == 0x0303)
                {
                    if (hello.body.size() < 4 || be16(hello.body, 2) != hello.body.size() - 4)
                        invalid = true;
                    else
                        crypto.clientSignature = signatureName(be16(hello.body, 0));
                }
            }
        }
        updated = true;
    });
    const bool overBudget = memory() - retained + flow.memory() > limits_.bytes;
    if (!valid || invalid || overBudget)
    {
        const bool limited = (*flow.streams)[direction].limited() || overBudget;
        if (limited)
            ++counters_.reassemblyLimit;
        else
            ++counters_.malformed;
        observation.detail = limited ? "DTLS inspection limit reached" : "Malformed DTLS handshake";
    }
    flow.observed |= observation.clientHello || observation.serverHello || observation.retrySeen;
    if (updated || !valid || invalid || overBudget)
        emit(observation);
    if (!valid || invalid || overBudget || (observation.serverHello && observation.version == 0x0304) ||
        ((*flow.streams)[0].finished() && (*flow.streams)[1].finished()))
    {
        flow.streams.reset();
    }
    dtlsBytes_ = dtlsBytes_ - retained + flow.memory();
    return true;
}

void Engine::indexQuic(QuicFlow& flow, bool remove)
{
    if (remove)
    {
        for (const auto& id : flow.indexedIds)
        {
            const auto found = quicIds_.find(id.first);
            if (found == quicIds_.end())
                continue;
            std::erase_if(found->second.owners, [&](const CidOwner& owner)
                { return owner.flow == &flow && owner.client == id.second; });
            if (!--found->second.references)
                quicIds_.erase(found);
        }
        return;
    }
    const auto before = flow.memory();
    const auto& o = flow.observation;
    for (const auto [id, client] : {std::pair{&o.quicOriginalId, true}, {&o.quicClientId, false},
        {&o.quicServerId, true}, {&o.quicRetryId, true}})
    {
        if (id->empty())
            continue;
        std::string raw;
        raw.reserve(id->size() / 2);
        for (size_t i = 0; i + 1 < id->size(); i += 2)
        {
            const auto digit = [](char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
            raw.push_back(static_cast<char>((digit((*id)[i]) << 4) | digit((*id)[i + 1])));
        }
        if (std::ranges::any_of(flow.indexedIds, [&](const auto& id)
            { return id.first == raw && id.second == client; }))
            continue;
        cidLengths_.set(raw.size());
        auto& entry = quicIds_[raw];
        ++entry.references;
        if (entry.owners.size() < 16)
            entry.owners.push_back({&flow, client});
        flow.indexedIds.emplace_back(std::move(raw), client);
    }
    quicBytes_ = quicBytes_ - before + flow.memory();
}

Engine::QuicFlow* Engine::findQuic(Bytes cid, bool& client) const
{
    if (cid.empty())
        return nullptr;
    const auto found = quicIds_.find(std::string_view(reinterpret_cast<const char*>(cid.data()), cid.size()));
    if (found == quicIds_.end() || found->second.references != 1 || found->second.owners.size() != 1)
        return nullptr;
    client = found->second.owners.front().client;
    return found->second.owners.front().flow;
}

void Engine::quicPath(QuicFlow& flow, const TcpPacket& packet, bool client, int64_t timestampUs)
{
    auto& o = flow.observation;
    const auto source = client ? packet.source : packet.destination;
    const auto destination = client ? packet.destination : packet.source;
    auto found = std::ranges::find_if(o.quicPaths, [&](const Observation::QuicPath& path)
        { return path.source == source && path.destination == destination; });
    flow.lastUs = o.lastUs = std::max(flow.lastUs, timestampUs);
    if (found != o.quicPaths.end())
    {
        // Existing paths change only counters; avoid walking retained handshake metadata per packet.
        found->lastUs = std::max(found->lastUs, timestampUs);
        ++found->packets;
        return;
    }
    const auto before = flow.memory();
    if (o.quicPaths.size() < 16 &&
        memory() + 4096 <= limits_.bytes)
    {
        o.quicPaths.push_back({source, destination, timestampUs, timestampUs, 1});
    }
    else
    {
        if (o.quicPathsDropped < UINT32_MAX)
            ++o.quicPathsDropped;
    }
    if (flow.observed)
        emit(o);
    quicBytes_ = quicBytes_ - before + flow.memory();
}

bool Engine::observeQuic(const TcpPacket& packet, int64_t timestampUs)
{
    const auto bytes = packet.payload;
    if (bytes.empty() || !(bytes[0] & 0x40))
        return false;
    bool client = false;
    QuicFlow* flow = nullptr;
    if (bytes[0] & 0x80)
    {
        const auto header = quicHeader(bytes);
        if (!header || header->initial() || header->retry())
            return false;
        flow = findQuic(header->destinationId, client);
        if (flow && flow->observation.quicVersion != header->version)
            flow = nullptr;
    }
    else
    {
        // Short headers omit CID length. Refuse collisions and ambiguous prefix matches.
        for (size_t length = 1; length <= 20 && length + 17 <= bytes.size(); ++length)
        {
            if (!cidLengths_[length])
                continue;
            const auto indexed = quicIds_.find(std::string_view(
                reinterpret_cast<const char*>(bytes.data() + 1), length));
            if (indexed != quicIds_.end() && indexed->second.references != 1)
                return false;
            bool candidateClient = false;
            if (auto* candidate = findQuic(bytes.subspan(1, length), candidateClient))
            {
                if (flow)
                    return false;
                flow = candidate;
                client = candidateClient;
            }
        }
    }
    if (!flow)
        return false;
    quicPath(*flow, packet, client, timestampUs);
    return true;
}
}
