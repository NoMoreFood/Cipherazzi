#include "Engine.h"
#include "Ipsec.h"
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>

namespace Cipherazzi
{
void IpsecConnections::publish(const Key& key, Flow& flow, const std::function<void(Observation)>& sink)
{
    auto evidence = std::make_shared<ProtocolEvidence>();
    evidence->fields = {{"ipsec_protocol", key.protocol == 50 ? "ESP" : "AH"},
        {"ipsec_spi", key.spi}, {"ipsec_last_sequence", flow.sequence}, {"ipsec_packets", flow.packets},
        {"ipsec_udp_encapsulation", flow.observation.udp},
        {"ipsec_visibility", "Packet headers only; algorithms and authenticity are not established"}};
    evidence->measure();
    flow.observation.application = std::move(evidence);
    flow.observation.state = "ipsec_headers_observed";
    flow.published = flow.observation.lastUs;
    sink(flow.observation);
}

void IpsecConnections::feed(const TransportPacket& packet, int64_t time, uint64_t& nextId, size_t budget,
    size_t limit, const std::function<void(Observation)>& sink)
{
    const Key key{packet.source, packet.destination, packet.ipsecSpi, packet.ipsecProtocol};
    auto found = flows_.find(key);
    if (found == flows_.end())
    {
        if (flows_.size() >= limit || memory() + 4096 > budget)
        {
            ++(flows_.size() >= limit ? counters_.flowLimit : counters_.reassemblyLimit);
            return;
        }
        auto& flow = flows_[key];
        auto& row = flow.observation;
        row.protocol = Observation::Protocol::Ipsec;
        row.flowId = ++nextId;
        row.firstUs = row.lastUs = time;
        row.source = packet.source;
        row.loopback = packet.loopback;
        row.destination = packet.destination;
        row.udp = packet.protocol == 17 && packet.ipsecProtocol == 50;
        flow.packets = 1;
        flow.sequence = packet.ipsecSequence;
        publish(key, flow, sink);
        return;
    }
    auto& flow = found->second;
    flow.observation.loopback |= packet.loopback;
    flow.observation.lastUs = std::max(time, flow.observation.lastUs);
    ++flow.packets;
    flow.sequence = packet.ipsecSequence;
    if (time - flow.published >= 5000000)
        publish(key, flow, sink);
}

void IpsecConnections::expire(int64_t time, bool all, int64_t idle, const std::function<void(Observation)>& sink)
{
    for (auto it = flows_.begin(); it != flows_.end();)
    {
        auto& flow = it->second;
        if (!all && time - flow.observation.lastUs <= idle)
        {
            ++it;
            continue;
        }
        publish(it->first, flow, sink);
        auto end = flow.observation;
        end.lifecycleOnly = true;
        end.endedUs = end.lastUs;
        end.closeReason = "IPsec observation window ended; association lifetime unknown";
        sink(std::move(end));
        it = flows_.erase(it);
    }
}

void IpsecAssociations::enrich(Observation& observation)
{
    if (observation.protocol != Observation::Protocol::Ipsec || !observation.application)
        return;
    const auto time = nowUs();
    if (time - refreshed_ >= 10000000)
    {
        // Enumerate in the storage worker, bounded in time frequency and retained associations.
        refreshed_ = time;
        entries_.clear();
        HANDLE engineHandle{};
        error_ = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engineHandle);
        std::unique_ptr<void, decltype(&FwpmEngineClose0)> engine(engineHandle, FwpmEngineClose0);
        HANDLE enumeration{};
        if (!error_)
            error_ = IPsecSaContextCreateEnumHandle0(engine.get(), nullptr, &enumeration);
        auto close = [&](void* handle) { IPsecSaContextDestroyEnumHandle0(engine.get(), handle); };
        std::unique_ptr<void, decltype(close)> enumerator(enumeration, close);
        for (unsigned page = 0; !error_ && page < 64; ++page)
        {
            IPSEC_SA_CONTEXT0** records{};
            UINT32 count{};
            error_ = IPsecSaContextEnum0(engine.get(), enumerator.get(), 64, &records, &count);
            auto release = [](IPSEC_SA_CONTEXT0** value) { FwpmFreeMemory0(reinterpret_cast<void**>(&value)); };
            std::unique_ptr<IPSEC_SA_CONTEXT0*, decltype(release)> owner(records, release);
            if (error_ || !count)
                break;
            for (UINT32 index = 0; index < count && entries_.size() < 4096; ++index)
                for (const auto* sa : {records[index]->inboundSa, records[index]->outboundSa})
                {
                    if (!sa || sa->saBundle.numSAs > 16)
                        continue;
                    Endpoint local, remote;
                    local.family = remote.family = sa->traffic.ipVersion == FWP_IP_VERSION_V6 ? 6 : 4;
                    if (local.family == 4)
                    {
                        const auto left = htonl(sa->traffic.localV4Address), right = htonl(sa->traffic.remoteV4Address);
                        std::memcpy(local.address.data(), &left, 4);
                        std::memcpy(remote.address.data(), &right, 4);
                    }
                    else
                    {
                        std::copy_n(sa->traffic.localV6Address, 16, local.address.begin());
                        std::copy_n(sa->traffic.remoteV6Address, 16, remote.address.begin());
                    }
                    if (local.family == 4 && sa->udpEncapsulation)
                    {
                        local.port = sa->udpEncapsulation->localUdpEncapPort;
                        remote.port = sa->udpEncapsulation->remoteUdpEncapPort;
                    }
                    for (UINT32 item = 0; item < sa->saBundle.numSAs && entries_.size() < 4096; ++item)
                    {
                        // Copy transform identifiers only; key blobs and endpoint identities are not accessed.
                        const auto& transform = sa->saBundle.saList[item];
                        const IPSEC_CIPHER_TRANSFORM0* cipher{};
                        const IPSEC_AUTH_TRANSFORM0* auth{};
                        switch (transform.saTransformType)
                        {
                        case IPSEC_TRANSFORM_AH:
                            if (transform.ahInformation) auth = &transform.ahInformation->authTransform;
                            break;
                        case IPSEC_TRANSFORM_ESP_AUTH:
                            if (transform.espAuthInformation) auth = &transform.espAuthInformation->authTransform;
                            break;
                        case IPSEC_TRANSFORM_ESP_AUTH_FW:
                            if (transform.espAuthFwInformation) auth = &transform.espAuthFwInformation->authTransform;
                            break;
                        case IPSEC_TRANSFORM_ESP_CIPHER:
                            if (transform.espCipherInformation)
                                cipher = &transform.espCipherInformation->cipherTransform;
                            break;
                        case IPSEC_TRANSFORM_ESP_AUTH_AND_CIPHER:
                            if (transform.espAuthAndCipherInformation)
                            {
                                cipher = &transform.espAuthAndCipherInformation->saCipherInformation.cipherTransform;
                                auth = &transform.espAuthAndCipherInformation->saAuthInformation.authTransform;
                            }
                            break;
                        default: break;
                        }
                        Entry entry;
                        const bool outbound = sa->saDirection == FWP_DIRECTION_OUTBOUND;
                        entry.source = outbound ? local : remote;
                        entry.destination = outbound ? remote : local;
                        entry.spi = transform.spi;
                        entry.protocol = transform.saTransformType == IPSEC_TRANSFORM_AH ? 51 : 50;
                        entry.fields = {{"ipsec_sa_source", "Windows Filtering Platform"},
                            {"ipsec_sa_observed_us", time}, {"ipsec_sa_context_id", records[index]->saContextId},
                            {"ipsec_sa_transform_type", transform.saTransformType},
                            {"ipsec_sa_mode", sa->traffic.trafficType == IPSEC_TRAFFIC_TYPE_TUNNEL ?
                                "Tunnel" : "Transport"}};
                        if (cipher)
                        {
                            const auto type = cipher->cipherTransformId.cipherType;
                            const auto config = cipher->cipherTransformId.cipherConfig;
                            entry.fields["ipsec_cipher_type"] = type;
                            entry.fields["ipsec_cipher_config"] = config;
                            entry.fields["ipsec_cipher"] = type == IPSEC_CIPHER_TYPE_DES ? "DES" :
                                type == IPSEC_CIPHER_TYPE_3DES ? "3DES" :
                                type >= IPSEC_CIPHER_TYPE_AES_128 && type <= IPSEC_CIPHER_TYPE_AES_256 ?
                                    "AES" : "Unknown";
                            entry.fields["ipsec_cipher_mode"] = config >= 6 && config <= 8 ? "GCM" :
                                config >= 1 && config <= 5 ? "CBC" : "Unknown";
                            entry.fields["ipsec_key_bits"] = type == IPSEC_CIPHER_TYPE_DES ? 56 :
                                type == IPSEC_CIPHER_TYPE_3DES ? 168 :
                                type >= IPSEC_CIPHER_TYPE_AES_128 && type <= IPSEC_CIPHER_TYPE_AES_256 ?
                                    128 + (type - IPSEC_CIPHER_TYPE_AES_128) * 64 : 0;
                        }
                        if (auth)
                        {
                            entry.fields["ipsec_auth_type"] = auth->authTransformId.authType;
                            entry.fields["ipsec_auth_config"] = auth->authTransformId.authConfig;
                            const auto config = auth->authTransformId.authConfig;
                            entry.fields["ipsec_authentication"] = config == IPSEC_AUTH_CONFIG_HMAC_MD5_96 ?
                                "HMAC-MD5-96" : config == IPSEC_AUTH_CONFIG_HMAC_SHA_1_96 ? "HMAC-SHA-1-96" :
                                config == IPSEC_AUTH_CONFIG_HMAC_SHA_256_128 ? "HMAC-SHA-256-128" :
                                config >= IPSEC_AUTH_CONFIG_GCM_AES_128 && config <= IPSEC_AUTH_CONFIG_GCM_AES_256 ?
                                    "AES-GCM" : "Unknown";
                        }
                        entries_.push_back(std::move(entry));
                    }
                }
            if (entries_.size() >= 4096 || page == 63)
            {
                error_ = ERROR_MORE_DATA;
                break;
            }
        }
        if (error_)
            entries_.clear();
    }

    // Match only a unique address, encapsulation, protocol, and SPI in the recorded Windows snapshot.
    auto evidence = std::make_shared<ProtocolEvidence>(*observation.application);
    const auto spi = evidence->fields.value("ipsec_spi", uint32_t{});
    const auto protocol = evidence->fields.value("ipsec_protocol", "") == "ESP" ? 50 : 51;
    const Entry* match{};
    for (const auto& entry : entries_)
        if (entry.spi == spi && entry.protocol == protocol && entry.source == observation.source &&
            entry.destination == observation.destination)
        {
            if (match)
            {
                match = nullptr;
                break;
            }
            match = &entry;
        }
    if (match)
    {
        evidence->fields.update(match->fields);
        evidence->fields["ipsec_sa_status"] =
            "Unique address, encapsulation, protocol, and SPI match in Windows snapshot";
    }
    else
        evidence->fields["ipsec_sa_status"] = error_ ? "Windows association metadata unavailable" :
            "No unique current Windows association";
    evidence->measure();
    observation.application = std::move(evidence);
}
}
