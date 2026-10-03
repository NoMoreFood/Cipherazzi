using System.Globalization;
using System.Text.Json;

namespace Cipherazzi.Data;

public sealed record ObservationProperty(string Category, string Name, string Value, string Evidence = "");

public sealed record FindingPolicy(int MinimumTls = 771, int MinimumDhBits = 2048, bool WarnMissingEms = true);

public static class ObservationDetails
{
    public static ConnectionRow Enrich(ConnectionRow row, Func<string, string> text)
    {
        var encoded = text("crypto_json");
        using var document = JsonDocument.Parse(encoded);
        var crypto = document.RootElement;
        string Json(string name) => Value(crypto, name);
        var protocol = Json("protocol") is { Length: > 0 } observedProtocol ? observedProtocol : "TLS";
        string Flag(string name) => Json(name) switch { "1" => "Observed", "0" => "Not present", _ => "Not observed" };
        var tls13 = row.Tls is "TLS 1.3" or "DTLS 1.3";
        var endpointEvidence = crypto.TryGetProperty("endpoint_confirmations", out var confirmations) &&
            confirmations.ValueKind == JsonValueKind.Array ? confirmations.EnumerateArray().ToArray() : [];
        string EndpointValues(string field) => string.Join(", ", endpointEvidence
            .Select(value => Value(value, field)).Where(value => value.Length > 0).Distinct());
        var values = new Dictionary<string, string>
        {
            ["Protocol"] = protocol, ["Classification"] = Json("classification"),
            ["SampleBytes"] = Json("sample_bytes"), ["SampleEntropy"] = double.TryParse(Json("sample_entropy"),
                CultureInfo.InvariantCulture, out var entropy) ?
                entropy.ToString("F3", CultureInfo.CurrentCulture) : "",
            ["SampleDirection"] = Json("sample_direction"), ["ClassificationLimit"] = Json("classification_limit"),
            ["SshSelectionEvidence"] = Json("ssh_selection_evidence"), ["SshVisibility"] = Json("ssh_visibility"),
            ["Transport"] = Json("transport") is { Length: > 0 } transport ? transport : "TCP",
            ["QuicVersion"] = Json("quic_version") switch { "1" => "v1", "1798521807" => "v2", var value => value },
            ["QuicOriginalId"] = Json("quic_original_dcid"), ["QuicClientId"] = Json("quic_client_scid"),
            ["QuicServerId"] = Json("quic_server_scid"), ["QuicVisibility"] = Json("quic_visibility"),
            ["QuicPathEvidence"] = Json("quic_path_evidence"), ["QuicPathsDropped"] = Json("quic_paths_dropped"),
            ["DtlsCookie"] = Json("dtls_cookie_exchange") == "True" ? "Observed" : "Not observed",
            ["DtlsVisibility"] = Json("dtls_visibility"),
            ["QuicRetry"] = Json("quic_retry") == "True" ? "Observed" : "Not observed",
            ["EndpointProvider"] = EndpointValues("provider"),
            ["EndpointSignature"] = EndpointValues("handshake_signature"),
            ["EndpointRawAlgorithm"] = EndpointValues("algorithm"), ["EndpointRawMode"] = EndpointValues("mode"),
            ["EndpointRawKeyBits"] = EndpointValues("key_bits"),
            ["EndpointAuthClass"] = EndpointValues("authentication_class"),
            ["EndpointLocalSignature"] = EndpointValues("local_handshake_signature"),
            ["EndpointLocalAuthClass"] = EndpointValues("local_authentication_class"),
            ["EndpointAlpn"] = EndpointValues("selected_alpn"),
            ["EndpointPeerVerification"] = string.Join(", ", endpointEvidence.Select(value =>
                Value(value, "peer_verified") switch { "1" => "Reported verified", "0" => "Reported unverified", _ => "Not reported" }).Distinct()),
            ["Time"] = row.Time, ["Source"] = row.Source, ["Destination"] = row.Destination,
            ["Peer"] = row.Sni is "" or "—" ? row.Destination : row.Sni,
            ["Tls"] = row.Tls, ["Cipher"] = row.Cipher, ["Sni"] = row.Sni, ["Process"] = row.Process,
            ["State"] = row.State, ["Group"] = text("group_name"), ["GroupClass"] = Json("group_class"),
            ["GroupStatus"] = Json("group_standardization"), ["GroupComponents"] = Json("group_components"),
            ["GroupReference"] = Json("group_reference"), ["ClassificationRules"] = Json("classification_rule_version"),
            ["NegotiationStages"] = crypto.TryGetProperty("negotiation_stages", out var stages) &&
                stages.ValueKind == JsonValueKind.Array ? stages.GetArrayLength().ToString() : "",
            ["NegotiationDropped"] = Json("negotiation_stages_dropped"),
            ["NegotiationTruncated"] = Json("negotiation_history_truncated") switch
            {
                "True" => "Yes", "False" => "No", _ => "Not recorded"
            },
            ["KeyExchange"] = text("key_exchange"), ["Encryption"] = text("encryption"),
            ["Mode"] = Json("encryption_mode"), ["KeyBits"] = text("key_bits"),
            ["Hash"] = text("hash_name"), ["RecordMac"] = Json("record_mac"),
            ["PrfHash"] = Json("prf_hash"), ["HkdfHash"] = Json("hkdf_hash"),
            ["Authentication"] = text("authentication"),
            ["Signature"] = tls13 ? "Encrypted" : Json("handshake_signature"),
            ["ClientSignature"] = tls13 ? "Encrypted" : Json("client_handshake_signature"),
            ["Psk"] = text("psk_mode"), ["PskIndex"] = Json("selected_psk_index"),
            ["PskOffers"] = Json("psk_offers"), ["PskModes"] = Json("offered_psk_modes"),
            ["EarlyData"] = Flag("early_data_offered"), ["EarlyAccepted"] = Json("early_data_accepted"),
            ["Ems"] = tls13 ? "Not applicable" : Flag("ems_selected"),
            ["EmsOffered"] = Flag("ems_offered"), ["Renegotiation"] = tls13 ? "Not applicable" :
                Flag("secure_renegotiation"), ["Ticket"] = Flag("session_ticket_offered"),
            ["Compression"] = Json("compression_method") == "0" ? "None" : Json("compression_method"),
            ["Downgrade"] = Json("downgrade_marker"), ["Resumption"] = Json("resumption"),
            ["ClientAuth"] = Json("client_authentication"), ["Certificate"] = text("certificate_sha256"),
            ["CertificateVisibility"] = Json("certificate_visibility"),
            ["OfferedGroups"] = Json("offered_groups"), ["OfferedSignatures"] = Json("offered_signatures"),
            ["OfferedCertificateSignatures"] = Json("offered_certificate_signatures"),
            ["OfferedKeyShares"] = Json("offered_key_shares"), ["OfferedCiphers"] = text("offered_ciphers"),
            ["OfferedVersions"] = text("offered_versions"), ["OfferedAlpn"] = text("offered_alpn"),
            ["SelectedAlpn"] = tls13 ? "Encrypted" : text("selected_alpn"),
            ["ClientExtensions"] = Json("client_extensions"), ["ServerExtensions"] = Json("server_extensions"),
            ["Ech"] = text("ech_offered") == "1" ? "Outer hello; ECH offered / possibly GREASE" : "Not observed",
            ["Visibility"] = Json("client_hello_visibility"), ["Confirmation"] = Json("handshake_confirmation"),
            ["Evidence"] = Json("evidence_source") + (endpointEvidence.Length > 0 ? " + endpoint adapter" : ""),
            ["DhBits"] = Json("dh_parameter_bits"),
            ["ClientHello"] = At(Json("client_hello_us")), ["ServerHello"] = At(Json("server_hello_us")),
            ["Retry"] = text("retry_seen") == "1" ? "Observed" : "Not observed",
            ["RetryTime"] = At(Json("retry_us")), ["RetryGroup"] = Json("retry_group"),
            ["Alert"] = text("alert"), ["AlertSide"] = Json("alert_sender"), ["AlertTime"] = At(Json("alert_us")),
            ["AlertLevel"] = Json("alert_level") switch { "1" => "Warning", "2" => "Fatal", _ => "" },
            ["Ended"] = At(text("ended_us")), ["Termination"] = text("close_reason"),
            ["SourcePid"] = text("source_pid"), ["ProcessPath"] = text("source_path"),
            ["ProcessEvidence"] = text("source_evidence"), ["DestinationPid"] = text("destination_pid"),
            ["Computer"] = text("computer_name"),
            ["ClientOwner"] = Account("source"), ["ServerOwner"] = Account("destination"),
            ["ClientAccount"] = text("source_account"), ["ClientDomain"] = text("source_account_domain"),
            ["ClientSid"] = text("source_account_sid"), ["ServerAccount"] = text("destination_account"),
            ["ServerDomain"] = text("destination_account_domain"), ["ServerSid"] = text("destination_account_sid"),
            ["ServerProcess"] = text("destination_process"), ["ServerPath"] = text("destination_path"),
            ["ServerProcessEvidence"] = text("destination_evidence"), ["Note"] = text("detail"),
            ["Run"] = text("run_id"), ["Flow"] = text("flow_id"), ["TlsNumber"] = text("tls_version")
        };
        string Account(string side)
        {
            var account = text(side + "_account");
            if (account.Length == 0)
                return text(side + "_account_sid") is { Length: > 0 } sid ? sid + " (name unavailable)" : "";
            var domain = text(side + "_account_domain");
            return domain.Length == 0 ? account : domain + "\\" + account;
        }
        values["HelloLatency"] = double.TryParse(text("hello_latency_us"), CultureInfo.InvariantCulture,
            out var microseconds) ? (microseconds / 1000).ToString("N3", CultureInfo.CurrentCulture) + " ms" : "";

        // Findings for other protocols assess what was selected or used; offered algorithms are not included.
        string Component(string name, string component) => crypto.TryGetProperty(name, out var parent) &&
            parent.ValueKind == JsonValueKind.Object ? Value(parent, component) : "";

        // Reading a property name allocates it, so rows without Kerberos evidence skip the enumeration.
        values["KerberosEncryption"] = !encoded.Contains("\"krb_", StringComparison.Ordinal) ? "" :
            string.Join(", ", crypto.EnumerateObject()
                .Where(field => field.Name.StartsWith("krb_", StringComparison.Ordinal) &&
                    field.Value.ValueKind == JsonValueKind.Object)
                .SelectMany(field => field.Value.EnumerateObject())
                .Where(component => component.Name == "encryption" ||
                    component.Name.EndsWith("_encryption", StringComparison.Ordinal))
                .Select(component => component.Value.ToString()).Distinct());
        values["NtlmResponse"] = Component("ntlm_authenticate", "nt_response");
        values["LmResponse"] = Component("ntlm_authenticate", "lm_response");
        values["SmbLegacyFormat"] = Json("smb_legacy_response_format");
        values["RdpSecurity"] = Json("rdp_selected_protocol") == "0" ||
            Json("rdp_server_encryption_method") is not ("" or "None") ? "Standard" : "";
        values["TdsEncryption"] = Json("tds_negotiated_encryption");
        values["TdsLogin"] = Json("tds_unencrypted_login_observed") == "True" ? "Unencrypted" : "";
        values["Findings"] = string.Join("; ", Findings(values, new FindingPolicy()));
        var certificates = new[] { "server_certificates", "client_certificates" }
            .Where(name => crypto.TryGetProperty(name, out _))
            .SelectMany(name => crypto.GetProperty(name).EnumerateArray()
                .Select((value, index) => $"{(name.StartsWith("server") ? "Server" : "Client")} {index + 1}|{value}"))
            .ToArray();
        var endpointCertificates = endpointEvidence.SelectMany(evidence => new[]
            { "server_certificates", "client_certificates" }.Where(name => evidence.TryGetProperty(name, out _))
            .SelectMany(name => evidence.GetProperty(name).EnumerateArray().Select((hash, index) =>
                $"Endpoint {(name.StartsWith("server") ? "server" : "client")} {index + 1}|{hash}")));
        certificates = certificates.Concat(endpointCertificates).Distinct().ToArray();
        return row with { Values = values, PropertyFactory = () => BuildProperties(values, encoded), Certificates = certificates };
    }

    private static string Value(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
            return "";
        return value.ValueKind == JsonValueKind.Array ?
            string.Join(", ", value.EnumerateArray().Select(item => item.ToString())) : value.ToString();
    }

    private static string At(string value) => long.TryParse(value, out var timestamp) && timestamp != 0 ?
        DateTimeOffset.FromUnixTimeMilliseconds(timestamp / 1000).ToLocalTime()
            .ToString("yyyy-MM-dd HH:mm:ss.fff zzz") : "Not observed";

    private static List<ObservationProperty> BuildProperties(Dictionary<string, string> values, string encoded)
    {
        // Expand negotiation and endpoint properties only for the observation being inspected.
        using var document = JsonDocument.Parse(encoded);
        var crypto = document.RootElement;
        var stages = crypto.TryGetProperty("negotiation_stages", out var history) ? history : default;
        var endpointEvidence = crypto.TryGetProperty("endpoint_confirmations", out var confirmations) &&
            confirmations.ValueKind == JsonValueKind.Array ? confirmations.EnumerateArray().ToArray() : [];
        var properties = new List<ObservationProperty>();
        foreach (var definition in ColumnDefinitions.All)
        {
            var protocol = values.GetValueOrDefault("Protocol", "TLS");
            if (protocol is not "TLS" and not "DTLS" && definition.Category is "QUIC" or "PQC evidence" or
                "Client offers" or "Session behavior" or "Extensions" or "Certificates" or "Endpoint authentication")
                continue;
            if (protocol is not "TLS" and not "DTLS" && definition.Name is "ClientHello" or "ServerHello" or
                "HelloLatency" or "Retry" or "RetryTime" or "RetryGroup" or "Alert" or "AlertLevel" or "AlertSide" or
                "AlertTime" or "Signature" or
                "ClientSignature" or "ClientAuth" or "Compression" or "Visibility" or "PrfHash" or "HkdfHash" or
                "Ech" or "SelectedAlpn" or "Hash")
                continue;
            if (protocol != "Unknown" && definition.Category == "Raw classification" ||
                protocol != "DTLS" && definition.Category == "DTLS" ||
                values.GetValueOrDefault("Transport") != "QUIC" && definition.Category == "QUIC" ||
                protocol != "SSH" && definition.Category == "SSH" ||
                protocol != "Unknown" && definition.Category == "Raw endpoint")
                continue;
            var value = values.GetValueOrDefault(definition.Name, "");
            var category = protocol == "SSH" && definition.Category == "Server selection" ?
                "SSH negotiation" : definition.Category;
            var caption = protocol == "SSH" ? definition.Name switch
            {
                "Cipher" => "Cipher", "Authentication" => "Host-key algorithm", _ => definition.Caption
            } : definition.Caption;
            properties.Add(new(category, caption, value.Length == 0 ? "Not observed" : value,
                protocol == "SSH" && definition.Name == "KeyExchange" ? Value(crypto, "ssh_selection_evidence") :
                    definition.Description));
        }

        if (values.GetValueOrDefault("Protocol") == "DTLS")
        {
            string Profile(int number) => $"0x{number:X4} (" + (number switch
            {
                1 => "SRTP_AES128_CM_HMAC_SHA1_80", 2 => "SRTP_AES128_CM_HMAC_SHA1_32",
                5 => "SRTP_NULL_HMAC_SHA1_80", 6 => "SRTP_NULL_HMAC_SHA1_32",
                7 => "SRTP_AEAD_AES_128_GCM", 8 => "SRTP_AEAD_AES_256_GCM", _ => "Unknown profile"
            }) + ")";
            if (crypto.TryGetProperty("srtp_offered_profiles", out var profiles) &&
                profiles.ValueKind == JsonValueKind.Array && profiles.GetArrayLength() > 0)
                properties.Add(new("DTLS-SRTP", "Offered profiles",
                    string.Join(", ", profiles.EnumerateArray().Select(profile => Profile(profile.GetInt32()))),
                    "Client offers do not establish a selected protection profile or media use."));
            if (crypto.TryGetProperty("srtp_selected_profile", out var selected) &&
                selected.ValueKind == JsonValueKind.Number)
                properties.Add(new("DTLS-SRTP", "Server-selected profile", Profile(selected.GetInt32()),
                    "Visible server selection; authentication and media use are not established."));
        }

        // Display both initial SSH preference lists and directional selections with their role evidence.
        if (crypto.TryGetProperty("ssh_peers", out var peers) && peers.ValueKind == JsonValueKind.Array)
        {
            var rolesKnown = Value(crypto, "ssh_roles_known") == "True";
            var index = 0;
            foreach (var peer in peers.EnumerateArray())
            {
                var category = rolesKnown ? index == 0 ? "SSH client offers" : "SSH server offers" :
                    index == 0 ? "SSH source offers" : "SSH destination offers";
                foreach (var field in peer.EnumerateObject())
                    properties.Add(new(category, Insights.Label(field.Name), field.Value.ToString(),
                        "Observed initial SSH messages. Roles require captured TCP connection setup."));
                index++;
            }
            if (crypto.TryGetProperty("ssh_selection", out var selection))
                foreach (var field in selection.EnumerateObject())
                    properties.Add(new("SSH negotiation", Insights.Label(field.Name),
                        field.Value.ToString() is { Length: > 0 } selected ? selected : "Not observed",
                        Value(crypto, "ssh_selection_evidence")));
            foreach (var field in new[] { "ssh_host_key_type", "ssh_host_key_sha256", "ssh_host_key_bits",
                "ssh_exchange_signature", "ssh_host_key_trust" })
                if (Value(crypto, field) is { Length: > 0 } value)
                    properties.Add(new("SSH host key", Insights.Label(field), value,
                        "Observed public key metadata; SHA-256 is hexadecimal. Signature validity and host trust are unverified."));
            if (crypto.TryGetProperty("ssh_host_certificate", out var certificate) &&
                certificate.ValueKind == JsonValueKind.Object)
                foreach (var field in certificate.EnumerateObject())
                {
                    var value = field.Value.ToString();
                    if (field.Value.ValueKind == JsonValueKind.Array)
                        value = field.Value.GetArrayLength() == 0 ?
                            field.Name == "principals" ? "Any principal" : "None" :
                            string.Join(", ", field.Value.EnumerateArray().Select(item => item.ToString()));
                    if (field.Name is "valid_after" or "valid_before" && field.Value.ValueKind == JsonValueKind.Number &&
                        field.Value.TryGetUInt64(out var seconds))
                        value = seconds == ulong.MaxValue ? "No expiry" : seconds <= 253402300799 ?
                            DateTimeOffset.FromUnixTimeSeconds((long)seconds).ToString("yyyy-MM-dd HH:mm:ss 'UTC'") :
                            $"{seconds} seconds since Unix epoch";
                    properties.Add(new("SSH host certificate", Insights.Label(field.Name), value,
                        "Public certificate metadata. CA signature validity, certificate validity, " +
                        "and host trust are unverified."));
                }
        }

        // Protocol fields retain their packet provenance without implying authenticated tunnel completion.
        if (values.GetValueOrDefault("Protocol") is "WireGuard" or "IKEv2" or "OpenVPN")
            foreach (var field in crypto.EnumerateObject())
            {
                if (field.Name.StartsWith("wireguard_", StringComparison.Ordinal) ||
                    field.Name.StartsWith("ike_", StringComparison.Ordinal) ||
                    field.Name.StartsWith("openvpn_", StringComparison.Ordinal) ||
                    field.Name.StartsWith("vpn_", StringComparison.Ordinal))
                {
                    if (field.Name == "openvpn_tls" && field.Value.ValueKind == JsonValueKind.Object)
                        foreach (var inner in field.Value.EnumerateObject())
                            properties.Add(new("OpenVPN control TLS", Insights.Label(inner.Name),
                                inner.Value.ToString(), "Visible control-channel TLS; data-channel cipher is unverified."));
                    else
                        properties.Add(new("VPN evidence", Insights.Label(field.Name),
                            field.Value.ToString(), "Observed public protocol fields; authentication is unverified."));
                }
            }

        foreach (var field in crypto.EnumerateObject())
        {
            var category = field.Name.StartsWith("smb_", StringComparison.Ordinal) ? "SMB negotiation" :
                field.Name.StartsWith("roce_", StringComparison.Ordinal) ? "RoCE transport" :
                field.Name.StartsWith("rdp_", StringComparison.Ordinal) ? "RDP negotiation" :
                field.Name.StartsWith("tds_", StringComparison.Ordinal) ?
                field.Name == "tds_packet_framing_observed" ? "TDS framing" : "TDS negotiation" :
                field.Name.StartsWith("krb_", StringComparison.Ordinal) ? "Kerberos exchange" :
                field.Name.StartsWith("ntlm_", StringComparison.Ordinal) ? "NTLM authentication" :
                field.Name.StartsWith("spnego_", StringComparison.Ordinal) ? "SPNEGO negotiation" : "";
            if (category.Length == 0)
                continue;

            // Keep RDMA payload protection separate from SMB message protection in the inspector.
            if (field.Name is "smb_rdma_read_transform" or "smb_rdma_write_transform" &&
                field.Value.ValueKind == JsonValueKind.Object)
            {
                var operation = field.Name == "smb_rdma_read_transform" ? "read" : "write";
                foreach (var component in field.Value.EnumerateObject())
                    properties.Add(new($"SMB RDMA {operation}", Insights.Label(component.Name), component.Value.ToString(),
                        "Observed RDMA payload protection metadata. Signatures are not verified; payload protection " +
                        "and SMB message protection are separate evidence."));
                continue;
            }
            if (field.Name is "smb_direct_client_negotiation" or "smb_direct_server_negotiation" &&
                field.Value.ValueKind == JsonValueKind.Object)
            {
                var side = field.Name.Contains("_client_", StringComparison.Ordinal) ? "client" : "server";
                foreach (var limit in field.Value.EnumerateObject())
                    properties.Add(new($"SMB Direct {side}", Insights.Label(limit.Name), limit.Value.ToString(),
                        "Observed RDMA transport negotiation. Transport limits and versions do not establish " +
                        "SMB signing, encryption, authentication, or connection completion."));
                continue;
            }
            if (field.Name.StartsWith("tds_", StringComparison.Ordinal) &&
                field.Value.ValueKind == JsonValueKind.Object)
            {
                var side = field.Name.EndsWith("_prelogin", StringComparison.Ordinal) ?
                    field.Name[4..^9].Replace('_', ' ') : "peer";
                foreach (var option in field.Value.EnumerateObject())
                {
                    var optionValue = option.Value.ToString();
                    if (option.Name == "encryption" && option.Value.ValueKind == JsonValueKind.Number &&
                        option.Value.TryGetByte(out var encryption))
                        optionValue = (encryption & 0x7f) switch
                        {
                            0 => "Available, off", 1 => "Available, on", 2 => "Not supported", 3 => "Required",
                            _ => $"Unknown (0x{encryption:X2})"
                        };
                    properties.Add(new($"TDS {side} PRELOGIN", Insights.Label(option.Name), optionValue,
                        "Public PRELOGIN negotiation. Encryption settings do not establish TLS completion " +
                        "or SQL authentication."));
                }
                continue;
            }

            // Expand Kerberos and NTLM evidence into one row per component; nothing here verifies authentication.
            if (field.Name.StartsWith("krb_", StringComparison.Ordinal) ||
                field.Name.StartsWith("ntlm_", StringComparison.Ordinal))
            {
                var message = Insights.Label(field.Name);
                if (field.Value.ValueKind == JsonValueKind.Object)
                    foreach (var component in field.Value.EnumerateObject())
                        properties.Add(new(category, $"{message}: {Insights.Label(component.Name)}",
                            component.Value.ValueKind == JsonValueKind.Array ?
                                string.Join(", ", component.Value.EnumerateArray().Select(item => item.ToString())) :
                                component.Value.ToString(),
                            "Observed cleartext protocol fields. Encryption types, flags, and attributes do not " +
                            "establish successful authentication; names, challenges, and responses are not retained."));
                else
                    properties.Add(new(category, message, field.Value.ToString()));
                continue;
            }
            var value = field.Value.ToString();
            string RdpSecurity(uint selected) => selected switch
            {
                0 => "Standard RDP security", 1 => "TLS", 2 => "CredSSP (HYBRID)",
                4 => "RDSTLS", 8 => "CredSSP with early authorization (HYBRID_EX)",
                16 => "RDS AAD authentication", _ => $"Unknown (0x{selected:X8})"
            };
            if (field.Name is "rdp_selected_protocol" or "rdp_requested_protocols" &&
                field.Value.ValueKind == JsonValueKind.Number && field.Value.TryGetUInt32(out var selected))
                value = field.Name == "rdp_selected_protocol" || selected == 0 ? RdpSecurity(selected) :
                    string.Join(", ", new uint[] { 1, 2, 4, 8, 16 }.Where(flag => (selected & flag) != 0)
                        .Select(RdpSecurity).Concat((selected & ~31u) != 0 ?
                            [RdpSecurity(selected & ~31u)] : []));
            else if (field.Name == "rdp_failure_code" && field.Value.ValueKind == JsonValueKind.Number &&
                field.Value.TryGetUInt32(out var failure))
                value = failure switch
                {
                    1 => "TLS required by server", 2 => "TLS disallowed by server", 3 => "Server certificate unavailable",
                    4 => "Inconsistent security protocols", 5 => "CredSSP required by server",
                    6 => "TLS with client certificate required", 7 => "Entra authentication required by server",
                    _ => $"Unknown (0x{failure:X8})"
                };

            // Resolved outcomes state how they were derived instead of sharing the description of fields as sent.
            properties.Add(new(category, Insights.Label(field.Name), value, field.Name switch
            {
                "tds_negotiated_encryption" =>
                    "Resolved from both PRELOGIN encryption settings. Login only leaves traffic after the login " +
                    "unencrypted, and None leaves the login unencrypted as well. A negotiated outcome does not " +
                    "establish TLS completion or SQL authentication.",
                "tds_unencrypted_login_observed" =>
                    "A LOGIN7 packet was sent outside TLS. Its contents are not read or retained.",
                "smb_legacy_selected_dialect" =>
                    "The client's offered dialect at the index the server selected. SMB1 selections do not " +
                    "establish authentication, signing, or encryption.",
                _ => "Observed protocol fields. Capabilities and selections do not establish successful " +
                    "authentication; an SMB encrypted transform is separate evidence of encrypted framing, " +
                    "not peer trust."
            }));
        }

        // Visible connection IDs link paths without proving encrypted path validation.
        if (crypto.TryGetProperty("quic_paths", out var paths) && paths.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var path in paths.EnumerateArray())
            {
                var category = $"QUIC path {++index:00}";
                properties.Add(new(category, "Client", Value(path, "source_address") + ":" +
                    Value(path, "source_port")));
                properties.Add(new(category, "Server", Value(path, "destination_address") + ":" +
                    Value(path, "destination_port")));
                properties.Add(new(category, "First observed", At(Value(path, "first_us"))));
                properties.Add(new(category, "Last observed", At(Value(path, "last_us"))));
                properties.Add(new(category, "Packets", Value(path, "packets"),
                    "Visible connection ID association; encrypted path validation is unverified."));
            }
        }

        // Keep every retained hello's wire-order offers separate from the final selection.
        if (stages.ValueKind == JsonValueKind.Array)
        {
            string Id(JsonElement element, string name) => element.TryGetProperty(name, out var value) &&
                value.ValueKind == JsonValueKind.Number && value.TryGetUInt16(out var number) ? $"0x{number:X4}" : "";
            string Ids(JsonElement element, string name)
            {
                if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
                    return "";
                return value.GetArrayLength() == 0 ? "None" : string.Join(", ", value.EnumerateArray()
                    .Select(item => $"0x{item.GetUInt16():X4}"));
            }
            foreach (var stage in stages.EnumerateArray())
            {
                var type = Value(stage, "type");
                var ordinal = Value(stage, "ordinal").PadLeft(2, '0');
                var category = $"Negotiation {ordinal} · {type}";
                void Add(string name, string value, string evidence = "") => properties.Add(new(category, name,
                    value.Length == 0 ? "Not observed" : value, evidence));
                Add("Observed", At(Value(stage, "timestamp_us")), "Time the complete handshake message was observed.");
                Add("Handshake bytes", Value(stage, "handshake_bytes"),
                    values.GetValueOrDefault("Protocol") == "DTLS" ?
                        "Includes the twelve-byte DTLS handshake header; excludes record headers." :
                        "Includes the four-byte handshake header; excludes TLS record headers.");
                Add("Legacy version", Id(stage, "legacy_version"));
                Add("Extension IDs", Ids(stage, "extension_ids"), "Extension identifiers in wire order.");
                if (type == "ClientHello")
                {
                    Add("SNI", Value(stage, "sni"));
                    Add("ECH indication", Value(stage, "ech_offered") is "True" or "1" ?
                        "Outer hello; ECH offered / possibly GREASE" : "Not observed");
                    Add("ALPN offers", Value(stage, "alpn"));
                    Add("Supported version IDs", Ids(stage, "offered_version_ids"));
                    Add("Cipher suite IDs", Ids(stage, "cipher_ids"));
                    Add("Supported group IDs", Ids(stage, "group_ids"));
                    Add("Signature algorithm IDs", Ids(stage, "signature_ids"));
                    Add("Certificate signature IDs", Ids(stage, "certificate_signature_ids"));
                }
                else
                {
                    Add("Selected version", Id(stage, "selected_version"));
                    Add("Selected cipher ID", Id(stage, "cipher_id"));
                    Add(type == "HelloRetryRequest" ? "Requested group ID" : "Selected group ID",
                        Id(stage, "selected_group_id"));
                }
                if (stage.TryGetProperty("key_shares", out var shares) && shares.ValueKind == JsonValueKind.Array)
                    Add("Key shares", shares.GetArrayLength() == 0 ? "None" :
                        string.Join(", ", shares.EnumerateArray().Select(share =>
                        $"{Id(share, "group_id")} ({Value(share, "bytes")} bytes)")),
                        "Group IDs and encoded key-exchange lengths in wire order; key material is not retained.");
            }
        }
        // Keep endpoint authentication results and their provenance separate from visible packet selections.
        for (var index = 0; index < endpointEvidence.Length; index++)
        {
            var evidence = endpointEvidence[index];
            var category = $"Endpoint evidence {index + 1}";
            if (Value(evidence, "protocol") == "Raw")
            {
                foreach (var field in new[] { "provider", "success", "match", "pid", "process_started_us",
                    "timestamp_us", "algorithm", "mode", "key_bits" })
                    properties.Add(new(category, Insights.Label(field), field.EndsWith("_us") ?
                        At(Value(evidence, field)) : Value(evidence, field),
                        "Public encryption metadata reported by the matched process. " +
                        "The algorithm is not inferred from ciphertext."));
                continue;
            }
            foreach (var (name, field) in new[]
            {
                ("Provider", "provider"), ("Reported success", "success"), ("Match", "match"),
                ("Process ID", "pid"), ("Process started", "process_started_us"), ("Local role", "local_role"),
                ("Event ID", "event_id"), ("Reported at", "timestamp_us"),
                ("Peer handshake signature", "handshake_signature"), ("Peer signature scheme ID", "handshake_signature_id"),
                ("Local handshake signature", "local_handshake_signature"),
                ("Local signature scheme ID", "local_handshake_signature_id"),
                ("Local authentication classification", "local_authentication_class"),
                ("Authentication classification", "authentication_class"), ("Selected ALPN", "selected_alpn")
            })
                properties.Add(new(category, name, field.EndsWith("_us") ? At(Value(evidence, field)) :
                    Value(evidence, field), "Public result reported by the endpoint adapter; matched to the captured socket and process lifetime."));
            properties.Add(new(category, "Peer verification", Value(evidence, "peer_verified") switch
            {
                "1" => "Endpoint reported verified", "0" => "Endpoint reported unverified", _ => "Not reported"
            }, "Collector does not independently validate the endpoint's trust policy."));
        }
        return properties;
    }

    public static IEnumerable<string> Findings(IReadOnlyDictionary<string, string> values, FindingPolicy policy)
    {
        var tls = int.TryParse(values.GetValueOrDefault("TlsNumber"), out var number) ? number : 0;
        if (tls != 0 && tls < policy.MinimumTls)
            yield return "Protocol below configured minimum";
        var encryption = values.GetValueOrDefault("Encryption", "");
        if (encryption is "NULL" or "RC4_128" or "3DES_EDE" or "DES40" or "DES_CBC")
            yield return "Legacy or null encryption selected";
        if (values.GetValueOrDefault("KeyExchange") == "RSA")
            yield return "Static RSA key exchange selected";
        if (values.GetValueOrDefault("Authentication") == "Anonymous")
            yield return "Anonymous authentication selected";
        if (int.TryParse(values.GetValueOrDefault("DhBits"), out var bits) && bits < policy.MinimumDhBits)
            yield return "DH parameter size below configured minimum";
        if (tls == 771 && policy.WarnMissingEms && values.GetValueOrDefault("Ems") == "Not present")
            yield return "Extended master secret not selected";
        if (values.GetValueOrDefault("Compression") is { Length: > 0 } compression && compression != "None")
            yield return "TLS compression selected";
        if (values.GetValueOrDefault("Protocol") == "SSH")
        {
            if (values.GetValueOrDefault("KeyExchange") == "diffie-hellman-group1-sha1")
                yield return "Legacy SSH key exchange selected";
            if (values.GetValueOrDefault("Authentication") is "ssh-rsa" or "ssh-dss")
                yield return "Legacy SSH host-key signature selected";
        }
        if (values.GetValueOrDefault("AlertLevel") == "Fatal")
            yield return "Plaintext fatal alert observed";

        // These conditions are fixed: each reflects a deprecated mechanism or the absence of encryption.
        if (values.GetValueOrDefault("KerberosEncryption", "").Split(", ").Any(type =>
            type.StartsWith("rc4", StringComparison.Ordinal) || type.StartsWith("des", StringComparison.Ordinal)))
            yield return "Legacy Kerberos encryption observed";
        if (values.GetValueOrDefault("NtlmResponse", "").StartsWith("NTLMv1", StringComparison.Ordinal))
            yield return "NTLMv1 response observed";
        if (values.GetValueOrDefault("LmResponse") == "LM")
            yield return "LM response observed";
        if (values.GetValueOrDefault("SmbLegacyFormat") is { Length: > 0 })
            yield return "SMB1 dialect selected";
        if (values.GetValueOrDefault("RdpSecurity") == "Standard")
            yield return "Standard RDP Security selected";
        if (values.GetValueOrDefault("TdsLogin") == "Unencrypted")
            yield return "Unencrypted TDS login observed";
        else if (values.GetValueOrDefault("TdsEncryption") == "None")
            yield return "Unencrypted TDS session negotiated";
        else if (values.GetValueOrDefault("TdsEncryption") == "Login only")
            yield return "Login-only TDS encryption negotiated";
    }
}

public sealed record ColumnDefinition(string Name, string Caption, string Category, int Width,
    bool Visible = false, string Description = "");

public static class ColumnDefinitions
{
    public static readonly ColumnDefinition[] All =
    [
        new("Peer", "Server / peer", "Connection", 170, true,
            "Observed server name, or destination address when a name is unavailable."),
        new("Transport", "Transport", "Connection", 75),
        new("QuicVersion", "QUIC version", "QUIC", 100),
        new("QuicOriginalId", "Original destination ID", "QUIC", 250),
        new("QuicClientId", "Client source ID", "QUIC", 220),
        new("QuicServerId", "Server source ID", "QUIC", 220),
        new("QuicRetry", "QUIC Retry", "QUIC", 100),
        new("QuicVisibility", "QUIC visibility", "QUIC", 350),
        new("QuicPathEvidence", "Path association evidence", "QUIC", 350),
        new("QuicPathsDropped", "Unretained paths", "QUIC", 145),
        new("DtlsCookie", "Cookie exchange", "DTLS", 150),
        new("DtlsVisibility", "DTLS visibility", "DTLS", 350),
        new("EndpointProvider", "Endpoint provider", "Endpoint authentication", 200),
        new("EndpointSignature", "Peer endpoint signature", "Endpoint authentication", 180),
        new("EndpointLocalSignature", "Local endpoint signature", "Endpoint authentication", 180),
        new("EndpointLocalAuthClass", "Local endpoint authentication class", "Endpoint authentication", 220),
        new("EndpointAuthClass", "Endpoint authentication class", "Endpoint authentication", 200),
        new("EndpointAlpn", "Endpoint selected ALPN", "Endpoint authentication", 160),
        new("EndpointPeerVerification", "Endpoint peer verification", "Endpoint authentication", 220),
        new("Time", "Observed", "Connection", 100, true),
        new("Sni", "SNI", "Connection", 190),
        new("Destination", "Destination", "Connection", 155),
        new("Tls", "Protocol", "Connection", 85, true),
        new("Cipher", "Cipher suite", "Server selection", 245),
        new("Group", "Key-exchange group", "Server selection", 145),
        new("GroupClass", "Key classification", "Server selection", 130, true,
            "Selected key-exchange group classification; does not assess authentication or handshake success."),
        new("Process", "Local process", "Processes", 130, true),
        new("Computer", "Collector computer", "Connection", 150, Description:
            "Computer running the collector. For imported captures, this is the importing computer."),
        new("ClientOwner", "Client owner", "Processes", 180, Description:
            "Primary process token user as DOMAIN\\account; applies only to an attributed local process."),
        new("ServerOwner", "Server owner", "Processes", 180, Description:
            "Primary process token user as DOMAIN\\account; applies only to an attributed local process."),
        new("State", "Observed messages", "Evidence", 175, Description:
            "Observed protocol messages or a bounded statistical classification; authentication is not implied."),
        new("SshSelectionEvidence", "Selection evidence", "SSH", 330),
        new("SshVisibility", "SSH visibility", "SSH", 350),
        new("Classification", "Classification", "Raw classification", 180),
        new("SampleBytes", "Sample bytes", "Raw classification", 120),
        new("SampleEntropy", "Entropy (bits/byte)", "Raw classification", 155),
        new("SampleDirection", "Sample direction", "Raw classification", 200),
        new("ClassificationLimit", "Classification limits", "Raw classification", 350),
        new("EndpointRawAlgorithm", "Reported encryption algorithm", "Raw endpoint", 230),
        new("EndpointRawMode", "Reported encryption mode", "Raw endpoint", 210),
        new("EndpointRawKeyBits", "Reported key bits", "Raw endpoint", 160),
        new("Findings", "Findings", "Evidence", 160, true,
            "Rules applied to observed parameters; unknown fields are not treated as failures."),
        new("Source", "Source", "Connection", 165),
        new("GroupStatus", "Group registry status", "PQC evidence", 165, Description:
            "Standardization status of the selected group, independent of its cryptographic classification."),
        new("GroupComponents", "Group components", "PQC evidence", 230),
        new("GroupReference", "Group specification", "PQC evidence", 250),
        new("ClassificationRules", "Classification rule version", "PQC evidence", 195, Description:
            "Collector rules used to classify this observation's selected group."),
        new("NegotiationStages", "Retained hello stages", "PQC evidence", 165),
        new("NegotiationDropped", "Unretained hello stages", "PQC evidence", 180),
        new("NegotiationTruncated", "Stage history truncated", "PQC evidence", 175, Description:
            "Whether the collector's bounded history omitted stages; No does not establish complete packet capture."),
        new("KeyExchange", "Key exchange", "Server selection", 200, Description:
            "TLS 1.2 cipher-suite family or TLS 1.3 visible key-share/PSK selection; resumption can reuse earlier secrets."),
        new("Encryption", "Encryption algorithm", "Server selection", 170),
        new("Mode", "Encryption mode", "Server selection", 135),
        new("KeyBits", "Symmetric key bits", "Server selection", 140,
            Description: "Algorithm key length, not an overall security-strength estimate."),
        new("Hash", "Cipher suite hash", "Server selection", 145),
        new("RecordMac", "Record protection", "Server selection", 145),
        new("PrfHash", "Legacy PRF", "Server selection", 130),
        new("HkdfHash", "HKDF / transcript hash", "Server selection", 175),
        new("Authentication", "Authentication selection", "Authentication", 195),
        new("Signature", "Server handshake signature", "Authentication", 240),
        new("ClientSignature", "Client handshake signature", "Authentication", 240),
        new("ClientAuth", "Client certificate authentication", "Authentication", 260),
        new("Certificate", "Server certificate SHA-256", "Certificates", 280),
        new("CertificateVisibility", "Certificate visibility", "Certificates", 260),
        new("Psk", "PSK selection", "Session behavior", 190),
        new("PskIndex", "Selected PSK index", "Session behavior", 150),
        new("PskOffers", "Visible PSK offers", "Session behavior", 150),
        new("PskModes", "Offered PSK modes", "Client offers", 240),
        new("Resumption", "Resumption evidence", "Session behavior", 270),
        new("EarlyData", "Early data offered", "Session behavior", 155),
        new("EarlyAccepted", "Early data acceptance", "Session behavior", 190),
        new("Ems", "Extended master secret selected", "Extensions", 235),
        new("EmsOffered", "Extended master secret offered", "Client offers", 235),
        new("Renegotiation", "Secure renegotiation", "Extensions", 190),
        new("Ticket", "Session ticket offered", "Client offers", 170),
        new("Compression", "TLS compression", "Server selection", 140),
        new("Downgrade", "Downgrade sentinel", "Extensions", 220),
        new("OfferedGroups", "Supported groups", "Client offers", 320),
        new("OfferedKeyShares", "Key shares", "Client offers", 240),
        new("OfferedSignatures", "Signature algorithms", "Client offers", 320),
        new("OfferedCertificateSignatures", "Certificate signature algorithms", "Client offers", 320),
        new("OfferedCiphers", "Cipher suites", "Client offers", 320),
        new("OfferedVersions", "Protocol versions", "Client offers", 180),
        new("OfferedAlpn", "ALPN offers", "Client offers", 180),
        new("SelectedAlpn", "Selected ALPN", "Server selection", 140),
        new("ClientExtensions", "Client extension IDs", "Extensions", 280),
        new("ServerExtensions", "Server extension IDs", "Extensions", 240),
        new("Ech", "ECH indication", "Evidence", 240),
        new("Visibility", "ClientHello visibility", "Evidence", 270),
        new("Confirmation", "Endpoint result", "Evidence", 145, true,
            "Endpoint-reported outcomes matched to socket, process lifetime, timing, and selected parameters."),
        new("Evidence", "Evidence source", "Evidence", 160),
        new("DhBits", "DH parameter bits", "Server selection", 150),
        new("ClientHello", "ClientHello observed", "Timing", 225),
        new("ServerHello", "ServerHello observed", "Timing", 225),
        new("HelloLatency", "CH–SH interval", "Timing", 130, Description:
            "Time between observed complete ClientHello and ServerHello; not full handshake duration."),
        new("Retry", "HelloRetryRequest", "Timing", 160),
        new("RetryTime", "Retry observed", "Timing", 225),
        new("RetryGroup", "Retry requested group", "Timing", 190),
        new("Alert", "Plaintext alert", "Diagnostics", 210),
        new("AlertLevel", "Alert level", "Diagnostics", 110),
        new("AlertSide", "Alert sender", "Diagnostics", 110),
        new("AlertTime", "Alert observed", "Timing", 225),
        new("Ended", "Last lifecycle observation", "Timing", 225),
        new("Termination", "Connection termination", "Diagnostics", 280),
        new("SourcePid", "Client PID", "Processes", 100),
        new("ProcessPath", "Client executable", "Processes", 320),
        new("ClientAccount", "Client account name", "Processes", 180),
        new("ClientDomain", "Client account domain", "Processes", 180),
        new("ClientSid", "Client account SID", "Processes", 310),
        new("ProcessEvidence", "Client attribution evidence", "Processes", 300),
        new("DestinationPid", "Server PID", "Processes", 100),
        new("ServerProcess", "Server process", "Processes", 160),
        new("ServerPath", "Server executable", "Processes", 320),
        new("ServerAccount", "Server account name", "Processes", 180),
        new("ServerDomain", "Server account domain", "Processes", 180),
        new("ServerSid", "Server account SID", "Processes", 310),
        new("ServerProcessEvidence", "Server attribution evidence", "Processes", 300),
        new("Note", "Capture note", "Diagnostics", 320),
        new("Run", "Capture session", "Evidence", 260),
        new("Flow", "Flow ID", "Evidence", 100)
    ];
}
