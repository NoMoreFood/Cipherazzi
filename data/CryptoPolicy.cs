using System.ComponentModel;
using System.Globalization;
using System.IO.Enumeration;
using System.Xml.Linq;

namespace Cipherazzi.Data;

public enum PolicyEndpoint { Either, Client, Server }
public enum PolicyCertificateRole { Server, Client, Both }
[TypeConverter(typeof(PolicyProtocolConverter))]
public enum PolicyProtocol { Tls, Ssh, Smb, WireGuard, IkeV2, OpenVpn }

public sealed class CryptoPolicy : ICustomTypeDescriptor
{
    [Category("Identity"), Description("Every enabled policy whose scope matches is evaluated.")]
    public string Name { get; set; } = "PQC migration";
    [Category("Identity")]
    public bool Enabled { get; set; } = true;
    [Category("Scope"), RefreshProperties(RefreshProperties.All),
        Description("Protocol assessed by this policy; TLS includes DTLS and QUIC TLS evidence.")]
    public PolicyProtocol Protocol { get; set; } = PolicyProtocol.Tls;
    [Category("Scope"), Description("Computer name; * and ? are case-insensitive wildcards.")]
    public string Computer { get; set; } = "*";
    [Category("Scope"), Description("Executable name or full path; * and ? are case-insensitive wildcards.")]
    public string Process { get; set; } = "*";
    [Category("Scope"), DisplayName("Server name"),
        Description("Observed SNI, or destination address when SNI is absent. ECH names are outer names.")]
    public string ServerName { get; set; } = "*";
    [Category("Scope"), DisplayName("Process role"),
        Description("Which local process is considered when matching the process scope.")]
    public PolicyEndpoint ProcessRole { get; set; } = PolicyEndpoint.Either;
    [Category("Key establishment"), DisplayName("Require PQ keys")]
    public bool RequirePostQuantumKeyExchange { get; set; } = true;
    [Category("Key establishment"), DisplayName("Standardized"),
        Description("Require a standardized PQ group when a PQ group is selected.")]
    public bool RequireStandardizedPqGroup { get; set; } = true;
    [Category("Key establishment"), DisplayName("Group IDs"),
        Description("Comma-separated TLS group IDs, decimal or 0x hexadecimal. Empty permits any.")]
    public string AllowedGroups { get; set; } = "";
    [Category("Protocol"), DisplayName("Minimum TLS"), TypeConverter(typeof(TlsVersionConverter))]
    public int MinimumTls { get; set; } = 771;
    [Category("Authentication"), DisplayName("PQ server signature")]
    public bool RequirePostQuantumServerAuthentication { get; set; }
    [Category("Authentication"), DisplayName("PQ client signature")]
    public bool RequirePostQuantumClientAuthentication { get; set; }
    [Category("Authentication"), DisplayName("Server signature IDs"),
        Description("Comma-separated server CertificateVerify scheme IDs. Empty permits any.")]
    public string AllowedServerSignatures { get; set; } = "";
    [Category("Authentication"), DisplayName("Client signature IDs"),
        Description("Comma-separated client CertificateVerify scheme IDs. Empty permits any.")]
    public string AllowedClientSignatures { get; set; } = "";
    [Category("Certificates"), DisplayName("Certificate role")]
    public PolicyCertificateRole CertificateRole { get; set; } = PolicyCertificateRole.Server;
    [Category("Certificates"), DisplayName("Require evidence"),
        Description("Evaluate the certificates presented in the selected role; trust is separate.")]
    public bool RequireCertificateEvidence { get; set; }
    [Category("Certificates"), DisplayName("PQ chain signatures"),
        Description("Require PQ signatures on every observed certificate in the selected role.")]
    public bool RequirePostQuantumCertificateSignatures { get; set; }
    [Category("Certificates"), DisplayName("Public-key OIDs"),
        Description("Comma-separated public-key algorithm OIDs. Empty permits any.")]
    public string AllowedCertificateKeys { get; set; } = "";
    [Category("Certificates"), DisplayName("Signature OIDs"),
        Description("Comma-separated certificate signature OIDs. Empty permits any.")]
    public string AllowedCertificateSignatures { get; set; } = "";
    [Category("Evidence"), DisplayName("Confirm completion")]
    public bool RequireEndpointCompletion { get; set; } = true;
    [Category("Evidence"), DisplayName("Verify peer"),
        Description("Require the reporting endpoint to state that peer verification succeeded.")]
    public bool RequirePeerVerification { get; set; }
    [Category("SSH"), DisplayName("Key exchanges"), Description("Approved SSH algorithm names, comma-separated.")]
    public string AllowedSshKeyExchanges { get; set; } = "";
    [Category("SSH"), DisplayName("Host keys")]
    public string AllowedSshHostKeys { get; set; } = "";
    [Category("SSH"), DisplayName("Ciphers"), Description("Approved negotiated ciphers in both directions.")]
    public string AllowedSshCiphers { get; set; } = "";
    [Category("SSH"), DisplayName("MACs"), Description("Approved MACs in both directions; AEAD uses implicit-aead.")]
    public string AllowedSshMacs { get; set; } = "";
    [Category("SSH"), DisplayName("Min. key bits")]
    public int MinimumSshHostKeyBits { get; set; }
    [Category("SSH"), DisplayName("Fingerprints"),
        Description("SHA-256 fingerprints in hexadecimal, comma-separated; captured keys do not establish trust.")]
    public string AllowedSshHostKeyFingerprints { get; set; } = "";
    [Category("SMB"), DisplayName("Min. dialect"),
        Description("SMB dialect ID in decimal: 514, 528, 768, 770, or 785; zero disables the requirement.")]
    public int MinimumSmbDialect { get; set; }
    [Category("SMB"), DisplayName("Signing req."),
        Description("Require the server's negotiation to mandate signing; this does not prove signed traffic.")]
    public bool RequireSmbSigningRequired { get; set; }
    [Category("SMB"), DisplayName("Signed frames"),
        Description("Require a captured SMB message with the signed flag; signatures are not verified.")]
    public bool RequireSmbSigning { get; set; }
    [Category("SMB"), DisplayName("Encryption"),
        Description("Require observed encrypted transform framing; authenticity is not verified.")]
    public bool RequireSmbEncryption { get; set; }
    [Category("SMB"), DisplayName("Encryption IDs"), Description("Approved selected SMB encryption context IDs.")]
    public string AllowedSmbCiphers { get; set; } = "";
    [Category("SMB"), DisplayName("Signing IDs"), Description("Approved selected SMB signing context IDs.")]
    public string AllowedSmbSigningAlgorithms { get; set; } = "";
    [Category("VPN"), DisplayName("Ciphers"),
        Description("Approved WireGuard/IKE SA_INIT encryption names. OpenVPN data ciphers need endpoint evidence.")]
    public string AllowedVpnCiphers { get; set; } = "";
    [Category("VPN"), DisplayName("Key exchanges")]
    public string AllowedVpnKeyExchanges { get; set; } = "";
    [Category("VPN"), DisplayName("Min. key bits")]
    public int MinimumVpnKeyBits { get; set; }
    [Category("VPN"), DisplayName("Authenticated"),
        Description("Require verified VPN authentication evidence. Passive handshake messages leave this unknown.")]
    public bool RequireVpnAuthentication { get; set; }
    [Category("OpenVPN control"), DisplayName("Minimum TLS"), TypeConverter(typeof(TlsVersionConverter))]
    public int MinimumOpenVpnTls { get; set; } = 771;
    [Category("OpenVPN control"), DisplayName("Ciphers"),
        Description("Approved selected TLS control-channel cipher names; independent of the encrypted data channel.")]
    public string AllowedOpenVpnControlCiphers { get; set; } = "";

    public CryptoPolicy Clone() => (CryptoPolicy)MemberwiseClone();

    // Present only requirements applicable to the selected protocol in the native property editor.
    AttributeCollection ICustomTypeDescriptor.GetAttributes() => TypeDescriptor.GetAttributes(this, true);
    string? ICustomTypeDescriptor.GetClassName() => TypeDescriptor.GetClassName(this, true);
    string? ICustomTypeDescriptor.GetComponentName() => TypeDescriptor.GetComponentName(this, true);
    TypeConverter ICustomTypeDescriptor.GetConverter() => TypeDescriptor.GetConverter(this, true);
    EventDescriptor? ICustomTypeDescriptor.GetDefaultEvent() => TypeDescriptor.GetDefaultEvent(this, true);
    PropertyDescriptor? ICustomTypeDescriptor.GetDefaultProperty() => TypeDescriptor.GetDefaultProperty(this, true);
    object? ICustomTypeDescriptor.GetEditor(Type editorBaseType) =>
        TypeDescriptor.GetEditor(this, editorBaseType, true);
    EventDescriptorCollection ICustomTypeDescriptor.GetEvents() => TypeDescriptor.GetEvents(this, true);
    EventDescriptorCollection ICustomTypeDescriptor.GetEvents(Attribute[]? attributes) =>
        TypeDescriptor.GetEvents(this, attributes ?? [], true);
    object ICustomTypeDescriptor.GetPropertyOwner(PropertyDescriptor? descriptor) => this;
    PropertyDescriptorCollection ICustomTypeDescriptor.GetProperties() => VisibleProperties(null);
    PropertyDescriptorCollection ICustomTypeDescriptor.GetProperties(Attribute[]? attributes) =>
        VisibleProperties(attributes);

    private PropertyDescriptorCollection VisibleProperties(Attribute[]? attributes) => new(TypeDescriptor
        .GetProperties(this, attributes ?? [], true).Cast<PropertyDescriptor>().Where(property =>
            property.Category is "Identity" or "Scope" || Protocol switch
            {
                PolicyProtocol.Tls => property.Category is "Key establishment" or "Protocol" or "Authentication" or
                    "Certificates" or "Evidence",
                PolicyProtocol.Ssh => property.Category == "SSH",
                PolicyProtocol.Smb => property.Category == "SMB",
                PolicyProtocol.OpenVpn => property.Category is "VPN" or "OpenVPN control",
                _ => property.Category == "VPN"
            }).ToArray(), readOnly: true);

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Name) || Name.Length > 128 ||
            new[] { Computer, Process, ServerName }.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > 256))
            throw new InvalidDataException("Supply a policy name and scopes of at most 256 characters.");
        if (MinimumTls is < 768 or > 772 || MinimumOpenVpnTls is < 768 or > 772 ||
            !Enum.IsDefined(Protocol) || !Enum.IsDefined(ProcessRole) || !Enum.IsDefined(CertificateRole))
            throw new InvalidDataException("Choose a supported protocol and endpoint role.");
        if (MinimumSshHostKeyBits is < 0 or > 65536 || MinimumVpnKeyBits is < 0 or > 65536 ||
            MinimumSmbDialect is not (0 or 0x0202 or 0x0210 or 0x0300 or 0x0302 or 0x0311))
            throw new InvalidDataException("Choose a supported SMB dialect and key sizes between 0 and 65536 bits.");
        foreach (var value in new[] { AllowedGroups, AllowedServerSignatures, AllowedClientSignatures,
            AllowedSmbCiphers, AllowedSmbSigningAlgorithms })
            _ = Ids(value);
        foreach (var value in new[] { AllowedCertificateKeys, AllowedCertificateSignatures })
            _ = Oids(value);
        foreach (var value in new[] { AllowedSshKeyExchanges, AllowedSshHostKeys, AllowedSshCiphers, AllowedSshMacs,
            AllowedVpnCiphers, AllowedVpnKeyExchanges, AllowedOpenVpnControlCiphers })
            _ = Names(value);
        if (Names(AllowedSshHostKeyFingerprints).Any(value => value.Length != 64 || value.Any(c => !Uri.IsHexDigit(c))))
            throw new InvalidDataException("SSH fingerprints must be hexadecimal SHA-256 values.");
    }

    public static HashSet<int> Ids(string value)
    {
        var result = new HashSet<int>();
        foreach (var part in Parts(value))
        {
            var hex = part.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
            if (!int.TryParse(hex ? part[2..] : part, hex ? NumberStyles.HexNumber : NumberStyles.None,
                CultureInfo.InvariantCulture, out var id) || id is < 0 or > 65535)
                throw new InvalidDataException("Algorithm IDs must be between 0 and 65535, decimal or 0x hexadecimal.");
            result.Add(id);
        }
        return result;
    }

    public static HashSet<string> Oids(string value)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var part in Parts(value))
        {
            if (part.Length > 128 || part.Split('.').Length < 2 || part.StartsWith('.') || part.EndsWith('.') ||
                part.Contains("..") || part.Any(c => c != '.' && (c < '0' || c > '9')))
                throw new InvalidDataException("Certificate algorithms must be numeric, dot-separated OIDs.");
            result.Add(part);
        }
        return result;
    }

    internal static HashSet<string> Names(string value)
    {
        var parts = Parts(value);
        if (parts.Any(part => part.Length > 256 || part.Any(char.IsControl)))
            throw new InvalidDataException("Algorithm names allow 256 characters without control characters.");
        return new(parts, StringComparer.OrdinalIgnoreCase);
    }

    private static string[] Parts(string value)
    {
        if (value.Length > 4096)
            throw new InvalidDataException("Algorithm lists exceed 4096 characters.");
        var parts = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 128)
            throw new InvalidDataException("An algorithm list exceeds 128 entries.");
        return parts;
    }

    internal bool Applies(FlowEvidence flow)
    {
        bool Match(string pattern, string value) =>
            pattern == "*" || FileSystemName.MatchesSimpleExpression(pattern, value, ignoreCase: true);
        bool ProcessMatch(string name, string path) => Match(Process, name) || path.Length > 0 && Match(Process, path);
        var protocol = Protocol switch
        {
            PolicyProtocol.Tls => flow.Protocol is "TLS" or "DTLS",
            PolicyProtocol.Ssh => flow.Protocol == "SSH",
            PolicyProtocol.Smb => flow.Protocol == "SMB",
            PolicyProtocol.WireGuard => flow.Protocol == "WireGuard",
            PolicyProtocol.IkeV2 => flow.Protocol == "IKEv2",
            _ => flow.Protocol == "OpenVPN"
        };
        return Enabled && protocol && Match(Computer, flow.Computer) &&
            Match(ServerName, flow.ServerName) && ProcessRole switch
        {
            PolicyEndpoint.Client => ProcessMatch(flow.ClientProcess, flow.ClientPath),
            PolicyEndpoint.Server => ProcessMatch(flow.ServerProcess, flow.ServerPath),
            _ => ProcessMatch(flow.ClientProcess, flow.ClientPath) ||
                ProcessMatch(flow.ServerProcess, flow.ServerPath) || ProcessMatch(flow.EndpointProcess, flow.EndpointPath)
        };
    }

    private static string AttributeName(string name) => char.ToLowerInvariant(name[0]) + name[1..];
    public XElement ToXml() => new("policy", GetType().GetProperties().Select(property =>
        new XAttribute(AttributeName(property.Name), property.GetValue(this)!)));

    public static CryptoPolicy FromXml(XElement element)
    {
        var policy = new CryptoPolicy();
        var names = typeof(CryptoPolicy).GetProperties().Select(property => AttributeName(property.Name)).ToHashSet();
        if (element.Attributes().Any(attribute => !names.Contains(attribute.Name.LocalName)))
            throw new InvalidDataException("A policy contains an unknown setting.");
        foreach (var property in typeof(CryptoPolicy).GetProperties())
        {
            if (element.Attribute(AttributeName(property.Name)) is not { } attribute)
                continue;
            var value = TypeDescriptor.GetConverter(property.PropertyType).ConvertFromInvariantString(attribute.Value);
            property.SetValue(policy, value);
        }
        policy.Validate();
        return policy;
    }
}

public sealed class PolicyProtocolConverter : EnumConverter
{
    private static readonly string[] Names = ["TLS / DTLS", "SSH", "SMB", "WireGuard", "IKEv2", "OpenVPN"];
    public PolicyProtocolConverter() : base(typeof(PolicyProtocol)) {}
    public override object? ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value) =>
        value is string name && Array.IndexOf(Names, name) is >= 0 and var index ?
            (PolicyProtocol)index : base.ConvertFrom(context, culture, value);
    public override object? ConvertTo(ITypeDescriptorContext? context, CultureInfo? culture, object? value,
        Type destinationType) =>
        destinationType == typeof(string) && value is PolicyProtocol protocol && Enum.IsDefined(protocol) ?
            Names[(int)protocol] : base.ConvertTo(context, culture, value, destinationType);
}

public sealed class TlsVersionConverter : Int32Converter
{
    private static readonly string[] Names = ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"];
    public override bool GetStandardValuesSupported(ITypeDescriptorContext? context) => true;
    public override bool GetStandardValuesExclusive(ITypeDescriptorContext? context) => true;
    public override StandardValuesCollection GetStandardValues(ITypeDescriptorContext? context) =>
        new(new[] { 768, 769, 770, 771, 772 });
    public override object? ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value) =>
        value is string name && Array.IndexOf(Names, name) is >= 0 and var index ?
            768 + index : base.ConvertFrom(context, culture, value);
    public override object? ConvertTo(ITypeDescriptorContext? context, CultureInfo? culture, object? value, Type destinationType) =>
        destinationType == typeof(string) && value is int version && version is >= 768 and <= 772 ?
            Names[version - 768] : base.ConvertTo(context, culture, value, destinationType);
}

public sealed record PolicyIssue(string Status, string Message);
public sealed record PolicyResult(string Name, string Status, List<PolicyIssue> Issues);

internal sealed class CompiledPolicy
{
    public CryptoPolicy Policy { get; }
    private readonly HashSet<int> groups, serverSignatures, clientSignatures;
    private readonly HashSet<string> certificateKeys, certificateSignatures;
    private readonly Dictionary<string, HashSet<string>> protocolNames;
    private readonly Dictionary<string, HashSet<int>> protocolIds;

    public CompiledPolicy(CryptoPolicy policy)
    {
        Policy = policy.Clone();
        Policy.Validate();
        groups = CryptoPolicy.Ids(Policy.AllowedGroups);
        serverSignatures = CryptoPolicy.Ids(Policy.AllowedServerSignatures);
        clientSignatures = CryptoPolicy.Ids(Policy.AllowedClientSignatures);
        certificateKeys = CryptoPolicy.Oids(Policy.AllowedCertificateKeys);
        certificateSignatures = CryptoPolicy.Oids(Policy.AllowedCertificateSignatures);
        protocolNames = new[] { Policy.AllowedSshKeyExchanges, Policy.AllowedSshHostKeys, Policy.AllowedSshCiphers,
            Policy.AllowedSshMacs, Policy.AllowedSshHostKeyFingerprints, Policy.AllowedVpnCiphers,
            Policy.AllowedVpnKeyExchanges, Policy.AllowedOpenVpnControlCiphers }.Distinct()
            .ToDictionary(value => value, CryptoPolicy.Names);
        protocolIds = new[] { Policy.AllowedSmbCiphers, Policy.AllowedSmbSigningAlgorithms }.Distinct()
            .ToDictionary(value => value, CryptoPolicy.Ids);
    }

    public PolicyResult? Evaluate(FlowEvidence flow)
    {
        if (!Policy.Applies(flow))
            return null;
        if (Policy.Protocol != PolicyProtocol.Tls)
            return EvaluateProtocol(flow);
        var issues = new List<PolicyIssue>();
        if (flow.EvidenceError.Length > 0)
            issues.Add(new("Insufficient evidence", flow.EvidenceError));
        void Require(bool observed, bool accepted, string missing, string violation)
        {
            if (!observed)
                issues.Add(new("Insufficient evidence", missing));
            else if (!accepted)
                issues.Add(new("Violation", violation));
        }

        // QUIC guarantees a TLS 1.3 minimum even when its endpoint omits the exact wire version.
        Require(flow.Tls > 0 || flow.Transport == "QUIC",
            flow.Tls > 0 ? flow.Tls >= Policy.MinimumTls : flow.Transport == "QUIC" && Policy.MinimumTls <= 772,
            "Selected TLS version not observed", "TLS version below policy minimum");
        if (Policy.RequirePostQuantumKeyExchange)
            Require(flow.KeyClass is not ("Unknown" or "Not observed" or "PSK only"), flow.KeyClass.Contains("post-quantum",
                StringComparison.OrdinalIgnoreCase), "Key-establishment classification unavailable",
                "Classical key establishment selected");
        if (Policy.RequireStandardizedPqGroup && flow.KeyClass.Contains("post-quantum", StringComparison.OrdinalIgnoreCase))
            Require(flow.GroupStatus.Length > 0 && flow.GroupStatus != "Unknown", flow.GroupStatus == "Standardized",
                "PQ group standardization status unavailable", "PQ group is not standardized");
        if (groups.Count > 0)
            Require(flow.GroupId >= 0, groups.Contains(flow.GroupId), "Selected group ID not observed",
                "Selected group is outside the approved list");
        foreach (var (required, status, observed, approved, label) in new[]
        {
            (Policy.RequirePostQuantumServerAuthentication, flow.ServerAuth, flow.ServerSignatureIds,
                serverSignatures, "Server"),
            (Policy.RequirePostQuantumClientAuthentication, flow.ClientAuth, flow.ClientSignatureIds,
                clientSignatures, "Client")
        })
        {
            if (required)
                Require(status is not ("Unknown" or "Not observed" or "PSK selected"), status == "Post-quantum",
                    label + " authentication classification unavailable", label + " authentication is not fully PQ");
            if (approved.Count > 0)
                Require(observed.Count > 0, observed.All(approved.Contains), label + " signature scheme not observed",
                    label + " signature scheme is outside the approved list");
        }
        var certificates = flow.Certificates.Where(certificate => Policy.CertificateRole == PolicyCertificateRole.Both ||
            certificate.Role == (Policy.CertificateRole == PolicyCertificateRole.Server ? "server" : "client")).ToList();
        var certificateRule = Policy.RequireCertificateEvidence || Policy.RequirePostQuantumCertificateSignatures ||
            certificateKeys.Count > 0 || certificateSignatures.Count > 0;
        if (certificateRule)
        {
            foreach (var role in Policy.CertificateRole switch
            {
                PolicyCertificateRole.Both => new[] { "server", "client" },
                PolicyCertificateRole.Client => new[] { "client" },
                _ => new[] { "server" }
            })
                Require(certificates.Any(certificate => certificate.Role == role), true,
                    role + " presented certificate evidence unavailable", "");
        }
        foreach (var certificate in certificates)
        {
            if (Policy.RequirePostQuantumCertificateSignatures)
                Require(certificate.SignatureClass is not ("" or "Unknown"), certificate.SignatureClass == "Post-quantum",
                    "Certificate signature classification unavailable", "Presented chain contains a classical signature");
            if (certificateKeys.Count > 0)
                Require(certificate.KeyOid.Length > 0, certificateKeys.Contains(certificate.KeyOid),
                    "Certificate public-key OID unavailable", "Certificate public-key algorithm is outside the approved list");
            if (certificateSignatures.Count > 0)
                Require(certificate.SignatureOid.Length > 0, certificateSignatures.Contains(certificate.SignatureOid),
                    "Certificate signature OID unavailable", "Certificate signature algorithm is outside the approved list");
        }
        if (Policy.RequireEndpointCompletion)
            Require(flow.Completion != "Not confirmed", flow.Completion == "Completed",
                "Endpoint handshake completion not reported", "Endpoint reported failure or conflicting outcomes");
        if (Policy.RequirePeerVerification)
            Require(flow.PeerVerification != "Not reported", flow.PeerVerification == "Verified",
                "Endpoint peer verification not reported", "Endpoint reported unverified or conflicting peer verification");
        return Result(issues);
    }

    private PolicyResult EvaluateProtocol(FlowEvidence flow)
    {
        var issues = new List<PolicyIssue>();
        if (flow.EvidenceError.Length > 0)
            issues.Add(new("Insufficient evidence", flow.EvidenceError));
        var evidence = flow.ProtocolEvidence;
        System.Text.Json.JsonElement Value(params string[] path)
        {
            var value = evidence;
            foreach (var name in path)
                if (value.ValueKind != System.Text.Json.JsonValueKind.Object || !value.TryGetProperty(name, out value))
                    return default;
            return value;
        }
        string Text(params string[] path) => Value(path).ToString();
        int Number(params string[] path)
        {
            var text = Text(path);
            var hex = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
            return int.TryParse(hex ? text[2..] : text, hex ? NumberStyles.HexNumber : NumberStyles.Integer,
                CultureInfo.InvariantCulture, out var value) ? value : -1;
        }
        void Require(bool observed, bool accepted, string missing, string violation)
        {
            if (!observed)
                issues.Add(new("Insufficient evidence", missing));
            else if (!accepted)
                issues.Add(new("Violation", violation));
        }
        void Approved(string list, string selected, string label)
        {
            var names = protocolNames[list];
            if (names.Count > 0)
                Require(selected.Length > 0 && selected != "Not selected", names.Contains(selected),
                    label + " selection not observed", label + " is outside the approved list");
        }
        void ApprovedIds(string list, string name, string label)
        {
            var allowed = protocolIds[list];
            if (allowed.Count == 0)
                return;
            var value = Value(name);
            var selected = value.ValueKind == System.Text.Json.JsonValueKind.Array ? value.EnumerateArray()
                .Select(item => CryptoPolicy.Ids(item.ToString()).Single()).ToArray() : [];
            Require(selected.Length > 0, selected.All(allowed.Contains), label + " not observed",
                label + " is outside the approved list");
        }

        // Assess SSH selections and public keys independently of user authentication or host trust.
        if (Policy.Protocol == PolicyProtocol.Ssh)
        {
            Approved(Policy.AllowedSshKeyExchanges, Text("ssh_selection", "key_exchange"), "SSH key exchange");
            Approved(Policy.AllowedSshHostKeys, Text("ssh_selection", "host_key"), "SSH host-key algorithm");
            foreach (var direction in new[] { "c2s", "s2c" })
            {
                var cipher = Text("ssh_selection", "cipher_" + direction);
                Approved(Policy.AllowedSshCiphers, cipher, "SSH " + direction + " cipher");
                var mac = cipher.Contains("gcm@openssh.com", StringComparison.Ordinal) ||
                    cipher == "chacha20-poly1305@openssh.com" ? "implicit-aead" :
                    Text("ssh_selection", "mac_" + direction);
                Approved(Policy.AllowedSshMacs, mac, "SSH " + direction + " MAC");
            }
            if (Policy.MinimumSshHostKeyBits > 0)
                Require(Number("ssh_host_key_bits") > 0, Number("ssh_host_key_bits") >= Policy.MinimumSshHostKeyBits,
                    "SSH host-key size not observed", "SSH host key is below the minimum size");
            Approved(Policy.AllowedSshHostKeyFingerprints, Text("ssh_host_key_sha256"), "SSH host-key fingerprint");
        }

        // Negotiated requirements, observed signing, and observed encryption are distinct SMB evidence.
        else if (Policy.Protocol == PolicyProtocol.Smb)
        {
            if (Policy.MinimumSmbDialect > 0)
            {
                // A selected SMB1 reply predates every SMB2 minimum; a rejected dialect list selects nothing.
                var legacy = Number("smb_selected_dialect") <= 0 && Text("smb_legacy_response_format").Length > 0;
                Require(Number("smb_selected_dialect") > 0 || legacy,
                    Number("smb_selected_dialect") >= Policy.MinimumSmbDialect,
                    "SMB dialect selection not observed", "SMB dialect is below the minimum");
            }
            if (Policy.RequireSmbSigningRequired)
                Require(Value("smb_server_signing_required").ValueKind is System.Text.Json.JsonValueKind.True or
                    System.Text.Json.JsonValueKind.False, Text("smb_server_signing_required") == "True",
                    "SMB server signing requirement not observed", "SMB server does not require signing");
            if (Policy.RequireSmbSigning)
                Require(Text("smb_signed_message_observed") == "True", true,
                    "Signed SMB framing not observed; negotiation alone is insufficient", "");
            if (Policy.RequireSmbEncryption)
                Require(Text("smb_encrypted_transform_observed") == "True", true,
                    "Encrypted SMB framing not observed; capabilities alone are insufficient", "");
            ApprovedIds(Policy.AllowedSmbCiphers, "smb_selected_cipher", "SMB encryption algorithm");
            ApprovedIds(Policy.AllowedSmbSigningAlgorithms, "smb_selected_signing_algorithm", "SMB signing algorithm");
        }

        // VPN algorithm evidence does not imply authentication or an established tunnel.
        else
        {
            Approved(Policy.AllowedVpnCiphers, Policy.Protocol == PolicyProtocol.OpenVpn ?
                Text("vpn_data_cipher") : Text("encryption"), "VPN encryption algorithm");
            Approved(Policy.AllowedVpnKeyExchanges, Policy.Protocol == PolicyProtocol.OpenVpn ?
                Text("vpn_data_key_exchange") : Text("key_exchange"), "VPN key exchange");
            if (Policy.MinimumVpnKeyBits > 0)
            {
                var bits = Number(Policy.Protocol == PolicyProtocol.OpenVpn ? "vpn_data_key_bits" : "symmetric_key_bits");
                Require(bits > 0, bits >= Policy.MinimumVpnKeyBits,
                    "VPN symmetric key size not observed", "VPN key size is below the minimum");
            }
            if (Policy.RequireVpnAuthentication)
                Require(Text("vpn_authentication") is "Verified" or "Failed", Text("vpn_authentication") == "Verified",
                    "VPN authentication requires endpoint evidence", "VPN authentication failed");
            if (Policy.Protocol == PolicyProtocol.OpenVpn)
            {
                var version = Text("openvpn_tls_version");
                var selected = Array.IndexOf(new[] { "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3" }, version);
                Require(selected >= 0, 768 + selected >= Policy.MinimumOpenVpnTls,
                    "OpenVPN control TLS selection not observed", "OpenVPN control TLS is below the minimum");
                Approved(Policy.AllowedOpenVpnControlCiphers, Text("openvpn_tls", "selected_cipher"),
                    "OpenVPN control TLS cipher");
            }
        }
        return Result(issues);
    }

    private PolicyResult Result(List<PolicyIssue> issues)
    {
        issues = issues.Distinct().ToList();
        return new(Policy.Name, issues.Any(issue => issue.Status == "Violation") ? "Violation" :
            issues.Count > 0 ? "Insufficient evidence" : "Pass", issues);
    }
}
