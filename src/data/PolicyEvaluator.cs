using System.Data;
using System.Text.Json;
using System.Xml.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Cipherazzi.Data;

public sealed class PolicyEvaluator
{
    private readonly CompiledPolicy[] policies;
    public IReadOnlyList<CryptoPolicy> Policies => policies.Select(policy => policy.Policy.Clone()).ToArray();
    public string Fingerprint { get; }

    public PolicyEvaluator(IEnumerable<CryptoPolicy> policies)
    {
        this.policies = policies.Select(policy => new CompiledPolicy(policy)).ToArray();
        if (this.policies.Length > 128 || this.policies.Select(policy => policy.Policy.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase).Count() != this.policies.Length)
            throw new InvalidDataException("Policy names must be unique; at most 128 policies are supported.");
        Fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n',
            this.policies.Select(policy => policy.Policy.ToXml().ToString(SaveOptions.DisableFormatting))))));
    }

    public static PolicyEvaluator Load(string path)
    {
        // Accept the policy section exported by the viewer without requiring desktop settings.
        using var input = File.OpenRead(path);
        if (input.Length > 256 * 1024)
            throw new InvalidDataException("Policy configuration exceeds 256 KiB.");
        var root = XDocument.Load(input).Root;
        if (root?.Name != "cipherazzi" || root.Elements("policies").Count() != 1 ||
            root.Element("policies") is not { } section || section.HasAttributes ||
            section.Elements().Any(element => element.Name != "policy") ||
            section.Nodes().OfType<XText>().Any(text => !string.IsNullOrWhiteSpace(text.Value)))
            throw new InvalidDataException("Expected a cipherazzi configuration with a policies section.");
        return new(section.Elements("policy").Select(CryptoPolicy.FromXml));
    }

    public List<PolicyResult> Evaluate(FlowEvidence flow) => policies.Select(policy => policy.Evaluate(flow))
        .OfType<PolicyResult>().ToList();

    public static string CertificateFactsSql(DatabaseSource source) => PqcInsights.CertificateFacts(source);

    public static string EndpointMatchSql(DatabaseSource source, string document, string connection) =>
        $"{connection}.run_id={source.JsonScalar(document, "matched_run_id")} AND " +
        $"{connection}.flow_id={source.JsonScalar(document, "matched_flow_id", integer: true, minimum: 1)}";

    // Unselected and unfamiliar TLS wire versions remain eligible for partial-observation assessment.
    private static string ProtocolName(string recorded) => recorded switch
    {
        "SSH 2.0" => "SSH",
        "Raw cryptography" => "Unknown",
        "Unknown" or "WireGuard" or "IKEv1" or "IKEv2" or "OpenVPN" or "SMB" or "RDP" or "TDS" or
            "Kerberos" or "LDAP" or "HTTP" or "DCE/RPC" or "SMTP" or "IMAP" or "POP3" or "FTP" or
            "PostgreSQL" or "MySQL" or "IPsec" => recorded,
        var name when name.StartsWith("DTLS", StringComparison.Ordinal) => "DTLS",
        _ => "TLS"
    };

    public static FlowEvidence ConnectionEvidence(IDataRecord record, string computer)
    {
        string Text(string name) => record[name] is DBNull ? "" : Convert.ToString(record[name]) ?? "";

        // Read a complete committed observation, including linked and reported certificate evidence.
        FlowEvidence Observation() => new()
        {
            Id = Convert.ToInt64(record["policy_observation_id"]),
            RunId = Text("run_id"),
            FlowId = Convert.ToInt64(record["flow_id"]),
            FirstUs = Convert.ToInt64(record["first_us"]),
            Computer = computer,
            ClientProcess = Text("source_process"),
            ClientPath = Text("source_path"),
            ServerProcess = Text("destination_process"),
            ServerPath = Text("destination_path"),
            ServerName = Text("sni") is { Length: > 0 } name ? name : Text("destination_address"),
            Protocol = ProtocolName(Text("policy_protocol")),
            Tls = record["tls_version"] is DBNull ? 0 : Convert.ToInt32(record["tls_version"]),
            GroupName = Text("group_name"),
            EchOffered = Convert.ToInt32(record["policy_ech_offered"]) != 0
        };
        var flow = Observation();
        try
        {
            var json = Text("metadata_json");
            if (json.Length > 2 * 1024 * 1024)
                throw new JsonException("Observation evidence exceeds the inspection bound.");
            return flow.Decode(json, Text("policy_certificate_facts"), Text("key_exchange"), Text("authentication"),
                protocol: flow.Protocol);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or
            FormatException or OverflowException)
        {
            // Discard partial signatures and protocol selections while preserving the recorded observation identity.
            flow = Observation();
            flow.Decode("{}", "", "", "", protocol: flow.Protocol);
            flow.EvidenceError = "Recorded cryptographic evidence could not be read";
            return flow;
        }
    }

    public static FlowEvidence? EndpointEvidence(string json, string computer, string id, string runId = "",
        long timestampUs = 0, string? recordedProtocol = null)
    {
        // Structured journal identity determines policy scope; JSON supplies only the corresponding evidence.
        var protocol = recordedProtocol is null ? null : ProtocolName(recordedProtocol);
        try { return DecodeEndpoint(json, computer, id, protocol) is { } flow ? flow with { RunId = runId } : null; }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or
            FormatException or OverflowException)
        {
            return new FlowEvidence
            {
                Computer = computer,
                FirstUs = timestampUs,
                LastUs = timestampUs,
                EndpointEventId = id,
                RunId = runId,
                EvidenceError = "Recorded endpoint assessment could not be read"
            }
                .Decode("{\"evidence_source\":\"Endpoint\"}", "", "", "", protocol: protocol);
        }
    }

    private static FlowEvidence? DecodeEndpoint(string json, string computer, string id, string? protocol)
    {
        if (json.Length > 2 * 1024 * 1024)
            throw new JsonException("Endpoint evidence exceeds the inspection bound.");
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("assessment", out var assessment))
            return null;
        string Text(string name) => assessment.TryGetProperty(name, out var value) ? value.ToString() : "";
        var role = Text("local_role");
        var process = Text("process");
        var path = Text("path");

        // Invalid operation times cannot define a cohort or suppress a recorded endpoint assessment.
        var firstUs = assessment.GetProperty("first_us").GetInt64();
        var lastUs = assessment.TryGetProperty("last_us", out var last) ? last.GetInt64() : firstUs;
        if (firstUs < 0 || lastUs < firstUs || lastUs > 253402300799999999)
            throw new JsonException("Invalid endpoint operation times.");

        // Unassociated reports retain their own identity, role, and evidence source.
        return new FlowEvidence
        {
            FirstUs = firstUs,
            LastUs = lastUs,
            ServerPort = assessment.TryGetProperty("server_port", out var port) ? port.GetInt32() : 0,
            Computer = computer,
            EndpointEventId = id,
            ClientProcess = role == "Client" ? process : "",
            ClientPath = role == "Client" ? path : "",
            ServerProcess = role == "Server" ? process : "",
            ServerPath = role == "Server" ? path : "",
            EndpointProcess = role == "Unknown" ? process : "",
            EndpointPath = role == "Unknown" ? path : "",
            ServerName = Text("server_name"),
            GroupName = Text("group_name"),
            Tls = assessment.GetProperty("tls_version").GetInt32()
        }.Decode(assessment.GetProperty("crypto").GetRawText(), Text("certificate_facts"),
            Text("key_exchange"), Text("authentication"), protocol: protocol);
    }
}
