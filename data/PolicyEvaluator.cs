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
        if (root?.Name != "cipherazzi" || root.Element("policies") is not { } section ||
            section.Elements().Any(element => element.Name != "policy"))
            throw new InvalidDataException("Expected a cipherazzi configuration with a policies section.");
        return new(section.Elements("policy").Select(CryptoPolicy.FromXml));
    }

    public List<PolicyResult> Evaluate(FlowEvidence flow) => policies.Select(policy => policy.Evaluate(flow))
        .OfType<PolicyResult>().ToList();

    public static string CertificateFactsSql(DatabaseSource source) => PqcInsights.CertificateFacts(source);

    public static FlowEvidence ConnectionEvidence(IDataRecord record, string computer)
    {
        string Text(string name) => record[name] is DBNull ? "" : Convert.ToString(record[name]) ?? "";

        // Read a complete committed observation, including linked and reported certificate evidence.
        var flow = new FlowEvidence
        {
            Id = Convert.ToInt64(record["policy_observation_id"]), RunId = Text("run_id"),
            FlowId = Convert.ToInt64(record["flow_id"]), FirstUs = Convert.ToInt64(record["first_us"]),
            Computer = computer, ClientProcess = Text("source_process"), ClientPath = Text("source_path"),
            ServerProcess = Text("destination_process"), ServerPath = Text("destination_path"),
            ServerName = Text("sni") is { Length: > 0 } name ? name : Text("destination_address"),
            Tls = record["tls_version"] is DBNull ? 0 : Convert.ToInt32(record["tls_version"]),
            GroupName = Text("group_name"),
            EchOffered = Convert.ToInt32(record["policy_ech_offered"]) != 0
        };
        try
        {
            var json = Text("metadata_json");
            if (json.Length > 2 * 1024 * 1024)
                throw new JsonException("Observation evidence exceeds the inspection bound.");
            return flow.Decode(json, Text("policy_certificate_facts"), Text("key_exchange"), Text("authentication"));
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or
            FormatException or OverflowException)
        {
            flow = flow.Decode("{}", "", "", "");
            flow.Protocol = Text("policy_protocol") switch
            {
                "SSH 2.0" => "SSH", "SMB" => "SMB", "WireGuard" => "WireGuard", "IKEv2" => "IKEv2",
                "OpenVPN" => "OpenVPN",
                var recordedProtocol when recordedProtocol.StartsWith("DTLS", StringComparison.Ordinal) => "DTLS",
                var recordedProtocol when recordedProtocol.StartsWith("TLS", StringComparison.Ordinal) ||
                    recordedProtocol == "SSL 3.0" => "TLS",
                _ => "Unknown"
            };
            flow.EvidenceError = "Recorded cryptographic evidence could not be read";
            return flow;
        }
    }

    public static FlowEvidence? EndpointEvidence(string json, string computer, string id, string runId = "")
    {
        try { return DecodeEndpoint(json, computer, id) is { } flow ? flow with { RunId = runId } : null; }
        catch (Exception error) when (error is JsonException or InvalidOperationException or
            FormatException or OverflowException)
        {
            return new FlowEvidence { Computer = computer, EndpointEventId = id, RunId = runId,
                EvidenceError = "Recorded endpoint assessment could not be read" }
                .Decode("{\"evidence_source\":\"Endpoint\"}", "", "", "");
        }
    }

    private static FlowEvidence? DecodeEndpoint(string json, string computer, string id)
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

        // Unassociated reports retain their own identity, role, and evidence source.
        return new FlowEvidence
        {
            FirstUs = assessment.GetProperty("first_us").GetInt64(), Computer = computer, EndpointEventId = id,
            ClientProcess = role == "Client" ? process : "", ClientPath = role == "Client" ? path : "",
            ServerProcess = role == "Server" ? process : "", ServerPath = role == "Server" ? path : "",
            EndpointProcess = role == "Unknown" ? process : "", EndpointPath = role == "Unknown" ? path : "",
            ServerName = Text("server_name"), GroupName = Text("group_name"),
            Tls = assessment.GetProperty("tls_version").GetInt32()
        }.Decode(assessment.GetProperty("crypto").GetRawText(), Text("certificate_facts"),
            Text("key_exchange"), Text("authentication"));
    }
}
