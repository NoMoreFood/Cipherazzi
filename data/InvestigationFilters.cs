using System.Data.Common;
using System.Globalization;
using System.Text.Json;
using System.Xml.Linq;

namespace Cipherazzi.Data;

public enum InvestigationTarget { Connections, Endpoints }
public enum ObservationField
{
    Computer, Process, ClientProcess, ServerProcess, ServerName, ClientAddress, ServerAddress,
    ClientPort, ServerPort, ProcessId, Protocol, Transport, Cipher, Group, State, KeyClass, Provider
}
public enum FilterComparison { Contains, Equals, StartsWith, NotEquals, Observed, NotObserved }

public sealed record FieldFilter(ObservationField Field, FilterComparison Comparison, string Value = "")
{
    public bool Numeric => Field is ObservationField.ClientPort or ObservationField.ServerPort or
        ObservationField.ProcessId;
    public bool NeedsValue => Comparison is not (FilterComparison.Observed or FilterComparison.NotObserved);

    internal void Validate()
    {
        if (!Enum.IsDefined(Field) || !Enum.IsDefined(Comparison) || Value is null || Value.Length > 256 ||
            Value.Contains('\0') || NeedsValue && Value.Length == 0)
            throw new InvalidDataException("Supply a supported filter and a value of at most 256 characters.");
        if (Numeric && NeedsValue && (Comparison is not (FilterComparison.Equals or FilterComparison.NotEquals) ||
            !long.TryParse(Value, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ||
            value < 1 || value > (Field == ObservationField.ProcessId ? uint.MaxValue : 65535)))
            throw new InvalidDataException("Ports and process IDs require a positive number and an equality comparison.");
    }
}

public sealed record Query(string Search, string Protocol, bool Incomplete, PageCursor Before, int PageSize = 250)
{
    public long FromUs { get; init; }
    public long ToUs { get; init; } = long.MaxValue;
    public IReadOnlyList<FieldFilter> Conditions { get; init; } = [];
    public bool HasDateRange => FromUs != 0 || ToUs != long.MaxValue;
    public bool HasAdvancedFilters => HasDateRange || Conditions.Count > 0;
    public string FilterKey => JsonSerializer.Serialize(new { Search, Protocol, Incomplete, Conditions });
    public string CacheKey => FilterKey + "\0" + FromUs + "\0" + ToUs;
    public string ScopeKey => FilterKey + "\0" + (HasDateRange ? $"{FromUs == 0}|{ToUs == long.MaxValue}|" +
        (ToUs == long.MaxValue ? "" : (ToUs - FromUs).ToString(CultureInfo.InvariantCulture)) : "");

    public void Validate(InvestigationTarget target = InvestigationTarget.Connections)
    {
        if (Search is null || Protocol is null || Search.Length > 256 || Search.Contains('\0') ||
            Protocol.Length > 64 || FromUs < 0 || FromUs > 253402300799999999L || ToUs < FromUs ||
            ToUs != long.MaxValue && ToUs > 253402300799999999L || Conditions is null || Conditions.Count > 16 ||
            PageSize is < 50 or > 2000)
            throw new InvalidDataException("Choose valid dates, at most 16 conditions, and a page size from 50 to 2000.");
        foreach (var condition in Conditions)
        {
            if (condition is null || target == InvestigationTarget.Connections &&
                condition.Field == ObservationField.Provider)
                throw new InvalidDataException("Provider conditions apply to endpoint reports.");
            condition.Validate();
        }
    }

    public Query CopyScope() => this with { Before = PageCursor.Newest, Conditions = Conditions.ToArray() };
}

public sealed record SavedSearch(string Name, InvestigationTarget Target, Query Query)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Name) || Name.Length > 80 || Name.Any(char.IsControl) || !Enum.IsDefined(Target))
            throw new InvalidDataException("Supply a saved-search name of at most 80 characters.");
        Query.Validate(Target);
    }

    public XElement ToXml() => new("search", new XAttribute("name", Name), new XAttribute("target", Target),
        new XAttribute("text", Query.Search), new XAttribute("protocol", Query.Protocol),
        new XAttribute("partial", Query.Incomplete), new XAttribute("fromUs", Query.FromUs),
        new XAttribute("toUs", Query.ToUs), Query.Conditions.Select(condition => new XElement("condition",
            new XAttribute("field", condition.Field), new XAttribute("comparison", condition.Comparison),
            new XAttribute("value", condition.Value))));

    public static SavedSearch FromXml(XElement element)
    {
        if (!Enum.TryParse<InvestigationTarget>((string?)element.Attribute("target"), out var target))
            throw new InvalidDataException("Choose a supported saved-search target.");
        var conditions = element.Elements("condition").Select(condition =>
        {
            if (!Enum.TryParse<ObservationField>((string?)condition.Attribute("field"), out var field) ||
                !Enum.TryParse<FilterComparison>((string?)condition.Attribute("comparison"), out var comparison))
                throw new InvalidDataException("Saved search contains an unsupported condition.");
            return new FieldFilter(field, comparison, (string?)condition.Attribute("value") ?? "");
        }).ToArray();
        var result = new SavedSearch((string?)element.Attribute("name") ?? "", target,
            new((string?)element.Attribute("text") ?? "", (string?)element.Attribute("protocol") ?? "",
                (bool?)element.Attribute("partial") ?? false, PageCursor.Newest)
            {
                FromUs = (long?)element.Attribute("fromUs") ?? 0,
                ToUs = (long?)element.Attribute("toUs") ?? long.MaxValue, Conditions = conditions
            });
        result.Validate();
        return result;
    }
}

internal static class InvestigationSql
{
    internal static string Escape(string text) => text.Replace("\\", "\\\\").Replace("%", "\\%")
        .Replace("_", "\\_").Replace("[", "\\[");

    internal static (long From, long To) Bounds(Query query, long from, long to) =>
        query.HasDateRange ? (query.FromUs, query.ToUs) : (from, to);

    internal static List<string> Conditions(DatabaseSource source, Query query, DbCommand command, bool endpoint)
    {
        query.Validate(endpoint ? InvestigationTarget.Endpoints : InvestigationTarget.Connections);
        string Json(string path) => source.JsonValue(endpoint ? "e.detail_json" : "c.crypto_json", path);
        var role = endpoint ? $"LOWER(COALESCE({Json("assessment.local_role")},{Json("role")},''))" : "";
        string Socket(string side, string field)
        {
            if (!endpoint)
                return $"c.{(side == "client" ? "source" : "destination")}_{field}";
            var value = $"CASE WHEN {role}='{side}' THEN {Json("local." + field)} " +
                $"WHEN {role}='{(side == "client" ? "server" : "client")}' THEN {Json("remote." + field)} END";
            return field == "port" ? $"CAST(({value}) AS BIGINT)" : value;
        }
        string[] Process(string side) => endpoint ?
            [$"CASE WHEN {role}='{side}' THEN {Json("assessment.process")} END",
             $"CASE WHEN {role}='{side}' THEN {Json("assessment.path")} END"] :
            [$"c.{(side == "client" ? "source" : "destination")}_process",
             $"c.{(side == "client" ? "source" : "destination")}_path"];
        string[] Fields(ObservationField field) => field switch
        {
            ObservationField.Computer => ["s.computer_name"],
            ObservationField.Process => endpoint ? [Json("assessment.process"), Json("assessment.path")] :
                ["c.source_process", "c.source_path", "c.destination_process", "c.destination_path"],
            ObservationField.ClientProcess => Process("client"), ObservationField.ServerProcess => Process("server"),
            ObservationField.ServerName => endpoint ? [$"COALESCE({Json("assessment.server_name")},e.peer)"] :
                ["COALESCE(NULLIF(c.sni,''),c.destination_address)"],
            ObservationField.ClientAddress => [Socket("client", "address")],
            ObservationField.ServerAddress => [Socket("server", "address")],
            ObservationField.ClientPort => [Socket("client", "port")],
            ObservationField.ServerPort => [Socket("server", "port")],
            ObservationField.ProcessId => endpoint ? ["e.pid"] : ["c.source_pid", "c.destination_pid"],
            ObservationField.Protocol => [endpoint ? "e.protocol" : "c.tls_name"],
            ObservationField.Transport => endpoint ? [Json("transport"), Json("assessment.crypto.transport")] :
                [$"COALESCE({Json("transport")},'TCP')"],
            ObservationField.Cipher => endpoint ? ["e.cipher"] : ["c.cipher_name", "c.encryption"],
            ObservationField.Group => [endpoint ? Json("assessment.group_name") : "c.group_name"],
            ObservationField.State => [endpoint ? "e.result" : "c.state"],
            ObservationField.KeyClass => [Json(endpoint ? "assessment.crypto.group_class" : "group_class")],
            ObservationField.Provider => ["e.provider"],
            _ => throw new InvalidDataException("Unsupported observation field.")
        };
        var predicates = new List<string>();

        // Every user value is bound; multiple conditions intersect and multi-owner fields retain any-match semantics.
        for (var index = 0; index < query.Conditions.Count; index++)
        {
            var condition = query.Conditions[index];
            var fields = Fields(condition.Field);
            var observed = "(" + string.Join(" OR ", fields.Select(field =>
                $"({field} IS NOT NULL AND {field}<>{(condition.Numeric ? "0" : "''")})")) + ")";
            if (!condition.NeedsValue)
            {
                predicates.Add(condition.Comparison == FilterComparison.Observed ? observed : "NOT " + observed);
                continue;
            }
            var parameter = "@condition" + index;
            var text = condition.Value;
            object value = condition.Numeric ? long.Parse(condition.Value, CultureInfo.InvariantCulture) :
                condition.Comparison == FilterComparison.Contains ? "%" + Escape(text) + "%" :
                condition.Comparison == FilterComparison.StartsWith ? Escape(text) + "%" : text;
            DatabaseSource.AddParameter(command, parameter, value);
            var matches = "(" + string.Join(" OR ", fields.Select(field => condition.Numeric ?
                $"{field}={parameter}" : condition.Comparison is FilterComparison.Contains or FilterComparison.StartsWith ?
                source.TextMatch(field, parameter) : $"{source.LowerText(field)}={source.LowerText(parameter)}")) + ")";
            predicates.Add(condition.Comparison == FilterComparison.NotEquals ? observed + " AND NOT " +
                "(" + string.Join(" OR ", fields.Select(field => condition.Numeric ?
                    $"COALESCE({field},0)={parameter}" :
                    $"COALESCE({source.LowerText(field)},'')={source.LowerText(parameter)}")) + ")" : matches);
        }
        return predicates;
    }

    internal static string EndpointWhere(DatabaseSource source, Query query, DbCommand command,
        long from = 0, long to = long.MaxValue, bool operationTime = false)
    {
        var conditions = Conditions(source, query, command, true);
        var time = operationTime ? $"CAST({source.JsonValue("e.detail_json", "assessment.first_us")} AS BIGINT)" :
            "e.timestamp_us";
        var bounds = Bounds(query, from, to);
        if (bounds.From > 0)
        {
            conditions.Add(time + ">=@since");
            DatabaseSource.AddParameter(command, "@since", bounds.From);
        }
        if (bounds.To < long.MaxValue)
        {
            conditions.Add(time + "<=@until");
            DatabaseSource.AddParameter(command, "@until", bounds.To);
        }
        if (query.Protocol.Length > 0)
        {
            conditions.Add("e.protocol=@version");
            DatabaseSource.AddParameter(command, "@version", query.Protocol);
        }
        if (query.Incomplete)
            conditions.Add("1=0");
        if (query.Search.Length > 0)
        {
            conditions.Add("(" + string.Join(" OR ", new[] { "e.peer", "e.provider", "e.kind", "e.result", "e.cipher",
                "e.protocol", "s.computer_name", source.JsonValue("e.detail_json", "assessment.process"),
                source.JsonValue("e.detail_json", "assessment.path"),
                source.JsonValue("e.detail_json", "assessment.server_name"),
                source.JsonValue("e.detail_json", "assessment.group_name"),
                source.JsonValue("e.detail_json", "assessment.crypto.group_class"),
                source.JsonValue("e.detail_json", "assessment.crypto.transport"),
                source.JsonValue("e.detail_json", "assessment.key_exchange"),
                source.JsonValue("e.detail_json", "assessment.authentication") }.Select(field =>
                    source.TextMatch(field, "@endpointPattern"))) + ")");
            DatabaseSource.AddParameter(command, "@endpointPattern", "%" + Escape(query.Search) + "%");
        }
        return conditions.Count == 0 ? "1=1" : string.Join(" AND ", conditions);
    }
}
