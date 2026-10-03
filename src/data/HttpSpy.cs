using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Cipherazzi.Data;

public sealed record HttpExchangeRow(long Id, long StartedUs, long EndedUs, string Client, string Server,
    string Process, string Account, string Transport, string Scheme, string Version, string Method, string Host,
    string Target, int? Status, string ContentType, long RequestBytes, long ResponseBytes, string State, string Note)
{
    public long? RequestEndUs { get; init; }
    public long? ResponseStartUs { get; init; }
    public string ClientPath { get; init; } = "";
    public long FlowId { get; init; }
    public long Sequence { get; init; }
    public long? ClientPid { get; init; }
    public string ClientAddress { get; init; } = "";
    public string ServerAddress { get; init; } = "";
    public int ClientPort { get; init; }
    public int ServerPort { get; init; }
    public long FlowStartedUs { get; init; }
    public int ConnectionClientPort { get; init; }
    public string Url => Method == "CONNECT" ? Target : Scheme + "://" + (Host.Length > 0 ? Host : Server) +
        (Target.StartsWith('/') || Target.Length == 0 ? Target : "/" + Target);
    public double DurationMs => Math.Max(0, EndedUs - StartedUs) / 1000.0;
    private long RequestEnd => Math.Clamp(RequestEndUs ?? StartedUs, StartedUs, Math.Max(StartedUs, EndedUs));
    private long ResponseStart => Math.Clamp(ResponseStartUs ?? Math.Max(StartedUs, EndedUs), RequestEnd,
        Math.Max(StartedUs, EndedUs));
    public double SendMs => (RequestEnd - StartedUs) / 1000.0;
    public double WaitMs => (ResponseStart - RequestEnd) / 1000.0;
    public double ReceiveMs => Math.Max(0, EndedUs - ResponseStart) / 1000.0;
}

public sealed record HttpExchangeDetail(HttpExchangeRow Row, string Reason, string RequestHeaders,
    string ResponseHeaders, byte[] RequestBody, byte[] ResponseBody);

// A binary body as it travelled, decoded and named for the preview and save actions.
public sealed record HttpBodyFile(byte[] Bytes, string ContentType, bool Image, bool Partial, string FileName);

public sealed record HttpSpySummary(long TlsConnections, long Decoded, long WithoutSecrets, long Unsupported,
    long Failed, long Messages, long Secrets);

public sealed record HttpSpySnapshot(List<HttpExchangeRow> Rows, bool HasMore, HttpSpySummary? Summary,
    (string Identity, long Revision) Stamp);

// The store is absent, unreadable without administrator rights, or unavailable for this kind of database.
public sealed class HttpSpyUnavailableException(string message, bool denied = false) : Exception(message)
{
    public bool Denied { get; } = denied;
}

// Decoded HTTP messages are kept in a private database beside the connection journal.
public static class HttpSpyStore
{
    public static string StorePath(DatabaseSource source) => source.Provider != DatabaseProvider.Sqlite ? "" :
        Path.Combine(Path.GetDirectoryName(source.FilePath) ?? "", "HttpSpy", Path.GetFileName(source.FilePath));

    private static SqliteConnection Open(DatabaseSource source, CancellationToken cancellation)
    {
        var path = StorePath(source);
        if (path.Length == 0)
            throw new HttpSpyUnavailableException("HTTP Spy messages are stored beside local capture journals only.");
        var directory = Path.GetDirectoryName(path)!;
        var absent = new HttpSpyUnavailableException("This capture has no HTTP Spy messages. Start the collector " +
            "with --httpspy to decode HTTP and HTTPS traffic.");
        if (!Directory.Exists(directory))
            throw absent;

        // A folder that cannot be listed is private; a listable folder without the store means none was recorded.
        var listable = true;
        if (!File.Exists(path))
        {
            try { _ = Directory.EnumerateFileSystemEntries(directory).Any(); }
            catch (UnauthorizedAccessException) { listable = false; }
            if (listable)
                throw absent;
        }
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 2
        }.ToString());
        try
        {
            connection.Open();
            if (cancellation.CanBeCanceled)
                SQLitePCL.raw.sqlite3_progress_handler(connection.Handle, 1000,
                    state => ((CancellationToken)state).IsCancellationRequested ? 1 : 0, cancellation);
            using var check = connection.CreateCommand();
            check.CommandText = "PRAGMA application_id";
            if (Convert.ToInt64(check.ExecuteScalar()) != 0x48545050)
                throw new HttpSpyUnavailableException("The HTTP Spy store was not created by the collector.");
            return connection;
        }
        catch (Exception error)
        {
            connection.Dispose();
            if (error is UnauthorizedAccessException or IOException ||
                error is SqliteException { SqliteErrorCode: 14 })
                throw new HttpSpyUnavailableException("The HTTP Spy store could not be opened. It holds decrypted " +
                    "traffic that only Administrators can read, and exists only after a collector run with " +
                    "--httpspy. Start the viewer as an administrator. " + error.Message, denied: true);
            throw;
        }
    }

    public static (string Identity, long Revision) ReadStamp(DatabaseSource source, CancellationToken cancellation)
    {
        using var connection = Open(source, cancellation);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT database_id,revision FROM store WHERE id=1";
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            throw new InvalidDataException("The HTTP Spy store has no revision.");
        return (reader.GetString(0), reader.GetInt64(1));
    }

    private const string RowColumns = "id,started_us,ended_us,client_address,client_port,server_address,server_port," +
        "client_pid,client_process,client_account,transport,scheme,version,method,host,target,status,content_type," +
        "request_bytes,response_bytes,state,note,request_end_us,response_start_us,client_path,flow_id,sequence";

    private static string Columns(SqliteConnection connection, bool detail = false)
    {
        using var version = connection.CreateCommand();
        version.CommandText = "PRAGMA user_version";
        return RowColumns + (Convert.ToInt32(version.ExecuteScalar()) >= 2 ?
            ",flow_started_us,connection_client_port" : ",started_us,client_port") +
            (detail ? ",reason,request_headers,response_headers,request_body,response_body" : "");
    }

    private static HttpExchangeRow ReadRow(SqliteDataReader reader)
    {
        string Text(int index) => reader.IsDBNull(index) ? "" : reader.GetString(index);
        var process = Text(8);
        if (process.Length == 0 && !reader.IsDBNull(7))
            process = "PID " + reader.GetInt64(7).ToString(CultureInfo.InvariantCulture);
        else if (!reader.IsDBNull(7))
            process += " (PID " + reader.GetInt64(7).ToString(CultureInfo.InvariantCulture) + ")";
        string Endpoint(int address, int port) => (Text(address).Contains(':') ? "[" + Text(address) + "]" :
            Text(address)) + ":" + reader.GetInt64(port);
        return new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2),
            Endpoint(3, 4), Endpoint(5, 6), process, Text(9), Text(10),
            Text(11), Text(12), Text(13), Text(14), Text(15), reader.IsDBNull(16) ? null : (int)reader.GetInt64(16),
            Text(17), reader.GetInt64(18), reader.GetInt64(19), Text(20), Text(21))
        {
            RequestEndUs = reader.IsDBNull(22) ? null : reader.GetInt64(22),
            ResponseStartUs = reader.IsDBNull(23) ? null : reader.GetInt64(23),
            ClientPath = Text(24), FlowId = reader.GetInt64(25), Sequence = reader.GetInt64(26),
            ClientPid = reader.IsDBNull(7) ? null : reader.GetInt64(7),
            ClientAddress = Text(3), ServerAddress = Text(5),
            ClientPort = (int)reader.GetInt64(4), ServerPort = (int)reader.GetInt64(6),
            FlowStartedUs = reader.GetInt64(27) is > 0 and var start ? start : reader.GetInt64(1),
            ConnectionClientPort = (int)(reader.GetInt64(28) is > 0 and var port ? port : reader.GetInt64(4))
        };
    }

    // Every word must appear in at least one searchable field; LIKE folds ASCII case.
    private static string SearchConditions(SqliteCommand command, string search)
    {
        var terms = search.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(8).ToArray();
        var conditions = new StringBuilder();
        for (var index = 0; index < terms.Length; ++index)
        {
            var term = terms[index];
            var prefix = term.IndexOf(':');
            var kind = prefix > 0 ? term[..prefix].ToLowerInvariant() : "";
            if (kind is "header" or "body" or "status")
                term = term[(prefix + 1)..];
            if (kind == "status" && term.Length == 3 && term[0] is >= '1' and <= '5' &&
                term[1..].Equals("xx", StringComparison.OrdinalIgnoreCase))
            {
                conditions.Append($" AND status BETWEEN @t{index} AND @t{index}+99");
                DatabaseSource.AddParameter(command, "@t" + index, (term[0] - '0') * 100);
                continue;
            }
            string[] headers = ["request_headers", "response_headers"];
            string[] bodies = ["CAST(request_body AS TEXT)", "CAST(response_body AS TEXT)"];
            string[] columns = kind switch
            {
                "header" => headers,
                "body" => bodies,
                "status" => ["CAST(status AS TEXT)"],
                _ => ["host", "target", "method", "client_process", "client_path", "client_account", "content_type",
                    "note", "state", "CAST(status AS TEXT)", "server_address", "client_address", .. headers, .. bodies]
            };
            conditions.Append(" AND (").Append(string.Join(" OR ", columns.Select(column =>
                $"{column} LIKE @t{index} ESCAPE '\\'"))).Append(')');
            DatabaseSource.AddParameter(command, "@t" + index, "%" +
                term.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%");
        }
        return conditions.ToString();
    }

    public static HttpSpySnapshot? Read(DatabaseSource source, string search, PageCursor before, int pageSize,
        (string Identity, long Revision)? known, CancellationToken cancellation)
    {
        if (pageSize is < 10 or > 2000)
            throw new ArgumentOutOfRangeException(nameof(pageSize));
        using var connection = Open(source, cancellation);
        using var stamp = connection.CreateCommand();
        stamp.CommandText = "SELECT database_id,revision FROM store WHERE id=1";
        (string, long) current;
        using (var reader = stamp.ExecuteReader())
        {
            if (!reader.Read())
                throw new InvalidDataException("The HTTP Spy store has no revision.");
            current = (reader.GetString(0), reader.GetInt64(1));
        }
        if (known == current)
            return null;
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT {Columns(connection)} FROM exchanges
            WHERE (started_us,id)<(@time,@id) {SearchConditions(command, search)}
            ORDER BY started_us DESC,id DESC LIMIT {pageSize + 1}
            """;
        DatabaseSource.AddParameter(command, "@time", before.Time);
        DatabaseSource.AddParameter(command, "@id", before.Id);
        var rows = new List<HttpExchangeRow>();
        using (var reader = command.ExecuteReader())
            while (reader.Read())
            {
                cancellation.ThrowIfCancellationRequested();
                rows.Add(ReadRow(reader));
            }
        var more = rows.Count > pageSize;
        if (more)
            rows.RemoveAt(rows.Count - 1);
        using var summary = connection.CreateCommand();
        summary.CommandText = "SELECT tls_flows,decoded_flows,missing_secrets,unsupported,failed,exchanges,secrets " +
            "FROM sessions ORDER BY updated_us DESC LIMIT 1";
        HttpSpySummary? latest = null;
        using (var reader = summary.ExecuteReader())
            if (reader.Read())
                latest = new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3),
                    reader.GetInt64(4), reader.GetInt64(5), reader.GetInt64(6));
        return new(rows, more, latest, current);
    }

    private static HttpExchangeDetail ReadDetail(SqliteDataReader reader)
    {
        byte[] Blob(int index) => reader.IsDBNull(index) ? [] : (byte[])reader[index];
        return new(ReadRow(reader), reader.GetString(29), reader.GetString(30), reader.GetString(31), Blob(32),
            Blob(33));
    }

    public static HttpExchangeDetail ReadDetail(DatabaseSource source, long id, CancellationToken cancellation)
    {
        using var connection = Open(source, cancellation);
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {Columns(connection, true)} FROM exchanges WHERE id=@id";
        DatabaseSource.AddParameter(command, "@id", id);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            throw new InvalidDataException("The selected message was removed by retention.");
        return ReadDetail(reader);
    }

    // Writes every matching decoded exchange, oldest first, as HAR 1.2; connections that stayed encrypted have none.
    public static long WriteHar(DatabaseSource source, string search, Stream output, CancellationToken cancellation,
        IProgress<long>? progress = null)
    {
        using var connection = Open(source, cancellation);
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT {Columns(connection, true)} FROM exchanges
            WHERE state<>'encrypted' {SearchConditions(command, search)} ORDER BY started_us,id
            """;
        using var writer = new Utf8JsonWriter(output, new JsonWriterOptions
        {
            Indented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
        writer.WriteStartObject();
        writer.WriteStartObject("log");
        writer.WriteString("version", "1.2");
        writer.WriteStartObject("creator");
        writer.WriteString("name", "Cipherazzi HTTP Spy");
        writer.WriteString("version", typeof(HttpSpyStore).Assembly.GetName().Version?.ToString(3) ?? "");
        writer.WriteEndObject();
        writer.WriteString("comment", "Decrypted HTTP traffic recorded by a local collector. Treat it as sensitive.");
        writer.WriteStartArray("entries");
        var count = 0L;
        using (var reader = command.ExecuteReader())
            while (reader.Read())
            {
                cancellation.ThrowIfCancellationRequested();
                WriteEntry(writer, ReadDetail(reader));
                writer.Flush();
                if (++count % 64 == 0)
                    progress?.Report(count);
            }
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.Flush();
        progress?.Report(count);
        return count;
    }

    private static void WriteHeaders(Utf8JsonWriter writer, string headers)
    {
        writer.WriteStartArray("headers");
        foreach (var line in headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0)
                continue;
            writer.WriteStartObject();
            writer.WriteString("name", line[..colon]);
            writer.WriteString("value", line[(colon + 1)..].Trim());
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }

    // Text bodies are kept as text; anything else is Base64, which HAR readers recognize by its encoding marker.
    private static void WriteBody(Utf8JsonWriter writer, byte[] body, string marker)
    {
        try { writer.WriteString("text", new UTF8Encoding(false, true).GetString(body)); }
        catch (DecoderFallbackException)
        {
            writer.WriteString("text", Convert.ToBase64String(body));
            writer.WriteString(marker, "base64");
        }
    }

    private static void WriteEntry(Utf8JsonWriter writer, HttpExchangeDetail detail)
    {
        var row = detail.Row;
        var version = row.Version.Length > 0 ? row.Version : "HTTP/1.1";
        var duration = Math.Round(row.DurationMs, 3);
        writer.WriteStartObject();
        writer.WriteString("startedDateTime", DateTimeOffset.FromUnixTimeMilliseconds(row.StartedUs / 1000).UtcDateTime
            .ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
        writer.WriteNumber("time", duration);

        // Bodies are stored as captured; HAR carries them after any Content-Encoding is removed.
        writer.WriteStartObject("request");
        writer.WriteString("method", row.Method);
        writer.WriteString("url", row.Url);
        writer.WriteString("httpVersion", version);
        writer.WriteStartArray("cookies");
        writer.WriteEndArray();
        WriteHeaders(writer, detail.RequestHeaders);
        writer.WriteStartArray("queryString");
        var query = row.Target.IndexOf('?');
        foreach (var (name, value) in HttpPayload.Pairs(query < 0 ? "" : row.Target[(query + 1)..]))
        {
            writer.WriteStartObject();
            writer.WriteString("name", name);
            writer.WriteString("value", value);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        if (detail.RequestBody.Length > 0)
        {
            writer.WriteStartObject("postData");
            writer.WriteString("mimeType", HttpMessageText.Header(detail.RequestHeaders, "Content-Type"));
            WriteBody(writer, HttpMessageText.Decode(detail.RequestBody,
                HttpMessageText.Header(detail.RequestHeaders, "Content-Encoding"), out _), "_encoding");
            writer.WriteEndObject();
        }
        writer.WriteNumber("headersSize", -1);
        writer.WriteNumber("bodySize", row.RequestBytes);
        writer.WriteEndObject();
        writer.WriteStartObject("response");
        writer.WriteNumber("status", row.Status ?? 0);
        writer.WriteString("statusText", detail.Reason);
        writer.WriteString("httpVersion", version);
        writer.WriteStartArray("cookies");
        writer.WriteEndArray();
        WriteHeaders(writer, detail.ResponseHeaders);
        var note = "";
        var decoded = detail.ResponseBody.Length == 0 ? detail.ResponseBody : HttpMessageText.Decode(
            detail.ResponseBody, HttpMessageText.Header(detail.ResponseHeaders, "Content-Encoding"), out note);
        writer.WriteStartObject("content");
        writer.WriteNumber("size", decoded.Length);
        writer.WriteString("mimeType", HttpMessageText.Header(detail.ResponseHeaders, "Content-Type"));
        if (decoded.Length > 0)
            WriteBody(writer, decoded, "encoding");
        var partial = row.ResponseBytes > detail.ResponseBody.Length ? "Only part of the body was kept. " : "";
        if (note.Length + partial.Length > 0)
            writer.WriteString("comment", partial + note);
        writer.WriteEndObject();
        writer.WriteString("redirectURL", HttpMessageText.Header(detail.ResponseHeaders, "Location"));
        writer.WriteNumber("headersSize", -1);
        writer.WriteNumber("bodySize", row.ResponseBytes);
        if (row.Status is null)
            writer.WriteString("comment", "No response was observed.");
        writer.WriteEndObject();
        writer.WriteStartObject("cache");
        writer.WriteEndObject();
        writer.WriteStartObject("timings");
        writer.WriteNumber("send", Math.Round(row.SendMs, 3));
        writer.WriteNumber("wait", Math.Round(row.WaitMs, 3));
        writer.WriteNumber("receive", Math.Round(row.ReceiveMs, 3));
        writer.WriteEndObject();
        writer.WriteString("serverIPAddress", row.ServerAddress);
        writer.WriteString("connection", row.Client[(row.Client.LastIndexOf(':') + 1)..]);
        writer.WriteString("_process", row.Process);
        writer.WriteString("_client", row.Client);
        if (row.Note.Length > 0)
            writer.WriteString("comment", row.Note);
        writer.WriteEndObject();
    }
}

// Presents a captured message: its start line, headers, and a readable form of its body.
public static class HttpMessageText
{
    private const int MaximumCharacters = 1 << 20;
    private const int MaximumDecodedBytes = 8 * 1024 * 1024;

    public static string Header(string headers, string name)
    {
        foreach (var line in headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = line.IndexOf(':');
            if (colon > 0 && string.Equals(line[..colon], name, StringComparison.OrdinalIgnoreCase))
                return line[(colon + 1)..].Trim();
        }
        return "";
    }

    public static byte[] Decode(byte[] body, string encoding, out string note)
    {
        note = "";
        var codings = encoding.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Reverse().ToArray();
        foreach (var coding in codings)
        {
            if (coding.Equals("identity", StringComparison.OrdinalIgnoreCase))
                continue;
            Func<Stream, Stream>? wrap = coding.ToLowerInvariant() switch
            {
                "gzip" or "x-gzip" => stream => new GZipStream(stream, CompressionMode.Decompress),
                "br" => stream => new BrotliStream(stream, CompressionMode.Decompress),
                "deflate" => stream => new ZLibStream(stream, CompressionMode.Decompress),
                _ => null
            };
            if (wrap is null)
            {
                note = $"Content-Encoding {coding} is not decoded.";
                return body;
            }

            // A body kept only in part still yields the text that precedes its end.
            using var output = new MemoryStream();
            bool limited = false, damaged = false;
            bool Read(Stream input)
            {
                var buffer = new byte[16384];
                while (output.Length < MaximumDecodedBytes)
                {
                    var count = input.Read(buffer, 0,
                        (int)Math.Min(buffer.Length, MaximumDecodedBytes - output.Length));
                    if (count == 0)
                        return false;
                    output.Write(buffer, 0, count);
                }
                return input.ReadByte() != -1;
            }
            try
            {
                using var input = wrap(new MemoryStream(body));
                limited = Read(input);
            }
            catch (Exception error) when (error is InvalidDataException or IOException or EndOfStreamException)
            {
                damaged = true;
                if (output.Length == 0 && coding.Equals("deflate", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var raw = new DeflateStream(new MemoryStream(body), CompressionMode.Decompress);
                        limited = Read(raw);
                        damaged = false;
                    }
                    catch (Exception inner) when (inner is InvalidDataException or IOException) { }
                }
            }
            if (limited)
                note = "The decoded body exceeds the 8 MiB display and save limit.";
            else if (damaged)
                note = output.Length == 0 ? $"The {coding} body could not be decoded." :
                    "The captured body ends before its compressed data does.";
            body = output.ToArray();
        }
        return body;
    }

    private static bool IsReadable(string contentType, byte[] decoded) => decoded.Length > 0 &&
        (contentType.StartsWith("text/") || contentType.Contains("json") || contentType.Contains("xml") ||
        contentType.Contains("javascript") || contentType.Contains("x-www-form-urlencoded") ||
        contentType.Contains("html") || LooksLikeText(decoded));

    // The decoded body of a message when it is binary, such as a picture or a download; null for text and no body.
    public static HttpBodyFile? BodyFile(string headers, byte[] body, long totalBytes, string target)
    {
        if (body.Length == 0)
            return null;
        var decoded = Decode(body, Header(headers, "Content-Encoding"), out var note);
        var type = Header(headers, "Content-Type").Split(';')[0].Trim().ToLowerInvariant();
        if (decoded.Length == 0 || IsReadable(type, decoded))
            return null;
        var (_, extension, picture) = HttpPayload.Identify(decoded);
        var name = "";
        try
        {
            var disposition = Regex.Match(Header(headers, "Content-Disposition"),
                "filename\\*?=(?:UTF-8'')?\"?([^\";]+)\"?", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
            name = Uri.UnescapeDataString(disposition.Success ? disposition.Groups[1].Value.Trim() :
                target.Split('?', '#')[0].Split('/')[^1]);
        }
        catch (Exception error) when (error is RegexMatchTimeoutException or UriFormatException) { }
        name = string.Concat(name.Select(character => Path.GetInvalidFileNameChars().Contains(character) ?
            '_' : character)).Trim(' ', '.');
        name = name.Length == 0 ? "body" : name[..Math.Min(name.Length, 100)];
        return new(decoded, type, picture || type.StartsWith("image/") && !type.Contains("svg"),
            totalBytes > body.Length || note.Length > 0,
            Path.GetExtension(name).Length == 0 ? name + "." + extension : name);
    }

    // The Base64, URL, SAML, and JWT views replace the body with what they decode from the whole message.
    public static string Render(string startLine, string headers, byte[] body, long totalBytes,
        HttpPayloadView view = HttpPayloadView.Automatic)
    {
        var text = new StringBuilder(startLine).Append("\r\n").Append(headers).Append("\r\n");
        var derived = view is HttpPayloadView.Base64 or HttpPayloadView.UrlEncoded or HttpPayloadView.Saml or
            HttpPayloadView.Jwt;
        var contentType = Header(headers, "Content-Type").ToLowerInvariant();
        var note = "";
        var decoded = body.Length == 0 ? body : Decode(body, Header(headers, "Content-Encoding"), out note);
        var readable = IsReadable(contentType, decoded);
        var value = "";
        if (readable)
        {
            var charset = contentType.Split(';').Select(part => part.Trim()).FirstOrDefault(part =>
                part.StartsWith("charset=", StringComparison.Ordinal))?[8..].Trim('"');
            try { value = (charset is null ? new UTF8Encoding(false, true) : Encoding.GetEncoding(charset))
                .GetString(decoded); }
            catch (Exception error) when (error is ArgumentException or DecoderFallbackException)
            { value = Encoding.Latin1.GetString(decoded); }
        }
        var found = derived || view == HttpPayloadView.Automatic ?
            HttpPayload.Describe(view, startLine, headers, value) : "";
        if (derived)
            text.Append(found);
        else if (totalBytes == 0)
            text.Append("(no body)");
        else if (decoded.Length == 0)
            text.Append($"({totalBytes:N0} body bytes were not kept)");
        else
        {
            // Automatic lays the body out by its data type; Raw keeps the text as sent.
            var formatted = view == HttpPayloadView.Automatic ?
                HttpPayload.Format(Header(headers, "Content-Type"), decoded, value) : null;
            if (formatted is null && (view == HttpPayloadView.Hex || !readable))
            {
                if (view == HttpPayloadView.Automatic)
                    text.Append(HttpPayload.Summarize(decoded)).Append("\r\n\r\n");
                formatted = HexDump(decoded, view == HttpPayloadView.Hex ? 65536 : 4096);
            }
            formatted ??= value;
            text.Append(formatted.Length > MaximumCharacters ? formatted[..MaximumCharacters] : formatted);
        }
        if (view == HttpPayloadView.Automatic && found.Length > 0)
            text.Append("\r\n\r\n").Append(found);
        if (note.Length > 0 && (decoded.Length > 0 || derived))
            text.Append("\r\n\r\n(").Append(note).Append(')');
        if (totalBytes > body.Length && (body.Length > 0 || derived))
            text.Append($"\r\n\r\n({totalBytes - body.Length:N0} more body bytes were not kept)");
        return text.ToString();
    }

    internal static bool LooksLikeText(byte[] bytes)
    {
        var sample = bytes.AsSpan(0, Math.Min(bytes.Length, 4096));
        if (sample.IndexOf((byte)0) >= 0)
            return false;
        foreach (var value in sample)
            if (value < 9 || value is > 13 and < 32)
                return false;
        try { _ = new UTF8Encoding(false, true).GetString(sample); return true; }
        catch (DecoderFallbackException) { return false; }
    }

    internal static string HexDump(byte[] bytes, int limit)
    {
        var text = new StringBuilder();
        var length = Math.Min(bytes.Length, limit);
        for (var offset = 0; offset < length; offset += 16)
        {
            var line = bytes.AsSpan(offset, Math.Min(16, length - offset));
            text.Append(offset.ToString("x8", CultureInfo.InvariantCulture)).Append("  ");
            for (var index = 0; index < 16; ++index)
                text.Append(index < line.Length ? line[index].ToString("x2", CultureInfo.InvariantCulture) : "  ")
                    .Append(index == 7 ? "  " : " ");
            text.Append(' ');
            foreach (var value in line)
                text.Append(value is >= 32 and < 127 ? (char)value : '.');
            text.Append("\r\n");
        }
        if (bytes.Length > length)
            text.Append($"… {bytes.Length - length:N0} more bytes");
        return text.ToString();
    }
}
