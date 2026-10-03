using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Cipherazzi.Data;

public enum HttpPayloadView { Automatic, Raw, Hex, Base64, UrlEncoded, Saml, Jwt }

// Unwraps the encodings that carry application payloads: Base64, URL and form encoding, SAML messages, and JWTs.
public static class HttpPayload
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);
    private static readonly Regex Token = new(@"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*",
        RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex HtmlInput = new(@"<input\b[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex HtmlAttribute = new(@"([A-Za-z][\w-]*)\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>]+))",
        RegexOptions.CultureInvariant, Timeout);
    private static readonly string[] SamlFields = ["SAMLRequest", "SAMLResponse", "SAMLart"];
    private static readonly JsonSerializerOptions Indented = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static string Crlf(string text) => text.Replace("\r\n", "\n").Replace("\n", "\r\n");

    public static string Pretty(string json)
    {
        using var document = JsonDocument.Parse(json);
        return Crlf(JsonSerializer.Serialize(document.RootElement, Indented));
    }

    private static string Pretty(XDocument document) => Crlf(document.ToString());

    private static string? TryPretty(string json)
    {
        try { return Pretty(json); }
        catch (JsonException) { return null; }
    }

    // Lays a body out for reading according to its data type; null when the type has nothing to improve.
    public static string? Format(string contentType, byte[] body, string text) => Format(contentType, body, text, 0);

    private static string? Format(string contentType, byte[] body, string text, int depth)
    {
        var type = contentType.Split(';')[0].Trim().ToLowerInvariant();
        var start = text.TrimStart();
        var untyped = type is "" or "text/plain" or "application/octet-stream";
        if (depth < 4 && body.AsSpan().StartsWith(new byte[] { 0x1f, 0x8b }))
        {
            var decoded = HttpMessageText.Decode(body, "gzip", out var note);
            if (decoded.Length > 0)
            {
                var value = HttpMessageText.LooksLikeText(decoded) ? Encoding.UTF8.GetString(decoded) : "";
                return "Gzip body\r\n\r\n" + (Format(type is "application/gzip" or "application/x-gzip" ?
                    "application/octet-stream" : contentType, decoded, value, depth + 1) ??
                    (value.Length > 0 ? value : HttpMessageText.HexDump(decoded, 4096))) +
                    (note.Length > 0 ? "\r\n\r\n(" + note + ")" : "");
            }
        }
        if (type.Contains("msgpack") || type.Contains("messagepack") || untyped && body.Length > 0 &&
            (body[0] is >= 0x80 and <= 0x9f or 0xdc or 0xdd or 0xde or 0xdf))
            return MessagePack(body);
        if (type.StartsWith("application/grpc", StringComparison.Ordinal))
            return Protobuf(body, true);
        if (type.Contains("protobuf") || type is "application/proto" or "application/vnd.google.protobuf")
            return Protobuf(body, false);
        if (untyped && body.Length >= 2 && !HttpMessageText.LooksLikeText(body) &&
            Identify(body).Kind == "Binary data" && Protobuf(body, false) is { } protobuf)
            return protobuf;
        if (type is "application/x-ndjson" or "application/jsonl" or "application/x-jsonlines")
        {
            var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(TryPretty).ToArray();
            return lines.Length > 0 && !lines.Contains(null) ? string.Join("\r\n\r\n", lines) : null;
        }
        if (type.Contains("json") || untyped && start is ['{' or '[', ..])
            return TryPretty(text);
        if (type.Contains("xml") || untyped && start.StartsWith("<?xml", StringComparison.Ordinal))
            return Parse(text) is { } document ? (document.Declaration is { } declaration ? declaration + "\r\n" : "") +
                Pretty(document) : null;
        if (type == "application/x-www-form-urlencoded")
        {
            var form = new StringBuilder();
            foreach (var (name, value) in Pairs(text.Trim()))
            {
                form.Append(name).Append(" = ");
                form.Append(value.TrimStart() is ['{' or '[', ..] && TryPretty(value) is { } json ?
                    "\r\n    " + json.Replace("\r\n", "\r\n    ") : value).Append("\r\n");
            }
            return form.Length > 0 ? form.ToString().TrimEnd() : null;
        }
        if (type.StartsWith("multipart/", StringComparison.Ordinal))
            return Multipart(contentType, body);
        if (type.Contains("x509") || type.Contains("pkix-cert") || start.StartsWith("-----BEGIN CERTIFICATE-----",
            StringComparison.Ordinal))
            return Certificate(body, start);
        return null;
    }

    // Binary formats are bounded and must consume the entire body before claiming a successful decode.
    private static string? Protobuf(byte[] body, bool grpc)
    {
        var output = new StringBuilder();
        var offset = 0;
        var fields = 0;
        ulong Varint(int end)
        {
            ulong value = 0;
            for (var shift = 0; shift < 70 && offset < end; shift += 7)
            {
                var part = body[offset++];
                if (shift == 63 && part > 1)
                    throw new InvalidDataException();
                value |= (ulong)(part & 127) << shift;
                if (part < 128)
                    return value;
            }
            throw new InvalidDataException();
        }
        void Message(int end)
        {
            while (offset < end)
            {
                if (++fields > 10000 || output.Length > 1 << 20)
                    throw new InvalidDataException();
                var tag = Varint(end);
                var number = tag >> 3;
                var wire = (int)(tag & 7);
                if (number is 0 or > 536870911)
                    throw new InvalidDataException();
                output.Append("Field ").Append(number).Append(" (wire ").Append(wire).Append("): ");
                if (wire == 0)
                    output.Append("varint ").Append(Varint(end));
                else if (wire is 1 or 5)
                {
                    var count = wire == 1 ? 8 : 4;
                    if (end - offset < count)
                        throw new InvalidDataException();
                    output.Append(wire == 1 ? "fixed64 " : "fixed32 ").Append(wire == 1 ?
                        BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(offset)) :
                        BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(offset)));
                    offset += count;
                }
                else if (wire == 2)
                {
                    var length = Varint(end);
                    if (length > (ulong)(end - offset))
                        throw new InvalidDataException();
                    var bytes = body.AsSpan(offset, (int)length).ToArray();
                    output.Append(HttpMessageText.LooksLikeText(bytes) ? "string " +
                        JsonSerializer.Serialize(Encoding.UTF8.GetString(
                            bytes.AsSpan(0, Math.Min(bytes.Length, 4096)))) +
                        (bytes.Length > 4096 ? "…" : "") :
                        $"bytes[{length}] " + Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 512))) +
                        (bytes.Length > 512 ? "…" : ""));
                    offset += (int)length;
                }
                else
                    throw new InvalidDataException();
                output.Append("\r\n");
            }
        }
        try
        {
            var message = 0;
            var decodedBytes = 0;
            while (offset < body.Length)
            {
                if (++message > 10000 || output.Length > 1 << 20)
                    return null;
                if (!grpc)
                {
                    Message(body.Length);
                    break;
                }
                if (body.Length - offset < 5 || body[offset] > 1)
                    return null;
                var compressed = body[offset] == 1;
                var length = BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(offset + 1));
                offset += 5;
                if (length > body.Length - offset)
                    return null;
                output.Append("gRPC message ").Append(message).Append("\r\n");
                if (compressed)
                {
                    var bytes = body.AsSpan(offset, (int)length).ToArray();
                    string? decoded = null;
                    if (bytes.AsSpan().StartsWith(new byte[] { 0x1f, 0x8b }))
                    {
                        var plain = HttpMessageText.Decode(bytes, "gzip", out var note);
                        decodedBytes += plain.Length;
                        if (note.Length > 0 || decodedBytes > 8 * 1024 * 1024)
                            return null;
                        decoded = Protobuf(plain, false);
                    }
                    output.Append(decoded ?? "Compressed message; its grpc-encoding is required.").Append("\r\n");
                    offset += (int)length;
                }
                else
                    Message(offset + (int)length);
            }
            return output.Length > 0 ? output.ToString().TrimEnd() : null;
        }
        catch (InvalidDataException) { return null; }
    }

    private static string? MessagePack(byte[] body)
    {
        var offset = 0;
        var nodes = 0;
        var output = new StringBuilder();
        ulong Unsigned(int count)
        {
            if (body.Length - offset < count)
                throw new InvalidDataException();
            ulong value = 0;
            while (count-- > 0)
                value = value << 8 | body[offset++];
            return value;
        }
        void Bytes(ulong length, bool text)
        {
            if (length > (ulong)(body.Length - offset))
                throw new InvalidDataException();
            var bytes = body.AsSpan(offset, (int)length);
            output.Append(text ? JsonSerializer.Serialize(Encoding.UTF8.GetString(
                bytes[..Math.Min(bytes.Length, 4096)])) +
                (bytes.Length > 4096 ? "…" : "") :
                $"bytes[{length}] " + Convert.ToHexString(bytes[..Math.Min(bytes.Length, 512)]) +
                (bytes.Length > 512 ? "…" : ""));
            offset += (int)length;
        }
        void Container(ulong count, bool map, int depth)
        {
            if (count > 10000)
                throw new InvalidDataException();
            output.Append(map ? "{" : "[");
            for (ulong index = 0; index < count; ++index)
            {
                output.Append(index == 0 ? "\r\n" : ",\r\n").Append(' ', (depth + 1) * 2);
                Value(depth + 1);
                if (!map)
                    continue;
                output.Append(": ");
                Value(depth + 1);
            }
            if (count > 0)
                output.Append("\r\n").Append(' ', depth * 2);
            output.Append(map ? "}" : "]");
        }
        void Value(int depth)
        {
            if (depth > 16 || ++nodes > 10000 || output.Length > 1 << 20)
                throw new InvalidDataException();
            var tag = (byte)Unsigned(1);
            if (tag <= 0x7f) { output.Append(tag); return; }
            if (tag >= 0xe0) { output.Append(unchecked((sbyte)tag)); return; }
            if (tag is >= 0xa0 and <= 0xbf) { Bytes((ulong)(tag & 31), true); return; }
            if (tag is >= 0x90 and <= 0x9f) { Container((ulong)(tag & 15), false, depth); return; }
            if (tag is >= 0x80 and <= 0x8f) { Container((ulong)(tag & 15), true, depth); return; }
            switch (tag)
            {
                case 0xc0: output.Append("null"); break;
                case 0xc2: output.Append("false"); break;
                case 0xc3: output.Append("true"); break;
                case >= 0xc4 and <= 0xc6: Bytes(Unsigned(1 << (tag - 0xc4)), false); break;
                case 0xca: output.Append(BitConverter.Int32BitsToSingle((int)Unsigned(4))
                    .ToString("R", CultureInfo.InvariantCulture)); break;
                case 0xcb: output.Append(BitConverter.Int64BitsToDouble((long)Unsigned(8))
                    .ToString("R", CultureInfo.InvariantCulture)); break;
                case >= 0xcc and <= 0xcf: output.Append(Unsigned(1 << (tag - 0xcc))); break;
                case >= 0xd0 and <= 0xd3:
                    var bits = 8 << (tag - 0xd0);
                    var signed = Unsigned(bits / 8);
                    output.Append(unchecked((long)(signed << (64 - bits))) >> (64 - bits));
                    break;
                case >= 0xd9 and <= 0xdb: Bytes(Unsigned(1 << (tag - 0xd9)), true); break;
                case 0xdc or 0xdd: Container(Unsigned(tag == 0xdc ? 2 : 4), false, depth); break;
                case 0xde or 0xdf: Container(Unsigned(tag == 0xde ? 2 : 4), true, depth); break;
                case >= 0xc7 and <= 0xc9:
                case >= 0xd4 and <= 0xd8:
                    var length = tag <= 0xc9 ? Unsigned(1 << (tag - 0xc7)) : (ulong)(1 << (tag - 0xd4));
                    output.Append("extension ").Append(unchecked((sbyte)Unsigned(1))).Append(' ');
                    Bytes(length, false);
                    break;
                default: throw new InvalidDataException();
            }
        }
        try
        {
            Value(0);
            return offset == body.Length ? output.ToString() : null;
        }
        catch (Exception error) when (error is InvalidDataException or DecoderFallbackException) { return null; }
    }

    // Each part of a form upload, with its own headers and a body laid out by that part's type.
    private static string? Multipart(string contentType, byte[] body)
    {
        var boundary = contentType.Split(';').Select(part => part.Trim()).FirstOrDefault(part =>
            part.StartsWith("boundary=", StringComparison.OrdinalIgnoreCase))?[9..].Trim('"');
        if (string.IsNullOrEmpty(boundary))
            return null;
        var output = new StringBuilder();
        var sections = Encoding.Latin1.GetString(body).Split("--" + boundary);

        // The first section is the preamble and the last starts with the closing delimiter.
        foreach (var (section, index) in sections.Skip(1).Select((value, position) => (value, position + 1)))
        {
            var part = section.StartsWith("\r\n", StringComparison.Ordinal) ? section[2..] : section;
            var split = part.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (part.StartsWith("--", StringComparison.Ordinal) || split < 0)
                continue;
            var content = part[(split + 4)..];
            content = content.EndsWith("\r\n", StringComparison.Ordinal) ? content[..^2] : content;
            var bytes = Encoding.Latin1.GetBytes(content);
            output.Append(output.Length > 0 ? "\r\n\r\n" : "").Append("Part ").Append(index).Append("\r\n")
                .Append(part[..split]).Append("\r\n\r\n");
            if (!HttpMessageText.LooksLikeText(bytes))
            {
                output.Append(Summarize(bytes));
                continue;
            }
            var text = Encoding.UTF8.GetString(bytes);
            output.Append(Format(HttpMessageText.Header(part[..split], "Content-Type"), bytes, text) ?? text);
        }
        return output.Length > 0 ? output.ToString() : null;
    }

    private static string? Certificate(byte[] body, string text)
    {
        try
        {
            using var certificate = text.StartsWith("-----BEGIN", StringComparison.Ordinal) ?
                X509Certificate2.CreateFromPem(text) : X509CertificateLoader.LoadCertificate(body);
            return string.Join("\r\n", $"Subject = {certificate.Subject}", $"Issuer = {certificate.Issuer}",
                $"Serial number = {certificate.SerialNumber}",
                $"Valid from = {certificate.NotBefore.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC",
                $"Valid to = {certificate.NotAfter.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC",
                $"Signature = {certificate.SignatureAlgorithm.FriendlyName}",
                $"SHA-256 = {certificate.GetCertHashString(HashAlgorithmName.SHA256)}");
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    // Names binary content by its leading bytes: a description, a file extension, and whether it is a picture.
    public static (string Kind, string Extension, bool Image) Identify(byte[] bytes)
    {
        bool Starts(ReadOnlySpan<byte> prefix) => bytes.AsSpan().StartsWith(prefix);
        if (Starts([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) && bytes.Length >= 24)
            return ("PNG image", "png", true);
        if (Starts("GIF8"u8) && bytes.Length >= 10)
            return ("GIF image", "gif", true);
        if (Starts([0xff, 0xd8, 0xff]))
            return ("JPEG image", "jpg", true);
        if (Starts("RIFF"u8) && bytes.Length >= 12 && bytes.AsSpan(8, 4).SequenceEqual("WEBP"u8))
            return ("WebP image", "webp", true);
        if (Starts("BM"u8) && bytes.Length >= 26 && bytes[14] is 12 or 40 or 108 or 124)
            return ("BMP image", "bmp", true);
        if (Starts([0, 0, 1, 0]) && bytes.Length >= 6)
            return ("Icon", "ico", true);
        if (Starts("%PDF-"u8))
            return ("PDF document", "pdf", false);
        if (Starts("PK\u0003\u0004"u8))
            return ("ZIP archive", "zip", false);
        if (Starts("\0asm"u8))
            return ("WebAssembly module", "wasm", false);
        if (Starts("SQLite format 3\0"u8))
            return ("SQLite database", "db", false);
        if (Starts("MZ"u8))
            return ("Windows executable", "exe", false);
        return Starts("\u007fELF"u8) ? ("ELF executable", "bin", false) : ("Binary data", "bin", false);
    }

    // The kind of content, with the pixel size of the pictures that state it up front.
    public static string Summarize(byte[] bytes)
    {
        var data = bytes.AsSpan();
        var kind = Identify(bytes).Kind;
        if (kind == "PNG image")
            kind += $", {BinaryPrimitives.ReadUInt32BigEndian(data[16..])} × " +
                $"{BinaryPrimitives.ReadUInt32BigEndian(data[20..])} pixels";
        else if (kind == "GIF image")
            kind += $", {BinaryPrimitives.ReadUInt16LittleEndian(data[6..])} × " +
                $"{BinaryPrimitives.ReadUInt16LittleEndian(data[8..])} pixels";
        return $"{kind} · {bytes.Length.ToString("N0", CultureInfo.CurrentCulture)} bytes";
    }

    // Describes what a view finds in a message; the automatic view reports only unambiguous SAML messages and JWTs.
    public static string Describe(HttpPayloadView view, string startLine, string headers, string body)
    {
        try
        {
            var found = view switch
            {
                HttpPayloadView.Base64 => Base64Values(startLine, headers, body),
                HttpPayloadView.UrlEncoded => UrlValues(startLine, headers, body),
                HttpPayloadView.Saml => Saml(startLine, headers, body),
                HttpPayloadView.Jwt => Jwt(startLine, headers, body),
                HttpPayloadView.Automatic => Join(Saml(startLine, headers, body), Jwt(startLine, headers, body)),
                _ => ""
            };
            if (found.Length > 0 || view == HttpPayloadView.Automatic)
                return found;
            return view switch
            {
                HttpPayloadView.Base64 => "(No Base64 value was found.)",
                HttpPayloadView.UrlEncoded => "(Nothing is URL encoded.)",
                HttpPayloadView.Saml => "(No SAML message was found.)",
                _ => "(No JSON Web Token was found.)"
            };
        }
        catch (RegexMatchTimeoutException)
        {
            return "(The message was too complex to scan.)";
        }
    }

    private static string Join(params string[] sections) =>
        string.Join("\r\n\r\n", sections.Where(section => section.Length > 0));

    private static string Unescape(string text) => Uri.UnescapeDataString(text.Replace('+', ' '));

    // The decoded names and values of a query string or form body.
    public static IEnumerable<(string Name, string Value)> Pairs(string text) =>
        text.Split('&', StringSplitOptions.RemoveEmptyEntries).Select(pair => pair.IndexOf('=') is >= 0 and var equals ?
            (Unescape(pair[..equals]), Unescape(pair[(equals + 1)..])) : (Unescape(pair), ""));

    // Accepts standard and URL-safe alphabets, missing padding, line breaks, and '+' that form decoding turned to ' '.
    private static bool Base64(string text, out byte[] bytes, int minimum = 8)
    {
        bytes = [];
        var clean = text.Trim().Replace("\r", "").Replace("\n", "").Replace('\t', ' ').Replace(' ', '+')
            .Replace('-', '+').Replace('_', '/').TrimEnd('=');
        if (clean.Length < minimum || clean.Length % 4 == 1)
            return false;
        var buffer = new byte[clean.Length * 3 / 4 + 3];
        if (!Convert.TryFromBase64String(clean.PadRight((clean.Length + 3) / 4 * 4, '='), buffer, out var written))
            return false;
        bytes = buffer[..written];
        return true;
    }

    // Name and value pairs from query strings, form bodies, and the hidden inputs of auto-submitted HTML forms.
    private static List<(string Source, string Name, string Value)> Fields(string startLine, string headers,
        string body)
    {
        var fields = new List<(string, string, string)>();
        void Add(string source, string text) =>
            fields.AddRange(Pairs(text).Select(pair => (source, pair.Name, pair.Value)));
        void Query(string source, string url)
        {
            var start = url.IndexOf('?');
            if (start < 0)
                return;
            var end = url.IndexOf('#', start);
            Add(source, end < 0 ? url[(start + 1)..] : url[(start + 1)..end]);
        }
        var parts = startLine.Split(' ');
        if (parts.Length > 1 && !parts[0].StartsWith("HTTP/", StringComparison.Ordinal))
            Query("query string", parts[1]);
        Query("Location header", HttpMessageText.Header(headers, "Location"));
        if (HttpMessageText.Header(headers, "Content-Type").Contains("x-www-form-urlencoded",
            StringComparison.OrdinalIgnoreCase))
            Add("form body", body.Trim());
        else if (body.Contains("<input", StringComparison.OrdinalIgnoreCase))
            foreach (Match input in HtmlInput.Matches(body))
            {
                string? name = null, value = null;
                foreach (Match attribute in HtmlAttribute.Matches(input.Value))
                {
                    var text = WebUtility.HtmlDecode(attribute.Groups[2].Success ? attribute.Groups[2].Value :
                        attribute.Groups[3].Success ? attribute.Groups[3].Value : attribute.Groups[4].Value);
                    if (attribute.Groups[1].Value.Equals("name", StringComparison.OrdinalIgnoreCase))
                        name = text;
                    else if (attribute.Groups[1].Value.Equals("value", StringComparison.OrdinalIgnoreCase))
                        value = text;
                }
                if (name is not null && value is not null)
                    fields.Add(("HTML form field", name, value));
            }
        return fields;
    }

    private static string Readable(byte[] bytes)
    {
        if (!HttpMessageText.LooksLikeText(bytes))
            return HttpMessageText.HexDump(bytes, 4096);
        var text = new UTF8Encoding(false).GetString(bytes);
        if (text.TrimStart() is not ['{' or '[', ..])
            return text;
        try { return Pretty(text); }
        catch (JsonException) { return text; }
    }

    private static string Base64Values(string startLine, string headers, string body)
    {
        var output = new StringBuilder();
        void Show(string label, string value)
        {
            if (!Base64(value, out var bytes))
                return;
            if (bytes is [0x1f, 0x8b, ..])
                bytes = HttpMessageText.Decode(bytes, "gzip", out _);
            output.Append(output.Length > 0 ? "\r\n\r\n" : "").Append(label).Append(" · ")
                .Append(bytes.Length.ToString("N0", CultureInfo.CurrentCulture)).Append(" bytes\r\n")
                .Append(Readable(bytes));
        }
        Show("Body", body);
        foreach (var (source, name, value) in Fields(startLine, headers, body))
            Show($"{name} ({source})", value);
        return output.ToString();
    }

    private static string UrlValues(string startLine, string headers, string body)
    {
        var output = new StringBuilder();
        foreach (var group in Fields(startLine, headers, body).GroupBy(field => field.Source))
        {
            output.Append(output.Length > 0 ? "\r\n\r\n" : "").Append(group.Key).Append("\r\n");
            foreach (var (_, name, value) in group)
                output.Append("  ").Append(name).Append(" = ").Append(value).Append("\r\n");
        }
        if (output.Length == 0 && body.Contains('%'))
            output.Append("body\r\n").Append(Unescape(body));
        return output.ToString().TrimEnd();
    }

    private static string Saml(string startLine, string headers, string body)
    {
        var fields = Fields(startLine, headers, body);
        var output = new StringBuilder();
        foreach (var (source, name, value) in fields.Where(field => SamlFields.Contains(field.Name)))
        {
            output.Append(output.Length > 0 ? "\r\n\r\n" : "").Append(name).Append(" (").Append(source).Append(")\r\n");
            output.Append(name == "SAMLart" ? value : Base64(value, out var bytes) ? DescribeSaml(bytes) :
                "The value is not Base64.");
        }

        // SOAP and artifact resolution exchange the XML directly in the body.
        if (output.Length == 0 && body.Contains("urn:oasis:names:tc:SAML", StringComparison.Ordinal))
            output.Append("SAML message (body)\r\n").Append(DescribeSaml(Encoding.UTF8.GetBytes(body)));
        var relay = fields.FirstOrDefault(field => field.Name == "RelayState").Value;
        if (output.Length > 0 && !string.IsNullOrEmpty(relay))
            output.Append("\r\n\r\nRelayState = ").Append(relay);
        return output.ToString();
    }

    private static XDocument? Parse(string xml)
    {
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreWhitespace = true
            });
            return XDocument.Load(reader);
        }
        catch (XmlException)
        {
            return null;
        }
    }

    // The HTTP-POST binding sends Base64 XML; the HTTP-Redirect binding deflates the XML before encoding it.
    private static string DescribeSaml(byte[] data)
    {
        var xml = Encoding.UTF8.GetString(data).TrimStart('﻿', ' ', '\r', '\n', '\t');
        var compression = "";
        if (!xml.StartsWith('<') && HttpMessageText.Decode(data, "deflate", out _) is { Length: > 0 } inflated)
        {
            xml = Encoding.UTF8.GetString(inflated).TrimStart('﻿', ' ', '\r', '\n', '\t');
            compression = "Deflate compressed\r\n";
        }
        if (!xml.StartsWith('<') || Parse(xml) is not { Root: { } root } document)
            return "The decoded value is not XML.\r\n" + Readable(data);
        var summary = new StringBuilder(compression);
        void Line(string name, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
                summary.Append(name).Append(" = ").Append(value.Trim()).Append("\r\n");
        }
        IEnumerable<XElement> All(string name) =>
            document.Descendants().Where(element => element.Name.LocalName == name);
        Line("Message", root.Name.LocalName);
        foreach (var name in new[]
            { "ID", "InResponseTo", "IssueInstant", "Destination", "AssertionConsumerServiceURL" })
            Line(name, root.Attribute(name)?.Value);
        Line("Issuer", All("Issuer").FirstOrDefault()?.Value);
        if (All("StatusCode").FirstOrDefault()?.Attribute("Value")?.Value is { } status)
            Line("Status", status[(status.LastIndexOf(':') + 1)..]);
        Line("Subject", All("NameID").FirstOrDefault()?.Value);
        if (All("Conditions").FirstOrDefault() is { } conditions)
        {
            Line("Not before", conditions.Attribute("NotBefore")?.Value);
            Line("Not on or after", conditions.Attribute("NotOnOrAfter")?.Value);
        }
        Line("Audience", string.Join(", ", All("Audience").Select(element => element.Value.Trim())));
        foreach (var attribute in All("Attribute").Take(40))
            Line("Attribute " + attribute.Attribute("Name")?.Value, string.Join(", ", attribute.Elements()
                .Where(element => element.Name.LocalName == "AttributeValue").Select(element => element.Value.Trim())));
        Line("Signature", All("Signature").Any() ? "present, not verified" : null);
        Line("Encrypted assertion", All("EncryptedAssertion").Any() ? "present, not decrypted" : null);
        return summary.Append("\r\n").Append(Pretty(document)).ToString();
    }

    private static string Jwt(string startLine, string headers, string body)
    {
        var output = new StringBuilder();
        foreach (var token in Token.Matches(startLine + "\r\n" + headers + "\r\n" + body).Select(match => match.Value)
            .Distinct().Take(10))
        {
            var parts = token.Split('.');
            if (!Base64(parts[0], out var header, 4) || !Base64(parts[1], out var payload, 4) ||
                !HttpMessageText.LooksLikeText(header) || !HttpMessageText.LooksLikeText(payload))
                continue;
            try
            {
                var section = new StringBuilder("JSON Web Token\r\nHeader\r\n")
                    .Append(Pretty(Encoding.UTF8.GetString(header))).Append("\r\nPayload\r\n")
                    .Append(Pretty(Encoding.UTF8.GetString(payload))).Append("\r\n");
                using var claims = JsonDocument.Parse(payload);
                foreach (var (name, label) in new[] { ("exp", "Expires"), ("nbf", "Not before"), ("iat", "Issued") })
                    if (claims.RootElement.ValueKind == JsonValueKind.Object &&
                        claims.RootElement.TryGetProperty(name, out var value) &&
                        value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var seconds) &&
                        seconds is > 0 and < 253402300799)
                        section.Append(label).Append(" = ").Append(DateTimeOffset.FromUnixTimeSeconds(seconds)
                            .ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture)).Append("\r\n");
                section.Append("Signature = ").Append(Base64(parts[2], out var signature, 1) ?
                    $"{signature.Length} bytes, not verified" : parts[2].Length == 0 ? "none" : "not Base64");
                output.Append(output.Length > 0 ? "\r\n\r\n" : "").Append(section);
            }
            catch (JsonException) { }
        }
        return output.ToString();
    }
}
