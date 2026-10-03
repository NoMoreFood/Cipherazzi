using System.Diagnostics;
using System.Drawing.Imaging;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;
using Microsoft.Data.Sqlite;

namespace Cipherazzi.UiTests;

// Reads decoded messages through the real viewer from a journal recorded with HTTP Spy and its sibling store.
internal static class HttpSpyUi
{
    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(Path.Combine(output, "HttpSpy"));
        var path = Path.Combine(output, "http-ui.db");
        var source = DatabaseSource.Sqlite(args[0]);
        foreach (var (from, to) in new[] { (args[0], path), (HttpSpyStore.StorePath(source),
            Path.Combine(output, "HttpSpy", "http-ui.db")) })
        {
            using var original = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = from, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            using var copy = new SqliteConnection($"Data Source={to};Pooling=False");
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
        }
        byte[] logo = Logo();
        AddBodies(Path.Combine(output, "HttpSpy", "http-ui.db"), logo);

        // A journal with no HTTP Spy store must explain itself instead of failing.
        var bare = Path.Combine(output, "bare");
        Directory.CreateDirectory(bare);
        var bareJournal = Path.Combine(bare, "bare.db");
        using (var original = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = args[0], Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString()))
        using (var copy = new SqliteConnection($"Data Source={bareJournal};Pooling=False"))
        {
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
        }
        var settings = new ViewerSettings { Live = false, Theme = "Light",
            PersistencePath = Path.Combine(output, "Viewer.config") };
        UiTheme.Select(settings.Theme);
        using var window = new MainForm(DatabaseSource.Sqlite(path), null, settings)
        {
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000)
        };
        var checks = new List<string>();
        var exit = 0;
        window.Shown += async (_, _) =>
        {
            try
            {
                var controls = Descendants(window).ToArray();
                var tabs = controls.OfType<TabControl>().Single(control => control.AccessibleName == "Workspace views");
                var search = controls.OfType<TextBox>().Single(control => control.PlaceholderText.Length > 0);
                tabs.SelectedIndex = 7;
                var view = controls.OfType<HttpSpyView>().Single();
                var grid = Descendants(view).OfType<DataGridView>().Single(control => control.Name == "HttpSpyGrid");
                var request = Descendants(view).OfType<TextBox>().Single(control =>
                    control.AccessibleName == "Request message");
                var response = Descendants(view).OfType<TextBox>().Single(control =>
                    control.AccessibleName == "Response message");
                await Until(() => grid.RowCount >= 10);

                DataGridViewRow Find(Func<DataGridViewRow, bool> match) =>
                    grid.Rows.Cast<DataGridViewRow>().First(match);
                string Cell(DataGridViewRow row, string name) => row.Cells[name].Value?.ToString() ?? "";

                // A request and its response appear together, with the body in a readable form.
                var post = Find(row => Cell(row, "Method") == "POST" && Cell(row, "Path") == "/submit" &&
                    Cell(row, "Protocol").Contains("TLS 1.3"));
                grid.CurrentCell = post.Cells["Method"];
                await Until(() => request.Text.StartsWith("POST /submit HTTP/1.1") && response.Text.Contains("201"));
                Require(request.Text.Contains("hello=world") && response.Text.Contains("\"a\": 1"),
                    "The request body or indented JSON response was not displayed.");
                checks.Add("Request and response bodies are decoded and readable");

                // Credentials stay masked by default.
                var get = Find(row => Cell(row, "Method") == "GET" && Cell(row, "Path") == "/first?q=1");
                grid.CurrentCell = get.Cells["Method"];
                await Until(() => request.Text.StartsWith("GET /first?q=1"));
                Require(request.Text.Contains("Authorization: [redacted") && !request.Text.Contains("hunter2") &&
                    response.Text.Contains("Set-Cookie: [redacted"), "Credential headers were not masked.");
                checks.Add("Credential headers are masked");

                // Copied commands keep ordinary quoted text literal and omit masked or derived headers.
                var copied = HttpSpyView.Curl(new(new(1, 0, 0, "", "", "", "", "TLS", "https", "HTTP/1.1",
                    "POST", "example.test", "/Bob's", 200, "text/plain", 0, 0, "complete", ""), "",
                    "X-Note: Alice's \"quote\" costs $5\r\nAuthorization: [redacted]\r\n" +
                    "Host: example.test\r\nContent-Length: 24\r\n", "",
                    Encoding.UTF8.GetBytes("Bob's ‘quote’ and ‚quote‛ cost $5"), []));
                Require(copied == "# WARNING: Redacted credential headers were omitted; authentication may fail.\r\n" +
                    "curl.exe -i -X 'POST' 'https://example.test/Bob''s' " +
                    "-H 'X-Note: Alice''s \"quote\" costs $5' --data-raw 'Bob''s ‘‘quote’’ and ‚‚quote‛‛ cost $5'",
                    "The copied PowerShell command changed literal text or included masked headers.");
                checks.Add("Copied PowerShell commands quote recorded arguments and preserve redaction");
                var metadata = Descendants(view).OfType<Label>().Single(control =>
                    control.AccessibleName == "Message connection and timings");
                Require(metadata.Text.Contains("Flow #") && metadata.Text.Contains("Wait (TTFB):"),
                    "The message connection and timing header is missing.");

                // Find-next searches the selected pane, advances, and wraps without changing the global filter.
                var find = Descendants(view).OfType<TextBox>().Single(control =>
                    control.AccessibleName == "Find in message");
                request.Focus();
                bool Key(Keys key) => (bool)typeof(HttpSpyView).GetMethod("ProcessCmdKey",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                    .Invoke(view, [Message.Create(IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero), key])!;
                Require(Key(Keys.Control | Keys.F) && find.Visible, "Ctrl+F did not open message finding.");
                find.Text = "redacted";
                Require(Key(Keys.F3) && request.SelectedText.Equals("redacted", StringComparison.OrdinalIgnoreCase),
                    "Find-next did not select matching request text.");
                Require(Key(Keys.Escape) && !find.Visible, "Escape did not close message finding.");
                response.Focus();
                Require(Key(Keys.Control | Keys.F), "Ctrl+F did not switch to the response pane.");
                find.Text = "set-cookie";
                Require(Key(Keys.F3) && response.SelectedText.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase),
                    "Find-next did not select matching response text.");
                Key(Keys.Escape);
                checks.Add("Message finding selects matching text without changing search filters");

                // A connection that could not be decoded says why.
                var encrypted = Find(row => Cell(row, "State") == "Encrypted");
                grid.CurrentCell = encrypted.Cells["Method"];
                await Until(() => request.Text.Contains("was not decoded"));
                Require(request.Text.Contains("No TLS secrets"),
                    "The reason a connection stayed encrypted is missing.");
                checks.Add("Undecoded connections explain why");

                // Payload views re-render the selected message without reloading it.
                var payload = Descendants(view).OfType<ComboBox>().Single(control =>
                    control.AccessibleName == "Payload view");
                grid.CurrentCell = post.Cells["Method"];
                await Until(() => request.Text.StartsWith("POST /submit HTTP/1.1"));
                payload.SelectedItem = "Hex";
                await Until(() => request.Text.Contains("68 65 6c 6c 6f 3d 77 6f") &&
                    response.Text.Contains("7b 22 61 22"));
                payload.SelectedItem = "URL decoded";
                grid.CurrentCell = get.Cells["Method"];
                await Until(() => request.Text.Contains("q = 1"));
                payload.SelectedItem = "Automatic";
                await Until(() => !request.Text.Contains("q = 1") && request.Text.StartsWith("GET /first?q=1"));
                checks.Add("Payload views re-render the selected message");

                // A picture can be previewed and any binary body saved; text and bodiless messages offer neither.
                Button BodyButton(string name) => Descendants(view).OfType<Button>().Single(control =>
                    control.AccessibleName == name);
                var previewResponse = BodyButton("Preview the response image");
                var saveResponse = BodyButton("Save the response body to a file");
                var previewRequest = BodyButton("Preview the request image");
                var saveRequest = BodyButton("Save the request body to a file");
                Require(!previewResponse.Visible && !saveResponse.Visible, "A text body offered binary actions.");
                grid.CurrentCell = Find(row => Cell(row, "Path") == "/logo.png").Cells["Method"];
                await Until(() => previewResponse.Visible && saveResponse.Visible);
                Require(!previewRequest.Visible && !saveRequest.Visible, "A message without a body offered actions.");
                Size? previewed = null;
                using (var watcher = new System.Windows.Forms.Timer { Interval = 20 })
                {
                    watcher.Tick += (_, _) =>
                    {
                        if (Application.OpenForms.OfType<ImagePreviewDialog>().FirstOrDefault() is not { } dialog)
                            return;
                        watcher.Stop();
                        previewed = dialog.ImageSize;
                        using var shot = new Bitmap(dialog.Width, dialog.Height);
                        dialog.DrawToBitmap(shot, new Rectangle(0, 0, shot.Width, shot.Height));
                        shot.Save(Path.Combine(output, "httpspy-preview.png"));
                        dialog.Close();
                    };
                    watcher.Start();
                    previewResponse.PerformClick();
                }
                Require(previewed == new Size(40, 30), "The picture preview did not open at the picture's size.");
                var file = view.ResponseFile!;
                var saved = Path.Combine(output, "logo-saved.png");
                Require(file.FileName == "logo.png" && await view.SaveBodyAsync(file, saved) &&
                    File.ReadAllBytes(saved).SequenceEqual(logo), "The saved picture differs from the response body.");
                Require(!await view.SaveBodyAsync(file, path) && File.ReadAllBytes(path).AsSpan(0, 15)
                    .SequenceEqual("SQLite format 3"u8), "Saving a body may overwrite the capture journal.");
                grid.CurrentCell = Find(row => Cell(row, "Path") == "/download.bin").Cells["Method"];
                await Until(() => saveResponse.Visible && view.ResponseFile?.FileName == "download.bin");
                Require(!previewResponse.Visible, "A binary download offered an image preview.");
                checks.Add("Pictures can be previewed and binary bodies saved");

                // Search narrows the list and HAR export follows it; clearing the search restores every message.
                var all = grid.RowCount;
                var undecoded = grid.Rows.Cast<DataGridViewRow>().Count(row => Cell(row, "State") == "Encrypted");
                var exportButton = controls.OfType<Button>().Single(control => control.Text == "&Export HAR…");
                Require(exportButton.Visible, "HAR export is not offered beside the HTTP Spy messages.");
                var har = Path.Combine(output, "messages.har");
                Require(await window.ExportHarAsync(har) == all - undecoded, "HAR export skipped decoded messages.");
                var harText = File.ReadAllText(har);
                using (var document = JsonDocument.Parse(harText))
                {
                    var log = document.RootElement.GetProperty("log");
                    var entries = log.GetProperty("entries").EnumerateArray().ToArray();
                    Require(log.GetProperty("version").GetString() == "1.2" && entries.Length == all - undecoded,
                        "The HAR file does not hold one entry per decoded message.");
                    string Url(JsonElement entry) => entry.GetProperty("request").GetProperty("url").GetString()!;
                    var submitted = entries.First(entry => Url(entry).EndsWith("/submit", StringComparison.Ordinal));
                    var sent = submitted.GetProperty("request").GetProperty("postData").GetProperty("text");
                    var received = submitted.GetProperty("response");
                    var timings = submitted.GetProperty("timings");
                    Require(timings.GetProperty("send").GetDouble() > 0 &&
                        timings.GetProperty("wait").GetDouble() > 0 &&
                        timings.GetProperty("receive").GetDouble() > 0 &&
                        Math.Abs(timings.EnumerateObject().Sum(value => value.Value.GetDouble()) -
                            submitted.GetProperty("time").GetDouble()) < 0.01,
                        "The HAR timings do not describe the recorded send, wait, and receive intervals.");
                    Require(sent.GetString()!.Contains("hello=world") &&
                        received.GetProperty("status").GetInt32() == 201 &&
                        received.GetProperty("content").GetProperty("text").GetString()!.Contains("\"a\""),
                        "The HAR entry lacks the request or response body.");
                    var queried = entries.First(entry => Url(entry).EndsWith("/first?q=1", StringComparison.Ordinal))
                        .GetProperty("request").GetProperty("queryString");
                    Require(queried[0].GetProperty("name").GetString() == "q" &&
                        queried[0].GetProperty("value").GetString() == "1", "The HAR entry lacks the query string.");
                }
                Require(!harText.Contains("hunter2"), "The HAR file exposed a masked credential.");
                Require(await window.ExportHarAsync(path) is null && File.ReadAllBytes(path).AsSpan(0, 15)
                    .SequenceEqual("SQLite format 3"u8), "HAR export may overwrite the capture journal.");
                search.Text = "tunnelled";
                await Until(() => grid.RowCount == 1 && Cell(grid.Rows[0], "Path") == "/tunnelled");
                Require(await window.ExportHarAsync(Path.Combine(output, "tunnelled.har")) == 1,
                    "HAR export ignored the search.");
                search.Text = "";
                await Until(() => grid.RowCount == all);
                foreach (var (term, expected) in new[] { ("header:Authorization", "GET"),
                    ("body:hello=world", "POST"), ("status:4xx", "GET") })
                {
                    search.Text = term;
                    await Until(() => grid.RowCount > 0 && grid.RowCount < all &&
                        grid.Rows.Cast<DataGridViewRow>().All(row => Cell(row, "Method") == expected));
                }
                search.Text = "";
                await Until(() => grid.RowCount == all);
                checks.Add("Search filters decoded messages and HAR export");
                CheckPayloads(checks);
                CheckFormatting(checks);
                CheckDecoding(checks);

                // Keep a picture selected so the body actions are part of every themed and scaled screenshot.
                grid.CurrentCell = Find(row => Cell(row, "Path") == "/logo.png").Cells["Method"];
                await Until(() => previewResponse.Visible);
                foreach (var (theme, points, size) in new[]
                    { ("Light", 9f, new Size(1000, 650)), ("Dark", 9f, new Size(1440, 900)),
                        ("Light", 12f, new Size(1100, 750)) })
                {
                    UiTheme.Apply(window, theme);
                    window.Font = new Font("Segoe UI", points);
                    window.ClientSize = size;
                    await Task.Delay(400);
                    using var bitmap = new Bitmap(window.Width, window.Height);
                    window.DrawToBitmap(bitmap, new Rectangle(0, 0, window.Width, window.Height));
                    bitmap.Save(Path.Combine(output, $"httpspy-{theme.ToLowerInvariant()}-{points}.png"));
                    CollectorUi.CheckToolbar(window);
                    var visible = grid.DisplayedRowCount(false);
                    Require(visible >= 3, $"Only {visible} message rows fit at {points} points: " +
                        $"grid {grid.ClientSize.Height}, header {grid.ColumnHeadersHeight}, row {grid.Rows[0].Height}.");
                    Require(request.ClientSize.Height > request.Font.Height * 2 &&
                        response.ClientSize.Height > response.Font.Height * 2,
                        $"Message pane heights {request.ClientSize.Height}/{response.ClientSize.Height} " +
                        $"are too small for font heights {request.Font.Height}/{response.Font.Height} at {points} points.");
                    Require(new[] { previewResponse, saveResponse }.All(button => view.ClientRectangle.Contains(
                        view.RectangleToClient(button.RectangleToScreen(button.ClientRectangle)))),
                        $"The body actions are clipped at {points} points and {size}.");
                }
                checks.Add("The workspace remains usable across themes and text sizes");

                // Follow the recorded connection tuple and capture interval into the TLS inspector.
                grid.CurrentCell = Find(row => Cell(row, "Path") == "/first?q=1" &&
                    Cell(row, "Protocol").Contains("TLS 1.3")).Cells["Method"];
                await Until(() => request.Text.StartsWith("GET /first?q=1"));
                grid.ContextMenuStrip!.Items.OfType<ToolStripMenuItem>().Single(item =>
                    item.Text == "View &TLS connection").PerformClick();
                var connections = controls.OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
                await Until(() => tabs.SelectedIndex == 0 && connections.RowCount == 1);
                Require(connections.Rows[0].Cells["Source"].Value?.ToString() == "10.66.0.1:50001" &&
                    connections.Rows[0].Cells["Destination"].Value?.ToString() == "10.66.0.2:9001",
                    "The TLS connection action selected a different connection.");
                checks.Add("HTTP messages navigate to their TLS connection by tuple and capture interval");

                var unavailable = false;
                try { HttpSpyStore.Read(DatabaseSource.Sqlite(bareJournal), "", PageCursor.Newest, 50, null,
                    CancellationToken.None); }
                catch (HttpSpyUnavailableException) { unavailable = true; }
                Require(unavailable, "A journal without an HTTP Spy store should report that it has none.");
                checks.Add("A journal without HTTP Spy messages reports so");

                // A failed store validation must release its file so the user can repair or replace it.
                var damagedStore = HttpSpyStore.StorePath(DatabaseSource.Sqlite(bareJournal));
                Directory.CreateDirectory(Path.GetDirectoryName(damagedStore)!);
                File.WriteAllText(damagedStore, new string('x', 4096));
                try
                {
                    HttpSpyStore.ReadStamp(DatabaseSource.Sqlite(bareJournal), CancellationToken.None);
                    throw new InvalidOperationException("An unreadable HTTP Spy store was accepted.");
                }
                catch (SqliteException error) when (error.SqliteErrorCode == 26) { }
                using (var replacement = new FileStream(damagedStore, FileMode.Open, FileAccess.ReadWrite,
                    FileShare.None))
                    replacement.SetLength(0);
                checks.Add("Unreadable HTTP Spy stores release their file handles");
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                { result = "passed", checks }, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception error)
            {
                exit = 1;
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                { result = "failed", checks, error = error.ToString() },
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            finally { window.Close(); }
        };
        Application.Run(window);
        return exit;
    }

    private static void CheckDecoding(List<string> checks)
    {
        const int limit = 8 * 1024 * 1024;
        foreach (var kind in new[] { "raw", "deflate", "gzip", "br" })
        foreach (var size in new[] { 1024, limit, limit + 1 })
        {
            var body = new byte[size];
            for (var i = 0; i < body.Length; ++i)
                body[i] = (byte)i;
            using var packed = new MemoryStream();
            using (Stream compressor = kind switch
            {
                "raw" => new DeflateStream(packed, CompressionLevel.Fastest, true),
                "deflate" => new ZLibStream(packed, CompressionLevel.Fastest, true),
                "gzip" => new GZipStream(packed, CompressionLevel.Fastest, true),
                _ => new BrotliStream(packed, CompressionLevel.Fastest, true)
            }) compressor.Write(body);
            var encoding = kind == "raw" ? "DeFlAtE" : kind;
            var encoded = packed.ToArray();
            var decoded = HttpMessageText.Decode(encoded, encoding + ", identity", out var note);
            Require(decoded.AsSpan().SequenceEqual(body.AsSpan(0, Math.Min(size, limit))) &&
                (note.Length > 0) == (size > limit), $"{kind}: decoding lost data or misreported its size limit.");
            var file = HttpMessageText.BodyFile("Content-Type: application/octet-stream\r\n" +
                $"Content-Encoding: {encoding}\r\n", encoded, encoded.Length, "/body.bin");
            Require(file is not null && file.Bytes.Length == Math.Min(size, limit) && file.Partial == (size > limit),
                $"{kind}: saving a decoded body bypassed the limit or hid its truncation.");
        }
        checks.Add("Raw deflate, zlib, gzip, and Brotli decoding and saved files respect the 8 MiB limit");
    }

    private static string Base64Url(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text))
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // Realistic SAML, JWT, Base64, and URL-encoded payloads, including damaged and hostile ones.
    private static void CheckPayloads(List<string> checks)
    {
        string Render(string start, string headers, string body, HttpPayloadView view)
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            return HttpMessageText.Render(start, headers, bytes, bytes.Length, view);
        }
        var form = "Content-Type: application/x-www-form-urlencoded\r\n";
        var assertion = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
            "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r1\" InResponseTo=\"_q1\" " +
            "Destination=\"https://sp.example/acs\"><saml:Issuer>https://idp.example/</saml:Issuer><samlp:Status>" +
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
            "<saml:Assertion ID=\"_a1\"><saml:Subject><saml:NameID>alice@example.test</saml:NameID></saml:Subject>" +
            "<saml:Conditions NotBefore=\"2026-10-27T10:00:00Z\" NotOnOrAfter=\"2026-10-27T10:05:00Z\">" +
            "<saml:AudienceRestriction><saml:Audience>https://sp.example/</saml:Audience></saml:AudienceRestriction>" +
            "</saml:Conditions><saml:AttributeStatement><saml:Attribute Name=\"role\"><saml:AttributeValue>admin" +
            "</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>";
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(assertion));

        // The POST binding carries Base64 XML in a form field beside the relay state.
        var post = "SAMLResponse=" + Uri.EscapeDataString(encoded) + "&RelayState=%2Fdashboard";
        var text = Render("POST /acs HTTP/1.1", form, post, HttpPayloadView.Saml);
        Require(new[] { "SAMLResponse (form body)", "Issuer = https://idp.example/", "Status = Success",
            "Subject = alice@example.test", "Attribute role = admin", "Audience = https://sp.example/",
            "Not on or after = 2026-10-27T10:05:00Z", "RelayState = /dashboard", "\r\n  <saml:Issuer>" }
            .All(text.Contains), "A SAML POST binding message was not decoded.");
        Require(Render("POST /acs HTTP/1.1", form, post, HttpPayloadView.Automatic).Contains("Status = Success"),
            "The automatic view did not decode a SAML message.");
        text = Render("POST /acs HTTP/1.1", form, post[..(post.Length / 2)], HttpPayloadView.Saml);
        Require(text.Contains("SAMLResponse") && !text.Contains("Status = Success"),
            "A truncated SAML message was not reported as damaged.");

        // The Redirect binding deflates the XML before encoding it.
        using var compressed = new MemoryStream();
        using (var deflate = new DeflateStream(compressed, CompressionLevel.Optimal, true))
            deflate.Write(Encoding.UTF8.GetBytes("<samlp:AuthnRequest " +
                "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_q1\" " +
                "AssertionConsumerServiceURL=\"https://sp.example/acs\"/>"));
        text = Render("GET /sso?SAMLRequest=" + Uri.EscapeDataString(Convert.ToBase64String(compressed.ToArray())) +
            "&RelayState=r HTTP/1.1", "Host: idp.example\r\n", "", HttpPayloadView.Saml);
        Require(text.Contains("Deflate compressed") && text.Contains("Message = AuthnRequest") &&
            text.Contains("AssertionConsumerServiceURL = https://sp.example/acs"),
            "A SAML Redirect binding message was not inflated.");

        // An identity provider answers with a page that submits the message from entity-encoded hidden inputs.
        var entities = string.Concat(encoded.Select(character => $"&#x{(int)character:x};"));
        text = Render("HTTP/1.1 200 OK", "Content-Type: text/html\r\n",
            "<form method=\"post\"><input type=\"hidden\" " + $"name=\"SAMLResponse\" value=\"{entities}\"/>" +
            "<input type=\"hidden\" name=\"RelayState\" value=\"a&amp;b\"/></form>", HttpPayloadView.Saml);
        Require(text.Contains("SAMLResponse (HTML form field)") && text.Contains("Status = Success") &&
            text.Contains("RelayState = a&b"), "An auto-submitted SAML form was not decoded.");

        // Messages are attacker-controlled, so external entities must never be read.
        var hostile = Convert.ToBase64String(Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><!DOCTYPE r " +
            "[<!ENTITY x SYSTEM \"file:///C:/Windows/win.ini\">]><r>&x;</r>"));
        text = Render("POST /acs HTTP/1.1", form, "SAMLResponse=" + Uri.EscapeDataString(hostile),
            HttpPayloadView.Saml);
        Require(text.Contains("is not XML") && !text.Contains("[fonts]") && !text.Contains("for 16-bit app support"),
            "A SAML message with an external entity was processed.");
        checks.Add("SAML messages decode from POST, Redirect, and auto-submitted forms without reading entities");

        // Tokens are found in bodies and headers; text that only resembles one is ignored.
        var token = Base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." +
            Base64Url("{\"sub\":\"alice\",\"exp\":1893456000}") + "." + Base64Url("signature");
        text = Render("HTTP/1.1 200 OK", "Content-Type: application/json\r\n",
            "{\"access_token\":\"" + token + "\",\"note\":\"eyJhbGciOiJub25lIn0.not-a-jwt.x\"}", HttpPayloadView.Jwt);
        Require(text.Contains("\"alg\": \"HS256\"") && text.Contains("\"sub\": \"alice\"") &&
            text.Contains("Expires = 2030-01-01 00:00:00 UTC") && text.Contains("Signature = 9 bytes, not verified") &&
            text.Split("JSON Web Token").Length == 2, "A JSON Web Token was not decoded.");
        Require(Render("GET / HTTP/1.1", "Cookie: session=" + token + "\r\n", "", HttpPayloadView.Automatic)
            .Contains("\"sub\": \"alice\""), "The automatic view missed a token in a header.");
        foreach (var claim in new[] { "\"unknown\"", "null", "true", "{}", "[]" })
        {
            var unusual = Base64Url("{\"alg\":\"none\"}") + "." +
                Base64Url("{\"sub\":\"alice\",\"exp\":" + claim + ",\"nbf\":" + claim +
                    ",\"iat\":" + claim + "}") + ".";
            text = Render("HTTP/1.1 200 OK", "Content-Type: text/plain\r\n", unusual, HttpPayloadView.Automatic);
            Require(text.Contains("\"sub\": \"alice\"") && !text.Contains("Expires =") &&
                !text.Contains("Not before =") && !text.Contains("Issued ="),
                "Nonnumeric token dates prevented displaying the recorded claims.");
        }
        checks.Add("JSON Web Tokens decode wherever they appear and preserve nonnumeric date claims");

        // Base64 and URL encodings, including unpadded and URL-safe variants.
        Require(Render("HTTP/1.1 200 OK", "Content-Type: text/plain\r\n", "aGVsbG8gd29ybGQ", HttpPayloadView.Base64)
            .Contains("11 bytes\r\nhello world"), "Unpadded Base64 was not decoded.");
        Require(Render("HTTP/1.1 200 OK", "Content-Type: text/plain\r\n", "not base64!", HttpPayloadView.Base64)
            .Contains("No Base64 value was found"), "Text that is not Base64 was decoded anyway.");
        text = Render("GET /q?a=b%20c&d=%7B%22x%22%3A1%7D&e=1+2 HTTP/1.1", "", "", HttpPayloadView.UrlEncoded);
        Require(text.Contains("a = b c") && text.Contains("d = {\"x\":1}") && text.Contains("e = 1 2"),
            "A query string was not URL decoded.");
        checks.Add("Base64 and URL encoded values decode");
    }

    // Automatic lays each body out by its data type, while Raw keeps the bytes as sent.
    private static void CheckFormatting(List<string> checks)
    {
        string Render(string type, byte[] body, HttpPayloadView view = HttpPayloadView.Automatic) =>
            HttpMessageText.Render("HTTP/1.1 200 OK", $"Content-Type: {type}\r\n", body, body.Length, view);
        byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);
        var json = "{\"a\":[1,2],\"b\":{\"c\":null}}";
        Require(Render("application/json", Bytes(json)).Contains("\r\n  \"a\": [") &&
            Render("text/plain", Bytes("[1,2]")).Contains("[\r\n  1,\r\n  2\r\n]"),
            "JSON was not indented, whether or not its type said so.");
        Require(Render("application/json", Bytes("{broken")).EndsWith("{broken") &&
            Render("application/json", Bytes(json), HttpPayloadView.Raw).EndsWith(json),
            "Malformed JSON or the raw view was altered.");
        var lines = Render("application/x-ndjson", Bytes("{\"a\":1}\n{\"b\":2}\n"));
        Require(lines.Contains("\"a\": 1") && lines.Contains("\"b\": 2"), "JSON lines were not indented.");

        // Unknown binary APIs remain readable, while malformed lengths and nesting fall back to hex.
        byte[] protobuf = [0x08, 0x96, 0x01, 0x12, 0x03, 0x66, 0x6f, 0x6f];
        foreach (var type in new[] { "application/x-protobuf", "application/octet-stream" })
            Require(Render(type, protobuf).Contains("Field 1 (wire 0): varint 150") &&
                Render(type, protobuf).Contains("Field 2 (wire 2): string \"foo\""),
                "A schema-less Protobuf message was not decoded.");
        byte[] grpc = [0, 0, 0, 0, 8, .. protobuf];
        Require(Render("application/grpc+proto", grpc).Contains("gRPC message 1") &&
            Render("application/grpc+proto", grpc).Contains("varint 150"), "A gRPC message was not decoded.");
        byte[] msgpack = [0x82, 0xa2, 0x69, 0x64, 0x2a, 0xa2, 0x6f, 0x6b, 0xc3];
        Require(Render("application/msgpack", msgpack).Contains("\"id\": 42") &&
            Render("application/octet-stream", msgpack).Contains("\"ok\": true"),
            "A MessagePack map was not decoded.");
        foreach (var (type, bytes) in new[] { ("application/x-protobuf", new byte[] { 0x12, 0xff }),
            ("application/grpc", grpc[..^1]), ("application/msgpack", msgpack[..^1]),
            ("application/grpc", new byte[50005]),
            ("application/msgpack", Enumerable.Repeat((byte)0x91, 40).ToArray()) })
            Require(Render(type, bytes).Contains("00000000"), "Malformed binary data did not fall back to hex.");
        using (var gzipBody = new MemoryStream())
        {
            using (var gzip = new GZipStream(gzipBody, CompressionLevel.Fastest, true))
                gzip.Write(Bytes("{\"inside\":true}"));
            Require(Render("application/octet-stream", gzipBody.ToArray()).Contains("\"inside\": true"),
                "A gzip body without Content-Encoding was not detected.");
        }
        checks.Add("Protobuf, gRPC, MessagePack, and gzip bodies decode with bounded malformed-data fallback");

        var xml = Render("application/soap+xml", Bytes("<?xml version=\"1.0\"?><r><c a=\"1\">t</c></r>"));
        Require(xml.Contains("<?xml version=\"1.0\"?>\r\n<r>\r\n  <c a=\"1\">t</c>\r\n</r>"),
            "XML was not indented with its declaration kept.");
        var hostile = Render("application/xml", Bytes("<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM " +
            "\"file:///C:/Windows/win.ini\">]><r>&x;</r>"));
        Require(hostile.EndsWith("<r>&x;</r>") && !hostile.Contains("[fonts]"),
            "XML with an external entity was expanded or reformatted.");

        var form = Render("application/x-www-form-urlencoded",
            Bytes("a=b+c&payload=%7B%22x%22%3A%5B1%2C2%5D%7D"));
        Require(form.Contains("a = b c") && form.Contains("payload = \r\n    {\r\n      \"x\": ["),
            "A form body was not split into decoded fields.");

        // A form upload lists its parts with their own layout; a damaged upload still renders.
        byte[] png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52,
            0, 0, 0, 3, 0, 0, 0, 2, 8, 2, 0, 0, 0];
        var upload = Encoding.Latin1.GetBytes("--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n" +
            "{\"k\":1}\r\n--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"p.png\"\r\n" +
            "Content-Type: image/png\r\n\r\n").Concat(png).Concat(Encoding.Latin1.GetBytes("\r\n--XyZ--\r\n"))
            .ToArray();
        var parts = Render("multipart/form-data; boundary=XyZ", upload);
        Require(parts.Contains("Part 1") && parts.Contains("name=\"note\"") && parts.Contains("\"k\": 1") &&
            parts.Contains("Part 2") && parts.Contains("filename=\"p.png\"") &&
            parts.Contains("PNG image, 3 × 2 pixels · 29 bytes"), "A form upload was not laid out by part.");
        Require(Render("multipart/form-data; boundary=XyZ", upload[..60]).Contains("Part 1"),
            "A truncated form upload could not be shown.");

        // Binary bodies are named by what they are; certificates show who issued them.
        var picture = Render("image/png", png);
        Require(picture.Contains("PNG image, 3 × 2 pixels") && picture.Contains("00000000  89 50 4e 47"),
            "A binary body was not described.");
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=format.test", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        var der = Render("application/pkix-cert", certificate.RawData);
        Require(der.Contains("Subject = CN=format.test") && der.Contains("SHA-256 = ") &&
            Render("text/plain", Bytes(certificate.ExportCertificatePem())).Contains("Issuer = CN=format.test") &&
            Render("application/pkix-cert", certificate.RawData, HttpPayloadView.Hex).Contains("00000000  30 82"),
            "A certificate was not summarized.");
        checks.Add("Automatic formats JSON, XML, forms, uploads, certificates, and binary bodies by type");

        // Binary bodies are classified for preview and saving, whatever their encoding or claimed file name.
        string Header(string type, string extra = "") => $"Content-Type: {type}\r\n{extra}";
        using var packed = new MemoryStream();
        using (var gzip = new System.IO.Compression.GZipStream(packed, System.IO.Compression.CompressionLevel.Fastest, true))
            gzip.Write(png);
        var zipped = HttpMessageText.BodyFile(Header("image/png", "Content-Encoding: gzip\r\n"), packed.ToArray(),
            packed.Length, "/a/b/icon.png");
        Require(zipped is { Image: true, Partial: false, FileName: "icon.png" } && zipped.Bytes.SequenceEqual(png),
            "A compressed picture was not decoded for preview.");
        Require(HttpMessageText.BodyFile(Header("text/plain"), Bytes("hello"), 5, "/a.txt") is null &&
            HttpMessageText.BodyFile(Header("image/svg+xml"), Bytes("<svg/>"), 6, "/a.svg") is null &&
            HttpMessageText.BodyFile(Header("image/png"), [], 0, "/a.png") is null,
            "Text, vector, or empty bodies were offered as files.");
        var named = HttpMessageText.BodyFile(Header("application/pdf", "Content-Disposition: attachment; " +
            "filename*=UTF-8''r%C3%A9sum%C3%A9.pdf\r\n"), Bytes("%PDF-1.7\0\u0001\u0002"), 40, "/download?id=7");
        Require(named is { Image: false, Partial: true, FileName: "résumé.pdf" }, "A download was not named by its header.");
        var hostileName = HttpMessageText.BodyFile(Header("application/octet-stream", "Content-Disposition: " +
            "attachment; filename=\"..\\..\\evil.exe\"\r\n"), [0, 1, 2, 3], 4, "/x")!.FileName;
        Require(!hostileName.Contains('\\') && !hostileName.Contains('/') && !hostileName.StartsWith('.'),
            "A download name could escape the chosen folder.");
        Require(HttpMessageText.BodyFile(Header("application/octet-stream"), [0, 1, 2, 3], 4, "/blob")!.FileName ==
            "blob.bin", "A download without a name did not get an extension.");
        using var decoded = HttpSpyView.DecodeImage(Logo());
        byte[] huge = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0x4e,
            0x20, 0, 0, 0x4e, 0x20, 8, 2, 0, 0, 0];
        Require(decoded?.Size == new Size(40, 30) && HttpSpyView.DecodeImage(huge) is null &&
            HttpSpyView.DecodeImage([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]) is null,
            "A damaged or oversized picture was decoded.");
        checks.Add("Binary bodies are classified, named safely, and pictures decode within limits");
    }

    private static byte[] Logo()
    {
        using var bitmap = new Bitmap(40, 30);
        using (var canvas = Graphics.FromImage(bitmap))
            canvas.Clear(Color.SteelBlue);
        using var stream = new MemoryStream();
        bitmap.Save(stream, ImageFormat.Png);
        return stream.ToArray();
    }

    // Adds a picture and a binary download as newer responses to the store a window will read.
    private static void AddBodies(string store, byte[] logo)
    {
        using var connection = new SqliteConnection($"Data Source={store};Pooling=False");
        connection.Open();
        using (var timings = connection.CreateCommand())
        {
            timings.CommandText = "UPDATE exchanges SET request_end_us=started_us+1200," +
                "response_start_us=started_us+143200,ended_us=started_us+147700 WHERE method='POST' AND target='/submit'";
            timings.ExecuteNonQuery();
        }
        var number = 0;
        byte[] blob = Enumerable.Range(0, 300).Select(value => (byte)value).ToArray();
        foreach (var (target, type, body) in new[] { ("/logo.png", "image/png", logo),
            ("/download.bin", "application/octet-stream", blob) })
        {
            using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TEMP TABLE pick AS SELECT * FROM exchanges WHERE method='GET' AND status=200 LIMIT 1;
                UPDATE pick SET id=(SELECT max(id)+1 FROM exchanges), sequence=@sequence,
                    started_us=(SELECT max(started_us)+1000 FROM exchanges),
                    ended_us=(SELECT max(ended_us)+2000 FROM exchanges),
                    target=@target, content_type=@type,
                    response_headers='Content-Type: ' || @type || char(13) || char(10),
                    response_body=@body, response_bytes=@length;
                INSERT INTO exchanges SELECT * FROM pick;
                DROP TABLE pick;
                """;
            command.Parameters.AddWithValue("@sequence", 9000 + ++number);
            command.Parameters.AddWithValue("@target", target);
            command.Parameters.AddWithValue("@type", type);
            command.Parameters.AddWithValue("@body", body);
            command.Parameters.AddWithValue("@length", body.Length);
            command.ExecuteNonQuery();
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private static IEnumerable<Control> Descendants(Control control) => control.Controls.Cast<Control>()
        .SelectMany(child => new[] { child }.Concat(Descendants(child)));

    private static async Task Until(Func<bool> ready)
    {
        var watch = Stopwatch.StartNew();
        while (!ready())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(45))
                throw new TimeoutException("The HTTP Spy workspace did not reach the expected state.");
            await Task.Delay(25);
        }
    }
}
