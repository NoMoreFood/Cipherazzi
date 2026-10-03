using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cipherazzi.Data;
using Npgsql;

if (args is ["--load", var saved])
{
    Console.WriteLine(ConnectionCredentials.Load(saved).Provider);
    return 0;
}
if (args is ["--audit-service", var name, var userFile, var systemFile, var report])
{
    return Cipherazzi.Deployment.Deployment.Run(name, ["--service"], (_, _) =>
    {
        using var input = JsonDocument.Parse(File.ReadAllText(userFile));
        var row = input.RootElement;
        var entropy = Encoding.UTF8.GetBytes("Cipherazzi connection|PostgreSql|" +
            row.GetProperty("Account").GetString());
        try
        {
            ProtectedData.Unprotect(row.GetProperty("ProtectedConnection").GetBytesFromBase64(), entropy,
                DataProtectionScope.CurrentUser);
            throw new InvalidOperationException("Another account decrypted the operator's credential.");
        }
        catch (CryptographicException) {}
        var loaded = ConnectionCredentials.Load(systemFile);
        using var identity = WindowsIdentity.GetCurrent();
        Require(identity.User!.IsWellKnown(WellKnownSidType.LocalSystemSid), "Audit did not run as LocalSystem.");
        Require(loaded.Provider == DatabaseProvider.PostgreSql, "LocalSystem could not load its credential.");
        File.WriteAllText(report, "LocalSystem round trip and cross-account decryption rejection passed.");
        return 0;
    });
}

var relay = Path.GetFullPath(args[0]);
var output = Path.GetFullPath(args[1]);
Directory.CreateDirectory(output);
using var identity = WindowsIdentity.GetCurrent();
var account = identity.User!;
var secret = "fixture-only;密碼='" + Guid.NewGuid().ToString("N");
var connection = new NpgsqlConnectionStringBuilder
{
    Host = "credential-test.invalid", Database = "fixture", Username = "credential-test", Password = secret,
    SslMode = SslMode.VerifyFull
}.ConnectionString;
var source = new DatabaseSource(DatabaseProvider.PostgreSql, connection);
var credential = Path.Combine(output, "viewer.credential");

// Exercise persisted ciphertext, account-only ACLs, replacement, and a separate reader process.
ConnectionCredentials.Save(credential, source);
Require(!File.ReadAllText(credential).Contains(secret, StringComparison.Ordinal), "Password was saved as plaintext.");
Require(ConnectionCredentials.Load(credential).ConnectionString == connection,
    "Protected connection did not round trip.");
Require(!source.ToString().Contains(secret, StringComparison.Ordinal) &&
    !JsonSerializer.Serialize(source).Contains("Password", StringComparison.OrdinalIgnoreCase),
    "Connection diagnostics exposed credentials.");
var security = new FileInfo(credential).GetAccessControl();
Require(security.AreAccessRulesProtected, "Credential permissions inherit from the containing directory.");
var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
Require(rules.Length == 1 && rules[0].IdentityReference.Equals(account) &&
    rules[0].AccessControlType == AccessControlType.Allow, "Another account can read the credential file.");
security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
    FileSystemRights.Read, AccessControlType.Allow));
new FileInfo(credential).SetAccessControl(security);
Reject(credential);
ConnectionCredentials.Save(credential, source);
Require(new FileInfo(credential).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Count == 1,
    "Replacing a credential retained permissive file permissions.");
var separate = await Run(Environment.ProcessPath!, ["--load", credential]);
Require(separate.Exit == 0 && separate.Text.Contains("PostgreSql"),
    "Another process in the same account could not load credentials.");

// Reject damaged ciphertext and plaintext files without echoing supplied secrets.
var tampered = JsonNode.Parse(File.ReadAllText(credential))!.AsObject();
var bytes = Convert.FromBase64String(tampered["ProtectedConnection"]!.GetValue<string>());
bytes[^1] ^= 1;
tampered["ProtectedConnection"] = Convert.ToBase64String(bytes);
var damaged = Path.Combine(output, "damaged.credential");
File.WriteAllText(damaged, tampered.ToJsonString());
new FileInfo(damaged).SetAccessControl(new FileInfo(credential).GetAccessControl());
Reject(damaged);
File.WriteAllText(damaged, connection);
Reject(damaged);
var provisioned = Path.Combine(output, "relay.credential");
var provision = await Run(relay, ["--protect-connection", provisioned, "--provider", "postgresql"], connection);
Require(provision.Exit == 0 && !provision.Text.Contains(secret, StringComparison.Ordinal),
    "Provisioning failed or echoed the secret.");
Require(ConnectionCredentials.Load(provisioned).ConnectionString == connection,
    "Provisioning changed the connection details.");
var sql = new DatabaseSource(DatabaseProvider.SqlServer, new Microsoft.Data.SqlClient.SqlConnectionStringBuilder
{
    DataSource = "credential-test.invalid", InitialCatalog = "fixture", UserID = "credential-test", Password = secret,
    Encrypt = Microsoft.Data.SqlClient.SqlConnectionEncryptOption.Mandatory
}.ConnectionString);
var sqlFile = Path.Combine(output, "sqlserver.credential");
ConnectionCredentials.Save(sqlFile, sql);
Require(ConnectionCredentials.Load(sqlFile).ConnectionString == sql.ConnectionString &&
    !File.ReadAllText(sqlFile).Contains(secret, StringComparison.Ordinal),
    "SQL Server credentials did not remain protected.");
var legacy = await Run(relay, ["--source", "unused.db", "--provider", "postgresql", "--connection-env", "UNUSED"]);
Require(legacy.Exit != 0 && legacy.Text.Contains("--connection-file"),
    "Relay accepted plaintext environment credentials.");

var elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
if (elevated)
{
    var systemCredential = Path.Combine(output, "system.credential");
    var protectedSystem = await Run(relay,
        ["--protect-connection", systemCredential, "--provider", "postgresql", "--local-system"], connection);
    Require(protectedSystem.Exit == 0, "LocalSystem provisioning failed: " + protectedSystem.Text);
    Reject(systemCredential);

    // Allow the fixture service to read ciphertext while keeping the user's DPAPI protection intact.
    security = new FileInfo(credential).GetAccessControl();
    security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
        FileSystemRights.Read, AccessControlType.Allow));
    new FileInfo(credential).SetAccessControl(security);
    var serviceName = "CipherazziCredentialTest-" + Guid.NewGuid().ToString("N");
    var result = Path.Combine(output, "service-result.txt");
    var binary = $"\"{Environment.ProcessPath}\" --audit-service {serviceName} \"{credential}\" " +
        $"\"{systemCredential}\" \"{result}\"";
    var created = await Run("sc.exe", ["create", serviceName, "binPath=", binary, "start=", "demand"]);
    Require(created.Exit == 0, "Could not create the fixture service.");
    try
    {
        Require((await Run("sc.exe", ["start", serviceName])).Exit == 0, "Could not start the fixture service.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while (!File.Exists(result))
            await Task.Delay(100, deadline.Token);
        Console.WriteLine(File.ReadAllText(result));
    }
    finally
    {
        await Run("sc.exe", ["stop", serviceName]);
        await Run("sc.exe", ["delete", serviceName]);
    }
}
else
{
    var denied = await Run(relay,
        ["--protect-connection", Path.Combine(output, "system.credential"),
            "--provider", "postgresql", "--local-system"],
        connection);
    Require(denied.Exit != 0 && denied.Text.Contains("elevated console"),
        "LocalSystem provisioning did not require elevation.");
    Console.WriteLine("LocalSystem service isolation checks require an elevated test run.");
}
Console.WriteLine("Protected credential persistence, ACLs, child-process loading, " +
    "corruption rejection, and provisioning passed.");
return 0;

void Reject(string path)
{
    try
    {
        ConnectionCredentials.Load(path);
        throw new InvalidOperationException("An invalid or inaccessible credential was accepted.");
    }
    catch (InvalidDataException error)
    {
        Require(!error.Message.Contains(secret, StringComparison.Ordinal), "Credential failure echoed the password.");
    }
}

static void Require(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

static async Task<(int Exit, string Text)> Run(string executable, string[] arguments, string? input = null)
{
    var start = new ProcessStartInfo(executable)
    {
        UseShellExecute = false, CreateNoWindow = true,
        RedirectStandardInput = input is not null, RedirectStandardOutput = true, RedirectStandardError = true
    };
    if (input is not null)
        start.StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
    foreach (var argument in arguments)
        start.ArgumentList.Add(argument);
    using var process = Process.Start(start)!;
    if (input is not null)
    {
        await process.StandardInput.WriteLineAsync(input);
        process.StandardInput.Close();
    }
    var output = process.StandardOutput.ReadToEndAsync();
    var error = process.StandardError.ReadToEndAsync();
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
    try { await process.WaitForExitAsync(timeout.Token); }
    finally
    {
        if (!process.HasExited)
            process.Kill(entireProcessTree: true);
    }
    return (process.ExitCode, await output + await error);
}
