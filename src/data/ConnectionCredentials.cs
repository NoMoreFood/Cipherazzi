using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Runtime.Versioning;

namespace Cipherazzi.Data;

[SupportedOSPlatform("windows")]
public static class ConnectionCredentials
{
    private sealed record SavedConnection(DatabaseProvider Provider, string Account, byte[] ProtectedConnection);

    private static byte[] Entropy(DatabaseProvider provider)
    {
        using var identity = WindowsIdentity.GetCurrent();
        return Encoding.UTF8.GetBytes($"Cipherazzi connection|{provider}|{identity.User!.Value}");
    }

    internal static byte[] Protect(DatabaseProvider provider, string connection)
    {
        var plaintext = Encoding.UTF8.GetBytes(connection);
        try { return ProtectedData.Protect(plaintext, Entropy(provider), DataProtectionScope.CurrentUser); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal static string Unprotect(DatabaseProvider provider, byte[] connection)
    {
        var plaintext = ProtectedData.Unprotect(connection, Entropy(provider), DataProtectionScope.CurrentUser);
        try { return Encoding.UTF8.GetString(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public static void Save(string path, DatabaseSource source)
    {
        if (source.Provider == DatabaseProvider.Sqlite)
            throw new ArgumentException("Choose a server connection to save credentials.");
        var connection = Protect(source.Provider, source.ConnectionString);
        path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var identity = WindowsIdentity.GetCurrent();
        var account = identity.User!;
        var protection = new FileSecurity();
        protection.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        protection.SetOwner(account);
        protection.AddAccessRule(new FileSystemAccessRule(account, FileSystemRights.FullControl,
            AccessControlType.Allow));
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            // Restrict the file before writing and replace it atomically without exposing a plaintext copy.
            using (var output = new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.None, 4096, FileOptions.WriteThrough, protection))
            {
                JsonSerializer.Serialize(output, new SavedConnection(source.Provider, account.Value,
                    connection));
                if (output.Length > 256 * 1024)
                    throw new InvalidDataException("The protected connection exceeds 256 KiB.");
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    public static DatabaseSource Load(string path)
    {
        try
        {
            path = Path.GetFullPath(path);
            using var input = File.OpenRead(path);
            using var identity = WindowsIdentity.GetCurrent();
            var account = identity.User!;
            var permissions = input.GetAccessControl();

            // Accept credentials only from files owned and restricted to the running account.
            if (!permissions.AreAccessRulesProtected ||
                !account.Equals(permissions.GetOwner(typeof(SecurityIdentifier))) ||
                permissions.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                    .Any(rule => rule.AccessControlType == AccessControlType.Allow &&
                        !rule.IdentityReference.Equals(account)))
                throw new InvalidDataException();
            if (input.Length is 0 or > 256 * 1024)
                throw new InvalidDataException();
            var saved = JsonSerializer.Deserialize<SavedConnection>(input);

            // Reject account or provider changes before decrypting the connection.
            if (saved is null || saved.Provider is not (DatabaseProvider.SqlServer or DatabaseProvider.PostgreSql) ||
                saved.Account != account.Value || saved.ProtectedConnection is not { Length: > 0 })
                throw new InvalidDataException();
            return new DatabaseSource(saved.Provider, Unprotect(saved.Provider, saved.ProtectedConnection));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or
            CryptographicException or ArgumentException)
        {
            throw new InvalidDataException(
                "Cannot open the protected connection. Provision it on this computer for the account running " +
                "this application, and check its file permissions.");
        }
    }
}
