using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SupraChat.Core;

public static class CredentialStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SemperSupra/SupraChat/SIWC/v1");
    private static string PathName => Path.Combine(AppState.DirectoryPath, "siwc-credential.dat");

    public static async Task SaveAsync(SiwcCredential credential)
    {
        Directory.CreateDirectory(AppState.DirectoryPath);
        var temp = PathName + ".tmp";
        var json = JsonSerializer.SerializeToUtf8Bytes(
            credential,
            new JsonSerializerOptions { WriteIndented = !OperatingSystem.IsWindows() });

        var payload = OperatingSystem.IsWindows()
            ? ProtectedData.Protect(json, Entropy, DataProtectionScope.CurrentUser)
            : json;

        await File.WriteAllBytesAsync(temp, payload);
        AppState.TryRestrict(temp);
        File.Move(temp, PathName, overwrite: true);
        AppState.TryRestrict(PathName);
    }

    public static async Task<SiwcCredential?> TryLoadAsync()
    {
        if (!File.Exists(PathName))
            return null;

        var payload = await File.ReadAllBytesAsync(PathName);
        var json = OperatingSystem.IsWindows()
            ? ProtectedData.Unprotect(payload, Entropy, DataProtectionScope.CurrentUser)
            : payload;

        return JsonSerializer.Deserialize<SiwcCredential>(json);
    }

    public static void Clear()
    {
        if (File.Exists(PathName))
            File.Delete(PathName);
    }
}
