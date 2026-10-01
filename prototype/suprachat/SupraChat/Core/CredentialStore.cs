using System.Text.Json;

namespace SupraChat.Core;

public static class CredentialStore
{
    private static string PathName => Path.Combine(AppState.DirectoryPath, "siwc-credential.json");

    public static async Task SaveAsync(SiwcCredential credential)
    {
        Directory.CreateDirectory(AppState.DirectoryPath);
        var temp = PathName + ".tmp";
        var json = JsonSerializer.Serialize(credential, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(temp, json);
        AppState.TryRestrict(temp);
        File.Move(temp, PathName, overwrite: true);
        AppState.TryRestrict(PathName);
    }

    public static async Task<SiwcCredential?> TryLoadAsync()
    {
        if (!File.Exists(PathName))
            return null;

        var json = await File.ReadAllTextAsync(PathName);
        return JsonSerializer.Deserialize<SiwcCredential>(json);
    }
}
