namespace SupraChat.Core;

public static class HostIdentity
{
    public static async Task<string> LoadOrCreateAsync()
    {
        var dir = AppState.DirectoryPath;
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "host-id.txt");
        if (File.Exists(path))
        {
            var current = (await File.ReadAllTextAsync(path)).Trim();
            if (current.StartsWith("urn:uuid:", StringComparison.Ordinal))
                return current;
        }

        var value = "urn:uuid:" + Guid.NewGuid();
        await File.WriteAllTextAsync(path, value + Environment.NewLine);
        AppState.TryRestrict(path);
        return value;
    }
}

public static class AppState
{
    public static string DirectoryPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SemperSupra",
            "SupraChat");

    public static void TryRestrict(string path)
    {
        if (OperatingSystem.IsWindows())
            return;

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (PlatformNotSupportedException)
        {
        }
    }
}
