using System.Text.Json;

namespace SupraChat.Core;

public sealed record AccessibilityPreferences(
    string Schema,
    double InterfaceScale,
    bool ReducedMotion)
{
    public static AccessibilityPreferences Default =>
        new(AccessibilityPreferencesStore.Schema, 1.0, false);
}

public static class AccessibilityPreferencesStore
{
    public const string Schema = "suprachat-accessibility-preferences/v1";
    public const double MinimumScale = 0.8;
    public const double MaximumScale = 2.0;
    public const double ScaleStep = 0.1;

    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static string PathName =>
        Path.Combine(AppState.DirectoryPath, "accessibility-preferences.json");

    public static async Task<AccessibilityPreferences> LoadAsync()
    {
        await Gate.WaitAsync();
        try
        {
            if (!File.Exists(PathName))
                return AccessibilityPreferences.Default;

            try
            {
                var text = await File.ReadAllTextAsync(PathName);
                var value = JsonSerializer.Deserialize<AccessibilityPreferences>(text);
                return value is null ? AccessibilityPreferences.Default : Normalize(value);
            }
            catch (JsonException)
            {
                return AccessibilityPreferences.Default;
            }
        }
        finally
        {
            Gate.Release();
        }
    }

    public static async Task<AccessibilityPreferences> SaveAsync(
        double interfaceScale,
        bool reducedMotion)
    {
        var value = Normalize(new AccessibilityPreferences(
            Schema,
            interfaceScale,
            reducedMotion));

        await Gate.WaitAsync();
        try
        {
            Directory.CreateDirectory(AppState.DirectoryPath);
            var temp = PathName + ".tmp";
            var json = JsonSerializer.Serialize(
                value,
                new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(temp, json + Environment.NewLine);
            AppState.TryRestrict(temp);
            File.Move(temp, PathName, overwrite: true);
            AppState.TryRestrict(PathName);
            return value;
        }
        finally
        {
            Gate.Release();
        }
    }

    public static AccessibilityPreferences Normalize(AccessibilityPreferences value)
    {
        var scale = Math.Clamp(value.InterfaceScale, MinimumScale, MaximumScale);
        scale = Math.Round(scale / ScaleStep) * ScaleStep;
        return value with
        {
            Schema = Schema,
            InterfaceScale = Math.Round(scale, 1)
        };
    }
}
