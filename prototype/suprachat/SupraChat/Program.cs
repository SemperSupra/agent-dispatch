using Avalonia;

namespace SupraChat;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var logPath = Environment.GetEnvironmentVariable("SUPRACHAT_STARTUP_LOG");
        void Log(string message)
        {
            if (string.IsNullOrWhiteSpace(logPath))
                return;

            try
            {
                var directory = Path.GetDirectoryName(logPath);
                if (!string.IsNullOrWhiteSpace(directory))
                    Directory.CreateDirectory(directory);
                File.AppendAllText(logPath, $"{DateTimeOffset.UtcNow:O} {message}{Environment.NewLine}");
            }
            catch
            {
                // Startup diagnostics must never become an application dependency.
            }
        }

        Log($"managed-main-entered framework={Environment.Version} os={Environment.OSVersion}");

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
            Log("desktop-lifetime-returned");
            return 0;
        }
        catch (Exception ex)
        {
            Log("fatal-startup-exception");
            Log(ex.ToString());
            return 70;
        }
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
