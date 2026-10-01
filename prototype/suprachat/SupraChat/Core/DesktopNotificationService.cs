using System.Diagnostics;
using Avalonia.Controls;

namespace SupraChat.Core;

public static class DesktopNotificationService
{
    public static string Adapter =>
        OperatingSystem.IsWindows() ? WindowsNotificationService.Adapter :
        OperatingSystem.IsMacOS() ? "macos-user-notification-via-osascript" :
        OperatingSystem.IsLinux() ? "freedesktop-notify-send" :
        "unsupported";

    public static bool TryNotify(Window owner, string title, string message)
    {
        if (OperatingSystem.IsWindows())
            return WindowsNotificationService.TryNotify(owner, title, message);

        if (OperatingSystem.IsMacOS())
            return TryStart(
                "/usr/bin/osascript",
                "-e",
                $"display notification {AppleScriptString(message)} with title {AppleScriptString(title)}");

        if (OperatingSystem.IsLinux())
            return TryStart(
                "notify-send",
                "--app-name=SupraChat",
                "--",
                title,
                message);

        return false;
    }

    private static bool TryStart(string fileName, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(fileName)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var arg in args)
                psi.ArgumentList.Add(arg);

            using var process = Process.Start(psi);
            if (process is null)
                return false;

            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string AppleScriptString(string value)
    {
        var escaped = value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal);
        return $"\\\"{escaped}\\\"";
    }
}
