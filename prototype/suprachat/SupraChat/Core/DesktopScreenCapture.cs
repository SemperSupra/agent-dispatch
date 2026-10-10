using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SupraChat.Core;

public sealed record ScreenCaptureDescriptor(
    string Schema,
    string Platform,
    bool Implemented,
    string Adapter,
    string? Executable,
    bool RequiresExplicitInvocation,
    string PermissionBoundary);

public static class DesktopScreenCapture
{
    public const string Schema = "suprachat-screen-capture/v1";

    public static ScreenCaptureDescriptor Describe()
    {
        if (OperatingSystem.IsWindows())
        {
            return new(
                Schema,
                "windows",
                true,
                "powershell-system-drawing",
                FindExecutable("pwsh.exe", "powershell.exe"),
                true,
                "Interactive desktop/session access; Windows desktop policy applies.");
        }

        if (OperatingSystem.IsMacOS())
        {
            var executable = FirstExisting(
                "/usr/sbin/screencapture",
                "/usr/bin/screencapture");
            return new(
                Schema,
                "macos",
                executable is not null,
                "macos-screencapture",
                executable,
                true,
                "macOS Screen Recording permission may be required.");
        }

        if (OperatingSystem.IsLinux())
        {
            var executable = FindExecutable("grim", "gnome-screenshot", "scrot", "import");
            return new(
                Schema,
                "linux",
                executable is not null,
                executable is null ? "unavailable" : Path.GetFileName(executable),
                executable,
                true,
                "Desktop/compositor screenshot policy applies; Wayland may require portal/compositor permission.");
        }

        return new(
            Schema,
            "unknown",
            false,
            "unsupported",
            null,
            true,
            "Unsupported platform.");
    }

    public static async Task<string> CaptureAsync(
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        var fullPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath) ?? Directory.GetCurrentDirectory());

        if (OperatingSystem.IsWindows())
            await CaptureWindowsAsync(fullPath, cancellationToken);
        else if (OperatingSystem.IsMacOS())
            await CaptureMacAsync(fullPath, cancellationToken);
        else if (OperatingSystem.IsLinux())
            await CaptureLinuxAsync(fullPath, cancellationToken);
        else
            throw new PlatformNotSupportedException("Screen capture is not implemented on this platform.");

        var info = new FileInfo(fullPath);
        if (!info.Exists || info.Length == 0)
            throw new InvalidOperationException("Screen capture completed without producing a non-empty image.");

        return fullPath;
    }

    private static async Task CaptureWindowsAsync(string outputPath, CancellationToken cancellationToken)
    {
        var shell = FindExecutable("pwsh.exe", "powershell.exe")
            ?? throw new InvalidOperationException("PowerShell is required for the Windows capture adapter.");

        const string script = """
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
try {
  $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
  $bitmap.Save($env:SUPRACHAT_CAPTURE_PATH, [System.Drawing.Imaging.ImageFormat]::Png)
}
finally {
  $graphics.Dispose()
  $bitmap.Dispose()
}
""";

        var psi = NewProcess(shell);
        psi.Environment["SUPRACHAT_CAPTURE_PATH"] = outputPath;
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add(script);
        await RunAsync(psi, cancellationToken);
    }

    private static async Task CaptureMacAsync(string outputPath, CancellationToken cancellationToken)
    {
        var executable = FirstExisting("/usr/sbin/screencapture", "/usr/bin/screencapture")
            ?? throw new InvalidOperationException("macOS screencapture utility is unavailable.");

        var psi = NewProcess(executable);
        psi.ArgumentList.Add("-x");
        psi.ArgumentList.Add("-t");
        psi.ArgumentList.Add("png");
        psi.ArgumentList.Add(outputPath);
        await RunAsync(psi, cancellationToken);
    }

    private static async Task CaptureLinuxAsync(string outputPath, CancellationToken cancellationToken)
    {
        var executable = FindExecutable("grim", "gnome-screenshot", "scrot", "import")
            ?? throw new InvalidOperationException(
                "No supported Linux screenshot adapter is installed (grim, gnome-screenshot, scrot, or ImageMagick import).");

        var name = Path.GetFileName(executable);
        var psi = NewProcess(executable);
        switch (name)
        {
            case "grim":
                psi.ArgumentList.Add(outputPath);
                break;
            case "gnome-screenshot":
                psi.ArgumentList.Add("-f");
                psi.ArgumentList.Add(outputPath);
                break;
            case "scrot":
                psi.ArgumentList.Add(outputPath);
                break;
            case "import":
                psi.ArgumentList.Add("-window");
                psi.ArgumentList.Add("root");
                psi.ArgumentList.Add(outputPath);
                break;
            default:
                throw new InvalidOperationException($"Unsupported Linux screenshot adapter: {name}");
        }

        await RunAsync(psi, cancellationToken);
    }

    private static ProcessStartInfo NewProcess(string executable) => new(executable)
    {
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };

    private static async Task RunAsync(ProcessStartInfo psi, CancellationToken cancellationToken)
    {
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start screen-capture adapter: {psi.FileName}");

        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        var stderr = await stderrTask;
        _ = await stdoutTask;

        if (process.ExitCode != 0)
        {
            var message = string.IsNullOrWhiteSpace(stderr)
                ? $"Screen-capture adapter exited with code {process.ExitCode}."
                : $"Screen-capture adapter exited with code {process.ExitCode}: {stderr.Trim()}";
            throw new InvalidOperationException(message);
        }
    }

    private static string? FirstExisting(params string[] paths) =>
        paths.FirstOrDefault(File.Exists);

    private static string? FindExecutable(params string[] names)
    {
        foreach (var name in names)
        {
            if (Path.IsPathRooted(name) && File.Exists(name))
                return name;

            var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    var candidate = Path.Combine(directory, name);
                    if (File.Exists(candidate))
                        return candidate;
                }
                catch
                {
                }
            }
        }

        return null;
    }
}
