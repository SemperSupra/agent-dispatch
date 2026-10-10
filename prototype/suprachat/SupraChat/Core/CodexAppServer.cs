using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SupraChat.Core;

public static class CodexAppServer
{
    public static IReadOnlyList<string> Arguments { get; } = new[]
    {
        "app-server",
        "--listen", "stdio://",
        "-c", "model_provider=\"openai_chatgpt_plan\"",
        "-c", "model_providers.openai_chatgpt_plan.name=\"ChatGPT plan\"",
        "-c", "model_providers.openai_chatgpt_plan.base_url=\"https://api.openai.com/v1\"",
        "-c", "model_providers.openai_chatgpt_plan.env_key=\"ACCESS_TOKEN\"",
        "-c", "model_providers.openai_chatgpt_plan.wire_api=\"responses\"",
        "-c", "model_providers.openai_chatgpt_plan.requires_openai_auth=false",
        "-c", "model_providers.openai_chatgpt_plan.supports_websockets=false"
    };

    public static string ResolveExecutable(string? baseDirectory = null)
    {
        baseDirectory ??= AppContext.BaseDirectory;
        var name = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "codex.exe" : "codex";

        var candidates = new[]
        {
            Path.Combine(baseDirectory, "runtime", "codex", name),
            Path.Combine(baseDirectory, "codex", name),
            Path.Combine(baseDirectory, name)
        };

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
                return candidate;
        }

        // Development fallback. Packaged builds are expected to carry a pinned runtime.
        return name;
    }

    public static Process Start(string accessToken) =>
        StartCore(accessToken);

    public static Process StartLocal() =>
        StartCore(accessToken: null);

    private static Process StartCore(string? accessToken)
    {
        var psi = new ProcessStartInfo(ResolveExecutable())
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var arg in Arguments)
            psi.ArgumentList.Add(arg);

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            psi.Environment["ACCESS_TOKEN"] = accessToken;
        }
        else
        {
            // Match the qualified guest experiment: local/read-only Codex must
            // neither inherit ambient OpenAI credentials nor the user's default
            // Codex/XDG auth state.
            foreach (var name in new[]
            {
                "ACCESS_TOKEN",
                "OPENAI_API_KEY",
                "CODEX_API_KEY",
                "OPENAI_ACCESS_TOKEN",
                "CHATGPT_ACCESS_TOKEN"
            })
            {
                psi.Environment.Remove(name);
            }

            var localHome = Path.Combine(AppState.DirectoryPath, "codex-local");
            var xdgConfig = Path.Combine(localHome, "xdg-config");
            var xdgData = Path.Combine(localHome, "xdg-data");
            Directory.CreateDirectory(localHome);
            Directory.CreateDirectory(xdgConfig);
            Directory.CreateDirectory(xdgData);
            psi.Environment["CODEX_HOME"] = localHome;
            psi.Environment["XDG_CONFIG_HOME"] = xdgConfig;
            psi.Environment["XDG_DATA_HOME"] = xdgData;
        }

        return Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start codex app-server.");
    }
}
