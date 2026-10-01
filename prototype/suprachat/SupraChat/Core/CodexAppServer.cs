using System.Diagnostics;

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

    public static Process Start(string accessToken)
    {
        var psi = new ProcessStartInfo("codex")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var arg in Arguments)
            psi.ArgumentList.Add(arg);
        psi.Environment["ACCESS_TOKEN"] = accessToken;

        return Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start codex app-server.");
    }
}
