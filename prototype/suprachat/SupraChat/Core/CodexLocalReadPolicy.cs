namespace SupraChat.Core;

public static class CodexLocalReadPolicy
{
    public const string Schema = "suprachat-codex-local-read-policy/v1";

    private static readonly HashSet<string> Allowed = new(StringComparer.Ordinal)
    {
        "config/read",
        "configRequirements/read",
        "experimentalFeature/list",
        "collaborationMode/list",
        "model/list",
        "plugin/list",
        "permissionProfile/list",
        "app/list",
        "mcpServerStatus/list",
        "skills/list",
        "windowsSandbox/readiness",
        "thread/realtime/listVoices",
        "remoteControl/status/read",
        "thread/list"
    };

    public static IReadOnlyList<string> Methods =>
        Allowed.OrderBy(x => x, StringComparer.Ordinal).ToArray();

    public static bool IsAllowed(string method) =>
        !string.IsNullOrWhiteSpace(method) && Allowed.Contains(method);

    public static void RequireAllowed(string method)
    {
        if (!IsAllowed(method))
            throw new InvalidOperationException(
                $"Codex local-read method is not in the credential-free qualification allowlist: {method}");
    }
}
