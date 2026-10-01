using System.Text.Json;

namespace SupraChat.Core;

public static class SupraChatMarketplace
{
    public const string MarketplaceName = "sempersupra-local";
    public const string DiagnosticsPluginName = "suprachat-diagnostics";
    public const string DiagnosticsPluginId = "suprachat-diagnostics@sempersupra-local";

    public static string RootPath =>
        Path.Combine(AppContext.BaseDirectory, "runtime", "marketplace");

    public static string ManifestPath =>
        Path.Combine(RootPath, ".agents", "plugins", "marketplace.json");

    public static string DiagnosticsPluginRoot =>
        Path.Combine(RootPath, "plugins", DiagnosticsPluginName);

    public static void RequirePackaged()
    {
        if (!Directory.Exists(RootPath))
            throw new InvalidOperationException($"Packaged SupraChat marketplace is missing: {RootPath}");
        if (!File.Exists(ManifestPath))
            throw new InvalidOperationException($"Marketplace manifest is missing: {ManifestPath}");
        if (!File.Exists(Path.Combine(
                DiagnosticsPluginRoot,
                ".codex-plugin",
                "plugin.json")))
            throw new InvalidOperationException("SupraChat diagnostics plugin manifest is missing.");
    }

    public static async Task<JsonElement> AddAsync(
        CodexAppServerClient client,
        CancellationToken cancellationToken = default)
    {
        RequirePackaged();
        return await client.RequestAsync(
            "marketplace/add",
            JsonSerializer.SerializeToElement(new
            {
                source = RootPath,
                refName = (string?)null,
                sparsePaths = (string[]?)null
            }),
            cancellationToken).ConfigureAwait(false);
    }

    public static async Task<JsonElement> RemoveAsync(
        CodexAppServerClient client,
        CancellationToken cancellationToken = default) =>
        await client.RequestAsync(
            "marketplace/remove",
            JsonSerializer.SerializeToElement(new
            {
                marketplaceName = MarketplaceName
            }),
            cancellationToken).ConfigureAwait(false);

    public static async Task<JsonElement> ListAsync(
        CodexAppServerClient client,
        CancellationToken cancellationToken = default)
    {
        RequirePackaged();
        return await client.RequestAsync(
            "plugin/list",
            JsonSerializer.SerializeToElement(new
            {
                cwds = new[] { RootPath },
                marketplaceKinds = (string[]?)null,
                forceRefetch = false
            }),
            cancellationToken).ConfigureAwait(false);
    }

    public static async Task<JsonElement> InstalledAsync(
        CodexAppServerClient client,
        CancellationToken cancellationToken = default) =>
        await client.RequestAsync(
            "plugin/installed",
            JsonSerializer.SerializeToElement(new
            {
                cwds = new[] { RootPath },
                installSuggestionPluginNames = new[] { DiagnosticsPluginName }
            }),
            cancellationToken).ConfigureAwait(false);

    public static async Task<JsonElement> InstallDiagnosticsAsync(
        CodexAppServerClient client,
        CancellationToken cancellationToken = default)
    {
        RequirePackaged();
        return await client.RequestAsync(
            "plugin/install",
            JsonSerializer.SerializeToElement(new
            {
                marketplacePath = ManifestPath,
                remoteMarketplaceName = (string?)null,
                installAttemptId = $"suprachat-{Guid.NewGuid():N}",
                pluginName = DiagnosticsPluginName
            }),
            cancellationToken).ConfigureAwait(false);
    }

    public static async Task<JsonElement> ReadDiagnosticsAsync(
        CodexAppServerClient client,
        CancellationToken cancellationToken = default)
    {
        RequirePackaged();
        return await client.RequestAsync(
            "plugin/read",
            JsonSerializer.SerializeToElement(new
            {
                marketplacePath = ManifestPath,
                remoteMarketplaceName = (string?)null,
                pluginName = DiagnosticsPluginName
            }),
            cancellationToken).ConfigureAwait(false);
    }

    public static async Task<JsonElement> UninstallDiagnosticsAsync(
        CodexAppServerClient client,
        CancellationToken cancellationToken = default) =>
        await client.RequestAsync(
            "plugin/uninstall",
            JsonSerializer.SerializeToElement(new
            {
                pluginId = DiagnosticsPluginId
            }),
            cancellationToken).ConfigureAwait(false);
}
