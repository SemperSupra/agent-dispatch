using System.Text.Json;
using SupraChat.Core;

namespace SupraChat.Automation;

internal static class BrowserMachine
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static BrowserHost? _host;

    public static async Task<object> StartAsync(JsonElement? parameters)
    {
        var p = ObjectOrEmpty(parameters);
        var headless = !p.TryGetProperty("headless", out var h) || h.ValueKind != JsonValueKind.False;
        var profile = StringProperty(p, "profile") ?? "automation";

        await Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            _host ??= new BrowserHost();
            await _host.StartAsync(headless, profile).ConfigureAwait(false);
            return new
            {
                running = _host.IsRunning,
                headless,
                profile,
                runtime_path = BrowserHost.RuntimePath,
                profiles_root = BrowserHost.ProfilesRoot
            };
        }
        finally
        {
            Gate.Release();
        }
    }

    public static async Task<object> StopAsync()
    {
        await Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var wasRunning = _host?.IsRunning == true;
            if (_host is not null)
            {
                await _host.DisposeAsync().ConfigureAwait(false);
                _host = null;
            }

            return new { stopped = wasRunning };
        }
        finally
        {
            Gate.Release();
        }
    }

    public static async Task<object> PagesAsync()
    {
        var host = RequireHost();
        return new { pages = await host.ListPagesAsync().ConfigureAwait(false) };
    }

    public static async Task<object> NewPageAsync(JsonElement? parameters)
    {
        var p = ObjectOrEmpty(parameters);
        return await RequireHost()
            .NewPageAsync(StringProperty(p, "url"))
            .ConfigureAwait(false);
    }

    public static async Task<object> NavigateAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        return await RequireHost()
            .NavigateAsync(IntProperty(p, "page"), RequiredString(p, "url"))
            .ConfigureAwait(false);
    }

    public static async Task<object> BackAsync(JsonElement? parameters) =>
        await RequireHost()
            .GoBackAsync(PageIndex(parameters))
            .ConfigureAwait(false);

    public static async Task<object> ForwardAsync(JsonElement? parameters) =>
        await RequireHost()
            .GoForwardAsync(PageIndex(parameters))
            .ConfigureAwait(false);

    public static async Task<object> ReloadAsync(JsonElement? parameters) =>
        await RequireHost()
            .ReloadAsync(PageIndex(parameters))
            .ConfigureAwait(false);

    public static async Task<object> ClosePageAsync(JsonElement? parameters)
    {
        await RequireHost()
            .ClosePageAsync(PageIndex(parameters))
            .ConfigureAwait(false);
        return new { closed = true };
    }

    public static async Task<object> ObserveAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        var includeHtml =
            p.TryGetProperty("include_html", out var value) &&
            value.ValueKind == JsonValueKind.True;

        return await RequireHost()
            .ObserveAsync(IntProperty(p, "page"), includeHtml)
            .ConfigureAwait(false);
    }

    public static async Task<object> ScreenshotAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        var destination = Path.GetFullPath(RequiredString(p, "path"));
        var fullPage =
            !p.TryGetProperty("full_page", out var fp) ||
            fp.ValueKind != JsonValueKind.False;

        await RequireHost()
            .ScreenshotAsync(IntProperty(p, "page"), destination, fullPage)
            .ConfigureAwait(false);

        return new { path = destination, full_page = fullPage };
    }

    public static async Task<object> ClickAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        await RequireHost()
            .ClickAsync(IntProperty(p, "page"), RequiredString(p, "selector"))
            .ConfigureAwait(false);
        return new { clicked = true };
    }

    public static async Task<object> FillAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        await RequireHost()
            .FillAsync(
                IntProperty(p, "page"),
                RequiredString(p, "selector"),
                RequiredString(p, "value"))
            .ConfigureAwait(false);
        return new { filled = true };
    }

    public static async Task<object> PressAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        await RequireHost()
            .PressAsync(
                IntProperty(p, "page"),
                RequiredString(p, "selector"),
                RequiredString(p, "key"))
            .ConfigureAwait(false);
        return new { pressed = true };
    }

    public static async Task<object> UploadAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        if (!p.TryGetProperty("paths", out var paths) ||
            paths.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("browser/upload requires params.paths array.");

        var values = paths.EnumerateArray()
            .Select(item => item.GetString())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => Path.GetFullPath(value!))
            .ToArray();

        await RequireHost()
            .SetInputFilesAsync(
                IntProperty(p, "page"),
                RequiredString(p, "selector"),
                values)
            .ConfigureAwait(false);

        return new { uploaded = values.Length };
    }

    public static async Task<object> GrantPermissionsAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        if (!p.TryGetProperty("permissions", out var permissions) ||
            permissions.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("browser/permissions/grant requires params.permissions array.");

        var values = permissions.EnumerateArray()
            .Select(item => item.GetString())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .ToArray();

        await RequireHost()
            .GrantPermissionsAsync(values, StringProperty(p, "origin"))
            .ConfigureAwait(false);

        return new { granted = values };
    }

    public static async Task<object> ClearPermissionsAsync()
    {
        await RequireHost().ClearPermissionsAsync().ConfigureAwait(false);
        return new { cleared = true };
    }

    public static async Task<object> TraceStartAsync()
    {
        await RequireHost().StartTracingAsync().ConfigureAwait(false);
        return new { tracing = true };
    }

    public static async Task<object> TraceStopAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        var destination = Path.GetFullPath(RequiredString(p, "path"));
        await RequireHost().StopTracingAsync(destination).ConfigureAwait(false);
        return new { tracing = false, path = destination };
    }

    public static async Task<object> EvaluateAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        object? argument = null;
        if (p.TryGetProperty("argument", out var arg))
            argument = JsonSerializer.Deserialize<object?>(arg.GetRawText());

        var result = await RequireHost()
            .EvaluateAsync(
                IntProperty(p, "page"),
                RequiredString(p, "expression"),
                argument)
            .ConfigureAwait(false);

        return new { result };
    }

    public static async Task<object> ObserveUrlAsync(
        string url,
        bool includeHtml)
    {
        await StartAsync(JsonSerializer.SerializeToElement(new
        {
            headless = true,
            profile = "automation-one-shot"
        })).ConfigureAwait(false);

        try
        {
            var page = await RequireHost().NewPageAsync(url).ConfigureAwait(false);
            return await RequireHost()
                .ObserveAsync(page.Index, includeHtml)
                .ConfigureAwait(false);
        }
        finally
        {
            await StopAsync().ConfigureAwait(false);
        }
    }

    public static async Task<object> ScreenshotUrlAsync(
        string url,
        string destination)
    {
        await StartAsync(JsonSerializer.SerializeToElement(new
        {
            headless = true,
            profile = "automation-one-shot"
        })).ConfigureAwait(false);

        try
        {
            var page = await RequireHost().NewPageAsync(url).ConfigureAwait(false);
            destination = Path.GetFullPath(destination);
            await RequireHost()
                .ScreenshotAsync(page.Index, destination, fullPage: true)
                .ConfigureAwait(false);
            return new { path = destination, url };
        }
        finally
        {
            await StopAsync().ConfigureAwait(false);
        }
    }

    private static BrowserHost RequireHost() =>
        _host is { IsRunning: true }
            ? _host
            : throw new InvalidOperationException(
                "Browser host is not running. Call browser/start first.");

    private static JsonElement ObjectOrEmpty(JsonElement? value) =>
        value is { ValueKind: JsonValueKind.Object } objectValue
            ? objectValue
            : JsonSerializer.SerializeToElement(new { });

    private static JsonElement RequireObject(JsonElement? value) =>
        value is { ValueKind: JsonValueKind.Object } objectValue
            ? objectValue
            : throw new InvalidOperationException("Browser params must be an object.");

    private static int PageIndex(JsonElement? parameters) =>
        IntProperty(RequireObject(parameters), "page");

    private static int IntProperty(JsonElement value, string name) =>
        value.TryGetProperty(name, out var property) &&
        property.TryGetInt32(out var result)
            ? result
            : throw new InvalidOperationException($"Missing integer params.{name}.");

    private static string RequiredString(JsonElement value, string name) =>
        StringProperty(value, name)
        ?? throw new InvalidOperationException($"Missing string params.{name}.");

    private static string? StringProperty(JsonElement value, string name) =>
        value.TryGetProperty(name, out var property) &&
        property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
}
