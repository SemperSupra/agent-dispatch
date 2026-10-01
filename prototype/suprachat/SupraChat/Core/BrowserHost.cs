using System.Text.Json;
using Microsoft.Playwright;

namespace SupraChat.Core;

public sealed record BrowserPageInfo(
    int Index,
    string Url,
    string Title);

public sealed record BrowserObservation(
    int Index,
    string Url,
    string Title,
    string AriaSnapshot,
    string? Html);

public sealed class BrowserHost : IAsyncDisposable
{
    private IPlaywright? _playwright;
    private IBrowserContext? _context;

    public static string RuntimePath =>
        Path.Combine(AppContext.BaseDirectory, "runtime", "playwright");

    public static string ProfilesRoot =>
        Path.Combine(AppState.DirectoryPath, "browser-profiles");

    public bool IsRunning => _context is not null;

    public async Task StartAsync(
        bool headless = false,
        string profileName = "default")
    {
        if (_context is not null)
            return;

        Directory.CreateDirectory(RuntimePath);
        Directory.CreateDirectory(ProfilesRoot);
        Environment.SetEnvironmentVariable("PLAYWRIGHT_BROWSERS_PATH", RuntimePath);

        _playwright = await Playwright.CreateAsync().ConfigureAwait(false);
        var profile = Path.Combine(ProfilesRoot, SafeProfileName(profileName));
        Directory.CreateDirectory(profile);

        _context = await _playwright.Chromium.LaunchPersistentContextAsync(
            profile,
            new BrowserTypeLaunchPersistentContextOptions
            {
                Headless = headless,
                AcceptDownloads = true
            }).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<BrowserPageInfo>> ListPagesAsync()
    {
        var context = RequireContext();
        var result = new List<BrowserPageInfo>();
        for (var index = 0; index < context.Pages.Count; index++)
        {
            var page = context.Pages[index];
            result.Add(new BrowserPageInfo(
                index,
                page.Url,
                await page.TitleAsync().ConfigureAwait(false)));
        }

        return result;
    }

    public async Task<BrowserPageInfo> NewPageAsync(string? url = null)
    {
        var context = RequireContext();
        var page = await context.NewPageAsync().ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(url))
            await page.GotoAsync(url).ConfigureAwait(false);

        return new BrowserPageInfo(
            context.Pages.IndexOf(page),
            page.Url,
            await page.TitleAsync().ConfigureAwait(false));
    }

    public async Task<BrowserPageInfo> NavigateAsync(int pageIndex, string url)
    {
        var page = RequirePage(pageIndex);
        await page.GotoAsync(url).ConfigureAwait(false);
        return await InfoAsync(pageIndex, page).ConfigureAwait(false);
    }

    public async Task<BrowserPageInfo> GoBackAsync(int pageIndex)
    {
        var page = RequirePage(pageIndex);
        await page.GoBackAsync().ConfigureAwait(false);
        return await InfoAsync(pageIndex, page).ConfigureAwait(false);
    }

    public async Task<BrowserPageInfo> GoForwardAsync(int pageIndex)
    {
        var page = RequirePage(pageIndex);
        await page.GoForwardAsync().ConfigureAwait(false);
        return await InfoAsync(pageIndex, page).ConfigureAwait(false);
    }

    public async Task<BrowserPageInfo> ReloadAsync(int pageIndex)
    {
        var page = RequirePage(pageIndex);
        await page.ReloadAsync().ConfigureAwait(false);
        return await InfoAsync(pageIndex, page).ConfigureAwait(false);
    }

    public async Task ClosePageAsync(int pageIndex) =>
        await RequirePage(pageIndex).CloseAsync().ConfigureAwait(false);

    public async Task<BrowserObservation> ObserveAsync(
        int pageIndex,
        bool includeHtml = false)
    {
        var page = RequirePage(pageIndex);
        var title = await page.TitleAsync().ConfigureAwait(false);
        var aria = await page.Locator("body").AriaSnapshotAsync().ConfigureAwait(false);
        var html = includeHtml
            ? await page.ContentAsync().ConfigureAwait(false)
            : null;

        return new BrowserObservation(
            pageIndex,
            page.Url,
            title,
            aria,
            html);
    }

    public async Task ScreenshotAsync(
        int pageIndex,
        string destination,
        bool fullPage = true)
    {
        Directory.CreateDirectory(
            Path.GetDirectoryName(Path.GetFullPath(destination))
            ?? AppState.DirectoryPath);

        await RequirePage(pageIndex).ScreenshotAsync(
            new PageScreenshotOptions
            {
                Path = destination,
                FullPage = fullPage
            }).ConfigureAwait(false);
    }

    public async Task ClickAsync(int pageIndex, string selector) =>
        await RequirePage(pageIndex)
            .Locator(selector)
            .ClickAsync()
            .ConfigureAwait(false);

    public async Task FillAsync(int pageIndex, string selector, string value) =>
        await RequirePage(pageIndex)
            .Locator(selector)
            .FillAsync(value)
            .ConfigureAwait(false);

    public async Task PressAsync(int pageIndex, string selector, string key) =>
        await RequirePage(pageIndex)
            .Locator(selector)
            .PressAsync(key)
            .ConfigureAwait(false);

    public async Task SetInputFilesAsync(
        int pageIndex,
        string selector,
        IEnumerable<string> paths) =>
        await RequirePage(pageIndex)
            .Locator(selector)
            .SetInputFilesAsync(paths.Select(Path.GetFullPath).ToArray())
            .ConfigureAwait(false);

    public async Task GrantPermissionsAsync(
        IEnumerable<string> permissions,
        string? origin = null)
    {
        var context = RequireContext();
        await context.GrantPermissionsAsync(
            permissions.ToArray(),
            string.IsNullOrWhiteSpace(origin)
                ? null
                : new BrowserContextGrantPermissionsOptions { Origin = origin })
            .ConfigureAwait(false);
    }

    public async Task ClearPermissionsAsync() =>
        await RequireContext().ClearPermissionsAsync().ConfigureAwait(false);

    public async Task StartTracingAsync()
    {
        await RequireContext().Tracing.StartAsync(
            new TracingStartOptions
            {
                Screenshots = true,
                Snapshots = true,
                Sources = true,
                AriaSnapshots = true,
                ScreenSnapshots = true
            }).ConfigureAwait(false);
    }

    public async Task StopTracingAsync(string destination)
    {
        Directory.CreateDirectory(
            Path.GetDirectoryName(Path.GetFullPath(destination))
            ?? AppState.DirectoryPath);

        await RequireContext().Tracing.StopAsync(
            new TracingStopOptions { Path = destination })
            .ConfigureAwait(false);
    }

    public async Task<JsonElement> EvaluateAsync(
        int pageIndex,
        string expression,
        object? argument = null)
    {
        var value = await RequirePage(pageIndex)
            .EvaluateAsync<object?>(expression, argument)
            .ConfigureAwait(false);
        return JsonSerializer.SerializeToElement(value);
    }

    public async Task StopAsync()
    {
        if (_context is not null)
        {
            await _context.CloseAsync().ConfigureAwait(false);
            _context = null;
        }

        _playwright?.Dispose();
        _playwright = null;
    }

    public async ValueTask DisposeAsync() =>
        await StopAsync().ConfigureAwait(false);

    private IBrowserContext RequireContext() =>
        _context
        ?? throw new InvalidOperationException(
            "Browser host is not running. Start it first.");

    private IPage RequirePage(int index)
    {
        var context = RequireContext();
        if (index < 0 || index >= context.Pages.Count)
            throw new ArgumentOutOfRangeException(
                nameof(index),
                index,
                $"Browser page index must be between 0 and {Math.Max(0, context.Pages.Count - 1)}.");

        return context.Pages[index];
    }

    private static async Task<BrowserPageInfo> InfoAsync(int index, IPage page) =>
        new(
            index,
            page.Url,
            await page.TitleAsync().ConfigureAwait(false));

    private static string SafeProfileName(string value)
    {
        var cleaned = new string(value
            .Trim()
            .Select(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' ? ch : '-')
            .ToArray());

        return string.IsNullOrWhiteSpace(cleaned) ? "default" : cleaned;
    }
}
