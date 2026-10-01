using Microsoft.Playwright;

namespace SupraChat.Core;

public sealed record BrowserRuntimeStatus(
    string Schema,
    string Platform,
    string BrowserDirectory,
    bool BrowserDirectoryPresent,
    string PlaywrightVersion,
    bool EphemeralByDefault,
    bool AccessibilitySnapshotSupported);

public sealed record BrowserPageSnapshot(
    string Schema,
    string Url,
    string Title,
    string AriaSnapshot,
    DateTimeOffset CapturedAt);

public sealed record BrowserScreenshotReceipt(
    string Schema,
    string Url,
    string OutputPath,
    long Bytes,
    bool FullPage,
    DateTimeOffset CapturedAt);

public sealed class BrowserSession : IAsyncDisposable
{
    public const string Schema = "suprachat-browser-session/v1";

    private readonly IPlaywright _playwright;
    private readonly IBrowser? _browser;
    private readonly IBrowserContext _context;

    private BrowserSession(
        IPlaywright playwright,
        IBrowser? browser,
        IBrowserContext context,
        IPage page)
    {
        _playwright = playwright;
        _browser = browser;
        _context = context;
        Page = page;
    }

    public IPage Page { get; }

    public static string BrowserDirectory =>
        Path.Combine(AppContext.BaseDirectory, "runtime", "browser");

    public static BrowserRuntimeStatus Status() => new(
        "suprachat-browser-runtime/v1",
        PlatformName(),
        BrowserDirectory,
        Directory.Exists(BrowserDirectory),
        typeof(IPlaywright).Assembly.GetName().Version?.ToString() ?? "unknown",
        EphemeralByDefault: true,
        AccessibilitySnapshotSupported: true);

    public static async Task<BrowserSession> StartAsync(
        bool headless = true,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (Directory.Exists(BrowserDirectory))
            Environment.SetEnvironmentVariable("PLAYWRIGHT_BROWSERS_PATH", BrowserDirectory);

        var playwright = await Playwright.CreateAsync();
        try
        {
            var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = headless
            });

            try
            {
                var context = await browser.NewContextAsync(new BrowserNewContextOptions
                {
                    AcceptDownloads = true
                });
                context.SetDefaultTimeout(15_000);

                var page = await context.NewPageAsync();
                return new BrowserSession(playwright, browser, context, page);
            }
            catch
            {
                await browser.DisposeAsync();
                throw;
            }
        }
        catch
        {
            playwright.Dispose();
            throw;
        }
    }

    public static async Task<BrowserSession> StartPersistentAsync(
        string profileDirectory,
        bool headless = false,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(profileDirectory))
            throw new ArgumentException("A browser profile directory is required.", nameof(profileDirectory));

        cancellationToken.ThrowIfCancellationRequested();
        Directory.CreateDirectory(profileDirectory);

        if (Directory.Exists(BrowserDirectory))
            Environment.SetEnvironmentVariable("PLAYWRIGHT_BROWSERS_PATH", BrowserDirectory);

        var playwright = await Playwright.CreateAsync();
        try
        {
            var context = await playwright.Chromium.LaunchPersistentContextAsync(
                profileDirectory,
                new BrowserTypeLaunchPersistentContextOptions
                {
                    Headless = headless,
                    AcceptDownloads = true
                });

            context.SetDefaultTimeout(15_000);
            var page = context.Pages.FirstOrDefault() ?? await context.NewPageAsync();
            return new BrowserSession(playwright, context.Browser, context, page);
        }
        catch
        {
            playwright.Dispose();
            throw;
        }
    }

    public async Task<BrowserPageSnapshot> NavigateAndSnapshotAsync(
        string url,
        CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed) ||
            parsed.Scheme is not ("http" or "https"))
            throw new ArgumentException("Browser navigation requires an absolute http or https URL.", nameof(url));

        cancellationToken.ThrowIfCancellationRequested();

        await Page.GotoAsync(parsed.AbsoluteUri, new PageGotoOptions
        {
            WaitUntil = WaitUntilState.DOMContentLoaded,
            Timeout = 30_000
        });

        return await SnapshotAsync(cancellationToken);
    }

    public async Task<BrowserPageSnapshot> SnapshotAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var title = await Page.TitleAsync();
        var aria = await Page.AriaSnapshotAsync(new PageAriaSnapshotOptions
        {
            Mode = AriaSnapshotMode.Ai,
            Depth = 10,
            Timeout = 15_000
        });

        return new BrowserPageSnapshot(
            Schema,
            Page.Url,
            title,
            aria,
            DateTimeOffset.UtcNow);
    }

    public async Task<BrowserPageSnapshot> ClickByRoleAsync(
        string role,
        string accessibleName,
        bool exact = true,
        CancellationToken cancellationToken = default)
    {
        if (!Enum.TryParse<AriaRole>(role, ignoreCase: true, out var ariaRole))
            throw new ArgumentException($"Unknown ARIA role: {role}", nameof(role));
        if (string.IsNullOrWhiteSpace(accessibleName))
            throw new ArgumentException("Accessible name is required.", nameof(accessibleName));

        cancellationToken.ThrowIfCancellationRequested();
        await Page.GetByRole(ariaRole, new PageGetByRoleOptions
        {
            Name = accessibleName,
            Exact = exact
        }).ClickAsync();

        return await SnapshotAsync(cancellationToken);
    }

    public async Task<BrowserPageSnapshot> FillByLabelAsync(
        string label,
        string value,
        bool exact = true,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(label))
            throw new ArgumentException("Accessible label is required.", nameof(label));

        cancellationToken.ThrowIfCancellationRequested();
        await Page.GetByLabel(label, new PageGetByLabelOptions
        {
            Exact = exact
        }).FillAsync(value);

        return await SnapshotAsync(cancellationToken);
    }

    public async Task<BrowserScreenshotReceipt> CaptureScreenshotAsync(
        string outputPath,
        bool fullPage = false,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(outputPath))
            throw new ArgumentException("A screenshot output path is required.", nameof(outputPath));

        cancellationToken.ThrowIfCancellationRequested();
        var fullPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath) ?? Directory.GetCurrentDirectory());

        await Page.ScreenshotAsync(new PageScreenshotOptions
        {
            Path = fullPath,
            FullPage = fullPage,
            Type = ScreenshotType.Png
        });

        var info = new FileInfo(fullPath);
        if (!info.Exists || info.Length == 0)
            throw new InvalidOperationException("Browser screenshot completed without a non-empty PNG.");

        return new BrowserScreenshotReceipt(
            "suprachat-browser-screenshot/v1",
            Page.Url,
            fullPath,
            info.Length,
            fullPage,
            DateTimeOffset.UtcNow);
    }

    public async Task<BrowserPageSnapshot> ClickAtAsync(
        float x,
        float y,
        string button = "left",
        int clickCount = 1,
        CancellationToken cancellationToken = default)
    {
        if (!float.IsFinite(x) || !float.IsFinite(y) || x < 0 || y < 0)
            throw new ArgumentOutOfRangeException(nameof(x), "Pointer coordinates must be finite and non-negative.");
        if (clickCount is < 1 or > 3)
            throw new ArgumentOutOfRangeException(nameof(clickCount), "Click count must be between 1 and 3.");
        if (!Enum.TryParse<MouseButton>(button, ignoreCase: true, out var mouseButton))
            throw new ArgumentException("Pointer button must be left, middle, or right.", nameof(button));

        cancellationToken.ThrowIfCancellationRequested();
        await Page.Mouse.ClickAsync(x, y, new MouseClickOptions
        {
            Button = mouseButton,
            ClickCount = clickCount
        });
        return await SnapshotAsync(cancellationToken);
    }

    public async Task<BrowserPageSnapshot> PressKeyAsync(
        string key,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(key))
            throw new ArgumentException("A Playwright key chord is required.", nameof(key));

        cancellationToken.ThrowIfCancellationRequested();
        await Page.Keyboard.PressAsync(key);
        return await SnapshotAsync(cancellationToken);
    }

    public async Task<BrowserPageSnapshot> TypeTextAsync(
        string text,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(text);

        cancellationToken.ThrowIfCancellationRequested();
        await Page.Keyboard.InsertTextAsync(text);
        return await SnapshotAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _context.DisposeAsync();
        }
        finally
        {
            try
            {
                if (_browser is { IsConnected: true })
                    await _browser.DisposeAsync();
            }
            finally
            {
                _playwright.Dispose();
            }
        }
    }

    private static string PlatformName() =>
        OperatingSystem.IsWindows() ? "windows" :
        OperatingSystem.IsMacOS() ? "macos" :
        OperatingSystem.IsLinux() ? "linux" :
        "unknown";
}
