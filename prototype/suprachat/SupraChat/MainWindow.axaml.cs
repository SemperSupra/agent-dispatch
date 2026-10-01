using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using SupraChat.Core;

namespace SupraChat;

public partial class MainWindow : Window
{
    private readonly SiwcClient _siwc = new();
    private readonly ResponsesClient _responses = new();
    private SiwcCredential? _credential;
    private Process? _codex;

    public MainWindow()
    {
        InitializeComponent();
    }

    private void Back_Click(object? sender, RoutedEventArgs e) => ChatView.GoBack();
    private void Forward_Click(object? sender, RoutedEventArgs e) => ChatView.GoForward();
    private void Reload_Click(object? sender, RoutedEventArgs e) => ChatView.Refresh();
    private void Home_Click(object? sender, RoutedEventArgs e) => ChatView.Navigate(new Uri("https://chatgpt.com/"));

    private void ChatView_EnvironmentRequested(object? sender, WebViewEnvironmentRequestedEventArgs e)
    {
        var webRoot = Path.Combine(AppState.DirectoryPath, "webview");
        Directory.CreateDirectory(webRoot);

        e.EnableDevTools = false;
        if (e is Avalonia.Platform.WindowsWebView2EnvironmentRequestedEventArgs windows)
        {
            windows.ProfileName = "SupraChat";
            windows.UserDataFolder = Path.Combine(webRoot, "windows");
            windows.IsInPrivateModeEnabled = false;
        }
        else if (e is Avalonia.Platform.AppleWKWebViewEnvironmentRequestedEventArgs apple)
        {
            apple.NonPersistentDataStore = false;
            apple.DataStoreIdentifier = new Guid("9f2d1f5f-11b7-4e6d-befa-8c69694254af");
            apple.ApplicationNameForUserAgent = "SupraChat";
        }
        else if (e is Avalonia.Platform.GtkWebViewEnvironmentRequestedEventArgs gtk)
        {
            gtk.EphemeralDataManager = false;
            gtk.BaseDataDirectory = Path.Combine(webRoot, "linux", "data");
            gtk.BaseCacheDirectory = Path.Combine(webRoot, "linux", "cache");
        }
    }

    private void OpenExternal_Click(object? sender, RoutedEventArgs e)
    {
        Process.Start(new ProcessStartInfo("https://chatgpt.com/") { UseShellExecute = true });
    }

    private async void SignIn_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            AuthStatus.Text = "Opening system browser for ChatGPT authorization…";
            var hostId = await HostIdentity.LoadOrCreateAsync();
            var existing = _credential ?? await CredentialStore.TryLoadAsync();
            _credential = await _siwc.SignInAsync(this, hostId, "SupraChat", existing);
            await CredentialStore.SaveAsync(_credential);
            AuthStatus.Text = $"Agent Lab authorized. Account subject: {Short(_credential.Subject)}; scope confirmed.";
            await PopulateModelsAsync();
        }
        catch (Exception ex)
        {
            AuthStatus.Text = $"Sign-in did not complete: {ex.Message}";
        }
    }

    private async void RefreshModels_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            await EnsureCredentialAsync();
            await PopulateModelsAsync();
        }
        catch (Exception ex)
        {
            AuthStatus.Text = ex.Message;
        }
    }

    private async Task PopulateModelsAsync()
    {
        if (_credential is null)
            return;

        var models = await _responses.ListModelsAsync(_credential.AccessToken);
        ModelBox.ItemsSource = models;
        ModelBox.SelectedItem ??= models.FirstOrDefault();
        AuthStatus.Text = $"Agent Lab authorized; {models.Count} model(s) visible to this ChatGPT-plan grant.";
    }

    private async void RunInterview_Click(object? sender, RoutedEventArgs e)
    {
        var timer = Stopwatch.StartNew();
        try
        {
            await EnsureCredentialAsync();
            if (ModelBox.SelectedItem is not ModelChoice model)
                throw new InvalidOperationException("Select a model first.");

            OutputBox.Text = "";
            var result = await _responses.StreamTextAsync(
                _credential!.AccessToken,
                model.Slug,
                PromptBox.Text ?? string.Empty,
                delta => OutputBox.Text += delta);

            timer.Stop();
            if (!result.Completed)
                throw new InvalidOperationException("The stream ended without response.completed.");

            var receiptPath = await QualificationReceipts.WriteDirectAsync(
                model.Slug,
                _credential,
                completed: true,
                timer.Elapsed,
                result.Text.Length);

            AuthStatus.Text = $"Interview completed with response.completed. Redacted receipt: {Path.GetFileName(receiptPath)}";
        }
        catch (Exception ex)
        {
            timer.Stop();
            AuthStatus.Text = $"Interview failed: {ex.Message}";
        }
    }

    private async void StartCodex_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            await EnsureCredentialAsync();
            if (_codex is { HasExited: false })
            {
                AuthStatus.Text = "Codex app-server is already running.";
                return;
            }

            _codex = CodexAppServer.Start(_credential!.AccessToken);
            AuthStatus.Text = $"Codex app-server started (PID {_codex.Id}); token is supplied only through process environment.";
        }
        catch (Exception ex)
        {
            AuthStatus.Text = $"Codex app-server start failed: {ex.Message}";
        }
    }

    private async Task EnsureCredentialAsync()
    {
        _credential ??= await CredentialStore.TryLoadAsync();
        if (_credential is null)
            throw new InvalidOperationException("Use Continue with ChatGPT first.");

        var refreshed = await _siwc.RefreshIfNeededAsync(_credential);
        if (!ReferenceEquals(refreshed, _credential))
        {
            _credential = refreshed;
            await CredentialStore.SaveAsync(_credential);

            if (_codex is { HasExited: false })
            {
                _codex.Kill(entireProcessTree: true);
                _codex = null;
            }
        }
    }

    private static string Short(string value) =>
        value.Length <= 12 ? value : value[..6] + "…" + value[^4..];

    protected override void OnClosed(EventArgs e)
    {
        if (_codex is { HasExited: false })
            _codex.Kill(entireProcessTree: true);
        base.OnClosed(e);
    }
}
