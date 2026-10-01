using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using SupraChat.Core;

namespace SupraChat;

public partial class MainWindow : Window
{
    private readonly SiwcClient _siwc = new();
    private readonly ResponsesClient _responses = new();
    private readonly List<ResponseAttachment> _attachments = new();
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

    private async void SignIn_Click(object? sender, RoutedEventArgs e) =>
        await CompleteSignInAsync(promptConsent: false);

    private async void EnablePlanUsage_Click(object? sender, RoutedEventArgs e) =>
        await CompleteSignInAsync(promptConsent: true);

    private async Task CompleteSignInAsync(bool promptConsent)
    {
        try
        {
            AuthStatus.Text = promptConsent
                ? "Opening system browser to request ChatGPT-plan permission…"
                : "Opening system browser for ChatGPT authorization…";
            var hostId = await HostIdentity.LoadOrCreateAsync();
            var existing = _credential ?? await CredentialStore.TryLoadAsync();
            _credential = await _siwc.SignInAsync(this, hostId, "SupraChat", existing, promptConsent);
            await CredentialStore.SaveAsync(_credential);

            AuthStatus.Text = _credential.HasPlanUsage
                ? $"Agent Lab authorized. Account subject: {Short(_credential.Subject)}; ChatGPT-plan scope granted."
                : $"Identity sign-in completed for {Short(_credential.Subject)}, but ChatGPT-plan usage was not granted.";

            if (_credential.HasPlanUsage)
                await PopulateModelsAsync();
        }
        catch (Exception ex)
        {
            AuthStatus.Text = $"Sign-in did not complete: {ex.Message}";
        }
    }

    private async void SignOut_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            _credential ??= await CredentialStore.TryLoadAsync();
            if (_credential is null)
            {
                AuthStatus.Text = "No Agent Lab session is stored.";
                return;
            }

            StopCodex();
            var confirmed = await _siwc.RevokeAsync(_credential);
            CredentialStore.Clear();
            _credential = null;
            ModelBox.ItemsSource = null;
            AuthStatus.Text = confirmed
                ? "Agent Lab renewable session revoked and local tokens cleared."
                : "Remote revocation could not be confirmed after a temporary server failure; local tokens were cleared.";
        }
        catch (Exception ex)
        {
            StopCodex();
            CredentialStore.Clear();
            _credential = null;
            ModelBox.ItemsSource = null;
            AuthStatus.Text = $"Local tokens cleared; remote revocation failed: {ex.Message}";
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
        if (_credential is null || !_credential.HasPlanUsage)
            return;

        var models = await _responses.ListModelsAsync(_credential.AccessToken);
        ModelBox.ItemsSource = models;
        ModelBox.SelectedItem ??= models.FirstOrDefault();
        AuthStatus.Text = $"Agent Lab authorized; {models.Count} model(s) visible to this ChatGPT-plan grant.";
    }

    private async void Attach_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            var top = TopLevel.GetTopLevel(this)
                ?? throw new InvalidOperationException("No desktop storage provider is available.");
            var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Attach image or file to Agent Lab",
                AllowMultiple = true
            });

            long totalBytes = 0;
            foreach (var existing in _attachments)
                totalBytes += EstimateDataUrlBytes(existing.Value);

            foreach (var file in files)
            {
                await using var stream = await file.OpenReadAsync();
                using var memory = new MemoryStream();
                await stream.CopyToAsync(memory);
                var bytes = memory.ToArray();
                totalBytes += bytes.LongLength;
                if (totalBytes > 50L * 1024 * 1024)
                    throw new InvalidOperationException("SIWC file inputs are capped at 50 MB combined per request.");

                var mime = MimeTypeFor(file.Name);
                var kind = IsImageMime(mime) ? "image" : "file";
                _attachments.Add(new ResponseAttachment(
                    kind,
                    file.Name,
                    SiwcProtocol.ToDataUrl(mime, bytes),
                    "auto"));
            }

            RefreshAttachmentStatus();
        }
        catch (Exception ex)
        {
            AttachmentsStatus.Text = $"Attachment selection failed: {ex.Message}";
        }
    }

    private void ClearAttachments_Click(object? sender, RoutedEventArgs e)
    {
        _attachments.Clear();
        RefreshAttachmentStatus();
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
            var result = await _responses.StreamAsync(
                _credential!.AccessToken,
                model.Slug,
                PromptBox.Text ?? string.Empty,
                _attachments,
                WebSearchBox.IsChecked == true,
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

            AuthStatus.Text =
                $"Interview completed with response.completed. Events={result.EventTypes.Count}; " +
                $"request_id={result.RequestId ?? "unknown"}; redacted receipt={Path.GetFileName(receiptPath)}";
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
            StopCodex();
        }

        if (!_credential.HasPlanUsage)
            throw new InvalidOperationException("ChatGPT-plan usage is not granted. Use Enable plan usage.");
    }

    private void RefreshAttachmentStatus()
    {
        if (_attachments.Count == 0)
        {
            AttachmentsStatus.Text = "No Agent Lab attachments selected.";
            return;
        }

        var images = _attachments.Count(x => x.Kind == "image");
        var files = _attachments.Count - images;
        AttachmentsStatus.Text = $"{_attachments.Count} attachment(s): {images} image(s), {files} file(s).";
    }

    private void StopCodex()
    {
        if (_codex is { HasExited: false })
            _codex.Kill(entireProcessTree: true);
        _codex = null;
    }

    private static string MimeTypeFor(string name) => Path.GetExtension(name).ToLowerInvariant() switch
    {
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".webp" => "image/webp",
        ".gif" => "image/gif",
        ".pdf" => "application/pdf",
        ".txt" => "text/plain",
        ".md" => "text/markdown",
        ".json" => "application/json",
        ".csv" => "text/csv",
        ".html" or ".htm" => "text/html",
        ".xml" => "application/xml",
        ".doc" => "application/msword",
        ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".ppt" => "application/vnd.ms-powerpoint",
        ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".xls" => "application/vnd.ms-excel",
        ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream"
    };

    private static bool IsImageMime(string mime) =>
        mime is "image/png" or "image/jpeg" or "image/webp" or "image/gif";

    private static long EstimateDataUrlBytes(string value)
    {
        var comma = value.IndexOf(',');
        if (comma < 0)
            return 0;
        var base64Length = value.Length - comma - 1;
        return base64Length * 3L / 4L;
    }

    private static string Short(string value) =>
        value.Length <= 12 ? value : value[..6] + "…" + value[^4..];

    protected override void OnClosed(EventArgs e)
    {
        StopCodex();
        base.OnClosed(e);
    }
}
