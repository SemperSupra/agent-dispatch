using System.Diagnostics;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using SupraChat.Core;

namespace SupraChat;

public partial class MainWindow : Window
{
    private readonly SiwcClient _siwc = new();
    private readonly ResponsesClient _responses = new();
    private readonly List<ResponseAttachment> _attachments = new();
    private readonly Queue<CodexProtocolEvent> _pendingServerRequests = new();

    private SiwcCredential? _credential;
    private CodexAppServerClient? _codex;
    private CodexAppServerClient.CodexEventSubscription? _codexEvents;
    private CancellationTokenSource? _codexEventsCts;
    private Task? _codexMonitorTask;

    private ResponsesWebSocketClient? _responsesWebSocket;
    private CancellationTokenSource? _responsesWebSocketCts;
    private Task? _responsesWebSocketMonitorTask;
    private WindowsCompanionHotkey? _windowsCompanionHotkey;

    public MainWindow()
    {
        InitializeComponent();
        Opened += (_, _) => InitializeDesktopIntegration();
        _ = InitializeAgentLabAsync();
    }

    private void InitializeDesktopIntegration()
    {
        if (!OperatingSystem.IsWindows() || _windowsCompanionHotkey is not null)
            return;

        _windowsCompanionHotkey = new WindowsCompanionHotkey(this);
        var registered = _windowsCompanionHotkey.TryRegister();
        if (!registered)
            AuthStatus.Text = $"Windows companion shortcut {WindowsCompanionHotkey.ShortcutDescription} is unavailable; another application may own it.";
    }

    private async Task InitializeAgentLabAsync()
    {
        try
        {
            _credential = await CredentialStore.TryLoadAsync();
            await RefreshRegistrationsAsync(_credential?.ClientId);
            if (_credential is not null)
            {
                AuthStatus.Text = _credential.HasPlanUsage
                    ? $"Saved Agent Lab session loaded for {Short(_credential.Subject)}; ChatGPT-plan scope granted."
                    : $"Saved identity session loaded for {Short(_credential.Subject)}; plan usage is not granted.";
            }
        }
        catch (Exception ex)
        {
            AuthStatus.Text = $"Saved Agent Lab state could not be loaded: {ex.Message}";
        }
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

    private async void UseSavedAccount_Click(object? sender, RoutedEventArgs e)
    {
        if (AccountBox.SelectedItem is not SiwcRegistration)
        {
            AuthStatus.Text = "Choose a saved ChatGPT account registration first.";
            return;
        }

        await CompleteSignInAsync(promptConsent: false);
    }

    private async void AddAccount_Click(object? sender, RoutedEventArgs e) =>
        await CompleteSignInAsync(promptConsent: false, forceNewRegistration: true);

    private async void EnablePlanUsage_Click(object? sender, RoutedEventArgs e) =>
        await CompleteSignInAsync(promptConsent: true);

    private async Task CompleteSignInAsync(bool promptConsent, bool forceNewRegistration = false)
    {
        try
        {
            AuthStatus.Text = promptConsent
                ? "Opening system browser to request ChatGPT-plan permission…"
                : "Opening system browser for ChatGPT authorization…";

            var hostId = await HostIdentity.LoadOrCreateAsync();
            var active = _credential ?? await CredentialStore.TryLoadAsync();
            var selected = AccountBox.SelectedItem as SiwcRegistration;

            SiwcCredential? existing = active;
            SiwcRegistration? registration = null;

            if (forceNewRegistration)
            {
                existing = null;
            }
            else if (selected is not null &&
                     !string.Equals(active?.ClientId, selected.ClientId, StringComparison.Ordinal))
            {
                existing = null;
                registration = selected;
            }

            var priorToken = _credential?.AccessToken;
            var priorClientId = _credential?.ClientId;

            _credential = await _siwc.SignInAsync(
                this,
                hostId,
                "SupraChat",
                existing,
                promptConsent,
                registration);
            await CredentialStore.SaveAsync(_credential);
            await RefreshRegistrationsAsync(_credential.ClientId);

            if (!string.Equals(priorToken, _credential.AccessToken, StringComparison.Ordinal) ||
                !string.Equals(priorClientId, _credential.ClientId, StringComparison.Ordinal))
            {
                await StopCodexAsync();
                await StopResponsesWebSocketAsync();
            }

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

            await StopCodexAsync();
            await StopResponsesWebSocketAsync();
            var confirmed = await _siwc.RevokeAsync(_credential);
            CredentialStore.Clear();
            _credential = null;
            ModelBox.ItemsSource = null;
            await RefreshRegistrationsAsync();
            AuthStatus.Text = confirmed
                ? "Agent Lab renewable session revoked and local tokens cleared; the account registration remains available for reauthorization."
                : "Remote revocation could not be confirmed after a temporary server failure; local tokens were cleared and the account registration was retained.";
        }
        catch (Exception ex)
        {
            await StopCodexAsync();
            await StopResponsesWebSocketAsync();
            CredentialStore.Clear();
            _credential = null;
            ModelBox.ItemsSource = null;
            await RefreshRegistrationsAsync();
            AuthStatus.Text = $"Local tokens cleared and account registration retained; remote revocation failed: {ex.Message}";
        }
    }

    private async Task RefreshRegistrationsAsync(string? selectClientId = null)
    {
        var registrations = await CredentialStore.ListRegistrationsAsync();
        AccountBox.ItemsSource = registrations;

        var targetClientId = selectClientId ?? _credential?.ClientId;
        if (!string.IsNullOrWhiteSpace(targetClientId))
        {
            AccountBox.SelectedItem = registrations.FirstOrDefault(x =>
                string.Equals(x.ClientId, targetClientId, StringComparison.Ordinal));
        }
        else
        {
            AccountBox.SelectedItem = null;
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

            long totalBytes = _attachments.Sum(existing => EstimateDataUrlBytes(existing.Value));

            foreach (var file in files)
            {
                await using var stream = await file.OpenReadAsync();
                using var memory = new MemoryStream();
                await stream.CopyToAsync(memory);
                var bytes = memory.ToArray();
                totalBytes += bytes.LongLength;

                // This is the upstream Responses file-input limit, not an application policy.
                if (bytes.LongLength >= 50L * 1024 * 1024 || totalBytes > 50L * 1024 * 1024)
                    throw new InvalidOperationException(
                        "Responses file inputs require each file to be under 50 MB and all files combined to be at most 50 MB.");

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
                delta => Dispatcher.UIThread.Post(() => OutputBox.Text += delta));

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
                $"Direct interview completed. Events={result.EventTypes.Count}; " +
                $"request_id={result.RequestId ?? "unknown"}; redacted receipt={Path.GetFileName(receiptPath)}";
        }
        catch (Exception ex)
        {
            timer.Stop();
            AuthStatus.Text = $"Direct interview failed: {ex.Message}";
        }
    }

    private async void SendRawResponses_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            await EnsureCredentialAsync();
            if (ModelBox.SelectedItem is not ModelChoice model)
                throw new InvalidOperationException("Select a model first.");

            RawResponsesEventsBox.Text = "";
            var result = await _responses.StreamRawAsync(
                _credential!.AccessToken,
                model.Slug,
                RawResponsesBodyBox.Text ?? "{}",
                onDelta: null,
                onEvent: (type, payload) => Dispatcher.UIThread.Post(() =>
                    AppendRawResponseEvent(type, payload)));

            AuthStatus.Text =
                $"Raw Responses request completed={result.Completed}; events={result.EventTypes.Count}; " +
                $"request_id={result.RequestId ?? "unknown"}.";
        }
        catch (Exception ex)
        {
            AppendRawResponseEvent("ERROR", ex.ToString());
            AuthStatus.Text = $"Raw Responses request failed: {ex.Message}";
        }
    }

    private async void ConnectResponsesWebSocket_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            await EnsureCredentialAsync();
            await StopResponsesWebSocketAsync();

            _responsesWebSocket = await ResponsesWebSocketClient.ConnectAsync(_credential!.AccessToken);
            _responsesWebSocketCts = new CancellationTokenSource();
            var socket = _responsesWebSocket;
            var cancellationToken = _responsesWebSocketCts.Token;
            _responsesWebSocketMonitorTask = Task.Run(
                () => MonitorResponsesWebSocketAsync(socket, cancellationToken),
                cancellationToken);

            AuthStatus.Text = "Responses WebSocket connected to the authenticated plan-sharing endpoint.";
        }
        catch (Exception ex)
        {
            AuthStatus.Text = $"Responses WebSocket connect failed: {ex.Message}";
        }
    }

    private async void DisconnectResponsesWebSocket_Click(object? sender, RoutedEventArgs e)
    {
        await StopResponsesWebSocketAsync();
        AuthStatus.Text = "Responses WebSocket disconnected.";
    }

    private async void SendResponsesWebSocketEvent_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            await EnsureCredentialAsync();
            if (ModelBox.SelectedItem is not ModelChoice model)
                throw new InvalidOperationException("Select a model first.");

            if (_responsesWebSocket is not { IsConnected: true })
            {
                _responsesWebSocket = await ResponsesWebSocketClient.ConnectAsync(_credential!.AccessToken);
                _responsesWebSocketCts = new CancellationTokenSource();
                var socket = _responsesWebSocket;
                var cancellationToken = _responsesWebSocketCts.Token;
                _responsesWebSocketMonitorTask = Task.Run(
                    () => MonitorResponsesWebSocketAsync(socket, cancellationToken),
                    cancellationToken);
            }

            await _responsesWebSocket.SendRawAsync(
                ResponsesWebSocketEventBox.Text ?? "{}",
                model.Slug);
            AuthStatus.Text = "Responses WebSocket event sent.";
        }
        catch (Exception ex)
        {
            AppendResponsesWebSocketEvent($"SEND ERROR {ex}");
            AuthStatus.Text = $"Responses WebSocket send failed: {ex.Message}";
        }
    }

    private async Task MonitorResponsesWebSocketAsync(
        ResponsesWebSocketClient socket,
        CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var raw in socket.ReadEventsAsync(cancellationToken))
            {
                Dispatcher.UIThread.Post(() => AppendResponsesWebSocketEvent(raw));
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() =>
                AppendResponsesWebSocketEvent($"MONITOR ERROR {ex}"));
        }
    }

    private async void StartCodex_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            var client = await EnsureCodexAsync();
            AuthStatus.Text =
                $"Codex app-server initialized (PID {client.ProcessId}); full protocol monitor is active.";
        }
        catch (Exception ex)
        {
            AuthStatus.Text = $"Codex app-server start failed: {ex.Message}";
        }
    }

    private async void RunCodexInterview_Click(object? sender, RoutedEventArgs e)
    {
        var timer = Stopwatch.StartNew();
        try
        {
            await EnsureCredentialAsync();
            if (ModelBox.SelectedItem is not ModelChoice model)
                throw new InvalidOperationException("Select a model first.");

            var client = await EnsureCodexAsync();
            OutputBox.Text = "";

            var result = await client.RunTextInterviewAsync(
                model.Slug,
                PromptBox.Text ?? string.Empty,
                delta => Dispatcher.UIThread.Post(() => OutputBox.Text += delta));

            timer.Stop();
            if (!result.Completed)
                throw new InvalidOperationException($"Codex turn completed with status {result.Status}.");

            var receiptPath = await QualificationReceipts.WriteCodexAsync(
                result.Model,
                _credential!,
                completed: true,
                timer.Elapsed,
                result.Text.Length);

            AuthStatus.Text =
                $"Codex interview completed. provider={result.ModelProvider}; thread={Short(result.ThreadId)}; " +
                $"turn={Short(result.TurnId)}; redacted receipt={Path.GetFileName(receiptPath)}";
        }
        catch (Exception ex)
        {
            timer.Stop();
            AuthStatus.Text = $"Codex interview failed: {ex.Message}";
        }
    }

    private async void SendRawRpc_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            var method = RawRpcMethodBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(method))
                throw new InvalidOperationException("Enter a Codex app-server method.");

            var client = await EnsureCodexAsync();
            var parameters = ParseOptionalJson(RawRpcParamsBox.Text);
            var result = await client.RequestAsync(method, parameters);
            RawRpcOutputBox.Text = PrettyJson(result);
            AuthStatus.Text = $"Codex RPC completed: {method}";
        }
        catch (Exception ex)
        {
            RawRpcOutputBox.Text = ex.ToString();
            AuthStatus.Text = $"Codex RPC failed: {ex.Message}";
        }
    }

    private async void RespondServerRequest_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (_pendingServerRequests.Count == 0)
                throw new InvalidOperationException("No Codex server request is pending.");

            var request = _pendingServerRequests.Peek();
            if (request.Id is null)
                throw new InvalidOperationException("Pending server request has no id.");

            var result = ParseOptionalJson(ServerResponseBox.Text)
                ?? JsonSerializer.SerializeToElement(new { });

            var client = await EnsureCodexAsync();
            await client.RespondAsync(request.Id, result);
            _pendingServerRequests.Dequeue();
            ShowNextServerRequest();
            AppendProtocolEvent($"responded id={request.Id} method={request.Method}");
        }
        catch (Exception ex)
        {
            AuthStatus.Text = $"Server-request response failed: {ex.Message}";
        }
    }

    private async void RejectServerRequest_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (_pendingServerRequests.Count == 0)
                throw new InvalidOperationException("No Codex server request is pending.");

            var request = _pendingServerRequests.Peek();
            if (request.Id is null)
                throw new InvalidOperationException("Pending server request has no id.");

            var client = await EnsureCodexAsync();
            await client.RespondErrorAsync(request.Id, -32000, "Rejected by SupraChat user.");
            _pendingServerRequests.Dequeue();
            ShowNextServerRequest();
            AppendProtocolEvent($"rejected id={request.Id} method={request.Method}");
        }
        catch (Exception ex)
        {
            AuthStatus.Text = $"Server-request rejection failed: {ex.Message}";
        }
    }

    private async Task EnsureCredentialAsync()
    {
        _credential ??= await CredentialStore.TryLoadAsync();
        if (_credential is null)
            throw new InvalidOperationException("Use Continue with ChatGPT first.");

        var priorToken = _credential.AccessToken;
        var refreshed = await _siwc.RefreshIfNeededAsync(_credential);
        if (!ReferenceEquals(refreshed, _credential))
        {
            _credential = refreshed;
            await CredentialStore.SaveAsync(_credential);
            if (!string.Equals(priorToken, refreshed.AccessToken, StringComparison.Ordinal))
            {
                await StopCodexAsync();
                await StopResponsesWebSocketAsync();
            }
        }

        if (!_credential.HasPlanUsage)
            throw new InvalidOperationException("ChatGPT-plan usage is not granted. Use Enable plan usage.");
    }

    private async Task<CodexAppServerClient> EnsureCodexAsync()
    {
        await EnsureCredentialAsync();

        if (_codex is { IsRunning: true })
            return _codex;

        await StopCodexAsync();
        _codex = await CodexAppServerClient.StartAsync(_credential!.AccessToken);

        _codexEventsCts = new CancellationTokenSource();
        _codexEvents = _codex.SubscribeEvents();
        _codexMonitorTask = MonitorCodexAsync(_codexEvents, _codexEventsCts.Token);

        return _codex;
    }

    private async Task MonitorCodexAsync(
        CodexAppServerClient.CodexEventSubscription subscription,
        CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var evt in subscription.Reader.ReadAllAsync(cancellationToken))
            {
                Dispatcher.UIThread.Post(() =>
                {
                    var prefix = evt.Kind == "server-request"
                        ? $"SERVER REQUEST id={evt.Id} method={evt.Method}"
                        : $"EVENT {evt.Method}";
                    AppendProtocolEvent($"{prefix} {CompactJson(evt.Payload)}");

                    if (evt.Kind == "server-request")
                    {
                        _pendingServerRequests.Enqueue(evt);
                        ShowNextServerRequest();
                    }
                });
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() =>
                AppendProtocolEvent($"protocol monitor stopped: {ex.Message}"));
        }
    }

    private void ShowNextServerRequest()
    {
        if (_pendingServerRequests.Count == 0)
        {
            PendingServerRequestBox.Text = "";
            return;
        }

        var evt = _pendingServerRequests.Peek();
        PendingServerRequestBox.Text =
            $"id={evt.Id}{Environment.NewLine}method={evt.Method}{Environment.NewLine}{PrettyJson(evt.Payload)}";
    }

    private void AppendResponsesWebSocketEvent(string raw)
    {
        var compact = raw.Replace("\r", " ").Replace("\n", " ");
        if (compact.Length > 6000)
            compact = compact[..6000] + "…";

        var current = ResponsesWebSocketEventsBox.Text ?? "";
        var next = current + DateTimeOffset.Now.ToString("HH:mm:ss.fff") +
            " " + compact + Environment.NewLine;
        ResponsesWebSocketEventsBox.Text = next.Length <= 80000 ? next : next[^80000..];
    }

    private async Task StopResponsesWebSocketAsync()
    {
        var monitor = _responsesWebSocketMonitorTask;
        _responsesWebSocketMonitorTask = null;

        _responsesWebSocketCts?.Cancel();
        _responsesWebSocketCts?.Dispose();
        _responsesWebSocketCts = null;

        if (_responsesWebSocket is not null)
        {
            await _responsesWebSocket.DisposeAsync();
            _responsesWebSocket = null;
        }

        if (monitor is not null)
        {
            try
            {
                await monitor;
            }
            catch
            {
            }
        }
    }

    private void AppendRawResponseEvent(string type, string payload)
    {
        var compact = payload.Replace("\r", " ").Replace("\n", " ");
        if (compact.Length > 3000)
            compact = compact[..3000] + "…";

        var current = RawResponsesEventsBox.Text ?? "";
        var next = current + DateTimeOffset.Now.ToString("HH:mm:ss.fff") +
            " " + type + " " + compact + Environment.NewLine;
        RawResponsesEventsBox.Text = next.Length <= 60000 ? next : next[^60000..];
    }

    private void AppendProtocolEvent(string line)
    {
        var current = ProtocolEventsBox.Text ?? "";
        var next = current + DateTimeOffset.Now.ToString("HH:mm:ss.fff") + " " + line + Environment.NewLine;
        ProtocolEventsBox.Text = next.Length <= 60000 ? next : next[^60000..];
    }

    private async Task StopCodexAsync()
    {
        var monitor = _codexMonitorTask;
        _codexMonitorTask = null;

        _codexEventsCts?.Cancel();
        _codexEventsCts?.Dispose();
        _codexEventsCts = null;

        if (_codexEvents is not null)
        {
            await _codexEvents.DisposeAsync();
            _codexEvents = null;
        }

        if (_codex is not null)
        {
            await _codex.DisposeAsync();
            _codex = null;
        }

        if (monitor is not null)
        {
            try
            {
                await monitor;
            }
            catch
            {
            }
        }

        _pendingServerRequests.Clear();
        ShowNextServerRequest();
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

    private static JsonElement? ParseOptionalJson(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        using var document = JsonDocument.Parse(text);
        return document.RootElement.Clone();
    }

    private static string PrettyJson(JsonElement element) =>
        JsonSerializer.Serialize(element, new JsonSerializerOptions { WriteIndented = true });

    private static string CompactJson(JsonElement element)
    {
        var text = element.GetRawText().Replace("\r", " ").Replace("\n", " ");
        return text.Length <= 2000 ? text : text[..2000] + "…";
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
        ".tsv" => "text/tab-separated-values",
        ".html" or ".htm" => "text/html",
        ".xml" => "application/xml",
        ".rtf" => "application/rtf",
        ".odt" => "application/vnd.oasis.opendocument.text",
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
        try
        {
            _windowsCompanionHotkey?.Dispose();
            _windowsCompanionHotkey = null;
            StopCodexAsync().GetAwaiter().GetResult();
            StopResponsesWebSocketAsync().GetAwaiter().GetResult();
        }
        catch
        {
        }

        base.OnClosed(e);
    }
}
