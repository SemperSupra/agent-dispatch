using System.Diagnostics;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Input;
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
    private BrowserSession? _browserSession;
    private AccessibilityPreferences _accessibilityPreferences = AccessibilityPreferences.Default;

    public MainWindow()
    {
        InitializeComponent();
        LoadCapabilityCatalog();
        Opened += async (_, _) =>
        {
            InitializeDesktopIntegration();
            await LoadAccessibilityPreferencesAsync();
            RefreshAccessibilityStatus();
            await RefreshMachineSurfaceAsync();
        };
        ScalingChanged += (_, _) => RefreshAccessibilityStatus();
        _ = InitializeAgentLabAsync();
    }

    private void MainWindow_KeyDown(object? sender, KeyEventArgs e)
    {
        var primaryModifier = OperatingSystem.IsMacOS()
            ? KeyModifiers.Meta
            : KeyModifiers.Control;

        if ((e.KeyModifiers & primaryModifier) != primaryModifier)
            return;

        switch (e.Key)
        {
            case Key.D1:
                RootTabs.SelectedIndex = 0;
                ChatView.Focus();
                e.Handled = true;
                break;
            case Key.D2:
                RootTabs.SelectedIndex = 1;
                PromptBox.Focus();
                e.Handled = true;
                break;
            case Key.D3:
                RootTabs.SelectedIndex = 2;
                e.Handled = true;
                break;
            case Key.L:
                RootTabs.SelectedIndex = 1;
                PromptBox.Focus();
                e.Handled = true;
                break;
            case Key.OemPlus:
            case Key.Add:
                _ = ChangeAccessibilityScaleAsync(AccessibilityPreferencesStore.ScaleStep);
                e.Handled = true;
                break;
            case Key.OemMinus:
            case Key.Subtract:
                _ = ChangeAccessibilityScaleAsync(-AccessibilityPreferencesStore.ScaleStep);
                e.Handled = true;
                break;
            case Key.D0:
            case Key.NumPad0:
                _ = SaveAccessibilityPreferencesAsync(1.0, _accessibilityPreferences.ReducedMotion);
                e.Handled = true;
                break;
        }
    }

    private async Task LoadAccessibilityPreferencesAsync()
    {
        _accessibilityPreferences = await AccessibilityPreferencesStore.LoadAsync();
        ApplyAccessibilityPreferences();
    }

    private async Task SaveAccessibilityPreferencesAsync(double scale, bool reducedMotion)
    {
        _accessibilityPreferences = await AccessibilityPreferencesStore.SaveAsync(scale, reducedMotion);
        ApplyAccessibilityPreferences();
    }

    private void ApplyAccessibilityPreferences()
    {
        FontSize = 14 * _accessibilityPreferences.InterfaceScale;
        ReducedMotionBox.IsChecked = _accessibilityPreferences.ReducedMotion;
        AccessibilityPreferencesStatus.Text =
            $"Interface scale {_accessibilityPreferences.InterfaceScale * 100:0}% · " +
            $"reduced motion {(_accessibilityPreferences.ReducedMotion ? "on" : "off")} · " +
            $"keyboard {AccessibilityContract.PrimaryModifierName}++/-/0";
        RefreshAccessibilityStatus();
    }

    private async Task ChangeAccessibilityScaleAsync(double delta) =>
        await SaveAccessibilityPreferencesAsync(
            _accessibilityPreferences.InterfaceScale + delta,
            _accessibilityPreferences.ReducedMotion);

    private async void AccessibilityScaleDown_Click(object? sender, RoutedEventArgs e) =>
        await ChangeAccessibilityScaleAsync(-AccessibilityPreferencesStore.ScaleStep);

    private async void AccessibilityScaleReset_Click(object? sender, RoutedEventArgs e) =>
        await SaveAccessibilityPreferencesAsync(1.0, _accessibilityPreferences.ReducedMotion);

    private async void AccessibilityScaleUp_Click(object? sender, RoutedEventArgs e) =>
        await ChangeAccessibilityScaleAsync(AccessibilityPreferencesStore.ScaleStep);

    private async void ReducedMotionBox_Click(object? sender, RoutedEventArgs e) =>
        await SaveAccessibilityPreferencesAsync(
            _accessibilityPreferences.InterfaceScale,
            ReducedMotionBox.IsChecked == true);

    private void InitializeDesktopIntegration()
    {
        if (!OperatingSystem.IsWindows() || _windowsCompanionHotkey is not null)
            return;

        _windowsCompanionHotkey = new WindowsCompanionHotkey(this);
        var registered = _windowsCompanionHotkey.TryRegister();
        if (!registered)
            AuthStatus.Text = $"Windows companion shortcut {WindowsCompanionHotkey.ShortcutDescription} is unavailable; another application may own it.";
    }

    private async void RefreshMachineSurface_Click(object? sender, RoutedEventArgs e) =>
        await RefreshMachineSurfaceAsync();

    private void RefreshAccessibilityStatus()
    {
        var accessibility = AccessibilityContract.Describe();
        AccessibilityStatus.Text =
            $"screen-reader-semantics={(accessibility.Human.ScreenReaderSemantics ? "ready" : "unavailable")} · " +
            $"keyboard={(accessibility.Human.KeyboardOnly ? "ready" : "unavailable")} · " +
            $"system-theme/high-contrast={(accessibility.Human.HighContrastFollowsPlatform ? "follow-platform" : "custom")} · " +
            $"render-scale={RenderScaling:0.##} · interface-scale={_accessibilityPreferences.InterfaceScale:0.0} · " +
            $"reduced-motion={(_accessibilityPreferences.ReducedMotion ? "on" : "off")} · " +
            $"shortcuts={string.Join(",", accessibility.Human.Shortcuts)}";
    }

    private async Task RefreshMachineSurfaceAsync()
    {
        var credential = await CredentialStore.TryLoadAsync();
        var automationName = OperatingSystem.IsWindows()
            ? "SupraChat.Automation.exe"
            : "SupraChat.Automation";
        var automationPath = Path.Combine(AppContext.BaseDirectory, automationName);
        var codexPath = CodexAppServer.ResolveExecutable();
        var screenCapture = DesktopScreenCapture.Describe();

        MachineExecutablePathBox.Text = automationPath;
        MachineStatus.Text =
            $"platform={PlatformLabel()} · " +
            $"automation={(File.Exists(automationPath) ? "ready" : "not-packaged")} · " +
            $"agent-stdio={(File.Exists(automationPath) ? "ready" : "not-packaged")} · " +
            $"codex={(Path.IsPathRooted(codexPath) && File.Exists(codexPath) ? "bundled" : "PATH-fallback")} · " +
            $"screen-capture={(screenCapture.Implemented ? screenCapture.Adapter : "unavailable")} · " +
            $"authorization={(credential is null ? "required" : credential.HasPlanUsage ? "plan-ready" : "identity-only")}";

        RefreshAudienceParityStatus();
    }

    private void RefreshAudienceParityStatus()
    {
        var parityPath = Path.Combine(
            AppContext.BaseDirectory,
            "oracles",
            "audience-parity-20261001.json");
        AudienceParityPathBox.Text = parityPath;

        if (!File.Exists(parityPath))
        {
            AudienceParityStatus.Text = "Audience parity ledger is not packaged.";
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(parityPath));
            var features = document.RootElement.GetProperty("features");
            var platform = PlatformLabel();
            var total = 0;
            var gaps = 0;
            var qualifying = 0;

            foreach (var feature in features.EnumerateArray())
            {
                total++;
                var hasGap = false;
                var hasQualify = false;

                if (feature.TryGetProperty("access", out var access))
                {
                    foreach (var state in access.EnumerateObject())
                    {
                        hasGap |= string.Equals(state.Value.GetString(), "gap", StringComparison.Ordinal);
                        hasQualify |= string.Equals(state.Value.GetString(), "qualify", StringComparison.Ordinal);
                    }
                }

                if (feature.TryGetProperty("platforms", out var platforms) &&
                    platforms.TryGetProperty(platform, out var platformState))
                {
                    hasGap |= string.Equals(platformState.GetString(), "gap", StringComparison.Ordinal);
                    hasQualify |= string.Equals(platformState.GetString(), "qualify", StringComparison.Ordinal);
                }

                if (hasGap)
                    gaps++;
                else if (hasQualify)
                    qualifying++;
            }

            var explicitWithoutGap = total - gaps - qualifying;
            AudienceParityStatus.Text =
                $"{total} capability families · {explicitWithoutGap} explicit/no-gap · " +
                $"{qualifying} qualifying · {gaps} gaps · platform={platform}. " +
                "Use suprachat-cli parity or parity/read for the complete semantic ledger.";
        }
        catch (Exception ex)
        {
            AudienceParityStatus.Text = $"Audience parity ledger could not be read: {ex.Message}";
        }
    }

    private void OpenStateFolder_Click(object? sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(AppState.DirectoryPath);

        var start = OperatingSystem.IsWindows()
            ? new ProcessStartInfo("explorer.exe", $"\"{AppState.DirectoryPath}\"") { UseShellExecute = true }
            : OperatingSystem.IsMacOS()
                ? new ProcessStartInfo("open", AppState.DirectoryPath) { UseShellExecute = false }
                : new ProcessStartInfo("xdg-open", AppState.DirectoryPath) { UseShellExecute = false };

        Process.Start(start);
    }

    private static string PlatformLabel() =>
        OperatingSystem.IsWindows() ? "windows" :
        OperatingSystem.IsMacOS() ? "macos" :
        OperatingSystem.IsLinux() ? "linux" :
        "unknown";

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

                AddAttachmentBytes(file.Name, bytes);
            }

            RefreshAttachmentStatus();
        }
        catch (Exception ex)
        {
            AttachmentsStatus.Text = $"Attachment selection failed: {ex.Message}";
        }
    }

    private async void CaptureScreen_Click(object? sender, RoutedEventArgs e)
    {
        var descriptor = DesktopScreenCapture.Describe();
        if (!descriptor.Implemented)
        {
            AttachmentsStatus.Text =
                $"Screen capture is unavailable on this host. Adapter={descriptor.Adapter}; {descriptor.PermissionBoundary}";
            return;
        }

        var tempPath = Path.Combine(
            Path.GetTempPath(),
            $"suprachat-screen-{Guid.NewGuid():N}.png");

        try
        {
            AttachmentsStatus.Text =
                $"Capturing screen via {descriptor.Adapter}. {descriptor.PermissionBoundary}";
            var capturedPath = await DesktopScreenCapture.CaptureAsync(tempPath);
            var bytes = await File.ReadAllBytesAsync(capturedPath);
            AddAttachmentBytes("screen-capture.png", bytes);
            RefreshAttachmentStatus();
            AttachmentsStatus.Text += $" Screen captured via {descriptor.Adapter}.";
        }
        catch (Exception ex)
        {
            AttachmentsStatus.Text =
                $"Screen capture failed via {descriptor.Adapter}: {ex.Message}";
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
            catch
            {
            }
        }
    }

    private void ClearAttachments_Click(object? sender, RoutedEventArgs e)
    {
        _attachments.Clear();
        RefreshAttachmentStatus();
    }

    public async Task HandleStartupArgumentsAsync(IEnumerable<string> args)
    {
        var imported = 0;
        foreach (var raw in args.Where(value => !string.IsNullOrWhiteSpace(value)))
        {
            if (File.Exists(raw))
            {
                var bytes = await File.ReadAllBytesAsync(raw);
                AddAttachmentBytes(Path.GetFileName(raw), bytes);
                imported++;
                RootTabs.SelectedIndex = 1;
                continue;
            }

            if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) ||
                !string.Equals(uri.Scheme, "suprachat", StringComparison.OrdinalIgnoreCase))
                continue;

            var text = QueryValue(uri, "text");
            if (!string.IsNullOrWhiteSpace(text))
            {
                PromptBox.Text = text;
                RootTabs.SelectedIndex = 1;
            }
        }

        if (imported > 0)
        {
            RefreshAttachmentStatus();
            AuthStatus.Text = $"Imported {imported} file(s) from the desktop launch request.";
        }
    }

    private void AddAttachmentBytes(string name, byte[] bytes)
    {
        var totalBytes = _attachments.Sum(existing => EstimateDataUrlBytes(existing.Value)) + bytes.LongLength;
        if (bytes.LongLength >= 50L * 1024 * 1024 || totalBytes > 50L * 1024 * 1024)
            throw new InvalidOperationException(
                "Responses file inputs require each file to be under 50 MB and all files combined to be at most 50 MB.");

        var mime = MimeTypeFor(name);
        var kind = IsImageMime(mime) ? "image" : "file";
        _attachments.Add(new ResponseAttachment(
            kind,
            name,
            SiwcProtocol.ToDataUrl(mime, bytes),
            "auto"));
    }

    private static string? QueryValue(Uri uri, string key)
    {
        foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pieces = part.Split('=', 2);
            var candidate = Uri.UnescapeDataString(pieces[0].Replace("+", " "));
            if (!string.Equals(candidate, key, StringComparison.OrdinalIgnoreCase))
                continue;

            return pieces.Length == 2
                ? Uri.UnescapeDataString(pieces[1].Replace("+", " "))
                : string.Empty;
        }

        return null;
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

            if (OperatingSystem.IsWindows() && !IsActive)
                DesktopNotificationService.TryNotify(this, "SupraChat", "Direct response completed.");
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

            if (OperatingSystem.IsWindows() && !IsActive)
                DesktopNotificationService.TryNotify(this, "SupraChat", "Codex response completed.");
        }
        catch (Exception ex)
        {
            timer.Stop();
            AuthStatus.Text = $"Codex interview failed: {ex.Message}";
        }
    }

    private sealed record CodexCatalogChoice(string Name, string Kind, string State)
    {
        public override string ToString() => $"[{State} · {Kind}] {Name}";
    }

    private void RefreshCapabilityCatalog_Click(object? sender, RoutedEventArgs e) =>
        LoadCapabilityCatalog();

    private void LoadCapabilityCatalog()
    {
        try
        {
            var path = Path.Combine(
                AppContext.BaseDirectory,
                "oracles",
                "codex-capability-catalog-20261001.json");
            if (!File.Exists(path))
            {
                CapabilityCatalogStatus.Text = "Packaged Codex capability catalog is unavailable.";
                CodexMethodBox.ItemsSource = null;
                return;
            }

            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            var packaged = root.GetProperty("packaged_runtime");
            var frontier = root.GetProperty("upstream_frontier");
            var stableNames = new HashSet<string>(StringComparer.Ordinal);

            foreach (var category in new[] { "client_requests", "server_requests", "server_notifications" })
            {
                foreach (var item in packaged.GetProperty(category).EnumerateArray())
                {
                    if (item.GetString() is { Length: > 0 } name)
                        stableNames.Add(name);
                }
            }

            var choices = new List<CodexCatalogChoice>();
            var allKnown = frontier.GetProperty("all_known");
            AddCatalogChoices(choices, allKnown.GetProperty("client_requests"), "client-request", stableNames);
            AddCatalogChoices(choices, allKnown.GetProperty("server_requests"), "server-request", stableNames);
            AddCatalogChoices(choices, allKnown.GetProperty("server_notifications"), "notification", stableNames);

            CodexMethodBox.ItemsSource = choices
                .OrderBy(x => x.Kind, StringComparer.Ordinal)
                .ThenBy(x => x.Name, StringComparer.Ordinal)
                .ToArray();

            var packagedTotal = packaged.GetProperty("counts").GetProperty("total").GetInt32();
            var frontierTotal = frontier.GetProperty("counts").GetProperty("total").GetInt32();
            CapabilityCatalogStatus.Text =
                $"Bundled Codex runtime: {packaged.GetProperty("version").GetString()} · " +
                $"{packagedTotal} protocol surfaces. Upstream frontier: {frontierTotal}. " +
                $"Frontier-only delta: {frontierTotal - packagedTotal}.";
        }
        catch (Exception ex)
        {
            CapabilityCatalogStatus.Text = $"Capability catalog could not be loaded: {ex.Message}";
            CodexMethodBox.ItemsSource = null;
        }
    }

    private static void AddCatalogChoices(
        ICollection<CodexCatalogChoice> output,
        JsonElement items,
        string kind,
        IReadOnlySet<string> stableNames)
    {
        foreach (var item in items.EnumerateArray())
        {
            if (item.GetString() is not { Length: > 0 } name)
                continue;
            output.Add(new CodexCatalogChoice(
                name,
                kind,
                stableNames.Contains(name) ? "packaged" : "frontier-only"));
        }
    }

    private void CodexMethodBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (CodexMethodBox.SelectedItem is not CodexCatalogChoice choice)
            return;

        if (choice.Kind == "client-request")
        {
            RawRpcMethodBox.Text = choice.Name;
            CapabilityCatalogStatus.Text =
                choice.State == "packaged"
                    ? CodexLocalReadPolicy.IsAllowed(choice.Name)
                        ? $"{choice.Name} is present in the bundled Codex runtime and is qualified for credential-free local read access."
                        : $"{choice.Name} is present in the bundled Codex runtime and is ready for explicit RPC qualification; authorization may still be required."
                    : $"{choice.Name} is upstream-frontier only; it is tracked but is not expected in the bundled Codex 0.159.3 runtime.";
            return;
        }

        CapabilityCatalogStatus.Text =
            $"{choice.Name} is a {choice.Kind}. It is observed through the protocol monitor rather than invoked as a client request.";
    }

    private async void ListRealtimeVoices_Click(object? sender, RoutedEventArgs e) =>
        await RunReadOnlyCodexProbeAsync(
            "thread/realtime/listVoices",
            JsonSerializer.SerializeToElement(new { }));

    private async void ReadRemoteStatus_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            await using var client = await CodexAppServerClient.StartLocalAsync();
            var result = await client.RequestAsync("remoteControl/status/read", null);
            RuntimeProbeOutputBox.Text = PrettyJson(result);
            AuthStatus.Text = "Credential-free local Codex read completed: remoteControl/status/read";
            PopulateRemoteIdentity(result);
        }
        catch (Exception ex)
        {
            RuntimeProbeOutputBox.Text = ex.ToString();
            AuthStatus.Text = $"Credential-free local Codex read failed: remoteControl/status/read: {ex.Message}";
        }
    }

    private async void RemoteEnable_Click(object? sender, RoutedEventArgs e)
    {
        if (!ConsumeRemoteConfirmation("Enabling Codex Remote"))
            return;
        var result = await RunCodexProbeForResultAsync(
            "remoteControl/enable",
            JsonSerializer.SerializeToElement(new { ephemeral = false }),
            consequential: true);
        PopulateRemoteIdentity(result);
    }

    private async void RemoteDisable_Click(object? sender, RoutedEventArgs e)
    {
        if (!ConsumeRemoteConfirmation("Disabling Codex Remote"))
            return;
        var result = await RunCodexProbeForResultAsync(
            "remoteControl/disable",
            JsonSerializer.SerializeToElement(new { ephemeral = false }),
            consequential: true);
        PopulateRemoteIdentity(result);
    }

    private async void RemotePairingStart_Click(object? sender, RoutedEventArgs e)
    {
        if (!ConsumeRemoteConfirmation("Starting Codex Remote pairing"))
            return;

        var result = await RunCodexProbeForResultAsync(
            "remoteControl/pairing/start",
            JsonSerializer.SerializeToElement(new { manualCode = RemoteManualCodeBox.IsChecked == true }),
            consequential: true);

        if (result is { } value)
        {
            if (value.TryGetProperty("environmentId", out var environmentId) &&
                environmentId.ValueKind == JsonValueKind.String)
                RemoteEnvironmentBox.Text = environmentId.GetString();

            if (value.TryGetProperty("pairingCode", out var pairingCode) &&
                pairingCode.ValueKind == JsonValueKind.String)
                RemotePairingCodeBox.Text = pairingCode.GetString();

            if (value.TryGetProperty("manualPairingCode", out var manualPairingCode) &&
                manualPairingCode.ValueKind == JsonValueKind.String)
                RemoteManualPairingCodeBox.Text = manualPairingCode.GetString();
        }
    }

    private async void RemotePairingStatus_Click(object? sender, RoutedEventArgs e)
    {
        var result = await RunCodexProbeForResultAsync(
            "remoteControl/pairing/status",
            JsonSerializer.SerializeToElement(new
            {
                pairingCode = NullIfWhiteSpace(RemotePairingCodeBox.Text),
                manualPairingCode = NullIfWhiteSpace(RemoteManualPairingCodeBox.Text)
            }),
            consequential: false);

        if (result is { } value && value.TryGetProperty("claimed", out var claimed))
            AuthStatus.Text = $"Remote pairing claimed={claimed.GetBoolean()}.";
    }

    private async void RemoteClients_Click(object? sender, RoutedEventArgs e)
    {
        var environmentId = RequireText(RemoteEnvironmentBox.Text, "Remote environment ID");
        await RunCodexProbeForResultAsync(
            "remoteControl/client/list",
            JsonSerializer.SerializeToElement(new
            {
                environmentId,
                cursor = (string?)null,
                limit = (int?)null,
                order = (string?)null
            }),
            consequential: false);
    }

    private async void RemoteRevoke_Click(object? sender, RoutedEventArgs e)
    {
        if (!ConsumeRemoteConfirmation("Revoking a Codex Remote client"))
            return;

        var environmentId = RequireText(RemoteEnvironmentBox.Text, "Remote environment ID");
        var clientId = RequireText(RemoteClientIdBox.Text, "Remote client ID");
        await RunCodexProbeForResultAsync(
            "remoteControl/client/revoke",
            JsonSerializer.SerializeToElement(new { environmentId, clientId }),
            consequential: true);
    }

    private bool ConsumeRemoteConfirmation(string operation)
    {
        if (RemoteConfirmBox.IsChecked != true)
        {
            RuntimeProbeOutputBox.Text =
                $"{operation} requires the explicit confirmation checkbox.";
            AuthStatus.Text = "Remote action not executed: confirmation is required.";
            return false;
        }

        RemoteConfirmBox.IsChecked = false;
        return true;
    }

    private void PopulateRemoteIdentity(JsonElement? result)
    {
        if (result is not { } value)
            return;

        if (value.TryGetProperty("environmentId", out var environmentId) &&
            environmentId.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(environmentId.GetString()))
            RemoteEnvironmentBox.Text = environmentId.GetString();
    }

    private static string RequireText(string? value, string label) =>
        !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : throw new InvalidOperationException($"{label} is required.");

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private async void ListPlugins_Click(object? sender, RoutedEventArgs e) =>
        await RunReadOnlyCodexProbeAsync(
            "plugin/list",
            JsonSerializer.SerializeToElement(new { }));

    private async void ListPermissionProfiles_Click(object? sender, RoutedEventArgs e) =>
        await RunReadOnlyCodexProbeAsync(
            "permissionProfile/list",
            JsonSerializer.SerializeToElement(new { }));

    private async void ListApps_Click(object? sender, RoutedEventArgs e) =>
        await RunReadOnlyCodexProbeAsync(
            "app/list",
            JsonSerializer.SerializeToElement(new { }));

    private async void ReadSandboxReadiness_Click(object? sender, RoutedEventArgs e) =>
        await RunReadOnlyCodexProbeAsync(
            "windowsSandbox/readiness",
            parameters: null);

    private void BrowserStatus_Click(object? sender, RoutedEventArgs e)
    {
        BrowserSnapshotBox.Text = JsonSerializer.Serialize(
            BrowserSession.Status(),
            new JsonSerializerOptions { WriteIndented = true });
    }

    private async void StartBrowser_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            var url = BrowserUrlBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(url))
                throw new InvalidOperationException("Enter an absolute HTTP or HTTPS URL.");

            await StopBrowserSessionAsync();
            BrowserSnapshotBox.Text = "Starting isolated browser…";
            var profile = Path.Combine(AppState.DirectoryPath, "browser-profile");
            _browserSession = await BrowserSession.StartPersistentAsync(profile, headless: false);
            var snapshot = await _browserSession.NavigateAndSnapshotAsync(url);
            BrowserSnapshotBox.Text = JsonSerializer.Serialize(
                snapshot,
                new JsonSerializerOptions { WriteIndented = true });
            AuthStatus.Text = "Application-owned browser started with its persistent human profile. Semantic ARIA snapshot is available; Stop browser remains available.";
        }
        catch (Exception ex)
        {
            await StopBrowserSessionAsync();
            BrowserSnapshotBox.Text = ex.ToString();
            AuthStatus.Text = $"Clean-room browser start/inspect failed: {ex.Message}";
        }
    }

    private async void StopBrowser_Click(object? sender, RoutedEventArgs e)
    {
        await StopBrowserSessionAsync();
        BrowserSnapshotBox.Text = "Clean-room browser stopped.";
        AuthStatus.Text = "Clean-room browser stopped.";
    }

    private async Task StopBrowserSessionAsync()
    {
        if (_browserSession is null)
            return;

        await _browserSession.DisposeAsync();
        _browserSession = null;
    }

    private async Task RunReadOnlyCodexProbeAsync(string method, JsonElement? parameters)
    {
        try
        {
            CodexLocalReadPolicy.RequireAllowed(method);
            RuntimeProbeOutputBox.Text = $"Running credential-free local read {method}…";
            await using var client = await CodexAppServerClient.StartLocalAsync();
            var result = await client.RequestAsync(method, parameters);
            RuntimeProbeOutputBox.Text = PrettyJson(result);
            AuthStatus.Text = $"Credential-free local Codex read completed: {method}";
        }
        catch (Exception ex)
        {
            RuntimeProbeOutputBox.Text = ex.ToString();
            AuthStatus.Text = $"Credential-free local Codex read failed: {method}: {ex.Message}";
        }
    }

    private async Task<JsonElement?> RunCodexProbeForResultAsync(
        string method,
        JsonElement? parameters,
        bool consequential)
    {
        try
        {
            RuntimeProbeOutputBox.Text = $"Running {method}…";
            var client = await EnsureCodexAsync();
            var result = await client.RequestAsync(method, parameters);
            RuntimeProbeOutputBox.Text = PrettyJson(result);
            AuthStatus.Text = consequential
                ? $"Confirmed Codex action completed: {method}"
                : $"Read-only Codex probe completed: {method}";
            return result;
        }
        catch (Exception ex)
        {
            RuntimeProbeOutputBox.Text = ex.ToString();
            AuthStatus.Text = consequential
                ? $"Confirmed Codex action failed: {method}: {ex.Message}"
                : $"Read-only Codex probe failed: {method}: {ex.Message}";
            return null;
        }
    }

    private async void SendRawRpc_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            var method = RawRpcMethodBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(method))
                throw new InvalidOperationException("Enter a Codex app-server method.");

            var parameters = ParseOptionalJson(RawRpcParamsBox.Text);
            JsonElement result;
            if (CodexLocalReadPolicy.IsAllowed(method))
            {
                await using var localClient = await CodexAppServerClient.StartLocalAsync();
                result = await localClient.RequestAsync(method, parameters);
                AuthStatus.Text = $"Credential-free local Codex read completed: {method}";
            }
            else
            {
                var client = await EnsureCodexAsync();
                result = await client.RequestAsync(method, parameters);
                AuthStatus.Text = $"Authorized Codex RPC completed: {method}";
            }
            RawRpcOutputBox.Text = PrettyJson(result);
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
            StopBrowserSessionAsync().GetAwaiter().GetResult();
            StopCodexAsync().GetAwaiter().GetResult();
            StopResponsesWebSocketAsync().GetAwaiter().GetResult();
        }
        catch
        {
        }

        base.OnClosed(e);
    }
}
