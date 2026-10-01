using System.Text.Json;
using SupraChat.Core;

static void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

var attempt = SiwcProtocol.CreateAuthorization(
    "urn:uuid:11111111-2222-3333-4444-555555555555",
    "SupraChat");

Require(attempt.AuthorizationUri.Host == "auth.openai.com", "wrong auth host");
Require(attempt.AuthorizationUri.Query.Contains("client_id=dynamic_agent_client"), "dynamic client missing");
Require(attempt.AuthorizationUri.Query.Contains("chatgpt.tokens.use.direct"), "plan scope missing");
Require(attempt.AuthorizationUri.Query.Contains("ext_agent_host_id="), "host id missing");
Require(attempt.AuthorizationUri.Query.Contains("code_challenge_method=S256"), "PKCE S256 missing");
Require(attempt.AuthorizationUri.Query.Contains("agent_name_hint=SupraChat"), "registration name missing");

var returning = SiwcProtocol.CreateAuthorization(
    "urn:uuid:11111111-2222-3333-4444-555555555555",
    "SupraChat",
    "oaiapp_existing",
    idTokenHint: "header.payload.sig",
    loginHint: "user@example.com",
    promptConsent: true);
Require(!returning.AuthorizationUri.Query.Contains("agent_name_hint="), "returning sign-in must omit agent_name_hint");
Require(returning.AuthorizationUri.Query.Contains("id_token_hint="), "returning id token hint missing");
Require(returning.AuthorizationUri.Query.Contains("login_hint="), "returning login hint missing");
Require(returning.AuthorizationUri.Query.Contains("prompt=consent"), "re-consent prompt missing");

var callback = new Uri("http://127.0.0.1:54321/auth/callback?code=abc&state=xyz");
var exactRedirect = SiwcProtocol.CallbackRedirectUri(callback);
Require(exactRedirect.AbsoluteUri == "http://127.0.0.1:54321/auth/callback", "callback redirect must preserve allocated port");
var tokenForm = SiwcProtocol.BuildTokenForm(attempt, "oaiapp_issued", "code", exactRedirect);
Require(tokenForm["redirect_uri"] == exactRedirect.AbsoluteUri, "token exchange redirect must exactly match callback listener");
var refreshForm = SiwcProtocol.BuildRefreshForm("oaiapp_issued", "refresh");
Require(refreshForm["grant_type"] == "refresh_token", "refresh grant missing");
Require(!refreshForm.ContainsKey("scope"), "refresh must retain existing grant without resending scope");
var revokeForm = SiwcProtocol.BuildRevocationForm("oaiapp_issued", "refresh");
Require(revokeForm["token_type_hint"] == "refresh_token", "revocation hint missing");
Require(revokeForm["client_id"] == "oaiapp_issued", "revocation client missing");

using (var request = JsonDocument.Parse(SiwcProtocol.BuildResponsesBody("test-model", "hello")))
{
    Require(request.RootElement.GetProperty("store").GetBoolean() == false, "store must be false");
    Require(request.RootElement.GetProperty("stream").GetBoolean(), "stream must be true");
    Require(!request.RootElement.TryGetProperty("tools", out _), "plain response should not add tools");
}

var png = SiwcProtocol.ToDataUrl("image/png", new byte[] { 1, 2, 3, 4 });
var file = SiwcProtocol.ToDataUrl("text/plain", System.Text.Encoding.UTF8.GetBytes("hello"));
using (var multimodal = JsonDocument.Parse(SiwcProtocol.BuildResponsesBody(
    "test-model",
    "inspect",
    new[]
    {
        new ResponseAttachment("image", "sample.png", png),
        new ResponseAttachment("file", "sample.txt", file)
    },
    enableWebSearch: true)))
{
    var root = multimodal.RootElement;
    Require(root.GetProperty("store").GetBoolean() == false, "multimodal store must be false");
    Require(root.GetProperty("stream").GetBoolean(), "multimodal stream must be true");
    var tools = root.GetProperty("tools");
    Require(tools.GetArrayLength() == 1 && tools[0].GetProperty("type").GetString() == "web_search",
        "web search tool missing");

    var parts = root.GetProperty("input")[0].GetProperty("content");
    Require(parts.GetArrayLength() == 3, "text + image + file content expected");
    Require(parts[1].GetProperty("type").GetString() == "input_image", "image input missing");
    Require(parts[2].GetProperty("type").GetString() == "input_file", "file input missing");
    Require(parts[2].GetProperty("file_data").GetString()!.StartsWith("data:text/plain;base64,"),
        "file data URL missing");
}

using (var normalizedRaw = JsonDocument.Parse(ResponsesClient.NormalizeRawResponsesBody(
    """{"input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}],"tools":[{"type":"web_search"}],"temperature":0.2}""",
    "gpt-example")))
{
    var root = normalizedRaw.RootElement;
    Require(root.GetProperty("model").GetString() == "gpt-example", "raw Responses default model injection failed");
    Require(root.GetProperty("store").GetBoolean() == false, "raw Responses store must be forced false");
    Require(root.GetProperty("stream").GetBoolean(), "raw Responses stream must be forced true");
    Require(root.GetProperty("tools")[0].GetProperty("type").GetString() == "web_search",
        "raw Responses supported tool field was filtered");
    Require(root.GetProperty("temperature").GetDouble() == 0.2,
        "raw Responses probe field was silently removed instead of reaching upstream validation");
}

using (var wsCreate = JsonDocument.Parse(ResponsesWebSocketClient.NormalizeClientEvent(
    """{"type":"response.create","stream_id":"planner","store":true,"stream":true,"background":true,"input":[{"role":"user","content":"hello"}]}""",
    "gpt-example")))
{
    var root = wsCreate.RootElement;
    Require(root.GetProperty("type").GetString() == "response.create", "WebSocket response.create type changed");
    Require(root.GetProperty("model").GetString() == "gpt-example", "WebSocket default model injection failed");
    Require(root.GetProperty("store").GetBoolean() == false, "WebSocket ChatGPT-plan store must be forced false");
    Require(root.GetProperty("stream_id").GetString() == "planner", "WebSocket stream_id must survive normalization");
    Require(!root.TryGetProperty("stream", out _), "WebSocket event must omit HTTP-only stream field");
    Require(!root.TryGetProperty("background", out _), "WebSocket event must omit background field");
}

using (var wsSteer = JsonDocument.Parse(ResponsesWebSocketClient.NormalizeClientEvent(
    """{"type":"response.steer","previous_response_id":"resp_1","input":"narrow the scope"}""",
    "gpt-example")))
{
    var root = wsSteer.RootElement;
    Require(root.GetProperty("type").GetString() == "response.steer", "WebSocket steer type changed");
    Require(root.GetProperty("previous_response_id").GetString() == "resp_1", "WebSocket steer lineage changed");
    Require(!root.TryGetProperty("model", out _), "Non-create WebSocket events must remain pass-through");
}

var modelJson = """{"models":[{"slug":"gpt-example","display_name":"GPT Example","visibility":"list"},{"slug":"hidden","display_name":"Hidden","visibility":"hidden"}]}""";
var models = ResponsesClient.ParseModels(modelJson);
Require(models.Count == 1 && models[0].Slug == "gpt-example" && models[0].DisplayName == "GPT Example", "SIWC model catalog parsing failed");

Require(CodexAppServer.Arguments.Contains("model_provider=\"openai_chatgpt_plan\""), "Codex provider missing");
Require(CodexAppServer.Arguments.Any(x => x.Contains("requires_openai_auth=false")), "Codex auth mode missing");
Require(CodexAppServer.Arguments.All(x => !x.Contains("Bearer ", StringComparison.OrdinalIgnoreCase)), "token leaked into arguments");

var codexInit = CodexAppServerClient.BuildInitializeParams(experimentalApi: true);
Require(codexInit.GetProperty("clientInfo").GetProperty("name").GetString() == "suprachat", "Codex initialize client identity missing");
Require(codexInit.GetProperty("capabilities").GetProperty("experimentalApi").GetBoolean(), "Codex experimental protocol capability must be enabled");

var codexThread = CodexAppServerClient.BuildThreadStartParams("gpt-example", Path.GetFullPath("."));
Require(codexThread.GetProperty("modelProvider").GetString() == "openai_chatgpt_plan", "Codex ChatGPT-plan provider missing");
Require(codexThread.GetProperty("approvalPolicy").GetString() == "never", "qualification interview approval policy changed");
Require(codexThread.GetProperty("sandbox").GetString() == "read-only", "qualification interview sandbox changed");
Require(codexThread.GetProperty("ephemeral").GetBoolean(), "qualification interview thread must be ephemeral");

var codexTurn = CodexAppServerClient.BuildTurnStartParams("thread-test", "hello");
Require(codexTurn.GetProperty("threadId").GetString() == "thread-test", "Codex turn thread id missing");
Require(codexTurn.GetProperty("input")[0].GetProperty("type").GetString() == "text", "Codex text input missing");

var surfacePath = Path.Combine(
    "prototype", "suprachat", "oracles", "codex-app-server-surface-20261001.json");
Require(File.Exists(surfacePath), "pinned Codex surface inventory missing");
using (var surfaceDoc = JsonDocument.Parse(File.ReadAllText(surfacePath)))
{
    var counts = surfaceDoc.RootElement.GetProperty("counts");
    Require(counts.GetProperty("client_requests").GetInt32() == 172, "Codex client-RPC inventory drifted");
    Require(counts.GetProperty("server_requests").GetInt32() == 9, "Codex server-request inventory drifted");
    Require(counts.GetProperty("server_notifications").GetInt32() == 85, "Codex notification inventory drifted");
    Require(counts.GetProperty("total").GetInt32() == 266, "Codex total protocol inventory drifted");
}

var fakeCredential = new SiwcCredential(
    "oaiapp_test",
    "urn:uuid:11111111-2222-3333-4444-555555555555",
    "subject-secret-value",
    "user@example.com",
    "ACCESS_TOKEN_MUST_NOT_APPEAR",
    "REFRESH_TOKEN_MUST_NOT_APPEAR",
    "ID_TOKEN_MUST_NOT_APPEAR",
    "Bearer",
    3600,
    new[] { "openid", SiwcProtocol.RequiredPlanScope },
    DateTimeOffset.UtcNow);

Require(fakeCredential.HasPlanUsage, "plan-usage scope should be recognized");
var identityOnly = fakeCredential with { Scopes = new[] { "openid", "profile" } };
Require(!identityOnly.HasPlanUsage, "identity-only session must remain distinct from plan usage");

var receipt = QualificationReceipts.BuildDirect(
    "gpt-example",
    fakeCredential,
    completed: true,
    TimeSpan.FromMilliseconds(1234),
    outputCharacters: 42);
var receiptJson = JsonSerializer.Serialize(receipt);

Require(receipt.Schema == QualificationReceipts.Schema, "receipt schema mismatch");
Require(receipt.Binding == "siwc-direct-responses", "receipt binding mismatch");
Require(receipt.Completed && !receipt.Store && receipt.Stream, "receipt completion/transport invariants wrong");
Require(!receipt.ContainsPrompt && !receipt.ContainsOutput && !receipt.ContainsTokenMaterial, "receipt privacy flags wrong");
Require(receipt.GrantedScopes.Contains(SiwcProtocol.RequiredPlanScope), "receipt must retain granted-scope metadata");
Require(!receiptJson.Contains("ACCESS_TOKEN_MUST_NOT_APPEAR", StringComparison.Ordinal), "access token leaked into receipt");
Require(!receiptJson.Contains("REFRESH_TOKEN_MUST_NOT_APPEAR", StringComparison.Ordinal), "refresh token leaked into receipt");
Require(!receiptJson.Contains("ID_TOKEN_MUST_NOT_APPEAR", StringComparison.Ordinal), "ID token leaked into receipt");
Require(!receiptJson.Contains("subject-secret-value", StringComparison.Ordinal), "raw account subject leaked into receipt");
Require(!receiptJson.Contains("user@example.com", StringComparison.Ordinal), "email leaked into receipt");

var codexReceipt = QualificationReceipts.BuildCodex(
    "gpt-example",
    fakeCredential,
    completed: true,
    TimeSpan.FromMilliseconds(1500),
    outputCharacters: 55);
var codexReceiptJson = JsonSerializer.Serialize(codexReceipt);
Require(codexReceipt.Binding == "siwc-codex-app-server", "Codex receipt binding mismatch");
Require(codexReceipt.Runtime.Contains("Codex app-server", StringComparison.Ordinal), "Codex receipt runtime missing");
Require(!codexReceiptJson.Contains("ACCESS_TOKEN_MUST_NOT_APPEAR", StringComparison.Ordinal), "access token leaked into Codex receipt");
Require(!codexReceiptJson.Contains("REFRESH_TOKEN_MUST_NOT_APPEAR", StringComparison.Ordinal), "refresh token leaked into Codex receipt");
Require(!codexReceiptJson.Contains("ID_TOKEN_MUST_NOT_APPEAR", StringComparison.Ordinal), "ID token leaked into Codex receipt");
Require(!codexReceiptJson.Contains("subject-secret-value", StringComparison.Ordinal), "raw account subject leaked into Codex receipt");
Require(!codexReceiptJson.Contains("user@example.com", StringComparison.Ordinal), "email leaked into Codex receipt");

var runtimeRoot = Path.Combine(Path.GetTempPath(), "suprachat-codex-resolution-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(Path.Combine(runtimeRoot, "runtime", "codex"));
var bundledName = OperatingSystem.IsWindows() ? "codex.exe" : "codex";
var bundledPath = Path.Combine(runtimeRoot, "runtime", "codex", bundledName);
File.WriteAllText(bundledPath, "fixture");
Require(CodexAppServer.ResolveExecutable(runtimeRoot) == bundledPath,
    "packaged Codex runtime must take precedence over PATH fallback");
Directory.Delete(runtimeRoot, recursive: true);

Require(WindowsCompanionHotkey.ShortcutDescription == "Alt+Space",
    "Windows companion shortcut drifted from first-party parity target");

Require(WindowsNotificationService.Adapter == "shell-notification-area",
    "Windows notification adapter identity drifted");
Require(DesktopNotificationService.Adapter is not "unsupported",
    "desktop notification adapter missing for supported platform");
Require(DesktopNotificationService.AppleScriptString("a\"b") == "\"a\\\"b\"",
    "macOS notification string escaping drifted");

var parityPath = Path.Combine("prototype", "suprachat", "oracles", "audience-parity-20261001.json");
Require(File.Exists(parityPath), "audience/accessibility parity manifest missing");
using (var parityDoc = JsonDocument.Parse(File.ReadAllText(parityPath)))
{
    var root = parityDoc.RootElement;
    Require(root.GetProperty("schema").GetString() == "suprachat-audience-parity/v1",
        "audience parity schema drifted");
    var features = root.GetProperty("features");
    Require(features.GetArrayLength() >= 15, "audience parity ledger unexpectedly sparse");

    var allowedParityStates = new HashSet<string>(new[]
    {
        "implemented",
        "implemented_with_fallback",
        "qualify",
        "human_boundary",
        "gap",
        "not_applicable"
    }, StringComparer.Ordinal);

    foreach (var feature in features.EnumerateArray())
    {
        Require(feature.TryGetProperty("id", out var id) && !string.IsNullOrWhiteSpace(id.GetString()),
            "parity feature id missing");
        Require(feature.TryGetProperty("access", out var access) && access.ValueKind == JsonValueKind.Object,
            $"parity access map missing for {id.GetString()}");
        foreach (var audience in new[] { "human", "accessible_human", "automation", "agent" })
        {
            Require(access.TryGetProperty(audience, out var state) &&
                    !string.IsNullOrWhiteSpace(state.GetString()),
                $"parity audience state missing for {id.GetString()}: {audience}");
            Require(allowedParityStates.Contains(state.GetString()!),
                $"unknown parity audience state for {id.GetString()}: {audience}={state.GetString()}");
        }

        if (feature.TryGetProperty("consequential", out var consequential) && consequential.GetBoolean())
        {
            var humanState = access.GetProperty("human").GetString();
            var accessibleState = access.GetProperty("accessible_human").GetString();
            Require(!(humanState == "implemented" && accessibleState == "gap"),
                $"accessible-human regression for consequential feature {id.GetString()}");
            Require(!(humanState == "implemented" && accessibleState == "not_applicable"),
                $"accessible-human path cannot be not_applicable for consequential human feature {id.GetString()}");
        }

        Require(feature.TryGetProperty("platforms", out var platforms) && platforms.ValueKind == JsonValueKind.Object,
            $"parity platform map missing for {id.GetString()}");
        foreach (var platform in new[] { "windows", "macos", "linux" })
        {
            Require(platforms.TryGetProperty(platform, out var state) &&
                    !string.IsNullOrWhiteSpace(state.GetString()),
                $"parity platform state missing for {id.GetString()}: {platform}");
            Require(allowedParityStates.Contains(state.GetString()!),
                $"unknown parity platform state for {id.GetString()}: {platform}={state.GetString()}");
        }

        Require(feature.TryGetProperty("human_boundary", out var boundary) &&
                !string.IsNullOrWhiteSpace(boundary.GetString()),
            $"parity authorization boundary missing for {id.GetString()}");
    }
}

var attachmentFixture = AttachmentInputs.Create(
    "sample.txt",
    System.Text.Encoding.UTF8.GetBytes("accessible machine attachment"));
Require(attachmentFixture.Kind == "file", "shared attachment MIME classification drifted");
Require(attachmentFixture.Value.StartsWith("data:text/plain;base64,", StringComparison.Ordinal),
    "shared attachment data URL drifted");

var accessibilityContract = AccessibilityContract.Describe();
Require(accessibilityContract.Schema == AccessibilityContract.Schema, "accessibility schema drifted");
Require(accessibilityContract.Human.KeyboardOnly, "keyboard-only accessibility invariant missing");
Require(accessibilityContract.Human.ScreenReaderSemantics, "screen-reader semantic invariant missing");
Require(accessibilityContract.Human.StableAutomationIds, "stable automation-id invariant missing");
Require(accessibilityContract.Human.BrowserAccessibilityFallback, "browser accessibility fallback invariant missing");
Require(accessibilityContract.Human.UserAdjustableInterfaceScale, "user-adjustable interface scale invariant missing");
Require(accessibilityContract.Human.InterfaceScaleMinimum <= 0.8 &&
        accessibilityContract.Human.InterfaceScaleMaximum >= 2.0,
    "accessible interface-scale range regressed");
Require(accessibilityContract.Human.ReducedMotionPreference, "reduced-motion preference invariant missing");
Require(!accessibilityContract.Automation.ScreenScrapingRequired, "automation accessibility regressed to screen scraping");
Require(!accessibilityContract.Agent.ScreenScrapingRequired, "agent accessibility regressed to screen scraping");

var accessibilityDocPath = Path.Combine("prototype", "suprachat", "ACCESSIBILITY.md");
Require(File.Exists(accessibilityDocPath), "accessibility contract document missing");
var accessibilityDoc = File.ReadAllText(accessibilityDocPath);
Require(accessibilityDoc.Contains("Accessibility regressions are qualification failures", StringComparison.Ordinal),
    "accessibility qualification invariant missing");

var mainWindowXamlPath = Path.Combine("prototype", "suprachat", "SupraChat", "MainWindow.axaml");
Require(File.Exists(mainWindowXamlPath), "MainWindow accessibility surface missing");
var mainWindowXaml = File.ReadAllText(mainWindowXamlPath);
foreach (var marker in new[]
{
    "AutomationProperties.AutomationId=\"SupraChat.MainWindow\"",
    "AutomationProperties.AutomationId=\"RootTabs\"",
    "AutomationProperties.AutomationId=\"AgentLab.Prompt\"",
    "AutomationProperties.AutomationId=\"Auth.Status\"",
    "AutomationProperties.AutomationId=\"Accessibility.Status\"",
    "AutomationProperties.AutomationId=\"Accessibility.ScaleDown\"",
    "AutomationProperties.AutomationId=\"Accessibility.ScaleReset\"",
    "AutomationProperties.AutomationId=\"Accessibility.ScaleUp\"",
    "AutomationProperties.AutomationId=\"Accessibility.ReducedMotion\"",
    "AutomationProperties.AutomationId=\"Accessibility.PreferencesStatus\"",
    "AutomationProperties.AutomationId=\"Machine.AudienceParityStatus\"",
    "AutomationProperties.AutomationId=\"RuntimeProbes.Voices\"",
    "AutomationProperties.AutomationId=\"RuntimeProbes.RemoteStatus\"",
    "AutomationProperties.AutomationId=\"RuntimeProbes.Plugins\"",
    "AutomationProperties.AutomationId=\"RuntimeProbes.Output\"",
    "AutomationProperties.LiveSetting=\"Polite\"",
    "AutomationProperties.HeadingLevel=\"1\"",
    "AutomationProperties.HeadingLevel=\"2\"",
    "KeyDown=\"MainWindow_KeyDown\""
})
{
    Require(mainWindowXaml.Contains(marker, StringComparison.Ordinal),
        $"required accessibility marker missing: {marker}");
}

var normalizedPreference = AccessibilityPreferencesStore.Normalize(
    new AccessibilityPreferences("wrong", 4.7, true));
Require(normalizedPreference.Schema == AccessibilityPreferencesStore.Schema,
    "accessibility preference schema normalization failed");
Require(normalizedPreference.InterfaceScale == AccessibilityPreferencesStore.MaximumScale,
    "accessibility scale maximum clamp failed");
Require(normalizedPreference.ReducedMotion,
    "reduced-motion preference was lost during normalization");

var automationSourcePath = Path.Combine(
    "prototype", "suprachat", "SupraChat.Automation", "Program.cs");
Require(File.Exists(automationSourcePath), "automation source missing");
var automationSource = File.ReadAllText(automationSourcePath);
foreach (var marker in new[]
{
    "\"voices\"",
    "\"remote-status\"",
    "\"plugins\"",
    "\"realtime/voices\"",
    "\"remote/status\"",
    "\"plugins/list\""
})
{
    Require(automationSource.Contains(marker, StringComparison.Ordinal),
        $"semantic machine runtime surface missing: {marker}");
}

var appXamlPath = Path.Combine("prototype", "suprachat", "SupraChat", "App.axaml");
Require(File.ReadAllText(appXamlPath).Contains("RequestedThemeVariant=\"Default\"", StringComparison.Ordinal),
    "application must follow the platform theme/high-contrast preference");

Console.WriteLine("SupraChat contract checks PASS");
