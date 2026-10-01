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

var modelJson = """{"models":[{"slug":"gpt-example","display_name":"GPT Example","visibility":"list"},{"slug":"hidden","display_name":"Hidden","visibility":"hidden"}]}""";
var models = ResponsesClient.ParseModels(modelJson);
Require(models.Count == 1 && models[0].Slug == "gpt-example" && models[0].DisplayName == "GPT Example", "SIWC model catalog parsing failed");

Require(CodexAppServer.Arguments.Contains("model_provider=\"openai_chatgpt_plan\""), "Codex provider missing");
Require(CodexAppServer.Arguments.Any(x => x.Contains("requires_openai_auth=false")), "Codex auth mode missing");
Require(CodexAppServer.Arguments.All(x => !x.Contains("Bearer ", StringComparison.OrdinalIgnoreCase)), "token leaked into arguments");

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

Console.WriteLine("SupraChat contract checks PASS");
