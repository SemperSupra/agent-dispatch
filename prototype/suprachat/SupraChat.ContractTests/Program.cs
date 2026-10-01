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
    loginHint: "user@example.com");
Require(!returning.AuthorizationUri.Query.Contains("agent_name_hint="), "returning sign-in must omit agent_name_hint");
Require(returning.AuthorizationUri.Query.Contains("id_token_hint="), "returning id token hint missing");
Require(returning.AuthorizationUri.Query.Contains("login_hint="), "returning login hint missing");

var callback = new Uri("http://127.0.0.1:54321/auth/callback?code=abc&state=xyz");
var exactRedirect = SiwcProtocol.CallbackRedirectUri(callback);
Require(exactRedirect.AbsoluteUri == "http://127.0.0.1:54321/auth/callback", "callback redirect must preserve allocated port");
var tokenForm = SiwcProtocol.BuildTokenForm(attempt, "oaiapp_issued", "code", exactRedirect);
Require(tokenForm["redirect_uri"] == exactRedirect.AbsoluteUri, "token exchange redirect must exactly match callback listener");
var refreshForm = SiwcProtocol.BuildRefreshForm("oaiapp_issued", "refresh");
Require(refreshForm["grant_type"] == "refresh_token", "refresh grant missing");
Require(!refreshForm.ContainsKey("scope"), "refresh must retain existing grant without resending scope");

using var request = JsonDocument.Parse(SiwcProtocol.BuildResponsesBody("test-model", "hello"));
Require(request.RootElement.GetProperty("store").GetBoolean() == false, "store must be false");
Require(request.RootElement.GetProperty("stream").GetBoolean(), "stream must be true");

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
