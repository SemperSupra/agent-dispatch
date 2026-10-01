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

using var request = JsonDocument.Parse(SiwcProtocol.BuildResponsesBody("test-model", "hello"));
Require(request.RootElement.GetProperty("store").GetBoolean() == false, "store must be false");
Require(request.RootElement.GetProperty("stream").GetBoolean(), "stream must be true");

Require(CodexAppServer.Arguments.Contains("model_provider=\"openai_chatgpt_plan\""), "Codex provider missing");
Require(CodexAppServer.Arguments.Any(x => x.Contains("requires_openai_auth=false")), "Codex auth mode missing");
Require(CodexAppServer.Arguments.All(x => !x.Contains("Bearer ", StringComparison.OrdinalIgnoreCase)), "token leaked into arguments");

Console.WriteLine("SupraChat contract checks PASS");
