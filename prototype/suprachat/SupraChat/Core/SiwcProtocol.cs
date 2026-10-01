using System.Security.Cryptography;
using System.Text;

namespace SupraChat.Core;

public sealed record SiwcAuthorizationAttempt(
    Uri AuthorizationUri,
    Uri RedirectUri,
    string State,
    string Nonce,
    string CodeVerifier,
    string RequestedClientId,
    string HostId);

public static class SiwcProtocol
{
    public const string FirstRegistrationClientId = "dynamic_agent_client";
    public const string Resource = "https://api.openai.com/v1";
    public const string RequiredPlanScope = "chatgpt.tokens.use.direct";
    public const string Scope = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
    public static readonly Uri AuthorizeEndpoint = new("https://auth.openai.com/api/accounts/authorize");
    public static readonly Uri TokenEndpoint = new("https://auth.openai.com/api/accounts/oauth/token");

    public static SiwcAuthorizationAttempt CreateAuthorization(
        string hostId,
        string appName,
        string? issuedClientId = null,
        Uri? redirectUri = null)
    {
        if (!hostId.StartsWith("urn:uuid:", StringComparison.Ordinal))
            throw new ArgumentException("hostId must be a stable urn:uuid value.", nameof(hostId));

        var state = RandomToken(32);
        var nonce = RandomToken(32);
        var verifier = RandomToken(64);
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var clientId = string.IsNullOrWhiteSpace(issuedClientId) ? FirstRegistrationClientId : issuedClientId;
        redirectUri ??= new Uri("http://127.0.0.1/auth/callback");

        var query = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["response_type"] = "code",
            ["redirect_uri"] = redirectUri.AbsoluteUri,
            ["scope"] = Scope,
            ["resource"] = Resource,
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge_method"] = "S256",
            ["code_challenge"] = challenge,
            ["ext_agent_host_id"] = hostId
        };
        if (clientId == FirstRegistrationClientId)
            query["agent_name_hint"] = appName;

        var uri = new UriBuilder(AuthorizeEndpoint)
        {
            Query = string.Join("&", query.Select(kv =>
                $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"))
        }.Uri;

        return new(uri, redirectUri, state, nonce, verifier, clientId, hostId);
    }

    public static IReadOnlyDictionary<string, string> BuildTokenForm(
        SiwcAuthorizationAttempt attempt,
        string issuedClientId,
        string code) =>
        new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = issuedClientId,
            ["code"] = code,
            ["code_verifier"] = attempt.CodeVerifier,
            ["redirect_uri"] = attempt.RedirectUri.AbsoluteUri,
            ["resource"] = Resource
        };

    public static string BuildResponsesBody(string model, string input) =>
        System.Text.Json.JsonSerializer.Serialize(new
        {
            model,
            input = new[] { new { role = "user", content = input } },
            store = false,
            stream = true
        });

    private static string RandomToken(int bytes) => Base64Url(RandomNumberGenerator.GetBytes(bytes));

    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
