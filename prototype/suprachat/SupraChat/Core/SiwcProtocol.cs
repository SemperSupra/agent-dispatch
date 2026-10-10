using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SupraChat.Core;

public sealed record SiwcAuthorizationAttempt(
    Uri AuthorizationUri,
    Uri RedirectUri,
    string State,
    string Nonce,
    string CodeVerifier,
    string RequestedClientId,
    string HostId);

public sealed record ResponseAttachment(
    string Kind,
    string Name,
    string Value,
    string Detail = "auto");

public static class SiwcProtocol
{
    public const string FirstRegistrationClientId = "dynamic_agent_client";
    public const string Resource = "https://api.openai.com/v1";
    public const string RequiredPlanScope = "chatgpt.tokens.use.direct";
    public const string Scope = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
    public static readonly Uri DiscoveryEndpoint = new("https://auth.openai.com/.well-known/openid-configuration");
    public static readonly Uri AuthorizeEndpoint = new("https://auth.openai.com/api/accounts/authorize");
    public static readonly Uri TokenEndpoint = new("https://auth.openai.com/api/accounts/oauth/token");

    public static SiwcAuthorizationAttempt CreateAuthorization(
        string hostId,
        string appName,
        string? issuedClientId = null,
        Uri? redirectUri = null,
        string? idTokenHint = null,
        string? loginHint = null,
        bool promptConsent = false)
    {
        if (!hostId.StartsWith("urn:uuid:", StringComparison.Ordinal))
            throw new ArgumentException("hostId must be a stable urn:uuid value.", nameof(hostId));

        var state = RandomToken(32);
        var nonce = RandomToken(32);
        var verifier = RandomToken(64);
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var isRegistration = string.IsNullOrWhiteSpace(issuedClientId);
        var clientId = isRegistration ? FirstRegistrationClientId : issuedClientId!;
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

        if (isRegistration)
        {
            query["agent_name_hint"] = appName;
        }
        else
        {
            if (!string.IsNullOrWhiteSpace(idTokenHint))
                query["id_token_hint"] = idTokenHint;
            if (!string.IsNullOrWhiteSpace(loginHint))
                query["login_hint"] = loginHint;
        }

        if (promptConsent)
            query["prompt"] = "consent";

        var uri = new UriBuilder(AuthorizeEndpoint)
        {
            Query = string.Join("&", query.Select(kv =>
                $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"))
        }.Uri;

        return new(uri, redirectUri, state, nonce, verifier, clientId, hostId);
    }

    public static Uri CallbackRedirectUri(Uri callbackUri)
    {
        if (!string.Equals(callbackUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(callbackUri.Host, "127.0.0.1", StringComparison.Ordinal) ||
            !string.Equals(callbackUri.AbsolutePath, "/auth/callback", StringComparison.Ordinal))
            throw new InvalidOperationException("Unexpected OAuth callback origin or path.");

        return new UriBuilder(callbackUri) { Query = "", Fragment = "" }.Uri;
    }

    public static IReadOnlyDictionary<string, string> BuildTokenForm(
        SiwcAuthorizationAttempt attempt,
        string issuedClientId,
        string code,
        Uri exactRedirectUri) =>
        new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = issuedClientId,
            ["code"] = code,
            ["code_verifier"] = attempt.CodeVerifier,
            ["redirect_uri"] = exactRedirectUri.AbsoluteUri,
            ["resource"] = Resource
        };

    public static IReadOnlyDictionary<string, string> BuildRefreshForm(
        string issuedClientId,
        string refreshToken) =>
        new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = issuedClientId,
            ["refresh_token"] = refreshToken,
            ["resource"] = Resource
        };

    public static IReadOnlyDictionary<string, string> BuildRevocationForm(
        string issuedClientId,
        string refreshToken) =>
        new Dictionary<string, string>
        {
            ["token"] = refreshToken,
            ["token_type_hint"] = "refresh_token",
            ["client_id"] = issuedClientId
        };

    public static string BuildResponsesBody(
        string model,
        string input,
        IEnumerable<ResponseAttachment>? attachments = null,
        bool enableWebSearch = false)
    {
        var content = new List<object>();
        if (!string.IsNullOrWhiteSpace(input))
            content.Add(new Dictionary<string, object?>
            {
                ["type"] = "input_text",
                ["text"] = input
            });

        foreach (var attachment in attachments ?? Array.Empty<ResponseAttachment>())
        {
            if (attachment.Kind == "image")
            {
                content.Add(new Dictionary<string, object?>
                {
                    ["type"] = "input_image",
                    ["image_url"] = attachment.Value,
                    ["detail"] = attachment.Detail
                });
            }
            else if (attachment.Kind == "file")
            {
                content.Add(new Dictionary<string, object?>
                {
                    ["type"] = "input_file",
                    ["filename"] = attachment.Name,
                    ["file_data"] = attachment.Value,
                    ["detail"] = attachment.Detail
                });
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(attachments), $"Unknown attachment kind: {attachment.Kind}");
            }
        }

        if (content.Count == 0)
            throw new ArgumentException("Responses input must contain text, an image, or a file.", nameof(input));

        var body = new Dictionary<string, object?>
        {
            ["model"] = model,
            ["input"] = new[]
            {
                new Dictionary<string, object?>
                {
                    ["role"] = "user",
                    ["content"] = content
                }
            },
            ["store"] = false,
            ["stream"] = true
        };

        if (enableWebSearch)
            body["tools"] = new object[] { new Dictionary<string, object?> { ["type"] = "web_search" } };

        return JsonSerializer.Serialize(body);
    }

    public static string ToDataUrl(string mimeType, ReadOnlySpan<byte> bytes) =>
        $"data:{mimeType};base64,{Convert.ToBase64String(bytes)}";

    private static string RandomToken(int bytes) => Base64Url(RandomNumberGenerator.GetBytes(bytes));

    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
