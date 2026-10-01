using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Avalonia.Controls;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SupraChat.Core;

public sealed record SiwcCredential(
    string ClientId,
    string HostId,
    string Subject,
    string? Email,
    string AccessToken,
    string RefreshToken,
    string IdToken,
    string TokenType,
    long ExpiresIn,
    string[] Scopes,
    DateTimeOffset SavedAt)
{
    public bool HasPlanUsage => Scopes.Contains(SiwcProtocol.RequiredPlanScope, StringComparer.Ordinal);
    public DateTimeOffset ExpiresAt => SavedAt.AddSeconds(ExpiresIn);
}

public sealed class SiwcClient
{
    private readonly HttpClient _http = new();
    private readonly SemaphoreSlim _refreshGate = new(1, 1);

    public async Task<SiwcCredential> SignInAsync(
        TopLevel owner,
        string hostId,
        string appName,
        SiwcCredential? existing = null)
    {
        var attempt = SiwcProtocol.CreateAuthorization(
            hostId,
            appName,
            existing?.ClientId,
            idTokenHint: existing?.IdToken,
            loginHint: existing?.Email);

        var options = new WebAuthenticatorOptions(attempt.AuthorizationUri, attempt.RedirectUri)
        {
            Mode = WebAuthenticatorMode.Browser,
            BrowserOptions = new BrowserOptions
            {
                Timeout = TimeSpan.FromMinutes(5),
                CallbackFilter = callback => callback.State == attempt.State
            }
        };

        var callback = await WebAuthenticationBroker.AuthenticateAsync(owner, options).ConfigureAwait(true);
        if (!string.Equals(callback.State, attempt.State, StringComparison.Ordinal))
            throw new InvalidOperationException("OAuth state mismatch.");
        if (callback.Error is { Length: > 0 })
            throw new InvalidOperationException($"OAuth error: {callback.Error}: {callback.ErrorDescription}");
        if (string.IsNullOrWhiteSpace(callback.Code))
            throw new InvalidOperationException("Authorization callback did not include a code.");

        var returnedClientId = callback.Parameters.TryGetValue("client_id", out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;

        string issuedClientId;
        if (attempt.RequestedClientId == SiwcProtocol.FirstRegistrationClientId)
        {
            issuedClientId = returnedClientId
                ?? throw new InvalidOperationException("Dynamic registration did not return an issued client_id.");
        }
        else
        {
            issuedClientId = attempt.RequestedClientId;
            if (returnedClientId is not null && !string.Equals(returnedClientId, issuedClientId, StringComparison.Ordinal))
                throw new InvalidOperationException("Returning sign-in supplied a different client_id.");
        }

        var exactRedirectUri = SiwcProtocol.CallbackRedirectUri(callback.CallbackUri);
        using var tokenResponse = await _http.PostAsync(
            SiwcProtocol.TokenEndpoint,
            new FormUrlEncodedContent(
                SiwcProtocol.BuildTokenForm(attempt, issuedClientId, callback.Code, exactRedirectUri)));

        var root = await ReadSuccessfulTokenResponseAsync(tokenResponse, "authorization-code exchange");
        var accessToken = Required(root, "access_token");
        var refreshToken = Required(root, "refresh_token");
        var idToken = Required(root, "id_token");
        var tokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() ?? "Bearer" : "Bearer";
        var expiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt64() : 3600;
        var scopes = ParseScopes(root, Array.Empty<string>());
        RequirePlanScope(scopes);

        var principal = await ValidateIdTokenAsync(idToken, issuedClientId, attempt.Nonce);
        var subject = principal.FindFirst("sub")?.Value
            ?? throw new InvalidOperationException("Validated ID token has no subject.");
        var email = principal.FindFirst("email")?.Value;

        if (existing is not null && !string.Equals(existing.Subject, subject, StringComparison.Ordinal))
            throw new InvalidOperationException("Returning sign-in resolved to a different ChatGPT account.");

        return new(
            issuedClientId,
            hostId,
            subject,
            email,
            accessToken,
            refreshToken,
            idToken,
            tokenType,
            expiresIn,
            scopes,
            DateTimeOffset.UtcNow);
    }

    public async Task<SiwcCredential> RefreshIfNeededAsync(
        SiwcCredential credential,
        TimeSpan? refreshWindow = null)
    {
        var window = refreshWindow ?? TimeSpan.FromMinutes(5);
        if (DateTimeOffset.UtcNow < credential.ExpiresAt - window)
            return credential;

        await _refreshGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (DateTimeOffset.UtcNow < credential.ExpiresAt - window)
                return credential;

            using var response = await _http.PostAsync(
                SiwcProtocol.TokenEndpoint,
                new FormUrlEncodedContent(
                    SiwcProtocol.BuildRefreshForm(credential.ClientId, credential.RefreshToken)))
                .ConfigureAwait(false);

            var root = await ReadSuccessfulTokenResponseAsync(response, "token refresh").ConfigureAwait(false);
            var accessToken = Required(root, "access_token");
            var refreshToken = Required(root, "refresh_token");
            var tokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() ?? credential.TokenType : credential.TokenType;
            var expiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt64() : 3600;
            var scopes = ParseScopes(root, credential.Scopes);
            RequirePlanScope(scopes);

            return credential with
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                TokenType = tokenType,
                ExpiresIn = expiresIn,
                Scopes = scopes,
                SavedAt = DateTimeOffset.UtcNow
            };
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private static async Task<JsonElement> ReadSuccessfulTokenResponseAsync(
        HttpResponseMessage response,
        string operation)
    {
        var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"{operation} failed ({(int)response.StatusCode}).");

        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static string[] ParseScopes(JsonElement root, IReadOnlyCollection<string> fallback)
    {
        if (!root.TryGetProperty("scope", out var sc) || string.IsNullOrWhiteSpace(sc.GetString()))
            return fallback.ToArray();

        return sc.GetString()!
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static void RequirePlanScope(IEnumerable<string> scopes)
    {
        if (!scopes.Contains(SiwcProtocol.RequiredPlanScope, StringComparer.Ordinal))
            throw new InvalidOperationException("ChatGPT plan usage permission was not granted.");
    }

    private static string Required(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.GetString() is { Length: > 0 } text
            ? text
            : throw new InvalidOperationException($"Token response omitted {name}.");

    private static async Task<ClaimsPrincipal> ValidateIdTokenAsync(
        string idToken,
        string clientId,
        string expectedNonce)
    {
        var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "https://auth.openai.com/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever());
        var config = await manager.GetConfigurationAsync(CancellationToken.None).ConfigureAwait(false);

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = config.Issuer,
            ValidateAudience = true,
            ValidAudience = clientId,
            ValidateLifetime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = config.SigningKeys,
            ClockSkew = TimeSpan.FromMinutes(2)
        };

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var principal = handler.ValidateToken(idToken, parameters, out _);
        var nonce = principal.FindFirst("nonce")?.Value;
        if (!string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
            throw new SecurityTokenValidationException("ID-token nonce mismatch.");
        return principal;
    }
}
