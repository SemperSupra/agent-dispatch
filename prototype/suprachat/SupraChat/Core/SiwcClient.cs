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
        SiwcCredential? existing = null,
        bool promptConsent = false,
        SiwcRegistration? registration = null)
    {
        if (existing is not null && registration is not null &&
            !string.Equals(existing.ClientId, registration.ClientId, StringComparison.Ordinal))
            throw new InvalidOperationException("Selected registration does not match the active credential.");

        var selectedClientId = existing?.ClientId ?? registration?.ClientId;
        var expectedSubject = existing?.Subject ?? registration?.Subject;
        var loginHint = existing?.Email ?? registration?.Email;

        var attempt = SiwcProtocol.CreateAuthorization(
            hostId,
            appName,
            selectedClientId,
            idTokenHint: existing?.IdToken,
            loginHint: loginHint,
            promptConsent: promptConsent);

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

        var principal = await ValidateIdTokenAsync(idToken, issuedClientId, attempt.Nonce);
        var subject = principal.FindFirst("sub")?.Value
            ?? throw new InvalidOperationException("Validated ID token has no subject.");
        var email = principal.FindFirst("email")?.Value;

        if (expectedSubject is not null && !string.Equals(expectedSubject, subject, StringComparison.Ordinal))
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

    public async Task<bool> RevokeAsync(SiwcCredential credential)
    {
        var endpoint = await GetRevocationEndpointAsync().ConfigureAwait(false);
        using var response = await _http.PostAsync(
            endpoint,
            new FormUrlEncodedContent(
                SiwcProtocol.BuildRevocationForm(credential.ClientId, credential.RefreshToken)))
            .ConfigureAwait(false);

        // The documented endpoint returns 200 for success and already-invalid
        // tokens. Temporary failures must not be mistaken for confirmed revocation.
        if ((int)response.StatusCode >= 500)
            return false;

        if (!response.IsSuccessStatusCode)
        {
            var detail = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            throw new InvalidOperationException(
                $"session revocation failed ({(int)response.StatusCode}){DiagnosticSuffix(response, detail)}");
        }

        return true;
    }

    private async Task<Uri> GetRevocationEndpointAsync()
    {
        using var response = await _http.GetAsync(SiwcProtocol.DiscoveryEndpoint).ConfigureAwait(false);
        var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"OIDC discovery failed ({(int)response.StatusCode}){DiagnosticSuffix(response, json)}");

        using var doc = JsonDocument.Parse(json);
        var text = doc.RootElement.TryGetProperty("revocation_endpoint", out var value)
            ? value.GetString()
            : null;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps ||
            !string.Equals(endpoint.Host, "auth.openai.com", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("OIDC discovery returned an unexpected revocation endpoint.");

        return endpoint;
    }

    private static async Task<JsonElement> ReadSuccessfulTokenResponseAsync(
        HttpResponseMessage response,
        string operation)
    {
        var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"{operation} failed ({(int)response.StatusCode}){DiagnosticSuffix(response, json)}");

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

    private static string Required(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.GetString() is { Length: > 0 } text
            ? text
            : throw new InvalidOperationException($"Token response omitted {name}.");

    private static string DiagnosticSuffix(HttpResponseMessage response, string body)
    {
        var requestId = response.Headers.TryGetValues("x-request-id", out var values)
            ? values.FirstOrDefault()
            : null;
        var compact = body.Replace("\r", " ").Replace("\n", " ").Trim();
        if (compact.Length > 500)
            compact = compact[..500] + "…";
        return $" request_id={requestId ?? "unknown"} body={compact}";
    }

    private static async Task<ClaimsPrincipal> ValidateIdTokenAsync(
        string idToken,
        string clientId,
        string expectedNonce)
    {
        var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
            SiwcProtocol.DiscoveryEndpoint.AbsoluteUri,
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
