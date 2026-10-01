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
}

public sealed class SiwcClient
{
    private readonly HttpClient _http = new();

    public async Task<SiwcCredential> SignInAsync(TopLevel owner, string hostId, string appName)
    {
        var attempt = SiwcProtocol.CreateAuthorization(hostId, appName);
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

        var issuedClientId = callback.Parameters.TryGetValue("client_id", out var returnedClientId)
            ? returnedClientId
            : throw new InvalidOperationException("Dynamic registration did not return an issued client_id.");

        using var tokenResponse = await _http.PostAsync(
            SiwcProtocol.TokenEndpoint,
            new FormUrlEncodedContent(SiwcProtocol.BuildTokenForm(attempt, issuedClientId, callback.Code)));

        var json = await tokenResponse.Content.ReadAsStringAsync();
        if (!tokenResponse.IsSuccessStatusCode)
            throw new InvalidOperationException($"Token exchange failed ({(int)tokenResponse.StatusCode}).");

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var accessToken = Required(root, "access_token");
        var refreshToken = Required(root, "refresh_token");
        var idToken = Required(root, "id_token");
        var tokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() ?? "Bearer" : "Bearer";
        var expiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt64() : 3600;
        var scope = root.TryGetProperty("scope", out var sc) ? sc.GetString() ?? "" : "";
        var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (!scopes.Contains(SiwcProtocol.RequiredPlanScope, StringComparer.Ordinal))
            throw new InvalidOperationException("ChatGPT plan usage permission was not granted.");

        var principal = await ValidateIdTokenAsync(idToken, issuedClientId, attempt.Nonce);
        var subject = principal.FindFirst("sub")?.Value
            ?? throw new InvalidOperationException("Validated ID token has no subject.");
        var email = principal.FindFirst("email")?.Value;

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
        var config = await manager.GetConfigurationAsync(CancellationToken.None);

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
