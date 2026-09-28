using System.Security.Claims;
using System.Text.Encodings.Web;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Dependably.Security;

/// <summary>
/// Scheme constants for the system-admin API-token handler. Actions opt in via
/// <c>[Authorize(AuthenticationSchemes = "Bearer," + SystemTokenDefaults.Scheme)]</c> so a JWT
/// session and a <c>dpsys_…</c> token both authenticate the same route.
/// </summary>
public static class SystemTokenDefaults
{
    public const string Scheme = "SystemToken";

    /// <summary>The claim value <see cref="RequireCapability"/>-adjacent code checks for a
    /// token-authenticated system principal, deliberately distinct from <c>system_admin</c> so
    /// <c>CapabilityHandler</c> and <c>SiemController</c> never grant it platform-wide access.</summary>
    public const string Role = "system_token";
}

/// <summary>Empty options — driven entirely by request shape and the database, like <see cref="TokenAuthenticationOptions"/>.</summary>
public sealed class SystemTokenAuthenticationOptions : AuthenticationSchemeOptions
{
}

/// <summary>
/// Resolves a <c>dpsys_…</c> system API token into a <see cref="ClaimsPrincipal"/> carrying
/// <c>scope=system</c> so <see cref="RouteScopeFilter"/> admits it on apex system routes, and
/// <c>role=system_token</c> — never <c>system_admin</c> — so nothing that grants platform-wide
/// access on that role does so for a token.
///
/// Claims emitted on success:
/// <list type="bullet">
///   <item><c>sub</c> — the token's own id, never the owner's. Every <c>sub</c>-keyed self-guard
///         (MFA/password-rotation status, <c>me/*</c>) therefore looks up a row that does not
///         exist for a token principal rather than accidentally reading the owner's.</item>
///   <item><c>scope</c> — always <c>system</c>.</item>
///   <item><c>role</c> — always <see cref="SystemTokenDefaults.Role"/>.</item>
///   <item><c>stok_owner</c> — the minting admin's id, read by <see cref="SystemActor"/> for the
///         audit detail's <c>via_token_owner</c> field.</item>
///   <item><c>stok_name</c> — the token's display name, read by <see cref="SystemActor"/> as the
///         audit row's <c>actor_label</c>.</item>
/// </list>
///
/// Only a <c>Bearer</c> header carrying the <see cref="SystemTokenRepository.TokenPrefix"/> is
/// read — no Basic or <c>X-NuGet-ApiKey</c> forms, unlike the tenant <c>ApiToken</c> scheme,
/// because this scheme has no protocol-client callers. A header without the prefix returns
/// <see cref="AuthenticateResult.NoResult"/> without a database round trip, so a JWT or a tenant
/// token presented on a dual-scheme route falls through to the other scheme in the policy instead
/// of failing here.
/// </summary>
public sealed class SystemTokenAuthenticationHandler : AuthenticationHandler<SystemTokenAuthenticationOptions>
{
    private readonly SystemTokenRepository _tokens;

    public SystemTokenAuthenticationHandler(
        IOptionsMonitor<SystemTokenAuthenticationOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder,
        SystemTokenRepository tokens)
        : base(options, loggerFactory, encoder)
    {
        _tokens = tokens;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? raw = ExtractRawToken(Request);
        if (raw is null)
        {
            return AuthenticateResult.NoResult();
        }

        var token = await _tokens.ResolveAsync(raw, Context.RequestAborted);
        if (token is null)
        {
            AuthDenialRecorder.FlagUnresolvedCredential(Context);
            return AuthenticateResult.Fail("Invalid or expired system API token.");
        }

        if (_tokens.ShouldTouchLastUsed(token.LastUsedAt))
        {
            await _tokens.TouchLastUsedAsync(token.Id, ct: Context.RequestAborted);
        }

        var identity = new ClaimsIdentity(BuildClaims(token), Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    /// <summary>Mirrors <see cref="TokenAuthenticationHandler.HandleChallengeAsync"/>.</summary>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (AuthDenialRecorder.ConsumeUnresolvedCredential(Context))
        {
            AuthDenialRecorder.RecordTokenRejected(Context, reason: AuthDenialRecorder.ReasonInvalid);
        }

        return base.HandleChallengeAsync(properties);
    }

    /// <summary>Mirrors <see cref="TokenAuthenticationHandler.HandleForbiddenAsync"/>.</summary>
    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        AuthDenialRecorder.RecordCapabilityDeniedForScheme(Context, Scheme.Name);
        return base.HandleForbiddenAsync(properties);
    }

    /// <summary>
    /// Reads a Bearer token carrying the <see cref="SystemTokenRepository.TokenPrefix"/>. Any
    /// other shape (no header, Basic, X-NuGet-ApiKey, or a Bearer value without the prefix)
    /// returns null so the caller reports <see cref="AuthenticateResult.NoResult"/> instead of
    /// spending a database round trip on a secret this scheme could never own.
    /// </summary>
    private static string? ExtractRawToken(HttpRequest request)
    {
        string? auth = request.Headers.Authorization.FirstOrDefault();
        if (auth is null || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string candidate = auth["Bearer ".Length..].Trim();
        return candidate.StartsWith(SystemTokenRepository.TokenPrefix, StringComparison.Ordinal)
            ? candidate
            : null;
    }

    private static List<Claim> BuildClaims(SystemTokenRecord token) =>
    [
        new("sub", token.Id),
        new("scope", "system"),
        new("role", SystemTokenDefaults.Role),
        new("stok_owner", token.CreatedBy),
        new("stok_name", token.Name),
    ];
}
