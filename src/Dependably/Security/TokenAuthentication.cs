using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Dapper;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Dependably.Security;

/// <summary>
/// Scheme constants for the API-token <see cref="AuthenticationHandler{TOptions}"/>.
/// Endpoints opt in via <c>[Authorize(AuthenticationSchemes = TokenAuthenticationDefaults.Scheme)]</c>.
/// </summary>
public static class TokenAuthenticationDefaults
{
    public const string Scheme = "ApiToken";
}

/// <summary>
/// Empty options today — the handler is fully driven by request shape and the database.
/// Kept separate so future config (e.g. per-endpoint override of expected header names)
/// has a place to land without changing the handler's class signature.
/// </summary>
public sealed class TokenAuthenticationOptions : AuthenticationSchemeOptions
{
}

/// <summary>
/// Resolves a registry API token (Bearer / Basic / X-NuGet-ApiKey) into a
/// <see cref="ClaimsPrincipal"/> so protocol endpoints can rely on
/// <c>[Authorize(AuthenticationSchemes = "ApiToken")]</c> and <c>[RequireCapability]</c>
/// instead of doing the resolution + capability check inline.
///
/// Claims emitted on success:
/// <list type="bullet">
///   <item><c>sub</c> — token owner (user id, or token id for CI/CD tokens)</item>
///   <item><c>org_id</c>, <c>tid</c> — tenant id (both forms; downstream code reads either)</item>
///   <item><c>role</c> — the user's DB role, or <c>ci</c> for CI/CD tokens</item>
///   <item><c>cap</c> — one claim per explicit capability when the token carries a
///         <c>capabilities</c> JSON array. Absent for legacy tokens — those fall back to
///         role-based capabilities via <see cref="CapabilityHandler"/>.</item>
/// </list>
///
/// On no auth header → <see cref="AuthenticateResult.NoResult"/> so other schemes (JWT
/// for admin) can try. On invalid token → <see cref="AuthenticateResult.Fail"/>.
///
/// Anonymous-pull paths must NOT add <c>[Authorize]</c>; they continue to handle the
/// "no token at all" case explicitly. The handler only populates <c>HttpContext.User</c>
/// when an endpoint is gated by this scheme — it doesn't run on every request.
/// </summary>
public sealed class TokenAuthenticationHandler : AuthenticationHandler<TokenAuthenticationOptions>
{
    private readonly TokenRepository _tokens;
    private readonly IMetadataStore _db;

    public TokenAuthenticationHandler(
        IOptionsMonitor<TokenAuthenticationOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder,
        TokenRepository tokens,
        IMetadataStore db)
        : base(options, loggerFactory, encoder)
    {
        _tokens = tokens;
        _db = db;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var raw = ExtractRawToken(Request);
        if (raw is null) return AuthenticateResult.NoResult();

        var token = await _tokens.ResolveAsync(raw, Context.RequestAborted);
        if (token is null) return AuthenticateResult.Fail("Invalid or expired API token.");

        var role = await LookupUserRoleAsync(token, Context.RequestAborted);
        var identity = new ClaimsIdentity(BuildClaims(token, role), Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    /// <summary>
    /// Reads the raw token from any of the three header conventions Dependably accepts:
    /// Bearer (npm), Basic with token-as-password (PyPI / NuGet authenticated reads),
    /// and X-NuGet-ApiKey (NuGet push). Mirrors <see cref="TokenAuthExtensions.ResolveTokenAsync"/>'s
    /// extraction logic — kept duplicated rather than shared so the auth pipeline doesn't
    /// depend on the extension method's HttpContext-based shape.
    /// </summary>
    private static string? ExtractRawToken(HttpRequest request)
    {
        var auth = request.Headers.Authorization.FirstOrDefault();
        if (auth is not null)
        {
            if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return auth["Bearer ".Length..].Trim();
            if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                var encoded = auth["Basic ".Length..].Trim();
                try
                {
                    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                    var colon = decoded.IndexOf(':');
                    if (colon >= 0) return decoded[(colon + 1)..];
                }
                catch (FormatException) { return null; }
            }
        }
        var nuget = request.Headers["X-NuGet-ApiKey"].FirstOrDefault();
        return string.IsNullOrEmpty(nuget) ? null : nuget;
    }

    /// <summary>
    /// Resolves the token owner's DB role. CI/CD tokens (no <c>UserId</c>) get a synthetic
    /// <c>ci</c> role — <see cref="Capabilities.ForRole"/> returns an empty set for it so
    /// every CI/CD token is forced to declare its capability set explicitly via
    /// <see cref="TokenRecord.Capabilities"/>. That's deliberate: an unscoped CI/CD token
    /// should never inherit broad role caps.
    /// </summary>
    private async Task<string> LookupUserRoleAsync(TokenRecord token, CancellationToken ct)
    {
        if (token.UserId is null) return "ci";
        await using var conn = await _db.OpenAsync(ct);
        var role = await conn.QuerySingleOrDefaultAsync<string>(
            "SELECT role FROM users WHERE id = @id", new { id = token.UserId });
        return role ?? "member";
    }

    private static List<Claim> BuildClaims(TokenRecord token, string role)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, token.UserId ?? token.Id),
            new("org_id", token.OrgId),
            new("tid", token.OrgId),
            new("role", role),
        };

        // Token-narrowed principals always emit explicit `cap` claims so that
        // CapabilityHandler doesn't fall through to role-derived caps. The token IS
        // what's authenticating — its caps are the ceiling regardless of whether the
        // owner happens to be an owner-role user. Every token row carries an explicit
        // capabilities JSON array; NULL/malformed values deny all (no scope fallback).
        var caps = ResolveTokenCapabilities(token);
        foreach (var c in caps)
            claims.Add(new Claim("cap", c));

        return claims;
    }

    /// <summary>
    /// Reads the token's explicit capability set from the cached
    /// <see cref="TokenRecord.CapabilitySet"/> — single source of truth.
    /// Issuance always populates the underlying JSON via
    /// <see cref="Capabilities.TryNormalizeAndAuthorize"/>; NULL/empty/malformed values
    /// surface here as the empty set, denying everything.
    /// </summary>
    private static IEnumerable<string> ResolveTokenCapabilities(TokenRecord token) =>
        token.CapabilitySet;
}
