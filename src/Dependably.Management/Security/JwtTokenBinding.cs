using Microsoft.IdentityModel.Tokens;

namespace Dependably.Security;

/// <summary>
/// Registered-claim binding shared by every JWT the management plane mints and validates.
///
/// The <c>aud</c> claim is the token-type discriminator: each purpose gets its own audience, and
/// each validator pins the single audience it accepts. That makes the token type a property the
/// signature covers and the token pipeline enforces before any application code runs, rather than
/// a convention an application-layer claim check has to keep in sync. A pre-second-factor
/// challenge JWT and a full session JWT are signed with the same instance secret and satisfy the
/// same algorithm/lifetime constraints, so audience binding is what makes one structurally
/// unusable in the other's place.
///
/// The <c>iss</c> claim is a constant for the product, not a per-instance value: tokens are signed
/// with the instance's own <c>jwt_secret</c>, so cross-instance replay is already excluded by the
/// signature. Pinning <c>iss</c> closes the remaining case where a token minted by some other
/// component that happens to share a secret is presented here.
/// </summary>
public static class JwtTokenBinding
{
    /// <summary>Value of the <c>iss</c> claim on every minted token, and the only issuer any validator accepts.</summary>
    public const string Issuer = "dependably";

    /// <summary>
    /// Audience of a full session JWT (<c>scope=tenant</c> or <c>scope=system</c>) — the only
    /// audience the JwtBearer session scheme accepts.
    /// </summary>
    public const string SessionAudience = "dependably:session";

    /// <summary>
    /// Audience of a short-lived pre-second-factor challenge JWT (<c>scope=mfa_challenge</c>).
    /// Accepted only by the manual challenge validator, never by the session scheme.
    /// </summary>
    public const string MfaChallengeAudience = "dependably:mfa-challenge";

    /// <summary>
    /// The token-validation rules the session (JwtBearer) scheme applies before any application
    /// code sees the principal. Exposed as a factory so the running host and the tests that
    /// assert on these rules share one definition instead of two that can drift apart.
    ///
    /// Audience and issuer are pinned here, which is what makes the token type a decision taken
    /// during validation rather than by a claim check further down the pipeline. The signing key
    /// is deliberately absent: the host resolves it per validation from the signing-key provider
    /// so a rotated secret is honoured without a restart.
    /// </summary>
    public static TokenValidationParameters SessionValidationParameters() => new()
    {
        ValidateIssuer = true,
        ValidIssuer = Issuer,
        ValidateAudience = true,
        ValidAudience = SessionAudience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero,
        ValidateIssuerSigningKey = true,
        // Explicit algorithm allow-list so only HS256 tokens are accepted, matching issuance in LoginService
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
    };
}
