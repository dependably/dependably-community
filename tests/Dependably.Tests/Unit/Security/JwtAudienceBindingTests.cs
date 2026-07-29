using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Pins the token-type discriminator to the <c>aud</c> claim rather than to <c>scope</c>.
///
/// Every JWT the instance mints is signed with the same <c>jwt_secret</c> and satisfies the same
/// algorithm and lifetime constraints, so without audience binding the only thing separating a
/// pre-second-factor MFA challenge from a full session token is an application-layer claim check
/// that has to name every non-session scope explicitly. These tests assert the binding is
/// enforced inside token validation — the stage JwtBearer runs before <c>OnTokenValidated</c>
/// and therefore before any scope check exists to consult — and that the rejection is caused by
/// the audience specifically, not by some other property the two token shapes happen to differ on.
/// </summary>
[Trait("Category", "Unit")]
public sealed class JwtAudienceBindingTests
{
    private const string Secret = "unit-test-jwt-secret-with-at-least-32-bytes";

    // The one instant every token in this class is minted at, read once and threaded through a
    // FakeTimeProvider so no two tokens can land on different clocks mid-run.
    // now-ok: IdentityModel validates lifetime against a clock of its own that
    // TokenValidationParameters exposes no seam for, so anchoring the mint to real time is what
    // keeps these tokens live and stops lifetime from deciding an outcome the assertions below
    // attribute to the audience or the issuer.
    private static readonly DateTimeOffset MintedAt = DateTimeOffset.UtcNow;

    private static FakeTimeProvider Clock() => new(MintedAt);

    // The host's real session-validation rules plus the signing key, which the running process
    // resolves per validation from JwtSigningKeyProvider rather than from the parameters.
    private static TokenValidationParameters SessionParams(string secret = Secret)
    {
        var parameters = JwtTokenBinding.SessionValidationParameters();
        parameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        return parameters;
    }

    private static ClaimsPrincipal ValidateAsSession(string token, string secret = Secret) =>
        new JwtSecurityTokenHandler { MapInboundClaims = false }
            .ValidateToken(token, SessionParams(secret), out _);

    // Mints an otherwise-valid, currently-live HS256 token with a caller-chosen issuer and
    // audience, so a test can vary exactly one of them and hold everything else constant.
    private static string SignedToken(string issuer, string audience, params Claim[] claims)
    {
        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret)), SecurityAlgorithms.HmacSha256);
        var now = MintedAt.UtcDateTime;
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: now.AddMinutes(-1),
            expires: now.AddMinutes(30),
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // The claim set a session token needs to satisfy every application-layer check that runs
    // after validation: a subject, a session scope, and a token version.
    private static Claim[] SessionShapedClaims() =>
    [
        new(JwtRegisteredClaimNames.Sub, "user-id"),
        new(JwtRegisteredClaimNames.Jti, "jti-fixed-for-this-test"),
        new("tid", "tenant-id"),
        new("org_id", "tenant-id"),
        new("role", "owner"),
        new("scope", "tenant"),
        new("tver", "1"),
    ];

    // ── The audience is what rejects a non-session token ───────────────────────

    /// <summary>
    /// The independence proof. Both tokens carry the *same* claim set — including
    /// <c>scope=tenant</c>, which the session scope allow-list admits — and differ in nothing but
    /// the <c>aud</c> value. The challenge-audience one is refused and the session-audience one is
    /// accepted, so the refusal cannot be attributed to the scope allow-list: that allow-list
    /// would pass this token, and it does not run at this stage in any case. Deleting the
    /// allow-list from OnJwtTokenValidatedAsync leaves this test's outcome unchanged.
    /// </summary>
    [Fact]
    public void Challenge_audience_is_refused_and_session_audience_accepted_for_identical_claims()
    {
        string refused = SignedToken(
            JwtTokenBinding.Issuer, JwtTokenBinding.MfaChallengeAudience, SessionShapedClaims());
        string accepted = SignedToken(
            JwtTokenBinding.Issuer, JwtTokenBinding.SessionAudience, SessionShapedClaims());

        // The two tokens are identical but for the audience, and the refused one carries the
        // scope the session allow-list admits — so the exception type, which names the audience
        // as the failing check, is the whole explanation for the difference in outcome.
        var handler = new JwtSecurityTokenHandler();
        Assert.Equal(
            [JwtTokenBinding.MfaChallengeAudience], handler.ReadJwtToken(refused).Audiences);
        Assert.Equal("tenant", handler.ReadJwtToken(refused).Claims.First(c => c.Type == "scope").Value);

        Assert.Throws<SecurityTokenInvalidAudienceException>(() => ValidateAsSession(refused));

        var principal = ValidateAsSession(accepted);
        Assert.Equal("tenant", principal.FindFirst("scope")?.Value);
    }

    /// <summary>
    /// The same proof against the real mint site: a challenge JWT produced by the production
    /// tenant-challenge helper is refused by the production session-validation rules, and the
    /// exception names the audience as the cause.
    /// </summary>
    [Fact]
    public void Real_tenant_mfa_challenge_is_refused_as_a_session_token_by_audience()
    {
        string challenge = LoginService.IssueMfaChallengeJwt(
            "user-id", "tenant-id", "owner", "user@example.test", 1, Secret, Clock());

        Assert.Throws<SecurityTokenInvalidAudienceException>(() => ValidateAsSession(challenge));
    }

    /// <summary>Same for the system-realm challenge, which carries no tid/role at all.</summary>
    [Fact]
    public void Real_system_mfa_challenge_is_refused_as_a_session_token_by_audience()
    {
        string challenge = LoginService.IssueSystemMfaChallengeJwt(
            "admin-id", "admin@example.test", 1, Secret, Clock());

        Assert.Throws<SecurityTokenInvalidAudienceException>(() => ValidateAsSession(challenge));
    }

    /// <summary>
    /// A future non-session token type inherits the refusal without anyone updating an
    /// allow-list: an unrecognised audience is refused purely for not being the session audience.
    /// </summary>
    [Fact]
    public void An_audience_no_validator_knows_about_is_refused()
    {
        string token = SignedToken(
            JwtTokenBinding.Issuer, "dependably:some-future-token-type", SessionShapedClaims());

        Assert.Throws<SecurityTokenInvalidAudienceException>(() => ValidateAsSession(token));
    }

    [Fact]
    public void A_token_carrying_no_audience_at_all_is_refused()
    {
        string token = SignedToken(JwtTokenBinding.Issuer, audience: null!, SessionShapedClaims());

        Assert.Throws<SecurityTokenInvalidAudienceException>(() => ValidateAsSession(token));
    }

    [Fact]
    public void A_token_carrying_a_foreign_issuer_is_refused()
    {
        string token = SignedToken(
            "https://idp.attacker.test", JwtTokenBinding.SessionAudience, SessionShapedClaims());

        Assert.Throws<SecurityTokenInvalidIssuerException>(() => ValidateAsSession(token));
    }

    [Fact]
    public void A_token_carrying_no_issuer_at_all_is_refused()
    {
        string token = SignedToken(issuer: null!, JwtTokenBinding.SessionAudience, SessionShapedClaims());

        Assert.Throws<SecurityTokenInvalidIssuerException>(() => ValidateAsSession(token));
    }

    // ── Adversarial twins: the legitimate paths still work ─────────────────────

    [Fact]
    public void Real_tenant_session_token_passes_session_validation()
    {
        string token = LoginService.IssueTenantJwt("user-id", "tenant-id", "owner", Secret, 7, Clock());

        var principal = ValidateAsSession(token);

        Assert.Equal("user-id", principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value);
        Assert.Equal("tenant", principal.FindFirst("scope")?.Value);
        Assert.Equal("tenant-id", principal.FindFirst("tid")?.Value);
        Assert.Equal("7", principal.FindFirst("tver")?.Value);
    }

    [Fact]
    public void Real_system_session_token_passes_session_validation()
    {
        string token = LoginService.IssueSystemJwt("admin-id", Secret, Clock(), 4);

        var principal = ValidateAsSession(token);

        Assert.Equal("admin-id", principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value);
        Assert.Equal("system", principal.FindFirst("scope")?.Value);
        Assert.Equal("4", principal.FindFirst("tver")?.Value);
    }

    [Fact]
    public void Real_tenant_mfa_challenge_still_reads_as_a_challenge()
    {
        string challenge = LoginService.IssueMfaChallengeJwt(
            "user-id", "tenant-id", "owner", "User@Example.test", 3, Secret, Clock());

        var (valid, sub, tid, role, eml, tver, _, realm) =
            LoginService.TryReadMfaChallenge(challenge, Secret);

        Assert.True(valid);
        Assert.Equal("user-id", sub);
        Assert.Equal("tenant-id", tid);
        Assert.Equal("owner", role);
        Assert.Equal("user@example.test", eml);
        Assert.Equal(3, tver);
        Assert.Equal("tenant", realm);
    }

    [Fact]
    public void Real_system_mfa_challenge_still_reads_as_a_challenge()
    {
        string challenge = LoginService.IssueSystemMfaChallengeJwt(
            "admin-id", "Admin@Example.test", 2, Secret, Clock());

        var (valid, sub, _, _, eml, tver, _, realm) =
            LoginService.TryReadMfaChallenge(challenge, Secret);

        Assert.True(valid);
        Assert.Equal("admin-id", sub);
        Assert.Equal("admin@example.test", eml);
        Assert.Equal(2, tver);
        Assert.Equal("system", realm);
    }

    // ── The binding holds in the other direction too ───────────────────────────

    /// <summary>
    /// A full session JWT — longer-lived and signed with the same secret — cannot stand in for a
    /// second-factor challenge either. The challenge validator pins the challenge audience, so
    /// the substitution fails on the audience before the scope check it also carries.
    /// </summary>
    [Fact]
    public void Session_token_is_refused_by_the_challenge_validator()
    {
        string session = LoginService.IssueTenantJwt("user-id", "tenant-id", "owner", Secret, 1, Clock());

        var (valid, sub, _, _, _, _, _, _) = LoginService.TryReadMfaChallenge(session, Secret);

        Assert.False(valid);
        Assert.Null(sub);
    }

    /// <summary>
    /// A token shaped exactly like a challenge — <c>scope=mfa_challenge</c> and every claim the
    /// challenge reader consumes — is still refused when its audience is not the challenge
    /// audience, so the challenge reader's own scope check is likewise not the sole discriminator.
    /// </summary>
    [Fact]
    public void Challenge_shaped_token_with_the_session_audience_is_refused_by_the_challenge_validator()
    {
        string token = SignedToken(
            JwtTokenBinding.Issuer,
            JwtTokenBinding.SessionAudience,
            new Claim(JwtRegisteredClaimNames.Sub, "user-id"),
            new Claim(JwtRegisteredClaimNames.Jti, "jti-fixed-for-this-test"),
            new Claim("tid", "tenant-id"),
            new Claim("role", "owner"),
            new Claim("scope", "mfa_challenge"),
            new Claim("tver", "1"),
            new Claim("eml", "user@example.test"));

        var (valid, _, _, _, _, _, _, _) = LoginService.TryReadMfaChallenge(token, Secret);

        Assert.False(valid);
    }

    // ── Every mint site stamps the binding ─────────────────────────────────────

    [Fact]
    public void Every_production_mint_site_stamps_the_issuer_and_its_own_audience()
    {
        var clock = Clock();
        var handler = new JwtSecurityTokenHandler();

        (string Token, string ExpectedAudience)[] minted =
        [
            (LoginService.IssueTenantJwt("u", "t", "owner", Secret, 1, clock), JwtTokenBinding.SessionAudience),
            (LoginService.IssueSystemJwt("a", Secret, clock, 1), JwtTokenBinding.SessionAudience),
            (LoginService.IssueMfaChallengeJwt("u", "t", "owner", "u@e.test", 1, Secret, clock), JwtTokenBinding.MfaChallengeAudience),
            (LoginService.IssueSystemMfaChallengeJwt("a", "a@e.test", 1, Secret, clock), JwtTokenBinding.MfaChallengeAudience),
        ];

        foreach (var (token, expectedAudience) in minted)
        {
            var parsed = handler.ReadJwtToken(token);
            Assert.Equal(JwtTokenBinding.Issuer, parsed.Issuer);
            Assert.Equal([expectedAudience], parsed.Audiences);
        }
    }
}
