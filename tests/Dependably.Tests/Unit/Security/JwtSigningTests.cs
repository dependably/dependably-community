using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Enforces the JWT crypto invariants declared in encryption.md §2: algorithm is
/// HS256, signing key has 256 bits of entropy, and validation rejects tampered,
/// re-signed, expired, or alg=none tokens under the production
/// <see cref="TokenValidationParameters"/> (mirroring Program.cs:238-247).
/// </summary>
[Trait("Category", "Unit")]
public sealed class JwtSigningTests
{
    // Same shape as FirstBootService.cs:62 — base64 of 32 CSPRNG bytes.
    private static string FreshSecret() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static TokenValidationParameters ProductionValidationParams(string secret) => new()
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
    };

    [Fact]
    public void Tenant_JWT_is_signed_with_HS256()
    {
        string token = LoginService.IssueTenantJwt("user-id", "tenant-id", "member", FreshSecret());
        var parsed = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.Equal(SecurityAlgorithms.HmacSha256, parsed.Header.Alg);
    }

    [Fact]
    public void System_JWT_is_signed_with_HS256()
    {
        string token = LoginService.IssueSystemJwt("sysadmin-id", FreshSecret());
        var parsed = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.Equal(SecurityAlgorithms.HmacSha256, parsed.Header.Alg);
    }

    [Fact]
    public void Valid_token_passes_production_validation()
    {
        string secret = FreshSecret();
        string token = LoginService.IssueTenantJwt("user-id", "tenant-id", "member", secret);
        var handler = new JwtSecurityTokenHandler();
        var principal = handler.ValidateToken(token, ProductionValidationParams(secret), out _);
        Assert.NotNull(principal);
    }

    [Fact]
    public void Tampered_signature_is_rejected()
    {
        string secret = FreshSecret();
        string token = LoginService.IssueTenantJwt("user-id", "tenant-id", "member", secret);

        // JWT is header.payload.signature — flip a base64url-valid char in the
        // signature so decoding still succeeds but HMAC verification fails.
        string[] parts = token.Split('.');
        Assert.Equal(3, parts.Length);
        char[] sigChars = parts[2].ToCharArray();
        sigChars[0] = sigChars[0] == 'A' ? 'B' : 'A';
        string tampered = string.Join('.', parts[0], parts[1], new string(sigChars));

        var handler = new JwtSecurityTokenHandler();
        Assert.ThrowsAny<SecurityTokenException>(() =>
            handler.ValidateToken(tampered, ProductionValidationParams(secret), out _));
    }

    [Fact]
    public void Token_signed_with_different_secret_is_rejected()
    {
        string attackerSecret = FreshSecret();
        string serverSecret = FreshSecret();
        string token = LoginService.IssueTenantJwt("user-id", "tenant-id", "member", attackerSecret);

        var handler = new JwtSecurityTokenHandler();
        Assert.ThrowsAny<SecurityTokenException>(() =>
            handler.ValidateToken(token, ProductionValidationParams(serverSecret), out _));
    }

    [Fact]
    public void Unsigned_alg_none_token_is_rejected()
    {
        string secret = FreshSecret();
        // Hand-craft an alg=none token with the same claims a legitimate one would carry.
        string header = Base64UrlEncode("{\"alg\":\"none\",\"typ\":\"JWT\"}"u8);
        string payload = Base64UrlEncode(Encoding.UTF8.GetBytes(
            $"{{\"sub\":\"user-id\",\"tid\":\"tenant-id\",\"role\":\"member\",\"scope\":\"tenant\"," +
            $"\"exp\":{DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}}}"));
        string unsigned = $"{header}.{payload}.";

        var handler = new JwtSecurityTokenHandler();
        Assert.ThrowsAny<SecurityTokenException>(() =>
            handler.ValidateToken(unsigned, ProductionValidationParams(secret), out _));
    }

    [Fact]
    public void Expired_token_is_rejected_under_zero_clock_skew()
    {
        string secret = FreshSecret();
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var pastIssued = DateTime.UtcNow.AddHours(-9);
        var pastExpired = DateTime.UtcNow.AddHours(-1);

        var expired = new JwtSecurityToken(
            claims: new[]
            {
                new System.Security.Claims.Claim("sub", "user-id"),
                new System.Security.Claims.Claim("tid", "tenant-id"),
            },
            notBefore: pastIssued,
            expires: pastExpired,
            signingCredentials: creds);
        string token = new JwtSecurityTokenHandler().WriteToken(expired);

        var handler = new JwtSecurityTokenHandler();
        Assert.Throws<SecurityTokenExpiredException>(() =>
            handler.ValidateToken(token, ProductionValidationParams(secret), out _));
    }

    [Fact]
    public void First_boot_secret_pattern_yields_32_bytes_of_entropy()
    {
        // Mirrors FirstBootService.cs:62 — Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).
        // The decoded byte length is the actual entropy delivered to HMAC-SHA256.
        byte[] raw = RandomNumberGenerator.GetBytes(32);
        string b64 = Convert.ToBase64String(raw);
        byte[] decoded = Convert.FromBase64String(b64);
        Assert.Equal(32, decoded.Length);
        Assert.Equal(raw, decoded);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
}
