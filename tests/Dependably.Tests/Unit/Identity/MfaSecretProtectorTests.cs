using System.Security.Cryptography;
using Dependably.Infrastructure.Identity;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for AES-GCM encryption in <see cref="MfaSecretProtector"/>. Verifies the
/// encrypt/decrypt round-trip, per-call nonce uniqueness, tamper detection, and key isolation.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MfaSecretProtectorTests
{
    private static MfaSecretProtector NewProtector() =>
        new(RandomNumberGenerator.GetBytes(32));

    // ── round-trip ────────────────────────────────────────────────────────────

    [Fact]
    public void Protect_Unprotect_RoundTrips()
    {
        var protector = NewProtector();
        string plaintext = "JBSWY3DPEHPK3PXP"; // typical TOTP base32 key

        string ciphertext = protector.Protect(plaintext);
        string recovered = protector.Unprotect(ciphertext);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void Protect_EmptyString_RoundTrips()
    {
        var protector = NewProtector();
        string ciphertext = protector.Protect(string.Empty);
        Assert.Equal(string.Empty, protector.Unprotect(ciphertext));
    }

    [Fact]
    public void Protect_UnicodeValue_RoundTrips()
    {
        var protector = NewProtector();
        const string value = "cléé-éé";
        Assert.Equal(value, protector.Unprotect(protector.Protect(value)));
    }

    // ── nonce uniqueness ──────────────────────────────────────────────────────

    [Fact]
    public void Protect_CalledTwice_ProducesDistinctCiphertexts()
    {
        var protector = NewProtector();
        string plaintext = "same-secret";

        string a = protector.Protect(plaintext);
        string b = protector.Protect(plaintext);

        Assert.NotEqual(a, b);
    }

    // ── tamper detection ──────────────────────────────────────────────────────

    [Fact]
    public void Unprotect_TamperedByte_ThrowsMfaSecretProtectionException()
    {
        var protector = NewProtector();
        byte[] raw = Convert.FromBase64String(protector.Protect("secret"));

        // Flip the last ciphertext byte.
        raw[^1] ^= 0xFF;

        Assert.Throws<MfaSecretProtectionException>(() =>
            protector.Unprotect(Convert.ToBase64String(raw)));
    }

    [Fact]
    public void Unprotect_TruncatedTag_ThrowsMfaSecretProtectionException()
    {
        var protector = NewProtector();
        byte[] raw = Convert.FromBase64String(protector.Protect("secret"));

        // Truncate to fewer bytes than nonce + tag.
        byte[] truncated = raw[..10];

        Assert.Throws<MfaSecretProtectionException>(() =>
            protector.Unprotect(Convert.ToBase64String(truncated)));
    }

    // ── wrong key ─────────────────────────────────────────────────────────────

    [Fact]
    public void Unprotect_WrongKey_ThrowsMfaSecretProtectionException()
    {
        var protectorA = NewProtector();
        var protectorB = NewProtector();

        string ciphertext = protectorA.Protect("secret");

        Assert.Throws<MfaSecretProtectionException>(() =>
            protectorB.Unprotect(ciphertext));
    }

    // ── malformed input ───────────────────────────────────────────────────────

    [Fact]
    public void Unprotect_NotBase64_ThrowsMfaSecretProtectionException()
    {
        var protector = NewProtector();
        Assert.Throws<MfaSecretProtectionException>(() =>
            protector.Unprotect("not-valid-base64!!!"));
    }

    // ── constructor guard ─────────────────────────────────────────────────────

    [Theory]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(0)]
    public void Constructor_NonThirtyTwoByteKey_Throws(int keyLen)
    {
        byte[] badKey = new byte[keyLen];
        Assert.Throws<ArgumentException>(() => new MfaSecretProtector(badKey));
    }
}
