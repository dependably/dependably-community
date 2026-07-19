using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure.Identity;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for <see cref="RecoveryCodeHasher"/>. Covers the keyed+salted round-trip, salt
/// uniqueness, key isolation, malformed-input handling, and the legacy bare-SHA-256 gate —
/// the stored form of pre-upgrade codes, which is unkeyed and unsalted over a ~47-bit code
/// space and so is offline-brute-forceable from a database dump. That fallback verifies only
/// when the operator opts in; a default instance rejects it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RecoveryCodeHasherTests
{
    private const string Code = "ABCDE-FGHIJ";

    private static RecoveryCodeHasher NewHasher(bool acceptLegacyCodes = false) =>
        new(RandomNumberGenerator.GetBytes(32), acceptLegacyCodes, NullLogger<RecoveryCodeHasher>.Instance);

    /// <summary>Produces the pre-upgrade stored form: unsalted lowercase-hex SHA-256.</summary>
    private static string LegacyHash(string code) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code))).ToLowerInvariant();

    // ── keyed round-trip ──────────────────────────────────────────────────────

    [Fact]
    public void Hash_Verify_RoundTrips()
    {
        var hasher = NewHasher();
        Assert.True(hasher.Verify(Code, hasher.Hash(Code)));
    }

    [Fact]
    public void Verify_WrongCode_ReturnsFalse()
    {
        var hasher = NewHasher();
        Assert.False(hasher.Verify("WRONG-CODE1", hasher.Hash(Code)));
    }

    [Fact]
    public void Hash_SameCodeTwice_ProducesDistinctSaltedValues()
    {
        var hasher = NewHasher();
        string first = hasher.Hash(Code);
        string second = hasher.Hash(Code);

        Assert.NotEqual(first, second);
        Assert.True(hasher.Verify(Code, first));
        Assert.True(hasher.Verify(Code, second));
    }

    [Fact]
    public void Hash_IsKeyed_SoAnotherInstanceKeyDoesNotVerify()
    {
        string stored = NewHasher().Hash(Code);
        Assert.False(NewHasher().Verify(Code, stored));
    }

    [Fact]
    public void Hash_DoesNotStoreBareSha256OfTheCode()
    {
        Assert.DoesNotContain(LegacyHash(Code), NewHasher().Hash(Code), StringComparison.OrdinalIgnoreCase);
    }

    // ── legacy bare-SHA-256 gate ──────────────────────────────────────────────

    [Fact]
    public void Verify_LegacyBareSha256_RejectedByDefault()
    {
        // Pins the fix: an unsalted, unkeyed digest is not a valid second factor unless the
        // operator has explicitly opened a migration window.
        Assert.False(NewHasher().Verify(Code, LegacyHash(Code)));
    }

    [Fact]
    public void Verify_LegacyBareSha256_AcceptedWhenOptedIn()
    {
        Assert.True(NewHasher(acceptLegacyCodes: true).Verify(Code, LegacyHash(Code)));
    }

    [Fact]
    public void Verify_LegacyBareSha256_WrongCode_ReturnsFalseEvenWhenOptedIn()
    {
        Assert.False(NewHasher(acceptLegacyCodes: true).Verify("WRONG-CODE1", LegacyHash(Code)));
    }

    [Fact]
    public void Verify_LegacyAcceptance_DoesNotWeakenTheKeyedFormat()
    {
        // Opting in must not turn the keyed branch into a bare-SHA-256 comparison.
        var hasher = NewHasher(acceptLegacyCodes: true);
        Assert.True(hasher.Verify(Code, hasher.Hash(Code)));
        Assert.False(hasher.Verify("WRONG-CODE1", hasher.Hash(Code)));
    }

    [Fact]
    public void IsLegacyFormat_DistinguishesStoredForms()
    {
        var hasher = NewHasher();
        Assert.True(hasher.IsLegacyFormat(LegacyHash(Code)));
        Assert.False(hasher.IsLegacyFormat(hasher.Hash(Code)));
        Assert.False(hasher.IsLegacyFormat(string.Empty));
    }

    // ── malformed stored values ───────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("hmac:v1:")]
    [InlineData("hmac:v1:no-separator")]
    [InlineData("hmac:v1::")]
    [InlineData("hmac:v1:!!!notbase64!!!:!!!notbase64!!!")]
    [InlineData("not-a-hash")]
    public void Verify_MalformedStoredValue_ReturnsFalseWithoutThrowing(string storedHash)
    {
        Assert.False(NewHasher().Verify(Code, storedHash));
        Assert.False(NewHasher(acceptLegacyCodes: true).Verify(Code, storedHash));
    }
}
