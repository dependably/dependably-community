using Dependably.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for <see cref="BcryptPasswordHasher{TUser}"/>, including interop with hashes
/// produced by direct <c>BCrypt.Net.BCrypt.HashPassword</c> calls (as used by FirstBootService
/// and UserService), to confirm Identity can verify all pre-existing stored hashes without
/// a migration step.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BcryptPasswordHasherTests
{
    private sealed class FakeUser { }

    private readonly BcryptPasswordHasher<FakeUser> _hasher = new();
    private readonly FakeUser _user = new();

    // ── HashPassword ──────────────────────────────────────────────────────────

    [Fact]
    public void HashPassword_ProducesNonEmptyHash()
    {
        string hash = _hasher.HashPassword(_user, "hunter2");
        Assert.False(string.IsNullOrWhiteSpace(hash));
    }

    [Fact]
    public void HashPassword_TwiceSamePw_ProducesDistinctHashes()
    {
        string a = _hasher.HashPassword(_user, "hunter2");
        string b = _hasher.HashPassword(_user, "hunter2");
        Assert.NotEqual(a, b);
    }

    // ── VerifyHashedPassword — success ────────────────────────────────────────

    [Fact]
    public void VerifyHashedPassword_CorrectPassword_ReturnsSuccess()
    {
        string hash = _hasher.HashPassword(_user, "correct-horse-battery");
        var result = _hasher.VerifyHashedPassword(_user, hash, "correct-horse-battery");
        Assert.Equal(PasswordVerificationResult.Success, result);
    }

    [Fact]
    public void VerifyHashedPassword_HashFromBcryptNet_ReturnsSuccess()
    {
        // Hashes produced by BCrypt.Net.BCrypt.HashPassword (work factor 12) must verify.
        // deepcode ignore NoHardcodedCredentials/test: static test-fixture password for a BCrypt hasher unit test, not a real credential.
        const string password = "integration-test-pw";
        string precomputedHash = BCrypt.Net.BCrypt.HashPassword(password, 12);

        var result = _hasher.VerifyHashedPassword(_user, precomputedHash, password);
        Assert.Equal(PasswordVerificationResult.Success, result);
    }

    // ── VerifyHashedPassword — failure ────────────────────────────────────────

    [Fact]
    public void VerifyHashedPassword_WrongPassword_ReturnsFailed()
    {
        string hash = _hasher.HashPassword(_user, "correct");
        var result = _hasher.VerifyHashedPassword(_user, hash, "wrong");
        Assert.Equal(PasswordVerificationResult.Failed, result);
    }

    [Fact]
    public void VerifyHashedPassword_EmptyStoredHash_ReturnsFailed()
    {
        var result = _hasher.VerifyHashedPassword(_user, string.Empty, "any");
        Assert.Equal(PasswordVerificationResult.Failed, result);
    }

    [Fact]
    public void VerifyHashedPassword_NullStoredHash_ReturnsFailed()
    {
        var result = _hasher.VerifyHashedPassword(_user, null!, "any");
        Assert.Equal(PasswordVerificationResult.Failed, result);
    }

    // ── never SuccessRehashNeeded ─────────────────────────────────────────────

    [Fact]
    public void VerifyHashedPassword_NeverReturnsSuccessRehashNeeded()
    {
        string hash = _hasher.HashPassword(_user, "pw");
        var result = _hasher.VerifyHashedPassword(_user, hash, "pw");
        Assert.NotEqual(PasswordVerificationResult.SuccessRehashNeeded, result);
    }
}
