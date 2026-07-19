using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for <see cref="SystemAdminUserStore"/> against an in-memory SQLite database.
/// Mirrors the DependablyUserStore surface, minus tenant isolation (system_admins are
/// globally unique by email).
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemAdminUserStoreTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly MfaSecretProtector _protector = new(RandomNumberGenerator.GetBytes(32));
    private readonly RecoveryCodeHasher _recoveryHasher = new(
        RandomNumberGenerator.GetBytes(32),
        acceptLegacyCodes: false,
        NullLogger<RecoveryCodeHasher>.Instance);

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO system_admins (id, email, password_hash) " +
            "VALUES ('sa1','admin@example.com','$hash$')");
    }

    public async Task DisposeAsync()
    {
        _protector.Dispose();
        await _db.DisposeAsync();
    }

    private SystemAdminUserStore Store(IRecoveryCodeHasher? recoveryHasher = null) =>
        new(_db, _protector, recoveryHasher ?? _recoveryHasher);

    // ── FindByIdAsync ─────────────────────────────────────────────────────────

    [Fact]
    public async Task FindByIdAsync_ExistingId_ReturnsUser()
    {
        var user = await Store().FindByIdAsync("sa1", CancellationToken.None);
        Assert.NotNull(user);
        Assert.Equal("sa1", user!.Id);
        Assert.Equal("admin@example.com", user.Email);
    }

    [Fact]
    public async Task FindByIdAsync_MissingId_ReturnsNull()
    {
        var user = await Store().FindByIdAsync("missing", CancellationToken.None);
        Assert.Null(user);
    }

    // ── FindByEmailAsync — case-insensitive ───────────────────────────────────

    [Fact]
    public async Task FindByEmailAsync_ExactMatch_ReturnsUser()
    {
        var user = await Store().FindByEmailAsync("admin@example.com", CancellationToken.None);
        Assert.NotNull(user);
        Assert.Equal("sa1", user!.Id);
    }

    [Fact]
    public async Task FindByEmailAsync_UppercaseInput_ReturnsUser()
    {
        var user = await Store().FindByEmailAsync("ADMIN@EXAMPLE.COM", CancellationToken.None);
        Assert.NotNull(user);
        Assert.Equal("sa1", user!.Id);
    }

    [Fact]
    public async Task FindByEmailAsync_MissingEmail_ReturnsNull()
    {
        var user = await Store().FindByEmailAsync("nobody@example.com", CancellationToken.None);
        Assert.Null(user);
    }

    // ── FindByNameAsync — email is the username ───────────────────────────────

    [Fact]
    public async Task FindByNameAsync_CaseInsensitive_ReturnsUser()
    {
        var user = await Store().FindByNameAsync("ADMIN@EXAMPLE.COM", CancellationToken.None);
        Assert.NotNull(user);
        Assert.Equal("sa1", user!.Id);
    }

    // ── authenticator key encryption ──────────────────────────────────────────

    [Fact]
    public async Task SetAuthenticatorKey_GetAuthenticatorKey_RoundTrips()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };
        const string totpKey = "BASE32TOTPKEY";

        await store.SetAuthenticatorKeyAsync(user, totpKey, CancellationToken.None);

        Assert.NotEqual(totpKey, user.AuthenticatorKey); // stored as ciphertext
        string? recovered = await store.GetAuthenticatorKeyAsync(user, CancellationToken.None);
        Assert.Equal(totpKey, recovered);
    }

    [Fact]
    public async Task GetAuthenticatorKeyAsync_NullKey_ReturnsNull()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };
        Assert.Null(await store.GetAuthenticatorKeyAsync(user, CancellationToken.None));
    }

    // ── recovery codes ────────────────────────────────────────────────────────

    [Fact]
    public async Task ReplaceCodesAsync_CountCodesAsync_ReturnsCorrectCount()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };

        await store.ReplaceCodesAsync(user, ["X1", "X2", "X3"], CancellationToken.None);
        Assert.Equal(3, await store.CountCodesAsync(user, CancellationToken.None));
    }

    [Fact]
    public async Task ReplaceCodesAsync_StoredColumnHoldsKeyedHashesNotPlaintextNorBareSha256()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };
        const string plainCode = "PLAIN-RECOVERY";

        await store.ReplaceCodesAsync(user, [plainCode], CancellationToken.None);

        Assert.NotNull(user.RecoveryCodes);
        Assert.DoesNotContain(plainCode, user.RecoveryCodes!);

        var hashes = JsonSerializer.Deserialize<List<string>>(user.RecoveryCodes!);
        Assert.All(hashes!, h => Assert.StartsWith("hmac:v1:", h));
        string bareSha256 = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(plainCode))).ToLowerInvariant();
        Assert.DoesNotContain(bareSha256, hashes!);
    }

    [Fact]
    public async Task RedeemCodeAsync_LegacyBareSha256Code_RejectedWhenLegacyAcceptanceOff()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };
        const string legacyCode = "LEGACY-SA-CODE";
        await SeedLegacyCodeAsync(store, user, legacyCode);

        Assert.False(await store.RedeemCodeAsync(user, legacyCode, CancellationToken.None));
        Assert.Equal(1, await store.CountCodesAsync(user, CancellationToken.None));
    }

    [Fact]
    public async Task RedeemCodeAsync_LegacyBareSha256Code_RedeemsWhenLegacyAcceptanceOn()
    {
        var store = Store(new RecoveryCodeHasher(
            RandomNumberGenerator.GetBytes(32),
            acceptLegacyCodes: true,
            NullLogger<RecoveryCodeHasher>.Instance));
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };
        const string legacyCode = "LEGACY-SA-CODE";
        await SeedLegacyCodeAsync(store, user, legacyCode);

        Assert.True(await store.RedeemCodeAsync(user, legacyCode, CancellationToken.None));
        Assert.Equal(0, await store.CountCodesAsync(user, CancellationToken.None));
        Assert.False(await store.RedeemCodeAsync(user, legacyCode, CancellationToken.None));
    }

    /// <summary>
    /// Stores <paramref name="code"/> the way a pre-upgrade release did: unsalted bare
    /// SHA-256 hex, written straight into the recovery-code column.
    /// </summary>
    private static async Task SeedLegacyCodeAsync(SystemAdminUserStore store, SystemAdminUser user, string code)
    {
        string legacyHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(code))).ToLowerInvariant();
        user.RecoveryCodes = JsonSerializer.Serialize(new List<string> { legacyHash });
        await store.UpdateAsync(user, CancellationToken.None);
    }

    [Fact]
    public async Task RedeemCodeAsync_ValidCode_ReturnsTrue()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };

        await store.ReplaceCodesAsync(user, ["RCODE1", "RCODE2"], CancellationToken.None);
        bool redeemed = await store.RedeemCodeAsync(user, "RCODE1", CancellationToken.None);

        Assert.True(redeemed);
        Assert.Equal(1, await store.CountCodesAsync(user, CancellationToken.None));
    }

    [Fact]
    public async Task RedeemCodeAsync_DoubleRedeem_SecondReturnsFalse()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };

        await store.ReplaceCodesAsync(user, ["CODE"], CancellationToken.None);
        Assert.True(await store.RedeemCodeAsync(user, "CODE", CancellationToken.None));
        Assert.False(await store.RedeemCodeAsync(user, "CODE", CancellationToken.None));
    }

    // ── two-factor enabled ────────────────────────────────────────────────────

    [Fact]
    public async Task SetTwoFactorEnabled_GetTwoFactorEnabled_RoundTrips()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };

        await store.SetTwoFactorEnabledAsync(user, true, CancellationToken.None);
        Assert.True(await store.GetTwoFactorEnabledAsync(user, CancellationToken.None));
    }

    // ── security stamp ────────────────────────────────────────────────────────

    [Fact]
    public async Task SetSecurityStamp_GetSecurityStamp_RoundTrips()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };

        await store.SetSecurityStampAsync(user, "stampval", CancellationToken.None);
        Assert.Equal("stampval", await store.GetSecurityStampAsync(user, CancellationToken.None));
    }

    // ── mixed partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task RedeemCodeAsync_MixedCodes_OnlyMatchingCodeIsConsumed()
    {
        var store = Store();
        var user = new SystemAdminUser { Id = "sa1", Email = "admin@example.com" };

        await store.ReplaceCodesAsync(user, ["S1", "S2", "S3"], CancellationToken.None);

        bool second = await store.RedeemCodeAsync(user, "S2", CancellationToken.None);
        Assert.True(second);
        Assert.Equal(2, await store.CountCodesAsync(user, CancellationToken.None));

        // S1 and S3 are still intact.
        Assert.True(await store.RedeemCodeAsync(user, "S1", CancellationToken.None));
        Assert.True(await store.RedeemCodeAsync(user, "S3", CancellationToken.None));
        Assert.Equal(0, await store.CountCodesAsync(user, CancellationToken.None));
    }

    // ── optimistic concurrency: no stale snapshot resurrects a consumed code ──────

    [Fact]
    public async Task RedeemCodeAsync_ConcurrentRedeemFromStaleSnapshot_DoesNotResurrectConsumedCode()
    {
        var store = Store();
        await SeedPersistedCodesAsync(store, ["S1", "S2", "S3"]);

        var requestA = await store.FindByIdAsync("sa1", CancellationToken.None);
        var requestB = await store.FindByIdAsync("sa1", CancellationToken.None);

        Assert.True(await store.RedeemCodeAsync(requestA!, "S1", CancellationToken.None));
        Assert.False(await store.RedeemCodeAsync(requestB!, "S2", CancellationToken.None));

        var fresh = await store.FindByIdAsync("sa1", CancellationToken.None);
        Assert.Equal(2, await store.CountCodesAsync(fresh!, CancellationToken.None));
        Assert.False(await store.RedeemCodeAsync(fresh!, "S1", CancellationToken.None));
    }

    [Fact]
    public async Task UpdateAsync_StaleSnapshotAfterConcurrentRedeem_FailsAndPreservesRedemption()
    {
        var store = Store();
        await SeedPersistedCodesAsync(store, ["S1", "S2", "S3"]);

        var login = await store.FindByIdAsync("sa1", CancellationToken.None);
        var settings = await store.FindByIdAsync("sa1", CancellationToken.None);

        Assert.True(await store.RedeemCodeAsync(login!, "S1", CancellationToken.None));

        await store.SetTwoFactorEnabledAsync(settings!, false, CancellationToken.None);
        var result = await store.UpdateAsync(settings!, CancellationToken.None);
        Assert.False(result.Succeeded);

        var fresh = await store.FindByIdAsync("sa1", CancellationToken.None);
        Assert.True(fresh!.TwoFactorEnabled);
        Assert.Equal(2, await store.CountCodesAsync(fresh, CancellationToken.None));
        Assert.False(await store.RedeemCodeAsync(fresh, "S1", CancellationToken.None));
    }

    private static async Task SeedPersistedCodesAsync(SystemAdminUserStore store, string[] codes)
    {
        var seed = await store.FindByIdAsync("sa1", CancellationToken.None);
        await store.ReplaceCodesAsync(seed!, codes, CancellationToken.None);
        await store.SetTwoFactorEnabledAsync(seed!, true, CancellationToken.None);
        Assert.True((await store.UpdateAsync(seed!, CancellationToken.None)).Succeeded);
    }
}
