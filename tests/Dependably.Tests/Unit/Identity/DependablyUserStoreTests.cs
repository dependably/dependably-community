using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for <see cref="DependablyUserStore"/> against an in-memory SQLite database.
/// Covers the BOLA isolation guarantee (same email in two tenants — only the matching tenant
/// row is returned), the authenticator-key encryption round-trip, recovery-code hash storage
/// and redemption, and security-stamp set/get.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DependablyUserStoreTests : IAsyncLifetime
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
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('tenantA', 'acme')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('tenantB', 'beta')");

        // Two users with identical emails, one per tenant — the classic BOLA setup.
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role, account_type) " +
            "VALUES ('uA','tenantA','alice@example.com','$hash$','member','forms')");
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role, account_type) " +
            "VALUES ('uB','tenantB','alice@example.com','$hash$','member','forms')");
    }

    public async Task DisposeAsync()
    {
        _protector.Dispose();
        await _db.DisposeAsync();
    }

    private DependablyUserStore StoreForTenant(string tenantId, IRecoveryCodeHasher? recoveryHasher = null)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Items[TenantContext.HttpItemsKey] =
            TenantContext.ForTenant(tenantId, tenantId);

        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);

        return new DependablyUserStore(_db, accessor, _protector, recoveryHasher ?? _recoveryHasher);
    }

    // ── BOLA isolation ────────────────────────────────────────────────────────

    [Fact]
    public async Task FindByEmailAsync_ReturnsOnlyMatchingTenantRow()
    {
        var storeA = StoreForTenant("tenantA");
        var result = await storeA.FindByEmailAsync("alice@example.com", CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("uA", result!.Id);
        Assert.Equal("tenantA", result.TenantId);
    }

    [Fact]
    public async Task FindByEmailAsync_TenantB_DoesNotReturnTenantARow()
    {
        var storeB = StoreForTenant("tenantB");
        var result = await storeB.FindByEmailAsync("alice@example.com", CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("uB", result!.Id);
        Assert.Equal("tenantB", result.TenantId);
    }

    [Fact]
    public async Task FindByNameAsync_IsolatedByTenant()
    {
        var storeA = StoreForTenant("tenantA");
        var user = await storeA.FindByNameAsync("alice@example.com", CancellationToken.None);
        Assert.Equal("uA", user?.Id);
    }

    // ── FindByIdAsync is tenant-agnostic (PK) ────────────────────────────────

    [Fact]
    public async Task FindByIdAsync_ReturnsCorrectRow_RegardlessOfCurrentTenant()
    {
        // FindByIdAsync does not require a tenant context — it is a PK lookup.
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns((HttpContext?)null);
        var store = new DependablyUserStore(_db, accessor, _protector, _recoveryHasher);

        var user = await store.FindByIdAsync("uA", CancellationToken.None);
        Assert.Equal("uA", user?.Id);
        Assert.Equal("tenantA", user?.TenantId);
    }

    // ── authenticator key encryption ──────────────────────────────────────────

    [Fact]
    public async Task SetAuthenticatorKey_ThenGet_RoundTrips()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        const string totpKey = "JBSWY3DPEHPK3PXP";
        await store.SetAuthenticatorKeyAsync(user, totpKey, CancellationToken.None);

        // The in-memory AuthenticatorKey property now holds the encrypted form.
        Assert.NotEqual(totpKey, user.AuthenticatorKey);

        // GetAuthenticatorKeyAsync decrypts and returns the original plaintext.
        string? recovered = await store.GetAuthenticatorKeyAsync(user, CancellationToken.None);
        Assert.Equal(totpKey, recovered);
    }

    [Fact]
    public async Task SetAuthenticatorKey_RawColumnNotPlaintext()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        const string totpKey = "JBSWY3DPEHPK3PXP";
        await store.SetAuthenticatorKeyAsync(user, totpKey, CancellationToken.None);

        // The value on the object must not be the plaintext.
        Assert.NotEqual(totpKey, user.AuthenticatorKey);
        Assert.False(string.IsNullOrEmpty(user.AuthenticatorKey));
    }

    [Fact]
    public async Task GetAuthenticatorKeyAsync_NullKey_ReturnsNull()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        string? result = await store.GetAuthenticatorKeyAsync(user, CancellationToken.None);
        Assert.Null(result);
    }

    // ── recovery codes ────────────────────────────────────────────────────────

    [Fact]
    public async Task ReplaceCodesAsync_CountCodesAsync_ReturnsCorrectCount()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        await store.ReplaceCodesAsync(user, ["AAA", "BBB", "CCC"], CancellationToken.None);
        int count = await store.CountCodesAsync(user, CancellationToken.None);

        Assert.Equal(3, count);
    }

    [Fact]
    public async Task ReplaceCodesAsync_StoredColumnHoldsKeyedHashesNotPlaintextNorBareSha256()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };
        const string plainCode = "RECOVERY-CODE-01";

        await store.ReplaceCodesAsync(user, [plainCode], CancellationToken.None);

        Assert.NotNull(user.RecoveryCodes);
        Assert.DoesNotContain(plainCode, user.RecoveryCodes!);

        var hashes = JsonSerializer.Deserialize<List<string>>(user.RecoveryCodes!);
        // Salted + keyed form, not the old unsalted bare SHA-256 hex.
        Assert.All(hashes!, h => Assert.StartsWith("hmac:v1:", h));
        string bareSha256 = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(plainCode))).ToLowerInvariant();
        Assert.DoesNotContain(bareSha256, hashes!);
    }

    [Fact]
    public async Task ReplaceCodesAsync_IdenticalCodes_ProduceDistinctSaltedHashes()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        // Two identical plaintext codes must hash to two DISTINCT stored values (per-code salt),
        // so a DB dump cannot spot duplicate codes or precompute a single rainbow entry.
        await store.ReplaceCodesAsync(user, ["SAME-CODE", "SAME-CODE"], CancellationToken.None);

        var hashes = JsonSerializer.Deserialize<List<string>>(user.RecoveryCodes!);
        Assert.Equal(2, hashes!.Count);
        Assert.NotEqual(hashes[0], hashes[1]);
    }

    [Fact]
    public async Task RedeemCodeAsync_LegacyBareSha256Code_RejectedWhenLegacyAcceptanceOff()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };
        const string legacyCode = "LEGACY-CODE-99";
        await SeedLegacyCodeAsync(store, user, legacyCode);

        // The weak stored form is not a valid second factor on a default instance.
        Assert.False(await store.RedeemCodeAsync(user, legacyCode, CancellationToken.None));

        // The rejected code is left in place rather than silently consumed, so it still
        // redeems if the operator opens a migration window.
        Assert.Equal(1, await store.CountCodesAsync(user, CancellationToken.None));
    }

    [Fact]
    public async Task RedeemCodeAsync_LegacyBareSha256Code_RedeemsWhenLegacyAcceptanceOn()
    {
        var legacyHasher = new RecoveryCodeHasher(
            RandomNumberGenerator.GetBytes(32),
            acceptLegacyCodes: true,
            NullLogger<RecoveryCodeHasher>.Instance);
        var store = StoreForTenant("tenantA", legacyHasher);
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };
        const string legacyCode = "LEGACY-CODE-99";
        await SeedLegacyCodeAsync(store, user, legacyCode);

        bool redeemed = await store.RedeemCodeAsync(user, legacyCode, CancellationToken.None);
        Assert.True(redeemed);
        Assert.Equal(0, await store.CountCodesAsync(user, CancellationToken.None));

        // One-time use: a second attempt fails.
        Assert.False(await store.RedeemCodeAsync(user, legacyCode, CancellationToken.None));
    }

    /// <summary>
    /// Stores <paramref name="code"/> the way a pre-upgrade release did: unsalted bare
    /// SHA-256 hex, written straight into the recovery-code column.
    /// </summary>
    private static async Task SeedLegacyCodeAsync(DependablyUserStore store, DependablyUser user, string code)
    {
        string legacyHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(code))).ToLowerInvariant();
        user.RecoveryCodes = JsonSerializer.Serialize(new List<string> { legacyHash });
        await store.UpdateAsync(user, CancellationToken.None);
    }

    [Fact]
    public async Task RedeemCodeAsync_ValidCode_ReturnsTrueAndDecrementsCount()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        await store.ReplaceCodesAsync(user, ["AAA", "BBB"], CancellationToken.None);
        bool redeemed = await store.RedeemCodeAsync(user, "AAA", CancellationToken.None);

        Assert.True(redeemed);
        Assert.Equal(1, await store.CountCodesAsync(user, CancellationToken.None));
    }

    [Fact]
    public async Task RedeemCodeAsync_DoubleRedeem_SecondReturnsFalse()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        await store.ReplaceCodesAsync(user, ["AAA"], CancellationToken.None);
        bool first = await store.RedeemCodeAsync(user, "AAA", CancellationToken.None);
        bool second = await store.RedeemCodeAsync(user, "AAA", CancellationToken.None);

        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public async Task RedeemCodeAsync_WrongCode_ReturnsFalse()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        await store.ReplaceCodesAsync(user, ["AAA"], CancellationToken.None);
        bool result = await store.RedeemCodeAsync(user, "ZZZ", CancellationToken.None);

        Assert.False(result);
    }

    // ── two-factor enabled ────────────────────────────────────────────────────

    [Fact]
    public async Task SetTwoFactorEnabled_GetTwoFactorEnabled_RoundTrips()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        await store.SetTwoFactorEnabledAsync(user, true, CancellationToken.None);
        bool enabled = await store.GetTwoFactorEnabledAsync(user, CancellationToken.None);

        Assert.True(enabled);
    }

    // ── security stamp ────────────────────────────────────────────────────────

    [Fact]
    public async Task SetSecurityStamp_GetSecurityStamp_RoundTrips()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        const string stamp = "abc123stamp";
        await store.SetSecurityStampAsync(user, stamp, CancellationToken.None);
        string? recovered = await store.GetSecurityStampAsync(user, CancellationToken.None);

        Assert.Equal(stamp, recovered);
    }

    // ── mixed partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task RedeemCodeAsync_MixedCodes_OnlyMatchingCodeIsConsumed()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };

        await store.ReplaceCodesAsync(user, ["CODE1", "CODE2", "CODE3"], CancellationToken.None);

        // Redeem the middle code.
        bool middle = await store.RedeemCodeAsync(user, "CODE2", CancellationToken.None);

        Assert.True(middle);
        Assert.Equal(2, await store.CountCodesAsync(user, CancellationToken.None));

        // The other two codes are still valid.
        Assert.True(await store.RedeemCodeAsync(user, "CODE1", CancellationToken.None));
        Assert.True(await store.RedeemCodeAsync(user, "CODE3", CancellationToken.None));
        Assert.Equal(0, await store.CountCodesAsync(user, CancellationToken.None));
    }

    // ── optimistic concurrency: no stale snapshot resurrects a consumed code ──────

    /// <summary>
    /// Persists three recovery codes, then loads two independent snapshots of the same row.
    /// One redeems, the other tries to redeem a different code from its now-stale snapshot.
    /// The column-scoped guard must reject the stale write so the already-consumed code is
    /// never restored to the list.
    /// </summary>
    [Fact]
    public async Task RedeemCodeAsync_ConcurrentRedeemFromStaleSnapshot_DoesNotResurrectConsumedCode()
    {
        var store = StoreForTenant("tenantA");
        await SeedPersistedCodesAsync(store, ["AAA", "BBB", "CCC"]);

        var requestA = await store.FindByIdAsync("uA", CancellationToken.None);
        var requestB = await store.FindByIdAsync("uA", CancellationToken.None);

        // Request A redeems AAA first and commits [BBB, CCC].
        Assert.True(await store.RedeemCodeAsync(requestA!, "AAA", CancellationToken.None));

        // Request B, holding the pre-redemption snapshot, redeems a different code. Its
        // whole-list write would resurrect AAA; the guard must make it lose the race.
        Assert.False(await store.RedeemCodeAsync(requestB!, "BBB", CancellationToken.None));

        var fresh = await store.FindByIdAsync("uA", CancellationToken.None);
        Assert.Equal(2, await store.CountCodesAsync(fresh!, CancellationToken.None));
        Assert.False(await store.RedeemCodeAsync(fresh!, "AAA", CancellationToken.None));
    }

    /// <summary>
    /// The finding's exact scenario: request A logs in via a recovery code (redeems and commits),
    /// while a concurrent authenticated Settings session (request B) disables MFA from a snapshot
    /// taken before A's write. B's whole-row UPDATE must be rejected by optimistic concurrency
    /// rather than writing its stale recovery-code list — which would resurrect the consumed code
    /// and clobber A's state.
    /// </summary>
    [Fact]
    public async Task UpdateAsync_StaleSnapshotAfterConcurrentRedeem_FailsAndPreservesRedemption()
    {
        var store = StoreForTenant("tenantA");
        await SeedPersistedCodesAsync(store, ["AAA", "BBB", "CCC"]);

        var login = await store.FindByIdAsync("uA", CancellationToken.None);
        var settings = await store.FindByIdAsync("uA", CancellationToken.None);

        Assert.True(await store.RedeemCodeAsync(login!, "AAA", CancellationToken.None));

        await store.SetTwoFactorEnabledAsync(settings!, false, CancellationToken.None);
        var result = await store.UpdateAsync(settings!, CancellationToken.None);
        Assert.False(result.Succeeded);

        var fresh = await store.FindByIdAsync("uA", CancellationToken.None);
        Assert.True(fresh!.TwoFactorEnabled);
        Assert.Equal(2, await store.CountCodesAsync(fresh, CancellationToken.None));
        Assert.False(await store.RedeemCodeAsync(fresh, "AAA", CancellationToken.None));
    }

    /// <summary>Persists a hashed recovery-code list and enables MFA on the seeded uA row.</summary>
    private static async Task SeedPersistedCodesAsync(DependablyUserStore store, string[] codes)
    {
        var seed = await store.FindByIdAsync("uA", CancellationToken.None);
        await store.ReplaceCodesAsync(seed!, codes, CancellationToken.None);
        await store.SetTwoFactorEnabledAsync(seed!, true, CancellationToken.None);
        Assert.True((await store.UpdateAsync(seed!, CancellationToken.None)).Succeeded);
    }
}
