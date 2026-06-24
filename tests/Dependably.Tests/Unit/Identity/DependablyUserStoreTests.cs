using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
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

    private DependablyUserStore StoreForTenant(string tenantId)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Items[TenantContext.HttpItemsKey] =
            TenantContext.ForTenant(tenantId, tenantId);

        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);

        return new DependablyUserStore(_db, accessor, _protector);
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
        var store = new DependablyUserStore(_db, accessor, _protector);

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
    public async Task ReplaceCodesAsync_StoredColumnHoldsHashesNotPlaintext()
    {
        var store = StoreForTenant("tenantA");
        var user = new DependablyUser { Id = "uA", TenantId = "tenantA", Email = "alice@example.com" };
        const string plainCode = "RECOVERY-CODE-01";

        await store.ReplaceCodesAsync(user, [plainCode], CancellationToken.None);

        Assert.NotNull(user.RecoveryCodes);
        Assert.DoesNotContain(plainCode, user.RecoveryCodes!);

        var hashes = JsonSerializer.Deserialize<List<string>>(user.RecoveryCodes!);
        string expectedHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(plainCode))).ToLowerInvariant();
        Assert.Contains(expectedHash, hashes!);
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
}
