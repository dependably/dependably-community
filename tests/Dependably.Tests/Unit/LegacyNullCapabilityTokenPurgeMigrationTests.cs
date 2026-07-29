using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Schema migration <c>purge_legacy_null_capability_tokens</c>: API tokens minted before the
/// <c>capabilities</c> column existed carry NULL, and the authorization layer denies them
/// outright rather than letting them inherit their owner's role. The chosen policy is
/// invalidation, not backfill — the rows are deleted so an operator sees the token vanish and
/// re-mints one, instead of debugging a token the UI still lists as live. These tests pin the
/// purge, the rows it must leave alone, and the mint-time guard that stops the state returning.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LegacyNullCapabilityTokenPurgeMigrationTests : IAsyncLifetime
{
    private const string MigrationName = "purge_legacy_null_capability_tokens";

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync("""
            INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES
                ('u1','o1','u1@example.com','','owner')
            """);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // Seeds the rows a pre-capabilities database holds, then rewinds the ledger so the
    // one-shot runs again on the next initializer pass — the upgrade this migration models.
    private async Task SeedLegacyRowsAndRewindLedgerAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities) VALUES
                ('ut-null','o1','u1','hash-ut-null', NULL),
                ('ut-empty','o1','u1','hash-ut-empty', '   '),
                ('ut-emptyarray','o1','u1','hash-ut-emptyarray', '[]'),
                ('ut-granting','o1','u1','hash-ut-granting', '["read:metadata"]')
            """);
        await conn.ExecuteAsync("""
            INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities) VALUES
                ('st-null','o1','ci-null','hash-st-null', NULL),
                ('st-emptyarray','o1','ci-emptyarray','hash-st-emptyarray', '[]'),
                ('st-granting','o1','ci-granting','hash-st-granting', '["publish:npm"]')
            """);
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name = @name", new { name = MigrationName });
    }

    private async Task<string[]> UserTokenIdsAsync()
    {
        await using var conn = await _db.OpenAsync();
        var ids = await conn.QueryAsync<string>("SELECT id FROM user_tokens ORDER BY id");
        return ids.ToArray();
    }

    private async Task<string[]> ServiceTokenIdsAsync()
    {
        await using var conn = await _db.OpenAsync();
        var ids = await conn.QueryAsync<string>("SELECT id FROM service_tokens ORDER BY id");
        return ids.ToArray();
    }

    [Fact]
    public async Task Upgrade_DeletesEveryCapabilityLessToken()
    {
        await SeedLegacyRowsAndRewindLedgerAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        Assert.Equal(new[] { "ut-granting" }, await UserTokenIdsAsync());
        Assert.Equal(new[] { "st-granting" }, await ServiceTokenIdsAsync());
    }

    // Adversarial twin: the purge keys on the capability column alone, so a token that grants
    // something must survive it regardless of which table or tenant it belongs to. Without this,
    // a predicate that over-matched would still pass the assertion above.
    [Fact]
    public async Task Upgrade_LeavesGrantingTokensUsable()
    {
        await SeedLegacyRowsAndRewindLedgerAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        string? userCaps = await conn.ExecuteScalarAsync<string>(
            "SELECT capabilities FROM user_tokens WHERE id = 'ut-granting'");
        string? serviceCaps = await conn.ExecuteScalarAsync<string>(
            "SELECT capabilities FROM service_tokens WHERE id = 'st-granting'");

        Assert.Equal("[\"read:metadata\"]", userCaps);
        Assert.Equal("[\"publish:npm\"]", serviceCaps);
    }

    // The policy is invalidation: after the upgrade the legacy token must not authenticate at
    // all. Denial-by-zero-capabilities would leave it resolving here and failing later at the
    // authorization gate, which is the confusing state this migration exists to remove.
    [Fact]
    public async Task PurgedLegacyToken_NoLongerResolves()
    {
        const string legacyRaw = "dpb_legacy_raw_token_value";
        string legacyHash = TokenRepository.HashToken(legacyRaw);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities)
                VALUES ('ut-legacy','o1','u1',@hash, NULL)
                """,
                new { hash = legacyHash });
            await conn.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = @name", new { name = MigrationName });
        }

        var tokens = new TokenRepository(_db, _clock);
        Assert.NotNull(await tokens.ResolveAsync(legacyRaw));

        await new SchemaInitializer(_db).InitializeAsync();

        Assert.Null(await tokens.ResolveAsync(legacyRaw));
    }

    // The ledger is what makes a non-idempotent one-shot run exactly once; a second pass must
    // not delete tokens minted in between.
    [Fact]
    public async Task SecondInitializerPass_DoesNotRePurge()
    {
        await SeedLegacyRowsAndRewindLedgerAsync();
        await new SchemaInitializer(_db).InitializeAsync();

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities)
                VALUES ('ut-after','o1','u1','hash-ut-after', '["read:artifact"]')
                """);
        }

        await new SchemaInitializer(_db).InitializeAsync();

        Assert.Equal(new[] { "ut-after", "ut-granting" }, await UserTokenIdsAsync());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("[]")]
    public async Task CreateUserToken_RefusesCapabilityLessValue(string capabilities)
    {
        var tokens = new TokenRepository(_db, _clock);

        await Assert.ThrowsAsync<ArgumentException>(
            () => tokens.CreateUserTokenAsync("o1", "u1", capabilities, expiresAt: null));

        Assert.Empty(await UserTokenIdsAsync());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("[]")]
    public async Task CreateServiceToken_RefusesCapabilityLessValue(string capabilities)
    {
        var tokens = new TokenRepository(_db, _clock);

        await Assert.ThrowsAsync<ArgumentException>(
            () => tokens.CreateServiceTokenAsync("o1", "ci", capabilities, expiresAt: null));

        Assert.Empty(await ServiceTokenIdsAsync());
    }

    // Adversarial twin for the guard: a real capability set still mints.
    [Fact]
    public async Task CreateToken_AcceptsAGrantingCapabilitySet()
    {
        var tokens = new TokenRepository(_db, _clock);

        var (_, userRecord) = await tokens.CreateUserTokenAsync(
            "o1", "u1", "[\"read:metadata\"]", expiresAt: null);
        var (_, serviceRecord) = await tokens.CreateServiceTokenAsync(
            "o1", "ci", "[\"publish:npm\"]", expiresAt: null);

        Assert.Equal("[\"read:metadata\"]", userRecord.Capabilities);
        Assert.Equal("[\"publish:npm\"]", serviceRecord.Capabilities);
    }
}
