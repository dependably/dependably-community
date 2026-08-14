using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Account emails are stored canonically and enforced case-insensitively.
///
/// Every account lookup folds case (<c>WHERE lower(email) = lower(@email)</c>) while
/// <c>UNIQUE (tenant_id, email)</c> compares bytes. Without a canonical write form, an actor
/// holding <c>tenant:configure</c> can invite <c>Owner@corp.com</c> alongside the existing
/// <c>owner@corp.com</c> and end up with two accounts that both satisfy every lookup — after
/// which which row authenticates for that address, and which one a password-reset link binds to,
/// is not decided by the address.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailCanonicalizationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public Task InitializeAsync() => new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static InviteRecord Invite(string orgId, string email) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        OrgId = orgId,
        Email = email,
        Role = "member",
        CreatedBy = "someone",
        CreatedAt = DateTimeOffset.UnixEpoch,
        ExpiresAt = DateTimeOffset.UnixEpoch.AddDays(1),
        AcceptedAt = null
    };

    private async Task<int> CountUsersAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM users WHERE tenant_id = @orgId", new { orgId });
    }

    /// <summary>
    /// The exploit, end to end: an invite addressed to a different casing of a member's address
    /// must not mint a second account. Mixed by construction — a genuinely new address in the same
    /// tenant, accepted from the same code path in the same test, still creates its account, so
    /// the rule cannot be satisfied by refusing invites.
    /// </summary>
    [Fact]
    public async Task InviteForACaseVariantOfAnExistingAccount_IsRefused_WhileANewAddressStillJoins()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "o-acme");
        await UserSeeder.InsertAsync(_db, orgId, "owner@corp.com", role: "owner");

        var sut = new UserService(_db, new OrgRepository(_db));

        string? collision = await sut.CreateFromInviteAsync(
            Invite(orgId, "Owner@corp.com"), "InvitePassword12345");
        Assert.Null(collision);
        Assert.Equal(1, await CountUsersAsync(orgId));

        string? fresh = await sut.CreateFromInviteAsync(
            Invite(orgId, "Newcomer@corp.com"), "InvitePassword12345");
        Assert.NotNull(fresh);
        Assert.Equal(2, await CountUsersAsync(orgId));
    }

    [Fact]
    public async Task InviteAcceptance_StoresTheAddressCanonically()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "o-acme");
        var sut = new UserService(_db, new OrgRepository(_db));

        string? userId = await sut.CreateFromInviteAsync(
            Invite(orgId, "  MiXeD@Corp.Com "), "InvitePassword12345");
        Assert.NotNull(userId);

        await using var conn = await _db.OpenAsync();
        string? stored = await conn.ExecuteScalarAsync<string>(
            "SELECT email FROM users WHERE id = @userId", new { userId });
        Assert.Equal("mixed@corp.com", stored);
    }

    /// <summary>
    /// The same address in another tenant is a different account — the tenant-scoped constraint
    /// must not become a global one.
    /// </summary>
    [Fact]
    public async Task TheSameAddressInAnotherTenant_IsStillItsOwnAccount()
    {
        string orgA = await OrgSeeder.InsertAsync(_db, "o-a");
        string orgB = await OrgSeeder.InsertAsync(_db, "o-b");
        await UserSeeder.InsertAsync(_db, orgA, "shared@corp.com");

        var sut = new UserService(_db, new OrgRepository(_db));

        Assert.NotNull(await sut.CreateFromInviteAsync(
            Invite(orgB, "Shared@corp.com"), "InvitePassword12345"));
        Assert.Equal(1, await CountUsersAsync(orgA));
        Assert.Equal(1, await CountUsersAsync(orgB));
    }

    /// <summary>
    /// A password-reset lookup and the login lookup must elect the same row when a legacy database
    /// still holds two case-variant accounts — otherwise a reset link resets an account other than
    /// the one that address logs in as. Both order by <c>created_at, id</c>, so the original
    /// account wins and the later duplicate can never take the address over.
    /// </summary>
    [Fact]
    public async Task FindIdByEmail_WithLegacyCaseVariantRows_ElectsTheOldestRow()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "o-acme");
        await DropCaseInsensitiveIndexAsync();

        // The duplicate is inserted FIRST so it also wins any natural (unordered) scan: the test
        // has to distinguish "the oldest account" from "whichever row the engine reaches first".
        string impostor = await UserSeeder.InsertAsync(_db, orgId, "Owner@corp.com");
        string original = await UserSeeder.InsertAsync(_db, orgId, "owner@corp.com");
        await SetCreatedAtAsync(original, "2026-01-01T00:00:00Z");
        await SetCreatedAtAsync(impostor, "2026-06-01T00:00:00Z");

        var sut = new UserService(_db, new OrgRepository(_db));

        Assert.Equal(original, await sut.FindIdByEmailAsync(orgId, "owner@corp.com"));
        Assert.Equal(original, await sut.FindIdByEmailAsync(orgId, "OWNER@CORP.COM"));
    }

    /// <summary>
    /// The upgrade path. A database that predates canonical storage can already hold two rows
    /// differing only in case, and the case-insensitive unique index cannot be created over them.
    /// Schema init must report that and carry on — an exception there aborts the apply, which on
    /// SQLite silently skips every remaining statement of the batch and crash-loops the boot.
    /// Both rows survive untouched, and the rest of schema init still runs.
    /// </summary>
    [Fact]
    public async Task SchemaInit_WithLegacyCaseVariantRows_ReportsAndCarriesOn()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "o-acme");
        await DropCaseInsensitiveIndexAsync();
        await UserSeeder.InsertAsync(_db, orgId, "owner@corp.com");
        await UserSeeder.InsertAsync(_db, orgId, "Owner@corp.com");

        await new SchemaInitializer(_db).InitializeAsync();

        // No crash, both accounts intact, and the mixed-case row is deliberately NOT rewritten:
        // lowercasing it would collide with its twin on the byte-exact UNIQUE.
        Assert.Equal(2, await CountUsersAsync(orgId));
        Assert.False(await IndexExistsAsync());
        await using (var conn = await _db.OpenAsync())
        {
            Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM users WHERE email = 'Owner@corp.com'"));
        }

        // Once the operator resolves the collision, the next boot installs the index.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM users WHERE email = 'Owner@corp.com'");
        }

        await new SchemaInitializer(_db).InitializeAsync();
        Assert.True(await IndexExistsAsync());
    }

    /// <summary>
    /// Rows already stored in mixed case, with no collision, are rewritten to the canonical form so
    /// the byte-exact UNIQUE and the folded lookups describe the same account set.
    /// </summary>
    [Fact]
    public async Task SchemaInit_CanonicalizesExistingRowsWhenNothingCollides()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "o-acme");
        await DropCaseInsensitiveIndexAsync();
        string userId = await UserSeeder.InsertAsync(_db, orgId, "Legacy@Corp.Com");

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        Assert.Equal("legacy@corp.com", await conn.ExecuteScalarAsync<string?>(
            "SELECT email FROM users WHERE id = @userId", new { userId }));
        Assert.True(await IndexExistsAsync());
    }

    /// <summary>
    /// With the index installed, a writer that forgets to canonicalize cannot land a case-variant
    /// duplicate — the constraint, not the caller's diligence, is what holds the invariant.
    /// </summary>
    [Fact]
    public async Task RawInsertOfACaseVariant_IsRejectedByTheIndex()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "o-acme");
        await UserSeeder.InsertAsync(_db, orgId, "owner@corp.com");

        await Assert.ThrowsAnyAsync<Exception>(
            () => UserSeeder.InsertAsync(_db, orgId, "OWNER@corp.com"));
    }

    private async Task DropCaseInsensitiveIndexAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("DROP INDEX IF EXISTS idx_users_tenant_email_ci");
    }

    private async Task<bool> IndexExistsAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_users_tenant_email_ci'") > 0;
    }

    private async Task SetCreatedAtAsync(string userId, string createdAt)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE users SET created_at = @createdAt WHERE id = @userId", new { userId, createdAt });
    }
}
