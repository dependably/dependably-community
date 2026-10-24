using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Credential revocation on a tenant lifecycle change, beyond sessions and remembered devices
/// (those are pinned by <see cref="TenantStatusSessionRevocationTests"/>). Whenever a status write
/// enters or leaves a lockout, and on soft-delete and restore, <see cref="OrgRepository"/> deletes
/// the tenant's personal access tokens, service tokens, pending password-reset and email-change
/// links and pending invites in the same transaction, reports the counts, and drops cached token
/// resolutions after the commit. Consumed links, accepted invites and every other tenant's
/// credentials are never touched.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantStatusCredentialRevocationTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TenantStatusCredentialRevocationTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private sealed record Tenant(string OrgId, string UserA, string UserB);

    /// <summary>One row of each credential kind the lifecycle write touches.</summary>
    private sealed record Counts(
        long UserTokens, long ServiceTokens, long PendingResets, long ConsumedResets,
        long PendingEmailChanges, long PendingInvites, long AcceptedInvites);

    private static readonly Counts Seeded = new(2, 1, 1, 1, 1, 1, 1);
    private static readonly Counts Revoked = new(0, 0, 0, 1, 0, 0, 1);

    private OrgRepository Repo(IMemoryCache? cache = null) =>
        new(_fixture.Store, cache: cache, time: TestTime.Frozen());

    private TokenRepository Tokens(IMemoryCache? cache = null) =>
        new(_fixture.Store, TestTime.Frozen(), cache);

    private async Task<Tenant> SeedTenantAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"tcr-{Guid.NewGuid():N}");
        string a = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"a-{Guid.NewGuid():N}@x.test");
        string b = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"b-{Guid.NewGuid():N}@x.test");
        return new Tenant(orgId, a, b);
    }

    private async Task SeedCredentialsAsync(Tenant t)
    {
        var tokens = Tokens();
        await tokens.CreateUserTokenAsync(t.OrgId, t.UserA, Capabilities.ReaderCapsCanonicalJson, expiresAt: null);
        await tokens.CreateUserTokenAsync(t.OrgId, t.UserB, Capabilities.ReaderCapsCanonicalJson, expiresAt: null);
        await tokens.CreateServiceTokenAsync(t.OrgId, "ci", Capabilities.ReaderCapsCanonicalJson, expiresAt: null);

        await using var conn = await _fixture.Store.OpenAsync();
        const string Expires = "2099-01-01T00:00:00Z";
        await conn.ExecuteAsync(
            """
            INSERT INTO password_reset_tokens (id, user_id, org_id, token_hash, expires_at, consumed_at)
            VALUES (@pending, @userA, @orgId, @pendingHash, @expires, NULL),
                   (@consumed, @userB, @orgId, @consumedHash, @expires, '2026-01-01T00:00:00Z')
            """,
            new
            {
                pending = Guid.NewGuid().ToString("N"),
                consumed = Guid.NewGuid().ToString("N"),
                userA = t.UserA,
                userB = t.UserB,
                orgId = t.OrgId,
                pendingHash = Guid.NewGuid().ToString("N"),
                consumedHash = Guid.NewGuid().ToString("N"),
                expires = Expires,
            });
        await conn.ExecuteAsync(
            """
            INSERT INTO email_change_tokens (id, user_id, org_id, new_email, token_hash, expires_at)
            VALUES (@id, @userA, @orgId, @newEmail, @hash, @expires)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                userA = t.UserA,
                orgId = t.OrgId,
                newEmail = $"new-{Guid.NewGuid():N}@x.test",
                hash = Guid.NewGuid().ToString("N"),
                expires = Expires,
            });
        await conn.ExecuteAsync(
            """
            INSERT INTO invites (id, org_id, email, role, token_hash, created_by, expires_at, accepted_at)
            VALUES (@pending, @orgId, @pendingEmail, 'member', @pendingHash, @userA, @expires, NULL),
                   (@accepted, @orgId, @acceptedEmail, 'member', @acceptedHash, @userA, @expires, '2026-01-01T00:00:00Z')
            """,
            new
            {
                pending = Guid.NewGuid().ToString("N"),
                accepted = Guid.NewGuid().ToString("N"),
                orgId = t.OrgId,
                pendingEmail = $"p-{Guid.NewGuid():N}@x.test",
                acceptedEmail = $"q-{Guid.NewGuid():N}@x.test",
                pendingHash = Guid.NewGuid().ToString("N"),
                acceptedHash = Guid.NewGuid().ToString("N"),
                userA = t.UserA,
                expires = Expires,
            });
    }

    // ── Which transitions revoke ─────────────────────────────────────────────

    [Theory]
    [InlineData("active", "suspended", true)]
    [InlineData("read_only", "suspended", true)]
    [InlineData("suspended", "suspended", true)]
    [InlineData("suspended", "active", true)]
    [InlineData("suspended", "read_only", true)]
    [InlineData("archived", "active", true)]
    [InlineData("deleting", "active", true)]
    [InlineData("active", "read_only", false)]
    [InlineData("read_only", "active", false)]
    [InlineData("active", "active", false)]
    public async Task UpdateOrgStatus_RevokesEveryApiCredentialExactlyWhenALockoutIsEnteredOrLeft(
        string from, string to, bool revokes)
    {
        // Mixed scenario: another tenant holds one of everything and must come through untouched.
        var target = await SeedTenantAsync();
        var other = await SeedTenantAsync();
        await SeedCredentialsAsync(target);
        await SeedCredentialsAsync(other);
        await SetOrgStatusRawAsync(target.OrgId, from);

        var result = await Repo().UpdateOrgStatusAsync(target.OrgId, to);

        Assert.True(result.Applied);
        Assert.Equal(revokes ? Revoked : Seeded, await CountAsync(target.OrgId));
        Assert.Equal(
            revokes ? new TenantAccessRevocation(2, 0, 2, 1, 1, 1, 1) : TenantAccessRevocation.None,
            result.Revoked);
        Assert.Equal(Seeded, await CountAsync(other.OrgId));
    }

    [Fact]
    public async Task SuspendThenRestore_DoesNotReviveTokens_ATokenIssuedAfterTheRestoreWorks()
    {
        var t = await SeedTenantAsync();
        var tokens = Tokens();
        var (before, _) = await tokens.CreateUserTokenAsync(t.OrgId, t.UserA, Capabilities.ReaderCapsCanonicalJson, expiresAt: null);
        Assert.NotNull(await tokens.ResolveAsync(before));
        var sut = Repo();

        Assert.True((await sut.UpdateOrgStatusAsync(t.OrgId, "suspended")).Applied);
        Assert.True((await sut.UpdateOrgStatusAsync(t.OrgId, "active")).Applied);

        Assert.Null(await tokens.ResolveAsync(before));
        var (after, _) = await tokens.CreateUserTokenAsync(t.OrgId, t.UserA, Capabilities.ReaderCapsCanonicalJson, expiresAt: null);
        Assert.NotNull(await tokens.ResolveAsync(after));
    }

    [Fact]
    public async Task ReadOnlyRoundTrip_KeepsEveryToken()
    {
        var t = await SeedTenantAsync();
        await SeedCredentialsAsync(t);
        var sut = Repo();

        await sut.UpdateOrgStatusAsync(t.OrgId, "read_only");
        await sut.UpdateOrgStatusAsync(t.OrgId, "active");

        Assert.Equal(Seeded, await CountAsync(t.OrgId));
    }

    // ── Refused writes revoke nothing ────────────────────────────────────────

    [Theory]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task UpdateOrgStatus_RejectedStatus_RevokesNothing(string status)
    {
        var t = await SeedTenantAsync();
        await SeedCredentialsAsync(t);

        Assert.Equal(TenantLifecycleResult.NotApplied, await Repo().UpdateOrgStatusAsync(t.OrgId, status));

        Assert.Equal(Seeded, await CountAsync(t.OrgId));
    }

    [Fact]
    public async Task Restore_OfATenantThatIsNotSoftDeleted_RevokesNothing()
    {
        var t = await SeedTenantAsync();
        await SeedCredentialsAsync(t);

        Assert.Equal(TenantLifecycleResult.NotApplied, await Repo().RestoreOrgAsync(t.OrgId));

        Assert.Equal(Seeded, await CountAsync(t.OrgId));
    }

    [Fact]
    public async Task SoftDelete_OfAnUnknownTenant_IsNotApplied()
    {
        Assert.Equal(TenantLifecycleResult.NotApplied, await Repo().SoftDeleteOrgAsync($"missing-{Guid.NewGuid():N}"));
    }

    // ── Soft-delete and restore ──────────────────────────────────────────────

    [Fact]
    public async Task SoftDeleteAndRestore_EachRevoke_AndLeaveOtherTenantsAlone()
    {
        var target = await SeedTenantAsync();
        var other = await SeedTenantAsync();
        await SeedCredentialsAsync(target);
        await SeedCredentialsAsync(other);
        var sut = Repo();

        var deletion = await sut.SoftDeleteOrgAsync(target.OrgId);
        Assert.True(deletion.Applied);
        Assert.Equal(new TenantAccessRevocation(2, 0, 2, 1, 1, 1, 1), deletion.Revoked);
        Assert.Equal(Revoked, await CountAsync(target.OrgId));

        // A token written around the application while the tenant is deleted is the restore's
        // backstop case: the restore revokes it too.
        await using (var direct = await _fixture.Store.OpenAsync())
        {
            await direct.ExecuteAsync(
                "INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities) VALUES (@id, @orgId, 'direct', @hash, @caps)",
                new { id = Guid.NewGuid().ToString("N"), orgId = target.OrgId, hash = Guid.NewGuid().ToString("N"), caps = Capabilities.ReaderCapsCanonicalJson });
        }
        var restore = await sut.RestoreOrgAsync(target.OrgId);
        Assert.True(restore.Applied);
        Assert.Equal(1, restore.Revoked.ServiceTokens);
        Assert.Equal(Revoked, await CountAsync(target.OrgId));

        Assert.Equal(Seeded, await CountAsync(other.OrgId));
    }

    // ── A cached resolution cannot keep a revoked token alive ────────────────

    [Theory]
    [InlineData("suspend")]
    [InlineData("soft-delete")]
    public async Task Lockout_DropsTheCachedResolutionOfEveryRevokedToken(string action)
    {
        var t = await SeedTenantAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var tokens = Tokens(cache);
        var (raw, _) = await tokens.CreateServiceTokenAsync(t.OrgId, "ci", Capabilities.ReaderCapsCanonicalJson, expiresAt: null);

        // Prime the cache the way a CI burst does; the frozen clock keeps the entry live.
        Assert.NotNull(await tokens.ResolveAsync(raw));

        var sut = Repo(cache);
        if (action == "suspend")
        {
            await sut.UpdateOrgStatusAsync(t.OrgId, "suspended");
        }
        else
        {
            await sut.SoftDeleteOrgAsync(t.OrgId);
        }

        Assert.Null(await tokens.ResolveAsync(raw));
    }

    [Fact]
    public async Task DeleteServiceToken_DropsItsCachedResolution()
    {
        var t = await SeedTenantAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var tokens = Tokens(cache);
        var (raw, record) = await tokens.CreateServiceTokenAsync(t.OrgId, "ci", Capabilities.ReaderCapsCanonicalJson, expiresAt: null);
        Assert.NotNull(await tokens.ResolveAsync(raw));

        Assert.Equal(1, await tokens.DeleteServiceTokenAsync(record.Id, t.OrgId));

        Assert.Null(await tokens.ResolveAsync(raw));
    }

    [Fact]
    public async Task DeleteServiceToken_OfAnotherTenant_DeletesNothing_AndKeepsItsResolution()
    {
        var owner = await SeedTenantAsync();
        var caller = await SeedTenantAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var tokens = Tokens(cache);
        var (raw, record) = await tokens.CreateServiceTokenAsync(owner.OrgId, "ci", Capabilities.ReaderCapsCanonicalJson, expiresAt: null);

        Assert.Equal(0, await tokens.DeleteServiceTokenAsync(record.Id, caller.OrgId));

        Assert.NotNull(await tokens.ResolveAsync(raw));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task SetOrgStatusRawAsync(string orgId, string status)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("UPDATE orgs SET status = @status WHERE id = @orgId", new { orgId, status });
    }

    private async Task<Counts> CountAsync(string orgId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<Counts>(
            """
            SELECT
                (SELECT COUNT(*) FROM user_tokens WHERE org_id = @orgId) AS UserTokens,
                (SELECT COUNT(*) FROM service_tokens WHERE org_id = @orgId) AS ServiceTokens,
                (SELECT COUNT(*) FROM password_reset_tokens WHERE org_id = @orgId AND consumed_at IS NULL) AS PendingResets,
                (SELECT COUNT(*) FROM password_reset_tokens WHERE org_id = @orgId AND consumed_at IS NOT NULL) AS ConsumedResets,
                (SELECT COUNT(*) FROM email_change_tokens WHERE org_id = @orgId AND consumed_at IS NULL) AS PendingEmailChanges,
                (SELECT COUNT(*) FROM invites WHERE org_id = @orgId AND accepted_at IS NULL) AS PendingInvites,
                (SELECT COUNT(*) FROM invites WHERE org_id = @orgId AND accepted_at IS NOT NULL) AS AcceptedInvites
            """,
            new { orgId });
    }
}
