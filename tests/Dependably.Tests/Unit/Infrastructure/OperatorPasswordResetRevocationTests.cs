using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Regression tests for the operator-initiated password reset revocation invariant: an operator
/// reset is the compromise-response control, so — like the self-service change-password path — it
/// must bump <c>token_version</c> (staling outstanding session JWTs), revoke the target's API
/// tokens, and invalidate the cached token version. Covers both the tenant-user reset
/// (<see cref="SystemAdminRepository.IssuePasswordResetAsync"/>) and the system-admin reset
/// (<see cref="SystemAdminRepository.ResetPasswordAsync"/>).
/// </summary>
[Trait("Category", "Unit")]
public sealed class OperatorPasswordResetRevocationTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public OperatorPasswordResetRevocationTests(InMemoryDbFixture fixture) => _fixture = fixture;

    // ── Tenant-user reset: token_version bump ─────────────────────────────────

    [Fact]
    public async Task IssuePasswordResetAsync_BumpsTokenVersion()
    {
        string slug = $"o-{Guid.NewGuid():N}";
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, slug);
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email);

        long before = await ReadUserVersionAsync(userId);

        var sut = new SystemAdminRepository(_fixture.Store);
        var result = await sut.IssuePasswordResetAsync(email, slug);

        Assert.NotNull(result);
        long after = await ReadUserVersionAsync(userId);
        Assert.Equal(before + 1, after);
    }

    // ── Tenant-user reset: API tokens revoked ─────────────────────────────────

    [Fact]
    public async Task IssuePasswordResetAsync_RevokesApiTokens()
    {
        string slug = $"o-{Guid.NewGuid():N}";
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, slug);
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email);
        await SeedTokenAsync(orgId, userId);
        await SeedTokenAsync(orgId, userId);

        Assert.Equal(2, await CountTokensAsync(userId));

        var sut = new SystemAdminRepository(_fixture.Store);
        await sut.IssuePasswordResetAsync(email, slug);

        Assert.Equal(0, await CountTokensAsync(userId));
    }

    // ── Tenant-user reset: token-version cache is invalidated ─────────────────

    [Fact]
    public async Task IssuePasswordResetAsync_InvalidatesTokenVersionCache()
    {
        string slug = $"o-{Guid.NewGuid():N}";
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, slug);
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email);

        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new UserTokenVersionStore(_fixture.Store, cache);

        // Prime the cache with the pre-reset version, so a stale (un-invalidated) cache would
        // keep serving the old value after the reset.
        long primed = (await versions.GetCurrentVersionAsync(userId))!.Value;

        var sut = new SystemAdminRepository(_fixture.Store, tokenVersions: versions);
        await sut.IssuePasswordResetAsync(email, slug);

        long afterReset = (await versions.GetCurrentVersionAsync(userId))!.Value;
        Assert.Equal(primed + 1, afterReset);
    }

    // ── Tenant-user reset: mixed partial-failure — only the target is revoked ──

    [Fact]
    public async Task IssuePasswordResetAsync_OnlyTargetUserIsRevoked()
    {
        string slug = $"o-{Guid.NewGuid():N}";
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, slug);

        string targetEmail = $"target-{Guid.NewGuid():N}@x.test";
        string targetId = await UserSeeder.InsertAsync(_fixture.Store, orgId, targetEmail);
        await SeedTokenAsync(orgId, targetId);

        string bystanderEmail = $"bystander-{Guid.NewGuid():N}@x.test";
        string bystanderId = await UserSeeder.InsertAsync(_fixture.Store, orgId, bystanderEmail);
        await SeedTokenAsync(orgId, bystanderId);

        long bystanderVersionBefore = await ReadUserVersionAsync(bystanderId);

        var sut = new SystemAdminRepository(_fixture.Store);
        await sut.IssuePasswordResetAsync(targetEmail, slug);

        // Target: tokens revoked, version bumped.
        Assert.Equal(0, await CountTokensAsync(targetId));

        // Bystander in the same org: untouched.
        Assert.Equal(1, await CountTokensAsync(bystanderId));
        Assert.Equal(bystanderVersionBefore, await ReadUserVersionAsync(bystanderId));
    }

    // ── System-admin reset: token_version bump ────────────────────────────────

    [Fact]
    public async Task ResetPasswordAsync_BumpsAdminTokenVersion()
    {
        string adminId = await SystemAdminSeeder.InsertAsync(_fixture.Store,
            $"sa-{Guid.NewGuid():N}@x.test");

        long before = await ReadAdminVersionAsync(adminId);

        string newHash = BCrypt.Net.BCrypt.HashPassword("NewAdminPass456!", workFactor: 4);
        var sut = new SystemAdminRepository(_fixture.Store);
        bool ok = await sut.ResetPasswordAsync(adminId, newHash, TestTime.KnownNow);

        Assert.True(ok);
        Assert.Equal(before + 1, await ReadAdminVersionAsync(adminId));
    }

    // ── System-admin reset: token-version cache is invalidated ────────────────

    [Fact]
    public async Task ResetPasswordAsync_InvalidatesAdminTokenVersionCache()
    {
        string adminId = await SystemAdminSeeder.InsertAsync(_fixture.Store,
            $"sa-{Guid.NewGuid():N}@x.test");

        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var adminVersions = new Dependably.Infrastructure.Identity.SystemAdminTokenVersionStore(
            _fixture.Store, cache);

        long primed = (await adminVersions.GetCurrentVersionAsync(adminId))!.Value;

        string newHash = BCrypt.Net.BCrypt.HashPassword("NewAdminPass456!", workFactor: 4);
        var sut = new SystemAdminRepository(_fixture.Store, adminTokenVersions: adminVersions);
        await sut.ResetPasswordAsync(adminId, newHash, TestTime.KnownNow);

        long afterReset = (await adminVersions.GetCurrentVersionAsync(adminId))!.Value;
        Assert.Equal(primed + 1, afterReset);
    }

    // ── System-admin reset: mixed partial-failure — only target bumped ────────

    [Fact]
    public async Task ResetPasswordAsync_OnlyTargetAdminIsBumped()
    {
        string targetId = await SystemAdminSeeder.InsertAsync(_fixture.Store,
            $"sa1-{Guid.NewGuid():N}@x.test");
        string bystanderId = await SystemAdminSeeder.InsertAsync(_fixture.Store,
            $"sa2-{Guid.NewGuid():N}@x.test");

        long bystanderBefore = await ReadAdminVersionAsync(bystanderId);

        string newHash = BCrypt.Net.BCrypt.HashPassword("NewAdminPass456!", workFactor: 4);
        var sut = new SystemAdminRepository(_fixture.Store);
        await sut.ResetPasswordAsync(targetId, newHash, TestTime.KnownNow);

        Assert.Equal(bystanderBefore, await ReadAdminVersionAsync(bystanderId));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private async Task SeedTokenAsync(string orgId, string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO user_tokens (id, org_id, user_id, token_hash) VALUES (@id, @orgId, @userId, @hash)",
            new { id = Guid.NewGuid().ToString("N"), orgId, userId, hash = Guid.NewGuid().ToString("N") });
    }

    private async Task<int> CountTokensAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM user_tokens WHERE user_id = @id", new { id = userId });
    }

    private async Task<long> ReadUserVersionAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });
    }

    private async Task<long> ReadAdminVersionAsync(string adminId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id = adminId });
    }
}
