using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Regression tests asserting that all four credential/session-invalidation sites rotate
/// <c>security_stamp</c> alongside <c>token_version</c>, keeping the Identity model consistent
/// with the credential change. token_version remains the canonical per-request session-invalidation
/// signal; security_stamp is Identity-internal and kept in sync here.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SecurityStampRotationTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public SecurityStampRotationTests(InMemoryDbFixture fixture) => _fixture = fixture;

    // ── UserService.ChangePasswordAsync ──────────────────────────────────────

    [Fact]
    public async Task ChangePasswordAsync_RotatesSecurityStamp()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        // deepcode ignore NoHardcodedCredentials: test fixture password, not a real credential
        const string password = "OldPassword123";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId,
            $"u-{Guid.NewGuid():N}@x.test", password: password);

        // Capture the stamp before (NULL on new rows is fine — it will differ after)
        string? stampBefore = await ReadUserStampAsync(userId);

        var sut = new UserService(_fixture.Store, new OrgRepository(_fixture.Store));
        var result = await sut.ChangePasswordAsync(userId, password, "NewPassword456!");

        Assert.Equal(PasswordChangeOutcome.Success, result.Outcome);

        string? stampAfter = await ReadUserStampAsync(userId);

        Assert.NotNull(stampAfter);
        Assert.NotEqual(stampBefore, stampAfter);
    }

    // ── UserService.BumpTokenVersionAndRevokeTokensAsync ─────────────────────

    [Fact]
    public async Task BumpTokenVersionAndRevokeTokensAsync_RotatesSecurityStamp()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId,
            $"u-{Guid.NewGuid():N}@x.test");

        string? stampBefore = await ReadUserStampAsync(userId);

        var sut = new UserService(_fixture.Store, new OrgRepository(_fixture.Store));
        long newVersion = await sut.BumpTokenVersionAndRevokeTokensAsync(userId);

        Assert.True(newVersion > 1);

        string? stampAfter = await ReadUserStampAsync(userId);

        Assert.NotNull(stampAfter);
        Assert.NotEqual(stampBefore, stampAfter);
    }

    // ── Mixed partial-failure: two users, only one bumped ────────────────────

    [Fact]
    public async Task BumpTokenVersionAndRevokeTokensAsync_OnlyTargetUserStampRotates()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string userId1 = await UserSeeder.InsertAsync(_fixture.Store, orgId,
            $"u1-{Guid.NewGuid():N}@x.test");
        string userId2 = await UserSeeder.InsertAsync(_fixture.Store, orgId,
            $"u2-{Guid.NewGuid():N}@x.test");

        // Seed a known stamp on user2 so we can assert it did NOT change.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET security_stamp = 'original-stamp' WHERE id = @id",
                new { id = userId2 });
        }

        var sut = new UserService(_fixture.Store, new OrgRepository(_fixture.Store));
        await sut.BumpTokenVersionAndRevokeTokensAsync(userId1);

        // User1's stamp is now set (was null).
        string? stamp1 = await ReadUserStampAsync(userId1);
        Assert.NotNull(stamp1);

        // User2's stamp is untouched.
        string? stamp2 = await ReadUserStampAsync(userId2);
        Assert.Equal("original-stamp", stamp2);
    }

    // ── SystemAdminRepository.RotatePasswordAsync ─────────────────────────────

    [Fact]
    public async Task RotatePasswordAsync_RotatesSecurityStamp()
    {
        // deepcode ignore NoHardcodedCredentials: test fixture password, not a real credential
        const string password = "AdminPass123";
        string adminId = await SystemAdminSeeder.InsertAsync(_fixture.Store,
            $"sa-{Guid.NewGuid():N}@x.test", password);

        string? stampBefore = await ReadAdminStampAsync(adminId);

        string newHash = BCrypt.Net.BCrypt.HashPassword("NewAdminPass456!", workFactor: 4);
        var sut = new SystemAdminRepository(_fixture.Store);
        long? result = await sut.RotatePasswordAsync(adminId, password, newHash);

        Assert.NotNull(result);

        string? stampAfter = await ReadAdminStampAsync(adminId);

        Assert.NotNull(stampAfter);
        Assert.NotEqual(stampBefore, stampAfter);
    }

    // ── SystemAdminRepository.BumpTokenVersionAsync ───────────────────────────

    [Fact]
    public async Task BumpTokenVersionAsync_RotatesSecurityStamp()
    {
        string adminId = await SystemAdminSeeder.InsertAsync(_fixture.Store,
            $"sa-{Guid.NewGuid():N}@x.test");

        string? stampBefore = await ReadAdminStampAsync(adminId);

        var sut = new SystemAdminRepository(_fixture.Store);
        long newVersion = await sut.BumpTokenVersionAsync(adminId);

        Assert.True(newVersion > 1);

        string? stampAfter = await ReadAdminStampAsync(adminId);

        Assert.NotNull(stampAfter);
        Assert.NotEqual(stampBefore, stampAfter);
    }

    // ── Mixed partial-failure: two admins, only one bumped ────────────────────

    [Fact]
    public async Task BumpTokenVersionAsync_OnlyTargetAdminStampRotates()
    {
        string adminId1 = await SystemAdminSeeder.InsertAsync(_fixture.Store,
            $"sa1-{Guid.NewGuid():N}@x.test");
        string adminId2 = await SystemAdminSeeder.InsertAsync(_fixture.Store,
            $"sa2-{Guid.NewGuid():N}@x.test");

        // Seed a known stamp on admin2 so we can assert it did NOT change.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE system_admins SET security_stamp = 'original-stamp' WHERE id = @id",
                new { id = adminId2 });
        }

        var sut = new SystemAdminRepository(_fixture.Store);
        await sut.BumpTokenVersionAsync(adminId1);

        string? stamp1 = await ReadAdminStampAsync(adminId1);
        Assert.NotNull(stamp1);

        string? stamp2 = await ReadAdminStampAsync(adminId2);
        Assert.Equal("original-stamp", stamp2);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<string?> ReadUserStampAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT security_stamp FROM users WHERE id = @id", new { id = userId });
    }

    private async Task<string?> ReadAdminStampAsync(string adminId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT security_stamp FROM system_admins WHERE id = @id", new { id = adminId });
    }
}
