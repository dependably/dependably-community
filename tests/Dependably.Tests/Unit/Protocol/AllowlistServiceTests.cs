using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

namespace Dependably.Tests.Unit.Protocol;

[Trait("Category", "Unit")]
public sealed class AllowlistServiceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly AllowlistService _sut;

    public AllowlistServiceTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _sut = new AllowlistService(_fixture.Store, new AuditRepository(_fixture.Store));
    }

    [Fact]
    public async Task IsAllowedAsync_ExactPurlMatch_ReturnsTrue()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await AllowlistSeeder.InsertAsync(_fixture.Store, orgId, "pkg:npm/acme@1.0.0");

        Assert.True(await _sut.IsAllowedAsync(orgId, "pkg:npm/acme@1.0.0"));
    }

    [Fact]
    public async Task IsAllowedAsync_WildcardPurl_NoVersion_MatchesAnyVersion()
    {
        // A wildcard entry (no @version) allows every version.
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await AllowlistSeeder.InsertAsync(_fixture.Store, orgId, "pkg:npm/lodash");

        Assert.True(await _sut.IsAllowedAsync(orgId, "pkg:npm/lodash@4.0.0"));
        Assert.True(await _sut.IsAllowedAsync(orgId, "pkg:npm/lodash@5.1.2"));
    }

    [Fact]
    public async Task IsAllowedAsync_NotListed_ReturnsFalse_AndAudits()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        Assert.False(await _sut.IsAllowedAsync(orgId, "pkg:npm/unknown@1.0.0"));

        await using var conn = await _fixture.Store.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'allowlist_blocked' AND org_id = @orgId",
            new { orgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task IsAllowedAsync_WrongOrgListed_DoesNotLeakAcrossTenants()
    {
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        var orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        await AllowlistSeeder.InsertAsync(_fixture.Store, orgA, "pkg:npm/private@1.0.0");

        Assert.False(await _sut.IsAllowedAsync(orgB, "pkg:npm/private@1.0.0"));
    }

    [Fact]
    public async Task IsAllowedAsync_NonPurlInput_BlocksWithEmptyEcosystemLabel()
    {
        // Covers ExtractEcosystem branch: input doesn't start with "pkg:" → ecosystem = "".
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        Assert.False(await _sut.IsAllowedAsync(orgId, "not-a-purl"));

        await using var conn = await _fixture.Store.OpenAsync();
        var ecosystem = await conn.ExecuteScalarAsync<string>(
            "SELECT ecosystem FROM audit_log WHERE action = 'allowlist_blocked' AND org_id = @orgId ORDER BY id DESC LIMIT 1",
            new { orgId });
        Assert.Equal("", ecosystem);
    }

    [Fact]
    public async Task IsAllowedAsync_PkgPrefixWithoutSlash_BlocksWithEmptyEcosystemLabel()
    {
        // Covers ExtractEcosystem branch: starts with "pkg:" but no '/' after position 4 → ecosystem = "".
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        Assert.False(await _sut.IsAllowedAsync(orgId, "pkg:malformed"));

        await using var conn = await _fixture.Store.OpenAsync();
        var ecosystem = await conn.ExecuteScalarAsync<string>(
            "SELECT ecosystem FROM audit_log WHERE action = 'allowlist_blocked' AND org_id = @orgId ORDER BY id DESC LIMIT 1",
            new { orgId });
        Assert.Equal("", ecosystem);
    }

    [Fact]
    public async Task RecordConflictIfNeededAsync_AlwaysAudits()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        await _sut.RecordConflictIfNeededAsync(
            orgId, "npm", "pkg:npm/conflict@1.0.0", "pkg:npm/conflict@1.0.0");

        await using var conn = await _fixture.Store.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'conflict_resolved' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(1, count);
    }
}
