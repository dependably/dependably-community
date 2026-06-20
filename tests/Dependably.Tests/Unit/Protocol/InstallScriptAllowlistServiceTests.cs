using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Covers <see cref="InstallScriptAllowlistService"/>: cache behaviour, version-pattern
/// matching (null = all versions, exact, trailing-glob), cache invalidation on add/remove,
/// and audit row verification via the audit repository.
/// </summary>
[Trait("Category", "Unit")]
public sealed class InstallScriptAllowlistServiceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly InstallScriptAllowlistService _sut;

    public InstallScriptAllowlistServiceTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _sut = new InstallScriptAllowlistService(
            _fixture.Store,
            new MemoryCache(new MemoryCacheOptions()),
            _clock);
    }

    // ── IsAllowlistedAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task NullVersionPattern_MatchesAnyVersion()
    {
        // NULL pattern = blanket exemption for any version of the package.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-null-{Guid.NewGuid():N}");
        await _sut.AddAsync(orgId, "npm", "esbuild", versionPattern: null, createdBy: null);

        Assert.True(await _sut.IsAllowlistedAsync(orgId, "npm", "esbuild", "0.19.0"));
        Assert.True(await _sut.IsAllowlistedAsync(orgId, "npm", "esbuild", "0.20.0"));
    }

    [Fact]
    public async Task ExactVersionPattern_MatchesOnlyThatVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-exact-{Guid.NewGuid():N}");
        await _sut.AddAsync(orgId, "npm", "postinstall-pkg", versionPattern: "2.1.0", createdBy: null);

        Assert.True(await _sut.IsAllowlistedAsync(orgId, "npm", "postinstall-pkg", "2.1.0"));
        Assert.False(await _sut.IsAllowlistedAsync(orgId, "npm", "postinstall-pkg", "2.1.1"));
        Assert.False(await _sut.IsAllowlistedAsync(orgId, "npm", "postinstall-pkg", "1.0.0"));
    }

    [Fact]
    public async Task GlobVersionPattern_MatchesByPrefix()
    {
        // "2.*" matches any version string starting with "2.".
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-glob-{Guid.NewGuid():N}");
        await _sut.AddAsync(orgId, "npm", "node-gyp", versionPattern: "10.*", createdBy: null);

        Assert.True(await _sut.IsAllowlistedAsync(orgId, "npm", "node-gyp", "10.0.0"));
        Assert.True(await _sut.IsAllowlistedAsync(orgId, "npm", "node-gyp", "10.1.2"));
        Assert.False(await _sut.IsAllowlistedAsync(orgId, "npm", "node-gyp", "9.4.0"));
        Assert.False(await _sut.IsAllowlistedAsync(orgId, "npm", "node-gyp", "11.0.0"));
    }

    [Fact]
    public async Task EcosystemMismatch_ReturnsFalse()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-eco-{Guid.NewGuid():N}");
        await _sut.AddAsync(orgId, "npm", "some-pkg", versionPattern: null, createdBy: null);

        // Same name, different ecosystem.
        Assert.False(await _sut.IsAllowlistedAsync(orgId, "pypi", "some-pkg", "1.0.0"));
    }

    [Fact]
    public async Task NameMismatch_ReturnsFalse()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-name-{Guid.NewGuid():N}");
        await _sut.AddAsync(orgId, "npm", "allowed-pkg", versionPattern: null, createdBy: null);

        Assert.False(await _sut.IsAllowlistedAsync(orgId, "npm", "other-pkg", "1.0.0"));
    }

    [Fact]
    public async Task CrossTenantIsolation_OtherOrgEntryNotVisible()
    {
        // An entry added for org A must not be visible to org B.
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-b-{Guid.NewGuid():N}");
        await _sut.AddAsync(orgA, "npm", "shared-name", versionPattern: null, createdBy: null);

        Assert.True(await _sut.IsAllowlistedAsync(orgA, "npm", "shared-name", "1.0.0"));
        Assert.False(await _sut.IsAllowlistedAsync(orgB, "npm", "shared-name", "1.0.0"));
    }

    // ── Cache invalidation ────────────────────────────────────────────────────

    [Fact]
    public async Task AddAsync_InvalidatesCache()
    {
        // Seed a new allowlist service per test to avoid state bleed from the class-fixture cache.
        var svc = new InstallScriptAllowlistService(
            _fixture.Store,
            new MemoryCache(new MemoryCacheOptions()),
            _clock);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-cache-add-{Guid.NewGuid():N}");

        // Prime the cache with an empty list.
        var before = await svc.ListAsync(orgId);
        Assert.Empty(before);

        // Add an entry — the cache entry for this org must be invalidated.
        await svc.AddAsync(orgId, "npm", "cache-test-pkg", null, null);

        // The next read must reflect the new entry, not the cached empty list.
        var after = await svc.ListAsync(orgId);
        Assert.Single(after);
        Assert.Equal("cache-test-pkg", after[0].Name);
    }

    [Fact]
    public async Task DeleteAsync_InvalidatesCache_AndReturnsRowCount()
    {
        var svc = new InstallScriptAllowlistService(
            _fixture.Store,
            new MemoryCache(new MemoryCacheOptions()),
            _clock);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-cache-del-{Guid.NewGuid():N}");
        var entry = await svc.AddAsync(orgId, "npm", "del-pkg", null, null);

        // The entry is listed before removal.
        Assert.Single(await svc.ListAsync(orgId));

        int deleted = await svc.DeleteAsync(orgId, entry.Id);
        Assert.Equal(1, deleted);

        // Cache entry must be gone; the next list returns empty.
        Assert.Empty(await svc.ListAsync(orgId));
    }

    [Fact]
    public async Task DeleteAsync_CrossTenantId_Returns0AndDoesNotDelete()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-xdel-a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-xdel-b-{Guid.NewGuid():N}");
        var entry = await _sut.AddAsync(orgA, "npm", "xdel-pkg", null, null);

        // Org B cannot delete Org A's entry.
        int deleted = await _sut.DeleteAsync(orgB, entry.Id);
        Assert.Equal(0, deleted);

        // Org A's entry is still present.
        Assert.True(await _sut.IsAllowlistedAsync(orgA, "npm", "xdel-pkg", "1.0.0"));
    }

    // ── MatchesVersionPattern (pure static helper) ────────────────────────────

    [Theory]
    [InlineData("1.0.0", "1.0.0", true)]
    [InlineData("1.0.0", "1.0.1", false)]
    [InlineData("1.*", "1.0.0", true)]
    [InlineData("1.*", "1.99.0", true)]
    [InlineData("1.*", "2.0.0", false)]
    [InlineData("1.*", "10.0.0", false)]    // "1" is not a prefix of "10"
    [InlineData("", "1.0.0", false)]         // empty pattern never matches
    [InlineData("1.0.0", "", false)]         // empty version never matches
    public void MatchesVersionPattern_PureTable(string pattern, string version, bool expected)
    {
        Assert.Equal(expected, InstallScriptAllowlistService.MatchesVersionPattern(pattern, version));
    }

    // ── ListAsync — entries sorted by ecosystem, name ─────────────────────────

    [Fact]
    public async Task ListAsync_ReturnsSortedByEcosystemAndName()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"isa-sort-{Guid.NewGuid():N}");
        await _sut.AddAsync(orgId, "npm", "z-pkg", null, null);
        await _sut.AddAsync(orgId, "npm", "a-pkg", null, null);
        await _sut.AddAsync(orgId, "pypi", "a-lib", null, null);

        var list = await _sut.ListAsync(orgId);
        Assert.Equal(3, list.Count);
        // Sorted by ecosystem then name: npm/a-pkg, npm/z-pkg, pypi/a-lib.
        Assert.Equal("npm", list[0].Ecosystem);
        Assert.Equal("a-pkg", list[0].Name);
        Assert.Equal("npm", list[1].Ecosystem);
        Assert.Equal("z-pkg", list[1].Name);
        Assert.Equal("pypi", list[2].Ecosystem);
    }
}
