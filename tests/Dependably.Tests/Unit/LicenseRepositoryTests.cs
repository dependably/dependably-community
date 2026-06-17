using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class LicenseRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org1', 'org1')");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) " +
            "VALUES ('pkg-1', 'org1', 'pypi', 'test', 'test')");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key) " +
            "VALUES ('pvid-1', 'pkg-1', '1.0.0', 'pkg:pypi/test@1.0.0', 'blobs/test'), " +
            "       ('pvid-2', 'pkg-1', '2.0.0', 'pkg:pypi/test@2.0.0', 'blobs/test2')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private LicenseRepository Repo() => new(_db, TimeProvider.System);

    // ── CheckPolicyAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task CheckPolicy_ModeOff_AlwaysAllowed()
    {
        var repo = Repo();
        var (allowed, blocked) = await repo.CheckPolicyAsync("org1", "off", ["GPL-3.0"]);
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Fact]
    public async Task CheckPolicy_EmptyLicenses_AlwaysAllowed()
    {
        var repo = Repo();
        var (allowed, blocked) = await repo.CheckPolicyAsync("org1", "block", []);
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task CheckPolicy_BlocklistedLicense_Blocked(string mode)
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0");

        var (allowed, blocked) = await repo.CheckPolicyAsync("org1", mode, ["MIT", "GPL-3.0"]);
        Assert.False(allowed);
        Assert.Equal("GPL-3.0", blocked);
    }

    [Fact]
    public async Task CheckPolicy_WarnMode_NotBlocklisted_Allowed_EvenIfNotOnAllowlist()
    {
        var repo = Repo();
        // allowlist is empty, no blocklist entries — warn mode should not enforce allowlist
        var (allowed, blocked) = await repo.CheckPolicyAsync("org1", "warn", ["MIT", "Apache-2.0"]);
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Fact]
    public async Task CheckPolicy_BlockMode_AllOnAllowlist_Allowed()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        await repo.AddAllowlistAsync("org1", "Apache-2.0");

        var (allowed, blocked) = await repo.CheckPolicyAsync("org1", "block", ["MIT", "Apache-2.0"]);
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Fact]
    public async Task CheckPolicy_BlockMode_LicenseNotOnAllowlist_Blocked()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");

        var (allowed, blocked) = await repo.CheckPolicyAsync("org1", "block", ["MIT", "GPL-3.0"]);
        Assert.False(allowed);
        Assert.Equal("GPL-3.0", blocked);
    }

    [Fact]
    public async Task CheckPolicy_BlocklistTakesPrecedenceOverAllowlist()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "GPL-3.0");
        await repo.AddBlocklistAsync("org1", "GPL-3.0");

        var (allowed, blocked) = await repo.CheckPolicyAsync("org1", "block", ["GPL-3.0"]);
        Assert.False(allowed);
        Assert.Equal("GPL-3.0", blocked);
    }

    [Fact]
    public async Task CheckPolicy_LicenseComparison_IsCaseInsensitive()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "gpl-3.0");

        var (allowed, _) = await repo.CheckPolicyAsync("org1", "warn", ["GPL-3.0"]);
        Assert.False(allowed);
    }

    // ── SetLicensesAsync / GetForVersionAsync ─────────────────────────────────

    [Fact]
    public async Task SetAndGet_Licenses_RoundTrip()
    {
        var repo = Repo();
        await repo.SetLicensesAsync("pvid-1", ["MIT", "Apache-2.0"], "upstream");

        var results = await repo.GetForVersionAsync("pvid-1");
        var spdxIds = results.Select(r => r.LicenseSpdx).ToHashSet();
        Assert.Contains("MIT", spdxIds);
        Assert.Contains("Apache-2.0", spdxIds);
        Assert.All(results, r => Assert.Equal("upstream", r.Source));
    }

    [Fact]
    public async Task SetLicenses_DuplicateIgnored()
    {
        var repo = Repo();
        await repo.SetLicensesAsync("pvid-2", ["MIT"], "upstream");
        await repo.SetLicensesAsync("pvid-2", ["MIT"], "sbom"); // same SPDX, different source — ON CONFLICT DO NOTHING

        var results = await repo.GetForVersionAsync("pvid-2");
        Assert.Single(results);
    }

    // ── Allowlist CRUD ────────────────────────────────────────────────────────

    [Fact]
    public async Task AddAllowlist_Duplicate_ReturnsNull()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        var second = await repo.AddAllowlistAsync("org1", "MIT");
        Assert.Null(second);
    }

    [Fact]
    public async Task RemoveAllowlist_ExistingEntry_ReturnsTrue()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        bool removed = await repo.RemoveAllowlistAsync("org1", "MIT");
        Assert.True(removed);
    }

    [Fact]
    public async Task RemoveAllowlist_NonExistentEntry_ReturnsFalse()
    {
        var repo = Repo();
        bool removed = await repo.RemoveAllowlistAsync("org1", "MIT");
        Assert.False(removed);
    }

    // ── Blocklist CRUD ────────────────────────────────────────────────────────

    [Fact]
    public async Task AddBlocklist_Duplicate_ReturnsNull()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0");
        var second = await repo.AddBlocklistAsync("org1", "GPL-3.0");
        Assert.Null(second);
    }

    [Fact]
    public async Task RemoveBlocklist_ExistingEntry_ReturnsTrue()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0");
        bool removed = await repo.RemoveBlocklistAsync("org1", "GPL-3.0");
        Assert.True(removed);
    }

    [Fact]
    public async Task GetBlocklist_OrgIsolation()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0");

        var org2List = await repo.GetBlocklistAsync("org2");
        Assert.Empty(org2List);
    }
}
