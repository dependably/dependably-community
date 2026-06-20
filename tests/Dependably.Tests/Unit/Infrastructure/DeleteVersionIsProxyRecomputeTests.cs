using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Regression tests for <see cref="PackageRepository.DeleteVersionAsync"/> ensuring that
/// <c>packages.is_proxy</c> is correctly recomputed after a version is removed. The flag
/// must be <c>true</c> exactly when no <c>origin='uploaded'</c> versions remain for
/// the parent package.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeleteVersionIsProxyRecomputeTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly PackageRepository _repo;

    public DeleteVersionIsProxyRecomputeTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new PackageRepository(_fixture.Store);
    }

    // Per-test unique purl scope — package_versions.purl is UNIQUE globally and the fixture
    // is shared across tests in the class.
    private static string Purl(string version = "1.0.0", string? scope = null)
        => $"pkg:npm/{scope ?? Guid.NewGuid().ToString("N")}/acme@{version}";

    private async Task<bool> ReadIsProxyAsync(string packageId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<bool>(
            "SELECT is_proxy FROM packages WHERE id = @id", new { id = packageId });
    }

    // ── is_proxy transitions to true when the last uploaded version is deleted ──

    [Fact]
    public async Task DeleteVersionAsync_LastUploadedRemoved_IsProxyBecomesTrue()
    {
        // Package starts as not-proxy (has an uploaded version). A proxy version also exists.
        // Deleting the uploaded version should flip is_proxy to true; the proxy version survives.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme",
            isProxy: false);

        string uploadedVerId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", Purl("1.0.0"),
            origin: "uploaded", blobKey: $"up-{Guid.NewGuid():N}");
        await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.1", Purl("1.0.1"),
            origin: "proxy", blobKey: $"px-{Guid.NewGuid():N}");

        Assert.False(await ReadIsProxyAsync(pkgId), "precondition: is_proxy starts false");

        await _repo.DeleteVersionAsync(uploadedVerId);

        Assert.True(await ReadIsProxyAsync(pkgId), "is_proxy must be true when no uploaded versions remain");

        // Proxy version must still exist.
        Assert.NotNull(await _repo.GetVersionAsync(pkgId, "1.0.1"));
    }

    // ── is_proxy stays false when an uploaded version is deleted but another remains ──

    [Fact]
    public async Task DeleteVersionAsync_OneOfTwoUploadedRemoved_IsProxyStaysFalse()
    {
        // Package has two uploaded versions; deleting one leaves the other.
        // is_proxy must remain false because an uploaded version still exists.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "multi",
            isProxy: false);

        string ver1Id = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", Purl("1.0.0"),
            origin: "uploaded", blobKey: $"u1-{Guid.NewGuid():N}");
        await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "2.0.0", Purl("2.0.0"),
            origin: "uploaded", blobKey: $"u2-{Guid.NewGuid():N}");

        await _repo.DeleteVersionAsync(ver1Id);

        Assert.False(await ReadIsProxyAsync(pkgId), "is_proxy must stay false while any uploaded version remains");
        Assert.NotNull(await _repo.GetVersionAsync(pkgId, "2.0.0"));
    }

    // ── is_proxy stays false when a proxy version is deleted and uploaded versions remain ──

    [Fact]
    public async Task DeleteVersionAsync_ProxyVersionDeleted_UploadedRemains_IsProxyStaysFalse()
    {
        // Deleting a proxy version from a package that still has uploaded versions must not
        // change is_proxy from false.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "mixed",
            isProxy: false);

        await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", Purl("1.0.0"),
            origin: "uploaded", blobKey: $"up-{Guid.NewGuid():N}");
        string proxyVerId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.1", Purl("1.0.1"),
            origin: "proxy", blobKey: $"px-{Guid.NewGuid():N}");

        await _repo.DeleteVersionAsync(proxyVerId);

        Assert.False(await ReadIsProxyAsync(pkgId), "is_proxy must remain false when uploaded versions still exist");
        Assert.NotNull(await _repo.GetVersionAsync(pkgId, "1.0.0"));
    }
}
