using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Extends <see cref="PackageRepositoryTests"/> with branches the original file did not reach:
/// FindVersionByBlobKeySuffix (hit/miss + VulnCheckedAt non-null), GetVersionAsync (hit/miss),
/// TouchLastUsedAsync, StreamAllBlobKeysAsync (yield + cancellation), GetTotalSizeBytesAsync
/// (zero-row COALESCE fallback + populated), DeleteVersionAsync, SetManualBlockStateAsync, and
/// DeleteProxyVersionsForNameAsync's empty branch (no proxy rows → no DELETE issued).
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageRepositoryExtendedTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly PackageRepository _repo;

    public PackageRepositoryExtendedTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new PackageRepository(_fixture.Store);
    }

    // Per-test unique purl scope — package_versions.purl is UNIQUE globally and the fixture
    // is shared across tests in the class.
    private static string Purl(string version = "1.0.0", string name = "acme")
        => $"pkg:npm/{Guid.NewGuid():N}/{name}@{version}";

    // ── FindVersionByBlobKeySuffixAsync ──────────────────────────────────────

    [Fact]
    public async Task FindVersionByBlobKeySuffixAsync_Match_ReturnsPackageAndVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "pypi", "acme");
        string blobKey = $"pypi/acme/{Guid.NewGuid():N}/acme-1.2.3.tar.gz";
        string verId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.2.3", Purl("1.2.3"), blobKey: blobKey);

        // Populate VulnCheckedAt so the non-null parse branch executes.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE package_versions SET vuln_checked_at = '2026-01-02T03:04:05Z' WHERE id = @id",
                new { id = verId });
        }

        var result = await _repo.FindVersionByBlobKeySuffixAsync(orgId, "pypi", "acme-1.2.3.tar.gz");

        Assert.NotNull(result);
        Assert.Equal(pkgId, result!.Value.Package.Id);
        Assert.Equal("acme", result.Value.Package.Name);
        Assert.Equal("1.2.3", result.Value.Version.Version);
        Assert.Equal(blobKey, result.Value.Version.BlobKey);
        Assert.NotNull(result.Value.Version.VulnCheckedAt);
    }

    [Fact]
    public async Task FindVersionByBlobKeySuffixAsync_NoMatch_ReturnsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "pypi", "acme");
        await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", Purl(), blobKey: $"pypi/acme/{Guid.NewGuid():N}/acme-1.0.0.tar.gz");

        // No row whose blob_key ends with /not-a-real-file.tar.gz
        var result = await _repo.FindVersionByBlobKeySuffixAsync(orgId, "pypi", "not-a-real-file.tar.gz");
        Assert.Null(result);
    }

    [Fact]
    public async Task FindVersionByBlobKeySuffixAsync_WrongOrg_ReturnsNull()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orgA-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgB-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgA, "pypi", "acme");
        string filename = $"acme-1.0.0-{Guid.NewGuid():N}.tar.gz";
        await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", Purl(), blobKey: $"pypi/acme/x/{filename}");

        Assert.NotNull(await _repo.FindVersionByBlobKeySuffixAsync(orgA, "pypi", filename));
        Assert.Null(await _repo.FindVersionByBlobKeySuffixAsync(orgB, "pypi", filename));
    }

    // ── GetVersionAsync(packageId, version) ──────────────────────────────────

    [Fact]
    public async Task GetVersionAsync_Found_AndMissing()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.2.3", Purl("1.2.3"),
            blobKey: $"k-{Guid.NewGuid():N}");

        var hit = await _repo.GetVersionAsync(pkgId, "1.2.3");
        Assert.NotNull(hit);
        Assert.Equal("1.2.3", hit!.Version);

        var miss = await _repo.GetVersionAsync(pkgId, "9.9.9");
        Assert.Null(miss);
    }

    // ── TouchLastUsedAsync ───────────────────────────────────────────────────

    [Fact]
    public async Task TouchLastUsedAsync_SetsLastUsedTimestamp()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl(),
            blobKey: $"k-{Guid.NewGuid():N}");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            string? before = await conn.ExecuteScalarAsync<string?>(
                "SELECT last_used FROM package_versions WHERE id = @id", new { id = verId });
            Assert.Null(before);
        }

        await _repo.TouchLastUsedAsync(verId);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            string? after = await conn.ExecuteScalarAsync<string?>(
                "SELECT last_used FROM package_versions WHERE id = @id", new { id = verId });
            Assert.False(string.IsNullOrEmpty(after));
        }
    }

    // ── IncrementDownloadCountAsync ──────────────────────────────────────────

    [Fact]
    public async Task IncrementDownloadCountAsync_AccumulatesAndStampsLastUsed()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl(),
            blobKey: $"k-{Guid.NewGuid():N}");

        // Fresh row starts at 0 and surfaces through the read model.
        var initial = await _repo.GetVersionAsync(pkgId, "1.0.0");
        Assert.Equal(0, initial!.DownloadCount);

        await _repo.IncrementDownloadCountAsync(verId);
        await _repo.IncrementDownloadCountAsync(verId);
        await _repo.IncrementDownloadCountAsync(verId);

        var after = await _repo.GetVersionAsync(pkgId, "1.0.0");
        Assert.Equal(3, after!.DownloadCount);

        // The download is also the moment last_used advances.
        await using var conn = await _fixture.Store.OpenAsync();
        string? lastUsed = await conn.ExecuteScalarAsync<string?>(
            "SELECT last_used FROM package_versions WHERE id = @id", new { id = verId });
        Assert.False(string.IsNullOrEmpty(lastUsed));
    }

    [Fact]
    public async Task IncrementDownloadCountByPurlAsync_BumpsGlobalPlaneTenantRow()
    {
        // By-purl increments now target tenant_artifact_access.download_count (global plane).
        // Seed a cache_artifact + tenant_artifact_access row for the target org.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string purl = Purl();
        string caId = Guid.NewGuid().ToString("N");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl) " +
                "VALUES (@id, 'rpm', 'acme', '1.0.0', 'acme-1.0.0.rpm', @bk, 'h', @purl)",
                new { id = caId, bk = $"proxy/h/acme-1.0.0.rpm", purl });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, download_count) VALUES (@orgId, @caId, 0)",
                new { orgId, caId });
        }

        await _repo.IncrementDownloadCountByPurlAsync(orgId, purl);
        await _repo.IncrementDownloadCountByPurlAsync(orgId, purl);

        await using var conn2 = await _fixture.Store.OpenAsync();
        int count = await conn2.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId, caId });
        Assert.Equal(2, count);

        // Unknown purl is a harmless no-op.
        await _repo.IncrementDownloadCountByPurlAsync(orgId, "pkg:rpm/nope@9.9.9");
    }

    // ── DeleteVersionAsync ───────────────────────────────────────────────────

    [Fact]
    public async Task DeleteVersionAsync_RemovesRow()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl(),
            blobKey: $"k-{Guid.NewGuid():N}");

        Assert.NotNull(await _repo.GetVersionAsync(pkgId, "1.0.0"));
        await _repo.DeleteVersionAsync(verId);
        Assert.Null(await _repo.GetVersionAsync(pkgId, "1.0.0"));
    }

    // ── SetManualBlockStateAsync ─────────────────────────────────────────────

    [Fact]
    public async Task SetManualBlockStateAsync_SetsAndClears()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl(),
            blobKey: $"k-{Guid.NewGuid():N}");

        await _repo.SetManualBlockStateAsync(verId, "blocked");
        Assert.Equal("blocked", (await _repo.GetVersionByIdAsync(orgId, verId))!.ManualBlockState);

        await _repo.SetManualBlockStateAsync(verId, null);
        Assert.Null((await _repo.GetVersionByIdAsync(orgId, verId))!.ManualBlockState);
    }

    // ── GetTotalSizeBytesAsync ───────────────────────────────────────────────

    [Fact]
    public async Task GetTotalSizeBytesAsync_NoRows_ReturnsZero()
    {
        // Org with zero packages exercises the COALESCE/?? 0L fallback.
        string emptyOrg = await OrgSeeder.InsertAsync(_fixture.Store, $"empty-{Guid.NewGuid():N}");
        Assert.Equal(0L, await _repo.GetTotalSizeBytesAsync(emptyOrg));
    }

    [Fact]
    public async Task GetTotalSizeBytesAsync_SumsAcrossOrgVersionsOnly()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orgA-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgB-{Guid.NewGuid():N}");
        string pkgA = await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "acme");
        string pkgB = await PackageSeeder.InsertAsync(_fixture.Store, orgB, "npm", "acme");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgA, "1.0.0", Purl("1.0.0"),
            blobKey: $"a1-{Guid.NewGuid():N}", sizeBytes: 100);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgA, "2.0.0", Purl("2.0.0"),
            blobKey: $"a2-{Guid.NewGuid():N}", sizeBytes: 250);
        // Other-org bytes must not be summed.
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgB, "1.0.0", Purl("1.0.0"),
            blobKey: $"b1-{Guid.NewGuid():N}", sizeBytes: 9999);

        Assert.Equal(350L, await _repo.GetTotalSizeBytesAsync(orgA));
    }

    // ── StreamAllBlobKeysAsync ───────────────────────────────────────────────

    [Fact]
    public async Task StreamAllBlobKeysAsync_YieldsEveryReferencedKey()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string k1 = $"stream-{Guid.NewGuid():N}/a";
        string k2 = $"stream-{Guid.NewGuid():N}/b";
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0"), blobKey: k1);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0"), blobKey: k2);

        var collected = new List<string>();
        await foreach (string key in _repo.StreamAllBlobKeysAsync())
        {
            collected.Add(key);
        }

        Assert.Contains(k1, collected);
        Assert.Contains(k2, collected);
    }

    [Fact]
    public async Task StreamAllBlobKeysAsync_CancelledMidStream_StopsEarly()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        // Multiple versions so we have rows in the iterator we can short-circuit out of.
        for (int i = 0; i < 4; i++)
        {
            await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, $"{i}.0.0", Purl($"{i}.0.0"),
                blobKey: $"cancel-{Guid.NewGuid():N}/{i}");
        }

        // Cancel *after* the connection opens (during iteration) so the IsCancellationRequested
        // branch inside the foreach yield loop is the one that exits.
        using var cts = new CancellationTokenSource();
        var collected = new List<string>();
        await foreach (string key in _repo.StreamAllBlobKeysAsync(cts.Token))
        {
            collected.Add(key);
            cts.Cancel();   // next iteration hits the `if (ct.IsCancellationRequested) yield break;` branch
        }

        // First key yielded, then loop exits via the cancellation branch.
        Assert.Single(collected);
    }

    // ── DeleteProxyVersionsForNameAsync empty branch ─────────────────────────

    [Fact]
    public async Task DeleteProxyVersionsForNameAsync_NoProxyRows_SkipsDelete_ReturnsEmpty()
    {
        // Only an 'uploaded' version exists — the conditional DELETE inside the repo must NOT run,
        // and the returned list must be empty.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl(),
            origin: "uploaded", blobKey: $"u1-{Guid.NewGuid():N}");

        var result = await _repo.DeleteProxyVersionsForNameAsync(orgId, "npm", "acme");

        Assert.Empty(result);
        // Uploaded row is still there.
        var remaining = await _repo.GetVersionsAsync(pkgId);
        Assert.Single(remaining);
        Assert.Equal("uploaded", remaining[0].Origin);
    }

    [Fact]
    public async Task DeleteProxyVersionsForNameAsync_UnknownName_ReturnsEmpty()
    {
        // Nothing inserted for this purl_name → first SELECT comes back empty,
        // branch `blobKeys.Count > 0` is false, DELETE is skipped.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var result = await _repo.DeleteProxyVersionsForNameAsync(orgId, "npm", "never-existed");
        Assert.Empty(result);
    }
}
