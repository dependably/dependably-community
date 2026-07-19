using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The read model's first consumer. Storage is the surface where two definitions of the same number
/// had drifted apart — what an operator was shown, and what the publish path enforced — so the point
/// of routing it here is that there is now one relation, evaluated by the database, that both read.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ArtifactInventoryRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'other')");
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES ('o1'), ('o2')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private ArtifactInventoryRepository NewInventory() => new(
        _db,
        new PackageRepository(_db, time: _clock),
        new CacheArtifactRepository(_db),
        new VulnerabilityRepository(_db, _clock));

    [Fact]
    public async Task Storage_counts_every_plane_including_the_layers_no_catalogue_row_sees()
    {
        await SeedEveryPlaneAsync();

        long bytes = await NewInventory().ComputeStorageBytesAsync("o1");

        // 1000 hosted + 2000 proxied + 5 manifest + 900_000 layer.
        Assert.Equal(903_005, bytes);
    }

    /// <summary>
    /// The assertion that keeps the two definitions from drifting apart again. A magic constant on
    /// either side would let them diverge without failing; equality cannot.
    /// </summary>
    [Fact]
    public async Task The_enforced_quota_baseline_and_the_number_the_operator_sees_are_the_same_relation()
    {
        await SeedEveryPlaneAsync();

        var orgs = new OrgRepository(_db);
        await orgs.TryReserveStorageAsync("o1", delta: 0, quota: null);

        await using var conn = await _db.OpenAsync();
        long enforced = await conn.ExecuteScalarAsync<long>(
            "SELECT storage_used_bytes FROM org_settings WHERE org_id = 'o1'");
        var (items, _) = await orgs.ListOrgsAsync(limit: 10, offset: 0);
        long reported = items.Single(i => i.Id == "o1").StorageBytes;
        long computed = await NewInventory().ComputeStorageBytesAsync("o1");

        Assert.Equal(reported, enforced);
        Assert.Equal(computed, enforced);
    }

    [Fact]
    public async Task Storage_is_zero_for_an_org_that_holds_nothing()
    {
        await SeedEveryPlaneAsync();

        // o2 holds no artifact at all, so the view yields it no row — the caller gets 0, not null.
        Assert.Equal(0, await NewInventory().ComputeStorageBytesAsync("o2"));
    }

    [Fact]
    public async Task Listing_a_package_returns_its_versions_from_both_catalogues()
    {
        await using var conn = await _db.OpenAsync();

        // An org that privately overrides a name it also proxies holds rows on both planes.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('p1', 'o1', 'npm', 'left-pad', 'left-pad', 0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
            "VALUES ('v1', 'p1', '1.0.0', 'pkg:npm/left-pad@1.0.0', 'registry/v1', 'uploaded')");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('ca1', 'npm', 'left-pad', '1.0.1', 'left-pad-1.0.1.tgz', 'proxy/ca1', 'ca1')");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca1')");

        var rows = await NewInventory().ListForPackageAsync("o1", "npm", "left-pad");

        Assert.Equal(2, rows.Count);
        var hosted = rows.Single(r => r.Version == "1.0.0");
        Assert.Equal("package_version", hosted.OwnerKind);
        Assert.Equal("v1", hosted.OwnerId);
        var proxied = rows.Single(r => r.Version == "1.0.1");
        Assert.Equal("cache_artifact", proxied.OwnerKind);
        Assert.Equal("ca1", proxied.OwnerId);
    }

    [Fact]
    public async Task Listing_a_package_never_reaches_another_orgs_artifacts()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pt', 'o2', 'npm', 'theirs', 'theirs', 0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
            "VALUES ('vt', 'pt', '1.0.0', 'pkg:npm/theirs@1.0.0', 'registry/vt', 'uploaded')");

        var rows = await NewInventory().ListForPackageAsync("o1", "npm", "theirs");

        Assert.Empty(rows);
    }

    // ── The serve-path merge, extracted from nine copies ─────────────────────────

    [Fact]
    public async Task Serveable_versions_span_both_catalogues()
    {
        await SeedOverriddenPackageAsync();

        var versions = await NewInventory().ListServeableVersionsAsync("o1", "p1", "npm", "left-pad");

        // The hosted version and the proxied one the org has never overridden.
        Assert.Equal(["1.0.0", "2.0.0"], versions.Select(v => v.Version).OrderBy(v => v, StringComparer.Ordinal));
    }

    [Fact]
    public async Task A_privately_overridden_version_is_served_from_the_hosted_plane_not_listed_twice()
    {
        await SeedOverriddenPackageAsync();
        await using (var conn = await _db.OpenAsync())
        {
            // The org proxies 1.0.0 as well as pushing its own — the same version string on both planes.
            await conn.ExecuteAsync(
                "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
                "VALUES ('ca2', 'npm', 'left-pad', '1.0.0', 'left-pad-1.0.0.tgz', 'proxy/ca2', 'ca2')");
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca2')");
        }

        var versions = await NewInventory().ListServeableVersionsAsync("o1", "p1", "npm", "left-pad");

        // Listed once, and it is the org's own artifact that survives — not the upstream copy.
        Assert.Equal(2, versions.Count);
        var overridden = versions.Single(v => v.Version == "1.0.0");
        Assert.Equal("v1", overridden.Id);
    }

    [Fact]
    public async Task A_package_with_no_proxied_versions_still_serves_its_hosted_ones()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
                "VALUES ('p1', 'o1', 'npm', 'private-only', 'private-only', 0)");
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
                "VALUES ('v1', 'p1', '1.0.0', 'pkg:npm/private-only@1.0.0', 'registry/v1', 'uploaded')");
        }

        var versions = await NewInventory().ListServeableVersionsAsync("o1", "p1", "npm", "private-only");

        Assert.Equal("1.0.0", Assert.Single(versions).Version);
    }

    // ── NuGet proxy-vs-proxy version dedup (#395) ────────────────────────────────

    /// <summary>
    /// A NuGet proxy first-fetch mirrors the flatcontainer trio into three cache_artifact rows
    /// (.nupkg, .nuspec, .sha512) that all share one version string. ListServeableVersionsAsync
    /// dedupes proxy-vs-uploaded but is deliberately file-level otherwise (PyPI's Simple Index
    /// needs a distinct row per distribution file), so the raw return here is three rows — this
    /// pins that DedupeProxyVersionsByVersion is what a version-level NuGet renderer must apply,
    /// not something ListServeableVersionsAsync already does.
    /// </summary>
    [Fact]
    public async Task Serveable_versions_are_not_deduped_across_a_single_proxied_nuget_versions_sidecar_files()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
                "VALUES ('p1', 'o1', 'nuget', 'newtonsoft.json', 'newtonsoft.json', 1)");
            await SeedNuGetTrioAsync(conn, "newtonsoft.json", "13.0.3");
        }

        var versions = await NewInventory().ListServeableVersionsAsync("o1", "p1", "nuget", "newtonsoft.json");

        Assert.Equal(3, versions.Count);
        Assert.All(versions, v => Assert.Equal("13.0.3", v.Version));
    }

    /// <summary>
    /// DedupeProxyVersionsByVersion collapses the three same-version proxy rows to the .nupkg
    /// row (the artifact NuGet clients install, not a detached sidecar), and leaves an uploaded
    /// version alongside it untouched — the mixed-batch case a version-level renderer serves.
    /// </summary>
    [Fact]
    public async Task DedupeProxyVersionsByVersion_collapses_nuget_sidecar_rows_to_the_nupkg_row_leaving_uploaded_versions_intact()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('p1', 'o1', 'nuget', 'newtonsoft.json', 'newtonsoft.json', 0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
            "VALUES ('v1', 'p1', '1.0.0', 'pkg:nuget/newtonsoft.json@1.0.0', 'registry/v1', 'uploaded')");
        await SeedNuGetTrioAsync(conn, "newtonsoft.json", "13.0.3");

        var versions = await NewInventory().ListServeableVersionsAsync("o1", "p1", "nuget", "newtonsoft.json");
        var deduped = ArtifactInventoryRepository.DedupeProxyVersionsByVersion(versions);

        // Mixed partial-failure: the uploaded version survives untouched, and the proxied
        // version — three rows on entry — collapses to exactly one.
        Assert.Equal(2, deduped.Count);
        var uploaded = deduped.Single(v => v.Version == "1.0.0");
        Assert.Equal("uploaded", uploaded.Origin);
        var proxied = deduped.Single(v => v.Version == "13.0.3");
        Assert.Equal("proxy", proxied.Origin);
        Assert.Equal("newtonsoft.json.13.0.3.nupkg", proxied.Filename);
    }

    // Seeds the three cache_artifact rows a single proxied NuGet version casts
    // (.nupkg, .nuspec, .sha512), matching NuGetFlatContainerHandler's proxy write path, plus
    // the org's tenant_artifact_access grant for each.
    private static async Task SeedNuGetTrioAsync(
        System.Data.Common.DbConnection conn, string name, string version)
    {
        string[] filenames =
        [
            $"{name}.{version}.nupkg",
            $"{name}.nuspec",
            $"{name}.{version}.nupkg.sha512",
        ];
        foreach (string filename in filenames)
        {
            string id = $"ca-{filename}";
            await conn.ExecuteAsync(
                "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
                "VALUES (@id, 'nuget', @name, @version, @filename, @blobKey, @id)",
                new { id, name, version, filename, blobKey = $"proxy/{id}" });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', @id)",
                new { id });
        }
    }

    // A package the org both proxies and privately overrides: hosted 1.0.0, proxied 2.0.0.
    private async Task SeedOverriddenPackageAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('p1', 'o1', 'npm', 'left-pad', 'left-pad', 0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
            "VALUES ('v1', 'p1', '1.0.0', 'pkg:npm/left-pad@1.0.0', 'registry/v1', 'uploaded')");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('ca1', 'npm', 'left-pad', '2.0.0', 'left-pad-2.0.0.tgz', 'proxy/ca1', 'ca1')");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca1')");
    }

    // Hosted bytes, proxied bytes, and an OCI image whose layers dwarf the manifest its catalogue row
    // sizes — the case that made a package_versions-only baseline report almost nothing.
    private async Task SeedEveryPlaneAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('p1', 'o1', 'npm', 'hosted', 'hosted', 0), " +
            "('p2', 'o1', 'oci', 'library/nginx', 'library/nginx', 0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) VALUES " +
            "('v1', 'p1', '1.0.0', 'pkg:npm/hosted@1.0.0', 'registry/v1', 1000, 'uploaded'), " +
            "('v2', 'p2', 'sha256:abc', 'pkg:oci/nginx@sha256:abc', 'oci/sha256/abc', 5, 'uploaded')");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) " +
            "VALUES ('ca1', 'npm', 'proxied', '1.0.0', 'proxied-1.0.0.tgz', 'proxy/ca1', 'ca1', 2000)");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca1')");
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type) VALUES
              ('sha256:abc', 'o1', 'oci/sha256/abc', 5,       'application/vnd.oci.image.manifest.v1+json'),
              ('sha256:def', 'o1', 'oci/sha256/def', 900000,  'application/vnd.oci.image.layer.v1.tar+gzip')
            """);
    }
}
