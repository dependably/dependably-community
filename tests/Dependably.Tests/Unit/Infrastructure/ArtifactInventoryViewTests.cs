using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The canonical read model. Every assertion here is a statement about what a read surface written
/// against <c>artifact_inventory</c> gets for free, and what it must still not assume.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ArtifactInventoryViewTests : IAsyncLifetime
{
    private const string PushedDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    private const string PulledDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    private const string DigestOnlyPush = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'other')");
        await SeedEveryShapeAsync(conn);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>
    /// The reason the view exists. An OCI image casts a shadow into BOTH catalogues — a tag push
    /// into package_versions, a proxy pull into cache_artifact — and every "exclude OCI" guard in
    /// the codebase was written against cache_artifact alone, so each was only half-enforced. Over
    /// one ecosystem column, the predicate every author already writes finally means what they think.
    /// </summary>
    [Fact]
    public async Task Excluding_oci_by_ecosystem_excludes_both_of_its_shadows()
    {
        await using var conn = await _db.OpenAsync();

        var oci = (await conn.QueryAsync<OciRow>(
            "SELECT owner_kind AS OwnerKind, version AS Version FROM artifact_inventory " +
            "WHERE org_id = 'o1' AND ecosystem = 'oci'")).ToList();

        // Both shadows are present, under one ecosystem value.
        Assert.Equal(2, oci.Count);
        Assert.Contains(oci, r => r.OwnerKind == "package_version" && r.Version == PushedDigest);
        Assert.Contains(oci, r => r.OwnerKind == "cache_artifact" && r.Version == PulledDigest);

        // So one predicate removes both. Written against either catalogue alone, it removes one.
        var kept = (await conn.QueryAsync<string>(
            "SELECT name FROM artifact_inventory WHERE org_id = 'o1' AND ecosystem != 'oci'")).ToList();
        Assert.DoesNotContain("library/nginx", kept);
        Assert.DoesNotContain("library/alpine", kept);
        Assert.Contains("hosted-pkg", kept);
        Assert.Contains("proxied-pkg", kept);
    }

    [Fact]
    public async Task An_artifact_on_either_plane_carries_the_key_back_to_its_own_table()
    {
        await using var conn = await _db.OpenAsync();

        var rows = (await conn.QueryAsync<OwnerRow>(
            "SELECT name AS Name, owner_kind AS OwnerKind, owner_id AS OwnerId, origin AS Origin " +
            "FROM artifact_inventory WHERE org_id = 'o1' AND name IN ('hosted-pkg', 'proxied-pkg')")).ToList();

        var hosted = rows.Single(r => r.Name == "hosted-pkg");
        Assert.Equal("package_version", hosted.OwnerKind);
        Assert.Equal("vh", hosted.OwnerId);
        Assert.Equal("uploaded", hosted.Origin);

        var proxied = rows.Single(r => r.Name == "proxied-pkg");
        Assert.Equal("cache_artifact", proxied.OwnerKind);
        Assert.Equal("cap", proxied.OwnerId);
        Assert.Equal("proxy", proxied.Origin);
    }

    /// <summary>
    /// An org reaches a cache_artifact through tenant_artifact_access alone and can hold one with no
    /// packages row at all. The proxy arm LEFT JOINs packages, so the artifact stays visible with a
    /// null package_id — an INNER JOIN drops it, which is the bug this model exists to prevent.
    /// </summary>
    [Fact]
    public async Task A_proxied_artifact_with_no_packages_row_is_still_in_the_inventory()
    {
        await using var conn = await _db.OpenAsync();

        var row = await conn.QuerySingleAsync<OrphanRow>(
            "SELECT name AS Name, package_id AS PackageId, display_name AS DisplayName " +
            "FROM artifact_inventory WHERE org_id = 'o1' AND name = 'orphan-pkg'");

        Assert.Null(row.PackageId);
        Assert.Equal("orphan-pkg", row.DisplayName); // no packages row to name it; its own name stands in
    }

    /// <summary>
    /// The honest limit. An image pushed by digest reference casts no catalogue row at all, so it is
    /// not in the inventory and never will be — but its bytes ARE stored, and org_storage_bytes
    /// counts them. Encoding that here is what keeps it from becoming the next bug.
    /// </summary>
    [Fact]
    public async Task A_digest_only_pushed_image_is_absent_from_the_inventory_but_its_bytes_are_counted()
    {
        await using var conn = await _db.OpenAsync();

        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM artifact_inventory WHERE org_id = 'o1' AND version = @digest",
            new { digest = DigestOnlyPush }));

        long stored = await conn.ExecuteScalarAsync<long>(
            "SELECT total_bytes FROM org_storage_bytes WHERE org_id = 'o1'");

        // 100 hosted + 200 proxied + 10 pushed manifest + 20 pulled manifest + 50_000 digest-only layer.
        Assert.Equal(50_330, stored);
    }

    /// <summary>
    /// Storage is not SUM(inventory.size_bytes) and never will be: a catalogue row for an image
    /// sizes its manifest, not its layers. org_storage_bytes exists because that difference is not
    /// something a caller should have to remember.
    /// </summary>
    [Fact]
    public async Task Storage_counts_an_images_real_bytes_not_the_bytes_of_its_catalogue_row()
    {
        await using var conn = await _db.OpenAsync();

        long fromInventory = await conn.ExecuteScalarAsync<long>(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM artifact_inventory WHERE org_id = 'o1'");
        long fromStorage = await conn.ExecuteScalarAsync<long>(
            "SELECT total_bytes FROM org_storage_bytes WHERE org_id = 'o1'");

        Assert.Equal(330, fromInventory);      // manifests only — a wrong answer for storage
        Assert.Equal(50_330, fromStorage);     // the layer bytes no catalogue row sees
        Assert.NotEqual(fromInventory, fromStorage);
    }

    [Fact]
    public async Task The_inventory_never_shows_one_org_another_orgs_artifacts()
    {
        await using var conn = await _db.OpenAsync();

        var names = (await conn.QueryAsync<string>(
            "SELECT name FROM artifact_inventory WHERE org_id = 'o2'")).ToList();

        Assert.Equal(["theirs"], names);
    }

    [Fact]
    public async Task A_license_joins_back_to_its_artifact_on_either_plane()
    {
        await using var conn = await _db.OpenAsync();

        var rows = (await conn.QueryAsync<LicenseRow>(
            """
            SELECT ai.name AS Name, al.license_spdx AS LicenseSpdx
            FROM artifact_inventory ai
            JOIN artifact_license al
              ON al.org_id = ai.org_id AND al.owner_kind = ai.owner_kind AND al.owner_id = ai.owner_id
            WHERE ai.org_id = 'o1'
            """)).ToList();

        Assert.Equal(2, rows.Count);
        Assert.Contains(rows, r => r.Name == "hosted-pkg" && r.LicenseSpdx == "MIT");
        Assert.Contains(rows, r => r.Name == "proxied-pkg" && r.LicenseSpdx == "Apache-2.0");
    }

    private sealed record OciRow(string OwnerKind, string Version);
    private sealed record OwnerRow(string Name, string OwnerKind, string OwnerId, string Origin);
    private sealed record OrphanRow(string Name, string? PackageId, string DisplayName);
    private sealed record LicenseRow(string Name, string LicenseSpdx);

    // Every shape an artifact can take: hosted, proxied, proxied-with-no-packages-row, the two OCI
    // shadows, an image pushed by digest that casts no catalogue row, and another org's artifact.
    private static async Task SeedEveryShapeAsync(System.Data.Common.DbConnection conn)
    {
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES
              ('ph',   'o1', 'npm', 'hosted-pkg',    'hosted-pkg',    0),
              ('pp',   'o1', 'npm', 'proxied-pkg',   'proxied-pkg',   1),
              ('poci', 'o1', 'oci', 'library/nginx', 'library/nginx', 0),
              ('pt',   'o2', 'npm', 'theirs',        'theirs',        0)
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) VALUES
              ('vh',   'ph',   '1.0.0',  'pkg:npm/hosted-pkg@1.0.0', 'registry/vh', 100, 'uploaded'),
              ('voci', 'poci', @pushed,  'pkg:oci/nginx@x',          'oci/sha256/1111', 10, 'uploaded'),
              ('vt',   'pt',   '1.0.0',  'pkg:npm/theirs@1.0.0',     'registry/vt', 999, 'uploaded')
            """,
            new { pushed = PushedDigest });

        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) VALUES
              ('cap',  'npm', 'proxied-pkg',    '2.0.0', 'proxied-pkg-2.0.0.tgz', 'proxy/cap',  'cap',  200),
              ('caor', 'npm', 'orphan-pkg',     '1.0.0', 'orphan-pkg-1.0.0.tgz',  'proxy/caor', 'caor', 0),
              ('caoci','oci', 'library/alpine', @pulled, 'manifest',              'oci/sha256/2222', '2222', 20)
            """,
            new { pulled = PulledDigest });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES " +
            "('o1', 'cap'), ('o1', 'caor'), ('o1', 'caoci')");

        // The pushed image's manifest, the pulled image's manifest, and a layer belonging to an
        // image pushed by digest — which casts no catalogue row anywhere.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type) VALUES
              (@pushed,     'o1', 'oci/sha256/1111', 10,     'application/vnd.oci.image.manifest.v1+json'),
              (@pulled,     'o1', 'oci/sha256/2222', 20,     'application/vnd.oci.image.manifest.v1+json'),
              (@digestOnly, 'o1', 'oci/sha256/3333', 50000,  'application/vnd.oci.image.layer.v1.tar+gzip')
            """,
            new { pushed = PushedDigest, pulled = PulledDigest, digestOnly = DigestOnlyPush });

        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, package_version_id, owner_kind, license_spdx, source) " +
            "VALUES ('l1', 'vh', 'package_version', 'MIT', 'manifest')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, cache_artifact_id, owner_kind, license_spdx, source) " +
            "VALUES ('l2', 'cap', 'cache_artifact', 'Apache-2.0', 'upstream')");
    }
}
