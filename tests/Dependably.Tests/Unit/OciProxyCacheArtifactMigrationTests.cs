using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Regression for the OCI proxy cache-plane migration. OCI was the only proxy ecosystem whose
/// write path (<c>OciUpstreamResolver.RecordCatalogVersionAsync</c>) never joined the shared
/// <c>cache_artifact</c> / <c>tenant_artifact_access</c> plane — it kept inserting
/// <c>package_versions</c> rows with <c>origin='proxy'</c> indefinitely, so the packages-list
/// version count (which sums <c>origin='uploaded'</c> plus the cache plane) never counted them.
///
/// <c>backfill_oci_cache_artifact</c> derives cache_artifact rows primarily FROM the OCI proxy
/// <c>package_versions</c> rows <c>delete_oci_proxy_package_versions</c> is about to remove — that
/// is the only inventory that must be preserved intact, and <c>oci_tags</c> cannot reconstruct it:
/// a digest loses its <c>oci_tags</c> row the instant its tag is repointed to a newer digest
/// (<c>OciUpstreamResolver</c>'s tag-upsert <c>ON CONFLICT DO UPDATE SET digest = excluded.digest</c>),
/// so a superseded digest can have zero <c>oci_tags</c> rows while its <c>package_versions</c> row
/// (and the bytes it references) still exist. A second pass over <c>oci_blobs</c>/<c>oci_tags</c>
/// supplements any manifest with a currently-resolving tag that never got a
/// <c>package_versions</c> row at all (a defensive net for a historical write-path failure).
/// </summary>
[Trait("Category", "Schema")]
public sealed class OciProxyCacheArtifactMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";
    private const string LayerMediaType = "application/vnd.oci.image.layer.v1.tar+gzip";

    // Seeds the DB to the state before backfill_oci_cache_artifact / delete_oci_proxy_package_versions
    // run: full schema applied, both one-shots re-armed, an org, an OCI packages row, a manifest
    // oci_blobs row (origin='proxy') with a resolving oci_tags row, a layer oci_blobs row (never a
    // cache-plane candidate), and the legacy orphan package_versions row the old write path left
    // behind for the manifest pull.
    private async Task<(string ManifestDigest, string OrphanVersionId)> SeedAsync(string orgId = "o-oci")
    {
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name IN " +
            "('backfill_oci_cache_artifact', 'delete_oci_proxy_package_versions')");

        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES (@orgId, @orgId)", new { orgId });

        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES (@pkgId, @orgId, 'oci', 'library/ubuntu', 'library/ubuntu', 1)",
            new { pkgId = "pkg-" + orgId, orgId });

        string manifestDigest = "sha256:" + new string('a', 64);
        string manifestBlobKey = "oci/sha256/" + new string('a', 64);
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
            "VALUES (@digest, @orgId, @mediaType, 2048, @blobKey, 'proxy')",
            new { digest = manifestDigest, orgId, mediaType = ManifestMediaType, blobKey = manifestBlobKey });

        await conn.ExecuteAsync(
            "INSERT INTO oci_tags (org_id, repository, tag, digest) " +
            "VALUES (@orgId, 'library/ubuntu', '22.04', @digest)",
            new { orgId, digest = manifestDigest });

        // A layer blob for the same image — pure byte storage, never a cache-plane candidate.
        string layerDigest = "sha256:" + new string('b', 64);
        string layerBlobKey = "oci/sha256/" + new string('b', 64);
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
            "VALUES (@digest, @orgId, @mediaType, 4096, @blobKey, 'proxy')",
            new { digest = layerDigest, orgId, mediaType = LayerMediaType, blobKey = layerBlobKey });

        // The orphan package_versions row the pre-fix write path inserted for the manifest pull.
        string orphanId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin, first_fetch) " +
            "VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, 2048, 'proxy', 1)",
            new
            {
                id = orphanId,
                pkgId = "pkg-" + orgId,
                version = manifestDigest,
                purl = $"pkg:oci/ubuntu@{manifestDigest.Replace(":", "%3A")}?repository_url=library/ubuntu&tag=22.04",
                blobKey = manifestBlobKey,
                filename = manifestBlobKey,
            });

        return (manifestDigest, orphanId);
    }

    [Fact]
    public async Task OciLicenseBackfill_SameDigestProxiedByTwoOrgs_DoesNotCollide()
    {
        // The cache-plane licence backfill derives its row id as 'ocilic-' || cache_artifact.id.
        // cache_artifact is GLOBAL (one row per digest) while oci_blobs is per-org, so two orgs that
        // both proxied the same licensed image make the INSERT...SELECT emit two rows with the SAME
        // id — a PK collision that (pre-fix) rolled the transactional migration back and crash-looped
        // the boot on a multi-tenant upgrade. Asserts the backfill completes and leaves exactly one
        // licence row for the shared artefact.
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        // Re-arm only the licence backfill so it re-runs over the two-org data seeded below.
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name = 'backfill_oci_licenses_to_shared_plane'");

        string digest = "sha256:" + new string('b', 64);
        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o-a','org-a'), ('o-b','org-b')");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('ca-shared','oci','library/img',@digest,'manifest','oci/sha256/bbbb','bbbb')",
            new { digest });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o-a','ca-shared'),('o-b','ca-shared')");
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, license_spdx) VALUES " +
            "(@digest,'o-a',@mt,1,'oci/sha256/bbbb','proxy','MIT'), " +
            "(@digest,'o-b',@mt,1,'oci/sha256/bbbb','proxy','MIT')",
            new { digest, mt = ManifestMediaType });

        // Must not throw (pre-fix: duplicate 'ocilic-ca-shared' PK → transactional rollback → boot loop).
        await new SchemaInitializer(_db).InitializeAsync();

        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_licenses " +
            "WHERE cache_artifact_id = 'ca-shared' AND owner_kind = 'cache_artifact'"));
    }

    [Fact]
    public async Task ManifestRow_BackfillsIntoCacheArtifactAndTenantArtifactAccess()
    {
        var (manifestDigest, _) = await SeedAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        var row = await conn.QuerySingleOrDefaultAsync<(string Id, string Name, string Version, string Filename, string BlobKey, string ContentHash, string? Purl)>(
            """
            SELECT id AS Id, name AS Name, version AS Version, filename AS Filename,
                   blob_key AS BlobKey, content_hash AS ContentHash, purl AS Purl
            FROM cache_artifact WHERE ecosystem = 'oci' AND name = 'library/ubuntu'
            """);

        Assert.NotEqual(default, row);
        Assert.Equal(manifestDigest, row.Version);
        Assert.Equal("manifest", row.Filename);
        Assert.Equal("oci/sha256/" + new string('a', 64), row.BlobKey);
        Assert.Equal(new string('a', 64), row.ContentHash);
        Assert.NotNull(row.Purl);
        Assert.StartsWith("pkg:oci/ubuntu@sha256%3A", row.Purl);
        Assert.Contains("tag=22.04", row.Purl);

        long accessRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access ta " +
            "JOIN cache_artifact ca ON ca.id = ta.cache_artifact_id " +
            "WHERE ta.org_id = 'o-oci' AND ca.ecosystem = 'oci' AND ca.name = 'library/ubuntu'");
        Assert.Equal(1, accessRows);
    }

    [Fact]
    public async Task OrphanPackageVersionsRow_IsDeletedAfterBackfill()
    {
        var (_, orphanVersionId) = await SeedAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        string? stillExists = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE id = @id", new { id = orphanVersionId });
        Assert.Null(stillExists);
    }

    [Fact]
    public async Task LayerBlob_NeverBackfillsIntoCacheArtifact()
    {
        await SeedAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Only one cache_artifact row exists for this org: the manifest. The layer blob (a
        // non-manifest media type) never lands a cache-plane row — layers stay pure byte
        // storage in oci_blobs.
        long cacheRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'oci'");
        Assert.Equal(1, cacheRows);
    }

    // A manifest with no resolving oci_tags row AND no package_versions row (a pure by-digest
    // sub-manifest fetch — the old write path only catalogued tag pulls) has no repository name
    // to catalogue it under, so the backfill skips it — matching pre-migration behaviour where
    // such a manifest was never catalogued either. Contrast with
    // RepointedTag_PackageVersionsRowSurvivesEvenWithoutResolvingOciTagsRow below: a digest that
    // DOES have a package_versions row is never skipped, even once its oci_tags row is gone.
    [Fact]
    public async Task ManifestWithNoResolvingTag_IsSkipped()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name IN " +
            "('backfill_oci_cache_artifact', 'delete_oci_proxy_package_versions')");
        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o-untagged','o-untagged')");

        string digest = "sha256:" + new string('c', 64);
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
            "VALUES (@digest, 'o-untagged', @mediaType, 1024, @blobKey, 'proxy')",
            new { digest, mediaType = ManifestMediaType, blobKey = "oci/sha256/" + new string('c', 64) });
        // Deliberately no oci_tags row for this digest.

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        long cacheRows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'oci' AND version = @digest",
            new { digest });
        Assert.Equal(0, cacheRows);
    }

    // Regression: a tag is mutable (docker pull my-image:stable resolves to a new digest on every
    // upstream release). OciUpstreamResolver's tag-upsert is ON CONFLICT DO UPDATE SET digest =
    // excluded.digest, so once 'stable' repoints from digest A to digest B, digest A's oci_tags
    // row is GONE — even though A was fully catalogued (package_versions row) under the old write
    // path and its bytes are still present. A backfill sourced from oci_blobs/oci_tags alone would
    // skip A (no resolving repository) and then delete_oci_proxy_package_versions would remove its
    // package_versions row right after — silently losing a previously-catalogued image from
    // inventory forever while its bytes keep counting toward storage. The backfill must source
    // primarily from package_versions so A survives regardless of oci_tags' current state.
    [Fact]
    public async Task RepointedTag_PackageVersionsRowSurvivesEvenWithoutResolvingOciTagsRow()
    {
        const string orgId = "o-repoint";
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name IN " +
            "('backfill_oci_cache_artifact', 'delete_oci_proxy_package_versions')");
        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES (@orgId, @orgId)", new { orgId });
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg-repoint', @orgId, 'oci', 'library/nginx', 'library/nginx', 1)",
            new { orgId });

        // Digest A: the superseded manifest. Fully catalogued by the old write path
        // (package_versions row present) but no longer resolvable via oci_tags — 'stable' has
        // moved on to digest B.
        string digestA = "sha256:" + new string('1', 64);
        string blobKeyA = "oci/sha256/" + new string('1', 64);
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
            "VALUES (@digest, @orgId, @mediaType, 1000, @blobKey, 'proxy')",
            new { digest = digestA, orgId, mediaType = ManifestMediaType, blobKey = blobKeyA });
        string versionAId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin, first_fetch) " +
            "VALUES (@id, 'pkg-repoint', @version, @purl, @blobKey, @filename, 1000, 'proxy', 1)",
            new
            {
                id = versionAId,
                version = digestA,
                purl = $"pkg:oci/nginx@{digestA.Replace(":", "%3A")}?repository_url=library/nginx&tag=stable",
                blobKey = blobKeyA,
                filename = blobKeyA,
            });
        // Deliberately no oci_tags row resolves to digestA — 'stable' has been repointed to B.

        // Digest B: the current manifest 'stable' resolves to now.
        string digestB = "sha256:" + new string('2', 64);
        string blobKeyB = "oci/sha256/" + new string('2', 64);
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
            "VALUES (@digest, @orgId, @mediaType, 2000, @blobKey, 'proxy')",
            new { digest = digestB, orgId, mediaType = ManifestMediaType, blobKey = blobKeyB });
        string versionBId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin, first_fetch) " +
            "VALUES (@id, 'pkg-repoint', @version, @purl, @blobKey, @filename, 2000, 'proxy', 1)",
            new
            {
                id = versionBId,
                version = digestB,
                purl = $"pkg:oci/nginx@{digestB.Replace(":", "%3A")}?repository_url=library/nginx&tag=stable",
                blobKey = blobKeyB,
                filename = blobKeyB,
            });
        await conn.ExecuteAsync(
            "INSERT INTO oci_tags (org_id, repository, tag, digest) " +
            "VALUES (@orgId, 'library/nginx', 'stable', @digest)",
            new { orgId, digest = digestB });

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();

        // The invariant: both package_versions rows the delete step removed must have a
        // cache_artifact row first, regardless of oci_tags' current state.
        long cacheRowsA = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'oci' AND name = 'library/nginx' AND version = @digest",
            new { digest = digestA });
        Assert.Equal(1, cacheRowsA);

        long cacheRowsB = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'oci' AND name = 'library/nginx' AND version = @digest",
            new { digest = digestB });
        Assert.Equal(1, cacheRowsB);

        // Digest A's cache_artifact carries its original 'tag=stable' purl qualifier and byte
        // size — read verbatim from package_versions, not recomputed.
        var (rowASizeBytes, rowAPurl) = await verify.QuerySingleAsync<(long SizeBytes, string? Purl)>(
            "SELECT size_bytes AS SizeBytes, purl AS Purl FROM cache_artifact " +
            "WHERE ecosystem = 'oci' AND name = 'library/nginx' AND version = @digest",
            new { digest = digestA });
        Assert.Equal(1000, rowASizeBytes);
        Assert.Contains("tag=stable", rowAPurl);

        // Both orphan package_versions rows are gone — only after both were preserved above.
        Assert.Null(await verify.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE id = @id", new { id = versionAId }));
        Assert.Null(await verify.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE id = @id", new { id = versionBId }));

        // Both tenant_artifact_access rows exist for this org.
        long accessRows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access ta " +
            "JOIN cache_artifact ca ON ca.id = ta.cache_artifact_id " +
            "WHERE ta.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.name = 'library/nginx'",
            new { orgId });
        Assert.Equal(2, accessRows);
    }

    // Two tenants pulled the same image (same digest, same repository name) before the fix
    // shipped — a shared upstream image, two orgs. The backfill must converge both onto the
    // single global cache_artifact row and grant each its own tenant_artifact_access row (the
    // same many-tenants-one-artifact dedup every other proxy ecosystem's migration follows).
    [Fact]
    public async Task TwoTenants_SameImage_ConvergeOnSingleCacheArtifact()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name IN " +
            "('backfill_oci_cache_artifact', 'delete_oci_proxy_package_versions')");

        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o-shared1','o-shared1')");
        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o-shared2','o-shared2')");

        string digest = "sha256:" + new string('d', 64);
        string blobKey = "oci/sha256/" + new string('d', 64);

        foreach (string orgId in new[] { "o-shared1", "o-shared2" })
        {
            await conn.ExecuteAsync(
                "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
                "VALUES (@pkgId, @orgId, 'oci', 'library/alpine', 'library/alpine', 1)",
                new { pkgId = "pkg-" + orgId, orgId });
            await conn.ExecuteAsync(
                "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
                "VALUES (@digest, @orgId, @mediaType, 512, @blobKey, 'proxy')",
                new { digest, orgId, mediaType = ManifestMediaType, blobKey });
            await conn.ExecuteAsync(
                "INSERT INTO oci_tags (org_id, repository, tag, digest) " +
                "VALUES (@orgId, 'library/alpine', 'latest', @digest)",
                new { orgId, digest });
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();

        long cacheRows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'oci' AND name = 'library/alpine' AND version = @digest",
            new { digest });
        Assert.Equal(1, cacheRows);

        long accessRows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access ta " +
            "JOIN cache_artifact ca ON ca.id = ta.cache_artifact_id " +
            "WHERE ca.ecosystem = 'oci' AND ca.name = 'library/alpine'");
        Assert.Equal(2, accessRows);
    }
}
