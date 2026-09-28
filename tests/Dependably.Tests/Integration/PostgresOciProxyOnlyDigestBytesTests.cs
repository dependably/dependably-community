using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres twin of <c>CacheArtifactRepositoryTests</c>' SQLite coverage for
/// <see cref="CacheArtifactRepository.GetOciProxyOnlyDistinctDigestBytesAsync"/> —
/// <c>CacheSizeAlertService</c>'s OCI measurement source. The query's <c>NOT EXISTS</c>
/// self-correlation and <c>GROUP BY digest</c> shape is exactly the kind of construct that can
/// silently misbehave under Postgres's stricter grouping rules even though SQLite tolerates it,
/// so it earns its own live assertion rather than inheriting the SQLite result on trust.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresOciProxyOnlyDigestBytesTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private static async Task InsertOciBlobAsync(
        IMetadataStore db, string digest, string orgId, long sizeBytes, string origin)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.layer.v1.tar+gzip', @sizeBytes, @blobKey, @origin)
            """,
            new { digest, orgId, sizeBytes, blobKey = $"oci/{digest}", origin });
    }

    [Fact]
    public async Task SharedProxyDigest_CountsOnce_UploadedDigest_ExcludedEntirely_AgainstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string org1 = await OrgSeeder.InsertAsync(store, "pg-oci-proxy-1");
        string org2 = await OrgSeeder.InsertAsync(store, "pg-oci-proxy-2");

        // Pulled via proxy by both orgs — the same physical, content-addressed layer, so it must
        // be counted once, not once per (digest, org_id) row.
        await InsertOciBlobAsync(store, "sha256:shared-layer", org1, 5000, "proxy");
        await InsertOciBlobAsync(store, "sha256:shared-layer", org2, 5000, "proxy");

        // org1 pushed this digest directly (uploaded); org2 separately pulled the identical
        // content via proxy. An uploaded row anywhere makes the whole digest a hosted artefact,
        // excluded even from org2's otherwise-ordinary-looking proxy row.
        await InsertOciBlobAsync(store, "sha256:mixed-layer", org1, 7000, "uploaded");
        await InsertOciBlobAsync(store, "sha256:mixed-layer", org2, 7000, "proxy");

        var repo = new CacheArtifactRepository(store);
        Assert.Equal(5000, await repo.GetOciProxyOnlyDistinctDigestBytesAsync());
    }

    [Fact]
    public async Task ProxiedManifest_ExcludedAsAlreadyCountedByCacheArtifact_LayerStillCounted_AgainstLivePostgres()
    {
        // A proxied OCI manifest pull writes both an oci_blobs row (origin='proxy') and a
        // cache_artifact row (ecosystem='oci', version=digest) — OciUpstreamResolver.Cache.cs plus
        // RecordCatalogVersionAsync. GetTotalSizeBytesAsync already counts the cache_artifact row,
        // so the oci_blobs row for that same digest must be excluded here or the manifest's bytes
        // are counted twice. Its layer, which only ever gets an oci_blobs row, must still count.
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(store, "pg-oci-manifest");
        const string manifestDigest = "sha256:manifest-live";
        const string layerDigest = "sha256:layer-live";

        await InsertOciBlobAsync(store, manifestDigest, orgId, 5000, "proxy");
        await InsertOciBlobAsync(store, layerDigest, orgId, 800_000, "proxy");

        var repo = new CacheArtifactRepository(store);
        await repo.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("N"),
            Ecosystem = "oci",
            Name = "library/nginx",
            Version = manifestDigest,
            Filename = "manifest.json",
            BlobKey = $"oci/{manifestDigest}",
            ContentHash = "sha256:manifest-live",
            SizeBytes = 5000,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        });

        Assert.Equal(800_000, await repo.GetOciProxyOnlyDistinctDigestBytesAsync());
        Assert.Equal(5000, await repo.GetTotalSizeBytesAsync());
    }
}
