using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// OCI now participates in every <see cref="RetentionService"/> eviction arm — the keep_versions
/// cap, the keep_days cutoff, and the unlisted purge — on both planes. These tests replace the
/// exclusion suite that pinned the opposite, and the inversion is the point: "unlimited" used to be
/// the only honest OCI retention setting because every other value silently did nothing.
///
/// What must NOT change is how the bytes come off. An OCI catalogue row's <c>blob_key</c> is the
/// manifest, which <c>oci_blobs</c> also points at and which the image's layers hang off, so
/// retention must never issue the direct blob delete it uses for every other ecosystem. It releases
/// the digest claim instead, and the physical delete is left to the cross-org refcount. Each
/// eviction assertion below is therefore paired with a byte-level one: the row goes, and the
/// manifest survives unless nothing claims it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RetentionServiceOciEvictionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private RetentionService Build()
    {
        var cfg = new ConfigurationBuilder().Build();
        var jwt = new JwtRevocationRepository(_db, time: _clock);
        var invites = new InviteRepository(_db, _clock);
        var samlConfig = new SamlConfigRepository(_db, _clock);
        return new RetentionService(new RetentionService.Dependencies(
            _db, _blobs, jwt, invites, samlConfig, new TrustedDeviceService(_db, _clock, cfg), cfg, new AirGapMode(cfg),
            NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new Dependably.Storage.TieredBlobStorage(_blobs, _blobs),
                new Dependably.Protocol.OciBlobKeyLock())));
    }

    // ── Cache plane ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task EnforceVersionLimit_NowEvictsExcessOciVersions()
    {
        var t = _clock.GetUtcNow();

        await SeedCacheArtifactAsync("oci", "library/ubuntu", "sha256:" + new string('1', 64), "manifest", t.AddDays(-30));
        await SeedCacheArtifactAsync("oci", "library/ubuntu", "sha256:" + new string('2', 64), "manifest", t.AddDays(-20));
        await SeedCacheArtifactAsync("oci", "library/ubuntu", "sha256:" + new string('3', 64), "manifest", t.AddDays(-10));

        // npm alongside, as the control that the cap itself still behaves.
        await SeedCacheArtifactAsync("npm", "left-pad", "1.0.0", "left-pad-1.0.0.tgz", t.AddDays(-30));
        await SeedCacheArtifactAsync("npm", "left-pad", "1.0.1", "left-pad-1.0.1.tgz", t.AddDays(-20));
        await SeedCacheArtifactAsync("npm", "left-pad", "1.0.2", "left-pad-1.0.2.tgz", t.AddDays(-10));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EnforceVersionLimitAsync(conn, "o1", keepVersions: 2, default);

        Assert.Equal(2, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'oci'"));
        Assert.Equal(2, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm'"));
    }

    [Fact]
    public async Task EnforceVersionLimit_DoesNotDeleteTheManifestBytesDirectly()
    {
        var t = _clock.GetUtcNow();
        string oldest = "sha256:" + new string('1', 64);
        await SeedCacheArtifactAsync("oci", "library/ubuntu", oldest, "manifest", t.AddDays(-30));
        await SeedCacheArtifactAsync("oci", "library/ubuntu", "sha256:" + new string('2', 64), "manifest", t.AddDays(-20));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EnforceVersionLimitAsync(conn, "o1", keepVersions: 1, default);

        // The catalogue row is gone, but the manifest bytes are not retention's to delete: they are
        // governed by the oci_blobs refcount and reclaimed by the sweep. A direct delete here is
        // what would strand the image's layers with no manifest to reach them from.
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE version = @v", new { v = oldest }));
        Assert.True(await _blobs.ExistsAsync(
            BlobKeys.StoreKey(BlobKeys.OciBlob("sha256", oldest.Replace("sha256:", "")))));
    }

    [Fact]
    public async Task EvictStaleBlobs_NowEvictsOciPastTheCutoff_WithoutDeletingTheManifestBytes()
    {
        var t = _clock.GetUtcNow();
        string digest = "sha256:" + new string('4', 64);
        string ociId = await SeedCacheArtifactAsync("oci", "library/alpine", digest, "manifest", t.AddDays(-100));
        string npmId = await SeedCacheArtifactAsync("npm", "stale-pkg", "1.0.0", "stale-pkg-1.0.0.tgz", t.AddDays(-100));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EvictStaleBlobsAsync(conn, "o1", keepDays: 7, default);

        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE id = @id", new { id = ociId }));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE id = @id", new { id = npmId }));

        Assert.True(await _blobs.ExistsAsync(
            BlobKeys.StoreKey(BlobKeys.OciBlob("sha256", digest.Replace("sha256:", "")))));
    }

    // ── Uploaded plane ───────────────────────────────────────────────────────────

    [Fact]
    public async Task PurgeUnlisted_NowPurgesAPushedOciImage_AndReleasesItsTagAndBlobRow()
    {
        var t = _clock.GetUtcNow();
        string digest = "sha256:" + new string('a', 64);
        var (versionId, blobKey) = await SeedPushedOciImageAsync("library/nginx", digest, t.AddDays(-100));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.PurgeUnlistedAsync(conn, "o1", afterDays: 7, default);

        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE id = @id", new { id = versionId }));

        // The tag has to go with it. A surviving oci_tags row is one of the claims the reclaim sweep
        // honours, so leaving it would pin the manifest and its whole layer closure forever — the
        // eviction would look like it worked and reclaim nothing.
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM oci_tags"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM oci_blobs"));

        // Nothing claims the digest any more, so the bytes are genuinely orphaned and come off —
        // through the cross-org refcount, not a direct delete.
        Assert.False(await _blobs.ExistsAsync(BlobKeys.StoreKey(blobKey)));
    }

    [Fact]
    public async Task PurgeUnlisted_KeepsTheManifestBytes_WhenAnotherRepositoryStillTagsTheDigest()
    {
        var t = _clock.GetUtcNow();
        string digest = "sha256:" + new string('a', 64);
        var (versionId, blobKey) = await SeedPushedOciImageAsync("library/nginx", digest, t.AddDays(-100));

        // The same digest tagged under a second repository — content-addressing makes this the
        // normal mirror-and-retag shape, not an edge case.
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "INSERT INTO oci_tags (org_id, repository, tag, digest) VALUES ('o1', 'team/nginx', 'stable', @digest)",
                new { digest });
        }

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.PurgeUnlistedAsync(conn, "o1", afterDays: 7, default);

        // The purged repository's own catalogue row and tag go, but the surviving claim under the
        // other repository must keep both the oci_blobs row and the bytes alive.
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE id = @id", new { id = versionId }));
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM oci_blobs"));
        Assert.True(await _blobs.ExistsAsync(BlobKeys.StoreKey(blobKey)));
    }

    [Fact]
    public async Task EnforceVersionLimit_NowEvictsPushedOciVersionsBeyondTheCap()
    {
        var t = _clock.GetUtcNow();
        await SeedPushedOciImageAsync("library/nginx", "sha256:" + new string('a', 64), t.AddDays(-30));

        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                """
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, created_at) VALUES
                  ('voci2', 'poci', 'sha256:' || @b, 'pkg:oci/library/nginx@x', 'oci/sha256/bbbb', 'uploaded', '2026-01-01T00:00:00Z'),
                  ('voci3', 'poci', 'sha256:' || @c, 'pkg:oci/library/nginx@y', 'oci/sha256/cccc', 'uploaded', '2026-01-02T00:00:00Z')
                """,
                new { b = new string('b', 64), c = new string('c', 64) });
        }

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EnforceVersionLimitAsync(conn, "o1", keepVersions: 1, default);

        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE package_id = 'poci'"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private async Task<string> SeedCacheArtifactAsync(
        string ecosystem, string name, string version, string filename,
        DateTimeOffset accessed, long size = 100)
    {
        string blobKey = ecosystem == "oci"
            ? BlobKeys.OciBlob("sha256", version.Replace("sha256:", ""))
            : BlobKeys.Proxy(Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(name + version))).ToLowerInvariant());
        await _blobs.PutAsync(blobKey, new MemoryStream(new byte[size]));

        var repo = new CacheArtifactRepository(_db);
        var inserted = await repo.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = ecosystem,
            Name = name,
            Version = version,
            Filename = filename,
            BlobKey = blobKey,
            ContentHash = "abc123",
            SizeBytes = size,
            FirstCachedAt = accessed,
            LastAccessedAt = accessed,
        });

        var access = new TenantArtifactAccessRepository(_db);
        await access.UpsertAsync("o1", inserted.Id, accessed);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE tenant_artifact_access SET last_used = @accessed WHERE org_id = 'o1' AND cache_artifact_id = @id",
            new { accessed = accessed.ToUtcIso(), id = inserted.Id });

        return inserted.Id;
    }

    /// <summary>
    /// Seeds the full shadow a tag push casts: a package_versions row whose blob_key is the
    /// manifest, the oci_blobs row for the digest, its tag, and the manifest bytes. Marked yanked at
    /// <paramref name="lastUsed"/> so the unlisted purge can reach it.
    /// </summary>
    private async Task<(string VersionId, string BlobKey)> SeedPushedOciImageAsync(
        string repository, string digest, DateTimeOffset lastUsed, long size = 100)
    {
        string blobKey = BlobKeys.OciBlob("sha256", digest.Replace("sha256:", ""));
        await _blobs.PutAsync(blobKey, new MemoryStream(new byte[size]));

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES ('poci', 'o1', 'oci', @repository, @repository)",
            new { repository });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin, last_used, yanked, yanked_at)
            VALUES ('voci', 'poci', @digest, 'pkg:oci/' || @repository || '@' || @digest, @blobKey, @size, 'uploaded', @lastUsed, 1, @lastUsed)
            """,
            new { digest, repository, blobKey, size, lastUsed = lastUsed.ToUtcIso() });
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type) " +
            "VALUES (@digest, 'o1', @blobKey, @size, 'application/vnd.oci.image.manifest.v1+json')",
            new { digest, blobKey, size });
        await conn.ExecuteAsync(
            "INSERT INTO oci_tags (org_id, repository, tag, digest) VALUES ('o1', @repository, 'latest', @digest)",
            new { repository, digest });

        return ("voci", blobKey);
    }
}
