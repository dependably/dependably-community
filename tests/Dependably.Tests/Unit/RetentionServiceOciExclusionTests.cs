using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// OCI is excluded from the per-org proxy-eviction arms of <see cref="RetentionService"/>
/// (<see cref="RetentionService.EnforceVersionLimitAsync"/> keep_versions cap and
/// <see cref="RetentionService.EvictStaleBlobsAsync"/> keep_days cap). Evicting an OCI
/// cache_artifact row would delete the manifest blob while its <c>oci_blobs</c> row and layer
/// blobs survive — a broken serve path and orphaned layers. Correct OCI eviction needs layer
/// refcounting, out of scope here, so OCI stays never-evicted from the cache plane.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RetentionServiceOciExclusionTests : IAsyncLifetime
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
            _db, _blobs, jwt, invites, samlConfig, cfg, new AirGapMode(cfg),
            NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock)));
    }

    // Seeds a cache_artifact + tenant_artifact_access row for org 'o1' and puts its blob in the
    // store, so eviction has something concrete to (attempt to) remove.
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
        // Backdate last_used so EvictStaleBlobsAsync's cutoff comparison sees it as stale too.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE tenant_artifact_access SET last_used = @accessed WHERE org_id = 'o1' AND cache_artifact_id = @id",
            new { accessed = accessed.ToString("yyyy-MM-ddTHH:mm:ssZ"), id = inserted.Id });

        return inserted.Id;
    }

    [Fact]
    public async Task EnforceVersionLimit_KeepsAllOciVersions_EvictsExcessNpm()
    {
        var t = _clock.GetUtcNow();

        // Three OCI manifests for the same repository, all older than the keep-2 cap.
        await SeedCacheArtifactAsync("oci", "library/ubuntu", "sha256:" + new string('1', 64), "manifest", t.AddDays(-30));
        await SeedCacheArtifactAsync("oci", "library/ubuntu", "sha256:" + new string('2', 64), "manifest", t.AddDays(-20));
        await SeedCacheArtifactAsync("oci", "library/ubuntu", "sha256:" + new string('3', 64), "manifest", t.AddDays(-10));

        // Three npm versions for comparison, same keep-2 cap — the oldest must be evicted.
        await SeedCacheArtifactAsync("npm", "left-pad", "1.0.0", "left-pad-1.0.0.tgz", t.AddDays(-30));
        await SeedCacheArtifactAsync("npm", "left-pad", "1.0.1", "left-pad-1.0.1.tgz", t.AddDays(-20));
        await SeedCacheArtifactAsync("npm", "left-pad", "1.0.2", "left-pad-1.0.2.tgz", t.AddDays(-10));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EnforceVersionLimitAsync(conn, "o1", keepVersions: 2, default);

        long ociRemaining = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'oci'");
        Assert.Equal(3, ociRemaining); // none evicted, despite exceeding the keep-2 cap

        long npmRemaining = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm'");
        Assert.Equal(2, npmRemaining); // oldest evicted, cap enforced
    }

    [Fact]
    public async Task EvictStaleBlobs_KeepsOciEvenWhenFarPastCutoff_EvictsStaleNpm()
    {
        var t = _clock.GetUtcNow();

        string ociId = await SeedCacheArtifactAsync(
            "oci", "library/alpine", "sha256:" + new string('4', 64), "manifest", t.AddDays(-100));
        string npmId = await SeedCacheArtifactAsync(
            "npm", "stale-pkg", "1.0.0", "stale-pkg-1.0.0.tgz", t.AddDays(-100));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EvictStaleBlobsAsync(conn, "o1", keepDays: 7, default);

        long ociRemaining = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE id = @id", new { id = ociId });
        Assert.Equal(1, ociRemaining);

        long npmRemaining = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE id = @id", new { id = npmId });
        Assert.Equal(0, npmRemaining);
    }

    // ── The pushed shadow ────────────────────────────────────────────────────────
    // An image reaches the catalogue through either plane: a proxy pull writes a cache_artifact row
    // (covered above), a tag push writes a package_versions row whose blob_key is the manifest. The
    // uploaded-plane arms must carry the same exclusion — deleting that row destroys the manifest
    // while the oci_blobs row, the tags, and every layer blob survive.

    // Seeds a pushed OCI image: packages + a package_versions row (origin='uploaded', version = the
    // manifest digest) + its manifest blob + the oci_blobs/oci_tags rows a real push writes.
    private async Task<(string VersionId, string BlobKey)> SeedPushedOciImageAsync(
        string repository, string digest, DateTimeOffset lastUsed, long size = 100)
    {
        string blobKey = BlobKeys.OciBlob("sha256", digest.Replace("sha256:", ""));
        await _blobs.PutAsync(blobKey, new MemoryStream(new byte[size]));

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('poci', 'o1', 'oci', @repository, @repository, 0)",
            new { repository });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin, last_used, yanked, yanked_at)
            VALUES ('voci', 'poci', @digest, 'pkg:oci/' || @repository || '@' || @digest, @blobKey, @size, 'uploaded', @lastUsed, 1, @lastUsed)
            """,
            new { digest, repository, blobKey, size, lastUsed = lastUsed.ToString("yyyy-MM-ddTHH:mm:ssZ") });
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type) " +
            "VALUES (@digest, 'o1', @blobKey, @size, 'application/vnd.oci.image.manifest.v1+json')",
            new { digest, blobKey, size });
        await conn.ExecuteAsync(
            "INSERT INTO oci_tags (org_id, repository, tag, digest) VALUES ('o1', @repository, 'latest', @digest)",
            new { repository, digest });

        return ("voci", blobKey);
    }

    // Every uploaded-plane arm must leave the image, its manifest blob, its tag, and its oci_blobs
    // row intact — the blob assertion is the one that matters, because deleting it is what orphans
    // the layers.
    private async Task AssertPushedImageSurvivedAsync(string versionId, string blobKey)
    {
        await using var conn = await _db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE id = @id", new { id = versionId }));
        Assert.True(await _blobs.ExistsAsync(BlobKeys.StoreKey(blobKey)));
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM oci_blobs"));
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM oci_tags"));
    }

    [Fact]
    public async Task EnforceVersionLimit_KeepsPushedOciManifest_EvenBeyondTheKeepCap()
    {
        var t = _clock.GetUtcNow();
        var (versionId, blobKey) = await SeedPushedOciImageAsync(
            "library/nginx", "sha256:" + new string('a', 64), t.AddDays(-30));

        // Two more digests for the same repository, so the image is well past a keep-1 cap.
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

        Assert.Equal(3, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE package_id = 'poci'"));
        await AssertPushedImageSurvivedAsync(versionId, blobKey);
    }

    [Fact]
    public async Task EvictStaleBlobs_KeepsPushedOciManifest_EvenFarPastTheCutoff()
    {
        var t = _clock.GetUtcNow();
        var (versionId, blobKey) = await SeedPushedOciImageAsync(
            "library/nginx", "sha256:" + new string('a', 64), t.AddDays(-100));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EvictStaleBlobsAsync(conn, "o1", keepDays: 7, default);

        await AssertPushedImageSurvivedAsync(versionId, blobKey);
    }

    [Fact]
    public async Task PurgeUnlisted_KeepsPushedOciManifest_EvenWhenYankedPastTheCutoff()
    {
        var t = _clock.GetUtcNow();
        // SeedPushedOciImageAsync marks the row yanked at the same instant, so the purge cutoff hits it.
        var (versionId, blobKey) = await SeedPushedOciImageAsync(
            "library/nginx", "sha256:" + new string('a', 64), t.AddDays(-100));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.PurgeUnlistedAsync(conn, "o1", afterDays: 7, default);

        await AssertPushedImageSurvivedAsync(versionId, blobKey);
    }
}
