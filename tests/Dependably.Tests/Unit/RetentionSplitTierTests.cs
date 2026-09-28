using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Which tier each retention pass deletes from when the cache and registry tiers are separate
/// stores. A proxied blob lives in the cache tier, so the keep_versions trim, the keep_days trim,
/// and the tenant-bound reclaim must delete it there — a delete aimed at the registry tier is a
/// silent no-op that leaves the bytes stored while their rows are gone. Uploaded versions and
/// project documents live in the registry tier, and deleting them must leave the cache tier alone.
///
/// <para>
/// Each case puts a copy of the doomed key in the OTHER tier as well, so a pass that deleted from
/// both tiers, or from the wrong one, fails as surely as one that deleted from neither.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class RetentionSplitTierTests : IAsyncLifetime
{
    private const string OrgId = "o1";

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _cache = new();
    private readonly InMemoryBlobStore _registry = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@OrgId, 'acme')", new { OrgId });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@OrgId) ON CONFLICT (org_id) DO NOTHING", new { OrgId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task KeepVersionsProxyTrim_DeletesTheBlobFromTheCacheTier()
    {
        var t = _clock.GetUtcNow();
        string oldKey = await SeedProxyVersionAsync("left-pad", "1.0.0", t.AddDays(-20), lastUsed: null);
        string newKey = await SeedProxyVersionAsync("left-pad", "2.0.0", t.AddDays(-1), lastUsed: null);
        await _registry.PutAsync(oldKey, new MemoryStream(new byte[10]));

        await using var conn = await _db.OpenAsync();
        await Build().EnforceVersionLimitAsync(conn, OrgId, keepVersions: 1, CancellationToken.None);

        Assert.False(await _cache.ExistsAsync(oldKey), "the trimmed version's bytes are still in the cache tier");
        Assert.True(await _cache.ExistsAsync(newKey));
        Assert.True(await _registry.ExistsAsync(oldKey), "the proxy trim reached into the registry tier");
    }

    [Fact]
    public async Task KeepDaysStaleTrim_DeletesTheBlobFromTheCacheTier()
    {
        var t = _clock.GetUtcNow();
        string staleKey = await SeedProxyVersionAsync("is-odd", "1.0.0", t.AddDays(-100), lastUsed: t.AddDays(-100));
        string freshKey = await SeedProxyVersionAsync("is-even", "1.0.0", t.AddDays(-1), lastUsed: t.AddDays(-1));
        await _registry.PutAsync(staleKey, new MemoryStream(new byte[10]));

        await using var conn = await _db.OpenAsync();
        await Build().EvictStaleBlobsAsync(conn, OrgId, keepDays: 30, CancellationToken.None);

        Assert.False(await _cache.ExistsAsync(staleKey), "the stale version's bytes are still in the cache tier");
        Assert.True(await _cache.ExistsAsync(freshKey));
        Assert.True(await _registry.ExistsAsync(staleKey), "the stale trim reached into the registry tier");
    }

    [Fact]
    public async Task TenantBoundReclaim_DeletesTheDivergentBlobFromTheCacheTier()
    {
        var t = _clock.GetUtcNow();
        string divergentKey = BlobKeys.Proxy(new string('d', 64));
        await SeedProxyVersionAsync("pad-left", "1.0.0", t.AddDays(-20), lastUsed: null, tenantBlobKey: divergentKey);
        await SeedProxyVersionAsync("pad-left", "2.0.0", t.AddDays(-1), lastUsed: null);
        await _cache.PutAsync(divergentKey, new MemoryStream(new byte[900]));
        await _registry.PutAsync(divergentKey, new MemoryStream(new byte[900]));

        await using var conn = await _db.OpenAsync();
        await Build().EnforceVersionLimitAsync(conn, OrgId, keepVersions: 1, CancellationToken.None);

        Assert.False(await _cache.ExistsAsync(divergentKey), "the tenant-bound bytes are still in the cache tier");
        Assert.True(await _registry.ExistsAsync(divergentKey), "the tenant-bound reclaim reached into the registry tier");
    }

    [Fact]
    public async Task UploadedVersionTrim_DeletesFromTheRegistryTier_AndLeavesTheCacheTierAlone()
    {
        string oldKey = BlobKeys.Hosted(OrgId, "npm", "hosted-pkg", "1.0.0", "hosted-pkg-1.0.0.tgz");
        string newKey = BlobKeys.Hosted(OrgId, "npm", "hosted-pkg", "1.0.1", "hosted-pkg-1.0.1.tgz");
        await _registry.PutAsync(BlobKeys.StoreKey(oldKey), new MemoryStream(new byte[10]));
        await _registry.PutAsync(BlobKeys.StoreKey(newKey), new MemoryStream(new byte[10]));
        await _cache.PutAsync(BlobKeys.StoreKey(oldKey), new MemoryStream(new byte[10]));
        int cacheKeys = await CountAsync(_cache);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES ('pkg-h', @OrgId, 'npm', 'hosted-pkg', 'hosted-pkg')",
            new { OrgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, created_at)
            VALUES ('v-old', 'pkg-h', '1.0.0', 'pkg:npm/hosted-pkg@1.0.0', @oldKey, 'uploaded', @t1),
                   ('v-new', 'pkg-h', '1.0.1', 'pkg:npm/hosted-pkg@1.0.1', @newKey, 'uploaded', @t2)
            """,
            new
            {
                oldKey,
                newKey,
                t1 = _clock.GetUtcNow().AddDays(-20).ToUtcIso(),
                t2 = _clock.GetUtcNow().AddDays(-1).ToUtcIso(),
            });

        await Build().EnforceVersionLimitAsync(conn, OrgId, keepVersions: 1, CancellationToken.None);

        Assert.False(await _registry.ExistsAsync(BlobKeys.StoreKey(oldKey)), "the trimmed upload is still in the registry tier");
        Assert.True(await _registry.ExistsAsync(BlobKeys.StoreKey(newKey)));
        Assert.Equal(cacheKeys, await CountAsync(_cache));
    }

    [Fact]
    public async Task ProjectDocumentGc_DeletesFromTheRegistryTier_AndLeavesTheCacheTierAlone()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO projects (id, org_id, name) VALUES ('proj', @OrgId, 'app')", new { OrgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, is_active, created_at)
            VALUES ('pv-old', @OrgId, 'proj', '1.0.0', 0, 0, @t1),
                   ('pv-new', @OrgId, 'proj', '2.0.0', 1, 1, @t2)
            """,
            new { OrgId, t1 = TestTime.KnownNow.AddDays(-20).ToUtcIso(), t2 = TestTime.KnownNow.AddDays(-1).ToUtcIso() });

        string sha = new('a', 64);
        string docKey = BlobKeys.ProjectDocument(OrgId, "proj", "pv-old", "sbom", sha);
        await conn.ExecuteAsync(
            """
            INSERT INTO project_documents (id, org_id, project_version_id, doc_type, format, sha256, size_bytes, blob_key)
            VALUES ('doc-old', @OrgId, 'pv-old', 'sbom', 'cyclonedx-json', @sha, 16, @docKey)
            """,
            new { OrgId, sha, docKey });
        await _registry.PutAsync(BlobKeys.StoreKey(docKey), new MemoryStream(new byte[16]));
        await _cache.PutAsync(BlobKeys.StoreKey(docKey), new MemoryStream(new byte[16]));
        int cacheKeys = await CountAsync(_cache);

        await Build().EnforceProjectVersionLimitAsync(conn, OrgId, keepProjectVersions: 1, CancellationToken.None);

        Assert.False(await _registry.ExistsAsync(BlobKeys.StoreKey(docKey)), "the swept document is still in the registry tier");
        Assert.Equal(cacheKeys, await CountAsync(_cache));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private RetentionService Build()
    {
        var cfg = new ConfigurationBuilder().Build();
        var tiered = new TieredBlobStorage(_cache, _registry);
        return new RetentionService(new RetentionService.Dependencies(
            _db, tiered, new JwtRevocationRepository(_db, time: _clock),
            new InviteRepository(_db, _clock), new SamlConfigRepository(_db, _clock), new TrustedDeviceService(_db, _clock, cfg),
            cfg, new AirGapMode(cfg), NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(_db, tiered, new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg),
            new OrgStatsHistoryRepository(_db),
            new BackgroundJobRunRepository(_db),
            new Dependably.Infrastructure.Usage.UsageEventRepository(_db),
            new Dependably.Infrastructure.Usage.UsageRollupRepository(_db)));
    }

    // Seeds one proxied npm version for the org with its blob in the cache tier; returns the key.
    private async Task<string> SeedProxyVersionAsync(
        string name, string version, DateTimeOffset accessed, DateTimeOffset? lastUsed, string? tenantBlobKey = null)
    {
        string blobKey = BlobKeys.Proxy(Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(name + version))).ToLowerInvariant());
        await _cache.PutAsync(blobKey, new MemoryStream(new byte[10]));

        var inserted = await new CacheArtifactRepository(_db).InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = name,
            Version = version,
            Filename = $"{name}-{version}.tgz",
            BlobKey = blobKey,
            ContentHash = "abc123",
            SizeBytes = 10,
            FirstCachedAt = accessed,
            LastAccessedAt = accessed,
        });

        var access = new TenantArtifactAccessRepository(_db);
        await access.UpsertAsync(OrgId, inserted.Id, accessed, TenantContentBinding.None);
        if (lastUsed is { } used)
        {
            await access.UpsertStateAsync(OrgId, inserted.Id, used);
        }

        if (tenantBlobKey is not null)
        {
            await using var conn = await _db.OpenAsync();
            await conn.ExecuteAsync(
                """
                UPDATE tenant_artifact_access SET blob_key = @tenantBlobKey, content_hash = @hash, size_bytes = 900
                WHERE org_id = @OrgId AND cache_artifact_id = @id
                """,
                new { tenantBlobKey, hash = new string('d', 64), OrgId, id = inserted.Id });
        }

        return blobKey;
    }

    private static async Task<int> CountAsync(IBlobStore store)
    {
        int count = 0;
        await foreach (var _ in store.ListAsync(""))
        {
            count++;
        }

        return count;
    }
}
