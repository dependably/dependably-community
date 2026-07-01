using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class RetentionPurgeUnlistedTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'globex')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private RetentionService Build()
    {
        var cfg = new ConfigurationBuilder().Build();
        var clock = TestTime.Frozen();
        var jwt = new JwtRevocationRepository(_db, time: clock);
        var invites = new InviteRepository(_db, clock);
        var samlConfig = new SamlConfigRepository(_db, clock);
        return new RetentionService(new RetentionService.Dependencies(
            _db, _blobs, jwt, invites, samlConfig, cfg, NullLogger<RetentionService>.Instance, clock));
    }

    // Seeds a package + version (one package per version so purl_name stays unique), puts a
    // blob at its store key, and stamps yanked / yanked_at. Returns (versionId, blobKey).
    private async Task<(string VersionId, string BlobKey)> SeedVersionAsync(
        string orgId, string slug, string origin, int yanked, DateTimeOffset? yankedAt)
    {
        string blobKey = $"hosted/{orgId}/nuget/{slug}/1.0.0/{slug}.1.0.0.nupkg";
        await _blobs.PutAsync(BlobKeys.StoreKey(blobKey), new MemoryStream([1, 2, 3]));

        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "nuget", slug);
        string versionId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", $"pkg:nuget/{slug}@1.0.0", origin: origin, blobKey: blobKey);

        string? yankedAtStr = yankedAt?.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE package_versions SET yanked = @yanked, yanked_at = @yankedAt WHERE id = @id",
            new { id = versionId, yanked, yankedAt = yankedAtStr });
        return (versionId, blobKey);
    }

    [Fact]
    public async Task PurgeUnlisted_RemovesOnlyAgedUnlistedHostedVersions()
    {
        // Policy: purge uploaded versions unlisted more than 30 days. The frozen clock and the
        // seed offsets share TestTime.KnownNow, so the 30-day cutoff is exact (margins ±10d).
        var now = TestTime.KnownNow;

        var (agedId, agedBlob) = await SeedVersionAsync("o1", "aged", "uploaded", yanked: 1, yankedAt: now.AddDays(-40));
        var (recentId, recentBlob) = await SeedVersionAsync("o1", "recent", "uploaded", yanked: 1, yankedAt: now.AddDays(-10));
        var (liveId, liveBlob) = await SeedVersionAsync("o1", "live", "uploaded", yanked: 0, yankedAt: null);
        var (legacyId, legacyBlob) = await SeedVersionAsync("o1", "legacy-null", "uploaded", yanked: 1, yankedAt: null);
        var (proxyId, proxyBlob) = await SeedVersionAsync("o1", "proxy-aged", "proxy", yanked: 1, yankedAt: now.AddDays(-40));
        var (otherId, otherBlob) = await SeedVersionAsync("o2", "other-org", "uploaded", yanked: 1, yankedAt: now.AddDays(-40));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.PurgeUnlistedAsync(conn, "o1", afterDays: 30, default);

        // Only the aged, unlisted, hosted o1 version is gone — row and blob both.
        Assert.False(await VersionExists(conn, agedId));
        Assert.False(await _blobs.ExistsAsync(BlobKeys.StoreKey(agedBlob)));

        // Everything else survives: recent unlist, never-yanked, legacy NULL yanked_at,
        // proxy-origin, and another tenant's aged unlist.
        var kept = new[]
        {
            (recentId, recentBlob), (liveId, liveBlob), (legacyId, legacyBlob),
            (proxyId, proxyBlob), (otherId, otherBlob),
        };
        foreach (var (id, blob) in kept)
        {
            Assert.True(await VersionExists(conn, id));
            Assert.True(await _blobs.ExistsAsync(BlobKeys.StoreKey(blob)));
        }
    }

    [Fact]
    public async Task PurgeUnlisted_NothingAged_IsNoOp()
    {
        var now = TestTime.KnownNow;
        var (recentId, recentBlob) = await SeedVersionAsync("o1", "recent", "uploaded", yanked: 1, yankedAt: now.AddDays(-5));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.PurgeUnlistedAsync(conn, "o1", afterDays: 30, default);

        Assert.True(await VersionExists(conn, recentId));
        Assert.True(await _blobs.ExistsAsync(BlobKeys.StoreKey(recentBlob)));
    }

    private static async Task<bool> VersionExists(System.Data.Common.DbConnection conn, string id)
        => await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE id = @id", new { id }) == 1;
}
