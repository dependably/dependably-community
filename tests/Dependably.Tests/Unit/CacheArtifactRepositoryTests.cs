using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class CacheArtifactRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static CacheArtifact Sample(string version, DateTimeOffset accessed) => new()
    {
        Id = Guid.NewGuid().ToString("D"),
        Ecosystem = "npm",
        Name = "lodash",
        Version = version,
        Filename = $"lodash-{version}.tgz",
        BlobKey = $"proxy/abc/{version}",
        ContentHash = "sha256:abc",
        SizeBytes = 100,
        FirstCachedAt = accessed,
        LastAccessedAt = accessed
    };

    [Fact]
    public async Task GetByCoordinate_RoundTrip()
    {
        var repo = new CacheArtifactRepository(_db);
        var a = Sample("1.0.0", TestTime.KnownNow);
        await repo.InsertAsync(a);

        var loaded = await repo.GetByCoordinateAsync("npm", "lodash", "1.0.0", "lodash-1.0.0.tgz");
        Assert.NotNull(loaded);
        Assert.Equal(a.Id, loaded!.Id);
        Assert.Equal(100, loaded.SizeBytes);
    }

    [Fact]
    public async Task ListLruCandidates_ReturnsOldestFirst()
    {
        var repo = new CacheArtifactRepository(_db);
        var t = TestTime.KnownNow;
        await repo.InsertAsync(Sample("1.0.0", t.AddDays(-30)));
        await repo.InsertAsync(Sample("2.0.0", t.AddDays(-10)));
        await repo.InsertAsync(Sample("3.0.0", t.AddDays(-1)));

        var candidates = await repo.ListLruCandidatesAsync(t.AddDays(-5), limit: 10);
        Assert.Equal(2, candidates.Count);
        Assert.Equal("1.0.0", candidates[0].Version);
        Assert.Equal("2.0.0", candidates[1].Version);
    }

    [Fact]
    public async Task GetTotalSizeBytes_SumsAll()
    {
        var repo = new CacheArtifactRepository(_db);
        await repo.InsertAsync(Sample("1.0.0", TestTime.KnownNow));
        await repo.InsertAsync(Sample("2.0.0", TestTime.KnownNow));
        long total = await repo.GetTotalSizeBytesAsync();
        Assert.Equal(200, total);
    }

    [Fact]
    public async Task TouchAccess_UpdatesLastAccessedAt()
    {
        var repo = new CacheArtifactRepository(_db);
        var a = Sample("1.0.0", TestTime.KnownNow.AddDays(-100));
        await repo.InsertAsync(a);

        var newer = TestTime.KnownNow;
        await repo.TouchAccessAsync(a.Id, newer);

        var loaded = await repo.GetByCoordinateAsync("npm", "lodash", "1.0.0", "lodash-1.0.0.tgz");
        Assert.True(loaded!.LastAccessedAt > a.LastAccessedAt);
    }

    [Fact]
    public async Task Delete_Removes()
    {
        var repo = new CacheArtifactRepository(_db);
        var a = Sample("1.0.0", TestTime.KnownNow);
        await repo.InsertAsync(a);
        await repo.DeleteAsync(a.Id);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "1.0.0", "lodash-1.0.0.tgz"));
    }

    private static CacheArtifact SampleEco(string ecosystem, string name, string version, DateTimeOffset cached) => new()
    {
        Id = Guid.NewGuid().ToString("D"),
        Ecosystem = ecosystem,
        Name = name,
        Version = version,
        Filename = $"{name}-{version}.tgz",
        BlobKey = $"proxy/{Guid.NewGuid():N}",
        ContentHash = "sha256:abc",
        SizeBytes = 100,
        FirstCachedAt = cached,
        LastAccessedAt = cached
    };

    [Fact]
    public async Task ListNeedingLicenseBackfill_ReturnsOnlyNullCheckedSupportedEcosystems_OldestFirst()
    {
        var repo = new CacheArtifactRepository(_db);
        var t = TestTime.KnownNow;

        // Supported ecosystems, all un-checked. first_cached_at ascending order is b, a, c.
        await repo.InsertAsync(SampleEco("npm", "a", "1.0.0", t.AddDays(-3)));
        await repo.InsertAsync(SampleEco("pypi", "b", "1.0.0", t.AddDays(-5)));
        await repo.InsertAsync(SampleEco("nuget", "c", "1.0.0", t.AddDays(-1)));

        // Excluded — unsupported ecosystems (no bytes-level license manifest / no extractor yet).
        await repo.InsertAsync(SampleEco("maven", "d", "1.0.0", t.AddDays(-10)));
        await repo.InsertAsync(SampleEco("cargo", "e", "1.0.0", t.AddDays(-10)));

        // Excluded — already license-checked.
        var already = SampleEco("npm", "f", "1.0.0", t.AddDays(-9));
        await repo.InsertAsync(already);
        await repo.MarkLicenseCheckedAsync(already.Id, t);

        var results = await repo.ListNeedingLicenseBackfillAsync(limit: 100);

        Assert.Equal(new[] { "b", "a", "c" }, results.Select(r => r.Name).ToList());
        // Projection carries the fields the backfill service needs.
        var first = results[0];
        Assert.Equal("pypi", first.Ecosystem);
        Assert.Equal("b-1.0.0.tgz", first.Filename);
        Assert.StartsWith("proxy/", first.BlobKey);
    }

    [Fact]
    public async Task ListNeedingLicenseBackfill_RespectsLimit()
    {
        var repo = new CacheArtifactRepository(_db);
        var t = TestTime.KnownNow;
        await repo.InsertAsync(SampleEco("npm", "a", "1.0.0", t.AddDays(-3)));
        await repo.InsertAsync(SampleEco("npm", "b", "1.0.0", t.AddDays(-5)));
        await repo.InsertAsync(SampleEco("npm", "c", "1.0.0", t.AddDays(-1)));

        var results = await repo.ListNeedingLicenseBackfillAsync(limit: 2);

        // Oldest-first, capped at the limit: b(-5), a(-3).
        Assert.Equal(new[] { "b", "a" }, results.Select(r => r.Name).ToList());
    }

    [Fact]
    public async Task ListNeedingLicenseBackfill_Cursor_AdvancesPastUnstampedRows()
    {
        // Regression for progress starvation: a keyset cursor advanced from the last row of a
        // batch must exclude that batch's rows from the next page even when none of them were
        // stamped (e.g. every row in the batch failed to process). Without a cursor, a plain
        // "WHERE license_checked_at IS NULL ... LIMIT n" re-returns the identical oldest rows
        // forever and nothing behind them is ever reached within the pass.
        var repo = new CacheArtifactRepository(_db);
        var t = TestTime.KnownNow;
        var a = SampleEco("npm", "a", "1.0.0", t.AddDays(-5));
        var b = SampleEco("npm", "b", "1.0.0", t.AddDays(-4));
        var c = SampleEco("npm", "c", "1.0.0", t.AddDays(-3));
        await repo.InsertAsync(a);
        await repo.InsertAsync(b);
        await repo.InsertAsync(c);

        // First page: oldest two, none stamped (simulates every row in the batch failing).
        var page1 = await repo.ListNeedingLicenseBackfillAsync(limit: 2);
        Assert.Equal(new[] { "a", "b" }, page1.Select(r => r.Name).ToList());

        // Advance the cursor from the last row of page1 (b), as the service does after every
        // batch regardless of outcome.
        var last = page1[^1];
        var page2 = await repo.ListNeedingLicenseBackfillAsync(
            limit: 2, afterFirstCachedAt: last.FirstCachedAt, afterId: last.Id);

        // Page 2 must reach "c" — the unstamped "a"/"b" rows from page1 must NOT re-appear.
        Assert.Equal(new[] { "c" }, page2.Select(r => r.Name).ToList());
    }

    [Fact]
    public async Task ListNeedingLicenseBackfill_Cursor_TiesOnSameTimestamp_BrokenById()
    {
        // Two rows sharing the exact same first_cached_at need a total order — id is the
        // tiebreaker — so the cursor comparison (first_cached_at > @after OR (= @after AND
        // id > @afterId)) never re-returns or skips a row when timestamps collide.
        var repo = new CacheArtifactRepository(_db);
        var t = TestTime.KnownNow.AddDays(-2);
        var tied1 = SampleEco("npm", "tied1", "1.0.0", t);
        var tied2 = SampleEco("npm", "tied2", "1.0.0", t);
        // Insert whichever sorts first by id so the expected order below is unambiguous.
        var ordered = new[] { tied1, tied2 }.OrderBy(x => x.Id, StringComparer.Ordinal).ToArray();
        await repo.InsertAsync(ordered[0]);
        await repo.InsertAsync(ordered[1]);

        var page1 = await repo.ListNeedingLicenseBackfillAsync(limit: 1);
        Assert.Single(page1);
        Assert.Equal(ordered[0].Id, page1[0].Id);

        var last = page1[0];
        var page2 = await repo.ListNeedingLicenseBackfillAsync(
            limit: 1, afterFirstCachedAt: last.FirstCachedAt, afterId: last.Id);

        Assert.Single(page2);
        Assert.Equal(ordered[1].Id, page2[0].Id);
    }

    [Fact]
    public async Task MarkLicenseChecked_SetsExactTimestamp_AndDropsFromQueue()
    {
        var repo = new CacheArtifactRepository(_db);
        var row = SampleEco("npm", "a", "1.0.0", TestTime.KnownNow.AddDays(-1));
        await repo.InsertAsync(row);

        var instant = new DateTimeOffset(2026, 2, 3, 4, 5, 6, TimeSpan.Zero);
        await repo.MarkLicenseCheckedAsync(row.Id, instant);

        await using var conn = await _db.OpenAsync();
        string? checkedAt = await conn.QuerySingleAsync<string?>(
            "SELECT license_checked_at FROM cache_artifact WHERE id = @id", new { id = row.Id });
        Assert.Equal("2026-02-03T04:05:06Z", checkedAt);

        var results = await repo.ListNeedingLicenseBackfillAsync(limit: 100);
        Assert.DoesNotContain(results, r => r.Id == row.Id);
    }

    [Fact]
    public async Task UpdateVersionsBehindAsync_RoundTripsThroughListServeFactsAndSyntheticProjection()
    {
        var repo = new CacheArtifactRepository(_db);
        var a = Sample("1.0.0", TestTime.KnownNow);
        await repo.InsertAsync(a);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', @id)", new { id = a.Id });
        }

        // Unwritten default is unknown (NULL), never 0 — the synthetic projection must carry that
        // through onto PackageVersion.VersionsBehind, the shape list/detail renderers read.
        var beforeFacts = await repo.ListServeFactsForNameAsync("o1", "npm", "lodash");
        Assert.Null(Assert.Single(beforeFacts).VersionsBehind);
        Assert.Null(Assert.Single(beforeFacts).ToPackageVersionSynthetic(
            new Dictionary<string, VulnGateSignals>()).VersionsBehind);

        await repo.UpdateVersionsBehindAsync(a.Id, 3);

        var afterFacts = await repo.ListServeFactsForNameAsync("o1", "npm", "lodash");
        var fact = Assert.Single(afterFacts);
        Assert.Equal(3, fact.VersionsBehind);
        Assert.Equal(3, fact.ToPackageVersionSynthetic(new Dictionary<string, VulnGateSignals>()).VersionsBehind);
    }

    [Fact]
    public async Task UpstreamUrl_RoundTripsThroughListServeFactsAndSyntheticProjection()
    {
        var repo = new CacheArtifactRepository(_db);
        // A private/internal upstream — the whole point is that the origin is whatever the org
        // proxied from, not a reconstructed public-registry URL.
        const string upstreamUrl = "https://nexus.internal.example.com/repository/npm/lodash/-/lodash-1.0.0.tgz";
        var a = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "lodash",
            Version = "1.0.0",
            Filename = "lodash-1.0.0.tgz",
            BlobKey = "proxy/abc/1.0.0",
            ContentHash = "sha256:abc",
            SizeBytes = 100,
            UpstreamUrl = upstreamUrl,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow
        };
        await repo.InsertAsync(a);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', @id)", new { id = a.Id });
        }

        var fact = Assert.Single(await repo.ListServeFactsForNameAsync("o1", "npm", "lodash"));
        Assert.Equal(upstreamUrl, fact.UpstreamUrl);
        Assert.Equal(upstreamUrl,
            fact.ToPackageVersionSynthetic(new Dictionary<string, VulnGateSignals>()).UpstreamUrl);
    }
}
