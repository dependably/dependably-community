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

        // Supported ecosystems, all un-checked. first_cached_at ascending order is e, b, a, c.
        await repo.InsertAsync(SampleEco("npm", "a", "1.0.0", t.AddDays(-3)));
        await repo.InsertAsync(SampleEco("pypi", "b", "1.0.0", t.AddDays(-5)));
        await repo.InsertAsync(SampleEco("nuget", "c", "1.0.0", t.AddDays(-1)));
        // Every cargo cache row is the crate tarball itself, so no filename discriminator is
        // needed the way maven's .pom sidecar needs one below.
        await repo.InsertAsync(SampleEco("cargo", "e", "1.0.0", t.AddDays(-10)));

        // Excluded — a maven row whose filename is not the .pom that carries the licence block.
        await repo.InsertAsync(SampleEco("maven", "d", "1.0.0", t.AddDays(-10)));

        // Excluded — already license-checked.
        var already = SampleEco("npm", "f", "1.0.0", t.AddDays(-9));
        await repo.InsertAsync(already);
        await repo.MarkLicenseCheckedAsync(already.Id, t);

        var results = await repo.ListNeedingLicenseBackfillAsync(limit: 100);

        Assert.Equal(new[] { "e", "b", "a", "c" }, results.Select(r => r.Name).ToList());
        // Projection carries the fields the backfill service needs.
        var first = results[1];
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

    // ── DateTimeOffsetHandler round-trip — SchemaInitializer.OwnerPlane.cs's global Dapper
    // handler is the sole thing standing between a raw DateTimeOffset property (FirstCachedAt,
    // LastAccessedAt below) and the TEXT the column actually stores. ─────────────────────────

    [Fact]
    public async Task InsertAsync_FirstCachedAt_MatchesExplicitCanonicalWriterShape()
    {
        // Regression: cache_artifact.first_cached_at is also written by an explicit
        // UtcTimestamp.ToUtcIso() string (the schema DEFAULT and the one-shot cache-plane
        // migration both use that shape). Before the fix, Dapper's built-in typeMap claimed the
        // DateTimeOffset parameter before the registered DateTimeOffsetHandler ever saw it, so
        // SetValue never ran; the ADO.NET provider serialized it directly instead — space-
        // separated, offset preserved (Microsoft.Data.Sqlite: "2026-03-04 05:06:07+00:00"), never
        // the canonical "T…Z" form. That disagreed with every other writer of the same columns,
        // breaking lexicographic ordering whenever rows from both writers land in the same table
        // (the mismatch flips ordering only within the same calendar day — the date prefix still
        // sorts correctly across days).
        var repo = new CacheArtifactRepository(_db);
        var instant = new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.Zero);
        var a = Sample("9.0.0", instant);
        await repo.InsertAsync(a);

        await using var conn = await _db.OpenAsync();
        var (firstCachedAt, lastAccessedAt) = await conn.QuerySingleAsync<(string FirstCachedAt, string LastAccessedAt)>(
            "SELECT first_cached_at AS FirstCachedAt, last_accessed_at AS LastAccessedAt " +
            "FROM cache_artifact WHERE id = @id",
            new { id = a.Id });

        Assert.Equal(instant.ToUtcIso(), firstCachedAt);
        Assert.Equal(instant.ToUtcIso(), lastAccessedAt);
    }

    [Fact]
    public async Task InsertAsync_NonZeroOffsetInstant_NormalizesToCanonicalUtc()
    {
        // +02:00 offset representing 2026-03-04T03:06:07Z. Before the fix, SetValue never ran
        // (see the class summary above) — Microsoft.Data.Sqlite's own DateTimeOffset
        // serialization preserved the +02:00 offset verbatim instead of converting to UTC first,
        // so this row would sort by its wall-clock time rather than its real instant.
        var repo = new CacheArtifactRepository(_db);
        var instant = new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.FromHours(2));
        var a = Sample("9.0.1", instant);
        await repo.InsertAsync(a);

        await using var conn = await _db.OpenAsync();
        string stored = await conn.QuerySingleAsync<string>(
            "SELECT first_cached_at FROM cache_artifact WHERE id = @id", new { id = a.Id });

        Assert.Equal("2026-03-04T03:06:07Z", stored);
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

    /// <summary>
    /// Every ecosystem's cache-hit lookup runs through the same two per-tenant projections, so the
    /// tenant content binding has to win in both for all of them — the fix cannot be npm-shaped.
    /// The theory walks the ecosystems that reach these projections, seeding a shared row holding
    /// one tenant's bytes plus a binding holding another's, and asserting the serving tenant reads
    /// its own hash, blob key and size back from each.
    /// </summary>
    [Theory]
    [InlineData("npm", "lodash", "4.17.21", "lodash-4.17.21.tgz")]
    [InlineData("pypi", "requests", "2.31.0", "requests-2.31.0-py3-none-any.whl")]
    [InlineData("nuget", "newtonsoft.json", "13.0.3", "newtonsoft.json.13.0.3.nupkg")]
    [InlineData("nuget-symbols", "app.pdb", "ssqp-key", "app.pdb")]
    [InlineData("maven", "com.example:lib", "1.0.0", "lib-1.0.0.jar")]
    [InlineData("terraform", "registry.terraform.io/hashicorp/aws", "5.0.0", "linux_amd64.zip")]
    [InlineData("cargo", "serde", "1.0.0", "serde-1.0.0.crate")]
    [InlineData("rpm", "bash", "5.2.15-1.el9", "bash-5.2.15-1.el9.x86_64.rpm")]
    [InlineData("apk", "busybox", "1.36.1-r5", "main/x86_64/busybox-1.36.1-r5.apk")]
    [InlineData("golang", "github.com/pkg/errors", "v0.9.1", "v0.9.1.zip")]
    public async Task ServeFacts_PreferTenantBinding_ForEveryProxyEcosystem(
        string ecosystem, string name, string version, string filename)
    {
        var repo = new CacheArtifactRepository(_db);
        const string sharedHash = "1111aaaa";
        const string ownHash = "2222bbbb";

        var shared = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = ecosystem,
            Name = name,
            Version = version,
            Filename = filename,
            BlobKey = $"proxy/{sharedHash}/{filename}",
            ContentHash = sharedHash,
            SizeBytes = 10,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        };
        await repo.InsertAsync(shared);

        await new TenantArtifactAccessRepository(_db).UpsertAsync(
            "o1", shared.Id, TestTime.KnownNow,
            new TenantContentBinding($"{ownHash}", $"proxy/{ownHash}/{filename}", 20));

        var byCoordinate = await repo.GetServeFactsByCoordinateAsync("o1", ecosystem, name, version, filename);
        var byId = await repo.GetServeFactsByIdAsync("o1", shared.Id);
        foreach (var facts in new[] { byCoordinate, byId })
        {
            Assert.NotNull(facts);
            Assert.Equal(ownHash, facts!.ContentHash);
            Assert.Equal($"proxy/{ownHash}/{filename}", facts.BlobKey);
            Assert.Equal(20, facts.SizeBytes);
        }

        // The index/metadata renderers publish the same values as the integrity a client checks
        // against, so they must agree with what the download path will actually stream.
        var indexFacts = Assert.Single(await repo.ListServeFactsForNameAsync("o1", ecosystem, name));
        Assert.Equal(ownHash, indexFacts.ContentHash);
        Assert.Equal($"proxy/{ownHash}/{filename}", indexFacts.BlobKey);
        Assert.Equal(20, indexFacts.SizeBytes);
    }

    /// <summary>
    /// Adversarial twin: a tenant with no binding — a row written before the binding columns
    /// existed, or by a preceding release during a blue-green cutover — still resolves to the
    /// shared row rather than to nothing. Failing that access closed would 503 every legacy
    /// coordinate on the first boot after an upgrade.
    /// </summary>
    [Fact]
    public async Task ServeFacts_WithNoTenantBinding_FallBackToTheSharedRow()
    {
        var repo = new CacheArtifactRepository(_db);
        var shared = Sample("9.9.9", TestTime.KnownNow);
        await repo.InsertAsync(shared);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', @id)",
                new { id = shared.Id });
        }

        var facts = await repo.GetServeFactsByCoordinateAsync("o1", "npm", "lodash", "9.9.9", "lodash-9.9.9.tgz");
        Assert.NotNull(facts);
        Assert.Equal(shared.ContentHash, facts!.ContentHash);
        Assert.Equal(shared.BlobKey, facts.BlobKey);
        Assert.Equal(shared.SizeBytes, facts.SizeBytes);
    }

    /// <summary>
    /// A blob a tenant is bound to must survive the eviction of an unrelated coordinate that
    /// happens to share the content-addressed key. The refcount behind
    /// <c>CacheOrphanBlobDeleter</c> counts tenant bindings as references for exactly this:
    /// a divergent tenant's bytes have no <c>cache_artifact</c> row of their own, so counting rows
    /// alone would let a sibling eviction delete bytes that are still being served.
    /// </summary>
    [Fact]
    public async Task BlobKeyReferencedElsewhere_CountsTenantBindings()
    {
        var repo = new CacheArtifactRepository(_db);
        var evicting = Sample("1.2.3", TestTime.KnownNow);
        var other = Sample("4.5.6", TestTime.KnownNow);
        await repo.InsertAsync(evicting);
        await repo.InsertAsync(other);

        const string boundKey = "proxy/deadbeef/lodash-1.2.3.tgz";

        // No row and no binding names the key yet.
        Assert.False(await repo.BlobKeyReferencedElsewhereAsync(boundKey, evicting.Id));

        // A tenant bound to those bytes through a DIFFERENT row keeps them alive.
        await new TenantArtifactAccessRepository(_db).UpsertAsync(
            "o1", other.Id, TestTime.KnownNow, new TenantContentBinding("deadbeef", boundKey, 10));
        Assert.True(await repo.BlobKeyReferencedElsewhereAsync(boundKey, evicting.Id));

        // A binding on the row being evicted is not a reference — it cascades away with it.
        Assert.False(await repo.BlobKeyReferencedElsewhereAsync(boundKey, other.Id));
    }
    /// <summary>
    /// A tenant whose own upstream served other bytes must not be advertised the shared row's
    /// byte-derived claims. <c>checksum_sha1</c>, <c>upstream_integrity_value</c> and
    /// <c>manifest_json</c> live only on the shared <c>cache_artifact</c> row, so for a diverging
    /// tenant they describe another tenant's artefact — and <c>NpmPackumentHandler</c> replaces the
    /// upstream version object with this projection precisely so the advertised integrity matches
    /// the bytes the tarball route streams. Advertising a foreign SRI beside this tenant's own
    /// SHA-256 therefore turns every install of the coordinate into EINTEGRITY: a refusal the
    /// tenant cannot clear, caused by a coordinate another tenant reached first. That is the same
    /// un-remediable cross-tenant denial the binding exists to avoid, arriving through the metadata
    /// instead of the bytes. The claims are omitted rather than guessed; the tenant's own SHA-256
    /// still stands, because that one describes the bytes it holds.
    /// </summary>
    [Fact]
    public async Task IndexFacts_ForADivergingTenant_OmitTheSharedRowsByteDerivedClaims()
    {
        var repo = new CacheArtifactRepository(_db);
        const string sharedHash = "1111aaaa";
        const string ownHash = "2222bbbb";

        var shared = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "left-pad",
            Version = "1.3.0",
            Filename = "left-pad-1.3.0.tgz",
            BlobKey = $"proxy/{sharedHash}/left-pad-1.3.0.tgz",
            ContentHash = sharedHash,
            SizeBytes = 10,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        };
        await repo.InsertAsync(shared);
        await repo.UpdateGlobalFactsAsync(
            shared.Id,
            purl: "pkg:npm/left-pad@1.3.0",
            checksumSha1: "5150dead",
            publishedAt: null,
            deprecated: null,
            hasInstallScript: false,
            installScriptKind: null,
            provenanceStatus: null,
            provenanceSigner: null,
            upstreamIntegrityValue: "sha512-sharedRowIntegrityOverOtherBytes==",
            upstreamIntegrityAlgorithm: "sha512-sri",
            manifestJson: """{"dependencies":{"from-the-other-tenants-tarball":"1.0.0"}}""");

        await new TenantArtifactAccessRepository(_db).UpsertAsync(
            "o1", shared.Id, TestTime.KnownNow,
            new TenantContentBinding(ownHash, $"proxy/{ownHash}/left-pad-1.3.0.tgz", 20));

        var facts = Assert.Single(await repo.ListServeFactsForNameAsync("o1", "npm", "left-pad"));
        Assert.True(facts.ContentDivergesFromSharedFacts);

        var synthetic = facts.ToPackageVersionSynthetic(new Dictionary<string, VulnGateSignals>());
        Assert.Equal(ownHash, synthetic.ChecksumSha256);
        Assert.Null(synthetic.ChecksumSha1);
        Assert.Null(synthetic.UpstreamIntegrityValue);
        Assert.Null(synthetic.UpstreamIntegrityAlgorithm);
        Assert.Null(synthetic.ManifestJson);
    }

    /// <summary>
    /// Adversarial twin: the non-diverging tenant — every tenant, on every coordinate, in normal
    /// operation — keeps every one of those claims. Suppressing them unconditionally would also
    /// pass the test above while stripping <c>dist.integrity</c> from the whole proxy cache and
    /// dropping every install manifest the packument renders.
    /// </summary>
    [Fact]
    public async Task IndexFacts_ForANonDivergingTenant_KeepTheSharedRowsByteDerivedClaims()
    {
        var repo = new CacheArtifactRepository(_db);
        const string hash = "1111aaaa";

        var shared = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "right-pad",
            Version = "1.3.0",
            Filename = "right-pad-1.3.0.tgz",
            BlobKey = $"proxy/{hash}/right-pad-1.3.0.tgz",
            ContentHash = hash,
            SizeBytes = 10,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        };
        await repo.InsertAsync(shared);
        await repo.UpdateGlobalFactsAsync(
            shared.Id,
            purl: "pkg:npm/right-pad@1.3.0",
            checksumSha1: "5150beef",
            publishedAt: null,
            deprecated: null,
            hasInstallScript: false,
            installScriptKind: null,
            provenanceStatus: null,
            provenanceSigner: null,
            upstreamIntegrityValue: "sha512-integrityOverTheseVeryBytes==",
            upstreamIntegrityAlgorithm: "sha512-sri",
            manifestJson: """{"dependencies":{"leftpad":"1.0.0"}}""");

        await new TenantArtifactAccessRepository(_db).UpsertAsync(
            "o1", shared.Id, TestTime.KnownNow,
            new TenantContentBinding(hash, $"proxy/{hash}/right-pad-1.3.0.tgz", 10));

        var facts = Assert.Single(await repo.ListServeFactsForNameAsync("o1", "npm", "right-pad"));
        Assert.False(facts.ContentDivergesFromSharedFacts);

        var synthetic = facts.ToPackageVersionSynthetic(new Dictionary<string, VulnGateSignals>());
        Assert.Equal("5150beef", synthetic.ChecksumSha1);
        Assert.Equal("sha512-integrityOverTheseVeryBytes==", synthetic.UpstreamIntegrityValue);
        Assert.Equal("sha512-sri", synthetic.UpstreamIntegrityAlgorithm);
        Assert.Equal("""{"dependencies":{"leftpad":"1.0.0"}}""", synthetic.ManifestJson);
    }

    /// <summary>
    /// A tenant with no binding at all is being served the shared blob, so the shared row's claims
    /// describe exactly those bytes and must be kept. This is the legacy/blue-green row, and it is
    /// the case where treating "hashes are not equal" as the test rather than "both hashes are
    /// known and unequal" would strip integrity from every un-backfilled coordinate.
    /// </summary>
    [Fact]
    public async Task IndexFacts_WithNoTenantBinding_KeepTheSharedRowsByteDerivedClaims()
    {
        var repo = new CacheArtifactRepository(_db);
        var shared = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "no-pad",
            Version = "1.3.0",
            Filename = "no-pad-1.3.0.tgz",
            BlobKey = "proxy/1111aaaa/no-pad-1.3.0.tgz",
            ContentHash = "1111aaaa",
            SizeBytes = 10,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        };
        await repo.InsertAsync(shared);
        await repo.UpdateGlobalFactsAsync(
            shared.Id,
            purl: "pkg:npm/no-pad@1.3.0",
            checksumSha1: "5150cafe",
            publishedAt: null,
            deprecated: null,
            hasInstallScript: false,
            installScriptKind: null,
            provenanceStatus: null,
            provenanceSigner: null,
            upstreamIntegrityValue: "sha512-legacyRowIntegrity==",
            upstreamIntegrityAlgorithm: "sha512-sri",
            manifestJson: null);

        await new TenantArtifactAccessRepository(_db).UpsertAsync(
            "o1", shared.Id, TestTime.KnownNow, TenantContentBinding.None);

        var facts = Assert.Single(await repo.ListServeFactsForNameAsync("o1", "npm", "no-pad"));
        Assert.False(facts.ContentDivergesFromSharedFacts);

        var synthetic = facts.ToPackageVersionSynthetic(new Dictionary<string, VulnGateSignals>());
        Assert.Equal("5150cafe", synthetic.ChecksumSha1);
        Assert.Equal("sha512-legacyRowIntegrity==", synthetic.UpstreamIntegrityValue);
    }

    /// <summary>
    /// Go modules are recorded via <c>CacheAccessOrigin.FirstFetchUnidentified</c>: the fetch path
    /// never hashes the <c>.zip</c> it stages, so the tenant binds its own (tenant-scoped)
    /// <c>blob_key</c> but no <c>content_hash</c> at all. Before the fix this bound-but-unhashed
    /// shape read as non-divergent — <c>ContentHash</c> (the COALESCEd value) fell back to the
    /// shared row's hash on both sides of the comparison, so it always equalled
    /// <c>SharedContentHash</c> regardless of whether this tenant's own bytes actually matched.
    /// <see cref="CacheArtifactIndexFacts.ContentDivergesFromSharedFacts"/> must read this as
    /// diverging: a real blob key with no hash to verify it against is exactly the "unknown, and
    /// unknown must not read as safe" case the binding exists to catch.
    /// </summary>
    [Fact]
    public async Task IndexFacts_GoShapedBoundButUnhashedBinding_IsDetectedAsDiverging()
    {
        var repo = new CacheArtifactRepository(_db);
        var shared = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "go",
            Name = "example.com/mod",
            Version = "v1.0.0",
            Filename = "v1.0.0.zip",
            BlobKey = "proxy/shared-hash/v1.0.0.zip",
            ContentHash = "shared-hash",
            SizeBytes = 10,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        };
        await repo.InsertAsync(shared);
        await repo.UpdateGlobalFactsAsync(
            shared.Id, purl: "pkg:golang/example.com/mod@v1.0.0", checksumSha1: null,
            publishedAt: null, deprecated: null, hasInstallScript: false, installScriptKind: null,
            provenanceStatus: null, provenanceSigner: null,
            upstreamIntegrityValue: null, upstreamIntegrityAlgorithm: null);

        // CacheAccessRecorder.BindingFor's FirstFetchUnidentified shape: a real, tenant-scoped
        // blob key, and deliberately no hash (the fetch path never computes one for Go).
        await new TenantArtifactAccessRepository(_db).UpsertAsync(
            "o1", shared.Id, TestTime.KnownNow,
            new TenantContentBinding(ContentHash: null, BlobKey: "go/o1/example.com/mod@v1.0.0.zip", SizeBytes: null));

        var indexFacts = Assert.Single(await repo.ListServeFactsForNameAsync("o1", "go", "example.com/mod"));
        Assert.True(indexFacts.ContentDivergesFromSharedFacts);

        var serveFacts = await repo.GetServeFactsByCoordinateAsync("o1", "go", "example.com/mod", "v1.0.0", "v1.0.0.zip");
        Assert.NotNull(serveFacts);
        Assert.True(serveFacts!.ContentDivergesFromSharedFacts);
    }

    /// <summary>
    /// Adversarial twin at the same coordinate shape: a real hash binding that happens to match
    /// the shared row (the ordinary, non-divergent case for a hashing ecosystem) must not be swept
    /// into "diverging" by an overly broad bound-but-unhashed check.
    /// </summary>
    [Fact]
    public async Task ServeFacts_BoundWithMatchingHash_IsNotDiverging()
    {
        var repo = new CacheArtifactRepository(_db);
        const string hash = "same-hash-both-sides";
        var shared = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "same-bytes",
            Version = "1.0.0",
            Filename = "same-bytes-1.0.0.tgz",
            BlobKey = $"proxy/{hash}/same-bytes-1.0.0.tgz",
            ContentHash = hash,
            SizeBytes = 10,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        };
        await repo.InsertAsync(shared);

        await new TenantArtifactAccessRepository(_db).UpsertAsync(
            "o1", shared.Id, TestTime.KnownNow,
            new TenantContentBinding(hash, $"proxy/{hash}/same-bytes-1.0.0.tgz", 10));

        var serveFacts = await repo.GetServeFactsByCoordinateAsync("o1", "npm", "same-bytes", "1.0.0", "same-bytes-1.0.0.tgz");
        Assert.NotNull(serveFacts);
        Assert.False(serveFacts!.ContentDivergesFromSharedFacts);
    }
}
