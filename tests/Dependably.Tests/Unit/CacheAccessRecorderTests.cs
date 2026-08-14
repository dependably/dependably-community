using System.Data.Common;
using System.Diagnostics.Metrics;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit;

// Attaches a MeterListener filtered only by DependablyMeter.MeterName + instrument name and
// asserts exact counts — must run alone against the process-wide static meter.
// See MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class CacheAccessRecorderTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private string _orgId = "";

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = _orgId, slug = $"org-{_orgId[..8]}" });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private CacheAccessRecorder BuildRecorder(ILogger<CacheAccessRecorder>? logger = null)
    {
        var cache = new CacheArtifactRepository(_db);
        var access = new TenantArtifactAccessRepository(_db);
        return new CacheAccessRecorder(
            cache,
            access,
            logger ?? NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>(),
            TimeProvider.System);
    }

    private CacheAccess SampleAccess(string? orgId = null) => new(
        OrgId: orgId ?? _orgId,
        Ecosystem: "npm",
        Name: "lodash",
        Version: "4.17.21",
        Filename: "lodash-4.17.21.tgz",
        Sha256: "abc123def456",
        SizeBytes: 1024,
        BlobKey: "proxy/npm/lodash/4.17.21/lodash-4.17.21.tgz",
        UpstreamUrl: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        Origin: CacheAccessOrigin.FirstFetch);

    [Fact]
    public async Task RecordAccessAsync_NewArtifact_InsertsArtifactAndRecordsTenantAccess()
    {
        var recorder = BuildRecorder();
        var access = SampleAccess();

        await recorder.RecordAccessAsync(access);

        await using var conn = await _db.OpenAsync();

        long artifactCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'lodash' AND version = '4.17.21'");
        Assert.Equal(1, artifactCount);

        long tenantCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = @orgId",
            new { orgId = _orgId });
        Assert.Equal(1, tenantCount);

        long accessCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT taa.access_count
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId
              AND ca.ecosystem = 'npm' AND ca.name = 'lodash' AND ca.version = '4.17.21'
            """,
            new { orgId = _orgId });
        Assert.Equal(1, accessCount);
    }

    [Fact]
    public async Task RecordAccessAsync_ExistingArtifact_TouchesLastAccessedAndBumpsCount()
    {
        var recorder = BuildRecorder();
        var access = SampleAccess();

        await recorder.RecordAccessAsync(access);
        await recorder.RecordAccessAsync(access);

        await using var conn = await _db.OpenAsync();

        // Only one cache_artifact row for the coordinate.
        long artifactCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'lodash' AND version = '4.17.21'");
        Assert.Equal(1, artifactCount);

        // access_count must be 2 after two calls for the same org+artifact.
        long accessCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT taa.access_count
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId
              AND ca.ecosystem = 'npm' AND ca.name = 'lodash' AND ca.version = '4.17.21'
            """,
            new { orgId = _orgId });
        Assert.Equal(2, accessCount);
    }

    [Fact]
    public async Task RecordAccessAsync_DbMissing_DoesNotThrow_AndLogsEveryAttempt()
    {
        // Drop the cache_artifact table so any query against it will throw.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DROP TABLE IF EXISTS tenant_artifact_access");
            await conn.ExecuteAsync("DROP TABLE IF EXISTS cache_artifact");
        }

        var logger = Substitute.For<ILogger<CacheAccessRecorder>>();
        var recorder = BuildRecorder(logger);

        // Must NOT throw. The recorder reports failure by returning null; what the caller does about
        // it is the caller's decision, not this class's.
        string? id = null;
        var ex = await Record.ExceptionAsync(async () => id = await recorder.RecordAccessAsync(SampleAccess()));
        Assert.Null(ex);
        Assert.Null(id);

        // Two attempts, two warnings. The count is asserted deliberately: it is the retry, and a
        // silent drop back to a single attempt would take the recovery below with it.
        logger.Received(2).Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    /// <summary>
    /// The reason the retry exists. The dominant failure here is contention on the metadata store,
    /// and a second attempt turns it into an ordinary success — which matters because a proxied
    /// artefact with no cache-plane row is one the registry can neither scan nor evict, and the fetch
    /// that produced it cannot be gated against anything.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_FirstAttemptFails_SecondSucceeds()
    {
        var logger = Substitute.For<ILogger<CacheAccessRecorder>>();
        var flaky = new FailsOnceStore(_db);
        var recorder = new CacheAccessRecorder(
            new CacheArtifactRepository(flaky),
            new TenantArtifactAccessRepository(flaky),
            logger,
            TimeProvider.System);

        string? id = await recorder.RecordAccessAsync(SampleAccess());

        // The first attempt threw and was swallowed; the second recorded the artefact.
        Assert.NotNull(id);
        Assert.Equal(1, flaky.Failures);

        await using var check = await _db.OpenAsync();
        Assert.Equal(1, await check.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM cache_artifact"));
    }

    // Throws on its first connection and behaves normally thereafter — a transient store failure
    // that clears on its own, which is the failure the retry is for.
    private sealed class FailsOnceStore(IMetadataStore inner) : IMetadataStore
    {
        private int _thrown;

        public int Failures => _thrown;

        public DbProvider Provider => inner.Provider;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default)
            => Interlocked.CompareExchange(ref _thrown, 1, 0) == 0
                ? throw new InvalidOperationException("transient metadata-store failure")
                : inner.OpenAsync(ct);
    }

    /// <summary>
    /// Two tenants access an already-cached artifact in sequence. Because the
    /// <c>cache_artifact</c> row is present before either <see cref="CacheAccessRecorder"/>
    /// call, both take the cache-hit branch: <c>GetByCoordinateAsync</c> returns the row,
    /// <c>TouchAccessAsync</c> updates <c>last_accessed_at</c>, and <c>UpsertAsync</c> writes
    /// a per-tenant <c>tenant_artifact_access</c> row. Neither call reaches
    /// <c>InsertAsync</c> (the ON CONFLICT + re-read path is covered separately by
    /// <see cref="InsertAsync_DuplicateCoordinate_ReturnsExistingRow"/>).
    ///
    /// Verifies: both calls return the same non-null <c>cache_artifact.id</c>, exactly 1
    /// <c>cache_artifact</c> row and exactly 2 <c>tenant_artifact_access</c> rows exist after
    /// both calls complete.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_AlreadyCachedArtifact_TwoTenantsEachGetOwnTaaRow()
    {
        // Seed a second org.
        string secondOrgId = Guid.NewGuid().ToString("N");
        await using (var seedConn = await _db.OpenAsync())
        {
            await seedConn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = secondOrgId, slug = $"org-{secondOrgId[..8]}" });
        }

        var repo = new CacheArtifactRepository(_db);
        var frozenClock = TestTime.Frozen();

        // Pre-insert the cache_artifact row so both recorder calls take the cache-hit branch.
        var cachedArtifact = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "acme-race",
            Version = "2.0.0",
            Filename = "acme-race-2.0.0.tgz",
            BlobKey = "proxy/npm/acme-race/2.0.0/acme-race-2.0.0.tgz",
            ContentHash = "deadbeef",
            SizeBytes = 512,
            FirstCachedAt = frozenClock.GetUtcNow(),
            LastAccessedAt = frozenClock.GetUtcNow(),
        };
        await repo.InsertAsync(cachedArtifact);

        // First tenant accesses the already-cached artifact.
        var recorderOrg1 = new CacheAccessRecorder(
            repo, new TenantArtifactAccessRepository(_db),
            NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>(),
            frozenClock);
        var accessOrg1 = new CacheAccess(
            OrgId: _orgId,
            Ecosystem: "npm",
            Name: "acme-race",
            Version: "2.0.0",
            Filename: "acme-race-2.0.0.tgz",
            Sha256: "deadbeef",
            SizeBytes: 512,
            BlobKey: "proxy/npm/acme-race/2.0.0/acme-race-2.0.0.tgz",
            UpstreamUrl: "https://registry.npmjs.org/acme-race/-/acme-race-2.0.0.tgz", Origin: CacheAccessOrigin.FirstFetch);

        string? idOrg1 = await recorderOrg1.RecordAccessAsync(accessOrg1);

        // Second tenant accesses the same already-cached artifact.
        var recorderOrg2 = new CacheAccessRecorder(
            repo, new TenantArtifactAccessRepository(_db),
            NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>(),
            frozenClock);
        var accessOrg2 = new CacheAccess(
            OrgId: secondOrgId,
            Ecosystem: accessOrg1.Ecosystem,
            Name: accessOrg1.Name,
            Version: accessOrg1.Version,
            Filename: accessOrg1.Filename,
            Sha256: accessOrg1.Sha256,
            SizeBytes: accessOrg1.SizeBytes,
            BlobKey: accessOrg1.BlobKey,
            UpstreamUrl: accessOrg1.UpstreamUrl, Origin: CacheAccessOrigin.FirstFetch);
        string? idOrg2 = await recorderOrg2.RecordAccessAsync(accessOrg2);

        // Both calls must return non-null and the same canonical cache_artifact id.
        Assert.NotNull(idOrg1);
        Assert.NotNull(idOrg2);
        Assert.Equal(cachedArtifact.Id, idOrg1);
        Assert.Equal(cachedArtifact.Id, idOrg2);

        await using var conn = await _db.OpenAsync();

        // Exactly one cache_artifact row for the coordinate.
        long artifactCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'acme-race' AND version = '2.0.0'");
        Assert.Equal(1, artifactCount);

        // Exactly two tenant_artifact_access rows — one per org, both referencing the same artifact.
        long taaCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @id",
            new { id = cachedArtifact.Id });
        Assert.Equal(2, taaCount);
    }

    /// <summary>
    /// Content-divergence path: the <c>cache_artifact</c> row carries <c>hashA</c>; a second
    /// tenant's access carries <c>hashB</c>. The recorder must still write the TAA row
    /// (fetch not failed), leave the cached row's <c>content_hash</c> unchanged at
    /// <c>hashA</c>, increment the <c>dependably.cache.content_divergences</c> counter, and
    /// emit a structured <see cref="LogLevel.Warning"/>.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_DivergingHash_SignalsDivergenceAndLeavesRowUnchanged()
    {
        var repo = new CacheArtifactRepository(_db);
        var frozenClock = TestTime.Frozen();

        const string hashA = "aaaa1111";
        const string hashB = "bbbb2222";

        // Pre-insert with hashA so the recorder takes the existing-row branch.
        var seeded = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "pypi",
            Name = "diverge-pkg",
            Version = "1.0.0",
            Filename = "diverge_pkg-1.0.0-py3-none-any.whl",
            BlobKey = "proxy/pypi/diverge-pkg/1.0.0/diverge_pkg-1.0.0.whl",
            ContentHash = hashA,
            SizeBytes = 256,
            FirstCachedAt = frozenClock.GetUtcNow(),
            LastAccessedAt = frozenClock.GetUtcNow(),
        };
        await repo.InsertAsync(seeded);

        var logger = Substitute.For<ILogger<CacheAccessRecorder>>();
        var recorder = new CacheAccessRecorder(
            repo,
            new TenantArtifactAccessRepository(_db),
            logger,
            frozenClock);

        long divergences = 0;
        using var listener = ContentDivergenceMeterListener(delta => divergences += delta);

        // Call with hashB — a diverging hash for the same coordinate.
        string? id = await recorder.RecordAccessAsync(new CacheAccess(
            OrgId: _orgId,
            Ecosystem: "pypi",
            Name: "diverge-pkg",
            Version: "1.0.0",
            Filename: "diverge_pkg-1.0.0-py3-none-any.whl",
            Sha256: hashB,
            SizeBytes: 256,
            BlobKey: seeded.BlobKey,
            UpstreamUrl: null, Origin: CacheAccessOrigin.FirstFetch));

        // TAA row must still be written — the fetch is not failed.
        Assert.NotNull(id);
        Assert.Equal(seeded.Id, id);

        await using var conn = await _db.OpenAsync();

        long taaCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = seeded.Id });
        Assert.Equal(1, taaCount);

        // The globally-cached content_hash must remain hashA — no mutation.
        string? storedHash = await conn.ExecuteScalarAsync<string>(
            "SELECT content_hash FROM cache_artifact WHERE id = @id",
            new { id = seeded.Id });
        Assert.Equal(hashA, storedHash);

        // The divergence counter must have been incremented exactly once.
        Assert.Equal(1, divergences);

        // A structured Warning must have been logged.
        logger.Received(1).Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    /// <summary>
    /// Negative path: when the freshly-fetched SHA-256 matches the cached row's
    /// <c>content_hash</c>, no divergence counter increment and no Warning are emitted.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_MatchingHash_DoesNotSignalDivergence()
    {
        var repo = new CacheArtifactRepository(_db);
        var frozenClock = TestTime.Frozen();

        const string hash = "cccc3333";

        var seeded = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "stable-pkg",
            Version = "2.0.0",
            Filename = "stable-pkg-2.0.0.tgz",
            BlobKey = "proxy/npm/stable-pkg/2.0.0/stable-pkg-2.0.0.tgz",
            ContentHash = hash,
            SizeBytes = 512,
            FirstCachedAt = frozenClock.GetUtcNow(),
            LastAccessedAt = frozenClock.GetUtcNow(),
        };
        await repo.InsertAsync(seeded);

        var logger = Substitute.For<ILogger<CacheAccessRecorder>>();
        var recorder = new CacheAccessRecorder(
            repo,
            new TenantArtifactAccessRepository(_db),
            logger,
            frozenClock);

        long divergences = 0;
        using var listener = ContentDivergenceMeterListener(delta => divergences += delta);

        await recorder.RecordAccessAsync(new CacheAccess(
            OrgId: _orgId,
            Ecosystem: "npm",
            Name: "stable-pkg",
            Version: "2.0.0",
            Filename: "stable-pkg-2.0.0.tgz",
            Sha256: hash,
            SizeBytes: 512,
            BlobKey: seeded.BlobKey,
            UpstreamUrl: null, Origin: CacheAccessOrigin.FirstFetch));

        // Counter must stay at zero — no divergence.
        Assert.Equal(0, divergences);

        // No Warning-level log should have been emitted.
        logger.DidNotReceive().Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    /// <summary>
    /// Verifies the round-trip contract of <see cref="CacheArtifactRepository.InsertAsync"/>
    /// when the coordinate already exists: the call must not throw and must return the
    /// pre-existing row (winner's id) rather than the caller's candidate id.
    /// </summary>
    [Fact]
    public async Task InsertAsync_DuplicateCoordinate_ReturnsExistingRow()
    {
        var repo = new CacheArtifactRepository(_db);
        var now = TestTime.KnownNow;

        var first = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "pypi",
            Name = "requests",
            Version = "2.31.0",
            Filename = "requests-2.31.0-py3-none-any.whl",
            BlobKey = "proxy/pypi/requests/2.31.0/requests-2.31.0.whl",
            ContentHash = "aabbcc",
            SizeBytes = 256,
            FirstCachedAt = now,
            LastAccessedAt = now,
        };

        // Winner insert.
        var returned1 = await repo.InsertAsync(first);
        Assert.Equal(first.Id, returned1.Id);

        // Loser insert — different id, same coordinate.
        var second = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = first.Ecosystem,
            Name = first.Name,
            Version = first.Version,
            Filename = first.Filename,
            BlobKey = first.BlobKey,
            ContentHash = first.ContentHash,
            SizeBytes = first.SizeBytes,
            FirstCachedAt = first.FirstCachedAt,
            LastAccessedAt = first.LastAccessedAt,
        };
        var returned2 = await repo.InsertAsync(second);

        // Must return the winner's id, not the loser's candidate id.
        Assert.Equal(first.Id, returned2.Id);

        // Only one row persisted.
        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'pypi' AND name = 'requests' AND version = '2.31.0'");
        Assert.Equal(1, count);
    }

    /// <summary>
    /// The tenant content binding is what a divergence costs the poisoner: org B's own fetch
    /// records its own SHA-256, blob key and size on <c>tenant_artifact_access</c>, and the
    /// per-tenant serve projection reads those before the shared row's. Without the binding the
    /// projection returns org A's blob key and hash — the bytes org B is then served, and the
    /// ETag its client verifies them against.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_DivergingHash_BindsTenantToItsOwnBytes_NotTheSharedRows()
    {
        var repo = new CacheArtifactRepository(_db);
        var frozenClock = TestTime.Frozen();
        string victimOrgId = await InsertOrgAsync();

        const string attackerHash = "a1a1a1a1";
        const string victimHash = "b2b2b2b2";

        var seeded = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "left-pad",
            Version = "1.0.0",
            Filename = "left-pad-1.0.0.tgz",
            BlobKey = $"proxy/{attackerHash}/left-pad-1.0.0.tgz",
            ContentHash = attackerHash,
            SizeBytes = 11,
            FirstCachedAt = frozenClock.GetUtcNow(),
            LastAccessedAt = frozenClock.GetUtcNow(),
        };
        await repo.InsertAsync(seeded);

        var recorder = new CacheAccessRecorder(
            repo, new TenantArtifactAccessRepository(_db),
            NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>(), frozenClock);

        string? id = await recorder.RecordAccessAsync(new CacheAccess(
            OrgId: victimOrgId,
            Ecosystem: "npm",
            Name: "left-pad",
            Version: "1.0.0",
            Filename: "left-pad-1.0.0.tgz",
            Sha256: victimHash,
            SizeBytes: 22,
            BlobKey: $"proxy/{victimHash}/left-pad-1.0.0.tgz",
            UpstreamUrl: "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
            Origin: CacheAccessOrigin.FirstFetch));

        // Not refused: refusing here would let whoever reaches a coordinate first deny it to
        // every other tenant, with no repair path.
        Assert.Equal(seeded.Id, id);

        var facts = await repo.GetServeFactsByCoordinateAsync(
            victimOrgId, "npm", "left-pad", "1.0.0", "left-pad-1.0.0.tgz");
        Assert.NotNull(facts);
        Assert.Equal(victimHash, facts!.ContentHash);
        Assert.Equal($"proxy/{victimHash}/left-pad-1.0.0.tgz", facts.BlobKey);
        Assert.Equal(22, facts.SizeBytes);

        // The tenant that planted the row keeps reading its own bytes, unaffected.
        await recorder.RecordAccessAsync(new CacheAccess(
            OrgId: _orgId, Ecosystem: "npm", Name: "left-pad", Version: "1.0.0",
            Filename: "left-pad-1.0.0.tgz", Sha256: attackerHash, SizeBytes: 11,
            BlobKey: seeded.BlobKey, UpstreamUrl: "https://attacker.example/left-pad-1.0.0.tgz",
            Origin: CacheAccessOrigin.FirstFetch));
        var attackerFacts = await repo.GetServeFactsByCoordinateAsync(
            _orgId, "npm", "left-pad", "1.0.0", "left-pad-1.0.0.tgz");
        Assert.Equal(attackerHash, attackerFacts!.ContentHash);
    }

    /// <summary>
    /// Adversarial twin of the divergence test: two tenants that resolve the SAME bytes must go on
    /// sharing one <c>cache_artifact</c> row and one blob. A fix that answered divergence by giving
    /// every tenant its own row would pass the poisoning test and quietly duplicate the entire
    /// cache plane per tenant, which this pins against.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_IdenticalBytesFromTwoTenants_ShareOneRowAndOneBlobKey()
    {
        var repo = new CacheArtifactRepository(_db);
        var frozenClock = TestTime.Frozen();
        string otherOrgId = await InsertOrgAsync();
        const string hash = "c3c3c3c3";

        var access = new CacheAccess(
            OrgId: _orgId, Ecosystem: "npm", Name: "shared-pkg", Version: "1.0.0",
            Filename: "shared-pkg-1.0.0.tgz", Sha256: hash, SizeBytes: 33,
            BlobKey: $"proxy/{hash}/shared-pkg-1.0.0.tgz",
            UpstreamUrl: "https://registry.npmjs.org/shared-pkg/-/shared-pkg-1.0.0.tgz",
            Origin: CacheAccessOrigin.FirstFetch);

        var recorder = new CacheAccessRecorder(
            repo, new TenantArtifactAccessRepository(_db),
            NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>(), frozenClock);

        string? firstId = await recorder.RecordAccessAsync(access);
        string? secondId = await recorder.RecordAccessAsync(access with { OrgId = otherOrgId });

        Assert.NotNull(firstId);
        Assert.Equal(firstId, secondId);

        await using var conn = await _db.OpenAsync();
        long rows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'shared-pkg'");
        Assert.Equal(1, rows);

        foreach (string org in new[] { _orgId, otherOrgId })
        {
            var facts = await repo.GetServeFactsByCoordinateAsync(
                org, "npm", "shared-pkg", "1.0.0", "shared-pkg-1.0.0.tgz");
            Assert.Equal(firstId, facts!.Id);
            Assert.Equal($"proxy/{hash}/shared-pkg-1.0.0.tgz", facts.BlobKey);
            Assert.Equal(hash, facts.ContentHash);
        }
    }

    /// <summary>
    /// The concurrent-insert branch. <c>GetByCoordinateAsync</c> returns null, so the recorder
    /// takes the insert path, but another tenant's row for the coordinate lands first: the
    /// <c>ON CONFLICT DO NOTHING</c> insert is a no-op and the re-read hands back the WINNER's row,
    /// carrying the winner's hash and blob key. Binding from that row would poison a tenant whose
    /// first-ever fetch merely lost a race, so the binding is written from this call's own values.
    /// The race is injected deterministically by seeding the winner between the recorder's
    /// coordinate read and its insert.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_LostInsertRace_BindsTenantToItsOwnBytes_NotTheWinnersRow()
    {
        var frozenClock = TestTime.Frozen();
        const string winnerHash = "d4d4d4d4";
        const string loserHash = "e5e5e5e5";

        var winnerRow = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "pypi",
            Name = "race-pkg",
            Version = "1.0.0",
            Filename = "race_pkg-1.0.0-py3-none-any.whl",
            BlobKey = $"proxy/{winnerHash}/race_pkg-1.0.0-py3-none-any.whl",
            ContentHash = winnerHash,
            SizeBytes = 44,
            FirstCachedAt = frozenClock.GetUtcNow(),
            LastAccessedAt = frozenClock.GetUtcNow(),
        };

        // The recorder opens one connection for the coordinate read and a second for the insert.
        // Seeding the winner just before the second is exactly the interleave that makes
        // InsertAsync a no-op and its re-read return a row this tenant never fetched.
        var raced = new RaceInjectingMetadataStore(
            _db, openCallsBeforeInjection: 1,
            inject: async () => await new CacheArtifactRepository(_db).InsertAsync(winnerRow));

        var recorder = new CacheAccessRecorder(
            new CacheArtifactRepository(raced), new TenantArtifactAccessRepository(raced),
            NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>(), frozenClock);

        string? id = await recorder.RecordAccessAsync(new CacheAccess(
            OrgId: _orgId,
            Ecosystem: "pypi",
            Name: "race-pkg",
            Version: "1.0.0",
            Filename: "race_pkg-1.0.0-py3-none-any.whl",
            Sha256: loserHash,
            SizeBytes: 55,
            BlobKey: $"proxy/{loserHash}/race_pkg-1.0.0-py3-none-any.whl",
            UpstreamUrl: "https://pypi.org/race_pkg-1.0.0-py3-none-any.whl",
            Origin: CacheAccessOrigin.FirstFetch));

        // The race really was lost: the row this tenant is attached to is the winner's.
        Assert.Equal(winnerRow.Id, id);

        var facts = await new CacheArtifactRepository(_db).GetServeFactsByCoordinateAsync(
            _orgId, "pypi", "race-pkg", "1.0.0", "race_pkg-1.0.0-py3-none-any.whl");
        Assert.NotNull(facts);
        Assert.Equal(loserHash, facts!.ContentHash);
        Assert.Equal($"proxy/{loserHash}/race_pkg-1.0.0-py3-none-any.whl", facts.BlobKey);
        Assert.Equal(55, facts.SizeBytes);
    }

    /// <summary>
    /// A first fetch that cannot identify the bytes it is admitting is refused, not admitted
    /// against whatever the shared coordinate row holds. An empty hash reaching a
    /// <see cref="CacheAccessOrigin.FirstFetch"/> means no binding can be written, and with no
    /// binding the tenant reads the shared row — the substitution the binding exists to stop. The
    /// caller turns the null into a 503 and drops the staged blob.
    /// </summary>
    [Theory]
    [InlineData("", "proxy/f6f6f6f6/unidentified-1.0.0.tgz")]
    [InlineData("f6f6f6f6", "")]
    public async Task RecordAccessAsync_FirstFetchWithoutContentIdentity_IsRefusedAndWritesNothing(
        string sha256, string blobKey)
    {
        var recorder = BuildRecorder();

        string? id = await recorder.RecordAccessAsync(new CacheAccess(
            OrgId: _orgId,
            Ecosystem: "npm",
            Name: "unidentified",
            Version: "1.0.0",
            Filename: "unidentified-1.0.0.tgz",
            Sha256: sha256,
            SizeBytes: 66,
            BlobKey: blobKey,
            UpstreamUrl: "https://registry.npmjs.org/unidentified/-/unidentified-1.0.0.tgz",
            Origin: CacheAccessOrigin.FirstFetch));

        Assert.Null(id);

        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'unidentified'"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = @orgId",
            new { orgId = _orgId }));
    }

    /// <summary>
    /// A FirstFetchUnidentified never binds a content hash, even when the call carries a non-empty
    /// one. By definition that path did not hash the bytes it staged — Go's
    /// <c>ResolveZipContentMetadataAsync</c> reads the hash back off the SHARED cache_artifact row —
    /// so binding it would leave the tenant holding its own blob_key beside a SHA-256 over another
    /// tenant's bytes, which is precisely the mixed provenance the binding exists to prevent. The
    /// blob key is bound alone because this origin is only permitted where the key is tenant-scoped.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_UnidentifiedFirstFetch_BindsItsOwnKeyButNotTheSharedRowsHash()
    {
        const string sharedHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        string tenantKey = $"go/{_orgId}/example.com/mod/@v/1.0.0.zip";

        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                     first_cached_at, last_accessed_at)
                VALUES ('ca-go','golang','example.com/mod','1.0.0','1.0.0.zip',
                        'go/other-org/example.com/mod/@v/1.0.0.zip', @sharedHash, 512,
                        '2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')
                """,
                new { sharedHash });
            await seed.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access
                    (org_id, cache_artifact_id, first_accessed_at, last_accessed_at, access_count)
                VALUES (@orgId,'ca-go','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',1)
                """,
                new { orgId = _orgId });
        }

        // The re-fetch after this org's own blob was evicted: the coordinate row exists, so the
        // Go path resolves a hash — the shared row's — and passes it along with its own blob key.
        string? id = await BuildRecorder().RecordAccessAsync(new CacheAccess(
            _orgId, "golang", "example.com/mod", "1.0.0", "1.0.0.zip",
            Sha256: sharedHash, SizeBytes: 512, BlobKey: tenantKey,
            UpstreamUrl: "https://proxy.golang.org/example.com/mod/@v/1.0.0.zip",
            Origin: CacheAccessOrigin.FirstFetchUnidentified));

        Assert.NotNull(id);

        await using var conn = await _db.OpenAsync();
        (string? contentHash, string? blobKey) = await conn.QuerySingleAsync<(string?, string?)>(
            """
            SELECT content_hash AS ContentHash, blob_key AS BlobKey
            FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = 'ca-go'
            """,
            new { orgId = _orgId });

        Assert.Equal(tenantKey, blobKey);
        Assert.Null(contentHash);
    }

    /// <summary>
    /// A non-positive size is "could not measure", not "measured zero" — PyPI's known-sha branch
    /// reports 0 whenever the blob store hands back a non-seekable stream (S3/Azure). Binding it
    /// would shadow the coordinate's recorded size with a zero the HEAD Content-Length is served
    /// from, so the size half of the binding is simply left unwritten and the shared value stands.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_FirstFetchWithUnmeasuredSize_BindsNoSizeRatherThanZero()
    {
        const string ownHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                     first_cached_at, last_accessed_at)
                VALUES ('ca-pypi','pypi','requests','2.31.0','requests-2.31.0-py3-none-any.whl',
                        'proxy/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/requests-2.31.0-py3-none-any.whl',
                        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 4096,
                        '2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')
                """);
        }

        string? id = await BuildRecorder().RecordAccessAsync(new CacheAccess(
            _orgId, "pypi", "requests", "2.31.0", "requests-2.31.0-py3-none-any.whl",
            Sha256: ownHash, SizeBytes: 0,
            BlobKey: $"proxy/{ownHash}/requests-2.31.0-py3-none-any.whl",
            UpstreamUrl: "https://pypi.org/simple/requests/",
            Origin: CacheAccessOrigin.FirstFetch));

        Assert.NotNull(id);

        await using var conn = await _db.OpenAsync();
        (string? blobKey, long? sizeBytes) = await conn.QuerySingleAsync<(string?, long?)>(
            """
            SELECT blob_key AS BlobKey, size_bytes AS SizeBytes
            FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = 'ca-pypi'
            """,
            new { orgId = _orgId });

        Assert.Equal($"proxy/{ownHash}/requests-2.31.0-py3-none-any.whl", blobKey);
        Assert.Null(sizeBytes);
    }

    /// <summary>
    /// Adversarial twin of the refusal: a cache-hit tick with no hash is NOT a refusal and must not
    /// disturb the binding. Three live call sites tick with <c>caFacts?.ContentHash ?? ""</c>, so
    /// treating an empty hash as a refusal everywhere would 503 apk, Terraform and Go cache hits;
    /// treating it as evidence would let the shared row's values overwrite the tenant's own. It is
    /// neither: the tick is recorded and the binding is left exactly as the fetch wrote it.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_CacheHitWithoutContentIdentity_IsRecordedAndLeavesBindingIntact()
    {
        var repo = new CacheArtifactRepository(_db);
        var frozenClock = TestTime.Frozen();
        var recorder = new CacheAccessRecorder(
            repo, new TenantArtifactAccessRepository(_db),
            NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>(), frozenClock);

        const string ownHash = "a7a7a7a7";
        var fetched = new CacheAccess(
            OrgId: _orgId, Ecosystem: "apk", Name: "busybox", Version: "1.36.1-r5",
            Filename: "main/x86_64/busybox-1.36.1-r5.apk", Sha256: ownHash, SizeBytes: 77,
            BlobKey: $"apk/{_orgId}/main/x86_64/busybox-1.36.1-r5.apk",
            UpstreamUrl: "https://dl-cdn.alpinelinux.org/busybox-1.36.1-r5.apk",
            Origin: CacheAccessOrigin.FirstFetch);
        string? id = await recorder.RecordAccessAsync(fetched);
        Assert.NotNull(id);

        // Now a hit that carries no content identity at all, exactly as ApkController's
        // `caFacts?.ContentHash ?? ""` supplies it when the serve facts lookup came back null.
        string? hitId = await recorder.RecordAccessAsync(fetched with
        {
            Sha256 = "",
            SizeBytes = 0,
            UpstreamUrl = null,
            Origin = CacheAccessOrigin.CacheHit,
        });

        Assert.Equal(id, hitId);

        var facts = await repo.GetServeFactsByCoordinateAsync(
            _orgId, "apk", "busybox", "1.36.1-r5", "main/x86_64/busybox-1.36.1-r5.apk");
        Assert.Equal(ownHash, facts!.ContentHash);
        Assert.Equal(77, facts.SizeBytes);
    }

    /// <summary>
    /// A cache hit that echoes ANOTHER tenant's hash back at the recorder — the shape apk,
    /// Terraform and Go hits take when the shared row is the only thing they can read — must not
    /// rewrite this tenant's binding. Without the CacheHit discriminator the echo is
    /// indistinguishable from a fetch and re-poisons the tenant one request after the fetch bound
    /// it correctly.
    /// </summary>
    [Fact]
    public async Task RecordAccessAsync_CacheHitEchoingForeignHash_DoesNotRewriteBinding()
    {
        var repo = new CacheArtifactRepository(_db);
        var frozenClock = TestTime.Frozen();
        var recorder = new CacheAccessRecorder(
            repo, new TenantArtifactAccessRepository(_db),
            NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>(), frozenClock);

        const string foreignHash = "b8b8b8b8";
        const string ownHash = "c9c9c9c9";

        await repo.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "nuget",
            Name = "newtonsoft.json",
            Version = "13.0.3",
            Filename = "newtonsoft.json.13.0.3.nupkg",
            BlobKey = $"proxy/{foreignHash}/newtonsoft.json.13.0.3.nupkg",
            ContentHash = foreignHash,
            SizeBytes = 88,
            FirstCachedAt = frozenClock.GetUtcNow(),
            LastAccessedAt = frozenClock.GetUtcNow(),
        });

        var own = new CacheAccess(
            OrgId: _orgId, Ecosystem: "nuget", Name: "newtonsoft.json", Version: "13.0.3",
            Filename: "newtonsoft.json.13.0.3.nupkg", Sha256: ownHash, SizeBytes: 99,
            BlobKey: $"proxy/{ownHash}/newtonsoft.json.13.0.3.nupkg",
            UpstreamUrl: "https://api.nuget.org/newtonsoft.json.13.0.3.nupkg",
            Origin: CacheAccessOrigin.FirstFetch);
        await recorder.RecordAccessAsync(own);

        await recorder.RecordAccessAsync(own with
        {
            Sha256 = foreignHash,
            SizeBytes = 88,
            BlobKey = $"proxy/{foreignHash}/newtonsoft.json.13.0.3.nupkg",
            UpstreamUrl = null,
            Origin = CacheAccessOrigin.CacheHit,
        });

        var facts = await repo.GetServeFactsByCoordinateAsync(
            _orgId, "nuget", "newtonsoft.json", "13.0.3", "newtonsoft.json.13.0.3.nupkg");
        Assert.Equal(ownHash, facts!.ContentHash);
        Assert.Equal($"proxy/{ownHash}/newtonsoft.json.13.0.3.nupkg", facts.BlobKey);
        Assert.Equal(99, facts.SizeBytes);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>Inserts an additional org and returns its id.</summary>
    private async Task<string> InsertOrgAsync()
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id, slug = $"org-{id[..8]}" });
        return id;
    }

    /// <summary>
    /// Returns an active <see cref="MeterListener"/> that invokes <paramref name="onDivergence"/>
    /// with each measurement emitted by <c>dependably.cache.content_divergences</c>.
    /// Must be disposed after the assertion.
    /// </summary>
    private static MeterListener ContentDivergenceMeterListener(Action<long> onDivergence)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName &&
                    instrument.Name == "dependably.cache.content_divergences")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, _, _) => onDivergence(measurement));
        listener.Start();
        return listener;
    }
}

/// <summary>
/// Wraps a real <see cref="IMetadataStore"/> and runs <c>inject</c> once, immediately before the
/// (n+1)th <see cref="OpenAsync"/>. Every repository call opens its own connection, so counting
/// opens is how a test lands a concurrent write between two specific statements of a method it
/// does not control — here, between the recorder's coordinate read and its insert.
/// </summary>
internal sealed class RaceInjectingMetadataStore : IMetadataStore
{
    private readonly IMetadataStore _inner;
    private readonly Func<Task> _inject;
    private int _opens;
    private readonly int _openCallsBeforeInjection;
    private bool _injected;

    public RaceInjectingMetadataStore(IMetadataStore inner, int openCallsBeforeInjection, Func<Task> inject)
    {
        _inner = inner;
        _openCallsBeforeInjection = openCallsBeforeInjection;
        _inject = inject;
    }

    public DbProvider Provider => _inner.Provider;

    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        if (!_injected && _opens == _openCallsBeforeInjection)
        {
            _injected = true;
            await _inject();
        }

        _opens++;
        return await _inner.OpenAsync(ct);
    }
}
