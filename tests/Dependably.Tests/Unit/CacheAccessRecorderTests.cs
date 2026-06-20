using System.Diagnostics.Metrics;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
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
        UpstreamUrl: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz");

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
    public async Task RecordAccessAsync_DbMissing_SwallowsExceptionAndLogs()
    {
        // Drop the cache_artifact table so any query against it will throw.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DROP TABLE IF EXISTS tenant_artifact_access");
            await conn.ExecuteAsync("DROP TABLE IF EXISTS cache_artifact");
        }

        var logger = Substitute.For<ILogger<CacheAccessRecorder>>();
        var recorder = BuildRecorder(logger);

        // Must NOT throw — failures are best-effort and logged as warnings.
        var ex = await Record.ExceptionAsync(() => recorder.RecordAccessAsync(SampleAccess()));
        Assert.Null(ex);

        // A warning must have been logged for the failure.
        logger.Received(1).Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception>(),
            Arg.Any<Func<object, Exception?, string>>());
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
            UpstreamUrl: "https://registry.npmjs.org/acme-race/-/acme-race-2.0.0.tgz");

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
            UpstreamUrl: accessOrg1.UpstreamUrl);
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
            UpstreamUrl: null));

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
            UpstreamUrl: null));

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

    // ── Helpers ──────────────────────────────────────────────────────────────

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
