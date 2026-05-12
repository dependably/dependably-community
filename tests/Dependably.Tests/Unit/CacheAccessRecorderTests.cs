using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

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
            logger ?? NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>());
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

        var artifactCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'lodash' AND version = '4.17.21'");
        Assert.Equal(1, artifactCount);

        var tenantCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = @orgId",
            new { orgId = _orgId });
        Assert.Equal(1, tenantCount);

        var accessCount = await conn.ExecuteScalarAsync<long>(
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
        var artifactCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'lodash' AND version = '4.17.21'");
        Assert.Equal(1, artifactCount);

        // access_count must be 2 after two calls for the same org+artifact.
        var accessCount = await conn.ExecuteScalarAsync<long>(
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
}
