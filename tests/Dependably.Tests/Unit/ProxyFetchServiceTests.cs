using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class ProxyFetchServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private ProxyFetchService Build()
    {
        var packages = new PackageRepository(_db);
        var audit = new AuditRepository(_db);
        var licenses = new LicenseRepository(_db);
        var vulns = new VulnerabilityRepository(_db);
        var cfg = new ConfigurationBuilder().Build();
        // OSV stub: returns no advisories so the block gate has nothing to act on.
        var osv = Substitute.For<IOsvSource>();
        osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new List<OsvAdvisory>()));
        osv.QueryBatchAsync(Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult(
                call.Arg<IReadOnlyList<string>>().Select(_ => new List<OsvAdvisory>()).ToList()));
        var scanner = new VulnerabilityScanService(_db, osv, vulns, audit, cfg,
            NullLogger<VulnerabilityScanService>.Instance);
        var proxyVersions = new ProxyVersionRecorder(packages, audit, licenses);
        var blockGate = new BlockGateService(vulns, audit);
        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var cacheRecorder = new CacheAccessRecorder(cacheArtifact, tenantAccess,
            NullLogger<CacheAccessRecorder>.Instance);
        return new ProxyFetchService(_blobs, cacheRecorder, proxyVersions, scanner, blockGate, packages);
    }

    [Fact]
    public async Task RecordAndScanAsync_clean_version_returns_Allowed_and_caches_blob()
    {
        var svc = Build();

        var bytes = "tarball-bytes"u8.ToArray();
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "left-pad", PurlName: "left-pad",
            Version: "1.0.0", Purl: "pkg:npm/left-pad@1.0.0",
            File: "left-pad-1.0.0.tgz", Bytes: bytes,
            ExtractLicenses: null,
            UserId: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: null));

        Assert.Equal(BlockDecision.Allowed, result.Decision);
        Assert.NotNull(result.VersionId);
        Assert.True(await _blobs.ExistsAsync(result.BlobKey));
    }

    [Fact]
    public async Task RecordAndScanAsync_records_cache_access_when_provided()
    {
        var svc = Build();

        var bytes = "tarball"u8.ToArray();
        await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "nuget",
            PackageName: "foo", PurlName: "foo",
            Version: "1.0.0", Purl: "pkg:nuget/foo@1.0.0",
            File: "foo.1.0.0.nupkg", Bytes: bytes,
            ExtractLicenses: null,
            UserId: null, SourceIp: null,
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "nuget", "foo", "1.0.0", "foo.1.0.0.nupkg",
                Sha256: "", SizeBytes: 0, BlobKey: "",
                UpstreamUrl: "https://api.nuget.org/v3/flatcontainer/foo/1.0.0/foo.1.0.0.nupkg")));

        await using var conn = await _db.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'nuget'");
        Assert.Equal(1, count);
    }
}
