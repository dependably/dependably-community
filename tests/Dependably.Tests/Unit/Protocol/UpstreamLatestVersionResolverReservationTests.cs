using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The Maven upstream-latest resolve applies the org's reserved namespaces before it fetches
/// <c>{g}/{a}/maven-metadata.xml</c>, on both readings of that URL (the artifact reading's groupId
/// <c>g</c> and the group-level name <c>g.a</c>). A reserved name produces zero upstream requests;
/// the WireMock request log is the evidence. The first-fetch seed in
/// <see cref="ProxyVersionRecorder"/> is exercised end to end through the real resolver.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamLatestVersionResolverReservationTests : IAsyncLifetime
{
    private const string MetadataPath = "/com/acme/widget/maven-metadata.xml";

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private WireMockServer _server = null!;
    private ReservedNamespaceService _reserved = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
        _reserved = new ReservedNamespaceService(
            _db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        _server.Given(Request.Create().WithPath(MetadataPath).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody(
                "<metadata><versioning><release>2.0.0</release>" +
                "<versions><version>1.0.0</version><version>1.5.0</version><version>2.0.0</version></versions>" +
                "</versioning></metadata>"));
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    [Theory]
    [InlineData("com.acme")]
    [InlineData("com.acme.*")]
    [InlineData("com")]
    public async Task Maven_ReservedGroupId_NeverConsultsUpstream(string pattern)
    {
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", pattern, createdBy: null);

        var latest = await BuildResolver().ResolveAsync("maven", orgId, "com.acme:widget");

        Assert.True(latest.IsReserved);
        Assert.Null(latest.Version);
        Assert.Null(latest.StableVersionsDescending);
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task Maven_ReservedGroupLevelName_NeverConsultsUpstream()
    {
        // com.acme.widget covers the group-level reading of com/acme/widget/maven-metadata.xml
        // but not the artifact reading's groupId (com.acme). Both readings share the URL, so
        // fetching it would ask upstream about the reserved name.
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", "com.acme.widget", createdBy: null);

        var latest = await BuildResolver().ResolveAsync("maven", orgId, "com.acme:widget");

        Assert.True(latest.IsReserved);
        Assert.Null(latest.Version);
        Assert.DoesNotContain(_server.LogEntries, e => e.RequestMessage?.Path == MetadataPath);
        Assert.Empty(_server.LogEntries);
    }

    [Theory]
    [InlineData("com.acmecorp")]
    [InlineData("com.acme.widget.internal")]
    [InlineData("org.other")]
    public async Task Maven_ReservationCoveringNeitherReading_ResolvesWithExactlyOneRequest(string pattern)
    {
        // Adversarial twin: the same org has a reservation, but it covers neither com.acme nor
        // com.acme.widget (a sibling past the dot boundary, a child of the group-level name, an
        // unrelated group). The resolve goes upstream exactly once.
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", pattern, createdBy: null);

        var latest = await BuildResolver().ResolveAsync("maven", orgId, "com.acme:widget");

        Assert.False(latest.IsReserved);
        Assert.Equal("2.0.0", latest.Version);
        Assert.Equal(1, _server.LogEntries.Count(e => e.RequestMessage?.Path == MetadataPath));
        Assert.Single(_server.LogEntries);
    }

    [Fact]
    public async Task Maven_AnotherOrgsReservation_DoesNotApply()
    {
        // Tenant isolation: org A's reservation of com.acme says nothing about org B. A resolve
        // for A sends nothing; the same resolve for B goes upstream once.
        string orgA = await SeedOrgWithMavenUpstreamAsync();
        string orgB = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgA, "maven", "com.acme", createdBy: null);
        var resolver = BuildResolver();

        var forA = await resolver.ResolveAsync("maven", orgA, "com.acme:widget");
        Assert.Empty(_server.LogEntries);

        var forB = await resolver.ResolveAsync("maven", orgB, "com.acme:widget");

        Assert.True(forA.IsReserved);
        Assert.False(forB.IsReserved);
        Assert.Equal("2.0.0", forB.Version);
        Assert.Single(_server.LogEntries);
    }

    [Fact]
    public async Task Maven_ReservationAddedAfterAResolve_StopsTheNextOne()
    {
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        var resolver = BuildResolver();
        Assert.Equal("2.0.0", (await resolver.ResolveAsync("maven", orgId, "com.acme:widget")).Version);
        Assert.Single(_server.LogEntries);
        _server.ResetLogEntries();

        await _reserved.AddAsync(orgId, "maven", "com.acme", createdBy: null);
        var latest = await resolver.ResolveAsync("maven", orgId, "com.acme:widget");

        Assert.True(latest.IsReserved);
        Assert.Empty(_server.LogEntries);
    }

    // ── First-fetch seed (ProxyVersionRecorder) through the gated resolver ──────

    [Fact]
    public async Task FirstFetchSeed_ReservedName_NoUpstreamRequest_AndSharedRowLeftAlone()
    {
        // The cache_artifact row is shared across orgs. A seed for an org that reserved the name
        // records nothing: no upstream request, no upstream-latest baseline, and the row's
        // versions_behind (written for an org that does consult upstream) is not cleared.
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", "com.acme", createdBy: null);
        string caId = await SeedMavenCacheArtifactAsync(orgId, "com.acme:widget", "1.0.0", versionsBehind: 2);

        await BuildRecorder().RecordAsync(await BuildMavenRequestAsync(orgId, "1.0.0"),
            extractLicenses: null, extractManifest: null, cacheArtifactId: caId);

        Assert.Empty(_server.LogEntries);
        Assert.Null(await ReadUpstreamLatestAsync(orgId));
        Assert.Equal(2, await ReadVersionsBehindAsync(caId));
    }

    [Fact]
    public async Task FirstFetchSeed_NotReserved_SeedsFromExactlyOneRequest()
    {
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", "com.acmecorp", createdBy: null);
        string caId = await SeedMavenCacheArtifactAsync(orgId, "com.acme:widget", "1.0.0", versionsBehind: null);

        await BuildRecorder().RecordAsync(await BuildMavenRequestAsync(orgId, "1.0.0"),
            extractLicenses: null, extractManifest: null, cacheArtifactId: caId);

        Assert.Single(_server.LogEntries);
        Assert.Equal("2.0.0", await ReadUpstreamLatestAsync(orgId));
        Assert.Equal(2, await ReadVersionsBehindAsync(caId)); // 1.5.0 and 2.0.0 are newer
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private async Task<string> SeedOrgWithMavenUpstreamAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured());
        await registries.AddAsync(orgId, new NewUpstreamRegistry("maven", _server.Urls[0]));
        return orgId;
    }

    private UpstreamClient BuildUpstreamClient()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-latest-reserved-{Guid.NewGuid():N}"),
            })
            .Build();
        return new UpstreamClient(
            new StaticHttpClientFactory(new HttpClient()),
            new TieredBlobStorage(_blobs, _blobs),
            new AuditRepository(_db),
            new AllowAllValidator(),
            new StubAirGapMode(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
    }

    private UpstreamLatestVersionResolver BuildResolver() =>
        new(BuildUpstreamClient(),
            new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured())),
            _reserved);

    private ProxyVersionRecorder BuildRecorder() =>
        new(new PackageRepository(_db), new AuditRepository(_db),
            new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db)), new CacheArtifactRepository(_db),
            BuildResolver(), NullLogger<ProxyVersionRecorder>.Instance);

    private async Task<string> SeedMavenCacheArtifactAsync(string orgId, string name, string version, int? versionsBehind)
    {
        await using var conn = await _db.OpenAsync();
        string caId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl, versions_behind)
            VALUES (@id, 'maven', @name, @version, @filename, @blobKey, 'h', @purl, @versionsBehind)
            """,
            new
            {
                id = caId,
                name,
                version,
                filename = $"widget-{version}.jar",
                blobKey = $"proxy/{caId}/widget-{version}.jar",
                purl = $"pkg:maven/com.acme/widget@{version}",
                versionsBehind,
            });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });
        return caId;
    }

    private async Task<ProxyVersionRequest> BuildMavenRequestAsync(string orgId, string version)
    {
        byte[] bytes = "jar-bytes"u8.ToArray();
        string sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        string key = BlobKeys.Proxy(sha);
        await _blobs.PutAsync(key, new MemoryStream(bytes));
        var blob = new BlobHandle(key, sha, bytes.LongLength,
            async ct => await _blobs.GetAsync(key, ct) ?? throw new InvalidOperationException("blob vanished"));
        return new ProxyVersionRequest(
            OrgId: orgId, Ecosystem: "maven", PackageName: "com.acme:widget", PurlName: "com.acme:widget",
            Version: version, Purl: $"pkg:maven/com.acme/widget@{version}",
            Sha256: sha, File: $"widget-{version}.jar", Blob: blob, AuditActorId: null);
    }

    private async Task<string?> ReadUpstreamLatestAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE org_id = @orgId AND purl_name = 'com.acme:widget'",
            new { orgId });
    }

    private async Task<int?> ReadVersionsBehindAsync(string caId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = caId });
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}
