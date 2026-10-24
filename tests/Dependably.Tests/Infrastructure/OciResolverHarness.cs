using Dapper;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// A real <see cref="OciUpstreamResolver"/> over an in-memory metadata store and blob stores,
/// pulling from a <see cref="FakeOciRegistry"/> through an optional per-request intercept. The clock
/// is a <see cref="FakeTimeProvider"/>, so moving-tag revalidation is driven by advancing it, and
/// an upstream fault is injected by returning a status (or throwing) from the intercept: a non-null
/// return replaces the fake registry's answer.
/// </summary>
public sealed class OciResolverHarness : IAsyncDisposable
{
    public const string Host = "registry.example";
    public const string Repository = "library/nginx";

    private OciResolverHarness(
        TestMetadataStore db, FakeTimeProvider clock, FakeOciRegistry upstream, InMemoryBlobStore cache,
        InMemoryBlobStore registry, OciUpstreamResolver resolver, string orgId, List<string> requests)
    {
        Db = db;
        Clock = clock;
        Upstream = upstream;
        Cache = cache;
        Registry = registry;
        Resolver = resolver;
        OrgId = orgId;
        Requests = requests;
    }

    public TestMetadataStore Db { get; }

    public FakeTimeProvider Clock { get; }

    public FakeOciRegistry Upstream { get; }

    public InMemoryBlobStore Cache { get; }

    public InMemoryBlobStore Registry { get; }

    public OciUpstreamResolver Resolver { get; }

    public string OrgId { get; }

    /// <summary>Every upstream request as "METHOD url", in order.</summary>
    public List<string> Requests { get; }

    public static async Task<OciResolverHarness> CreateAsync(
        bool airGapped = false,
        Func<HttpRequestMessage, HttpResponseMessage?>? intercept = null,
        TimeSpan? tagTtl = null,
        PullGate pullGate = PullGate.NotWired)
    {
        var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();
        string orgId = await OrgSeeder.InsertAsync(db, $"oci-{Guid.NewGuid():N}");
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, name, url, position, auth_type, prefixes)
                VALUES (@id, @orgId, 'oci', @host, @host, 0, 'anonymous', '[""]')
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId, host = Host });
        }

        var clock = TestTime.Frozen();
        var upstream = new FakeOciRegistry(Repository);
        var requests = new List<string>();
        var cache = new InMemoryBlobStore();
        var registry = new InMemoryBlobStore();
        var options = Options.Create(new OciOptions
        {
            ManifestTagTtl = tagTtl ?? TimeSpan.FromMinutes(5),
            TokenCacheDuration = TimeSpan.FromMinutes(55),
        });
        var http = new Factory(new Handler(upstream, requests, intercept));
        var blobs = new TieredBlobStorage(cache, registry);
        var cacheArtifacts = new CacheArtifactRepository(db);
        var airGap = new AirGap(airGapped);
        var auth = new OciUpstreamAuthService(
            http, options, new AirGap(false), NullLogger<OciUpstreamAuthService>.Instance, clock);
        var resolver = new OciUpstreamResolver(
            http, auth, options, blobs, db, airGap,
            new OciImageLicenseRecorder(
                db, blobs, clock, NullLogger<OciImageLicenseRecorder>.Instance,
                new LicenseRepository(db, clock, TestNormalizers.License(db))),
            new CacheAccessRecorder(
                cacheArtifacts, new TenantArtifactAccessRepository(db),
                NullLogger<CacheAccessRecorder>.Instance, clock),
            cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, clock, TestEnvelope.Unconfigured(),
            pullGate: pullGate == PullGate.NotWired
                ? null
                : new OciPullGateResolver(
                    db, new OciScanRepository(db), new VulnerabilityRepository(db, clock),
                    new Coverage(pullGate == PullGate.CoverageFails)));
        return new OciResolverHarness(db, clock, upstream, cache, registry, resolver, orgId, requests);
    }

    /// <summary>How the OCI pull gate's facts read is wired into the resolver.</summary>
    public enum PullGate
    {
        /// <summary>No gate: moving-tag promotion is age-only.</summary>
        NotWired,

        /// <summary>A gate over an org whose scanner is reporting, with no scan results stored.</summary>
        Covered,

        /// <summary>A gate whose coverage read throws, as a database fault would.</summary>
        CoverageFails,
    }

    public async Task SetScanEnforcementAsync(string mode)
    {
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET oci_scan_enforcement = @mode WHERE org_id = @orgId",
            new { mode, orgId = OrgId });
    }

    public async Task SetMinReleaseAgeHoursAsync(int? hours)
    {
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET min_release_age_hours = @hours WHERE org_id = @orgId",
            new { hours, orgId = OrgId });
    }

    /// <summary>Sets the org's proxy passthrough and tenant air-gap flags.</summary>
    public async Task SetUpstreamPostureAsync(bool passthrough, bool airGapped)
    {
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @passthrough, air_gapped = @airGapped WHERE org_id = @orgId",
            new { passthrough = passthrough ? 1 : 0, airGapped = airGapped ? 1 : 0, orgId = OrgId });
    }

    public async ValueTask DisposeAsync() => await Db.DisposeAsync();

    private sealed class Handler(
        FakeOciRegistry upstream, List<string> requests, Func<HttpRequestMessage, HttpResponseMessage?>? intercept)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (requests)
            {
                requests.Add($"{request.Method} {request.RequestUri}");
            }

            return Task.FromResult(intercept?.Invoke(request) ?? upstream.Respond(request));
        }
    }

    private sealed class Coverage(bool fails) : IOciScanCoverage
    {
        public bool Enabled => true;

        public Task<bool> IsCoveredAsync(string orgId, CancellationToken ct = default)
            => fails ? throw new InvalidOperationException("coverage read failed") : Task.FromResult(true);
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        private readonly HttpClient _client = new(handler);

        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AirGap(bool enabled) : IAirGapMode
    {
        public bool IsEnabled => enabled;

        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();

        public bool IsJobDisabled(string jobName) => enabled;
    }
}
