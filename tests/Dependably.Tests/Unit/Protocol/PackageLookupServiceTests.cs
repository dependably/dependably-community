using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Verdict-assembly coverage for <see cref="PackageLookupService"/>: malware (OSV MAL- ids),
/// scored/unscored advisory buckets, KEV/EPSS enrichment from already-cached
/// <c>vulnerabilities</c> rows, license policy (off/warn/block), tenant policy divergence
/// between two orgs, air-gapped degradation, and mixed partial-failure scenarios (OSV succeeds
/// while upstream metadata fails, and vice versa) per the project's house testing rule.
///
/// Builds a real <see cref="UpstreamClient"/>/<see cref="UpstreamRegistryResolver"/>/
/// <see cref="VulnerabilityRepository"/>/<see cref="LicenseRepository"/> over an in-memory
/// SQLite store, routing outbound HTTP through a WireMock server so npm/PyPI/NuGet/Maven
/// upstream responses are fully controlled per test. <see cref="IOsvSource"/> is a hand-rolled
/// fake so a test can make the OSV query throw independently of the upstream metadata fetch.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageLookupServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private WireMockServer _server = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    // ── Malware ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task MalwareAdvisory_WithBlockMaliciousOn_ReturnsBlockedVerdict()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("left-pad", "1.3.0", license: "MIT");
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory> { MalwareAdvisory("MAL-2024-1") });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "left-pad", "1.3.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("blocked", outcome.Result!.Verdict);
        Assert.Equal("Malicious", outcome.Result.BlockedReason);
        Assert.True(outcome.Result.Malware.Detected);
        Assert.Contains("MAL-2024-1", outcome.Result.Malware.AdvisoryIds);
    }

    [Fact]
    public async Task MalwareAdvisory_WithBlockMaliciousWarn_ReturnsWarnNotBlocked()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        await SetBlockMaliciousAsync(orgId, "warn");
        StubNpmPackument("evil-pkg", "1.0.0", license: "MIT");
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory> { MalwareAdvisory("MAL-2024-2") });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "evil-pkg", "1.0.0"));

        Assert.Equal("warn", outcome.Result!.Verdict);
        Assert.True(outcome.Result.Malware.Detected);
    }

    // ── Scored + unscored advisory buckets ──────────────────────────────────────

    [Fact]
    public async Task ScoredAndUnscoredAdvisories_BothSurfaced_NeitherDropped()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("mixed-vulns", "2.0.0", license: "MIT");
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-scored-1", 6.5, "MEDIUM"),
            UnscoredAdvisoryRecord("GHSA-unscored-1"),
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "mixed-vulns", "2.0.0"));

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.True(vulns.Available);
        Assert.Single(vulns.Scored);
        Assert.Equal("GHSA-scored-1", vulns.Scored[0].Id);
        Assert.Equal(6.5, vulns.Scored[0].CvssScore);
        Assert.Single(vulns.Unscored);
        Assert.Equal("GHSA-unscored-1", vulns.Unscored[0].Id);
        Assert.Equal(6.5, vulns.MaxCvss);
    }

    [Fact]
    public async Task KevAndEpss_EnrichedFromAlreadyCachedVulnerabilitiesRow()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("kev-pkg", "1.0.0", license: "MIT");
        await VulnerabilitySeeder.InsertVulnAsync(
            _db, "GHSA-kev-1", ecosystem: "npm", packageName: "kev-pkg",
            severity: "CRITICAL", cvssScore: 9.8, isKev: true, epssScore: 0.87);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-kev-1", 9.8, "CRITICAL"),
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "kev-pkg", "1.0.0"));

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.True(vulns.HasKev);
        Assert.Equal(0.87, vulns.MaxEpss);
        Assert.True(vulns.Scored[0].IsKev);
        // BlockKev defaults to 'off' — KEV alone does not block by default.
        Assert.Equal("allowed", outcome.Result.Verdict);
    }

    // ── License policy ───────────────────────────────────────────────────────────

    [Fact]
    public async Task LicenseOffMode_ReportsInformationally_NoVerdict()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("gpl-pkg", "1.0.0", license: "GPL-3.0-only");
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "gpl-pkg", "1.0.0"));

        var license = outcome.Result!.License;
        Assert.Equal("off", license.Mode);
        Assert.Null(license.Allowed);
        Assert.Contains("GPL-3.0-only", license.Spdx);
        Assert.Equal("allowed", outcome.Result.Verdict);
    }

    [Fact]
    public async Task LicenseBlockMode_UnapprovedLicense_ReportsNotAllowed_OverallWarn()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        await LicensePolicySeeder.SetModeAsync(_db, orgId, "block");
        StubNpmPackument("gpl-pkg", "1.0.0", license: "GPL-3.0-only");
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "gpl-pkg", "1.0.0"));

        var license = outcome.Result!.License;
        Assert.Equal("block", license.Mode);
        Assert.False(license.Allowed);
        Assert.Equal("GPL-3.0-only", license.BlockedLicense);
        // License is not (yet) an enforcement arm of BlockGateService — the lookup verdict still
        // matches what the install-time gate would decide, but surfaces the license concern as warn.
        Assert.Equal("warn", outcome.Result.Verdict);
    }

    [Fact]
    public async Task LicenseBlockMode_AllowlistedLicense_Passes()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        await LicensePolicySeeder.SetModeAsync(_db, orgId, "block");
        await LicensePolicySeeder.AddAllowlistEntryAsync(_db, orgId, "MIT");
        StubNpmPackument("mit-pkg", "1.0.0", license: "MIT");
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "mit-pkg", "1.0.0"));

        Assert.True(outcome.Result!.License.Allowed);
        Assert.Equal("allowed", outcome.Result.Verdict);
    }

    // ── Tenant policy divergence ─────────────────────────────────────────────────

    [Fact]
    public async Task TwoOrgs_DifferentBlockMaliciousPolicy_GetDifferentVerdicts()
    {
        string strictOrg = await SeedOrgWithNpmUpstreamAsync();
        string lenientOrg = await SeedOrgWithNpmUpstreamAsync();
        await SetBlockMaliciousAsync(lenientOrg, "warn");
        StubNpmPackument("shared-pkg", "1.0.0", license: "MIT");
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory> { MalwareAdvisory("MAL-2024-3") });
        var service = BuildService(osv);

        var strictOutcome = await service.LookupAsync(new PackageLookupRequest(strictOrg, "npm", "shared-pkg", "1.0.0"));
        var lenientOutcome = await service.LookupAsync(new PackageLookupRequest(lenientOrg, "npm", "shared-pkg", "1.0.0"));

        Assert.Equal("blocked", strictOutcome.Result!.Verdict);
        Assert.Equal("warn", lenientOutcome.Result!.Verdict);
    }

    // ── Mixed / partial-failure scenarios ────────────────────────────────────────

    [Fact]
    public async Task OsvSucceeds_UpstreamMetadataFails_DegradesGracefully_StillReturnsVerdict()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        // No packument stub registered — WireMock answers 404 for the packument path, but the
        // request carries an explicit version so metadata is not strictly required to proceed.
        _server.Given(Request.Create().WithPath("/broken-pkg").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(500));
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory> { MalwareAdvisory("MAL-2024-4") });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "broken-pkg", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("blocked", outcome.Result!.Verdict);
        Assert.True(outcome.Result.Malware.Detected);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
        Assert.Contains("release_age", outcome.Result.UnavailableChecks);
    }

    [Fact]
    public async Task UpstreamMetadataSucceeds_OsvFails_MarksVulnerabilitiesUnavailable_OverallWarn()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("flaky-osv-pkg", "1.0.0", license: "MIT");
        var osv = new FakeOsvSource(_ => throw new InvalidOperationException("OSV backend unreachable"));
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "flaky-osv-pkg", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.False(outcome.Result!.Vulnerabilities.Available);
        Assert.Contains("vulnerabilities", outcome.Result.UnavailableChecks);
        // Never a false "allowed" when the security-relevant check itself couldn't run.
        Assert.Equal("warn", outcome.Result.Verdict);
    }

    [Fact]
    public async Task OsvUnreachable_WithoutThrowing_MarksVulnerabilitiesUnavailable_OverallWarn_NotAllowed()
    {
        // Pins the real OsvClient/LocalOsvSource outage shape: QueryAsync's contract is to
        // swallow the failure and return an EMPTY list — no exception ever reaches the caller.
        // A fake that only throws (like the test above) cannot exercise this path; it exercised
        // only the belt-and-braces try/catch, not the reachability signal the lookup depends on.
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("outage-osv-pkg", "1.0.0", license: "MIT");
        var osv = new FakeOsvSource(_ => [], reached: false);
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "outage-osv-pkg", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.False(outcome.Result!.Vulnerabilities.Available);
        Assert.Contains("vulnerabilities", outcome.Result.UnavailableChecks);
        // The empty advisory list must never be read as "no malware" — the verdict has to
        // surface the uncertainty instead of presenting a confident "allowed".
        Assert.False(outcome.Result.Malware.Detected);
        Assert.NotEqual("allowed", outcome.Result.Verdict);
        Assert.Equal("warn", outcome.Result.Verdict);
    }

    [Fact]
    public async Task OsvReached_GenuinelyEmpty_StaysAllowed()
    {
        // The counterpart to the outage test above: OSV was actually consulted and came back
        // with zero advisories — this is the one case that legitimately stays "allowed".
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("clean-reached-pkg", "1.0.0", license: "MIT");
        var osv = new FakeOsvSource(_ => [], reached: true);
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "clean-reached-pkg", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.True(outcome.Result!.Vulnerabilities.Available);
        Assert.DoesNotContain("vulnerabilities", outcome.Result.UnavailableChecks);
        Assert.Equal("allowed", outcome.Result.Verdict);
    }

    [Fact]
    public async Task NoVersionGiven_UpstreamUnreachable_ReturnsUpstreamUnavailable_NeverFalseAllowed()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        // No stub registered for the packument path at all -> WireMock answers 404 for
        // everything, which UpstreamClient surfaces as a definitive (non-transient) miss; use a
        // 500 instead so every source in the fallback loop is treated as unreachable.
        _server.Given(Request.Create().WithPath("/unreachable-pkg").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(503));
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "unreachable-pkg", null));

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable, outcome.Status);
        Assert.Null(outcome.Result);
    }

    // ── Version resolution ───────────────────────────────────────────────────────

    [Fact]
    public async Task NoVersionGiven_ResolvesLatestStable_AndSaysWhichVersion()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("auto-latest", "2.5.0", license: "ISC", distTagsLatest: "2.5.0");
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "auto-latest", null));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("2.5.0", outcome.Result!.Version);
        Assert.True(outcome.Result.VersionInferred);
    }

    // ── Air-gapped ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AirGappedOrg_ExplicitVersion_AdvisoryAndLicenseStillEvaluated_MetadataUnavailable()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        await SetAirGappedAsync(orgId, true);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory> { MalwareAdvisory("MAL-2024-5") });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "offline-pkg", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.True(outcome.Result!.AirGapped);
        Assert.True(outcome.Result.Malware.Detected);
        Assert.Equal("blocked", outcome.Result.Verdict);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
        Assert.Contains("release_age", outcome.Result.UnavailableChecks);
    }

    [Fact]
    public async Task AirGappedOrg_NoVersionGiven_ReturnsVersionRequired()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        await SetAirGappedAsync(orgId, true);
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "offline-pkg", null));

        Assert.Equal(PackageLookupStatus.VersionRequired, outcome.Status);
    }

    // ── Input validation / ecosystem support ─────────────────────────────────────

    [Fact]
    public async Task UnsupportedEcosystem_ReturnsUnsupportedEcosystem()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "rpm", "bash", "5.0"));

        Assert.Equal(PackageLookupStatus.UnsupportedEcosystem, outcome.Status);
    }

    [Fact]
    public async Task Golang_NoVersionGiven_ReturnsVersionRequired_NoMetadataSourceWired()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "golang", "example.com/mod", null));

        Assert.Equal(PackageLookupStatus.VersionRequired, outcome.Status);
    }

    [Fact]
    public async Task Golang_ExplicitVersion_QueriesOsvOnly()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory> { MalwareAdvisory("MAL-2024-6") });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(
            new PackageLookupRequest(orgId, "golang", "example.com/mod", "v1.2.3"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.True(outcome.Result!.Malware.Detected);
        Assert.Equal("pkg:golang/example.com/mod@v1.2.3", outcome.Result.Purl);
    }

    [Fact]
    public async Task MavenCoordinate_MissingColon_ReturnsInvalidInput()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "maven", "no-colon-here", "1.0"));

        Assert.Equal(PackageLookupStatus.InvalidInput, outcome.Status);
        Assert.Equal("maven.coordinateInvalid", outcome.Reason);
    }

    // ── Test doubles / helpers ───────────────────────────────────────────────────

    private static OsvAdvisory MalwareAdvisory(string id) => new(
        Id: id, Aliases: [], Summary: "Known malicious package", Severity: null, CvssScore: null,
        AffectedPackages: [], Published: null, Modified: null, IsHydrated: true);

    private static OsvAdvisory ScoredAdvisoryRecord(string id, double cvss, string severity) => new(
        Id: id, Aliases: [], Summary: "A scored vulnerability", Severity: severity, CvssScore: cvss,
        AffectedPackages: [], Published: null, Modified: null, IsHydrated: true);

    private static OsvAdvisory UnscoredAdvisoryRecord(string id) => new(
        Id: id, Aliases: [], Summary: "An undisclosed-severity advisory", Severity: null, CvssScore: null,
        AffectedPackages: [], Published: null, Modified: null, IsHydrated: true);

    private async Task<string> SeedOrgWithNpmUpstreamAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured());
        await registries.AddAsync(orgId, new NewUpstreamRegistry("npm", _server.Urls[0]));
        return orgId;
    }

    private async Task SetBlockMaliciousAsync(string orgId, string mode)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET block_malicious = @mode WHERE org_id = @orgId",
            new { mode, orgId });
    }

    private async Task SetAirGappedAsync(string orgId, bool airGapped)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET air_gapped = @flag WHERE org_id = @orgId",
            new { orgId, flag = airGapped ? 1 : 0 });
    }

    private void StubNpmPackument(
        string name, string version, string license, string? distTagsLatest = null)
    {
        string latest = distTagsLatest ?? version;
        string json = $$"""
            {
              "name": "{{name}}",
              "dist-tags": { "latest": "{{latest}}" },
              "versions": {
                "{{version}}": { "name": "{{name}}", "version": "{{version}}", "license": "{{license}}" }
              },
              "time": { "{{version}}": "2024-01-15T00:00:00.000Z" }
            }
            """;
        _server.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBody(json));
    }

    private PackageLookupService BuildService(IOsvSource osv, bool instanceAirGapped = false)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-lookup-test-{Guid.NewGuid():N}"),
                ["Npm:Upstream"] = "http://npm.invalid",
                ["PyPI:Upstream"] = "http://pypi.invalid",
            })
            .Build();

        var blobs = new InMemoryBlobStore();
        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var urlValidator = new AllowAllValidator();
        var airGap = new StubAirGapMode(instanceAirGapped);

        var upstreamClient = new UpstreamClient(
            httpFactory, new TieredBlobStorage(blobs, blobs), new AuditRepository(_db),
            urlValidator, airGap, new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);

        var registryRepo = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured());
        var registryResolver = new UpstreamRegistryResolver(registryRepo);
        var latestResolver = new UpstreamLatestVersionResolver(upstreamClient, registryResolver);

        var orgs = new OrgRepository(_db);
        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var cache = new PackageLookupCache(TimeProvider.System);

        return new PackageLookupService(
            orgs, registryResolver, upstreamClient, latestResolver, osv, vulns, licenses,
            airGap, TimeProvider.System, cache);
    }

    /// <summary>
    /// <paramref name="reached"/> defaults to true (a genuine, consulted answer). Passing
    /// false pins the real <see cref="OsvClient"/>/<c>LocalOsvSource</c> outage behaviour —
    /// the source returns no advisories WITHOUT throwing — that a throwing fake cannot exercise.
    /// </summary>
    private sealed class FakeOsvSource : IOsvSource
    {
        private readonly Func<string, List<OsvAdvisory>> _handler;
        private readonly bool _reached;
        public FakeOsvSource(Func<string, List<OsvAdvisory>> handler, bool reached = true)
        {
            _handler = handler;
            _reached = reached;
        }

        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
            => Task.FromResult(_handler(purl));

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default)
            => Task.FromResult(purls.Select(_handler).ToList());

        public Task<OsvQueryResult> TryQueryAsync(string purl, CancellationToken ct = default)
            => Task.FromResult(new OsvQueryResult(_handler(purl), _reached));
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class StubAirGapMode : IAirGapMode
    {
        public StubAirGapMode(bool enabled) => IsEnabled = enabled;
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    /// <summary>Routes HttpClient requests through the WireMock server, preserving the path.</summary>
    private sealed class WireMockHandler : HttpMessageHandler
    {
        private readonly WireMockServer _server;
        public WireMockHandler(WireMockServer server) => _server = server;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            string url = _server.Urls[0] + request.RequestUri!.PathAndQuery;
            using var innerRequest = new HttpRequestMessage(request.Method, url);
            foreach (var h in request.Headers)
            {
                innerRequest.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }

            var inner = new HttpClient();
            return await inner.SendAsync(innerRequest, ct);
        }
    }
}
