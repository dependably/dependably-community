using Dapper;
using Dependably.Api;
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

    // One master key per test instance: the seed side encrypts an upstream's stored credential
    // and the service side decrypts it, so both protectors must share key material.
    private readonly byte[] _envelopeKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

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

    /// <summary>
    /// Go resolves a latest version from its module proxy, so an omitted version is no longer a
    /// hard failure on its own — it fails only when the org has no golang upstream to ask, which
    /// is the transient-shaped UpstreamUnavailable rather than the client-error VersionRequired.
    /// </summary>
    [Fact]
    public async Task Golang_NoVersionGiven_NoGoUpstreamConfigured_ReturnsUpstreamUnavailable()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "golang", "example.com/mod", null));

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable, outcome.Status);
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

    // A malformed npm name must be rejected as input, never forwarded upstream. The bare-scope
    // case is the one that bites: registry.npmjs.org answers GET /@scope with 405 (not 404), so a
    // forwarded typo comes back as "this source is unhealthy" and the lookup would report an
    // upstream outage (503) instead of a bad name. Unscoped names cannot contain a separator at
    // all, so "a/b" is equally malformed.
    [Theory]
    [InlineData("@dependably")]      // scope with no name part
    [InlineData("@")]                // scope sigil alone
    [InlineData("@/name")]           // empty scope
    [InlineData("@scope/")]          // empty name
    [InlineData("plain/slashed")]    // unscoped names admit no separator
    [InlineData("@scope/name/extra")]
    public async Task MalformedNpmName_ReturnsInvalidInput_WithoutContactingUpstream(string name)
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", name, "1.0.0"));

        Assert.Equal(PackageLookupStatus.InvalidInput, outcome.Status);
        Assert.Equal("name.invalid", outcome.Reason);
        Assert.Equal("name", outcome.Field);
    }

    [Theory]
    [InlineData("left-pad")]
    [InlineData("@scope/name")]
    public void WellShapedNpmNames_AreAccepted(string name)
    {
        Assert.True(Dependably.Api.NpmProtocol.NpmSharedHelpers.IsUpstreamSafeNpmName(name));
    }

    // The name is composed into an authenticated upstream URL. ASP.NET decodes the query value
    // once, so a double-encoded "%252e%252e%252f" arrives here as the literal string
    // "%2e%2e%2f" — no literal ".." or "/", so it clears the base rules — and would be decoded
    // to "../" by the upstream. ValidateUpstreamSegment's '%' ban rejects it before any fetch.
    [Theory]
    [InlineData("pypi", "%2e%2e%2fadmin")]
    [InlineData("pypi", "req%2fuests")]
    [InlineData("nuget", "%2e%2e%2f%2e%2e%2fpackages")]
    [InlineData("cargo", "ser%2fde")]
    [InlineData("golang", "example.com/%2e%2e%2fmod")]
    [InlineData("golang", "example.com/a%2fb")]
    public async Task PercentEncodedName_ReturnsInvalidInput_WithoutContactingUpstream(string ecosystem, string name)
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, ecosystem, name, "1.0.0"));

        Assert.Equal(PackageLookupStatus.InvalidInput, outcome.Status);
        Assert.Equal("name.invalid", outcome.Reason);
        Assert.Equal("name", outcome.Field);
    }

    // The groupId becomes a URL path via Replace('.', '/'), so a '%' in any groupId sub-segment
    // or in the artifactId is a traversal vector; a literal '/' smuggled into the groupId and the
    // pre-existing artifact-'/' rule are also rejected as malformed coordinates.
    [Theory]
    [InlineData("com.example:art%2e%2e%2fifact")]  // '%' in artifactId
    [InlineData("com.%2e%2e.example:artifact")]    // '%' in a groupId sub-segment
    [InlineData("com/evil:artifact")]              // '/' smuggled into the groupId
    [InlineData("com.example:art/ifact")]          // regression guard: artifact '/' still rejected
    [InlineData("com.exam\u0000ple:artifact")] // null byte in a groupId sub-segment
    public async Task MalformedMavenCoordinate_ReturnsInvalidInput(string coordinate)
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "maven", coordinate, "1.0"));

        Assert.Equal(PackageLookupStatus.InvalidInput, outcome.Status);
        Assert.Equal("maven.coordinateInvalid", outcome.Reason);
    }

    [Fact]
    public async Task PercentEncodedVersion_ReturnsInvalidInput()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "left-pad", "1.0.0%2f%2e%2e"));

        Assert.Equal(PackageLookupStatus.InvalidInput, outcome.Status);
        Assert.Equal("version.invalid", outcome.Reason);
    }

    // The '%' ban must not reject any legitimate name in these ecosystems — none of their name
    // grammars admit '%'. These pass validation and proceed (the outcome past validation depends
    // on upstream config, so the invariant asserted is only "not rejected as invalid input").
    [Theory]
    [InlineData("pypi", "typing_extensions")]
    [InlineData("nuget", "Newtonsoft.Json")]
    [InlineData("maven", "com.google.guava:guava")]
    [InlineData("golang", "github.com/foo/bar")]
    [InlineData("cargo", "serde_json")]
    public async Task WellShapedNames_AreNotRejectedAsInvalidInput(string ecosystem, string name)
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, ecosystem, name, "1.0.0"));

        Assert.NotEqual(PackageLookupStatus.InvalidInput, outcome.Status);
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


    // ── Cargo ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CargoLookup_WithNoVersion_ResolvesLatestStableFromIndex()
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync();
        StubCargoIndex("proc-macro2", ("1.0.0", false), ("1.0.1", false));
        StubCratesIoApi("proc-macro2", ("1.0.1", "MIT OR Apache-2.0", "2024-03-04T05:06:07Z"));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "proc-macro2", null));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("1.0.1", outcome.Result!.Version);
        Assert.True(outcome.Result.VersionInferred);
    }

    /// <summary>
    /// The reported bug: a crate whose license crates.io publishes as "MIT OR Apache-2.0" read as
    /// unknown locally. Asserts the SPDX arrives AND that none of the three checks behind the
    /// "not checked at lookup time" note remain disclaimed.
    /// </summary>
    [Fact]
    public async Task CargoLookup_CratesIoUpstream_ResolvesLicenseAndPublishedAt()
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync();
        StubCargoIndex("proc-macro2", ("1.0.1", false));
        StubCratesIoApi("proc-macro2", ("1.0.1", "MIT OR Apache-2.0", "2024-03-04T05:06:07Z"));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "proc-macro2", "1.0.1"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal(["MIT OR Apache-2.0"], outcome.Result!.License.Spdx);
        Assert.DoesNotContain("license", outcome.Result.UnavailableChecks);
        Assert.DoesNotContain("release_age", outcome.Result.UnavailableChecks);
        Assert.DoesNotContain("deprecated", outcome.Result.UnavailableChecks);
    }

    /// <summary>
    /// Proves the release-age hold actually RUNS for cargo rather than merely dropping off the
    /// unavailable list: the crate is published well inside a 720-hour hold, so the verdict has
    /// to move. The 30-day seed offset sits far from the hold boundary so no calendar drift can
    /// flip it.
    /// </summary>
    [Fact]
    public async Task CargoLookup_MinReleaseAgeHold_FiresForCargo()
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync();
        await SetMinReleaseAgeHoursAsync(orgId, 720);
        var clock = TestTime.Frozen();
        string publishedAt = clock.GetUtcNow().AddDays(-2).ToUtcIso();
        StubCargoIndex("fresh-crate", ("1.0.0", false));
        StubCratesIoApi("fresh-crate", ("1.0.0", "MIT", publishedAt));
        var service = BuildService(NoAdvisories(), clock: clock);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "fresh-crate", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("blocked", outcome.Result!.Verdict);
        Assert.Equal("ReleaseAge", outcome.Result.BlockedReason);
    }

    [Fact]
    public async Task CargoLookup_YankedVersion_ReportsDeprecated()
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync();
        await SetBlockDeprecatedAsync(orgId, "block_all");
        StubCargoIndex("yanked-crate", ("1.0.0", true));
        StubCratesIoApi("yanked-crate", ("1.0.0", "MIT", "2020-01-02T03:04:05Z"));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "yanked-crate", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("blocked", outcome.Result!.Verdict);
        Assert.Equal("Deprecated", outcome.Result.BlockedReason);
    }

    /// <summary>
    /// A mirror the operator configured deliberately must not trigger an egress call to
    /// crates.io. The lookup still succeeds on index-only facts, and says exactly which checks
    /// it could not run — the honest degrade, not a failure and not a false "allowed".
    /// </summary>
    [Fact]
    public async Task CargoLookup_PrivateMirror_NoCratesIoApi_DegradesHonestly()
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync(_server.Urls[0]);
        StubCargoIndex("internal-crate", ("2.0.0", false));
        StubCratesIoApi("internal-crate", ("2.0.0", "MIT", "2020-01-02T03:04:05Z"));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "internal-crate", null));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("2.0.0", outcome.Result!.Version);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
        Assert.Contains("release_age", outcome.Result.UnavailableChecks);
        // The index carries yanked, so deprecation IS resolved even with no API leg.
        Assert.DoesNotContain("deprecated", outcome.Result.UnavailableChecks);
        Assert.DoesNotContain(
            _server.LogEntries,
            e => e.RequestMessage?.Path?.Contains("/api/v1/crates", StringComparison.Ordinal) == true);
    }

    [Theory]
    [InlineData(500)]
    [InlineData(429)]
    public async Task CargoLookup_CratesIoApiUnhealthy_StillReturnsIndexFacts(int statusCode)
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync();
        StubCargoIndex("api-down", ("3.1.0", false));
        _server.Given(Request.Create().WithPath("/api/v1/crates/api-down").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(statusCode));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "api-down", null));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("3.1.0", outcome.Result!.Version);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
    }

    /// <summary>
    /// The crates.io API lives on a different host than the configured index, so the upstream's
    /// stored credential must not ride along to it.
    /// </summary>
    [Fact]
    public async Task CargoLookup_Credential_NotSentToCratesIoApiHost()
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync(
            "https://index.crates.io", token: "super-secret-token");
        StubCargoIndex("authed-crate", ("1.0.0", false));
        StubCratesIoApi("authed-crate", ("1.0.0", "MIT", "2020-01-02T03:04:05Z"));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "authed-crate", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        var apiRequest = Assert.Single(
            _server.LogEntries,
            e => e.RequestMessage?.Path?.Contains("/api/v1/crates", StringComparison.Ordinal) == true);
        var apiHeaders = apiRequest.RequestMessage?.Headers;
        Assert.NotNull(apiHeaders);
        Assert.DoesNotContain("Authorization", apiHeaders.Keys);
    }

    [Fact]
    public async Task CargoLookup_UnknownCrate_Index404_ReturnsUpstreamNotFound()
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync();
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "no-such-crate", null));

        Assert.Equal(PackageLookupStatus.UpstreamNotFound, outcome.Status);
    }

    [Fact]
    public async Task CargoLookup_IndexUnavailable_ExplicitVersion_DegradesInsteadOfFailing()
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync();
        _server.Given(Request.Create().WithPath($"/{CargoController.IndexPath("flaky-crate")}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(503));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "flaky-crate", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("1.0.0", outcome.Result!.Version);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
        Assert.Contains("release_age", outcome.Result.UnavailableChecks);
        Assert.Contains("deprecated", outcome.Result.UnavailableChecks);
    }

    [Fact]
    public async Task CargoLookup_IndexUnavailable_NoVersion_ReportsUpstreamUnavailable()
    {
        string orgId = await SeedOrgWithCargoUpstreamAsync();
        _server.Given(Request.Create().WithPath($"/{CargoController.IndexPath("flaky-crate")}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(503));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "cargo", "flaky-crate", null));

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable, outcome.Status);
    }

    // ── Go ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GoLookup_WithNoVersion_ResolvesLatestFromAtLatest()
    {
        string orgId = await SeedOrgWithGoUpstreamAsync();
        StubGoLatest("example.com/mod", "v1.4.0", "2024-05-06T07:08:09Z");
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "golang", "example.com/mod", null));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("v1.4.0", outcome.Result!.Version);
        Assert.True(outcome.Result.VersionInferred);
    }

    /// <summary>
    /// Go's proxy answers version and publish time but carries no license or deprecation signal
    /// outside the module zip, which lookup never downloads — so those two stay disclaimed.
    /// </summary>
    [Fact]
    public async Task GoLookup_ReportsReleaseAge_ButLicenseAndDeprecatedUnavailable()
    {
        string orgId = await SeedOrgWithGoUpstreamAsync();
        StubGoInfo("example.com/mod", "v1.2.3", "2024-05-06T07:08:09Z");
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(
            new PackageLookupRequest(orgId, "golang", "example.com/mod", "v1.2.3"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.DoesNotContain("release_age", outcome.Result!.UnavailableChecks);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
        Assert.Contains("deprecated", outcome.Result.UnavailableChecks);
    }

    [Fact]
    public async Task GoLookup_UnknownModule_ReturnsUpstreamNotFound()
    {
        string orgId = await SeedOrgWithGoUpstreamAsync();
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "golang", "example.com/gone", null));

        Assert.Equal(PackageLookupStatus.UpstreamNotFound, outcome.Status);
    }

    // ── Unavailable-checks honesty across ecosystems ─────────────────────────────

    /// <summary>
    /// NuGet resolves version existence only — it never consults a deprecation signal — so
    /// reporting one as checked would misrepresent what an "allowed" verdict covers.
    /// </summary>
    [Fact]
    public async Task NuGetLookup_ReportsDeprecatedUnavailable()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
        await registries.AddAsync(orgId, new NewUpstreamRegistry("nuget", _server.Urls[0]));
        _server.Given(Request.Create().WithPath("/flatcontainer/newtonsoft.json/index.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBody("""{"versions":["13.0.1"]}"""));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(
            new PackageLookupRequest(orgId, "nuget", "Newtonsoft.Json", "13.0.1"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Contains("deprecated", outcome.Result!.UnavailableChecks);
    }

    /// <summary>
    /// npm DOES consult deprecation, so a clean package must not be reported as unchecked —
    /// the guard against conflating "resolved: not deprecated" with "never looked".
    /// </summary>
    [Fact]
    public async Task NpmLookup_NotDeprecated_DoesNotReportDeprecatedUnavailable()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("clean-pkg", "1.0.0", license: "MIT");
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "clean-pkg", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.DoesNotContain("deprecated", outcome.Result!.UnavailableChecks);
    }

    // ── Cargo / Go helpers ───────────────────────────────────────────────────────

    private static FakeOsvSource NoAdvisories() => new(_ => new List<OsvAdvisory>());

    private async Task<string> SeedOrgWithCargoUpstreamAsync(
        string url = "https://index.crates.io", string? token = null)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
        await registries.AddAsync(orgId, token is null
            ? new NewUpstreamRegistry("cargo", url)
            : new NewUpstreamRegistry("cargo", url, AuthType: "bearer", Secret: token));
        return orgId;
    }

    private async Task<string> SeedOrgWithGoUpstreamAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
        await registries.AddAsync(orgId, new NewUpstreamRegistry("golang", _server.Urls[0]));
        return orgId;
    }

    private async Task SetMinReleaseAgeHoursAsync(string orgId, int hours)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET min_release_age_hours = @hours WHERE org_id = @orgId",
            new { hours, orgId });
    }

    private async Task SetBlockDeprecatedAsync(string orgId, string mode)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET block_deprecated = @mode WHERE org_id = @orgId",
            new { mode, orgId });
    }

    /// <summary>
    /// Stubs the sparse index at the crate's real spec-derived path via
    /// <see cref="CargoController.IndexPath"/> — never a path the test computes itself, so a
    /// wrong path in the production fetch surfaces as a 404 here rather than passing.
    /// </summary>
    private void StubCargoIndex(string name, params (string Version, bool Yanked)[] versions)
    {
        string body = string.Join('\n', versions.Select(v =>
            $$"""{"name":"{{name}}","vers":"{{v.Version}}","cksum":"aa","yanked":{{(v.Yanked ? "true" : "false")}}}"""));
        _server.Given(Request.Create().WithPath($"/{CargoController.IndexPath(name)}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "text/plain")
                .WithBody(body));
    }

    private void StubCratesIoApi(
        string name, params (string Version, string License, string CreatedAt)[] versions)
    {
        string body = $$"""
            { "versions": [ {{string.Join(", ", versions.Select(v =>
                $$"""{"num":"{{v.Version}}","license":"{{v.License}}","created_at":"{{v.CreatedAt}}","yanked":false}"""))}} ] }
            """;
        _server.Given(Request.Create().WithPath($"/api/v1/crates/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBody(body));
    }

    private void StubGoLatest(string module, string version, string time)
        => _server.Given(Request.Create().WithPath($"/{module}/@latest").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBody($$"""{"Version":"{{version}}","Time":"{{time}}"}"""));

    private void StubGoInfo(string module, string version, string time)
        => _server.Given(Request.Create().WithPath($"/{module}/@v/{version}.info").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBody($$"""{"Version":"{{version}}","Time":"{{time}}"}"""));

    private async Task<string> SeedOrgWithNpmUpstreamAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
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

    private PackageLookupService BuildService(
        IOsvSource osv, bool instanceAirGapped = false, TimeProvider? clock = null)
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

        var registryRepo = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
        var registryResolver = new UpstreamRegistryResolver(registryRepo);
        var latestResolver = new UpstreamLatestVersionResolver(upstreamClient, registryResolver);

        var orgs = new OrgRepository(_db);
        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var cache = new PackageLookupCache(TimeProvider.System);

        return new PackageLookupService(
            orgs, registryResolver, upstreamClient, latestResolver, osv, vulns, licenses,
            airGap, clock ?? TimeProvider.System, cache);
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
