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
using NSubstitute;
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
    private readonly ReservedNamespaceService _reserved;

    public PackageLookupServiceTests()
    {
        _reserved = new ReservedNamespaceService(
            _db,
            new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()),
            TimeProvider.System);
    }
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
        Assert.Equal("malicious", outcome.Result.BlockedReason);
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

    [Fact]
    public async Task Kev_ResolvedThroughAliasCve_WhenAdvisoryHasNoRowOfItsOwn()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("alias-kev-pkg", "1.0.0", license: "MIT");
        await VulnerabilitySeeder.InsertVulnAsync(
            _db, "CVE-2021-44228", ecosystem: "npm", packageName: "alias-kev-pkg",
            isKev: true, epssScore: 0.97);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-jfh8-c2jp-5v3q", 10.0, "CRITICAL") with { Aliases = ["CVE-2021-44228"] },
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "alias-kev-pkg", "1.0.0"));

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.True(vulns.HasKev);
        Assert.Equal(0.97, vulns.MaxEpss);
        Assert.True(vulns.Scored[0].IsKev);
        Assert.Equal(0.97, vulns.Scored[0].Epss);
    }

    [Fact]
    public async Task Kev_ResolvedThroughSiblingRowAliases_AndEpssTakesMaxAcrossMatches()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("sibling-kev-pkg", "1.0.0", license: "MIT");
        await VulnerabilitySeeder.InsertVulnAsync(
            _db, "GHSA-other-0001", ecosystem: "npm", packageName: "sibling-kev-pkg",
            aliases: "[\"CVE-2021-44228\"]", isKev: true, epssScore: 0.40);
        await VulnerabilitySeeder.InsertVulnAsync(
            _db, "CVE-2021-44228", ecosystem: "npm", packageName: "sibling-kev-pkg",
            isKev: false, epssScore: 0.90);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-jfh8-c2jp-5v3q", 10.0, "CRITICAL") with { Aliases = ["CVE-2021-44228"] },
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "sibling-kev-pkg", "1.0.0"));

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.True(vulns.HasKev);
        Assert.Equal(0.90, vulns.MaxEpss);
    }

    [Fact]
    public async Task KevAndEpss_OfAMultiCveSiblingRow_DoNotEnrichAnAdvisoryAliasingOnlyOneOfItsCves()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("multi-cve-pkg", "1.0.0", license: "MIT");
        await SetBlockKevAsync(orgId, "block");
        await SetEpssToleranceAsync(orgId, probability: 0.5, percentile: null);
        // The distro row's KEV flag and EPSS score are aggregates over both of its CVEs: only
        // CVE-2024-1001 is in KEV and carries the high score, and the live advisory names only
        // CVE-2024-1002.
        await VulnerabilitySeeder.InsertVulnAsync(
            _db, "RLSA-2024:7001", ecosystem: "Rocky Linux:9", packageName: "multi-cve-pkg",
            aliases: "[\"CVE-2024-1001\",\"CVE-2024-1002\"]", isKev: true, epssScore: 0.95);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-mcve-0001-aaaa", 5.0, "MEDIUM") with { Aliases = ["CVE-2024-1002"] },
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "multi-cve-pkg", "1.0.0"));
        var detail = await service.FindAdvisoryDetailAsync(orgId, "npm", "multi-cve-pkg", "1.0.0", "GHSA-mcve-0001-aaaa");

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.False(vulns.HasKev);
        Assert.Null(vulns.MaxEpss);
        Assert.False(vulns.Scored[0].IsKev);
        Assert.Equal("allowed", outcome.Result.Verdict);
        Assert.NotNull(detail);
        Assert.Null(detail.Intel);
    }

    [Fact]
    public async Task KevAndEpss_OfARowStoredUnderTheAdvisorysOwnId_StillEnrich_WhateverItsAliases()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("own-row-pkg", "1.0.0", license: "MIT");
        await SetBlockKevAsync(orgId, "block");
        await VulnerabilitySeeder.InsertVulnAsync(
            _db, "GHSA-own0-0001-aaaa", ecosystem: "npm", packageName: "own-row-pkg",
            aliases: "[\"CVE-2024-2001\",\"CVE-2024-2002\"]", isKev: true, epssScore: 0.60);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-own0-0001-aaaa", 5.0, "MEDIUM") with { Aliases = ["CVE-2024-2002"] },
        });

        var outcome = await BuildService(osv).LookupAsync(new PackageLookupRequest(orgId, "npm", "own-row-pkg", "1.0.0"));

        Assert.True(outcome.Result!.Vulnerabilities.HasKev);
        Assert.Equal(0.60, outcome.Result.Vulnerabilities.MaxEpss);
        Assert.Equal("blocked", outcome.Result.Verdict);
        Assert.Equal("kev", outcome.Result.BlockedReason);
    }

    [Fact]
    public async Task Kev_ResolvedFromStoredCatalogue_WhenNoVulnerabilitiesRowExistsAnywhere()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("catalogue-kev-pkg", "1.0.0", license: "MIT");
        await new VulnerabilityRepository(_db, TimeProvider.System).ReplaceKevCatalogAsync(new Dictionary<string, KevEntry>
        {
            ["CVE-2021-44228"] = new(true, "2021-12-10", null),
        });
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-jfh8-c2jp-5v3q", 10.0, "CRITICAL") with { Aliases = ["CVE-2021-44228"] },
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "catalogue-kev-pkg", "1.0.0"));

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.True(vulns.HasKev);
        Assert.True(vulns.Scored[0].IsKev);
        Assert.Null(vulns.MaxEpss);
    }

    [Fact]
    public async Task Epss_ResolvedFromStoredScores_ForACveNoVulnerabilitiesRowNamesAnywhere()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("stored-epss-pkg", "1.0.0", license: "MIT");
        await new VulnerabilityRepository(_db, TimeProvider.System).ReplaceEpssScoresAsync(
            new Dictionary<string, EpssScore>
            {
                ["CVE-2021-44228"] = new(0.97, 0.999),
                ["CVE-2021-45046"] = new(0.40, 0.95),
            }, "2026-10-05");
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            // The GHSA id itself is no CVE, so only its aliases reach the stored scores; the
            // advisory takes the highest across them.
            ScoredAdvisoryRecord("GHSA-jfh8-c2jp-5v3q", 5.0, "MEDIUM") with { Aliases = ["CVE-2021-45046", "CVE-2021-44228"] },
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "stored-epss-pkg", "1.0.0"));

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.Equal(0.97, vulns.MaxEpss);
        Assert.Equal(0.97, vulns.Scored[0].Epss);
        Assert.False(vulns.HasKev);
    }

    [Fact]
    public async Task Epss_ProbabilityCeiling_BlocksOnAScoreOnlyTheStoredFileHolds()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("epss-block-pkg", "1.0.0", license: "MIT");
        await SetEpssToleranceAsync(orgId, probability: 0.5, percentile: null);
        await new VulnerabilityRepository(_db, TimeProvider.System).ReplaceEpssScoresAsync(
            new Dictionary<string, EpssScore> { ["CVE-2021-44228"] = new(0.97, 0.999) }, null);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-jfh8-c2jp-5v3q", 5.0, "MEDIUM") with { Aliases = ["CVE-2021-44228"] },
        });

        var outcome = await BuildService(osv).LookupAsync(new PackageLookupRequest(orgId, "npm", "epss-block-pkg", "1.0.0"));

        Assert.Equal("blocked", outcome.Result!.Verdict);
        Assert.Equal("epss", outcome.Result.BlockedReason);
    }

    [Fact]
    public async Task Epss_PercentileCeiling_BlocksOnAStoredPercentile()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("epss-pct-pkg", "1.0.0", license: "MIT");
        await SetEpssToleranceAsync(orgId, probability: null, percentile: 0.9);
        await new VulnerabilityRepository(_db, TimeProvider.System).ReplaceEpssScoresAsync(
            new Dictionary<string, EpssScore> { ["CVE-2021-44228"] = new(0.10, 0.95) }, null);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-jfh8-c2jp-5v3q", 5.0, "MEDIUM") with { Aliases = ["CVE-2021-44228"] },
        });

        var outcome = await BuildService(osv).LookupAsync(new PackageLookupRequest(orgId, "npm", "epss-pct-pkg", "1.0.0"));

        Assert.Equal("blocked", outcome.Result!.Verdict);
        Assert.Equal("epss_percentile", outcome.Result.BlockedReason);
    }

    [Fact]
    public async Task Epss_EmptyStore_ReadsAsNoSignal_NotAsAFailure()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("epss-empty-pkg", "1.0.0", license: "MIT");
        await SetEpssToleranceAsync(orgId, probability: 0.5, percentile: 0.5);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-jfh8-c2jp-5v3q", 5.0, "MEDIUM") with { Aliases = ["CVE-2021-44228"] },
        });

        var outcome = await BuildService(osv).LookupAsync(new PackageLookupRequest(orgId, "npm", "epss-empty-pkg", "1.0.0"));

        Assert.Null(outcome.Result!.Vulnerabilities.MaxEpss);
        Assert.Equal("allowed", outcome.Result.Verdict);
    }

    [Fact]
    public async Task DuplicateAdvisoryIds_FromTheSource_AreReportedOnce_WithMergedAliases()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("dup-adv-pkg", "1.0.0", license: "MIT");
        await new VulnerabilityRepository(_db, TimeProvider.System).ReplaceKevCatalogAsync(
            new Dictionary<string, KevEntry> { ["CVE-2037-0001"] = new(null, null, null) });
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-dup-0001", 8.0, "HIGH") with { Aliases = ["CVE-2037-0002"] },
            ScoredAdvisoryRecord("GHSA-dup-0001", 8.0, "HIGH") with { Aliases = ["CVE-2037-0001"] },
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "dup-adv-pkg", "1.0.0"));

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.Single(vulns.Scored);
        Assert.Empty(vulns.Unscored);
        Assert.True(vulns.HasKev);
        Assert.True(vulns.Scored[0].IsKev);
    }

    [Fact]
    public async Task Kev_NotReported_WhenOnlyUnrelatedRowsAreKev()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("unrelated-kev-pkg", "1.0.0", license: "MIT");
        await VulnerabilitySeeder.InsertVulnAsync(
            _db, "CVE-2020-0001", ecosystem: "npm", packageName: "unrelated-kev-pkg",
            isKev: true, epssScore: 0.5);
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-aaaa-bbbb-cccc", 7.0, "HIGH") with { Aliases = ["CVE-2021-0002"] },
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "unrelated-kev-pkg", "1.0.0"));

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.False(vulns.HasKev);
        Assert.Null(vulns.MaxEpss);
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

    [Theory]
    [InlineData("PyPI", false)]
    [InlineData("npm", true)]
    public async Task LocalDump_WithoutTheEcosystemsFeed_IsNoOsvCoverage_NeverCheckedClean(
        string dumpEcosystem, bool expectChecked)
    {
        // OSV_MODE=local with a dump that holds no npm feed: an empty answer for an npm package is
        // silence, not a clean result. The twin (the dump holds the npm feed) stays checked.
        string dir = Path.Combine(Path.GetTempPath(), $"lookup-osv-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(dir, "ADV-1.json"), $$"""
                {"id":"ADV-1","summary":"other package","affected":[{"package":{"ecosystem":"{{dumpEcosystem}}","name":"unrelated-pkg"},"versions":["9.9.9"]}]}
                """);
            string orgId = await SeedOrgWithNpmUpstreamAsync();
            StubNpmPackument("local-dump-pkg", "1.0.0", license: "MIT");
            var service = BuildService(new LocalOsvSource(dir, NullLogger<LocalOsvSource>.Instance));

            var result = (await service.LookupAsync(
                new PackageLookupRequest(orgId, "npm", "local-dump-pkg", "1.0.0"))).Result!;

            Assert.Equal(expectChecked, result.Vulnerabilities.Available);
            if (expectChecked)
            {
                Assert.Equal(AdvisorySourceInfo.CheckedStatus, result.AdvisorySource.Status);
                Assert.Equal("allowed", result.Verdict);
            }
            else
            {
                Assert.Equal(AdvisorySourceInfo.UnavailableStatus, result.AdvisorySource.Status);
                Assert.Equal("no_osv_coverage", result.AdvisorySource.Reason);
                Assert.Equal("warn", result.Verdict);
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
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

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "conan", "boost", "1.84.0"));

        Assert.Equal(PackageLookupStatus.UnsupportedEcosystem, outcome.Status);
    }

    /// <summary>
    /// Go resolves a latest version from its module proxy, so an omitted version is no longer a
    /// hard failure on its own — it fails only when the org has no golang upstream to ask. That
    /// is a configuration state with its own outcome, not the retryable UpstreamUnavailable.
    /// </summary>
    [Fact]
    public async Task Golang_NoVersionGiven_NoGoUpstreamConfigured_ReturnsUpstreamNotConfigured()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var service = BuildService(new FakeOsvSource(_ => []));

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "golang", "example.com/mod", null));

        Assert.Equal(PackageLookupStatus.UpstreamNotConfigured, outcome.Status);
        Assert.Equal("golang", outcome.Reason);
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task NoUpstreamConfigured_IsNotCached_SoAddingAnUpstreamTakesEffectAtOnce()
    {
        // Nothing invalidates the lookup cache when an operator adds an upstream, so the
        // not-configured answer must not outlive the configuration it describes.
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        StubWidgetMavenMetadata();
        var service = BuildService(NoAdvisories());
        var request = new PackageLookupRequest(orgId, "maven", "com.acme:widget", null);

        var before = await service.LookupAsync(request);
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
        await registries.AddAsync(orgId, new NewUpstreamRegistry("maven", _server.Urls[0]));
        var after = await service.LookupAsync(request);

        Assert.Equal(PackageLookupStatus.UpstreamNotConfigured, before.Status);
        Assert.Equal(PackageLookupStatus.Ok, after.Status);
        Assert.Equal("2.0.0", after.Result!.Version);
    }

    [Fact]
    public async Task NoUpstreamConfigured_ExplicitVersion_StillAnswers_NotMarkedReserved()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "maven", "com.acme:widget", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.False(outcome.Result!.Reserved);
        Assert.Contains("release_age", outcome.Result.UnavailableChecks);
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

    // ── Maven reserved namespaces ────────────────────────────────────────────────

    [Theory]
    [InlineData("com.acme")]
    [InlineData("com.acme.widget")]
    public async Task MavenLookup_ReservedName_ExplicitVersion_NeverConsultsUpstream(string pattern)
    {
        // Both readings of com/acme/widget/maven-metadata.xml are checked. A reserved coordinate
        // reads as local-only: the advisory and licence verdict still run, the upstream-derived
        // checks are reported unavailable, and upstream is never asked.
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", pattern, createdBy: null);
        StubWidgetMavenMetadata();
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "maven", "com.acme:widget", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("1.0.0", outcome.Result!.Version);
        Assert.True(outcome.Result.Reserved);
        Assert.Contains("release_age", outcome.Result.UnavailableChecks);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task MavenLookup_NotReserved_ExplicitVersion_IsNotMarkedReserved()
    {
        // Adversarial twin of the explicit-version case: a reservation past the dot boundary
        // leaves the coordinate unreserved, so upstream is consulted and no marker is set.
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", "com.acmecorp", createdBy: null);
        StubWidgetMavenMetadata();
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "maven", "com.acme:widget", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.False(outcome.Result!.Reserved);
        Assert.NotEmpty(_server.LogEntries);
    }

    [Fact]
    public async Task MavenLookup_ReservedName_NoVersion_IsReserved_WithoutConsultingUpstream()
    {
        // With no version there is nothing to evaluate without upstream. The reservation is a
        // standing operator choice, so the outcome says so: never the retryable
        // UpstreamUnavailable, and never a false "not found".
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", "com.acme", createdBy: null);
        StubWidgetMavenMetadata();
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "maven", "com.acme:widget", null));

        Assert.Equal(PackageLookupStatus.Reserved, outcome.Status);
        Assert.Equal("maven", outcome.Reason);
        Assert.Null(outcome.Result);
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task MavenLookup_NotReserved_NoVersion_UpstreamUnreachable_IsStillUpstreamUnavailable()
    {
        // Adversarial twin: an unreserved coordinate whose upstream answers 503 is a genuine
        // outage and keeps the retryable outcome.
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", "com.acmecorp", createdBy: null);
        _server.Given(Request.Create().WithPath("/com/acme/widget/maven-metadata.xml").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(503));
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "maven", "com.acme:widget", null));

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable, outcome.Status);
        Assert.NotEmpty(_server.LogEntries);
    }

    [Fact]
    public async Task MavenLookup_ReservationInAnotherOrg_DoesNotApply()
    {
        string reservingOrg = await SeedOrgWithMavenUpstreamAsync();
        string otherOrg = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(reservingOrg, "maven", "com.acme", createdBy: null);
        StubWidgetMavenMetadata();
        var service = BuildService(NoAdvisories());

        var reserving = await service.LookupAsync(new PackageLookupRequest(reservingOrg, "maven", "com.acme:widget", null));
        var other = await service.LookupAsync(new PackageLookupRequest(otherOrg, "maven", "com.acme:widget", null));

        Assert.Equal(PackageLookupStatus.Reserved, reserving.Status);
        Assert.Equal(PackageLookupStatus.Ok, other.Status);
        Assert.Equal("2.0.0", other.Result!.Version);
        Assert.False(other.Result.Reserved);
    }

    [Fact]
    public async Task MavenLookup_NotReserved_NoVersion_ResolvesLatestFromUpstream()
    {
        // Adversarial twin: a reservation that covers neither reading (com.acmecorp sits past the
        // dot boundary) leaves the lookup going upstream and resolving the latest release.
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        await _reserved.AddAsync(orgId, "maven", "com.acmecorp", createdBy: null);
        StubWidgetMavenMetadata();
        var service = BuildService(NoAdvisories());

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "maven", "com.acme:widget", null));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("2.0.0", outcome.Result!.Version);
        Assert.True(outcome.Result.VersionInferred);
        Assert.NotEmpty(_server.LogEntries);
        Assert.All(_server.LogEntries,
            e => Assert.Equal("/com/acme/widget/maven-metadata.xml", e.RequestMessage?.Path));
    }

    [Fact]
    public async Task MavenLookup_ResolverReportsReserved_IsReservedNotNotFound()
    {
        // The lookup's latest-version resolve treats a reserved result as the Reserved outcome.
        // Reached here through a resolver that reserves while the lookup's own metadata fetch
        // does not, so the classification is pinned independently of the lookup's own gate.
        string orgId = await SeedOrgWithMavenUpstreamAsync();
        StubWidgetMavenMetadata();
        var resolver = Substitute.For<IUpstreamLatestVersionResolver>();
        resolver.ResolveAsync("maven", orgId, "com.acme:widget", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(UpstreamLatestVersion.Reserved));
        var service = BuildService(NoAdvisories(), latestResolverOverride: resolver);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "maven", "com.acme:widget", null));

        Assert.Equal(PackageLookupStatus.Reserved, outcome.Status);
    }

    // ── Aliases + fixed version on lookup advisories ─────────────────────────────

    private const string LodashRanges =
        """
        {"id":"GHSA-35jh-r3h4-6jhm","affected":[{"package":{"ecosystem":"npm","name":"lodash"},
         "ranges":[{"type":"SEMVER","events":[
           {"introduced":"0"},{"fixed":"3.10.2"},{"introduced":"4.0.0"},{"fixed":"4.17.21"}]}]}]}
        """;

    private static OsvAdvisory WithRaw(OsvAdvisory advisory, string rawJson) => advisory with { RawJson = rawJson };

    [Fact]
    public async Task Advisories_CarryMergedAliases_WithoutTheirOwnId_OnBothBuckets()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("alias-pkg", "1.0.0", license: "MIT");
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            ScoredAdvisoryRecord("GHSA-alias-0001", 8.0, "HIGH") with { Aliases = ["CVE-2037-0002", "GHSA-alias-0001"] },
            ScoredAdvisoryRecord("GHSA-alias-0001", 8.0, "HIGH") with { Aliases = ["CVE-2037-0001", "cve-2037-0002"] },
            UnscoredAdvisoryRecord("PYSEC-2037-1") with { Aliases = ["CVE-2037-0001"] },
        });
        var service = BuildService(osv);

        var outcome = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "alias-pkg", "1.0.0"));

        var vulns = outcome.Result!.Vulnerabilities;
        Assert.Equal(["CVE-2037-0002", "CVE-2037-0001"], vulns.Scored.Single().Aliases);
        Assert.Equal(["CVE-2037-0001"], vulns.Unscored.Single().Aliases);
    }

    [Fact]
    public async Task FixedVersion_ResolvesTheReleaseLineOfTheQueriedVersion()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("lodash-a", "4.17.20", license: "MIT");
        StubNpmPackument("lodash-b", "3.5.0", license: "MIT");
        StubNpmPackument("lodash-c", "4.17.21", license: "MIT");
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            WithRaw(ScoredAdvisoryRecord("GHSA-35jh-r3h4-6jhm", 7.4, "HIGH"), LodashRanges),
        });
        var service = BuildService(osv);

        // The record's package name is "lodash"; a differing name falls back to every entry.
        var onModernLine = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "lodash-a", "4.17.20"));
        var onOldLine = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "lodash-b", "3.5.0"));
        var alreadyFixed = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "lodash-c", "4.17.21"));

        Assert.Equal("4.17.21", onModernLine.Result!.Vulnerabilities.Scored.Single().FixedVersion);
        Assert.Equal("3.10.2", onOldLine.Result!.Vulnerabilities.Scored.Single().FixedVersion);
        Assert.Null(alreadyFixed.Result!.Vulnerabilities.Scored.Single().FixedVersion);
    }

    [Fact]
    public async Task FixedVersion_MixedAdvisories_NullWhereNoFixOrNoRange_AndRepeatLookupKeepsFields()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        StubNpmPackument("mixed-fix", "2.0.0", license: "MIT");
        const string noFix =
            """{"id":"GHSA-nofix","affected":[{"package":{"ecosystem":"npm","name":"mixed-fix"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}""";
        const string fixedAt =
            """{"id":"GHSA-fix","affected":[{"package":{"ecosystem":"npm","name":"mixed-fix"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.1"}]}]}]}""";
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            WithRaw(ScoredAdvisoryRecord("GHSA-fix", 6.0, "MEDIUM"), fixedAt),
            WithRaw(ScoredAdvisoryRecord("GHSA-nofix", 5.0, "MEDIUM"), noFix),
            UnscoredAdvisoryRecord("GHSA-noraw"),
        });
        var service = BuildService(osv);

        var first = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "mixed-fix", "2.0.0"));
        var cached = await service.LookupAsync(new PackageLookupRequest(orgId, "npm", "mixed-fix", "2.0.0"));

        foreach (var outcome in new[] { first, cached })
        {
            var vulns = outcome.Result!.Vulnerabilities;
            Assert.Equal("2.0.1", vulns.Scored.Single(a => a.Id == "GHSA-fix").FixedVersion);
            Assert.Null(vulns.Scored.Single(a => a.Id == "GHSA-nofix").FixedVersion);
            Assert.Null(vulns.Unscored.Single().FixedVersion);
        }
    }

    // ── Advisory detail fallback ─────────────────────────────────────────────────

    [Fact]
    public async Task FindAdvisoryDetail_MatchesByIdOrAlias_AndResolvesFromTheOsvRecord()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var osv = new FakeOsvSource(_ => new List<OsvAdvisory>
        {
            WithRaw(ScoredAdvisoryRecord("GHSA-35jh-r3h4-6jhm", 7.4, "HIGH") with { Aliases = ["CVE-2021-23337"] }, LodashRanges),
            ScoredAdvisoryRecord("GHSA-other", 5.0, "MEDIUM"),
        });
        var service = BuildService(osv);

        var byId = await service.FindAdvisoryDetailAsync(orgId, "npm", "lodash", "4.17.20", "GHSA-35jh-r3h4-6jhm");
        var byAlias = await service.FindAdvisoryDetailAsync(orgId, "npm", "lodash", "4.17.20", "CVE-2021-23337");
        var unknown = await service.FindAdvisoryDetailAsync(orgId, "npm", "lodash", "4.17.20", "GHSA-nope");

        Assert.NotNull(byId);
        Assert.Equal("4.17.21", FixedVersionResolver.Resolve(byId.Detail.Affected, "npm", "lodash", "4.17.20"));
        Assert.NotNull(byAlias);
        Assert.Equal("GHSA-35jh-r3h4-6jhm", byAlias.Detail.Id);
        Assert.Null(unknown);
    }

    [Fact]
    public async Task FindAdvisoryDetail_ReservedName_OsvUnreached_AndBadCoordinate_AreNull()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        await _reserved.AddAsync(orgId, "npm", "internal-lib", createdBy: null);
        var advisories = new List<OsvAdvisory> { ScoredAdvisoryRecord("GHSA-x", 5.0, "MEDIUM") };
        var reachable = BuildService(new FakeOsvSource(_ => advisories));
        var unreachable = BuildService(new FakeOsvSource(_ => new List<OsvAdvisory>(), reached: false));

        Assert.Null(await reachable.FindAdvisoryDetailAsync(orgId, "npm", "internal-lib", "1.0.0", "GHSA-x"));
        Assert.Null(await unreachable.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "1.0.0", "GHSA-x"));
        Assert.Null(await reachable.FindAdvisoryDetailAsync(orgId, "rpm", "public-lib", "1.0.0", "GHSA-x"));
        Assert.Null(await reachable.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "../1", "GHSA-x"));
        Assert.NotNull(await reachable.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "1.0.0", "GHSA-x"));
    }


    // ── OSV answer caching ───────────────────────────────────────────────────────

    [Fact]
    public async Task FindAdvisoryDetail_RepeatedCalls_HitOsvOncePerTtl_ThenAgain()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var osv = new FakeOsvSource(_ => [ScoredAdvisoryRecord("GHSA-x", 5.0, "MEDIUM")]);
        var clock = TestTime.Frozen();
        var service = BuildService(osv, clock: clock);

        for (int i = 0; i < 3; i++)
        {
            Assert.NotNull(await service.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "1.0.0", "GHSA-x"));
        }

        Assert.Single(osv.QueryCalls);

        clock.Advance(TimeSpan.FromMinutes(6));
        Assert.NotNull(await service.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "1.0.0", "GHSA-x"));
        Assert.Equal(2, osv.QueryCalls.Count);
    }

    [Fact]
    public async Task FindAdvisoryDetail_UnreachedOsv_IsNotCached_AndRecoversWhenReached()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var osv = new FakeOsvSource(_ => [ScoredAdvisoryRecord("GHSA-x", 5.0, "MEDIUM")], reached: false);
        var service = BuildService(osv, clock: TestTime.Frozen());

        Assert.Null(await service.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "1.0.0", "GHSA-x"));
        Assert.Null(await service.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "1.0.0", "GHSA-x"));
        Assert.Equal(2, osv.QueryCalls.Count);

        osv.Reached = true;
        Assert.NotNull(await service.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "1.0.0", "GHSA-x"));
    }

    [Fact]
    public async Task FindAdvisoryDetail_NameReservedAfterFirstCall_IsRefusedOnTheSecond()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var osv = new FakeOsvSource(_ => [ScoredAdvisoryRecord("GHSA-x", 5.0, "MEDIUM")]);
        var service = BuildService(osv, clock: TestTime.Frozen());

        Assert.NotNull(await service.FindAdvisoryDetailAsync(orgId, "npm", "later-reserved", "1.0.0", "GHSA-x"));
        await _reserved.AddAsync(orgId, "npm", "later-reserved", createdBy: null);

        Assert.Null(await service.FindAdvisoryDetailAsync(orgId, "npm", "later-reserved", "1.0.0", "GHSA-x"));
    }

    [Fact]
    public async Task Apk_OriginProbe_IsCachedAcrossLookups_AndNotWhenUnreached()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: DistroFeed(
            "Alpine:v3.20", "openssl", ["3.1.0-r0"], ScoredAdvisoryRecord("ALPINE-CVE-2024-9", 7.5, "HIGH")));
        var clock = TestTime.Frozen();
        var service = BuildService(osv, clock: clock);

        foreach (string version in new[] { "3.1.4-r5", "3.1.5-r0", "3.1.6-r0" })
        {
            var result = (await service.LookupAsync(
                new PackageLookupRequest(orgId, "apk", "openssl", version, "v3.20"))).Result!;
            Assert.Equal("checked", result.AdvisorySource.Status);
        }

        Assert.Single(osv.ScopedCalls, c => c.Version == "0");

        clock.Advance(TimeSpan.FromMinutes(6));
        await service.LookupAsync(new PackageLookupRequest(orgId, "apk", "openssl", "3.1.7-r0", "v3.20"));
        Assert.Equal(2, osv.ScopedCalls.Count(c => c.Version == "0"));

        var unreached = new FakeOsvSource(_ => [], scoped: (s, n, v) =>
            new OsvScopedQueryResult([], Reached: v != "0"));
        var flaky = BuildService(unreached, clock: clock);
        for (int i = 0; i < 2; i++)
        {
            var r = (await flaky.LookupAsync(
                new PackageLookupRequest(orgId, "apk", "zlib", $"1.3.{i}-r0", "v3.20"))).Result!;
            Assert.Equal("unavailable", r.AdvisorySource.Status);
        }

        Assert.Equal(2, unreached.ScopedCalls.Count(c => c.Version == "0"));
    }


    [Fact]
    public async Task OsvQueryCache_PastTheByteBudget_EvictsOldest_AndOversizeEntriesAreNotStored()
    {
        var clock = TestTime.Frozen();
        var advisory = ScoredAdvisoryRecord("GHSA-big", 5.0, "MEDIUM") with { RawJson = new string('x', 1000) };
        long each = OsvQueryCache.EstimateBytes([advisory]);
        var cache = new OsvQueryCache(clock, maxBytes: each * 3 * 8);
        int computes = 0;

        Task<string> Get(string key, int advisories) => cache.GetOrComputeAsync<string>(key, () =>
        {
            computes++;
            return Task.FromResult(("v", true, each * advisories));
        }, CancellationToken.None);

        for (int i = 0; i < 40; i++)
        {
            await Get($"k{i}", 1);
            clock.Advance(TimeSpan.FromSeconds(1));
        }

        Assert.True(cache.TotalBytes <= each * 3 * 8);
        Assert.Equal(each * cache.EntryCount, cache.TotalBytes);
        Assert.True(cache.EntryCount < 40);
        int before = computes;
        await Get("k0", 1);
        Assert.Equal(before + 1, computes);

        await Get("huge", 4);
        await Get("huge", 4);
        Assert.Equal(before + 3, computes);
    }


    [Fact]
    public async Task FindAdvisoryDetail_ConcurrentIdenticalCalls_ShareOneOsvQuery()
    {
        string orgId = await SeedOrgWithNpmUpstreamAsync();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var osv = new FakeOsvSource(_ => [ScoredAdvisoryRecord("GHSA-x", 5.0, "MEDIUM")]) { Gate = gate };
        var service = BuildService(osv, clock: TestTime.Frozen());

        var first = service.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "1.0.0", "GHSA-x");
        while (osv.QueryCalls.Count == 0)
        {
            await Task.Yield();
        }

        var second = service.FindAdvisoryDetailAsync(orgId, "npm", "public-lib", "1.0.0", "GHSA-x");
        // now-ok: real elapsed time lets the second call reach the single-flight lock before the gate opens
        await Task.Delay(TimeSpan.FromMilliseconds(300), TimeProvider.System, CancellationToken.None);
        Assert.Single(osv.QueryCalls);

        gate.SetResult();
        Assert.NotNull(await first);
        Assert.NotNull(await second);
        Assert.Single(osv.QueryCalls);
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
        Assert.Equal("release_age", outcome.Result.BlockedReason);
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
        Assert.Equal("deprecated", outcome.Result.BlockedReason);
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

    // ── apk / rpm: release-scoped distro feeds ───────────────────────────────────

    private static readonly string[] AffectedApk = ["8.5.0-r0"];

    private static Func<DistroScope, string, string, OsvScopedQueryResult> DistroFeed(
        string ecosystem, string name, string[] affectedVersions, OsvAdvisory advisory) =>
        (scope, n, v) => new OsvScopedQueryResult(
            scope.OsvEcosystem == ecosystem && n == name && (affectedVersions.Contains(v) || v == "0")
                ? [advisory]
                : [],
            Reached: true);

    [Fact]
    public async Task Apk_AffectedVersion_ReportsAdvisory_ScopedToTheRequestedRelease()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: DistroFeed(
            "Alpine:v3.20", "curl", AffectedApk, ScoredAdvisoryRecord("ALPINE-CVE-2024-1", 7.5, "HIGH")));

        var outcome = await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0", "v3.20"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        var result = outcome.Result!;
        Assert.True(result.Vulnerabilities.Available);
        Assert.Equal("ALPINE-CVE-2024-1", Assert.Single(result.Vulnerabilities.Scored).Id);
        Assert.Equal("checked", result.AdvisorySource.Status);
        Assert.Equal("osv", result.AdvisorySource.Source);
        Assert.Equal("Alpine:v3.20", result.AdvisorySource.Distro);
        Assert.False(result.AdvisorySource.DistroInferred);
        Assert.Equal("pkg:apk/alpine/curl@8.5.0-r0", result.Purl);
        Assert.Equal(("Alpine:v3.20", "curl", "8.5.0-r0"), Assert.Single(osv.ScopedCalls));
    }

    [Fact]
    public async Task Apk_UnaffectedVersion_IsExplicitlyCheckedAndClean()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: DistroFeed(
            "Alpine:v3.20", "curl", AffectedApk, ScoredAdvisoryRecord("ALPINE-CVE-2024-1", 7.5, "HIGH")));

        var outcome = await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.9.1-r0", "Alpine:v3.20"));

        var result = outcome.Result!;
        Assert.True(result.Vulnerabilities.Available);
        Assert.Empty(result.Vulnerabilities.Scored);
        Assert.Empty(result.Vulnerabilities.Unscored);
        Assert.Equal("checked", result.AdvisorySource.Status);
        Assert.DoesNotContain("vulnerabilities", result.UnavailableChecks);
        Assert.Equal("allowed", result.Verdict);
    }

    [Fact]
    public async Task Apk_NoRequestedRelease_AndNoUpstream_SaysSoInsteadOfReadingClean()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([], Reached: true));

        var outcome = await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        var result = outcome.Result!;
        Assert.False(result.Vulnerabilities.Available);
        Assert.Equal("unavailable", result.AdvisorySource.Status);
        Assert.Equal("distro_required", result.AdvisorySource.Reason);
        Assert.Contains("vulnerabilities", result.UnavailableChecks);
        Assert.Equal("warn", result.Verdict);
        Assert.Empty(osv.ScopedCalls);
    }

    [Fact]
    public async Task Apk_ReleaseDerivedFromASingleConfiguredUpstream()
    {
        string orgId = await SeedOrgWithApkUpstreamsAsync("https://dl-cdn.alpinelinux.org/alpine/v3.19/main");
        var osv = new FakeOsvSource(_ => [], scoped: DistroFeed(
            "Alpine:v3.19", "curl", AffectedApk, ScoredAdvisoryRecord("ALPINE-CVE-2024-2", 5.0, "MEDIUM")));

        var outcome = await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0"));

        var result = outcome.Result!;
        Assert.Equal("checked", result.AdvisorySource.Status);
        Assert.Equal("Alpine:v3.19", result.AdvisorySource.Distro);
        Assert.True(result.AdvisorySource.DistroInferred);
        Assert.Single(result.Vulnerabilities.Scored);
    }

    [Fact]
    public async Task Apk_UpstreamsOnDifferentReleases_AreAmbiguous_AndNotGuessed()
    {
        string orgId = await SeedOrgWithApkUpstreamsAsync(
            "https://dl-cdn.alpinelinux.org/alpine/v3.19/main", "https://dl-cdn.alpinelinux.org/alpine/v3.20/main");
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([], Reached: true));

        var outcome = await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0"));

        Assert.Equal("distro_required", outcome.Result!.AdvisorySource.Reason);
        Assert.Empty(osv.ScopedCalls);
    }

    [Fact]
    public async Task Apk_RequestedReleaseWinsOverTheUpstreamRelease()
    {
        string orgId = await SeedOrgWithApkUpstreamsAsync("https://dl-cdn.alpinelinux.org/alpine/v3.19/main");
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([], Reached: true));

        await BuildService(osv).LookupAsync(new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0", "3.21"));

        Assert.All(osv.ScopedCalls, c => Assert.Equal("Alpine:v3.21", c.Scope));
        Assert.NotEmpty(osv.ScopedCalls);
    }

    [Theory]
    [InlineData("apk", "edge")]
    [InlineData("apk", "bookworm")]
    [InlineData("apk", "v3")]
    [InlineData("rpm", "Rocky Linux")]
    [InlineData("rpm", "Debian:12")]
    [InlineData("rpm", "9")]
    [InlineData("rpm", "Rocky Linux:9.4")]
    [InlineData("rpm", "AlmaLinux:9.4")]
    [InlineData("rpm", "Red Hat:enterprise_linux:9")]
    public async Task InvalidDistro_IsRejectedAsInput(string ecosystem, string distro)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");

        var outcome = await BuildService(NoAdvisories()).LookupAsync(
            new PackageLookupRequest(orgId, ecosystem, "openssl", ecosystem == "apk" ? "1.0-r0" : "1.0-1", distro));

        Assert.Equal(PackageLookupStatus.InvalidInput, outcome.Status);
        Assert.Equal("distro", outcome.Field);
        Assert.Equal("distro.invalid", outcome.Reason);
    }

    [Theory]
    [InlineData("apk", "curl", "8.5.0", "v3.20")]
    [InlineData("apk", "curl", "8.5.0-r", "v3.20")]
    [InlineData("rpm", "openssl", "3.0.7", "Rocky Linux:9")]
    [InlineData("rpm", "openssl", "3.0.7-", "Rocky Linux:9")]
    public async Task BareVersionWithoutBuild_IsRejected_NotComparedAsClean(
        string ecosystem, string name, string version, string distro)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([], Reached: true));

        var outcome = await BuildService(osv).LookupAsync(new PackageLookupRequest(orgId, ecosystem, name, version, distro));

        Assert.Equal(PackageLookupStatus.InvalidInput, outcome.Status);
        Assert.Equal("version", outcome.Field);
        Assert.Equal("version.releaseRequired", outcome.Reason);
        Assert.Empty(osv.ScopedCalls);
    }

    [Fact]
    public async Task Apk_SubPackageNameTheFeedNeverLists_IsOriginUnknown_NotChecked()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        // The feed files advisories under the origin "openssl"; it has never heard of "libssl3".
        var osv = new FakeOsvSource(_ => [], scoped: DistroFeed(
            "Alpine:v3.20", "openssl", ["3.1.0-r0"], ScoredAdvisoryRecord("ALPINE-CVE-2024-9", 7.5, "HIGH")));
        var service = BuildService(osv);

        var subPackage = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "apk", "libssl3", "3.1.0-r0", "v3.20"))).Result!;
        var origin = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "apk", "openssl", "3.1.4-r5", "v3.20"))).Result!;

        Assert.Equal("unavailable", subPackage.AdvisorySource.Status);
        Assert.Equal("origin_unknown", subPackage.AdvisorySource.Reason);
        Assert.False(subPackage.Vulnerabilities.Available);
        Assert.Equal("warn", subPackage.Verdict);
        Assert.Equal("checked", origin.AdvisorySource.Status);
    }

    [Fact]
    public async Task Apk_OriginProbeUnreached_IsUnavailable_NeverChecked()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, v) => v == "0"
            ? new OsvScopedQueryResult([], Reached: false, Covered: false)
            : new OsvScopedQueryResult([], Reached: true));

        var result = (await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0", "v3.20"))).Result!;

        Assert.Equal("unavailable", result.AdvisorySource.Status);
        Assert.Equal("osv_unreachable", result.AdvisorySource.Reason);
    }

    [Fact]
    public async Task Apk_SourceUnreached_IsUnavailable_NeverClean()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([], Reached: false, Covered: false));

        var result = (await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0", "v3.20"))).Result!;

        Assert.False(result.Vulnerabilities.Available);
        Assert.Equal("osv_unreachable", result.AdvisorySource.Reason);
        Assert.Equal("warn", result.Verdict);
    }

    [Fact]
    public async Task Apk_SourceThrows_IsUnavailable_NeverClean()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => throw new InvalidOperationException("boom"));

        var result = (await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0", "v3.20"))).Result!;

        Assert.False(result.Vulnerabilities.Available);
        Assert.Equal("osv_unreachable", result.AdvisorySource.Reason);
    }

    [Fact]
    public async Task Apk_ReleaseTheSourceHoldsNoFeedFor_IsNoCoverage_NeverClean()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([], Reached: true, Covered: false));

        var result = (await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0", "v3.20"))).Result!;

        Assert.False(result.Vulnerabilities.Available);
        Assert.Equal("no_osv_coverage", result.AdvisorySource.Reason);
        Assert.Equal("Alpine:v3.20", result.AdvisorySource.Distro);
    }

    [Fact]
    public async Task Rpm_AffectedVersion_ReportsAdvisory_AndUnaffectedIsCheckedClean()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: DistroFeed(
            "Rocky Linux:9", "openssl", ["3.0.7-24.el9"], ScoredAdvisoryRecord("RLSA-2024:1", 9.1, "CRITICAL")));
        var service = BuildService(osv);

        var affected = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "rpm", "openssl", "3.0.7-24.el9", "rocky linux:9"))).Result!;
        var fixedBuild = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "rpm", "openssl", "3.0.7-27.el9", "rocky linux:9"))).Result!;

        Assert.Equal("RLSA-2024:1", Assert.Single(affected.Vulnerabilities.Scored).Id);
        Assert.Equal("Rocky Linux:9", affected.AdvisorySource.Distro);
        Assert.Equal("pkg:rpm/rocky-linux/openssl@3.0.7-24.el9", affected.Purl);
        Assert.Empty(fixedBuild.Vulnerabilities.Scored);
        Assert.True(fixedBuild.Vulnerabilities.Available);
        Assert.Equal("checked", fixedBuild.AdvisorySource.Status);
    }

    [Fact]
    public async Task Rpm_NameTheScopedFeedNeverLists_IsNameUnknown_NotCheckedClean()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        // The Rocky Linux 9 feed lists openssl; "opensll" (a typo) and an EPEL-only package are
        // names it has never filed an advisory under.
        var osv = new FakeOsvSource(_ => [], scoped: DistroFeed(
            "Rocky Linux:9", "openssl", ["3.0.7-24.el9"], ScoredAdvisoryRecord("RLSA-2024:2", 9.1, "CRITICAL")));
        var service = BuildService(osv);

        var typo = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "rpm", "opensll", "3.0.7-27.el9", "Rocky Linux:9"))).Result!;
        var epel = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "rpm", "htop", "3.3.0-1.el9", "Rocky Linux:9"))).Result!;
        var listed = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "rpm", "openssl", "3.0.7-27.el9", "Rocky Linux:9"))).Result!;

        foreach (var unknown in new[] { typo, epel })
        {
            Assert.Equal("unavailable", unknown.AdvisorySource.Status);
            Assert.Equal("name_unknown", unknown.AdvisorySource.Reason);
            Assert.Equal("Rocky Linux:9", unknown.AdvisorySource.Distro);
            Assert.False(unknown.Vulnerabilities.Available);
            Assert.Contains("vulnerabilities", unknown.UnavailableChecks);
            Assert.Equal("warn", unknown.Verdict);
        }

        Assert.Equal("checked", listed.AdvisorySource.Status);
        Assert.True(listed.Vulnerabilities.Available);
        Assert.Contains(("Rocky Linux:9", "opensll", "0"), osv.ScopedCalls);
    }

    [Fact]
    public async Task Rpm_NameProbeUnreached_IsUnavailable_NeverChecked()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, v) => v == "0"
            ? new OsvScopedQueryResult([], Reached: false, Covered: false)
            : new OsvScopedQueryResult([], Reached: true));

        var result = (await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "rpm", "openssl", "3.0.7-27.el9", "Rocky Linux:9"))).Result!;

        Assert.Equal("unavailable", result.AdvisorySource.Status);
        Assert.Equal("osv_unreachable", result.AdvisorySource.Reason);
    }

    [Fact]
    public async Task Rpm_NoRelease_AndAmbiguousUpstream_IsDistroRequired()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
        await registries.AddAsync(orgId, new NewUpstreamRegistry("rpm", "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os"));
        await registries.AddAsync(orgId, new NewUpstreamRegistry("rpm", "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os"));
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([], Reached: true));

        var result = (await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "rpm", "openssl", "3.0.7-24.el9"))).Result!;

        Assert.Equal("distro_required", result.AdvisorySource.Reason);
        Assert.False(result.Vulnerabilities.Available);
        Assert.Empty(osv.ScopedCalls);
    }

    [Fact]
    public async Task Rpm_ReleaseDerivedFromASingleRockyUpstream()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
        await registries.AddAsync(orgId, new NewUpstreamRegistry("rpm", "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os"));
        await registries.AddAsync(orgId, new NewUpstreamRegistry("rpm", "https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os"));
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([], Reached: true));

        var result = (await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "rpm", "openssl", "3.0.7-24.el9"))).Result!;

        Assert.Equal("Rocky Linux:9", result.AdvisorySource.Distro);
        Assert.True(result.AdvisorySource.DistroInferred);
    }

    [Fact]
    public async Task DistroLookup_IsCachedPerRelease_NotSharedAcrossReleases()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => [], scoped: DistroFeed(
            "Alpine:v3.20", "curl", AffectedApk, ScoredAdvisoryRecord("ALPINE-CVE-2024-1", 7.5, "HIGH")));
        var service = BuildService(osv);

        var onAffectedRelease = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0", "v3.20"))).Result!;
        var onOtherRelease = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0", "v3.19"))).Result!;
        var repeat = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r0", "v3.20"))).Result!;

        Assert.Single(onAffectedRelease.Vulnerabilities.Scored);
        Assert.Empty(onOtherRelease.Vulnerabilities.Scored);
        Assert.Single(repeat.Vulnerabilities.Scored);
        // v3.20 answers once; v3.19 answers empty and is then probed for the name, once.
        Assert.Equal(3, osv.ScopedCalls.Count);
    }

    [Theory]
    [InlineData("apk", "curl")]
    [InlineData("rpm", "openssl")]
    [InlineData("oci", "library/nginx")]
    [InlineData("terraform", "hashicorp/aws")]
    public async Task NewEcosystems_RequireAnExplicitVersion(string ecosystem, string name)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");

        var outcome = await BuildService(NoAdvisories()).LookupAsync(
            new PackageLookupRequest(orgId, ecosystem, name, null));

        Assert.Equal(PackageLookupStatus.VersionRequired, outcome.Status);
    }

    [Theory]
    [InlineData("apk", "curl", "8.5.0-r0", "v3.20")]
    [InlineData("terraform", "hashicorp/aws", "5.0.0", null)]
    public async Task NewEcosystems_ReservedName_IsReportedReserved(
        string ecosystem, string name, string version, string? distro)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        string otherOrg = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await _reserved.AddAsync(orgId, ecosystem, name, createdBy: null);
        var service = BuildService(new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([], Reached: true)));

        var reserved = (await service.LookupAsync(new PackageLookupRequest(orgId, ecosystem, name, version, distro))).Result!;
        var open = (await service.LookupAsync(new PackageLookupRequest(otherOrg, ecosystem, name, version, distro))).Result!;

        Assert.True(reserved.Reserved);
        Assert.False(open.Reserved);
    }

    private static OsvAdvisory AdvisoryWithRanges(string id, string[] aliases, string affectedJson) => new(
        Id: id, Aliases: aliases, Summary: "distro advisory", Severity: "HIGH", CvssScore: 7.5,
        AffectedPackages: [], Published: null, Modified: null, IsHydrated: true,
        RawJson: $$"""{"id":"{{id}}","affected":{{affectedJson}}}""");

    [Fact]
    public async Task Rpm_Advisory_CarriesAliases_AndTheFixOfTheScopedRelease_NotAnotherReleasesFix()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var advisory = AdvisoryWithRanges("RLSA-2024:7", ["CVE-2024-0007", "RLSA-2024:7"],
            """
            [{"package":{"ecosystem":"Rocky Linux:8","name":"openssl"},
              "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9:9.9-1.el8"}]}]},
             {"package":{"ecosystem":"Rocky Linux:9","name":"openssl"},
              "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.0.7-27.el9"}]}]}]
            """);
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([advisory], Reached: true));

        var result = (await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "rpm", "openssl", "1:3.0.7-24.el9", "Rocky Linux:9"))).Result!;

        var found = Assert.Single(result.Vulnerabilities.Scored);
        Assert.Equal(["CVE-2024-0007"], found.Aliases);
        Assert.Equal("1:3.0.7-27.el9", found.FixedVersion);
    }

    [Fact]
    public async Task Apk_Advisory_FixedVersionUsesApkOrdering()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var advisory = AdvisoryWithRanges("ALPINE-CVE-2024-8", ["CVE-2024-0008"],
            """
            [{"package":{"ecosystem":"Alpine:v3.20","name":"curl"},
              "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.5.0-r10"}]}]}]
            """);
        var osv = new FakeOsvSource(_ => [], scoped: (_, _, _) => new OsvScopedQueryResult([advisory], Reached: true));
        var service = BuildService(osv);

        // -r9 < -r10 numerically (a text ordering would call it newer and report no fix).
        var result = (await service.LookupAsync(
            new PackageLookupRequest(orgId, "apk", "curl", "8.5.0-r9", "v3.20"))).Result!;

        Assert.Equal("8.5.0-r10", Assert.Single(result.Vulnerabilities.Scored).FixedVersion);
    }

    [Fact]
    public async Task OciAdvisory_HasAliases_AndNoFixedVersion()
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        await SeedScanResultAsync(orgId, versionId, 0, ("DEBIAN-CVE-2024-0010", 8.0));

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        var found = Assert.Single(result.Vulnerabilities.Scored);
        Assert.Equal(["CVE-2024-0001"], found.Aliases);
        Assert.Null(found.FixedVersion);
    }

    [Theory]
    [InlineData("apk")]
    [InlineData("rpm")]
    [InlineData("oci")]
    [InlineData("terraform")]
    public async Task AdvisoryDetailFallback_IsNotAnsweredForEcosystemsWithoutAPurlQuery(string ecosystem)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var service = BuildService(new FakeOsvSource(_ => [AdvisoryWithRanges("X-1", [], "[]")]));

        var detail = await service.FindAdvisoryDetailAsync(orgId, ecosystem, "pkg/name", "1.0-1", "X-1");

        Assert.Null(detail);
    }

    // ── terraform: no advisory source ────────────────────────────────────────────

    [Fact]
    public async Task Terraform_ReportsNotApplicable_WithoutConsultingAnySource_AndDoesNotWarn()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var osv = new FakeOsvSource(_ => throw new InvalidOperationException("OSV must not be queried"));

        var outcome = await BuildService(osv).LookupAsync(
            new PackageLookupRequest(orgId, "terraform", "hashicorp/aws", "5.31.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        var result = outcome.Result!;
        Assert.Equal("not_applicable", result.AdvisorySource.Status);
        Assert.Equal("no_advisory_source", result.AdvisorySource.Reason);
        Assert.Null(result.AdvisorySource.Source);
        Assert.False(result.Vulnerabilities.Available);
        Assert.DoesNotContain("vulnerabilities", result.UnavailableChecks);
        Assert.Equal("allowed", result.Verdict);
        Assert.Equal("pkg:terraform/hashicorp/aws@5.31.0", result.Purl);
    }

    // ── oci: the org's own image-scan result ─────────────────────────────────────

    private const string ImageDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    private async Task<(string OrgId, string VersionId)> SeedHostedImageAsync(string repository = "team/app")
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        string pkg = await PackageSeeder.InsertAsync(_db, orgId, "oci", repository);
        string versionId = await PackageSeeder.InsertVersionAsync(_db, pkg, ImageDigest, "pkg:oci/app@sha256%3A1111");
        return (orgId, versionId);
    }

    private async Task SeedScanResultAsync(
        string orgId, string versionId, int gaps = 0, params (string OsvId, double Cvss)[] advisories)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_scan_coverage (
                id, org_id, owner_kind, package_version_id, platform, scanner_version,
                extraction_version, osv_source, scanned_at, gaps_json, gap_count)
            VALUES (@id, @orgId, 'package_version', @pv, 'linux/amd64', '1', '1', 'remote', '2026-06-15T12:00:00.000Z', '[]', @gaps)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, pv = versionId, gaps });

        foreach (var (osvId, cvss) in advisories)
        {
            string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
                _db, osvId, ecosystem: "Debian:12", packageName: "openssl", severity: "HIGH", cvssScore: cvss,
                aliases: "[\"CVE-2024-0001\"]");
            string componentId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_image_components (
                    id, org_id, owner_kind, package_version_id, platform, purl, ecosystem, name, version)
                VALUES (@componentId, @orgId, 'package_version', @pv, 'linux/amd64', 'pkg:deb/debian/openssl@3.0', 'deb', 'openssl', '3.0')
                """,
                new { componentId, orgId, pv = versionId });
            await conn.ExecuteAsync(
                "INSERT INTO oci_component_vulns (id, org_id, component_id, vuln_id) VALUES (@id, @orgId, @componentId, @vulnId)",
                new { id = Guid.NewGuid().ToString("N"), orgId, componentId, vulnId });
        }
    }

    private PackageLookupService BuildOciService()
    {
        var scans = new Dependably.Infrastructure.OciScan.OciScanRepository(_db);
        var pullGate = new OciPullGateResolver(
            _db, scans, new VulnerabilityRepository(_db, TimeProvider.System), new LiveScannerCoverage());
        return BuildService(new FakeOsvSource(_ => throw new InvalidOperationException("OSV must not be queried")),
            ociScans: scans, ociPullGate: pullGate, quarantine: new QuarantineRepository(_db, TimeProvider.System));
    }

    private sealed class LiveScannerCoverage : Dependably.Infrastructure.OciScan.IOciScanCoverage
    {
        public bool Enabled => true;

        public Task<bool> IsCoveredAsync(string orgId, CancellationToken ct = default) => Task.FromResult(true);
    }

    // Under oci_scan_enforcement=block the lookup answers what the pull gate would: an image with
    // no complete scan is refused as unscanned, a finding over a tolerance is refused by its arm.

    [Fact]
    public async Task Oci_UnderBlock_ImageWithNoScanResult_IsBlockedUnscanned_AsThePullGateRefusesIt()
    {
        var (orgId, _) = await SeedHostedImageAsync();
        await SetOciScanEnforcementAsync(orgId, "block");

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.Equal("no_scan_result", result.AdvisorySource.Reason);
        Assert.Equal("blocked", result.Verdict);
        Assert.Equal("unscanned", result.BlockedReason);
    }

    [Fact]
    public async Task Oci_UnderBlock_PartialScanWithNoFindings_IsBlockedUnscanned()
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        await SetOciScanEnforcementAsync(orgId, "block");
        await SeedScanResultAsync(orgId, versionId, gaps: 2);

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.Equal("scan_incomplete", result.AdvisorySource.Reason);
        Assert.Equal("blocked", result.Verdict);
        Assert.Equal("unscanned", result.BlockedReason);
    }

    [Fact]
    public async Task Oci_UnderBlock_CompleteCleanScan_IsAllowed()
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        await SetOciScanEnforcementAsync(orgId, "block");
        await SeedScanResultAsync(orgId, versionId);

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.Equal("checked", result.AdvisorySource.Status);
        Assert.Equal("allowed", result.Verdict);
    }

    [Fact]
    public async Task Oci_UnderBlock_ScoreOverTheTolerance_IsBlockedByTheScoreArm()
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        await SetOciScanEnforcementAsync(orgId, "block");
        await SetMaxOsvScoreToleranceAsync(orgId, 7.0);
        await SeedScanResultAsync(orgId, versionId, 0, ("DEBIAN-CVE-2024-0020", 9.1));

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.Equal("blocked", result.Verdict);
        Assert.Equal("vuln_score", result.BlockedReason);
    }

    [Fact]
    public async Task Oci_UnderBlock_UnscannedImageAnOperatorApproved_IsNotBlocked()
    {
        var (orgId, _) = await SeedHostedImageAsync();
        await SetOciScanEnforcementAsync(orgId, "block");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO quarantine (id, org_id, ecosystem, purl, gate, state) VALUES (@id, @orgId, 'oci', @purl, 'unscanned', 'approved')",
                new { id = Guid.NewGuid().ToString("N"), orgId, purl = PurlNormalizer.Oci("team/app", ImageDigest) });
        }

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.Null(result.BlockedReason);
        Assert.Equal("warn", result.Verdict);
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    public async Task Oci_UnderOffOrWarn_UnscannedImageAndScoreOverTheTolerance_OnlyWarn(string posture)
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        var (otherOrg, _) = await SeedHostedImageAsync("team/other");
        await SetOciScanEnforcementAsync(orgId, posture);
        await SetOciScanEnforcementAsync(otherOrg, posture);
        await SetMaxOsvScoreToleranceAsync(orgId, 7.0);
        await SeedScanResultAsync(orgId, versionId, 0, ("DEBIAN-CVE-2024-0021", 9.1));
        var service = BuildOciService();

        var scored = (await service.LookupAsync(new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;
        var unscanned = (await service.LookupAsync(new PackageLookupRequest(otherOrg, "oci", "team/other", ImageDigest))).Result!;

        Assert.Equal("warn", scored.Verdict);
        Assert.Null(scored.BlockedReason);
        Assert.Equal("warn", unscanned.Verdict);
        Assert.Null(unscanned.BlockedReason);
    }

    [Fact]
    public async Task Oci_ScannedImageWithAdvisories_AnswersFromTheOrgsScanResult()
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        await SeedScanResultAsync(orgId, versionId, 0, ("DEBIAN-CVE-2024-0001", 8.1));

        var outcome = await BuildOciService().LookupAsync(new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        var result = outcome.Result!;
        Assert.True(result.Vulnerabilities.Available);
        var advisory = Assert.Single(result.Vulnerabilities.Scored);
        Assert.Equal("DEBIAN-CVE-2024-0001", advisory.Id);
        Assert.Equal(8.1, advisory.CvssScore);
        Assert.Equal("checked", result.AdvisorySource.Status);
        Assert.Equal("oci_scan", result.AdvisorySource.Source);
    }

    [Fact]
    public async Task Oci_ScannedCleanImage_IsExplicitlyCheckedAndClean()
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        await SeedScanResultAsync(orgId, versionId);

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.True(result.Vulnerabilities.Available);
        Assert.Empty(result.Vulnerabilities.Scored);
        Assert.Equal("checked", result.AdvisorySource.Status);
        Assert.Equal("allowed", result.Verdict);
    }

    [Fact]
    public async Task Oci_ImageWithNoScanResult_IsUnavailable_NeverClean()
    {
        var (orgId, _) = await SeedHostedImageAsync();

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.False(result.Vulnerabilities.Available);
        Assert.Equal("unavailable", result.AdvisorySource.Status);
        Assert.Equal("no_scan_result", result.AdvisorySource.Reason);
        Assert.Equal("warn", result.Verdict);
    }

    [Fact]
    public async Task Oci_ScanResultIsReadFreshWhenItLands_NotServedFromTheLookupCache()
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        var service = BuildOciService();

        var before = (await service.LookupAsync(new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;
        await SeedScanResultAsync(orgId, versionId, 0, ("DEBIAN-CVE-2024-0002", 6.0));
        var after = (await service.LookupAsync(new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.Equal("no_scan_result", before.AdvisorySource.Reason);
        Assert.Equal("checked", after.AdvisorySource.Status);
        Assert.Single(after.Vulnerabilities.Scored);
    }

    [Fact]
    public async Task Oci_AnotherOrgsScanResult_IsNeverVisible()
    {
        var (orgA, versionA) = await SeedHostedImageAsync();
        await SeedScanResultAsync(orgA, versionA, 0, ("DEBIAN-CVE-2024-0003", 9.0));
        // Org B hosts an image of the same name and digest but holds no scan result of its own.
        var (orgB, _) = await SeedHostedImageAsync();

        var forB = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgB, "oci", "team/app", ImageDigest))).Result!;
        var forA = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgA, "oci", "team/app", ImageDigest))).Result!;

        Assert.Empty(forB.Vulnerabilities.Scored);
        Assert.Equal("no_scan_result", forB.AdvisorySource.Reason);
        Assert.False(forB.Vulnerabilities.Available);
        Assert.Single(forA.Vulnerabilities.Scored);
    }

    [Fact]
    public async Task Oci_ProxiedImageSharedByTwoOrgs_ShowsEachOrgOnlyItsOwnScan()
    {
        string orgA = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        string caId = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
                "VALUES (@caId, 'oci', 'library/nginx', @digest, 'manifest', 'k', 'h')",
                new { caId, digest = ImageDigest });
            foreach (string org in new[] { orgA, orgB })
            {
                await conn.ExecuteAsync(
                    "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@org, @caId)",
                    new { org, caId });
            }

            await conn.ExecuteAsync(
                """
                INSERT INTO oci_scan_coverage (
                    id, org_id, owner_kind, cache_artifact_id, platform, scanner_version,
                    extraction_version, osv_source, scanned_at, gaps_json, gap_count)
                VALUES (@id, @orgA, 'cache_artifact', @caId, 'linux/amd64', '1', '1', 'remote', '2026-06-15T12:00:00.000Z', '[]', 0)
                """,
                new { id = Guid.NewGuid().ToString("N"), orgA, caId });
        }

        var service = BuildOciService();
        var forA = (await service.LookupAsync(new PackageLookupRequest(orgA, "oci", "library/nginx", ImageDigest))).Result!;
        var forB = (await service.LookupAsync(new PackageLookupRequest(orgB, "oci", "library/nginx", ImageDigest))).Result!;

        Assert.Equal("checked", forA.AdvisorySource.Status);
        Assert.Equal("no_scan_result", forB.AdvisorySource.Reason);
    }

    [Fact]
    public async Task Oci_PartialScan_WithNoAdvisories_IsUnavailable_NotClean()
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        await SeedScanResultAsync(orgId, versionId, gaps: 2);

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.False(result.Vulnerabilities.Available);
        Assert.Equal("unavailable", result.AdvisorySource.Status);
        Assert.Equal("scan_incomplete", result.AdvisorySource.Reason);
        Assert.Equal("warn", result.Verdict);
    }

    [Fact]
    public async Task Oci_PartialScan_StillReportsTheAdvisoriesItFound()
    {
        var (orgId, versionId) = await SeedHostedImageAsync();
        await SeedScanResultAsync(orgId, versionId, 1, ("DEBIAN-CVE-2024-0004", 7.0));

        var result = (await BuildOciService().LookupAsync(
            new PackageLookupRequest(orgId, "oci", "team/app", ImageDigest))).Result!;

        Assert.Single(result.Vulnerabilities.Scored);
        Assert.Equal("scan_incomplete", result.AdvisorySource.Reason);
        Assert.Contains("vulnerabilities", result.UnavailableChecks);
    }

    [Theory]
    [InlineData("latest")]
    [InlineData("1.25")]
    [InlineData("sha256:abc")]
    public async Task Oci_VersionThatIsNotADigest_IsRejected(string version)
    {
        var (orgId, _) = await SeedHostedImageAsync();

        var outcome = await BuildOciService().LookupAsync(new PackageLookupRequest(orgId, "oci", "team/app", version));

        Assert.Equal(PackageLookupStatus.InvalidInput, outcome.Status);
        Assert.Equal("oci.digestRequired", outcome.Reason);
    }

    private async Task<string> SeedOrgWithApkUpstreamsAsync(params string[] urls)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
        foreach (string url in urls)
        {
            await registries.AddAsync(orgId, new NewUpstreamRegistry("apk", url));
        }

        return orgId;
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

    private async Task<string> SeedOrgWithMavenUpstreamAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Configured(_envelopeKey));
        await registries.AddAsync(orgId, new NewUpstreamRegistry("maven", _server.Urls[0]));
        return orgId;
    }

    private void StubWidgetMavenMetadata()
        => _server.Given(Request.Create().WithPath("/com/acme/widget/maven-metadata.xml").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody(
                "<metadata><versioning><release>2.0.0</release>" +
                "<versions><version>1.0.0</version><version>2.0.0</version></versions></versioning></metadata>"));

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

    private async Task SetEpssToleranceAsync(string orgId, double? probability, double? percentile)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET max_epss_tolerance = @probability, max_epss_percentile_tolerance = @percentile WHERE org_id = @orgId",
            new { probability, percentile, orgId });
    }

    private async Task SetBlockKevAsync(string orgId, string mode)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET block_kev = @mode WHERE org_id = @orgId",
            new { mode, orgId });
    }

    private async Task SetOciScanEnforcementAsync(string orgId, string mode)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET oci_scan_enforcement = @mode WHERE org_id = @orgId",
            new { mode, orgId });
    }

    private async Task SetMaxOsvScoreToleranceAsync(string orgId, double tolerance)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET max_osv_score_tolerance = @tolerance WHERE org_id = @orgId",
            new { tolerance, orgId });
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
        IOsvSource osv, bool instanceAirGapped = false, TimeProvider? clock = null,
        IUpstreamLatestVersionResolver? latestResolverOverride = null,
        Dependably.Infrastructure.OciScan.OciScanRepository? ociScans = null,
        OciPullGateResolver? ociPullGate = null, QuarantineRepository? quarantine = null)
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
        var latestResolver = latestResolverOverride
            ?? new UpstreamLatestVersionResolver(upstreamClient, registryResolver, _reserved);

        var orgs = new OrgRepository(_db);
        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var cache = new PackageLookupCache(TimeProvider.System);

        return new PackageLookupService(
            orgs, registryResolver, upstreamClient, latestResolver, osv, vulns, licenses,
            airGap, clock ?? TimeProvider.System, cache, _reserved, ociScans: ociScans,
            ociPullGate: ociPullGate, quarantine: quarantine);
    }

    /// <summary>
    /// <paramref name="reached"/> defaults to true (a genuine, consulted answer). Passing
    /// false pins the real <see cref="OsvClient"/>/<c>LocalOsvSource</c> outage behaviour —
    /// the source returns no advisories WITHOUT throwing — that a throwing fake cannot exercise.
    /// </summary>
    private sealed class FakeOsvSource : IOsvSource
    {
        private readonly Func<string, List<OsvAdvisory>> _handler;
        private readonly Func<DistroScope, string, string, OsvScopedQueryResult>? _scoped;

        public FakeOsvSource(
            Func<string, List<OsvAdvisory>> handler, bool reached = true,
            Func<DistroScope, string, string, OsvScopedQueryResult>? scoped = null)
        {
            _handler = handler;
            Reached = reached;
            _scoped = scoped;
        }

        public List<(string Scope, string Name, string Version)> ScopedCalls { get; } = [];

        public List<string> QueryCalls { get; } = [];

        public bool Reached { get; set; }

        public Task<OsvScopedQueryResult> TryQueryDistroPackageAsync(
            DistroScope scope, string name, string version, CancellationToken ct = default)
        {
            ScopedCalls.Add((scope.OsvEcosystem, name, version));
            return Task.FromResult(_scoped?.Invoke(scope, name, version)
                ?? new OsvScopedQueryResult([], Reached: false, Covered: false));
        }

        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
            => Task.FromResult(_handler(purl));

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default)
            => Task.FromResult(purls.Select(_handler).ToList());

        public TaskCompletionSource? Gate { get; set; }

        public async Task<OsvQueryResult> TryQueryAsync(string purl, CancellationToken ct = default)
        {
            QueryCalls.Add(purl);
            if (Gate is not null)
            {
                await Gate.Task;
            }

            return new OsvQueryResult(_handler(purl), Reached);
        }
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
