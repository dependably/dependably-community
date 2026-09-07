using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// GitLab issue #610 — export fidelity: every producer's <c>properties[]</c> carries the
/// exploitation/decision-support/dependency-context signals the platform already stores, plus
/// document-level coverage and freshness metadata, using the single <see cref="DependablyExportProperties"/>
/// namespace.
///
/// <para><b>Fail-closed discipline is the throughline, not a separate concern per property.</b>
/// Every test below either asserts a specific value or asserts a specific, deliberate absence
/// (never a value a consumer could mistake for "verified benign") — the tri-state KEV-ransomware
/// tests and the install-script tests are the sharpest instances of that rule, and
/// <see cref="FailClosedDiscipline"/> collects the cross-cutting assertions a future reviewer can
/// point at as a group.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomExportFidelityTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly Dictionary<string, string?> _instanceSettings = new(StringComparer.Ordinal);
    private readonly InstanceVulnTrackerConfig _tracker;
    private readonly SbomExportService _export;

    public SbomExportFidelityTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _tracker = new InstanceVulnTrackerConfig(
            (key, _) => Task.FromResult(_instanceSettings.GetValueOrDefault(key)), _clock);
        _export = new SbomExportService(_fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), _tracker);
    }

    // InstanceVulnTrackerConfig caches its resolved connection for a short TTL against a frozen
    // clock that never advances in a test, so a mid-test config change needs an explicit
    // Invalidate() — the same call the apex PUT endpoints make after a real save.
    private void EnableTracker()
    {
        _instanceSettings["vuln_tracker_enabled"] = "1";
        _instanceSettings["vuln_tracker_base_url"] = "https://tracker.internal.test";
        _tracker.Invalidate();
    }

    // ── seeding helpers ──────────────────────────────────────────────────────

    private async Task<(string ProjectId, string VersionId)> SeedProjectVersionAsync(
        string orgId, string name, bool isLatest = true, bool isActive = true)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', @name, 'application', @now)
            """,
            new { projectId, orgId, name, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions
                (id, org_id, project_id, version, is_latest, is_active, created_at)
            VALUES (@versionId, @orgId, @projectId, '1.0.0', @isLatest, @isActive, @now)
            """,
            new
            {
                versionId,
                orgId,
                projectId,
                isLatest = isLatest ? 1 : 0,
                isActive = isActive ? 1 : 0,
                now = _clock.GetUtcNow().ToUtcIso(),
            });
        return (projectId, versionId);
    }

    private async Task<string> InsertComponentAsync(
        string orgId, string versionId, string purl, string ecosystem, string purlName, string name,
        string version = "1.0.0", string? dependencyKind = null, string dependencyScope = "unknown",
        DateTimeOffset? vulnCheckedAt = null)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, dependency_kind, dependency_scope, vuln_checked_at, created_at)
            VALUES
                (@id, @orgId, @versionId, @purl, @ecosystem, @purlName, @version, @name,
                 'library', @dependencyKind, @dependencyScope, @vulnCheckedAt, @now)
            """,
            new
            {
                id,
                orgId,
                versionId,
                purl,
                ecosystem,
                purlName,
                version,
                name,
                dependencyKind,
                dependencyScope,
                vulnCheckedAt = vulnCheckedAt?.ToUtcIso(),
                now = _clock.GetUtcNow().ToUtcIso(),
            });
        return id;
    }

    private async Task<string> InsertVulnerabilityAsync(
        string osvId, string ecosystem = "npm", string packageName = "pkg",
        string? severity = "HIGH", double? cvssScore = 7.5, double? nvdScore = null,
        bool isKev = false, bool? isKevRansomware = null, string? kevDueDate = null, string? kevDateAdded = null,
        string? kevRequiredAction = null, string? kevCwes = null, string? kevNotes = null,
        double? epssScore = null, double? epssPercentile = null,
        string? ssvcExploitation = null, string? ssvcAutomatable = null, string? ssvcTechnicalImpact = null,
        string? nvdCheckedAt = null, string? nvdAssertedAt = null,
        string? ssvcCheckedAt = null, string? ssvcAssertedAt = null)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities
                (id, osv_id, ecosystem, package_name, severity, cvss_score, nvd_score,
                 nvd_checked_at, nvd_asserted_at,
                 is_kev, kev_known_ransomware, kev_due_date, kev_date_added,
                 kev_required_action, kev_cwes, kev_notes,
                 epss_score, epss_percentile, ssvc_exploitation, ssvc_automatable, ssvc_technical_impact,
                 ssvc_checked_at, ssvc_asserted_at,
                 modified_at, fetched_at)
            VALUES
                (@id, @osvId, @ecosystem, @packageName, @severity, @cvssScore, @nvdScore,
                 @nvdCheckedAt, @nvdAssertedAt,
                 @isKev, @isKevRansomware, @kevDueDate, @kevDateAdded,
                 @kevRequiredAction, @kevCwes, @kevNotes,
                 @epssScore, @epssPercentile, @ssvcExploitation, @ssvcAutomatable, @ssvcTechnicalImpact,
                 @ssvcCheckedAt, @ssvcAssertedAt,
                 @now, @now)
            """,
            new
            {
                id,
                osvId,
                ecosystem,
                packageName,
                severity,
                cvssScore,
                nvdScore,
                nvdCheckedAt,
                nvdAssertedAt,
                isKev = isKev ? 1 : 0,
                isKevRansomware = isKevRansomware.HasValue ? (isKevRansomware.Value ? 1 : 0) : (int?)null,
                kevDueDate,
                kevDateAdded,
                kevRequiredAction,
                kevCwes,
                kevNotes,
                epssScore,
                epssPercentile,
                ssvcExploitation,
                ssvcAutomatable,
                ssvcTechnicalImpact,
                ssvcCheckedAt,
                ssvcAssertedAt,
                now = _clock.GetUtcNow().ToUtcIso(),
            });
        return id;
    }

    private async Task LinkAsync(string componentId, string vulnId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });
    }

    private async Task InsertHostedInstallScriptAsync(
        string orgId, string ecosystem, string purlName, string version)
    {
        string packageId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, created_at)
            VALUES (@packageId, @orgId, @ecosystem, @purlName, @purlName, @now)
            """,
            new { packageId, orgId, ecosystem, purlName, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, has_install_script, created_at)
            VALUES
                (@versionId, @packageId, @version, @purl, @blobKey, 1, @now)
            """,
            new
            {
                versionId,
                packageId,
                version,
                purl = $"pkg:{ecosystem}/{purlName}@{version}",
                blobKey = $"registry/{ecosystem}/{purlName}/{version}",
                now = _clock.GetUtcNow().ToUtcIso(),
            });
    }

    private static Dictionary<string, string> PropsOf(JsonElement entry) =>
        entry.GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!, StringComparer.Ordinal);

    // ── KEV / ransomware tri-state ───────────────────────────────────────────

    [Fact]
    public async Task KevRansomware_ExplicitTrue_ExportsTrue()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"kevransom-t-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-6001", isKev: true, isKevRansomware: true);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.Equal("true", props[DependablyExportProperties.Kev]);
        Assert.Equal("true", props[DependablyExportProperties.KevRansomware]);
    }

    [Fact]
    public async Task KevRansomware_ExplicitFalse_ExportsFalse_NotUnknown()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"kevransom-f-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-6002", isKev: true, isKevRansomware: false);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.Equal("true", props[DependablyExportProperties.Kev]);
        Assert.Equal("false", props[DependablyExportProperties.KevRansomware]);
    }

    [Fact]
    public async Task KevRansomware_NoAssertion_ExportsUnknown_NeverCollapsedToFalse()
    {
        // KEV-listed but CISA made no ransomware assertion at all — the case the tri-state exists
        // to preserve: null must render as "unknown", never silently fold into "false".
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"kevransom-u-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-6003", isKev: true, isKevRansomware: null);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.Equal("true", props[DependablyExportProperties.Kev]);
        Assert.Equal("unknown", props[DependablyExportProperties.KevRansomware]);
    }

    [Fact]
    public async Task KevRansomware_NotKev_ExportsUnknown()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"kevransom-n-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-6004", isKev: false, isKevRansomware: null);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.Equal("false", props[DependablyExportProperties.Kev]);
        Assert.Equal("unknown", props[DependablyExportProperties.KevRansomware]);
    }

    [Fact]
    public async Task KevDueDateAndDateAdded_AttributedToCisa_OmittedWhenNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"kevdate-{Guid.NewGuid():N}"[..20]);
        var (projectA, versionA) = await SeedProjectVersionAsync(orgId, "with-dates");
        string compA = await InsertComponentAsync(orgId, versionA, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnA = await InsertVulnerabilityAsync(
            "CVE-2100-6010", isKev: true, kevDueDate: "2026-07-01", kevDateAdded: "2026-06-01");
        await LinkAsync(compA, vulnA);

        var withDates = PropsOf(await ExportSingleVulnAsync(orgId, projectA, versionA));
        Assert.Equal("2026-07-01", withDates[DependablyExportProperties.CisaKevDueDate]);
        Assert.Equal("2026-06-01", withDates[DependablyExportProperties.CisaKevDateAdded]);

        var (projectB, versionB) = await SeedProjectVersionAsync(orgId, "no-dates");
        string compB = await InsertComponentAsync(orgId, versionB, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnB = await InsertVulnerabilityAsync("CVE-2100-6011", isKev: false);
        await LinkAsync(compB, vulnB);

        var withoutDates = PropsOf(await ExportSingleVulnAsync(orgId, projectB, versionB));
        Assert.False(withoutDates.ContainsKey(DependablyExportProperties.CisaKevDueDate));
        Assert.False(withoutDates.ContainsKey(DependablyExportProperties.CisaKevDateAdded));
    }

    [Fact]
    public async Task KevRequiredActionCwesNotes_AttributedToCisa_OmittedWhenNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"kevremain-{Guid.NewGuid():N}"[..20]);
        var (projectA, versionA) = await SeedProjectVersionAsync(orgId, "with-fields");
        string compA = await InsertComponentAsync(orgId, versionA, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnA = await InsertVulnerabilityAsync(
            "CVE-2100-6012", isKev: true,
            kevRequiredAction: "Apply the vendor patch.",
            kevCwes: """["CWE-502","CWE-400"]""",
            kevNotes: "https://vendor.example/advisory");
        await LinkAsync(compA, vulnA);

        var withFields = PropsOf(await ExportSingleVulnAsync(orgId, projectA, versionA));
        Assert.Equal("Apply the vendor patch.", withFields[DependablyExportProperties.CisaKevRequiredAction]);
        Assert.Equal("""["CWE-502","CWE-400"]""", withFields[DependablyExportProperties.CisaKevCwes]);
        Assert.Equal("https://vendor.example/advisory", withFields[DependablyExportProperties.CisaKevNotes]);

        var (projectB, versionB) = await SeedProjectVersionAsync(orgId, "no-fields");
        string compB = await InsertComponentAsync(orgId, versionB, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnB = await InsertVulnerabilityAsync("CVE-2100-6013", isKev: false);
        await LinkAsync(compB, vulnB);

        var withoutFields = PropsOf(await ExportSingleVulnAsync(orgId, projectB, versionB));
        Assert.False(withoutFields.ContainsKey(DependablyExportProperties.CisaKevRequiredAction));
        Assert.False(withoutFields.ContainsKey(DependablyExportProperties.CisaKevCwes));
        Assert.False(withoutFields.ContainsKey(DependablyExportProperties.CisaKevNotes));
    }

    // ── Unscored + KEV distinguishing "no CVSS" from "not severe" ────────────

    [Fact]
    public async Task Unscored_Kev_ReadsActAndUnscored_NotBenign()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"unscored-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        // No CVSS from either source, but CISA-KEV-listed.
        string vulnId = await InsertVulnerabilityAsync(
            "CVE-2100-6020", severity: null, cvssScore: null, nvdScore: null, isKev: true);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.False(entry.TryGetProperty("ratings", out _), "no rating should be emitted for an unscored advisory");
        Assert.Equal(EffectivePriority.Act, props[DependablyExportProperties.Priority]);
        Assert.Equal("true", props[DependablyExportProperties.Unscored]);
    }

    // ── SSVC exploitation ─────────────────────────────────────────────────────

    [Theory]
    [InlineData("active", EffectivePriority.Act, "CVE-2100-7001")]
    [InlineData("poc", EffectivePriority.Attend, "CVE-2100-7002")]
    [InlineData("none", EffectivePriority.Track, "CVE-2100-7003")]
    [InlineData(null, EffectivePriority.Track, "CVE-2100-7004")]
    public async Task SsvcExploitation_DrivesPriority_AndAlwaysExportsAValue(
        string? ssvc, string expectedPriority, string osvId)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ssvc-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnId = await InsertVulnerabilityAsync(osvId, cvssScore: 3.0, ssvcExploitation: ssvc);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.Equal(ssvc ?? "unknown", props[DependablyExportProperties.SsvcExploitation]);
        Assert.Equal(expectedPriority, props[DependablyExportProperties.Priority]);
    }

    // ── NVD/SSVC per-signal freshness timestamps ─────────────────────────────

    [Fact]
    public async Task NvdAndSsvcFreshness_BothPresent_ExportsTheAssertedAtPreferredOverCheckedAt()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"fresh-both-{Guid.NewGuid():N}"[..14]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        // asserted_at deliberately differs from checked_at so the test can tell COALESCE(asserted,
        // checked) actually prefers the asserted value rather than coincidentally matching either.
        string checkedAt = _clock.GetUtcNow().ToUtcIso();
        const string assertedAt = "2026-06-10T00:00:00Z";
        string vulnId = await InsertVulnerabilityAsync(
            "CVE-2100-9600", cvssScore: 5.0,
            nvdScore: 6.0, nvdCheckedAt: checkedAt, nvdAssertedAt: assertedAt,
            ssvcExploitation: "none", ssvcCheckedAt: checkedAt, ssvcAssertedAt: assertedAt);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.Equal(assertedAt, props[DependablyExportProperties.NvdCheckedAt]);
        Assert.Equal(assertedAt, props[DependablyExportProperties.SsvcCheckedAt]);
    }

    [Fact]
    public async Task NvdAndSsvcFreshness_BothStale_StillExportTheRawOldTimestamp_NeverSuppressed()
    {
        // "Stale" here is entirely from the reader's perspective: this export surface computes no
        // fresh/stale boolean and owns no staleness horizon — it exports whatever the columns hold,
        // old or not, and lets the consumer compare against its own cutoff.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"stale-both-{Guid.NewGuid():N}"[..14]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        const string longAgo = "2025-01-01T00:00:00Z";
        string vulnId = await InsertVulnerabilityAsync(
            "CVE-2100-9601", cvssScore: 5.0,
            nvdScore: 6.0, nvdCheckedAt: longAgo, nvdAssertedAt: null,
            ssvcExploitation: "none", ssvcCheckedAt: longAgo, ssvcAssertedAt: null);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.Equal(longAgo, props[DependablyExportProperties.NvdCheckedAt]);
        Assert.Equal(longAgo, props[DependablyExportProperties.SsvcCheckedAt]);
    }

    [Fact]
    public async Task NvdFreshness_PresentWithSsvcAbsent_OnlyNvdPropertyExports()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"fresh-one-{Guid.NewGuid():N}"[..14]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string checkedAt = _clock.GetUtcNow().ToUtcIso();
        string vulnId = await InsertVulnerabilityAsync(
            "CVE-2100-9602", cvssScore: 5.0,
            nvdScore: 6.0, nvdCheckedAt: checkedAt, nvdAssertedAt: null,
            ssvcExploitation: null, ssvcCheckedAt: null, ssvcAssertedAt: null);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.Equal(checkedAt, props[DependablyExportProperties.NvdCheckedAt]);
        Assert.False(props.ContainsKey(DependablyExportProperties.SsvcCheckedAt));
    }

    [Fact]
    public async Task NvdAndSsvcFreshness_BothAbsent_BothPropertiesOmitted()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"fresh-none-{Guid.NewGuid():N}"[..14]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-9603", cvssScore: 5.0);
        await LinkAsync(compId, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectId, versionId);
        var props = PropsOf(entry);

        Assert.False(props.ContainsKey(DependablyExportProperties.NvdCheckedAt));
        Assert.False(props.ContainsKey(DependablyExportProperties.SsvcCheckedAt));
    }

    [Fact]
    public async Task ReachableButCurrentlyFailingTracker_StaleTimestampsStillExport_NotMaskedByTrackerConfiguredTrue()
    {
        // The scenario tracker-configured alone cannot answer: the connection has been reachable
        // for months (tracker-configured=true) but has been failing for the last three weeks, so
        // this advisory's own enrichment stamps are old. A consumer trusting tracker-configured
        // alone would misread this as current; the per-signal timestamp is what lets it tell.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"failing-tracker-{Guid.NewGuid():N}"[..10]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "npm", "left-pad", "left-pad");
        const string threeWeeksStale = "2026-05-20T00:00:00Z";
        string vulnId = await InsertVulnerabilityAsync(
            "CVE-2100-9604", cvssScore: 5.0,
            nvdScore: 6.0, nvdCheckedAt: threeWeeksStale, nvdAssertedAt: threeWeeksStale,
            ssvcExploitation: "none", ssvcCheckedAt: threeWeeksStale, ssvcAssertedAt: threeWeeksStale);
        await LinkAsync(compId, vulnId);

        EnableTracker();
        string json = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "vdr", CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        var entry = doc.RootElement.GetProperty("vulnerabilities").EnumerateArray().Single();
        var props = PropsOf(entry);
        var metadataProps = doc.RootElement.GetProperty("metadata").GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!, StringComparer.Ordinal);

        Assert.Equal("true", metadataProps[DependablyExportProperties.TrackerConfigured]);
        // tracker-configured=true does NOT imply fresh: the per-signal timestamp still reads the
        // genuinely old stamp, proving the coarse flag was never used to mask or fabricate freshness.
        Assert.Equal(threeWeeksStale, props[DependablyExportProperties.NvdCheckedAt]);
        Assert.Equal(threeWeeksStale, props[DependablyExportProperties.SsvcCheckedAt]);
    }

    // ── dependency-kind / dependency-scope (component-level) ─────────────────

    [Fact]
    public async Task DependencyKindAndScope_PresentAndAbsent()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"depkind-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(
            orgId, versionId, "pkg:npm/known@1.0.0", "npm", "known", "known",
            dependencyKind: "transitive", dependencyScope: "dev");
        await InsertComponentAsync(
            orgId, versionId, "pkg:npm/unknown@1.0.0", "npm", "unknown-pkg", "unknown-pkg",
            dependencyKind: null, dependencyScope: "unknown");

        string json = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "inventory", CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        var components = doc.RootElement.GetProperty("components").EnumerateArray().ToList();

        var known = components.Single(c => c.GetProperty("name").GetString() == "known");
        var knownProps = PropsOf(known);
        Assert.Equal("transitive", knownProps[DependablyExportProperties.DependencyKind]);
        Assert.Equal("dev", knownProps[DependablyExportProperties.DependencyScope]);

        var unknown = components.Single(c => c.GetProperty("name").GetString() == "unknown-pkg");
        var unknownProps = PropsOf(unknown);
        Assert.False(unknownProps.ContainsKey(DependablyExportProperties.DependencyKind));
        // dependency_scope is NOT NULL DEFAULT 'unknown' in the schema — never actually absent.
        Assert.Equal("unknown", unknownProps[DependablyExportProperties.DependencyScope]);
    }

    // ── install-script: positive-only, never "false" ─────────────────────────

    [Fact]
    public async Task InstallScript_PositiveMatch_ExportsTrue_MissingMatch_IsOmittedEntirely()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"instscript-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "pkg:npm/has-script@1.0.0", "npm", "has-script", "has-script", version: "1.0.0");
        await InsertComponentAsync(orgId, versionId, "pkg:npm/no-registry-hit@1.0.0", "npm", "no-registry-hit", "no-registry-hit", version: "1.0.0");
        await InsertHostedInstallScriptAsync(orgId, "npm", "has-script", "1.0.0");

        string json = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "inventory", CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        var components = doc.RootElement.GetProperty("components").EnumerateArray().ToList();

        var hasScript = components.Single(c => c.GetProperty("name").GetString() == "has-script");
        Assert.Equal("true", PropsOf(hasScript)[DependablyExportProperties.InstallScript]);

        var noHit = components.Single(c => c.GetProperty("name").GetString() == "no-registry-hit");
        bool noHitHasProps = noHit.TryGetProperty("properties", out var noHitProps);
        if (noHitHasProps)
        {
            Assert.DoesNotContain(
                noHitProps.EnumerateArray(),
                p => p.GetProperty("name").GetString() == DependablyExportProperties.InstallScript);
        }
    }

    // ── affected-applications: multi-project, latest-version-scoped ──────────

    [Fact]
    public async Task AffectedApplications_CountsInServiceProjects_ExcludesRetiredSupersededVersions()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"blast-{Guid.NewGuid():N}"[..20]);
        var (projectA, versionA) = await SeedProjectVersionAsync(orgId, "app-a", isLatest: true);
        var (_, versionB) = await SeedProjectVersionAsync(orgId, "app-b", isLatest: true);
        var (_, versionC) = await SeedProjectVersionAsync(
            orgId, "app-c", isLatest: false, isActive: false);
        // A fourth application still running a superseded release. It counts, and the assertion
        // below is what keeps this exported number in step with the dashboard the customer
        // receiving the VEX document can also see.
        var (_, versionD) = await SeedProjectVersionAsync(
            orgId, "app-d", isLatest: false, isActive: true);

        string vulnId = await InsertVulnerabilityAsync("CVE-2100-8001", cvssScore: 5.0);
        string compA = await InsertComponentAsync(orgId, versionA, "pkg:npm/shared@1.0.0", "npm", "shared", "shared");
        string compB = await InsertComponentAsync(orgId, versionB, "pkg:npm/shared@1.0.0", "npm", "shared", "shared");
        string compC = await InsertComponentAsync(orgId, versionC, "pkg:npm/shared@1.0.0", "npm", "shared", "shared");
        string compD = await InsertComponentAsync(orgId, versionD, "pkg:npm/shared@1.0.0", "npm", "shared", "shared");
        await LinkAsync(compA, vulnId);
        await LinkAsync(compB, vulnId);
        await LinkAsync(compC, vulnId);
        await LinkAsync(compD, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectA, versionA);
        var props = PropsOf(entry);

        // app-a and app-b are latest and app-d is a superseded release still marked active;
        // app-c is superseded AND retired, so it is the only one that does not count. The rule is
        // ProjectLifecycle.InServiceFilter, matching SbomBlastRadiusRepository exactly.
        Assert.Equal("3", props[DependablyExportProperties.AffectedApplications]);
    }

    [Fact]
    public async Task AffectedApplications_ZeroIsARealAnswer_AlwaysPresent()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"blast-zero-{Guid.NewGuid():N}"[..16]);
        var (projectA, versionA) = await SeedProjectVersionAsync(
            orgId, "app-a", isLatest: false, isActive: false);
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-8002", cvssScore: 5.0);
        string compA = await InsertComponentAsync(orgId, versionA, "pkg:npm/solo@1.0.0", "npm", "solo", "solo");
        await LinkAsync(compA, vulnId);

        var entry = await ExportSingleVulnAsync(orgId, projectA, versionA);
        var props = PropsOf(entry);

        Assert.Equal("0", props[DependablyExportProperties.AffectedApplications]);
    }

    // ── document-level scan coverage ──────────────────────────────────────────

    [Fact]
    public async Task DocumentCoverage_BucketsScannedUnscannedUnscannable_AndRecordsLastScanAt()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"coverage-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        // Scanned: has a stamp.
        await InsertComponentAsync(
            orgId, versionId, "pkg:npm/scanned@1.0.0", "npm", "scanned", "scanned",
            vulnCheckedAt: _clock.GetUtcNow());
        // Unscanned: scannable ecosystem, no stamp yet.
        await InsertComponentAsync(orgId, versionId, "pkg:npm/pending@1.0.0", "npm", "pending", "pending");
        // Unscannable: OSV publishes no feed for OCI.
        await InsertComponentAsync(orgId, versionId, "pkg:oci/image@1.0.0", "oci", "image", "image");

        string json = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "inventory", CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        var props = doc.RootElement.GetProperty("metadata").GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!, StringComparer.Ordinal);

        Assert.Equal("1", props[DependablyExportProperties.ScannedCount]);
        Assert.Equal("1", props[DependablyExportProperties.UnscannedCount]);
        Assert.Equal("1", props[DependablyExportProperties.UnscannableCount]);
        Assert.Equal(_clock.GetUtcNow().ToUtcIso(), props[DependablyExportProperties.LastScanAt]);
    }

    // ── tracker-configured ────────────────────────────────────────────────────

    [Fact]
    public async Task TrackerConfigured_ReflectsTheInstanceConnection_TrueAndFalse()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"tracker-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");

        string offJson = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "inventory", CancellationToken.None))!;
        using var offDoc = JsonDocument.Parse(offJson);
        var offProps = offDoc.RootElement.GetProperty("metadata").GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!, StringComparer.Ordinal);
        Assert.Equal("false", offProps[DependablyExportProperties.TrackerConfigured]);

        EnableTracker();
        string onJson = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "inventory", CancellationToken.None))!;
        using var onDoc = JsonDocument.Parse(onJson);
        var onProps = onDoc.RootElement.GetProperty("metadata").GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!, StringComparer.Ordinal);
        Assert.Equal("true", onProps[DependablyExportProperties.TrackerConfigured]);
    }

    // ── VEX-standalone parity with the VDR producer ───────────────────────────

    [Fact]
    public async Task VexStandaloneProducer_EmitsTheSamePerVulnerabilityProperties_AsTheVdrProducer()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"parity-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        string purl = "pkg:npm/left-pad@1.0.0";
        string compId = await InsertComponentAsync(
            orgId, versionId, purl, "npm", "left-pad", "left-pad",
            dependencyKind: "transitive", dependencyScope: "dev");
        await InsertHostedInstallScriptAsync(orgId, "npm", "left-pad", "1.0.0");
        string vulnId = await InsertVulnerabilityAsync(
            "CVE-2100-9001", cvssScore: 8.8, isKev: true, isKevRansomware: true,
            kevDueDate: "2026-08-01", epssPercentile: 0.95, ssvcExploitation: "active");
        await LinkAsync(compId, vulnId);

        string? purlKey = SbomPurlKey.ForComponent("npm", "left-pad", purl);
        Assert.NotNull(purlKey);
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO project_vuln_analysis
                    (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_source, updated_at)
                VALUES (@id, @orgId, @versionId, @purlKey, @vulnKey, 'exploitable', 'upload', @now)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    versionId,
                    purlKey,
                    vulnKey = "CVE-2100-9001",
                    now = _clock.GetUtcNow().ToUtcIso(),
                });
        }

        string vdrJson = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "vdr", CancellationToken.None))!;
        using var vdrDoc = JsonDocument.Parse(vdrJson);
        var vdrEntry = vdrDoc.RootElement.GetProperty("vulnerabilities").EnumerateArray().Single();
        var vdrProps = PropsOf(vdrEntry);

        string vexJson = (await _export.BuildVexDocumentAsync(orgId, projectId, versionId, CancellationToken.None))!;
        using var vexDoc = JsonDocument.Parse(vexJson);
        var vexEntry = vexDoc.RootElement.GetProperty("vulnerabilities").EnumerateArray().Single();
        var vexProps = PropsOf(vexEntry);

        Assert.Equal(vdrProps.OrderBy(p => p.Key, StringComparer.Ordinal), vexProps.OrderBy(p => p.Key, StringComparer.Ordinal));
        // Sanity-check the shared computation actually ran, not two empty sets agreeing vacuously.
        Assert.Equal(EffectivePriority.Act, vdrProps[DependablyExportProperties.Priority]);
        Assert.Equal("true", vdrProps[DependablyExportProperties.KevRansomware]);
    }

    // ── Fail-closed discipline, collected ─────────────────────────────────────

    /// <summary>
    /// Cross-cutting fail-closed assertions in one place: nowhere in this surface may an
    /// absent/unconfigured signal render as a value a consumer could mistake for verified-benign.
    /// </summary>
    public sealed class FailClosedDiscipline : IClassFixture<InMemoryDbFixture>
    {
        private readonly InMemoryDbFixture _fixture;
        private readonly FakeTimeProvider _clock = TestTime.Frozen();
        private readonly SbomExportService _export;

        public FailClosedDiscipline(InMemoryDbFixture fixture)
        {
            _fixture = fixture;
            var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
            _export = new SbomExportService(_fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker);
        }

        [Fact]
        public async Task AbsentSsvcAndNvdSignals_NeverRenderAsBenignValues()
        {
            string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"failclosed-{Guid.NewGuid():N}"[..16]);
            string projectId = Guid.NewGuid().ToString("N");
            string versionId = Guid.NewGuid().ToString("N");
            await using (var conn = await _fixture.Store.OpenAsync())
            {
                await conn.ExecuteAsync(
                    """
                    INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
                    VALUES (@projectId, @orgId, 'project', 'app', 'application', @now)
                    """,
                    new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
                await conn.ExecuteAsync(
                    """
                    INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
                    VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
                    """,
                    new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
                string compId = Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    """
                    INSERT INTO sbom_components
                        (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name, component_type, created_at)
                    VALUES (@compId, @orgId, @versionId, 'pkg:npm/left-pad@1.0.0', 'npm', 'left-pad', '1.0.0', 'left-pad', 'library', @now)
                    """,
                    new { compId, orgId, versionId, now = _clock.GetUtcNow().ToUtcIso() });
                string vulnId = Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    """
                    INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, fetched_at)
                    VALUES (@vulnId, 'CVE-2100-9500', 'npm', 'left-pad', 'LOW', 2.0, @now)
                    """,
                    new { vulnId, now = _clock.GetUtcNow().ToUtcIso() });
                await conn.ExecuteAsync(
                    "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @compId, @vulnId)",
                    new { id = Guid.NewGuid().ToString("N"), compId, vulnId });
            }

            string json = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "vdr", CancellationToken.None))!;
            using var doc = JsonDocument.Parse(json);
            var entry = doc.RootElement.GetProperty("vulnerabilities").EnumerateArray().Single();
            var props = entry.GetProperty("properties").EnumerateArray()
                .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!, StringComparer.Ordinal);
            var metadataProps = doc.RootElement.GetProperty("metadata").GetProperty("properties").EnumerateArray()
                .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!, StringComparer.Ordinal);

            // Every genuinely absent SSVC/enrichment signal renders as an explicit "unknown" —
            // never omitted in a way a consumer could read as "checked and clean" — and the
            // document-level flag makes the absence's cause (feature never configured) explicit.
            Assert.Equal("unknown", props[DependablyExportProperties.SsvcExploitation]);
            Assert.Equal("unknown", props[DependablyExportProperties.KevRansomware]);
            Assert.Equal("false", metadataProps[DependablyExportProperties.TrackerConfigured]);
            Assert.False(props.ContainsKey(DependablyExportProperties.NvdScore));
            Assert.False(props.ContainsKey(DependablyExportProperties.SsvcAutomatable));
            Assert.False(props.ContainsKey(DependablyExportProperties.SsvcTechnicalImpact));

            // Priority is still computed and never silently omitted — "no signal" is not "no
            // opinion"; it is a Track-bucket, non-suppressed verdict a consumer can act on.
            Assert.True(props.ContainsKey(DependablyExportProperties.Priority));
            Assert.NotEqual(EffectivePriority.Suppressed, props[DependablyExportProperties.Priority]);
        }

        [Fact]
        public async Task InstallScriptMiss_IsOmitted_NeverAssertedFalse()
        {
            string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"failclosed-inst-{Guid.NewGuid():N}"[..10]);
            string projectId = Guid.NewGuid().ToString("N");
            string versionId = Guid.NewGuid().ToString("N");
            await using var conn = await _fixture.Store.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
                VALUES (@projectId, @orgId, 'project', 'app', 'application', @now)
                """,
                new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
                VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
                """,
                new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
            string compId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name, component_type, created_at)
                VALUES (@compId, @orgId, @versionId, 'pkg:npm/never-published@1.0.0', 'npm', 'never-published', '1.0.0', 'never-published', 'library', @now)
                """,
                new { compId, orgId, versionId, now = _clock.GetUtcNow().ToUtcIso() });

            string json = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "inventory", CancellationToken.None))!;
            using var doc = JsonDocument.Parse(json);
            var component = doc.RootElement.GetProperty("components").EnumerateArray().Single();

            if (component.TryGetProperty("properties", out var props))
            {
                Assert.DoesNotContain(
                    props.EnumerateArray(),
                    p => p.GetProperty("name").GetString() == DependablyExportProperties.InstallScript);
            }
        }
    }

    // ── shared helper ──────────────────────────────────────────────────────────

    private async Task<JsonElement> ExportSingleVulnAsync(string orgId, string projectId, string versionId)
    {
        string json = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, "vdr", CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("vulnerabilities").EnumerateArray().Single().Clone();
    }
}
