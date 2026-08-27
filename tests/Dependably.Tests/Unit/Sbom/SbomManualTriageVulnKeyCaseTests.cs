using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Writer parity for <c>project_vuln_analysis.vuln_key</c> case: the write-side counterpart of
/// <see cref="SbomVulnKeyParityTests"/>, driven through the real VEX ingest writer and the real
/// manual-triage writer rather than hand-inserted rows.
///
/// <para>Every reader matches <c>vuln_key</c> case-insensitively — the analysis view, the policy
/// resolve and the VDR export, all through <see cref="SbomVulnKeyComparer"/>. The manual-triage
/// upsert's conflict target is a byte-for-byte UNIQUE, so an API client citing
/// <c>cve-2100-0020</c> for the advisory a document recorded as <c>CVE-2100-0020</c> misses the
/// conflict entirely and lands a second row. The result is two analysis rows for one advisory on
/// one component, carrying contradictory states, both of which every case-insensitive reader
/// considers a match — an operator's decision that reads as applied while the row the evaluator
/// resolves still says something else.</para>
///
/// <para>The twins are what keep the rule honest in both directions: a genuinely different
/// advisory, and the same advisory on a different component, each keep their own row, and a GHSA
/// id's conventionally-lowercase suffix survives the write verbatim.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomManualTriageVulnKeyCaseTests : IClassFixture<InMemoryDbFixture>
{
    private const string ComponentPurlKey = "pkg:npm/left-pad";
    private const string OtherComponentPurlKey = "pkg:npm/right-pad";

    private readonly InMemoryDbFixture _fixture;
    private readonly SbomMergeService _merge;
    private readonly SbomAnalysisRepository _analysis;

    public SbomManualTriageVulnKeyCaseTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _merge = new SbomMergeService(new SbomIngestRepository(fixture.Store));
        _analysis = new SbomAnalysisRepository(fixture.Store, TestTime.Frozen());
    }

    // ── fixtures ──────────────────────────────────────────────────────────────

    private static string InventoryJson() => """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "metadata": { "component": { "type": "application", "name": "app", "version": "1.0.0" } },
          "components": [
            { "type": "library", "name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0" },
            { "type": "library", "name": "right-pad", "version": "2.0.0", "purl": "pkg:npm/right-pad@2.0.0" }
          ]
        }
        """;

    private static string VexJson(string advisoryId, string componentPurl) => $$"""
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "vulnerabilities": [
            {
              "id": "{{advisoryId}}",
              "affects": [ { "ref": "{{componentPurl}}" } ],
              "analysis": { "state": "not_affected", "justification": "code_not_reachable" }
            }
          ]
        }
        """;

    private static CycloneDxDocument Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return CycloneDxParser.Parse(doc.RootElement);
    }

    private sealed record SeededVersion(string OrgId, string VersionId);

    private async Task<SeededVersion> SeedVersionWithUploadedVexAsync(
        string slug, string advisoryId, string componentPurl = "pkg:npm/left-pad@1.0.0")
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"{slug}-{Guid.NewGuid():N}");
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        var now = TestTime.KnownNow;

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, @name)",
                new { projectId, orgId, name = $"proj-{projectId[..8]}" });
            await conn.ExecuteAsync(
                "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@versionId, @orgId, @projectId, '1.0.0')",
                new { versionId, orgId, projectId });
        }

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson()), now);
        await _merge.ApplyCycloneDxStatementsAsync(
            orgId, versionId, Parse(VexJson(advisoryId, componentPurl)).Statements, actorId: null, now);

        return new SeededVersion(orgId, versionId);
    }

    private Task<AnalysisVexRow?> TriageAsync(
        SeededVersion seeded, string purlKey, string vulnKey, string state) =>
        _analysis.UpsertManualTriageAsync(new ManualTriageWrite(
            seeded.OrgId,
            seeded.VersionId,
            purlKey,
            vulnKey,
            Optional<string?>.Of(state),
            Optional<string?>.Absent,
            Optional<string?>.Absent,
            Optional<string?>.Absent,
            ActorId: null));

    /// <summary>The three columns these tests read, as settable properties so Dapper materializes
    /// them column-by-column rather than through constructor matching.</summary>
    private sealed class StoredRow
    {
        public string VulnKey { get; set; } = "";
        public string? VexState { get; set; }
        public string? VexSource { get; set; }
    }

    private async Task<IReadOnlyList<StoredRow>> RowsAsync(SeededVersion seeded, string purlKey)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        var rows = await conn.QueryAsync<StoredRow>(
            """
            SELECT vuln_key AS VulnKey, vex_state AS VexState, vex_source AS VexSource
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId AND purl_key = @purlKey
            ORDER BY vuln_key
            """,
            new { orgId = seeded.OrgId, versionId = seeded.VersionId, purlKey });
        return rows.ToList();
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TriageCitingAnUploadedAdvisoryInAnotherCase_UpdatesTheUploadedRow()
    {
        var seeded = await SeedVersionWithUploadedVexAsync("triage-case-a", "CVE-2100-0020");

        // Control: the upload landed exactly one row, under its own spelling, as an upload.
        var uploaded = Assert.Single(await RowsAsync(seeded, ComponentPurlKey));
        Assert.Equal("CVE-2100-0020", uploaded.VulnKey);
        Assert.Equal("upload", uploaded.VexSource);

        var refreshed = await TriageAsync(seeded, ComponentPurlKey, "cve-2100-0020", "exploitable");

        var row = Assert.Single(await RowsAsync(seeded, ComponentPurlKey));
        Assert.Equal("CVE-2100-0020", row.VulnKey);
        Assert.Equal("exploitable", row.VexState);
        Assert.Equal("manual", row.VexSource);

        // The row handed back to the caller is the one that was written, not a second one.
        Assert.NotNull(refreshed);
        Assert.Equal("CVE-2100-0020", refreshed.VulnKey);
        Assert.Equal("manual", refreshed.VexSource);
    }

    [Fact]
    public async Task RepeatedTriageInAThirdCase_KeepsUpdatingTheSameRow()
    {
        var seeded = await SeedVersionWithUploadedVexAsync("triage-case-b", "CVE-2100-0021");

        await TriageAsync(seeded, ComponentPurlKey, "cve-2100-0021", "exploitable");
        await TriageAsync(seeded, ComponentPurlKey, "Cve-2100-0021", "resolved");

        var row = Assert.Single(await RowsAsync(seeded, ComponentPurlKey));
        Assert.Equal("CVE-2100-0021", row.VulnKey);
        Assert.Equal("resolved", row.VexState);
    }

    [Fact]
    public async Task TriageCitingADifferentAdvisory_GetsItsOwnRow()
    {
        // Adversarial twin: the conflict key folds case, it does not collapse distinct advisories.
        var seeded = await SeedVersionWithUploadedVexAsync("triage-case-c", "CVE-2100-0022");

        await TriageAsync(seeded, ComponentPurlKey, "CVE-2100-0023", "exploitable");

        var rows = await RowsAsync(seeded, ComponentPurlKey);
        Assert.Equal(2, rows.Count);
        Assert.Equal("CVE-2100-0022", rows[0].VulnKey);
        Assert.Equal("not_affected", rows[0].VexState);
        Assert.Equal("upload", rows[0].VexSource);
        Assert.Equal("CVE-2100-0023", rows[1].VulnKey);
        Assert.Equal("exploitable", rows[1].VexState);
        Assert.Equal("manual", rows[1].VexSource);
    }

    [Fact]
    public async Task TriageOnAnotherComponent_GetsItsOwnRow()
    {
        // Second adversarial twin: the key is (component, advisory). One advisory triaged on a
        // second component must not be folded onto the first component's row.
        var seeded = await SeedVersionWithUploadedVexAsync("triage-case-d", "CVE-2100-0024");

        await TriageAsync(seeded, OtherComponentPurlKey, "cve-2100-0024", "exploitable");

        var original = Assert.Single(await RowsAsync(seeded, ComponentPurlKey));
        Assert.Equal("upload", original.VexSource);
        Assert.Equal("not_affected", original.VexState);

        var added = Assert.Single(await RowsAsync(seeded, OtherComponentPurlKey));
        Assert.Equal("cve-2100-0024", added.VulnKey);
        Assert.Equal("manual", added.VexSource);
    }

    [Fact]
    public async Task TriageCitingAGhsaIdInAnotherCase_KeepsTheStoredSuffixVerbatim()
    {
        // A GHSA id's alphanumeric suffix is conventionally lowercase, so the stored spelling is
        // the document's own and the triage adopts it rather than folding it to one case.
        var seeded = await SeedVersionWithUploadedVexAsync("triage-case-e", "GHSA-mh6f-8j2x-4483");

        var refreshed = await TriageAsync(
            seeded, ComponentPurlKey, "GHSA-MH6F-8J2X-4483", "exploitable");

        var row = Assert.Single(await RowsAsync(seeded, ComponentPurlKey));
        Assert.Equal("GHSA-mh6f-8j2x-4483", row.VulnKey);
        Assert.Equal("manual", row.VexSource);
        Assert.NotNull(refreshed);
        Assert.Equal("GHSA-mh6f-8j2x-4483", refreshed.VulnKey);
    }

    [Fact]
    public async Task TriageOfAnAdvisoryNoDocumentCovers_StoresTheCallersOwnSpelling()
    {
        // With no row to adopt a spelling from, the caller's id is stored as it was cited — the
        // write side canonicalizes nothing.
        var seeded = await SeedVersionWithUploadedVexAsync("triage-case-f", "CVE-2100-0025");

        await TriageAsync(seeded, ComponentPurlKey, "GHSA-5crp-9r3c-p9vr", "exploitable");

        var rows = await RowsAsync(seeded, ComponentPurlKey);
        Assert.Equal(2, rows.Count);
        Assert.Contains(rows, r => string.Equals(r.VulnKey, "GHSA-5crp-9r3c-p9vr", StringComparison.Ordinal));
    }
}
