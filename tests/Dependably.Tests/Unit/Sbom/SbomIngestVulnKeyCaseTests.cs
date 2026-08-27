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
/// Writer parity for the two ingest arms, driven through the real parsers, the real merge service
/// and the real retraction sweeps — the same call sequence the upload endpoints run.
///
/// <para>The security assertion is the VEX arm's manual guard. "An operator's manual triage
/// outranks an uploaded statement" is expressed as the conflict update's WHERE clause, so it only
/// refuses a statement that actually conflicts. An uploaded document citing an advisory in a case
/// the stored row does not use conflicts with nothing, is therefore never refused, and lands a
/// second row beside the manual one — the decision stops being honoured, and no surface says
/// so.</para>
///
/// <para>The sweeps are the other half. Retraction-by-omission clears every upload-sourced row a
/// request did not assert; once the writers resolve onto the stored spelling, a keep-set that
/// matched ordinally would fail to recognise the row the same request had just written and
/// retract it on the spot. Both halves have to move together, which is why they are pinned
/// together here.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomIngestVulnKeyCaseTests : IClassFixture<InMemoryDbFixture>
{
    private const string ComponentPurlKey = "pkg:pypi/requests";

    private readonly InMemoryDbFixture _fixture;
    private readonly SbomMergeService _merge;
    private readonly SbomAnalysisRepository _analysis;

    public SbomIngestVulnKeyCaseTests(InMemoryDbFixture fixture)
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
            { "type": "library", "name": "requests", "version": "2.28.1", "purl": "pkg:pypi/requests@2.28.1" }
          ]
        }
        """;

    private static string VexJson(string advisoryId, string state) => $$"""
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "vulnerabilities": [
            {
              "id": "{{advisoryId}}",
              "affects": [ { "ref": "pkg:pypi/requests@2.28.1" } ],
              "analysis": { "state": "{{state}}" }
            }
          ]
        }
        """;

    private static string SarifJson(string advisoryId, string reachability) => $$"""
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "sbom-reach", "semanticVersion": "0.2.0" } },
              "results": [
                {
                  "ruleId": "{{advisoryId}}",
                  "level": "error",
                  "message": { "text": "requests@2.28.1 is vulnerable to {{advisoryId}}." },
                  "properties": {
                    "purl": "pkg:pypi/requests@2.28.1",
                    "reachability": "{{reachability}}",
                    "confidence": "high"
                  }
                }
              ]
            }
          ]
        }
        """;

    private sealed record SeededVersion(string OrgId, string VersionId);

    private async Task<SeededVersion> SeedVersionAsync(string slug)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"{slug}-{Guid.NewGuid():N}");
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, @name)",
                new { projectId, orgId, name = $"proj-{projectId[..8]}" });
            await conn.ExecuteAsync(
                "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@versionId, @orgId, @projectId, '1.0.0')",
                new { versionId, orgId, projectId });
        }

        using var inventory = JsonDocument.Parse(InventoryJson());
        await _merge.MergeComponentsAsync(
            orgId, versionId, CycloneDxParser.Parse(inventory.RootElement), TestTime.KnownNow);
        return new SeededVersion(orgId, versionId);
    }

    // The VEX upload path in full: apply the document's statements, then sweep everything this
    // request did not assert — the order SbomController runs them in.
    private async Task UploadVexAsync(SeededVersion seeded, string advisoryId, string state)
    {
        using var doc = JsonDocument.Parse(VexJson(advisoryId, state));
        var application = await _merge.ApplyCycloneDxStatementsAsync(
            seeded.OrgId, seeded.VersionId, CycloneDxParser.Parse(doc.RootElement).Statements,
            actorId: null, TestTime.KnownNow);
        await _merge.RetractUnassertedVexAsync(
            seeded.OrgId, seeded.VersionId, application.Asserted, TestTime.KnownNow);
    }

    private async Task UploadSarifAsync(
        SeededVersion seeded,
        string advisoryId,
        string reachability,
        string? actorId = null,
        DateTimeOffset? at = null)
    {
        using var doc = JsonDocument.Parse(SarifJson(advisoryId, reachability));
        var application = await _merge.ApplySarifAsync(
            seeded.OrgId, seeded.VersionId, SarifParser.Parse(doc.RootElement),
            actorId, at ?? TestTime.KnownNow);
        await _merge.RetractUnassertedSarifAsync(
            seeded.OrgId, seeded.VersionId, application, at ?? TestTime.KnownNow);
    }

    private Task<AnalysisVexRow?> TriageAsync(
        SeededVersion seeded, string vulnKey, string state, string? actorId = null) =>
        _analysis.UpsertManualTriageAsync(new ManualTriageWrite(
            seeded.OrgId,
            seeded.VersionId,
            ComponentPurlKey,
            vulnKey,
            Optional<string?>.Of(state),
            Optional<string?>.Absent,
            Optional<string?>.Absent,
            Optional<string?>.Absent,
            actorId));

    /// <summary>Both arms of the rows these tests read, as settable properties so Dapper
    /// materializes them column-by-column rather than through constructor matching.</summary>
    private sealed class StoredRow
    {
        public string VulnKey { get; set; } = "";
        public string? VexState { get; set; }
        public string? VexSource { get; set; }
        public string? Reachability { get; set; }
        public string? Confidence { get; set; }
        public string? UpdatedBy { get; set; }
        public string UpdatedAt { get; set; } = "";
    }

    private async Task<IReadOnlyList<StoredRow>> RowsAsync(SeededVersion seeded)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        var rows = await conn.QueryAsync<StoredRow>(
            """
            SELECT vuln_key AS VulnKey, vex_state AS VexState, vex_source AS VexSource,
                   reachability AS Reachability, confidence AS Confidence,
                   updated_by AS UpdatedBy, updated_at AS UpdatedAt
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId AND purl_key = @purlKey
            ORDER BY vuln_key
            """,
            new { orgId = seeded.OrgId, versionId = seeded.VersionId, purlKey = ComponentPurlKey });
        return rows.ToList();
    }

    // ── the manual guard ──────────────────────────────────────────────────────

    [Fact]
    public async Task VexUpload_CitingAManualDecisionInAnotherCase_IsRefusedByTheManualGuard()
    {
        var seeded = await SeedVersionAsync("ingest-guard");
        await TriageAsync(seeded, "cve-2023-32681", "not_affected");

        await UploadVexAsync(seeded, "CVE-2023-32681", "exploitable");

        var row = Assert.Single(await RowsAsync(seeded));
        Assert.Equal("cve-2023-32681", row.VulnKey);
        Assert.Equal("not_affected", row.VexState);
        Assert.Equal("manual", row.VexSource);
    }

    [Fact]
    public async Task VexUpload_CitingAManualDecisionInMatchingCase_IsStillRefused()
    {
        // Control on the control: the guard's behaviour is unchanged for the spelling that always
        // conflicted, so the case difference is what the test above measures.
        var seeded = await SeedVersionAsync("ingest-guard-same-case");
        await TriageAsync(seeded, "CVE-2023-32681", "not_affected");

        await UploadVexAsync(seeded, "CVE-2023-32681", "exploitable");

        var row = Assert.Single(await RowsAsync(seeded));
        Assert.Equal("not_affected", row.VexState);
        Assert.Equal("manual", row.VexSource);
    }

    [Fact]
    public async Task SarifUpload_CitingAManualDecisionInAnotherCase_AnnotatesTheSameRowAndLeavesTheVexArm()
    {
        // The two arms name disjoint columns, so resolving onto the manual row adds reachability
        // without touching the decision — the SARIF arm has no guard because it needs none.
        var seeded = await SeedVersionAsync("ingest-sarif");
        await TriageAsync(seeded, "cve-2023-32681", "not_affected");

        await UploadSarifAsync(seeded, "CVE-2023-32681", "reachable");

        var row = Assert.Single(await RowsAsync(seeded));
        Assert.Equal("cve-2023-32681", row.VulnKey);
        Assert.Equal("not_affected", row.VexState);
        Assert.Equal("manual", row.VexSource);
        Assert.Equal("reachable", row.Reachability);
        Assert.Equal("high", row.Confidence);
    }

    // ── provenance ───────────────────────────────────────────────────────────

    [Fact]
    public async Task SarifUpload_OnAManualDecision_LeavesItsProvenanceToTheOperator()
    {
        // A SARIF result observes reachability; it does not decide anything. Landing on a row an
        // operator triaged, it must not claim authorship of that decision — the triage editor
        // renders updated_by/updated_at as "set by", so restamping them attributes the operator's
        // call to whoever uploaded the log.
        var seeded = await SeedVersionAsync("ingest-provenance");
        await TriageAsync(seeded, "cve-2023-32681", "not_affected", actorId: "operator-1");

        await UploadSarifAsync(
            seeded, "CVE-2023-32681", "reachable",
            actorId: "sarif-uploader", at: TestTime.KnownNow.AddDays(3));

        var row = Assert.Single(await RowsAsync(seeded));
        Assert.Equal("reachable", row.Reachability);
        Assert.Equal("high", row.Confidence);
        Assert.Equal("not_affected", row.VexState);
        Assert.Equal("manual", row.VexSource);
        Assert.Equal("operator-1", row.UpdatedBy);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), row.UpdatedAt);
    }

    [Fact]
    public async Task SarifUpload_OnAManualDecisionCitedInMatchingCase_LeavesItsProvenanceToo()
    {
        // The provenance rule is about what a SARIF is, not about spelling: the same row reached
        // through a conflict that always fired must be treated identically.
        var seeded = await SeedVersionAsync("ingest-provenance-same-case");
        await TriageAsync(seeded, "CVE-2023-32681", "not_affected", actorId: "operator-2");

        await UploadSarifAsync(
            seeded, "CVE-2023-32681", "reachable",
            actorId: "sarif-uploader", at: TestTime.KnownNow.AddDays(3));

        var row = Assert.Single(await RowsAsync(seeded));
        Assert.Equal("reachable", row.Reachability);
        Assert.Equal("operator-2", row.UpdatedBy);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), row.UpdatedAt);
    }

    [Fact]
    public async Task SarifUpload_OnAnUploadSourcedRow_StillStampsItsOwnProvenance()
    {
        // Adversarial twin: preserving a manual stamp must not freeze provenance generally. A row
        // whose VEX arm came from a document has no human author to protect, so the log that last
        // wrote it is the honest answer.
        var seeded = await SeedVersionAsync("ingest-provenance-upload");
        await UploadVexAsync(seeded, "CVE-2023-32681", "not_affected");

        await UploadSarifAsync(
            seeded, "cve-2023-32681", "reachable",
            actorId: "sarif-uploader", at: TestTime.KnownNow.AddDays(3));

        var row = Assert.Single(await RowsAsync(seeded));
        Assert.Equal("reachable", row.Reachability);
        Assert.Equal("sarif-uploader", row.UpdatedBy);
        Assert.Equal(TestTime.KnownNow.AddDays(3).ToUtcIso(), row.UpdatedAt);
    }

    [Fact]
    public async Task SarifRetraction_OnAManualDecision_ClearsItsArmWithoutRestampingProvenance()
    {
        // The sweep clears SARIF-owned columns on a manual row by design — every column it nulls
        // is the log's, and the VEX arm is untouched. Its updated_at write is not the log's
        // though, and on a manually triaged row it would move the date beside the operator's name.
        var seeded = await SeedVersionAsync("ingest-provenance-sweep");
        await TriageAsync(seeded, "cve-2023-32681", "not_affected", actorId: "operator-3");
        await UploadSarifAsync(seeded, "CVE-2023-32681", "reachable", actorId: "sarif-uploader");

        // The next log reports a different advisory, so the first one's reachability is withdrawn.
        await UploadSarifAsync(
            seeded, "CVE-2024-11111", "reachable",
            actorId: "sarif-uploader", at: TestTime.KnownNow.AddDays(3));

        var rows = await RowsAsync(seeded);
        Assert.Equal(2, rows.Count);
        var triaged = Assert.Single(rows, r => r.VulnKey == "cve-2023-32681");
        Assert.Null(triaged.Reachability);
        Assert.Equal("not_affected", triaged.VexState);
        Assert.Equal("manual", triaged.VexSource);
        Assert.Equal("operator-3", triaged.UpdatedBy);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), triaged.UpdatedAt);
    }

    // ── the sweeps ────────────────────────────────────────────────────────────

    [Fact]
    public async Task VexUpload_CitingAnUploadedRowInAnotherCase_UpdatesItAndTheSweepKeepsIt()
    {
        // The writer resolves onto the stored row, so the sweep has to recognise that row under
        // the document's own spelling — otherwise it retracts what the same request just wrote.
        var seeded = await SeedVersionAsync("ingest-sweep");
        await UploadVexAsync(seeded, "CVE-2023-32681", "not_affected");

        await UploadVexAsync(seeded, "cve-2023-32681", "exploitable");

        var row = Assert.Single(await RowsAsync(seeded));
        Assert.Equal("CVE-2023-32681", row.VulnKey);
        Assert.Equal("exploitable", row.VexState);
        Assert.Equal("upload", row.VexSource);
    }

    [Fact]
    public async Task SarifUpload_CitingAnAnnotatedRowInAnotherCase_UpdatesItAndTheSweepKeepsIt()
    {
        var seeded = await SeedVersionAsync("ingest-sweep-sarif");
        await UploadSarifAsync(seeded, "CVE-2023-32681", "not-observed");

        await UploadSarifAsync(seeded, "cve-2023-32681", "reachable");

        var row = Assert.Single(await RowsAsync(seeded));
        Assert.Equal("CVE-2023-32681", row.VulnKey);
        Assert.Equal("reachable", row.Reachability);
    }

    [Fact]
    public async Task VexUpload_OmittingAPreviouslyAssertedAdvisory_StillRetractsIt()
    {
        // Adversarial twin for the sweep: matching the keep-set case-insensitively must not turn
        // retraction-by-omission into "retract nothing". An advisory this document does not name
        // is still withdrawn.
        var seeded = await SeedVersionAsync("ingest-sweep-omit");
        await UploadVexAsync(seeded, "CVE-2023-32681", "not_affected");

        await UploadVexAsync(seeded, "CVE-2024-11111", "exploitable");

        var row = Assert.Single(await RowsAsync(seeded));
        Assert.Equal("CVE-2024-11111", row.VulnKey);
        Assert.Equal("exploitable", row.VexState);
    }

    [Fact]
    public async Task VexUpload_CitingADifferentAdvisoryThanTheManualDecision_GetsItsOwnRow()
    {
        // Adversarial twin for the writer: folding case must not fold distinct advisories, and
        // the guard must not become a blanket refusal of everything an upload asserts.
        var seeded = await SeedVersionAsync("ingest-distinct");
        await TriageAsync(seeded, "cve-2023-32681", "not_affected");

        await UploadVexAsync(seeded, "CVE-2024-11111", "exploitable");

        var rows = await RowsAsync(seeded);
        Assert.Equal(2, rows.Count);
        Assert.Equal("CVE-2024-11111", rows[0].VulnKey);
        Assert.Equal("exploitable", rows[0].VexState);
        Assert.Equal("upload", rows[0].VexSource);
        Assert.Equal("cve-2023-32681", rows[1].VulnKey);
        Assert.Equal("not_affected", rows[1].VexState);
        Assert.Equal("manual", rows[1].VexSource);
    }
}
