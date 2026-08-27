using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The boot-time reconciliation that collapses case-variant duplicate <c>project_vuln_analysis</c>
/// rows onto one row per advisory, losing no arm.
///
/// <para>The rows are inserted by hand here, which is correct and deliberate rather than a shortcut
/// to be "fixed" later: the three production writers all resolve their conflict key
/// case-insensitively, so none of them can produce the state this pass exists to repair. Driving
/// the ingest path would seed a single row and assert nothing. The shape being seeded is what a
/// deployment holds after triaging advisories through the writers that did not fold case.</para>
///
/// <para>Each case asserts the merged row's facts column by column, not just its count — the whole
/// hazard is a collapse that keeps one row and silently drops the arm the other one carried.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomAnalysisCaseVariantReconciliationTests : IAsyncLifetime
{
    private const string Purl = "pkg:pypi/requests";
    private const string OtherPurl = "pkg:npm/lodash";

    private readonly TestMetadataStore _db = new();

    public Task InitializeAsync() => new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── harness ───────────────────────────────────────────────────────────────

    /// <summary>Re-applies the schema, which is what runs the reconciliation on a real boot.</summary>
    private Task RebootAsync() => new SchemaInitializer(_db).InitializeAsync();

    private sealed record SeededVersion(string OrgId, string VersionId);

    private async Task<SeededVersion> SeedVersionAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"o-{Guid.NewGuid():N}");
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, @name)",
            new { projectId, orgId, name = $"proj-{projectId[..8]}" });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@versionId, @orgId, @projectId, '1.0.0')",
            new { versionId, orgId, projectId });
        return new SeededVersion(orgId, versionId);
    }

    private async Task SeedRowAsync(
        SeededVersion version,
        string vulnKey,
        string purlKey = Purl,
        string? vexState = null,
        string? vexJustification = null,
        string? vexResponse = null,
        string? vexDetail = null,
        string? vexSource = null,
        string? reachability = null,
        string? confidence = null,
        int sarifSuppressed = 0,
        double? securitySeverity = null,
        string? severityOrigin = null,
        string? fingerprint = null,
        string? updatedBy = null,
        string updatedAt = "2026-01-01T00:00:00Z")
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis (
                id, org_id, project_version_id, purl_key, vuln_key,
                vex_state, vex_justification, vex_response, vex_detail, vex_source,
                reachability, confidence, sarif_suppressed, security_severity,
                severity_origin, fingerprint, updated_by, updated_at)
            VALUES (
                @id, @orgId, @versionId, @purlKey, @vulnKey,
                @vexState, @vexJustification, @vexResponse, @vexDetail, @vexSource,
                @reachability, @confidence, @sarifSuppressed, @securitySeverity,
                @severityOrigin, @fingerprint, @updatedBy, @updatedAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = version.OrgId,
                versionId = version.VersionId,
                purlKey,
                vulnKey,
                vexState,
                vexJustification,
                vexResponse,
                vexDetail,
                vexSource,
                reachability,
                confidence,
                sarifSuppressed,
                securitySeverity,
                severityOrigin,
                fingerprint,
                updatedBy,
                updatedAt,
            });
    }

    private sealed class StoredRow
    {
        public string PurlKey { get; set; } = "";
        public string VulnKey { get; set; } = "";
        public string? VexState { get; set; }
        public string? VexJustification { get; set; }
        public string? VexResponse { get; set; }
        public string? VexDetail { get; set; }
        public string? VexSource { get; set; }
        public string? Reachability { get; set; }
        public string? Confidence { get; set; }
        public int SarifSuppressed { get; set; }
        public double? SecuritySeverity { get; set; }
        public string? SeverityOrigin { get; set; }
        public string? Fingerprint { get; set; }
        public string? UpdatedBy { get; set; }
        public string UpdatedAt { get; set; } = "";
    }

    private async Task<List<StoredRow>> ReadRowsAsync(SeededVersion version)
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<StoredRow>(
            """
            SELECT purl_key          AS PurlKey,
                   vuln_key          AS VulnKey,
                   vex_state         AS VexState,
                   vex_justification AS VexJustification,
                   vex_response      AS VexResponse,
                   vex_detail        AS VexDetail,
                   vex_source        AS VexSource,
                   reachability      AS Reachability,
                   confidence        AS Confidence,
                   sarif_suppressed  AS SarifSuppressed,
                   security_severity AS SecuritySeverity,
                   severity_origin   AS SeverityOrigin,
                   fingerprint       AS Fingerprint,
                   updated_by        AS UpdatedBy,
                   updated_at        AS UpdatedAt
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId
            ORDER BY purl_key, vuln_key
            """,
            new { orgId = version.OrgId, versionId = version.VersionId });
        return rows.ToList();
    }

    /// <summary>
    /// The spelling every reader already resolves this advisory to, read the way
    /// <c>GetAnalysisRowAsync</c> reads it. The reconciliation must keep exactly this value, so the
    /// merge never changes which id an operator sees.
    /// </summary>
    private async Task<string> ResolvedSpellingAsync(SeededVersion version, string vulnKey, string purlKey = Purl)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            """
            SELECT vuln_key FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId
              AND purl_key = @purlKey AND UPPER(vuln_key) = UPPER(@vulnKey)
            ORDER BY vuln_key
            LIMIT 1
            """,
            new { orgId = version.OrgId, versionId = version.VersionId, purlKey, vulnKey }) ?? "";
    }

    // ── the three shapes the merge rule has to answer for ─────────────────────

    /// <summary>
    /// Both rows carry the VEX arm with different values. The later statement is the one the last
    /// document asserted, so it survives, together with its author — and the stored advisory-id
    /// spelling does not move.
    /// </summary>
    [Fact]
    public async Task SameArmOnBothRows_KeepsTheLatestStatementAndTheStoredSpelling()
    {
        var version = await SeedVersionAsync();
        await SeedRowAsync(
            version, "CVE-2023-1234", vexState: "exploitable", vexDetail: "reported by doc-a",
            vexSource: "upload", updatedBy: "doc-a", updatedAt: "2026-01-01T00:00:00Z");
        await SeedRowAsync(
            version, "cve-2023-1234", vexState: "not_affected", vexJustification: "code_not_reachable",
            vexDetail: "reported by doc-b", vexSource: "upload", updatedBy: "doc-b",
            updatedAt: "2026-02-01T00:00:00Z");

        string expectedSpelling = await ResolvedSpellingAsync(version, "cve-2023-1234");
        await RebootAsync();

        var row = Assert.Single(await ReadRowsAsync(version));
        Assert.Equal(expectedSpelling, row.VulnKey);
        Assert.Equal("not_affected", row.VexState);
        Assert.Equal("code_not_reachable", row.VexJustification);
        Assert.Equal("reported by doc-b", row.VexDetail);
        Assert.Equal("upload", row.VexSource);
        Assert.Equal("doc-b", row.UpdatedBy);
        Assert.Equal("2026-02-01T00:00:00Z", row.UpdatedAt);
    }

    /// <summary>
    /// The split-arm shape the naive collapse loses: one row holds the VEX statement, the other
    /// holds the reachability match. Both have to end up on the survivor.
    /// </summary>
    [Fact]
    public async Task EachRowCarryingADifferentArm_MergesBothOntoOneRow()
    {
        var version = await SeedVersionAsync();
        await SeedRowAsync(
            version, "GHSA-MH6F-8J2X-4483", vexState: "not_affected",
            vexJustification: "vulnerable_code_not_in_execute_path", vexResponse: "will_not_fix",
            vexDetail: "not on the request path", vexSource: "upload",
            updatedBy: "vex-doc", updatedAt: "2026-01-01T00:00:00Z");
        await SeedRowAsync(
            version, "GHSA-mh6f-8j2x-4483", reachability: "reachable", confidence: "high",
            sarifSuppressed: 1, securitySeverity: 7.5, severityOrigin: "asserted",
            fingerprint: "fp-9f2c", updatedBy: "sarif-doc", updatedAt: "2026-03-01T00:00:00Z");

        await RebootAsync();

        var row = Assert.Single(await ReadRowsAsync(version));
        Assert.Equal("not_affected", row.VexState);
        Assert.Equal("vulnerable_code_not_in_execute_path", row.VexJustification);
        Assert.Equal("will_not_fix", row.VexResponse);
        Assert.Equal("not on the request path", row.VexDetail);
        Assert.Equal("upload", row.VexSource);
        Assert.Equal("reachable", row.Reachability);
        Assert.Equal("high", row.Confidence);
        Assert.Equal(1, row.SarifSuppressed);
        Assert.Equal(7.5, row.SecuritySeverity);
        Assert.Equal("asserted", row.SeverityOrigin);
        Assert.Equal("fp-9f2c", row.Fingerprint);

        // Neither arm is manual, so the stamp names the last document to write either of them.
        Assert.Equal("sarif-doc", row.UpdatedBy);
        Assert.Equal("2026-03-01T00:00:00Z", row.UpdatedAt);
    }

    /// <summary>
    /// The decision that must never be discarded: the manual triage sits on the row the ordering
    /// would otherwise drop, and the survivor carries an upload-sourced statement that is also
    /// newer. Manual outranks it anyway, and keeps the operator's own name and date.
    /// </summary>
    [Fact]
    public async Task ManualTriageOnTheLosingRow_OutranksTheUploadedStatementOnTheSurvivor()
    {
        var version = await SeedVersionAsync();
        await SeedRowAsync(
            version, "CVE-2023-32681", vexState: "exploitable", vexDetail: "asserted by a scanner",
            vexSource: "upload", updatedBy: "vex-doc", updatedAt: "2026-05-01T00:00:00Z");
        await SeedRowAsync(
            version, "cve-2023-32681", vexState: "not_affected",
            vexJustification: "code_not_present", vexDetail: "we do not ship the proxy helper",
            vexSource: "manual", updatedBy: "operator-1", updatedAt: "2026-02-01T00:00:00Z");

        await RebootAsync();

        var row = Assert.Single(await ReadRowsAsync(version));
        Assert.Equal("not_affected", row.VexState);
        Assert.Equal("code_not_present", row.VexJustification);
        Assert.Equal("we do not ship the proxy helper", row.VexDetail);
        Assert.Equal("manual", row.VexSource);
        Assert.Equal("operator-1", row.UpdatedBy);
        Assert.Equal("2026-02-01T00:00:00Z", row.UpdatedAt);
    }

    /// <summary>
    /// Three spellings of one advisory, each carrying something different: an upload statement, the
    /// operator's decision, and a reachability match. One row survives holding the decision and the
    /// reachability facts, stamped by the human.
    /// </summary>
    [Fact]
    public async Task ThreeWayDuplicate_CollapsesToOneRowHoldingTheDecisionAndTheReachability()
    {
        var version = await SeedVersionAsync();
        await SeedRowAsync(
            version, "CVE-2024-0001", vexState: "in_triage", vexSource: "upload",
            updatedBy: "vex-doc", updatedAt: "2026-01-01T00:00:00Z");
        await SeedRowAsync(
            version, "CVE-2024-0001".ToLowerInvariant(), vexState: "resolved",
            vexJustification: "component_not_present", vexSource: "manual",
            updatedBy: "operator-2", updatedAt: "2026-02-01T00:00:00Z");
        await SeedRowAsync(
            version, "cVe-2024-0001", reachability: "not-observed", confidence: "medium",
            securitySeverity: 4.2, severityOrigin: "representative", fingerprint: "fp-1a2b",
            updatedBy: "sarif-doc", updatedAt: "2026-04-01T00:00:00Z");

        await RebootAsync();

        var row = Assert.Single(await ReadRowsAsync(version));
        Assert.Equal("resolved", row.VexState);
        Assert.Equal("component_not_present", row.VexJustification);
        Assert.Equal("manual", row.VexSource);
        Assert.Equal("not-observed", row.Reachability);
        Assert.Equal("medium", row.Confidence);
        Assert.Equal(4.2, row.SecuritySeverity);
        Assert.Equal("representative", row.SeverityOrigin);
        Assert.Equal("fp-1a2b", row.Fingerprint);
        Assert.Equal("operator-2", row.UpdatedBy);
        Assert.Equal("2026-02-01T00:00:00Z", row.UpdatedAt);
    }

    // ── the adversarial half ──────────────────────────────────────────────────

    /// <summary>
    /// The twin of every case above: advisories that merely resemble each other are never merged.
    /// Two distinct CVEs, a GHSA and a CVE, and the same advisory recorded against a different
    /// component all stay as separate rows — mixed into one version with a real duplicate pair, so
    /// the pass has to separate them in a single run rather than by refusing to act.
    /// </summary>
    [Fact]
    public async Task DifferentAdvisoriesAndDifferentComponents_AreNeverMerged()
    {
        var version = await SeedVersionAsync();
        await SeedRowAsync(version, "CVE-2023-1234", vexState: "exploitable", vexSource: "upload");
        await SeedRowAsync(version, "CVE-2023-9999", vexState: "not_affected", vexSource: "upload");
        await SeedRowAsync(version, "GHSA-mh6f-8j2x-4483", vexState: "in_triage", vexSource: "upload");

        // A genuine duplicate pair on a second component, so the run does real work.
        await SeedRowAsync(
            version, "CVE-2023-1234", purlKey: OtherPurl, vexState: "exploitable",
            vexSource: "upload", updatedBy: "doc-a", updatedAt: "2026-01-01T00:00:00Z");
        await SeedRowAsync(
            version, "cve-2023-1234", purlKey: OtherPurl, reachability: "reachable",
            confidence: "low", updatedBy: "doc-b", updatedAt: "2026-02-01T00:00:00Z");

        await RebootAsync();

        var rows = await ReadRowsAsync(version);
        Assert.Equal(4, rows.Count);

        var onRequests = rows.Where(r => r.PurlKey == Purl).ToList();
        Assert.Equal(3, onRequests.Count);
        Assert.Equal(
            new[] { "CVE-2023-1234", "CVE-2023-9999", "GHSA-mh6f-8j2x-4483" },
            onRequests.Select(r => r.VulnKey).OrderBy(k => k, StringComparer.Ordinal).ToArray());

        // The same advisory id on a different component is a different row and stays one — while
        // the case-variant pair that WAS one advisory collapsed, carrying both arms.
        var onLodash = Assert.Single(rows, r => r.PurlKey == OtherPurl);
        Assert.Equal("exploitable", onLodash.VexState);
        Assert.Equal("reachable", onLodash.Reachability);
        Assert.Equal("low", onLodash.Confidence);
    }

    /// <summary>
    /// A database with no duplicates is left byte-for-byte alone — no restamping, no reordering, no
    /// spelling rewritten to one case — and a second run over already-reconciled data changes
    /// nothing either.
    /// </summary>
    [Fact]
    public async Task ADatabaseWithNoDuplicates_IsUntouched_AndASecondRunIsANoOp()
    {
        var version = await SeedVersionAsync();
        await SeedRowAsync(
            version, "GHSA-mh6f-8j2x-4483", vexState: "not_affected",
            vexJustification: "code_not_present", vexSource: "manual", reachability: "unknown",
            updatedBy: "operator-3", updatedAt: "2026-01-01T00:00:00Z");
        await SeedRowAsync(
            version, "CVE-2023-1234", vexState: "exploitable", vexSource: "upload",
            updatedBy: "vex-doc", updatedAt: "2026-01-02T00:00:00Z");

        var before = await ReadRowsAsync(version);
        await RebootAsync();
        var afterFirst = await ReadRowsAsync(version);
        Assert.Equivalent(before, afterFirst, strict: true);

        // Now the idempotency claim, over data the pass has already reconciled.
        var dupes = await SeedVersionAsync();
        await SeedRowAsync(
            dupes, "CVE-2025-4242", vexState: "exploitable", vexSource: "upload",
            updatedBy: "doc-a", updatedAt: "2026-01-01T00:00:00Z");
        await SeedRowAsync(
            dupes, "cve-2025-4242", reachability: "reachable", confidence: "high",
            updatedBy: "doc-b", updatedAt: "2026-02-01T00:00:00Z");

        await RebootAsync();
        var reconciled = await ReadRowsAsync(dupes);
        Assert.Single(reconciled);

        await RebootAsync();
        Assert.Equivalent(reconciled, await ReadRowsAsync(dupes), strict: true);
        Assert.Equivalent(afterFirst, await ReadRowsAsync(version), strict: true);
    }
}
