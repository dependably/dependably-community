using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// A manual triage decision is about <i>(product, package, advisory)</i>, not about a version label.
///
/// <para><c>project_vuln_analysis</c> is keyed on the version-less <c>purl_key</c>, so a decision
/// already survives a component bump and an SBOM re-upload within one version row. Nothing carried
/// it across a release, so a team that triaged forty <c>not_affected</c> statements on 2.3.0 saw all
/// forty return as open findings on 2.4.0 and re-fire the violation alert — a re-triage bill charged
/// on every release, which is the fastest way to teach a team to stop triaging.</para>
///
/// <para>The narrowness is the whole design. Only <c>vex_source='manual'</c> rows are inherited: an
/// <c>upload</c> row is an assertion the predecessor's own VEX document made and the SARIF
/// reachability columns are an assertion its SARIF made, and both are re-asserted by the new
/// version's own documents. Inheriting either would defeat retraction-by-omission — a producer that
/// withdraws a statement expects it gone, not answered by an inherited copy.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProjectVersionTriageCarryForwardTests : IAsyncLifetime
{
    private const string OrgId = "o1";
    private const string Triager = "alice";

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@OrgId, 'acme')", new { OrgId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task NewVersion_InheritsManualTriage_ButNotUploadedOrReachabilityRows()
    {
        var repo = Repo();
        var v230 = await ResolveAsync(repo, "billing-api", "2.3.0");

        await SeedAnalysisAsync(v230.ProjectVersionId, "pkg:npm/left-pad", "CVE-2100-2000",
            vexState: "not_affected", vexSource: "manual",
            vexJustification: "code_not_reachable", vexDetail: "the sink is behind a disabled flag");
        await SeedAnalysisAsync(v230.ProjectVersionId, "pkg:npm/minimist", "CVE-2100-2001",
            vexState: "not_affected", vexSource: "upload");
        await SeedAnalysisAsync(v230.ProjectVersionId, "pkg:npm/lodash", "CVE-2100-2002",
            vexState: null, vexSource: null, reachability: "not-observed", confidence: "high");

        var v240 = await ResolveAsync(repo, "billing-api", "2.4.0");

        var carried = await AnalysisAsync(v240.ProjectVersionId);
        var only = Assert.Single(carried);
        Assert.Equal("pkg:npm/left-pad", only.PurlKey);
        Assert.Equal("CVE-2100-2000", only.VulnKey);
        Assert.Equal("not_affected", only.VexState);
        Assert.Equal("manual", only.VexSource);
        Assert.Equal("code_not_reachable", only.VexJustification);
        Assert.Equal("the sink is behind a disabled flag", only.VexDetail);

        // The reachability arm is never inherited, not even onto a row that IS inherited for its
        // VEX half — a fresh version has observed nothing until its own SARIF says so.
        Assert.Null(only.Reachability);
        Assert.Null(only.Confidence);

        // The predecessor keeps everything it had; carrying forward is a copy, not a move.
        Assert.Equal(3, (await AnalysisAsync(v230.ProjectVersionId)).Count);
    }

    /// <summary>
    /// The decision is inherited, not newly made. Stamping the uploader who happened to create the
    /// new version would attribute a judgement to somebody who never made it, and would reset the
    /// age an operator reads to decide whether a triage is still current.
    /// </summary>
    [Fact]
    public async Task InheritedRow_KeepsTheOriginalUpdatedByAndUpdatedAt()
    {
        var repo = Repo();
        var v1 = await ResolveAsync(repo, "provenance", "1.0.0", actorId: "bob");
        string triagedAt = TestTime.KnownNow.AddDays(-30).ToUtcIso();
        await SeedAnalysisAsync(v1.ProjectVersionId, "pkg:npm/left-pad", "CVE-2100-2100",
            vexState: "not_affected", vexSource: "manual", updatedBy: Triager, updatedAt: triagedAt);

        var v2 = await ResolveAsync(repo, "provenance", "2.0.0", actorId: "carol");

        var only = Assert.Single(await AnalysisAsync(v2.ProjectVersionId));
        Assert.Equal(Triager, only.UpdatedBy);
        Assert.Equal(triagedAt, only.UpdatedAt);
    }

    [Fact]
    public async Task FirstVersionOfAProject_InheritsNothing()
    {
        var repo = Repo();
        var first = await ResolveAsync(repo, "brand-new", "0.1.0");
        Assert.Empty(await AnalysisAsync(first.ProjectVersionId));
    }

    /// <summary>
    /// The predecessor is the project's <c>is_latest</c> version, and only falls back to the most
    /// recently created one when no version holds the flag. An operator who promoted an older
    /// release has said that release is the one the project currently ships, so its triage is the
    /// triage a new version inherits.
    ///
    /// <para>Mutant this discriminates: dropping <c>is_latest DESC</c> from the predecessor
    /// ORDER BY, which collapses the rule to "most recently created". The seeding is what makes
    /// that visible — the flag sits on the OLDER row, so the two rules disagree. A project whose
    /// latest is also its newest cannot tell them apart.</para>
    /// </summary>
    [Fact]
    public async Task PredecessorPrefersLatestOverNewest()
    {
        var repo = Repo();
        var older = await ResolveAsync(repo, "promoted-back", "1.0.0");
        var newer = await ResolveAsync(repo, "promoted-back", "2.0.0");

        // Promote the OLDER version back to latest: the flag and the recency now disagree.
        await repo.PromoteLatestAsync(OrgId, await ProjectIdAsync(older.ProjectVersionId), older.ProjectVersionId);

        await SeedAnalysisAsync(older.ProjectVersionId, "pkg:npm/from-latest", "CVE-2100-2300",
            vexState: "not_affected", vexSource: "manual");
        await SeedAnalysisAsync(newer.ProjectVersionId, "pkg:npm/from-newest", "CVE-2100-2301",
            vexState: "not_affected", vexSource: "manual");

        var third = await ResolveAsync(repo, "promoted-back", "3.0.0");

        var only = Assert.Single(await AnalysisAsync(third.ProjectVersionId));
        Assert.Equal("pkg:npm/from-latest", only.PurlKey);
    }

    /// <summary>
    /// A project whose newest version was never promoted still has a predecessor worth inheriting
    /// from: the fallback is the most recently created version, not "nothing".
    /// </summary>
    [Fact]
    public async Task PredecessorIsMostRecentlyCreated_WhenNoVersionIsLatest()
    {
        var repo = Repo();
        var v1 = await ResolveAsync(repo, "unpromoted", "1.0.0");
        var v2 = await ResolveAsync(repo, "unpromoted", "2.0.0");

        // Clear every latest flag, the state a hand-migrated or partially-restored project can be in.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE project_versions SET is_latest = 0");
        }

        await SeedAnalysisAsync(v2.ProjectVersionId, "pkg:npm/newest", "CVE-2100-2200",
            vexState: "not_affected", vexSource: "manual");
        await SeedAnalysisAsync(v1.ProjectVersionId, "pkg:npm/oldest", "CVE-2100-2201",
            vexState: "not_affected", vexSource: "manual");

        _clock.Advance(TimeSpan.FromMinutes(5));
        var v3 = await ResolveAsync(repo, "unpromoted", "3.0.0");

        var only = Assert.Single(await AnalysisAsync(v3.ProjectVersionId));
        Assert.Equal("pkg:npm/newest", only.PurlKey);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ProjectRepository Repo() => new(_db, _clock);

    private async Task<ProjectResolution> ResolveAsync(
        ProjectRepository repo, string projectName, string version, string? actorId = "uploader")
    {
        // Each release advances the frozen clock so created_at ordering is deterministic rather
        // than a tie broken by row id.
        _clock.Advance(TimeSpan.FromHours(1));
        return await repo.ResolveOrCreateAsync(
            OrgId, new ProjectVersionRequest(projectName, version, true, IsLatest: true), actorId, CancellationToken.None);
    }

    private async Task<string> ProjectIdAsync(string projectVersionId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
                   "SELECT project_id FROM project_versions WHERE id = @id", new { id = projectVersionId })
               ?? throw new InvalidOperationException(
                   $"No project_versions row for {projectVersionId}.");
    }

    private sealed record AnalysisRow(
        string PurlKey, string VulnKey, string? VexState, string? VexSource,
        string? VexJustification, string? VexDetail, string? Reachability, string? Confidence,
        string? UpdatedBy, string UpdatedAt);

    private async Task<IReadOnlyList<AnalysisRow>> AnalysisAsync(string projectVersionId)
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.QueryAsync<AnalysisRow>(
            """
            SELECT purl_key AS PurlKey, vuln_key AS VulnKey, vex_state AS VexState,
                   vex_source AS VexSource, vex_justification AS VexJustification,
                   vex_detail AS VexDetail, reachability AS Reachability, confidence AS Confidence,
                   updated_by AS UpdatedBy, updated_at AS UpdatedAt
            FROM project_vuln_analysis
            WHERE org_id = @OrgId AND project_version_id = @projectVersionId
            ORDER BY purl_key
            """,
            new { OrgId, projectVersionId })).AsList();
    }

    private async Task SeedAnalysisAsync(
        string projectVersionId, string purlKey, string vulnKey, string? vexState, string? vexSource,
        string? vexJustification = null, string? vexDetail = null, string? reachability = null,
        string? confidence = null, string? updatedBy = Triager, string? updatedAt = null)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis
                (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_justification,
                 vex_detail, vex_source, reachability, confidence, updated_by, updated_at)
            VALUES
                (@id, @OrgId, @projectVersionId, @purlKey, @vulnKey, @vexState, @vexJustification,
                 @vexDetail, @vexSource, @reachability, @confidence, @updatedBy, @updatedAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                OrgId,
                projectVersionId,
                purlKey,
                vulnKey,
                vexState,
                vexJustification,
                vexDetail,
                vexSource,
                reachability,
                confidence,
                updatedBy,
                updatedAt = updatedAt ?? TestTime.KnownNow.ToUtcIso(),
            });
    }
}
