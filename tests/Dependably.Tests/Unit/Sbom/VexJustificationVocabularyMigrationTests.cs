using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The boot pass that rewrites stored <c>vex_justification</c> values spelled
/// <c>protected_by_perimeter</c> onto the CycloneDX <c>protected_at_perimeter</c>.
///
/// <para>The rows are seeded by hand, which is the only way to produce them: no writer in the
/// product spells the retired value any more, so driving the triage endpoint would seed a row
/// this pass has nothing to do with. The shape being seeded is what a deployment holds after
/// operators triaged advisories through an editor that offered the wrong spelling.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class VexJustificationVocabularyMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public Task InitializeAsync() => new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>Re-applying the schema is what runs the pass on a real boot.</summary>
    private Task RebootAsync() => new SchemaInitializer(_db).InitializeAsync();

    [Fact]
    public async Task Reboot_RewritesTheRetiredSpellingAndLeavesEveryOtherValueAlone()
    {
        var version = await SeedVersionAsync();
        await SeedRowAsync(version, "CVE-2100-0001", "protected_by_perimeter");
        await SeedRowAsync(version, "CVE-2100-0002", "protected_at_runtime");
        await SeedRowAsync(version, "CVE-2100-0003", "code_not_reachable");
        await SeedRowAsync(version, "CVE-2100-0004", justification: null);

        await RebootAsync();

        Assert.Equal("protected_at_perimeter", await JustificationAsync(version, "CVE-2100-0001"));
        Assert.Equal("protected_at_runtime", await JustificationAsync(version, "CVE-2100-0002"));
        Assert.Equal("code_not_reachable", await JustificationAsync(version, "CVE-2100-0003"));
        Assert.Null(await JustificationAsync(version, "CVE-2100-0004"));
    }

    [Fact]
    public async Task Reboot_LeavesTheRestOfTheRowUntouched()
    {
        var version = await SeedVersionAsync();
        await SeedRowAsync(version, "CVE-2100-0005", "protected_by_perimeter");

        await RebootAsync();

        await using var conn = await _db.OpenAsync();
        var (state, source, detail, updatedAt) =
            await conn.QuerySingleAsync<(string State, string Source, string Detail, string UpdatedAt)>(
            """
            SELECT vex_state AS State, vex_source AS Source, vex_detail AS Detail,
                   updated_at AS UpdatedAt
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId AND vuln_key = @vulnKey
            """,
            new { orgId = version.OrgId, versionId = version.VersionId, vulnKey = "CVE-2100-0005" });

        // The pass records no decision of its own, so it stamps nothing: the operator's name and
        // the moment they decided stay exactly as they were.
        Assert.Equal("not_affected", state);
        Assert.Equal("manual", source);
        Assert.Equal("edge is behind the WAF", detail);
        Assert.Equal(SeededStamp, updatedAt);
    }

    // ── harness ───────────────────────────────────────────────────────────────

    private const string SeededStamp = "2026-01-01T00:00:00Z";

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

    private async Task SeedRowAsync(SeededVersion version, string vulnKey, string? justification)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis (
                id, org_id, project_version_id, purl_key, vuln_key,
                vex_state, vex_justification, vex_detail, vex_source, updated_at)
            VALUES (
                @id, @orgId, @versionId, 'pkg:npm/qs', @vulnKey,
                'not_affected', @justification, 'edge is behind the WAF', 'manual', @updatedAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = version.OrgId,
                versionId = version.VersionId,
                vulnKey,
                justification,
                updatedAt = SeededStamp,
            });
    }

    private async Task<string?> JustificationAsync(SeededVersion version, string vulnKey)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT vex_justification FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId AND vuln_key = @vulnKey
            """,
            new { orgId = version.OrgId, versionId = version.VersionId, vulnKey });
    }
}
