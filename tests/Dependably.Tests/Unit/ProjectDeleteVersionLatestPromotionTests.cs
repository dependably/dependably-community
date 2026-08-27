using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Deleting a project's <c>is_latest</c> version must promote the newest survivor.
///
/// <para>A latest-less project holding versions is a broken state, not a cosmetic one: every
/// <c>latest</c> route 404s, the project list renders a null version label, and the rollup counts
/// the project as unevaluated — which degrades its whole ancestor collection chain to
/// "Not scanned". Because the nightly policy sweep is bounded to <c>is_latest</c> rows, such a
/// project also stops being re-evaluated at all, and on an air-gapped instance it has no evaluation
/// path left.</para>
///
/// <para>The rule mirrors the first-version auto-latest invariant on the create path, from one
/// premise: a project that holds versions always has one that <c>latest</c> resolves to.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProjectDeleteVersionLatestPromotionTests : IAsyncLifetime
{
    private const string OrgId = "o1";

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
    public async Task DeletingTheLatestVersion_PromotesTheNewestSurvivor()
    {
        string projectId = await SeedProjectAsync("billing-api");
        string v1 = await SeedVersionAsync(projectId, "1.0.0", ageDays: 40);
        string v2 = await SeedVersionAsync(projectId, "2.0.0", ageDays: 20);
        string v3 = await SeedVersionAsync(projectId, "3.0.0", ageDays: 10, isLatest: true);

        Assert.True(await Repo().DeleteVersionAsync(OrgId, projectId, v3));

        Assert.Equal(v2, await LatestIdAsync(projectId));
        Assert.Equal(1, await LatestCountAsync(projectId));
        Assert.True(await ExistsAsync(v1));
    }

    /// <summary>
    /// A project with nothing left to be latest is correctly latest-less — the promotion must not
    /// invent a row, and the delete must still succeed.
    /// </summary>
    [Fact]
    public async Task DeletingTheLastVersion_LeavesNoLatest()
    {
        string projectId = await SeedProjectAsync("only-child");
        string only = await SeedVersionAsync(projectId, "1.0.0", ageDays: 10, isLatest: true);

        Assert.True(await Repo().DeleteVersionAsync(OrgId, projectId, only));

        Assert.Null(await LatestIdAsync(projectId));
        Assert.Equal(0, await LatestCountAsync(projectId));
    }

    /// <summary>
    /// Adversarial twin: deleting a NON-latest version must not move the flag.
    ///
    /// <para>Mutant this discriminates: dropping the <c>if (wasLatest)</c> condition so the
    /// promotion fires on every delete. The seeding is what makes that visible — the flag sits on
    /// <c>promotedLatest</c>, which is deliberately <b>not</b> the newest survivor, so an
    /// unconditional promotion retargets <c>latest</c> onto <c>newest</c> (or trips
    /// <c>idx_project_versions_latest</c> trying). Seeding the flag on the newest row instead would
    /// make the mutant a no-op and the twin decorative.</para>
    /// </summary>
    [Fact]
    public async Task DeletingANonLatestVersion_LeavesTheLatestFlagWhereItWas()
    {
        string projectId = await SeedProjectAsync("stable");
        string old = await SeedVersionAsync(projectId, "1.0.0", ageDays: 40);
        string promotedLatest = await SeedVersionAsync(projectId, "2.0.0", ageDays: 30, isLatest: true);
        string newest = await SeedVersionAsync(projectId, "3.0.0", ageDays: 10);

        Assert.True(await Repo().DeleteVersionAsync(OrgId, projectId, old));

        Assert.Equal(promotedLatest, await LatestIdAsync(projectId));
        Assert.Equal(1, await LatestCountAsync(projectId));
        Assert.True(await ExistsAsync(newest));
    }

    /// <summary>
    /// A promotion must never reach across projects: deleting one project's latest leaves a sibling
    /// project's versions untouched, flag included.
    /// </summary>
    [Fact]
    public async Task PromotionIsScopedToTheProject()
    {
        string a = await SeedProjectAsync("project-a");
        string aOld = await SeedVersionAsync(a, "1.0.0", ageDays: 40);
        string aLatest = await SeedVersionAsync(a, "2.0.0", ageDays: 10, isLatest: true);

        string b = await SeedProjectAsync("project-b");
        string bOld = await SeedVersionAsync(b, "1.0.0", ageDays: 5);
        string bLatest = await SeedVersionAsync(b, "2.0.0", ageDays: 1, isLatest: true);

        Assert.True(await Repo().DeleteVersionAsync(OrgId, a, aLatest));

        Assert.Equal(aOld, await LatestIdAsync(a));
        Assert.Equal(bLatest, await LatestIdAsync(b));
        Assert.Equal(1, await LatestCountAsync(b));
        Assert.True(await ExistsAsync(bOld));
    }

    /// <summary>
    /// A miss returns false and writes nothing — the rollback path must not leave a promotion
    /// behind, and must not demote the version that is legitimately latest.
    /// </summary>
    [Fact]
    public async Task DeletingAnUnknownVersion_ReturnsFalseAndChangesNothing()
    {
        string projectId = await SeedProjectAsync("untouched");
        string latest = await SeedVersionAsync(projectId, "1.0.0", ageDays: 10, isLatest: true);

        Assert.False(await Repo().DeleteVersionAsync(OrgId, projectId, Guid.NewGuid().ToString("N")));

        Assert.Equal(latest, await LatestIdAsync(projectId));
        Assert.Equal(1, await LatestCountAsync(projectId));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ProjectRepository Repo() => new(_db, _clock);

    private async Task<string> SeedProjectAsync(string name)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@id, @OrgId, @name)",
            new { id, OrgId, name });
        return id;
    }

    private async Task<string> SeedVersionAsync(
        string projectId, string version, int ageDays, bool isLatest = false)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@id, @OrgId, @projectId, @version, @isLatest, @createdAt)
            """,
            new
            {
                id,
                OrgId,
                projectId,
                version,
                isLatest = isLatest ? 1 : 0,
                createdAt = TestTime.KnownNow.AddDays(-ageDays).ToUtcIso(),
            });
        return id;
    }

    private async Task<string?> LatestIdAsync(string projectId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM project_versions WHERE project_id = @projectId AND is_latest = 1",
            new { projectId });
    }

    private async Task<long> LatestCountAsync(string projectId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM project_versions WHERE project_id = @projectId AND is_latest = 1",
            new { projectId });
    }

    private async Task<bool> ExistsAsync(string versionId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM project_versions WHERE id = @id", new { id = versionId }) > 0;
    }
}
