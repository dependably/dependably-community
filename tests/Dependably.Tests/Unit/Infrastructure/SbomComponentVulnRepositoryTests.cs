using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the durable first-observation instant on the projects-plane (component × vuln) link,
/// the twin of <c>VulnerabilityRepositoryTests</c>'s registry-plane coverage. Unlike the
/// registry plane's <c>ON CONFLICT DO NOTHING</c>, <see cref="SbomComponentVulnRepository"/>
/// upserts and genuinely moves <c>checked_at</c> on every re-scan — so the same test must
/// distinguish "checked_at moved" from "first_seen_at did not", not merely assert nothing
/// changed at all.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomComponentVulnRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task LinkComponentVulnAsync_RelinkAsAReScan_LeavesFirstSeenAtUnchanged_ButMovesCheckedAt()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"o-{Guid.NewGuid():N}");
        string componentId = await SeedComponentAsync(orgId, "npm", "left-pad", "1.3.0");
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(_db, $"GHSA-{Guid.NewGuid():N}");

        var clock = TestTime.Frozen();
        var repo = new SbomComponentVulnRepository(_db, clock);

        await repo.LinkComponentVulnAsync(componentId, vulnId);
        string firstSeen = TestTime.KnownNow.ToUtcIso();

        var rescanTime = TestTime.KnownNow.AddHours(3);
        clock.SetUtcNow(rescanTime);
        await repo.LinkComponentVulnAsync(componentId, vulnId); // a re-scan re-linking the same pair

        await using var conn = await _db.OpenAsync();
        var (storedFirstSeen, storedCheckedAt) = await conn.QuerySingleAsync<(string FirstSeenAt, string CheckedAt)>(
            "SELECT first_seen_at AS FirstSeenAt, checked_at AS CheckedAt FROM sbom_component_vulns " +
            "WHERE component_id = @componentId AND vuln_id = @vulnId",
            new { componentId, vulnId });

        Assert.Equal(firstSeen, storedFirstSeen);
        Assert.Equal(rescanTime.ToUtcIso(), storedCheckedAt);
        Assert.NotEqual(storedFirstSeen, storedCheckedAt);
    }

    private async Task<string> SeedComponentAsync(string orgId, string ecosystem, string name, string version)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string projectVersionId = Guid.NewGuid().ToString("N");
        string componentId = Guid.NewGuid().ToString("N");
        string purl = $"pkg:{ecosystem}/{name}@{version}";

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@id, @orgId, @name)",
            new { id = projectId, orgId, name = $"proj-{Guid.NewGuid():N}" });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@id, @orgId, @projectId, '1.0.0')",
            new { id = projectVersionId, orgId, projectId });
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name)
            VALUES
                (@id, @orgId, @projectVersionId, @purl, @ecosystem, @name, @version, @name)
            """,
            new { id = componentId, orgId, projectVersionId, purl, ecosystem, name, version });

        return componentId;
    }
}
