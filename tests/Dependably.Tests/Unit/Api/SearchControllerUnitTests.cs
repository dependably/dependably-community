using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Covers the global-search endpoint (GET /api/v1/search): the grouped response shape the
/// top-bar overlay consumes, name-matching, and the short-query short-circuit.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SearchControllerUnitTests
{
    private static readonly System.Text.Json.JsonSerializerOptions WebJsonOptions = new(System.Text.Json.JsonSerializerDefaults.Web);

    [Fact]
    public async Task Search_Member_MatchingQuery_ReturnsPackagesGroup()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("acme-utils");
        await s.WithPackageAsync("other-lib");
        var b = await s.BuildAsync();

        var result = await b.SearchController.Search("acme", limit: 8, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);

        using var doc = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions));
        var root = doc.RootElement;
        Assert.Equal("acme", root.GetProperty("query").GetString());

        var groups = root.GetProperty("groups");
        Assert.Equal(1, groups.GetArrayLength());
        var g0 = groups[0];
        Assert.Equal("packages", g0.GetProperty("kind").GetString());

        var results = g0.GetProperty("results");
        Assert.True(results.GetArrayLength() >= 1);

        bool hasMatch = false, hasNonMatch = false;
        foreach (var r in results.EnumerateArray())
        {
            string? name = r.GetProperty("name").GetString();
            if (name == "acme-utils")
            {
                hasMatch = true;
            }
            if (name == "other-lib")
            {
                hasNonMatch = true;
            }
        }
        Assert.True(hasMatch);
        Assert.False(hasNonMatch);

        // Each result carries the fields the frontend deep-links with.
        Assert.True(results[0].TryGetProperty("ecosystem", out _));
        Assert.True(results[0].TryGetProperty("purlName", out _));
    }

    [Fact]
    public async Task Search_Member_MatchingProjectName_ReturnsProjectsGroup()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        await SeedProjectAsync(b.Db, b.PrimaryOrgId, "acme-frontend");
        await SeedProjectAsync(b.Db, b.PrimaryOrgId, "other-service");

        var result = await b.SearchController.Search("acme", limit: 8, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);

        using var doc = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions));
        var groups = doc.RootElement.GetProperty("groups");

        var projectsGroup = groups.EnumerateArray()
            .FirstOrDefault(g => g.GetProperty("kind").GetString() == "projects");
        Assert.True(projectsGroup.ValueKind != System.Text.Json.JsonValueKind.Undefined,
            "expected a 'projects' group in the response");

        var results = projectsGroup.GetProperty("results");
        bool hasMatch = false, hasNonMatch = false;
        foreach (var r in results.EnumerateArray())
        {
            string? name = r.GetProperty("name").GetString();
            if (name == "acme-frontend") { hasMatch = true; }
            if (name == "other-service") { hasNonMatch = true; }
        }
        Assert.True(hasMatch);
        Assert.False(hasNonMatch);

        // Each result carries the id the frontend deep-links into project-detail with.
        Assert.True(results[0].TryGetProperty("id", out _));
    }

    [Fact]
    public async Task Search_Member_NoMatchingProject_OmitsProjectsGroup()
    {
        // Adversarial twin of the test above: a query matching no project name must not add an
        // empty 'projects' group — a mutant that always appended the group regardless of hit
        // count would pass the positive test but fail this one.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("acme-utils");
        var b = await s.BuildAsync();

        await SeedProjectAsync(b.Db, b.PrimaryOrgId, "unrelated-project");

        var result = await b.SearchController.Search("acme", limit: 8, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);

        using var doc = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions));
        var groups = doc.RootElement.GetProperty("groups");

        foreach (var g in groups.EnumerateArray())
        {
            Assert.NotEqual("projects", g.GetProperty("kind").GetString());
        }
    }

    private static async Task SeedProjectAsync(Dependably.Infrastructure.IMetadataStore db, string orgId, string name)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@id, @orgId, @name)",
            new { id = Guid.NewGuid().ToString("N"), orgId, name });
    }

    [Fact]
    public async Task Search_Member_MatchingOsvId_ReturnsVulnerabilitiesGroup()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("acme-utils");
        await s.WithPackageVersionAsync("acme-utils", "1.0.0");
        var b = await s.BuildAsync();

        string target = $"GHSA-target-{Guid.NewGuid():N}";
        await SeedAndLinkVulnAsync(b.Db, b.PrimaryOrgId, "acme-utils", "1.0.0", target);

        var result = await b.SearchController.Search(target, limit: 8, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);

        using var doc = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions));
        var groups = doc.RootElement.GetProperty("groups");

        var vulnGroup = groups.EnumerateArray()
            .FirstOrDefault(g => g.GetProperty("kind").GetString() == "vulnerabilities");
        Assert.True(vulnGroup.ValueKind != System.Text.Json.JsonValueKind.Undefined,
            "expected a 'vulnerabilities' group in the response");

        var results = vulnGroup.GetProperty("results");
        Assert.Equal(1, results.GetArrayLength());
        Assert.Equal(target, results[0].GetProperty("osvId").GetString());
    }

    [Fact]
    public async Task Search_Member_NoMatchingVuln_OmitsVulnerabilitiesGroup()
    {
        // Adversarial twin of the test above: a query matching no advisory must not add an
        // empty 'vulnerabilities' group.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("acme-utils");
        var b = await s.BuildAsync();

        var result = await b.SearchController.Search("acme", limit: 8, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);

        using var doc = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions));
        var groups = doc.RootElement.GetProperty("groups");

        foreach (var g in groups.EnumerateArray())
        {
            Assert.NotEqual("vulnerabilities", g.GetProperty("kind").GetString());
        }
    }

    private static async Task SeedAndLinkVulnAsync(
        Dependably.Infrastructure.IMetadataStore db, string orgId, string packageName, string version, string osvId)
    {
        string vulnId = await Dependably.Tests.Infrastructure.Seeding.VulnerabilitySeeder.InsertVulnAsync(db, osvId, packageName: packageName);
        await using var conn = await db.OpenAsync();
        string? versionId = await conn.QuerySingleAsync<string>(
            """
            SELECT pv.id FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.name = @packageName AND pv.version = @version
            """,
            new { orgId, packageName, version });
        await Dependably.Tests.Infrastructure.Seeding.VulnerabilitySeeder.LinkAsync(db, versionId!, vulnId);
    }

    [Fact]
    public async Task Search_ShortQuery_ReturnsEmptyGroups()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("acme-utils");
        var b = await s.BuildAsync();

        var result = await b.SearchController.Search("a", limit: 8, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);

        using var doc = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions));
        Assert.Equal(0, doc.RootElement.GetProperty("groups").GetArrayLength());
    }
}
