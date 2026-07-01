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
