using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The stored upstream base URL is the string every proxy path appends onto, so its shape decides
/// whether those paths resolve at all — and a NuGet registration path that does not resolve fails
/// invisibly: the handler falls back to local-only data and serves a structurally valid document
/// that simply omits every upstream version. Normalizing at write time is what keeps the one
/// unambiguous operator mistake from becoming a permanent silent fallback.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamRegistryControllerUrlNormalizationTests
{
    private static async Task<string> AddAndReadUrlAsync(string ecosystem, string url)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(
            new AddUpstreamRegistryRequest(Ecosystem: ecosystem, Url: url), CancellationToken.None);
        Assert.IsType<CreatedAtActionResult>(result);

        await using var conn = await b.Db.OpenAsync();
        return await conn.QuerySingleAsync<string>(
            "SELECT url FROM upstream_registry WHERE org_id = @org AND ecosystem = @ecosystem",
            new { org = b.PrimaryOrgId, ecosystem });
    }

    /// <summary>
    /// The reported footgun. NuGet's own UI, its docs, and nuget.config all name the service
    /// INDEX (<c>…/v3/index.json</c>), but the proxy needs the service ROOT — it appends
    /// <c>/registration5-semver1/…</c> and <c>/flatcontainer/…</c>. Stored verbatim, every
    /// registration fetch 404s forever and every response is a local-only fallback.
    /// </summary>
    [Theory]
    [InlineData("https://api.nuget.org/v3/index.json")]
    [InlineData("https://api.nuget.org/v3/index.json/")]
    [InlineData("https://api.nuget.org/v3/INDEX.JSON")]
    [InlineData("https://api.nuget.org/v3/")]
    [InlineData("https://api.nuget.org/v3")]
    public async Task Nuget_ServiceIndexOrTrailingSlash_IsStoredAsTheServiceRoot(string entered)
        => Assert.Equal("https://api.nuget.org/v3", await AddAndReadUrlAsync("nuget", entered));

    /// <summary>
    /// The suffix strip is NuGet-specific. Another ecosystem may legitimately have a path segment
    /// named index.json, so only the trailing slash is normalized there.
    /// </summary>
    [Fact]
    public async Task NonNuget_KeepsAnIndexJsonSuffix_AndLosesOnlyTheTrailingSlash()
    {
        Assert.Equal("https://cache.example/npm", await AddAndReadUrlAsync("npm", "https://cache.example/npm/"));
        Assert.Equal(
            "https://cache.example/npm/index.json",
            await AddAndReadUrlAsync("npm", "https://cache.example/npm/index.json"));
    }

    /// <summary>
    /// Normalization runs before validation and must never manufacture a URL that passes it. A
    /// value that normalizes to nothing is handed to the validator unchanged, so malformed input
    /// is still rejected on its own terms rather than silently accepted as an empty base.
    /// </summary>
    [Fact]
    public async Task AUrlThatWouldNormalizeToNothing_IsStillRejected()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(
            new AddUpstreamRegistryRequest(Ecosystem: "nuget", Url: "/"), CancellationToken.None);

        Assert.IsNotType<CreatedAtActionResult>(result);
    }
}
