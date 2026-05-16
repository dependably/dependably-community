using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Api;
using Dependably.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Tests for <see cref="NuGetController.MergeLocalIntoUpstreamRegistration"/>. The bug this
/// guards against: a privately uploaded prerelease (e.g. Newtonsoft.Json 13.0.5-beta1)
/// previously caused the registration index to drop every upstream version, so downstream
/// packages pinning ">= 13.0.3" stable failed NU1103. The merge must surface both lines.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetRegistrationMergeTests
{
    private static string MinimalUpstream(string id, params string[] versions)
    {
        var entries = new JsonArray();
        foreach (var v in versions)
        {
            entries.Add(new JsonObject
            {
                ["@id"] = $"https://api.nuget.org/v3/registration5-semver1/{id}/{v}.json",
                ["@type"] = "Package",
                ["catalogEntry"] = new JsonObject
                {
                    ["id"] = id,
                    ["version"] = v,
                    ["listed"] = true,
                    ["packageContent"] = $"https://api.nuget.org/v3-flatcontainer/{id}/{v}/{id}.{v}.nupkg"
                }
            });
        }
        var root = new JsonObject
        {
            ["@id"] = $"https://api.nuget.org/v3/registration5-semver1/{id}/index.json",
            ["@type"] = new JsonArray("catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"),
            ["count"] = 1,
            ["items"] = new JsonArray(new JsonObject
            {
                ["@id"] = $"https://api.nuget.org/v3/registration5-semver1/{id}/index.json#page/upstream",
                ["@type"] = "catalog:CatalogPage",
                ["count"] = versions.Length,
                ["items"] = entries,
                ["lower"] = versions.Length > 0 ? versions[0] : "",
                ["upper"] = versions.Length > 0 ? versions[^1] : ""
            })
        };
        return root.ToJsonString();
    }

    private static Package Pkg(string name) => new() { Name = name, PurlName = name.ToLowerInvariant() };

    private static PackageVersion Ver(string version, bool yanked = false) => new()
    {
        Version = version,
        Yanked = yanked
    };

    private static (int Count, string[] Versions) ReadPages(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var pages = doc.RootElement.GetProperty("items");
        var versions = pages.EnumerateArray()
            .SelectMany(p => p.GetProperty("items").EnumerateArray())
            .Select(e => e.GetProperty("catalogEntry").GetProperty("version").GetString()!)
            .ToArray();
        return (doc.RootElement.GetProperty("count").GetInt32(), versions);
    }

    [Fact]
    public void Merge_AddsLocalPrerelease_NextToUpstreamStable()
    {
        // The real-world case: upstream has stable versions, local has a private prerelease.
        // The merged response must list both so a downstream pinning ">= 13.0.3" finds 13.0.3.
        var upstream = MinimalUpstream("newtonsoft.json", "13.0.1", "13.0.3");
        var local = new[] { Ver("13.0.5-beta1") };

        var merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Newtonsoft.Json"), "newtonsoft.json");

        var (count, versions) = ReadPages(merged);
        Assert.Equal(2, count); // upstream page + new local page
        Assert.Contains("13.0.1", versions);
        Assert.Contains("13.0.3", versions);
        Assert.Contains("13.0.5-beta1", versions);
    }

    [Fact]
    public void Merge_DedupesVersionsAlreadyInUpstream()
    {
        // If a private build shadows an upstream version (same version string), don't add a
        // second entry — clients seeing two catalogEntry objects with the same version is
        // undefined behaviour. The local entry is suppressed.
        var upstream = MinimalUpstream("foo", "1.0.0", "2.0.0");
        var local = new[] { Ver("1.0.0"), Ver("3.0.0-pre") };

        var merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        var (_, versions) = ReadPages(merged);
        Assert.Equal(3, versions.Length); // 1.0.0, 2.0.0 (upstream) + 3.0.0-pre (local)
        Assert.Single(versions, v => v == "1.0.0");
    }

    [Fact]
    public void Merge_SkipsYankedLocalVersions()
    {
        var upstream = MinimalUpstream("foo", "1.0.0");
        var local = new[] { Ver("2.0.0", yanked: true), Ver("3.0.0") };

        var merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        var (_, versions) = ReadPages(merged);
        Assert.DoesNotContain("2.0.0", versions);
        Assert.Contains("3.0.0", versions);
    }

    [Fact]
    public void Merge_NoLocalOnlyVersions_ReturnsUpstreamUnchanged()
    {
        // Every local version already in upstream → no new page, no count bump.
        var upstream = MinimalUpstream("foo", "1.0.0", "2.0.0");
        var local = new[] { Ver("1.0.0"), Ver("2.0.0") };

        var merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        var (count, _) = ReadPages(merged);
        Assert.Equal(1, count);
    }

    [Fact]
    public void Merge_LocalPageEntries_PointToOurFlatcontainer_NotUpstream()
    {
        // Local versions must use our proxy URLs for packageContent — otherwise the client
        // bypasses the proxy and our first-fetch / vuln-gate / blocklist hooks never fire.
        var upstream = MinimalUpstream("foo", "1.0.0");
        var local = new[] { Ver("9.9.9-private") };

        var merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        using var doc = JsonDocument.Parse(merged);
        var localPage = doc.RootElement.GetProperty("items")[1];
        var entry = localPage.GetProperty("items")[0];
        var packageContent = entry.GetProperty("catalogEntry").GetProperty("packageContent").GetString();
        Assert.NotNull(packageContent);
        Assert.Contains("/nuget/flatcontainer/foo/9.9.9-private/foo.9.9.9-private.nupkg", packageContent);
        Assert.DoesNotContain("api.nuget.org", packageContent);
    }

    [Fact]
    public void Merge_VersionStringsSortedSemantically_ForLowerUpper()
    {
        // Lexical sort would put "10.0.0" before "9.0.0". NuGet clients expect semver order
        // on a page's lower/upper bounds, so the page metadata uses NuGetVersion comparison.
        var upstream = MinimalUpstream("foo", "0.0.1");
        var local = new[] { Ver("10.0.0"), Ver("9.0.0"), Ver("9.5.0-beta") };

        var merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        using var doc = JsonDocument.Parse(merged);
        var localPage = doc.RootElement.GetProperty("items")[1];
        Assert.Equal("9.0.0", localPage.GetProperty("lower").GetString());
        Assert.Equal("10.0.0", localPage.GetProperty("upper").GetString());
    }

    [Fact]
    public void Merge_MalformedUpstreamJson_ReturnsUpstreamUnchanged()
    {
        // Defensive: don't throw on unexpected upstream shapes — let the caller decide
        // whether to fall back. We propagate the original string unchanged.
        var bogus = "not json at all";
        var merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            bogus, new[] { Ver("1.0.0") }, Pkg("Foo"), "foo");
        Assert.Equal(bogus, merged);
    }
}
