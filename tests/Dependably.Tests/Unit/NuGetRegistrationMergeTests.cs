using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Api;
using Dependably.Infrastructure;

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
        foreach (string v in versions)
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
        string[] versions = pages.EnumerateArray()
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
        string upstream = MinimalUpstream("newtonsoft.json", "13.0.1", "13.0.3");
        var local = new[] { Ver("13.0.5-beta1") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
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
        string upstream = MinimalUpstream("foo", "1.0.0", "2.0.0");
        var local = new[] { Ver("1.0.0"), Ver("3.0.0-pre") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        var (_, versions) = ReadPages(merged);
        Assert.Equal(3, versions.Length); // 1.0.0, 2.0.0 (upstream) + 3.0.0-pre (local)
        Assert.Single(versions, v => v == "1.0.0");
    }

    [Fact]
    public void Merge_SkipsYankedLocalVersions()
    {
        string upstream = MinimalUpstream("foo", "1.0.0");
        var local = new[] { Ver("2.0.0", yanked: true), Ver("3.0.0") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        var (_, versions) = ReadPages(merged);
        Assert.DoesNotContain("2.0.0", versions);
        Assert.Contains("3.0.0", versions);
    }

    [Fact]
    public void Merge_NoLocalOnlyVersions_ReturnsUpstreamUnchanged()
    {
        // Every local version already in upstream → no new page, no count bump.
        string upstream = MinimalUpstream("foo", "1.0.0", "2.0.0");
        var local = new[] { Ver("1.0.0"), Ver("2.0.0") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        var (count, _) = ReadPages(merged);
        Assert.Equal(1, count);
    }

    [Fact]
    public void Merge_LocalPageEntries_PointToOurFlatcontainer_NotUpstream()
    {
        // Local versions must use our proxy URLs for packageContent — otherwise the client
        // bypasses the proxy and our first-fetch / vuln-gate / blocklist hooks never fire.
        string upstream = MinimalUpstream("foo", "1.0.0");
        var local = new[] { Ver("9.9.9-private") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        using var doc = JsonDocument.Parse(merged);
        var localPage = doc.RootElement.GetProperty("items")[1];
        var entry = localPage.GetProperty("items")[0];
        string? packageContent = entry.GetProperty("catalogEntry").GetProperty("packageContent").GetString();
        Assert.NotNull(packageContent);
        Assert.Contains("/nuget/flatcontainer/foo/9.9.9-private/foo.9.9.9-private.nupkg", packageContent);
        Assert.DoesNotContain("api.nuget.org", packageContent);
    }

    [Fact]
    public void Merge_VersionStringsSortedSemantically_ForLowerUpper()
    {
        // Lexical sort would put "10.0.0" before "9.0.0". NuGet clients expect semver order
        // on a page's lower/upper bounds, so the page metadata uses NuGetVersion comparison.
        string upstream = MinimalUpstream("foo", "0.0.1");
        var local = new[] { Ver("10.0.0"), Ver("9.0.0"), Ver("9.5.0-beta") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
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
        string bogus = "not json at all";
        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            bogus, new[] { Ver("1.0.0") }, Pkg("Foo"), "foo");
        Assert.Equal(bogus, merged);
    }

    // ── URL rewriting ─────────────────────────────────────────────────────────

    [Fact]
    public void Merge_WithBaseUrl_RewritesUpstreamLeafPackageContent()
    {
        // When baseUrl is supplied, upstream entries in the merged document must have their
        // packageContent rewritten to the local flatcontainer route so downloads route through
        // the proxy gate rather than bypassing it via the upstream URL.
        string upstream = MinimalUpstream("foo", "1.0.0", "2.0.0");
        var local = new[] { Ver("3.0.0-pre") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo", "https://my.instance/nuget");

        using var doc = JsonDocument.Parse(merged);
        var upstreamPage = doc.RootElement.GetProperty("items")[0];
        foreach (var entry in upstreamPage.GetProperty("items").EnumerateArray())
        {
            string? packageContent = entry.GetProperty("catalogEntry").GetProperty("packageContent").GetString();
            Assert.NotNull(packageContent);
            Assert.StartsWith("https://my.instance/nuget/flatcontainer/foo/", packageContent);
            Assert.DoesNotContain("api.nuget.org", packageContent);
        }
    }

    [Fact]
    public void Merge_WithBaseUrl_RewritesUpstreamLeafAtId()
    {
        // Each upstream leaf @id must point at our registration route so clients following leaf
        // URLs land on this instance.
        string upstream = MinimalUpstream("foo", "1.0.0");
        var local = new[] { Ver("9.0.0") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo", "https://my.instance/nuget");

        using var doc = JsonDocument.Parse(merged);
        var upstreamPage = doc.RootElement.GetProperty("items")[0];
        string? leafId = upstreamPage.GetProperty("items")[0].GetProperty("@id").GetString();
        Assert.NotNull(leafId);
        Assert.StartsWith("https://my.instance/nuget/registration/foo/", leafId);
        Assert.EndsWith(".json", leafId);
        Assert.DoesNotContain("api.nuget.org", leafId);
    }

    [Fact]
    public void Merge_WithBaseUrl_LocalPageEntriesStillPointToLocalRoutes()
    {
        // The local-version page is built by BuildLocalPage which always uses relative paths,
        // independent of the baseUrl rewrite. Both upstream and local entries must end up local.
        string upstream = MinimalUpstream("foo", "1.0.0");
        var local = new[] { Ver("9.9.9-private") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo", "https://my.instance/nuget");

        using var doc = JsonDocument.Parse(merged);
        var localPage = doc.RootElement.GetProperty("items")[1];
        string? pc = localPage.GetProperty("items")[0].GetProperty("catalogEntry").GetProperty("packageContent").GetString();
        Assert.NotNull(pc);
        Assert.Contains("/nuget/flatcontainer/foo/9.9.9-private/foo.9.9.9-private.nupkg", pc);
        Assert.DoesNotContain("api.nuget.org", pc);
    }

    [Fact]
    public void RewriteRegistrationIndexUrls_RewritesAllLeaves()
    {
        // Pure-upstream path: the full index is passed through after URL rewriting.
        string upstream = MinimalUpstream("bar", "4.0.0", "5.0.0");

        string rewritten = NuGetController.RewriteRegistrationIndexUrls(
            upstream, "bar", "https://proxy.example/nuget");

        using var doc = JsonDocument.Parse(rewritten);
        foreach (var page in doc.RootElement.GetProperty("items").EnumerateArray())
        {
            foreach (var entry in page.GetProperty("items").EnumerateArray())
            {
                string? pc = entry.GetProperty("catalogEntry").GetProperty("packageContent").GetString();
                Assert.StartsWith("https://proxy.example/nuget/flatcontainer/bar/", pc);
                Assert.DoesNotContain("api.nuget.org", pc);

                string? id = entry.GetProperty("@id").GetString();
                Assert.StartsWith("https://proxy.example/nuget/registration/bar/", id);
                Assert.DoesNotContain("api.nuget.org", id);
            }
        }
    }

    [Fact]
    public void RewriteRegistrationIndexUrls_MalformedJson_ReturnsUnchanged()
    {
        // Malformed upstream JSON must not throw — the caller receives the original string.
        string bogus = "{bad json";
        string result = NuGetController.RewriteRegistrationIndexUrls(bogus, "foo", "https://x/nuget");
        Assert.Equal(bogus, result);
    }

    [Fact]
    public void RewriteRegistrationLeafUrls_RewritesPackageContentAndAtId()
    {
        // A proxied leaf response must have both packageContent and @id rewritten to local routes.
        string leafJson = """
            {
              "@id": "https://api.nuget.org/v3/registration5-semver1/foo/1.2.3.json",
              "@type": "Package",
              "catalogEntry": {
                "id": "Foo",
                "version": "1.2.3",
                "listed": true,
                "packageContent": "https://api.nuget.org/v3-flatcontainer/foo/1.2.3/foo.1.2.3.nupkg"
              },
              "listed": true,
              "packageContent": "https://api.nuget.org/v3-flatcontainer/foo/1.2.3/foo.1.2.3.nupkg"
            }
            """;

        string rewritten = NuGetController.RewriteRegistrationLeafUrls(
            leafJson, "foo", "https://proxy.example/nuget");

        using var doc = JsonDocument.Parse(rewritten);
        string? leafId = doc.RootElement.GetProperty("@id").GetString();
        Assert.Equal("https://proxy.example/nuget/registration/foo/1.2.3.json", leafId);

        string? pc = doc.RootElement.GetProperty("packageContent").GetString();
        Assert.Equal("https://proxy.example/nuget/flatcontainer/foo/1.2.3/foo.1.2.3.nupkg", pc);

        string? catalogPc = doc.RootElement.GetProperty("catalogEntry").GetProperty("packageContent").GetString();
        Assert.Equal("https://proxy.example/nuget/flatcontainer/foo/1.2.3/foo.1.2.3.nupkg", catalogPc);
    }

    [Fact]
    public void RewriteRegistrationLeafUrls_MissingFields_DoesNotThrow()
    {
        // Absent packageContent and catalogEntry fields must not cause exceptions — upstream
        // JSON is hostile input that may omit optional fields.
        string leafJson = """{"@id":"https://upstream/foo/1.0.0.json","@type":"Package"}""";

        string rewritten = NuGetController.RewriteRegistrationLeafUrls(
            leafJson, "foo", "https://proxy.example/nuget");

        // Must not throw; @id is left unchanged when version cannot be extracted.
        Assert.NotNull(rewritten);
        using var doc = JsonDocument.Parse(rewritten);
        // No packageContent field was present; document is still valid JSON.
        Assert.False(doc.RootElement.TryGetProperty("packageContent", out _));
    }

    [Fact]
    public void RewriteRegistrationLeafUrls_MalformedJson_ReturnsUnchanged()
    {
        string bogus = "not json";
        string result = NuGetController.RewriteRegistrationLeafUrls(bogus, "foo", "https://x/nuget");
        Assert.Equal(bogus, result);
    }

    [Fact]
    public void RewriteRegistrationIndexUrls_NonStringVersion_SkipsLeafRewriteNoThrow()
    {
        // A hostile or buggy upstream may return a non-string version field (e.g. a number).
        // GetValue<string>() would throw InvalidOperationException; TryGetString must skip
        // the bad leaf without crashing, leaving the other leaf still rewritten.
        string indexJson = """
            {
              "@id": "https://api.nuget.org/v3/registration5-semver1/foo/index.json",
              "count": 1,
              "items": [
                {
                  "@id": "https://api.nuget.org/v3/registration5-semver1/foo/index.json#page/1",
                  "@type": "catalog:CatalogPage",
                  "count": 2,
                  "items": [
                    {
                      "@id": "https://api.nuget.org/v3/registration5-semver1/foo/1.0.0.json",
                      "@type": "Package",
                      "catalogEntry": {
                        "id": "Foo",
                        "version": 123,
                        "packageContent": "https://api.nuget.org/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg"
                      },
                      "packageContent": "https://api.nuget.org/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg"
                    },
                    {
                      "@id": "https://api.nuget.org/v3/registration5-semver1/foo/2.0.0.json",
                      "@type": "Package",
                      "catalogEntry": {
                        "id": "Foo",
                        "version": "2.0.0",
                        "packageContent": "https://api.nuget.org/v3-flatcontainer/foo/2.0.0/foo.2.0.0.nupkg"
                      },
                      "packageContent": "https://api.nuget.org/v3-flatcontainer/foo/2.0.0/foo.2.0.0.nupkg"
                    }
                  ]
                }
              ]
            }
            """;

        // Must not throw — non-string version leaf is skipped (URLs left as-is), string leaf is rewritten.
        string rewritten = NuGetController.RewriteRegistrationIndexUrls(
            indexJson, "foo", "https://proxy.example/nuget");

        using var doc = JsonDocument.Parse(rewritten);
        var items = doc.RootElement.GetProperty("items")[0].GetProperty("items");

        // Leaf with numeric version — @id and packageContent are left unrewritten.
        string? badLeafId = items[0].GetProperty("@id").GetString();
        Assert.Contains("api.nuget.org", badLeafId);

        // Leaf with valid string version — @id and packageContent are rewritten.
        string? goodLeafId = items[1].GetProperty("@id").GetString();
        Assert.NotNull(goodLeafId);
        Assert.StartsWith("https://proxy.example/nuget/registration/foo/", goodLeafId);
        Assert.DoesNotContain("api.nuget.org", goodLeafId);

        string? goodPc = items[1].GetProperty("catalogEntry").GetProperty("packageContent").GetString();
        Assert.NotNull(goodPc);
        Assert.StartsWith("https://proxy.example/nuget/flatcontainer/foo/", goodPc);
        Assert.DoesNotContain("api.nuget.org", goodPc);
    }

    [Fact]
    public void HostedRegistration_NoUpstream_UrlsAlwaysLocal()
    {
        // BuildLocalRegistration (not called here, exercised via the static helpers) builds
        // exclusively from BaseUrl(). This test verifies MergeLocalIntoUpstreamRegistration
        // with no upstream versions still uses relative local paths for the local page.
        string upstream = MinimalUpstream("baz", "1.0.0");
        var local = new[] { Ver("2.0.0") };

        // Without a baseUrl argument the local page uses relative paths (unchanged behaviour).
        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Baz"), "baz");

        using var doc = JsonDocument.Parse(merged);
        var localPage = doc.RootElement.GetProperty("items")[1];
        string? pc = localPage.GetProperty("items")[0].GetProperty("catalogEntry").GetProperty("packageContent").GetString();
        Assert.NotNull(pc);
        Assert.Contains("/nuget/flatcontainer/baz/2.0.0/baz.2.0.0.nupkg", pc);
    }
}
