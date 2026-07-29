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
        // The local-version page is built by BuildLocalPage, which threads the same baseUrl
        // through to its leaves, so local entries land under this instance's routes too —
        // whether that base is the absolute supplied baseUrl or the relative fallback.
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
    public void Merge_SplicedLocalLeaf_CatalogEntryCarriesJsonLdIdAndType()
    {
        // The spliced local leaf's catalogEntry must carry "@id"/"@type" like every other
        // catalogEntry in the document (upstream leaves and the local-only render path both
        // do). A missing "@id" here is the JSON-LD verbatim-identifier defect the local-only
        // render path already fixed but this splice path did not inherit.
        string upstream = MinimalUpstream("foo", "1.0.0");
        var local = new[] { Ver("9.9.9-private") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo");

        using var doc = JsonDocument.Parse(merged);
        var localPage = doc.RootElement.GetProperty("items")[1];
        var catalogEntry = localPage.GetProperty("items")[0].GetProperty("catalogEntry");
        Assert.Equal("PackageDetails", catalogEntry.GetProperty("@type").GetString());
        string? entryId = catalogEntry.GetProperty("@id").GetString();
        Assert.NotNull(entryId);
        Assert.Contains("/nuget/registration/foo/9.9.9-private.json", entryId);
    }

    [Fact]
    public void Merge_WithBaseUrl_SplicedLocalLeaf_IdAndPackageContentAreAbsolute()
    {
        // Every upstream leaf in the merged document is rewritten to an absolute URL by
        // RewriteAllLeafUrls when baseUrl is supplied. The spliced local leaf must match —
        // packageContent deserializes into a System.Uri downstream, which throws on
        // .AbsoluteUri for a relative value.
        string upstream = MinimalUpstream("foo", "1.0.0");
        var local = new[] { Ver("9.9.9-private") };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, Pkg("Foo"), "foo", "https://my.instance/nuget");

        using var doc = JsonDocument.Parse(merged);
        var localPage = doc.RootElement.GetProperty("items")[1];
        var leaf = localPage.GetProperty("items")[0];

        string? leafId = leaf.GetProperty("@id").GetString();
        Assert.NotNull(leafId);
        Assert.StartsWith("https://my.instance/nuget/registration/foo/9.9.9-private.json", leafId);

        string? catalogPc = leaf.GetProperty("catalogEntry").GetProperty("packageContent").GetString();
        Assert.NotNull(catalogPc);
        Assert.StartsWith("https://my.instance/nuget/flatcontainer/foo/9.9.9-private/", catalogPc);

        // Must round-trip through System.Uri without throwing (the real NuGet client behavior).
        var parsed = new Uri(catalogPc!);
        Assert.Equal(catalogPc, parsed.AbsoluteUri);
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

    // ── Externalized upstream pages ──────────────────────────────────────────

    // What api.nuget.org returns for a package past its page-size threshold: the page object
    // carries an @id pointing at a separate document and omits `items` entirely.
    private static string UpstreamWithExternalizedPage(string id, string pageUrl) =>
        new JsonObject
        {
            ["@id"] = $"https://api.nuget.org/v3/registration5-semver1/{id}/index.json",
            ["@type"] = new JsonArray("catalog:CatalogRoot", "PackageRegistration"),
            ["count"] = 1,
            ["items"] = new JsonArray(new JsonObject
            {
                ["@id"] = pageUrl,
                ["@type"] = "catalog:CatalogPage",
                ["count"] = 2,
                ["lower"] = "1.0.0",
                ["upper"] = "2.0.0",
            }),
        }.ToJsonString();

    // The document that @id points at: the same page shape, this time with its leaves.
    private static string ExternalPageDocument(string id, string pageUrl, params string[] versions)
    {
        var entries = new JsonArray();
        foreach (string v in versions)
        {
            entries.Add(new JsonObject
            {
                ["@id"] = $"https://api.nuget.org/v3/registration5-semver1/{id}/{v}.json",
                ["@type"] = "Package",
                ["packageContent"] = $"https://api.nuget.org/v3-flatcontainer/{id}/{v}/{id}.{v}.nupkg",
                ["catalogEntry"] = new JsonObject
                {
                    ["id"] = id,
                    ["version"] = v,
                    ["listed"] = true,
                    ["packageContent"] = $"https://api.nuget.org/v3-flatcontainer/{id}/{v}/{id}.{v}.nupkg",
                },
            });
        }
        return new JsonObject
        {
            ["@id"] = pageUrl,
            ["@type"] = "catalog:CatalogPage",
            ["count"] = versions.Length,
            ["items"] = entries,
            ["lower"] = versions[0],
            ["upper"] = versions[^1],
        }.ToJsonString();
    }

    private static Func<string, CancellationToken, Task<string?>> ServePage(string url, string document) =>
        (requested, _) => Task.FromResult<string?>(requested == url ? document : null);

    /// <summary>
    /// The bug: an externalized page contributes nothing to the upstream version set, so every
    /// proxy-cached version of that package is misread as local-only and re-spliced as a duplicate
    /// local page. Inlining the page first is what makes the dedupe see those versions.
    ///
    /// Mixed by construction: one cached version that exists upstream must be deduped away while a
    /// genuinely local-only version in the same batch is still spliced — so the rule cannot be
    /// satisfied by simply never splicing.
    /// </summary>
    [Fact]
    public async Task ExternalizedPage_CachedVersionThatExistsUpstream_IsNotRespliced()
    {
        const string pageUrl = "https://api.nuget.org/v3/registration5-semver1/foo/page/1.0.0/2.0.0.json";
        string index = UpstreamWithExternalizedPage("foo", pageUrl);

        // The behaviour without inlining, asserted rather than described: the externalized page
        // contributes no versions, so BOTH cached versions are misread as local-only and 2.0.0 is
        // re-emitted as a duplicate of a version the same document already advertises upstream.
        using (var unInlined = JsonDocument.Parse(NuGetRegistrationHelpers.MergeLocalIntoUpstreamRegistration(
            index, [Ver("2.0.0"), Ver("9.9.9")], Pkg("Foo"), "foo", "https://proxy.example/nuget")))
        {
            var splicedWithoutInlining = unInlined.RootElement.GetProperty("items")[1]
                .GetProperty("items").EnumerateArray()
                .Select(l => l.GetProperty("catalogEntry").GetProperty("version").GetString())
                .ToList();
            Assert.Equal(["2.0.0", "9.9.9"], splicedWithoutInlining);
        }

        string inlined = await NuGetRegistrationHelpers.InlineExternalizedPagesAsync(
            index, ServePage(pageUrl, ExternalPageDocument("foo", pageUrl, "1.0.0", "2.0.0")),
            maxPages: 32, CancellationToken.None);

        string merged = NuGetRegistrationHelpers.MergeLocalIntoUpstreamRegistration(
            inlined, [Ver("2.0.0"), Ver("9.9.9")], Pkg("Foo"), "foo", "https://proxy.example/nuget");

        using var doc = JsonDocument.Parse(merged);
        var pages = doc.RootElement.GetProperty("items").EnumerateArray().ToList();

        // The upstream page is now inline (2 leaves), and exactly one local page was appended.
        Assert.Equal(2, pages.Count);
        Assert.Equal(2, pages[0].GetProperty("items").GetArrayLength());

        var localVersions = pages[1].GetProperty("items").EnumerateArray()
            .Select(l => l.GetProperty("catalogEntry").GetProperty("version").GetString())
            .ToList();
        // 2.0.0 exists upstream and must NOT be re-emitted; 9.9.9 is genuinely local-only.
        Assert.Equal(["9.9.9"], localVersions);
    }

    /// <summary>
    /// The proxy-bypass half. An externalized page's leaves keep api.nuget.org URLs because the
    /// rewrite, like the dedupe, walks page items that were not there. After inlining, no @id or
    /// packageContent anywhere in the document may point at the upstream host — including the
    /// page's own @id, which is inline now and dereferenced by nobody.
    /// </summary>
    [Fact]
    public async Task ExternalizedPage_AfterInlining_NoUrlPointsAtTheUpstreamHost()
    {
        const string pageUrl = "https://api.nuget.org/v3/registration5-semver1/foo/page/1.0.0/2.0.0.json";

        string inlined = await NuGetRegistrationHelpers.InlineExternalizedPagesAsync(
            UpstreamWithExternalizedPage("foo", pageUrl),
            ServePage(pageUrl, ExternalPageDocument("foo", pageUrl, "1.0.0", "2.0.0")),
            maxPages: 32, CancellationToken.None);

        string merged = NuGetRegistrationHelpers.MergeLocalIntoUpstreamRegistration(
            inlined, [Ver("9.9.9")], Pkg("Foo"), "foo", "https://proxy.example/nuget");

        // The index root @id is upstream-supplied and informational; every url the client would
        // dereference to download or resolve must be local.
        using var doc = JsonDocument.Parse(merged);
        foreach (var page in doc.RootElement.GetProperty("items").EnumerateArray())
        {
            Assert.DoesNotContain("api.nuget.org", page.GetProperty("@id").GetString());
            foreach (var leaf in page.GetProperty("items").EnumerateArray())
            {
                Assert.DoesNotContain("api.nuget.org", leaf.GetProperty("@id").GetString());
                Assert.DoesNotContain("api.nuget.org", leaf.GetProperty("packageContent").GetString());
                Assert.DoesNotContain("api.nuget.org",
                    leaf.GetProperty("catalogEntry").GetProperty("packageContent").GetString());
            }
        }
    }

    /// <summary>
    /// A page that cannot be fetched is left exactly as it was — externalized, with its upstream
    /// @id intact. Rewriting that @id to a local route this instance cannot serve would turn a
    /// degraded dedupe into an unresolvable document, and dropping the page would hide versions.
    /// </summary>
    [Fact]
    public async Task ExternalizedPage_ThatCannotBeFetched_IsLeftDereferenceable()
    {
        const string pageUrl = "https://api.nuget.org/v3/registration5-semver1/foo/page/1.0.0/2.0.0.json";

        string inlined = await NuGetRegistrationHelpers.InlineExternalizedPagesAsync(
            UpstreamWithExternalizedPage("foo", pageUrl),
            (_, _) => Task.FromResult<string?>(null),
            maxPages: 32, CancellationToken.None);

        string merged = NuGetRegistrationHelpers.MergeLocalIntoUpstreamRegistration(
            inlined, [Ver("2.0.0")], Pkg("Foo"), "foo", "https://proxy.example/nuget");

        using var doc = JsonDocument.Parse(merged);
        var upstreamPage = doc.RootElement.GetProperty("items")[0];
        Assert.Equal(pageUrl, upstreamPage.GetProperty("@id").GetString());
        Assert.False(upstreamPage.TryGetProperty("items", out _));
    }

    /// <summary>
    /// A response that is not a page document (no items) must not replace the page object — a
    /// malformed or hostile upstream should degrade to the un-inlined page, not to a page whose
    /// leaves vanished.
    /// </summary>
    [Fact]
    public async Task ExternalizedPage_FetchReturningANonPage_LeavesThePageAlone()
    {
        const string pageUrl = "https://api.nuget.org/v3/registration5-semver1/foo/page/1.0.0/2.0.0.json";
        string index = UpstreamWithExternalizedPage("foo", pageUrl);

        string inlined = await NuGetRegistrationHelpers.InlineExternalizedPagesAsync(
            index, ServePage(pageUrl, """{"@id":"whatever","count":0}"""),
            maxPages: 32, CancellationToken.None);

        Assert.Equal(index, inlined);
    }

    /// <summary>
    /// maxPages bounds the upstream fan-out one registration request can trigger, so a hostile
    /// index listing pages without end cannot turn one client request into unbounded outbound
    /// traffic. Pages past the cap keep their upstream @id and stay dereferenceable.
    /// </summary>
    [Fact]
    public async Task ExternalizedPages_BeyondTheCap_AreLeftExternalized()
    {
        var pageArray = new JsonArray();
        for (int i = 0; i < 5; i++)
        {
            pageArray.Add(new JsonObject
            {
                ["@id"] = $"https://api.nuget.org/v3/registration5-semver1/foo/page/{i}.json",
                ["@type"] = "catalog:CatalogPage",
            });
        }
        string index = new JsonObject { ["count"] = 5, ["items"] = pageArray }.ToJsonString();

        int fetches = 0;
        string inlined = await NuGetRegistrationHelpers.InlineExternalizedPagesAsync(
            index,
            (url, _) =>
            {
                fetches++;
                return Task.FromResult<string?>(ExternalPageDocument("foo", url, "1.0.0"));
            },
            maxPages: 2, CancellationToken.None);

        Assert.Equal(2, fetches);
        using var doc = JsonDocument.Parse(inlined);
        var pages = doc.RootElement.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(2, pages.Count(p => p.TryGetProperty("items", out _)));
        Assert.Equal(3, pages.Count(p => !p.TryGetProperty("items", out _)));
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
