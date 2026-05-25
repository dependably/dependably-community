using Dependably.Protocol;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Targets the residual uncovered branches in <see cref="LocalOsvSource"/> after the two
/// sibling test files: IConfiguration constructor edge cases, null/empty JSON payloads,
/// affected entries with missing package fields, the existing-key path in the per-file
/// indexer, multiple affected packages and ranges per advisory, aliases passthrough,
/// CVSS severity types that don't start with "CVSS", non-CVSS severity fallbacks where
/// database_specific.severity is null, ParsePurl's case-insensitive "pkg:" prefix and
/// uppercase ecosystem normalisation, and the QueryBatchAsync cancellation break.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LocalOsvSourceMoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "osvtest_more_" + Guid.NewGuid().ToString("N"));

    public LocalOsvSourceMoreTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private LocalOsvSource Build() => new(_dir, NullLogger<LocalOsvSource>.Instance);

    // ---- IConfiguration constructor branches --------------------------------------------

    [Fact]
    public void Ctor_MissingOsvLocalPath_Throws()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        var ex = Assert.Throws<InvalidOperationException>(
            () => new LocalOsvSource(config, NullLogger<LocalOsvSource>.Instance));
        Assert.Contains("OSV_LOCAL_PATH", ex.Message);
    }

    [Fact]
    public void Ctor_InvalidRefreshMinutes_FallsBackToDefault()
    {
        // Non-numeric value → int.TryParse fails → defaults to 60.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OSV_LOCAL_PATH"] = _dir,
                ["OSV_LOCAL_REFRESH_MINUTES"] = "not-a-number"
            })
            .Build();

        using var src = new LocalOsvSource(config, NullLogger<LocalOsvSource>.Instance);
        Assert.NotNull(src); // ctor must succeed
    }

    [Fact]
    public void Ctor_ZeroRefreshMinutes_FallsBackToDefault()
    {
        // m <= 0 → defaults to 60 (covers the `m > 0` branch).
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OSV_LOCAL_PATH"] = _dir,
                ["OSV_LOCAL_REFRESH_MINUTES"] = "0"
            })
            .Build();

        using var src = new LocalOsvSource(config, NullLogger<LocalOsvSource>.Instance);
        Assert.NotNull(src);
    }

    [Fact]
    public void Ctor_NegativeRefreshMinutes_FallsBackToDefault()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OSV_LOCAL_PATH"] = _dir,
                ["OSV_LOCAL_REFRESH_MINUTES"] = "-5"
            })
            .Build();

        using var src = new LocalOsvSource(config, NullLogger<LocalOsvSource>.Instance);
        Assert.NotNull(src);
    }

    // ---- TryIndexFileAsync / BuildAdvisory branches -------------------------------------

    [Fact]
    public async Task NullJsonPayload_IsSkipped()
    {
        // A file literally containing the JSON token `null` deserialises to a null RawOsvDump.
        File.WriteAllText(Path.Combine(_dir, "nullbody.json"), "null");
        // Drop a valid neighbour so the load loop still produces a key.
        File.WriteAllText(Path.Combine(_dir, "good.json"), """
            {
              "id": "GHSA-ok",
              "affected": [{ "package": { "ecosystem": "npm", "name": "ok" },
                             "versions": ["1.0.0"] }]
            }
            """);
        var src = Build();
        await src.ReloadAsync(CancellationToken.None);

        Assert.Single(await src.QueryAsync("pkg:npm/ok@1.0.0"));
    }

    [Fact]
    public async Task AffectedPackage_MissingEcosystem_SkippedFromIndex()
    {
        // Package has a name but no ecosystem → TryIndexFileAsync's `pkg.Ecosystem is null`
        // continue path skips indexing this entry. The advisory itself is not registered
        // under any key, so queries find nothing.
        var json = """
            {
              "id": "GHSA-noeco",
              "affected": [{ "package": { "name": "ghost" }, "versions": ["1.0.0"] }]
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "noeco.json"), json);
        var src = Build();

        Assert.Empty(await src.QueryAsync("pkg:npm/ghost@1.0.0"));
    }

    [Fact]
    public async Task AffectedPackage_MissingName_SkippedFromIndex()
    {
        var json = """
            {
              "id": "GHSA-noname",
              "affected": [{ "package": { "ecosystem": "npm" }, "versions": ["1.0.0"] }]
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "noname.json"), json);
        var src = Build();

        Assert.Empty(await src.QueryAsync("pkg:npm/anything@1.0.0"));
    }

    [Fact]
    public async Task TwoAdvisories_SameEcoAndName_AppendToExistingKey()
    {
        // Exercise the `index.TryGetValue(key, out var list)` true branch in
        // TryIndexFileAsync where a list already exists for the (eco,name) key.
        File.WriteAllText(Path.Combine(_dir, "first.json"), """
            {
              "id": "GHSA-first",
              "affected": [{ "package": { "ecosystem": "npm", "name": "dup" },
                             "versions": ["1.0.0"] }]
            }
            """);
        File.WriteAllText(Path.Combine(_dir, "second.json"), """
            {
              "id": "GHSA-second",
              "affected": [{ "package": { "ecosystem": "npm", "name": "dup" },
                             "versions": ["1.0.0"] }]
            }
            """);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/dup@1.0.0");
        Assert.Equal(2, hits.Count);
        Assert.Contains(hits, h => h.Id == "GHSA-first");
        Assert.Contains(hits, h => h.Id == "GHSA-second");
    }

    [Fact]
    public async Task Advisory_WithoutAffected_BuildsEmptyPackageList()
    {
        // Covers `raw.Affected?` null short-circuit and the resulting `[]` fallback.
        // The file is loaded but produces no index keys.
        var json = """
            {
              "id": "GHSA-empty",
              "summary": "no affected list"
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "empty.json"), json);
        // Pair with a valid file so the reload still has indexable content.
        File.WriteAllText(Path.Combine(_dir, "other.json"), """
            {
              "id": "GHSA-other",
              "affected": [{ "package": { "ecosystem": "npm", "name": "other" },
                             "versions": ["1.0.0"] }]
            }
            """);
        var src = Build();

        // Empty-affected advisory not indexed under any key.
        Assert.Empty(await src.QueryAsync("pkg:npm/anything@1.0.0"));
        Assert.Single(await src.QueryAsync("pkg:npm/other@1.0.0"));
    }

    [Fact]
    public async Task Advisory_AffectedEntryWithoutPackageObject_FilteredOut()
    {
        // Covers BuildAdvisory's `a.Package is not null` filter (the `Where` clause).
        var json = """
            {
              "id": "GHSA-nopkg",
              "affected": [{ "versions": ["1.0.0"] },
                           { "package": { "ecosystem": "npm", "name": "kept" },
                             "versions": ["1.0.0"] }]
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "nopkg.json"), json);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/kept@1.0.0");
        Assert.Single(hits);
    }

    [Fact]
    public async Task Advisory_MultipleAffectedPackages_AllIndexed()
    {
        // One advisory referencing two distinct packages — both keys must resolve to it.
        var json = """
            {
              "id": "GHSA-multi",
              "affected": [
                { "package": { "ecosystem": "npm", "name": "alpha" },
                  "versions": ["1.0.0"] },
                { "package": { "ecosystem": "npm", "name": "beta" },
                  "versions": ["2.0.0"] }
              ]
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "multi.json"), json);
        var src = Build();

        var a = await src.QueryAsync("pkg:npm/alpha@1.0.0");
        var b = await src.QueryAsync("pkg:npm/beta@2.0.0");
        Assert.Single(a);
        Assert.Single(b);
        Assert.Equal("GHSA-multi", a[0].Id);
        Assert.Equal("GHSA-multi", b[0].Id);
    }

    [Fact]
    public async Task Advisory_DuplicateVersions_DistinctOnLoad()
    {
        // Covers the `.Distinct()` call inside BuildAdvisory's projection.
        var json = """
            {
              "id": "GHSA-dupver",
              "affected": [{ "package": { "ecosystem": "npm", "name": "dupver" },
                             "versions": ["1.0.0", "1.0.0", "2.0.0"] }]
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "dupver.json"), json);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/dupver@1.0.0");
        Assert.Single(hits);
        Assert.Equal(2, hits[0].AffectedPackages[0].Versions.Length);
    }

    [Fact]
    public async Task Advisory_WithAliases_PreservedOnAdvisory()
    {
        // Covers `raw.Aliases?.ToArray()` non-null branch.
        var json = """
            {
              "id": "GHSA-aliased",
              "aliases": ["CVE-2026-0001", "CVE-2026-0002"],
              "affected": [{ "package": { "ecosystem": "npm", "name": "aliased" },
                             "versions": ["1.0.0"] }]
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "aliased.json"), json);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/aliased@1.0.0");
        Assert.Single(hits);
        Assert.Equal(2, hits[0].Aliases.Length);
        Assert.Contains("CVE-2026-0001", hits[0].Aliases);
    }

    [Fact]
    public async Task Advisory_WithoutId_DefaultsToEmptyString()
    {
        // Covers `raw.Id ?? ""` fallback.
        var json = """
            {
              "summary": "no id",
              "affected": [{ "package": { "ecosystem": "npm", "name": "noid" },
                             "versions": ["1.0.0"] }]
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "noid.json"), json);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/noid@1.0.0");
        Assert.Single(hits);
        Assert.Equal("", hits[0].Id);
    }

    [Fact]
    public async Task Severity_NonCvssType_IgnoredAndDbSpecificUsed()
    {
        // The severity[] entry has a type that doesn't start with "CVSS" — FirstOrDefault
        // returns null, so cvssScore stays null and severity falls back to
        // database_specific.severity (the second branch of the fallback chain).
        var json = """
            {
              "id": "GHSA-noncvss",
              "severity": [{ "type": "CUSTOM", "score": "ignored" }],
              "affected": [{ "package": { "ecosystem": "npm", "name": "noncvss" },
                             "versions": ["1.0.0"] }],
              "database_specific": { "severity": "HIGH" }
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "noncvss.json"), json);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/noncvss@1.0.0");
        Assert.Single(hits);
        Assert.Null(hits[0].CvssScore);
        Assert.Equal("HIGH", hits[0].Severity);
    }

    [Fact]
    public async Task Severity_DatabaseSpecificEntryNotSeverityKey_RemainsNull()
    {
        // database_specific exists but doesn't contain a "severity" key — TryGetValue
        // returns false and severity stays null.
        var json = """
            {
              "id": "GHSA-dbother",
              "affected": [{ "package": { "ecosystem": "npm", "name": "dbother" },
                             "versions": ["1.0.0"] }],
              "database_specific": { "cwe_id": "CWE-79" }
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "dbother.json"), json);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/dbother@1.0.0");
        Assert.Single(hits);
        Assert.Null(hits[0].Severity);
    }

    [Fact]
    public async Task Severity_DatabaseSpecificSeverityNull_StaysNull()
    {
        // database_specific.severity exists but is explicitly null — `dbSev?.ToString()` is null.
        var json = """
            {
              "id": "GHSA-dbnull",
              "affected": [{ "package": { "ecosystem": "npm", "name": "dbnull" },
                             "versions": ["1.0.0"] }],
              "database_specific": { "severity": null }
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "dbnull.json"), json);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/dbnull@1.0.0");
        Assert.Single(hits);
        Assert.Null(hits[0].Severity);
    }

    // ---- ParsePurl + NormalizeEcosystem branches ----------------------------------------

    [Fact]
    public async Task ParsePurl_PkgPrefixCaseInsensitive()
    {
        // The "pkg:" prefix uses OrdinalIgnoreCase — uppercase still parses.
        File.WriteAllText(Path.Combine(_dir, "case.json"), """
            {
              "id": "GHSA-case",
              "affected": [{ "package": { "ecosystem": "npm", "name": "casepkg" },
                             "versions": ["1.0.0"] }]
            }
            """);
        var src = Build();

        var hits = await src.QueryAsync("PKG:npm/casepkg@1.0.0");
        Assert.Single(hits);
    }

    [Fact]
    public async Task ParsePurl_NormalizesUnknownEcosystem_Lowercased()
    {
        // The `var other => other` arm of NormalizeEcosystem (lowercase passthrough).
        // Index it under lowercase to match the lookup.
        File.WriteAllText(Path.Combine(_dir, "exotic.json"), """
            {
              "id": "GHSA-exotic",
              "affected": [{ "package": { "ecosystem": "cargo", "name": "exotic" },
                             "versions": ["1.0.0"] }]
            }
            """);
        var src = Build();

        // Mixed-case ecosystem in the PURL must lowercase to "cargo".
        var hits = await src.QueryAsync("pkg:CARGO/exotic@1.0.0");
        Assert.Single(hits);
    }

    // ---- QueryBatchAsync cancellation branch --------------------------------------------

    [Fact]
    public async Task QueryBatchAsync_AlreadyCancelledToken_BreaksEarly()
    {
        File.WriteAllText(Path.Combine(_dir, "any.json"), """
            {
              "id": "GHSA-any",
              "affected": [{ "package": { "ecosystem": "npm", "name": "any" },
                             "versions": ["1.0.0"] }]
            }
            """);
        var src = Build();
        // Warm the lazy initial load so the cancellation hits the foreach, not the await.
        await src.QueryAsync("pkg:npm/any@1.0.0");

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await src.QueryBatchAsync(
            new[] { "pkg:npm/any@1.0.0", "pkg:npm/any@1.0.0" }, cts.Token);

        // The loop breaks before adding any element.
        Assert.Empty(result);
    }
}
