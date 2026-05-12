using Dependably.Protocol;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Extends LocalOsvSourceTests with the remaining branches: range-only advisories (no
/// explicit version list), database_specific severity fallback, ReloadAsync after files
/// change, IsHydrated flag, and Dispose. Each test uses its own temp directory so the
/// reload doesn't pick up siblings.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LocalOsvSourceExtendedTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "osvtest_ext_" + Guid.NewGuid().ToString("N"));

    public LocalOsvSourceExtendedTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private LocalOsvSource Build() => new(_dir, NullLogger<LocalOsvSource>.Instance);

    [Fact]
    public async Task RangeOnly_Advisory_NoVersionsList_MatchesAnyQueryVersion()
    {
        // OSV permits affected entries with ranges but no explicit Versions list. The local
        // source reports such advisories for every version of the named package — the scan
        // service decides what to do with them downstream.
        var json = """
            {
              "id": "GHSA-range",
              "summary": "range only",
              "affected": [{ "package": { "ecosystem": "npm", "name": "lodash" } }]
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "range.json"), json);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/lodash@99.99.99");
        Assert.Single(hits);
        Assert.Equal("GHSA-range", hits[0].Id);
    }

    [Fact]
    public async Task DatabaseSpecific_Severity_UsedAsFallbackWhenNoCvssVector()
    {
        // No `severity[]` in the dump; database_specific.severity is consulted instead.
        var json = """
            {
              "id": "GHSA-dbsev",
              "summary": "db-specific severity",
              "affected": [{ "package": { "ecosystem": "npm", "name": "foo" },
                             "versions": ["1.0.0"] }],
              "database_specific": { "severity": "MODERATE" }
            }
            """;
        File.WriteAllText(Path.Combine(_dir, "dbsev.json"), json);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/foo@1.0.0");
        Assert.Single(hits);
        // OsvScoring.NormalizeSeverity maps MODERATE → MEDIUM.
        Assert.Equal("MEDIUM", hits[0].Severity);
        Assert.Null(hits[0].CvssScore);
    }

    [Fact]
    public async Task ReloadAsync_PicksUpNewFiles()
    {
        // Initial state: empty directory → no advisories.
        var src = Build();
        Assert.Empty(await src.QueryAsync("pkg:npm/added@1.0.0"));

        // Drop a new file and trigger reload.
        File.WriteAllText(Path.Combine(_dir, "added.json"), """
            {
              "id": "GHSA-added",
              "affected": [{ "package": { "ecosystem": "npm", "name": "added" },
                             "versions": ["1.0.0"] }]
            }
            """);
        await src.ReloadAsync(CancellationToken.None);

        var hits = await src.QueryAsync("pkg:npm/added@1.0.0");
        Assert.Single(hits);
    }

    [Fact]
    public async Task ReloadAsync_DropsOldFiles()
    {
        File.WriteAllText(Path.Combine(_dir, "gone.json"), """
            {
              "id": "GHSA-gone",
              "affected": [{ "package": { "ecosystem": "npm", "name": "gone" },
                             "versions": ["1.0.0"] }]
            }
            """);
        var src = Build();
        Assert.Single(await src.QueryAsync("pkg:npm/gone@1.0.0"));

        File.Delete(Path.Combine(_dir, "gone.json"));
        await src.ReloadAsync(CancellationToken.None);
        Assert.Empty(await src.QueryAsync("pkg:npm/gone@1.0.0"));
    }

    [Fact]
    public void Dispose_NoExceptionEvenAfterRefreshTimer()
    {
        // The internal ctor doesn't create a timer; ensure Dispose stays safe regardless.
        var src = Build();
        Assert.Null(Record.Exception(() =>
        {
            src.Dispose();
            // A second Dispose must not throw — pinning the idempotency contract.
            src.Dispose();
        }));
    }

    [Fact]
    public async Task ReloadAsync_DirectoryDoesNotExist_ClearsIndexAndReturnsEmpty()
    {
        // Seed an advisory so the index is non-empty after first load.
        File.WriteAllText(Path.Combine(_dir, "seed.json"), """
            {
              "id": "GHSA-seed",
              "affected": [{ "package": { "ecosystem": "npm", "name": "seed-pkg" },
                             "versions": ["1.0.0"] }]
            }
            """);
        var src = Build();
        // Confirm it was indexed.
        Assert.Single(await src.QueryAsync("pkg:npm/seed-pkg@1.0.0"));

        // Remove the directory entirely, then reload — index must be cleared.
        Directory.Delete(_dir, recursive: true);
        await src.ReloadAsync(CancellationToken.None);

        Assert.Empty(await src.QueryAsync("pkg:npm/seed-pkg@1.0.0"));
    }

    [Fact]
    public async Task QueryAsync_MalformedJsonFile_SkipsFileAndIndexesValidAdvisory()
    {
        // Write an invalid JSON file alongside a valid advisory.  After an explicit
        // ReloadAsync the valid advisory must be found while the bad file is silently skipped.
        File.WriteAllText(Path.Combine(_dir, "bad.json"), "{invalid json");
        File.WriteAllText(Path.Combine(_dir, "good.json"), """
            {
              "id": "GHSA-good",
              "affected": [{ "package": { "ecosystem": "npm", "name": "good-pkg" },
                             "versions": ["2.0.0"] }]
            }
            """);
        var src = Build();
        await src.ReloadAsync(CancellationToken.None);

        var hits = await src.QueryAsync("pkg:npm/good-pkg@2.0.0");
        Assert.Single(hits);
        Assert.Equal("GHSA-good", hits[0].Id);
        // The malformed file should not surface any advisory.
        Assert.Empty(await src.QueryAsync("pkg:npm/bad@1.0.0"));
    }

    [Fact]
    public async Task QueryBatchAsync_EmptyBatch_ReturnsEmpty()
    {
        var src = Build();
        var result = await src.QueryBatchAsync(new List<string>());
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void Dispose_WithTimerActive_DoesNotThrow()
    {
        // The IConfiguration constructor creates a real System.Threading.Timer.
        // Disposing once (and again) must not throw regardless of timer state.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OSV_LOCAL_PATH"] = _dir,
                ["OSV_LOCAL_REFRESH_MINUTES"] = "60"
            })
            .Build();

        var src = new LocalOsvSource(config, NullLogger<LocalOsvSource>.Instance);
        Assert.Null(Record.Exception(() =>
        {
            src.Dispose();
            // Second call must also be safe (timer already disposed).
            src.Dispose();
        }));
    }
}
