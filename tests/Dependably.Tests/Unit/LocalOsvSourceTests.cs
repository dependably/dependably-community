using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class LocalOsvSourceTests : IDisposable
{
    private readonly string _dir;

    public LocalOsvSourceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "osvtest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private void WriteAdvisory(string id, string ecosystem, string name, string[] versions, string? severity = null)
    {
        var sevBlock = severity is null ? "" : $@",
  ""severity"": [{{ ""type"": ""CVSS_V3"", ""score"": ""{severity}"" }}]";
        var json = $@"{{
  ""id"": ""{id}"",
  ""summary"": ""test advisory"",
  ""affected"": [{{
    ""package"": {{ ""ecosystem"": ""{ecosystem}"", ""name"": ""{name}"" }},
    ""versions"": [{string.Join(",", versions.Select(v => $"\"{v}\""))}]
  }}]{sevBlock}
}}";
        File.WriteAllText(Path.Combine(_dir, $"{id}.json"), json);
    }

    private LocalOsvSource Build() => new(_dir, NullLogger<LocalOsvSource>.Instance);

    [Fact]
    public async Task Query_HitOnVersion_ReturnsAdvisory()
    {
        WriteAdvisory("GHSA-1", "npm", "lodash", ["4.17.20", "4.17.21"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/lodash@4.17.21");
        Assert.Single(hits);
        Assert.Equal("GHSA-1", hits[0].Id);
        Assert.True(hits[0].IsHydrated);
    }

    [Fact]
    public async Task Query_VersionMiss_ReturnsEmpty()
    {
        WriteAdvisory("GHSA-2", "npm", "lodash", ["4.17.20"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/lodash@4.17.21");
        Assert.Empty(hits);
    }

    [Fact]
    public async Task Query_NameMiss_ReturnsEmpty()
    {
        WriteAdvisory("GHSA-3", "npm", "lodash", ["1.0.0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/ghost@1.0.0");
        Assert.Empty(hits);
    }

    [Fact]
    public async Task Query_EcosystemCaseInsensitive()
    {
        // OSV uses "PyPI" / "npm" / "NuGet"; PURLs use lowercase. Match both.
        WriteAdvisory("GHSA-4", "PyPI", "requests", ["2.0.0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:pypi/requests@2.0.0");
        Assert.Single(hits);
    }

    [Fact]
    public async Task Query_CvssScoreParsedFromAdvisory()
    {
        WriteAdvisory("GHSA-5", "npm", "lodash", ["4.17.20"],
            severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/lodash@4.17.20");
        Assert.Single(hits);
        Assert.Equal("CRITICAL", hits[0].Severity);
        Assert.NotNull(hits[0].CvssScore);
    }

    [Fact]
    public async Task QueryBatch_ParallelToInputs_PreservesOrder()
    {
        WriteAdvisory("GHSA-A", "npm", "lodash", ["4.17.20"]);
        WriteAdvisory("GHSA-B", "npm", "react",  ["18.0.0"]);
        var src = Build();

        var results = await src.QueryBatchAsync([
            "pkg:npm/react@18.0.0",
            "pkg:npm/ghost@1.0.0",
            "pkg:npm/lodash@4.17.20"
        ]);

        Assert.Equal(3, results.Count);
        Assert.Equal("GHSA-B", results[0][0].Id);
        Assert.Empty(results[1]);
        Assert.Equal("GHSA-A", results[2][0].Id);
    }

    [Fact]
    public async Task Query_MissingDirectory_EmptyResults()
    {
        Directory.Delete(_dir, recursive: true);
        var src = new LocalOsvSource(_dir, NullLogger<LocalOsvSource>.Instance);
        var hits = await src.QueryAsync("pkg:npm/lodash@1.0.0");
        Assert.Empty(hits);
    }

    [Fact]
    public async Task Query_MalformedJson_SkippedNotThrown()
    {
        File.WriteAllText(Path.Combine(_dir, "bad.json"), "{not json");
        WriteAdvisory("GHSA-OK", "npm", "lodash", ["1.0.0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/lodash@1.0.0");
        Assert.Single(hits);
        Assert.Equal("GHSA-OK", hits[0].Id);
    }

    [Fact]
    public async Task Query_MalformedPurl_ReturnsEmpty()
    {
        WriteAdvisory("GHSA-Z", "npm", "lodash", ["1.0.0"]);
        var src = Build();

        Assert.Empty(await src.QueryAsync("not-a-purl"));
        Assert.Empty(await src.QueryAsync("pkg:npm/lodash"));      // no version
        Assert.Empty(await src.QueryAsync("pkg:npmlodash@1.0.0")); // no slash
    }
}
