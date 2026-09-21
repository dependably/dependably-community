using System.Text.RegularExpressions;
using Dependably.Api.Setup;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Coverage gate for <see cref="SetupRecipeCatalog.Ecosystems"/>: the list <c>GET
/// /api/v1/ecosystems</c> reads to answer which ecosystems have setup recipes. Pins that the
/// list cannot drift from the <c>Build</c> switch it is meant to summarize — an id added to one
/// without the other either advertises an ecosystem with no recipes, or hides one that has them.
/// </summary>
public sealed partial class SetupRecipeCatalogTests
{
    private const string BaseUrl = "https://repo.example.com";

    [Fact]
    public void EveryListedEcosystem_BuildsARecipe()
    {
        var missing = SetupRecipeCatalog.Ecosystems
            .Where(eco => SetupRecipeCatalog.Build(eco, BaseUrl) is null)
            .ToList();

        Assert.True(missing.Count == 0,
            "Every id in SetupRecipeCatalog.Ecosystems must build recipes via Build(). Missing: "
            + string.Join(", ", missing));
    }

    [Fact]
    public void UnknownEcosystem_IsNotInTheList_AndBuildsNothing()
    {
        Assert.DoesNotContain("zzz", SetupRecipeCatalog.Ecosystems);
        Assert.Null(SetupRecipeCatalog.Build("zzz", BaseUrl));
    }

    /// <summary>
    /// The other direction of the drift guard: <see cref="EveryListedEcosystem_BuildsARecipe"/>
    /// alone lets an arm added to the <c>Build</c> switch with no matching entry in
    /// <see cref="SetupRecipeCatalog.Ecosystems"/> stay invisible — every existing id still
    /// builds, so that test stays green while the endpoint quietly under-reports. This reads
    /// <c>SetupRecipeCatalog.cs</c> as text (the same approach
    /// <c>SetupRecipeCatalogComplianceTests</c> uses against <c>ecosystems.js</c>), extracts the
    /// switch's own arm ids in source order, and asserts the published list matches them
    /// exactly — set and order both, so a reordering that changes response ordering is caught
    /// too.
    /// </summary>
    [Fact]
    public void Ecosystems_MatchTheBuildSwitchExactly()
    {
        string path = Path.Combine(
            Dependably.Tests.Compliance.SourceRoots.RepoRoot(),
            "src", "Dependably.Management", "Api", "Setup", "SetupRecipeCatalog.cs");
        Assert.True(File.Exists(path), $"SetupRecipeCatalog.cs not found at {path}.");

        string source = File.ReadAllText(path);
        var switchMatch = BuildSwitchBodyRegex().Match(source);
        Assert.True(switchMatch.Success,
            "Could not locate the `ecosystem switch { … _ => null }` block in Build().");

        string[] armIds = ArmIdRegex().Matches(switchMatch.Groups["body"].Value)
            .Select(m => m.Groups["id"].Value)
            .ToArray();

        Assert.NotEmpty(armIds);
        Assert.Equal(armIds, SetupRecipeCatalog.Ecosystems);
    }

    // ecosystem switch { "npm" => Npm(baseUrl), … _ => null }
    [GeneratedRegex(@"ecosystem\s+switch\s*\{(?<body>.*?)_\s*=>\s*null", RegexOptions.Singleline)]
    private static partial Regex BuildSwitchBodyRegex();

    // "npm" =>
    [GeneratedRegex(@"""(?<id>[a-z0-9]+)""\s*=>")]
    private static partial Regex ArmIdRegex();
}
