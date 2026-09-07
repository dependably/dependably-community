using System.IO.Compression;
using Dependably.Api.Setup;
using Dependably.Infrastructure;
using Dependably.Tests.Compliance;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class SkillCatalogTests
{
    private const string HttpsBase = "https://repo.example.com";

    [Fact]
    public void SkillIds_HaveTheExpectedCounts()
    {
        Assert.Equal(17, SkillCatalog.ConfigSkillIds.Count);
        Assert.Equal(9, SkillCatalog.RemediationSkillIds.Count);
    }

    [Theory]
    [InlineData("fix-vulnerable-dependency")]
    [InlineData("fix-injection")]
    [InlineData("fix-xss")]
    [InlineData("fix-path-traversal")]
    [InlineData("fix-unsafe-deserialization")]
    [InlineData("fix-ssrf")]
    [InlineData("fix-broken-access-control")]
    [InlineData("fix-weak-cryptography")]
    [InlineData("fix-authentication-failures")]
    public void TryGetSkillMarkdown_RemediationId_ReturnsFrontmatterAndBody(string skillId)
    {
        string? markdown = SkillCatalog.TryGetSkillMarkdown(skillId);
        Assert.NotNull(markdown);
        Assert.StartsWith("---", markdown);
        Assert.Contains($"name: {skillId}", markdown);
        Assert.Contains("description:", markdown);
    }

    [Fact]
    public void TryGetSkillMarkdown_EveryConfigId_ReturnsFrontmatterAndBody()
    {
        foreach (string skillId in SkillCatalog.ConfigSkillIds)
        {
            string? markdown = SkillCatalog.TryGetSkillMarkdown(skillId);
            Assert.NotNull(markdown);
            Assert.StartsWith("---", markdown);
            Assert.Contains($"name: {skillId}", markdown);
        }
    }

    [Theory]
    [InlineData("not-a-real-skill")]
    [InlineData("../fix-xss")]
    [InlineData("")]
    public void TryGetSkillMarkdown_UnknownId_ReturnsNull(string skillId)
    {
        Assert.Null(SkillCatalog.TryGetSkillMarkdown(skillId));
    }

    /// <summary>
    /// The remediation path keeps its original scope. Serving a config skill from it would widen
    /// what a shipped route returns, which is the one thing generalising the catalogue must not do.
    /// </summary>
    [Fact]
    public void TryGetRemediationSkillMarkdown_ConfigId_ReturnsNull()
    {
        foreach (string skillId in SkillCatalog.ConfigSkillIds)
        {
            Assert.Null(SkillCatalog.TryGetRemediationSkillMarkdown(skillId));
        }

        Assert.NotNull(SkillCatalog.TryGetRemediationSkillMarkdown("fix-xss"));
    }

    [Fact]
    public void Index_HasOneSummaryPerKnownSkill_WithNonEmptyDescription()
    {
        var index = SkillCatalog.Index;
        Assert.Equal(SkillCatalog.ConfigSkillIds.Count + SkillCatalog.RemediationSkillIds.Count, index.Count);

        foreach (string id in SkillCatalog.ConfigSkillIds)
        {
            var summary = Assert.Single(index, s => s.Id == id);
            Assert.Equal(id, summary.Name);
            Assert.Equal(SkillFamilies.Config, summary.Family);
            Assert.False(string.IsNullOrWhiteSpace(summary.Description));
            Assert.False(string.IsNullOrWhiteSpace(summary.Ecosystem));
            Assert.False(string.IsNullOrWhiteSpace(summary.Scope));
        }

        foreach (string id in SkillCatalog.RemediationSkillIds)
        {
            var summary = Assert.Single(index, s => s.Id == id);
            Assert.Equal(id, summary.Name);
            Assert.Equal(SkillFamilies.Remediation, summary.Family);
            Assert.False(string.IsNullOrWhiteSpace(summary.Description));
            Assert.Null(summary.Ecosystem);
            Assert.Null(summary.Scope);
        }
    }

    [Fact]
    public void RemediationIndex_IsExactlyTheRemediationFamily()
    {
        var ids = SkillCatalog.RemediationIndex.Select(s => s.Id).ToList();
        Assert.Equal(SkillCatalog.RemediationSkillIds.OrderBy(x => x), ids.OrderBy(x => x));
    }

    [Fact]
    public void BuildBundle_ContainsEveryEntryAtTheInstallLayout()
    {
        byte[] zip = SkillCatalog.BuildBundle();
        using var archive = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read);

        var expected = SkillCatalog.ConfigSkillIds
            .Concat(SkillCatalog.RemediationSkillIds)
            .Select(id => $"{id}/SKILL.md")
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToList();
        var actual = archive.Entries.Select(e => e.FullName).OrderBy(x => x, StringComparer.Ordinal).ToList();
        Assert.Equal(expected, actual);

        // The layout is load-bearing: unpacking into ~/.claude/skills/ must land each file where
        // that assistant already looks, so an entry is never bare or nested under a family folder.
        Assert.All(archive.Entries, e => Assert.EndsWith("/SKILL.md", e.FullName, StringComparison.Ordinal));
        Assert.DoesNotContain(archive.Entries, e => e.FullName.StartsWith("remediation/", StringComparison.Ordinal));

        using var reader = new StreamReader(archive.Entries.Single(e => e.FullName == "fix-xss/SKILL.md").Open());
        Assert.Contains("name: fix-xss", reader.ReadToEnd());
    }

    [Theory]
    [InlineData(SkillFamilies.Config, 17)]
    [InlineData(SkillFamilies.Remediation, 9)]
    public void BuildBundle_NarrowsToOneFamily(string family, int expectedCount)
    {
        using var archive = new ZipArchive(new MemoryStream(SkillCatalog.BuildBundle(family)), ZipArchiveMode.Read);
        Assert.Equal(expectedCount, archive.Entries.Count);

        var idsInFamily = SkillCatalog.Index.Where(s => s.Family == family).Select(s => s.Id).ToHashSet();
        Assert.All(archive.Entries, e => Assert.Contains(e.FullName.Split('/')[0], idsInFamily));
    }

    /// <summary>
    /// The archive is a pure function of embedded content. A per-request timestamp would give the
    /// same corpus a different checksum on every download, which is a poor thing to hand an
    /// operator of a registry whose subject is verifying that bytes did not change.
    /// </summary>
    [Fact]
    public void BuildBundle_IsByteIdenticalAcrossCalls()
    {
        Assert.Equal(SkillCatalog.BuildBundle(), SkillCatalog.BuildBundle());
    }

    /// <summary>
    /// The config skills and the Setup recipe matrix state the same fact — which (ecosystem, scope)
    /// cells a reader can be configured for — and they have drifted before: four ecosystems shipped
    /// recipes with no skill behind them. Set equality in both directions is what keeps them
    /// together. A new ecosystem, or a newly added scope on an existing one, fails here until its
    /// skill lands; a skill claiming a cell the catalogue will not serve fails the same way, because
    /// the page would then advertise a configuration the instance never produces.
    /// </summary>
    [Fact]
    public void ConfigSkills_CoverExactlyTheSetupRecipeCells()
    {
        var recipeCells = new HashSet<(string Ecosystem, string Scope)>();
        foreach (string eco in Ecosystems())
        {
            var response = SetupRecipeCatalog.Build(eco, HttpsBase);
            Assert.NotNull(response);
            foreach (var recipe in response.Recipes)
            {
                recipeCells.Add((eco, recipe.Scope));
            }
        }

        var skillCells = SkillCatalog.Index
            .Where(s => s.Family == SkillFamilies.Config)
            .Select(s => (Ecosystem: s.Ecosystem!, Scope: s.Scope!))
            .ToHashSet();

        var cellsWithNoSkill = recipeCells.Except(skillCells).OrderBy(c => c.Ecosystem).ThenBy(c => c.Scope).ToList();
        var skillsWithNoCell = skillCells.Except(recipeCells).OrderBy(c => c.Ecosystem).ThenBy(c => c.Scope).ToList();

        Assert.True(
            cellsWithNoSkill.Count == 0,
            "Setup recipe cells with no client-config skill: "
                + string.Join(", ", cellsWithNoSkill.Select(c => $"{c.Ecosystem}/{c.Scope}"))
                + ". Add skills/<ecosystem>-configure-<scope>/SKILL.md and embed it in the Management csproj.");

        Assert.True(
            skillsWithNoCell.Count == 0,
            "Client-config skills claiming a cell the Setup catalogue does not serve: "
                + string.Join(", ", skillsWithNoCell.Select(c => $"{c.Ecosystem}/{c.Scope}"))
                + ". Either the skill's frontmatter ecosystem/scope is wrong, or the recipe is missing.");
    }

    /// <summary>
    /// Reads the ecosystem vocabulary from the frontend rather than restating it, the same way
    /// <c>SetupRecipeCatalogComplianceTests</c> does — a hand-copied list in the gate is exactly the
    /// drift the gate exists to catch.
    /// </summary>
    private static IReadOnlyList<string> Ecosystems()
    {
        string path = Path.Combine(SourceRoots.RepoRoot(), "web", "src", "lib", "ecosystems.js");
        Assert.True(File.Exists(path), $"Ecosystem vocabulary not found at {path}.");

        string text = File.ReadAllText(path);
        int open = text.IndexOf("ECOSYSTEMS", StringComparison.Ordinal);
        Assert.True(open >= 0, $"Could not find the ECOSYSTEMS array in {path}.");
        int start = text.IndexOf('[', open);
        int end = text.IndexOf(']', start);
        Assert.True(start > 0 && end > start, $"Could not parse the ECOSYSTEMS array out of {path}.");

        string[] keys = text[(start + 1)..end]
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(k => k.Trim('\'', '"', ' '))
            .Where(k => k.Length > 0)
            .ToArray();

        Assert.NotEmpty(keys);
        return keys;
    }

    [Theory]
    [InlineData("""
        ---
        name: fix-xss
        description: Remediate cross-site scripting.
        category: remediation
        cwe:
          - CWE-79
          - CWE-80
        ---

        ## When to use this
        """, "fix-xss", "Remediate cross-site scripting.", null, null)]
    [InlineData("""
        ---
        name: fix-injection
        description: "Quoted description, with a comma."
        ---
        """, "fix-injection", "Quoted description, with a comma.", null, null)]
    [InlineData("""
        ---
        name: npm-configure-project
        description: Point npm at a dependably org.
        ecosystem: npm
        scope: project
        inputs:
          - DEPENDABLY_BASE_URL
          - NPM_TOKEN
        ---
        """, "npm-configure-project", "Point npm at a dependably org.", "npm", "project")]
    public void ParseFrontmatter_ExtractsScalars_IgnoringListValuedKeys(
        string markdown, string expectedName, string expectedDescription, string? expectedEcosystem, string? expectedScope)
    {
        var front = SkillCatalog.ParseFrontmatter(markdown);
        Assert.Equal(expectedName, front.Name);
        Assert.Equal(expectedDescription, front.Description);
        Assert.Equal(expectedEcosystem, front.Ecosystem);
        Assert.Equal(expectedScope, front.Scope);
    }

    [Fact]
    public void ParseFrontmatter_NoDelimiters_ReturnsNulls()
    {
        var front = SkillCatalog.ParseFrontmatter("# Just a heading, no frontmatter");
        Assert.Null(front.Name);
        Assert.Null(front.Description);
        Assert.Null(front.Ecosystem);
        Assert.Null(front.Scope);
    }
}
