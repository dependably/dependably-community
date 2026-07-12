using Dependably.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class RemediationSkillCatalogTests
{
    [Fact]
    public void KnownSkillIds_HasSixEntries()
    {
        Assert.Equal(6, RemediationSkillCatalog.KnownSkillIds.Count);
    }

    [Theory]
    [InlineData("fix-vulnerable-dependency")]
    [InlineData("fix-injection")]
    [InlineData("fix-xss")]
    [InlineData("fix-path-traversal")]
    [InlineData("fix-unsafe-deserialization")]
    [InlineData("fix-ssrf")]
    public void TryGetSkillMarkdown_KnownId_ReturnsFrontmatterAndBody(string skillId)
    {
        string? markdown = RemediationSkillCatalog.TryGetSkillMarkdown(skillId);
        Assert.NotNull(markdown);
        Assert.StartsWith("---", markdown);
        Assert.Contains($"name: {skillId}", markdown);
        Assert.Contains("description:", markdown);
    }

    [Theory]
    [InlineData("not-a-real-skill")]
    [InlineData("../fix-xss")]
    [InlineData("")]
    public void TryGetSkillMarkdown_UnknownId_ReturnsNull(string skillId)
    {
        Assert.Null(RemediationSkillCatalog.TryGetSkillMarkdown(skillId));
    }

    [Fact]
    public void Index_HasOneSummaryPerKnownSkill_WithNonEmptyDescription()
    {
        var index = RemediationSkillCatalog.Index;
        Assert.Equal(RemediationSkillCatalog.KnownSkillIds.Count, index.Count);
        foreach (string id in RemediationSkillCatalog.KnownSkillIds)
        {
            var summary = Assert.Single(index, s => s.Id == id);
            Assert.Equal(id, summary.Name);
            Assert.False(string.IsNullOrWhiteSpace(summary.Description));
        }
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
        """, "fix-xss", "Remediate cross-site scripting.")]
    [InlineData("""
        ---
        name: fix-injection
        description: "Quoted description, with a comma."
        ---
        """, "fix-injection", "Quoted description, with a comma.")]
    public void ParseFrontmatter_ExtractsNameAndDescription_IgnoringListValuedKeys(
        string markdown, string expectedName, string expectedDescription)
    {
        var (name, description) = RemediationSkillCatalog.ParseFrontmatter(markdown);
        Assert.Equal(expectedName, name);
        Assert.Equal(expectedDescription, description);
    }

    [Fact]
    public void ParseFrontmatter_NoDelimiters_ReturnsNulls()
    {
        var (name, description) = RemediationSkillCatalog.ParseFrontmatter("# Just a heading, no frontmatter");
        Assert.Null(name);
        Assert.Null(description);
    }
}
