using System.IO.Compression;
using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class SkillsControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public SkillsControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private static async Task<JsonDocument> IndexAsync(HttpClient c)
    {
        var resp = await c.GetAsync("/api/v1/skills");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
    }

    [Fact]
    public async Task Index_Anonymous_Returns200_WithBothFamilies()
    {
        using var c = _factory.CreateClient();
        using var doc = await IndexAsync(c);

        Assert.Equal(26, doc.RootElement.GetArrayLength());

        var byFamily = doc.RootElement.EnumerateArray()
            .GroupBy(e => e.GetProperty("family").GetString())
            .ToDictionary(g => g.Key!, g => g.Count());
        Assert.Equal(17, byFamily["config"]);
        Assert.Equal(9, byFamily["remediation"]);
    }

    [Fact]
    public async Task Index_ConfigEntriesCarryEcosystemAndScope_RemediationEntriesDoNot()
    {
        using var c = _factory.CreateClient();
        using var doc = await IndexAsync(c);

        foreach (var entry in doc.RootElement.EnumerateArray())
        {
            string family = entry.GetProperty("family").GetString()!;
            var ecosystem = entry.GetProperty("ecosystem");
            var scope = entry.GetProperty("scope");
            if (family == "config")
            {
                Assert.False(string.IsNullOrWhiteSpace(ecosystem.GetString()));
                Assert.False(string.IsNullOrWhiteSpace(scope.GetString()));
            }
            else
            {
                Assert.Equal(JsonValueKind.Null, ecosystem.ValueKind);
                Assert.Equal(JsonValueKind.Null, scope.ValueKind);
            }

            Assert.False(string.IsNullOrWhiteSpace(entry.GetProperty("description").GetString()));
        }
    }

    [Fact]
    public async Task Index_CarriesTheCellTheSetupPageLooksUp()
    {
        // The Setup page finds its shortcut by (family, ecosystem, scope) over this index rather
        // than reconstructing an id locally, so a cell it can select must be findable that way.
        using var c = _factory.CreateClient();
        using var doc = await IndexAsync(c);

        var npmProject = doc.RootElement.EnumerateArray().Single(e =>
            e.GetProperty("family").GetString() == "config"
            && e.GetProperty("ecosystem").GetString() == "npm"
            && e.GetProperty("scope").GetString() == "project");
        Assert.Equal("npm-configure-project", npmProject.GetProperty("id").GetString());

        var ociProject = doc.RootElement.EnumerateArray().Where(e =>
            e.GetProperty("family").GetString() == "config"
            && e.GetProperty("ecosystem").GetString() == "oci"
            && e.GetProperty("scope").GetString() == "project");
        Assert.Empty(ociProject);
    }

    [Theory]
    [InlineData("npm-configure-project")]
    [InlineData("hex-configure-global")]
    [InlineData("terraform-configure-global")]
    [InlineData("fix-xss")]
    public async Task GetSkill_KnownId_Returns200_TextMarkdown_WithFrontmatterIntact(string skillId)
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync($"/api/v1/skills/{skillId}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.StartsWith("text/markdown", resp.Content.Headers.ContentType?.MediaType);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.StartsWith("---", body);
        Assert.Contains($"name: {skillId}", body);
    }

    [Theory]
    [InlineData("not-a-real-skill")]
    [InlineData("npm-configure-machine")]
    [InlineData("..%2f..%2fetc%2fpasswd")]
    public async Task GetSkill_UnknownId_Returns404_NotFileContent(string skillId)
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync($"/api/v1/skills/{skillId}");
        Assert.True(
            resp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadRequest,
            $"expected 404/400, got {resp.StatusCode}");
    }

    [Fact]
    public async Task Bundle_Anonymous_ReturnsAZipOfTheWholeCorpus()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/skills/bundle");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("application/zip", resp.Content.Headers.ContentType?.MediaType);
        Assert.Equal("dependably-skills.zip", resp.Content.Headers.ContentDisposition?.FileNameStar
            ?? resp.Content.Headers.ContentDisposition?.FileName);

        using var archive = new ZipArchive(await resp.Content.ReadAsStreamAsync(), ZipArchiveMode.Read);
        Assert.Equal(26, archive.Entries.Count);
        Assert.Contains(archive.Entries, e => e.FullName == "fix-xss/SKILL.md");
        Assert.Contains(archive.Entries, e => e.FullName == "npm-configure-project/SKILL.md");
    }

    [Theory]
    [InlineData("remediation", 9)]
    [InlineData("config", 17)]
    public async Task Bundle_NarrowsToOneFamily(string family, int expected)
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync($"/api/v1/skills/bundle?family={family}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains($"dependably-{family}-skills.zip",
            resp.Content.Headers.ContentDisposition?.ToString() ?? string.Empty);

        using var archive = new ZipArchive(await resp.Content.ReadAsStreamAsync(), ZipArchiveMode.Read);
        Assert.Equal(expected, archive.Entries.Count);
    }

    /// <summary>
    /// `bundle` sits under the same path prefix as `{skillId}`. The literal segment outranks the
    /// parameter in ASP.NET route precedence, but that is a framework behaviour this endpoint now
    /// depends on — so pin it, and pin the twin: an unknown family is a 404, not a silent
    /// whole-corpus download that an operator asked to narrow.
    /// </summary>
    [Fact]
    public async Task Bundle_IsNotShadowedBySkillIdRoute_AndRefusesAnUnknownFamily()
    {
        using var c = _factory.CreateClient();

        var bundle = await c.GetAsync("/api/v1/skills/bundle");
        Assert.Equal("application/zip", bundle.Content.Headers.ContentType?.MediaType);

        var unknownFamily = await c.GetAsync("/api/v1/skills/bundle?family=everything");
        Assert.Equal(HttpStatusCode.NotFound, unknownFamily.StatusCode);

        // And the parameter route still answers for a real id rather than being eaten by the literal.
        var single = await c.GetAsync("/api/v1/skills/fix-xss");
        Assert.StartsWith("text/markdown", single.Content.Headers.ContentType?.MediaType);
    }

    /// <summary>
    /// The adversarial twin of the generalisation: widening the catalogue must not widen what the
    /// shipped remediation routes return, or a one-liner copied out of a running instance starts
    /// resolving to something it never named.
    /// </summary>
    [Fact]
    public async Task RemediationRoutes_StayScopedToTheRemediationFamily()
    {
        using var c = _factory.CreateClient();

        var indexResp = await c.GetAsync("/api/v1/remediation/skills");
        Assert.Equal(HttpStatusCode.OK, indexResp.StatusCode);
        using var doc = await JsonDocument.ParseAsync(await indexResp.Content.ReadAsStreamAsync());
        Assert.Equal(9, doc.RootElement.GetArrayLength());
        Assert.All(doc.RootElement.EnumerateArray(),
            e => Assert.StartsWith("fix-", e.GetProperty("id").GetString()));

        var configResp = await c.GetAsync("/api/v1/remediation/skills/npm-configure-project");
        Assert.Equal(HttpStatusCode.NotFound, configResp.StatusCode);
    }

    [Fact]
    public async Task Endpoints_AreAnonymous_NotRedirectedToLogin()
    {
        using var c = _factory.CreateClient();
        var indexResp = await c.GetAsync("/api/v1/skills");
        var skillResp = await c.GetAsync("/api/v1/skills/npm-configure-project");
        Assert.NotEqual(HttpStatusCode.Unauthorized, indexResp.StatusCode);
        Assert.NotEqual(HttpStatusCode.Unauthorized, skillResp.StatusCode);
    }
}
