using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class RemediationControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public RemediationControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Index_Anonymous_Returns200_WithSixSkills()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/remediation/skills");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(6, doc.RootElement.GetArrayLength());
        var ids = doc.RootElement.EnumerateArray()
            .Select(e => e.GetProperty("id").GetString())
            .ToHashSet();
        Assert.Contains("fix-vulnerable-dependency", ids);
        Assert.Contains("fix-injection", ids);
        Assert.Contains("fix-xss", ids);
        Assert.Contains("fix-path-traversal", ids);
        Assert.Contains("fix-unsafe-deserialization", ids);
        Assert.Contains("fix-ssrf", ids);
    }

    [Fact]
    public async Task GetSkill_KnownId_Returns200_TextMarkdown_WithFrontmatterIntact()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/remediation/skills/fix-vulnerable-dependency");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.StartsWith("text/markdown", resp.Content.Headers.ContentType?.MediaType);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.StartsWith("---", body);
        Assert.Contains("name: fix-vulnerable-dependency", body);
        Assert.Contains("## npm", body);
    }

    [Fact]
    public async Task GetSkill_UnknownId_Returns404()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/remediation/skills/not-a-real-skill");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task GetSkill_PathTraversalAttempt_Returns404_NotFileContent()
    {
        // skillId is validated against the closed embedded-manifest set only — a path-shaped
        // id must 404 like any other unknown id, never reach a filesystem/resource lookup.
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/remediation/skills/..%2f..%2fetc%2fpasswd");
        Assert.True(
            resp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadRequest,
            $"expected 404/400, got {resp.StatusCode}");
    }

    [Fact]
    public async Task Endpoints_AreAnonymous_NotRedirectedToLogin()
    {
        using var c = _factory.CreateClient();
        var indexResp = await c.GetAsync("/api/v1/remediation/skills");
        var skillResp = await c.GetAsync("/api/v1/remediation/skills/fix-xss");
        Assert.NotEqual(HttpStatusCode.Unauthorized, indexResp.StatusCode);
        Assert.NotEqual(HttpStatusCode.Unauthorized, skillResp.StatusCode);
    }
}
