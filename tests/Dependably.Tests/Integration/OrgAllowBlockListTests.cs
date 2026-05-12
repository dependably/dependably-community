using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// Covers OrgController's allowlist + blocklist + settings + stats + setup paths — the
/// surfaces not picked up by the existing TokenIssuance / UserManagement / Saml tests.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OrgAllowBlockListTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public OrgAllowBlockListTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        var jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<HttpClient> MemberClient()
    {
        var id = await _factory.CreateUser($"oabl-{Guid.NewGuid():N}@example.com", "Password12345");
        var jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    // ── Settings (GET/PUT) ────────────────────────────────────────────────────

    [Fact]
    public async Task GetSettings_Admin_Returns200WithObject()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
    }

    [Fact]
    public async Task GetRetention_Admin_Returns200()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/retention");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task GetProxySettings_Admin_Returns200()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/proxy-settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Allowlist ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Allowlist_AddListDelete_RoundTrip()
    {
        using var c = await AdminClient();
        var pattern = $"pkg:npm/awesome-{Guid.NewGuid():N}";

        var add = await c.PostAsJsonAsync("/api/v1/allowlist",
            new { ecosystem = "npm", purlPattern = pattern });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);

        var doc = await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync());
        var id = doc.RootElement.GetProperty("id").GetString();
        Assert.False(string.IsNullOrEmpty(id));

        var list = await c.GetAsync("/api/v1/allowlist");
        list.EnsureSuccessStatusCode();
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        Assert.Contains(items.EnumerateArray(),
            e => e.GetProperty("purlPattern").GetString() == pattern);

        var remove = await c.DeleteAsync($"/api/v1/allowlist/{id}");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);
    }

    [Fact]
    public async Task Allowlist_AddByMember_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.PostAsJsonAsync("/api/v1/allowlist",
            new { ecosystem = "npm", purlPattern = "pkg:npm/anything" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Allowlist_DeleteUnknownId_Idempotent_Returns204()
    {
        // The repository's DeleteAsync is idempotent — operators can re-run cleanup scripts
        // without worrying about whether a row already went. Pinning this guards a
        // surprise behavioural change.
        using var c = await AdminClient();
        var resp = await c.DeleteAsync($"/api/v1/allowlist/never-{Guid.NewGuid():N}");
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    // ── Blocklist ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Blocklist_AddListDelete_RoundTrip()
    {
        using var c = await AdminClient();
        var pattern = $"pkg:npm/sketchy-{Guid.NewGuid():N}";

        var add = await c.PostAsJsonAsync("/api/v1/blocklist",
            new { ecosystem = "npm", pattern });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        var id = (await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString();

        var list = await c.GetAsync("/api/v1/blocklist");
        list.EnsureSuccessStatusCode();
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        Assert.Contains(items.EnumerateArray(),
            e => e.GetProperty("pattern").GetString() == pattern);

        var remove = await c.DeleteAsync($"/api/v1/blocklist/{id}");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);
    }

    [Fact]
    public async Task Blocklist_AddByMember_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.PostAsJsonAsync("/api/v1/blocklist",
            new { ecosystem = "npm", pattern = "pkg:npm/anything" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Stats + Setup + Activity + Audit ──────────────────────────────────────

    [Fact]
    public async Task Stats_Admin_Returns200WithCounts()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/stats");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    [InlineData("nuget")]
    public async Task Setup_ReturnsSnippetForEcosystem(string eco)
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/setup/{eco}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Activity_Admin_Returns200WithPagination()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/activity?limit=10&page=1");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Audit_Admin_Returns200()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/audit?limit=10&page=1");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Audit_Member_Forbidden()
    {
        // tenant audit is admin-only.
        using var c = await MemberClient();
        var resp = await c.GetAsync("/api/v1/audit");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }
}
