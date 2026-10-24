using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

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
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"oabl-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
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
        string pattern = $"pkg:npm/awesome-{Guid.NewGuid():N}";

        var add = await c.PostAsJsonAsync("/api/v1/allowlist",
            new { purlPattern = pattern });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);

        var doc = await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync());
        string? id = doc.RootElement.GetProperty("id").GetString();
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
            new { purlPattern = "pkg:npm/anything" });
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
        string pattern = $"pkg:npm/sketchy-{Guid.NewGuid():N}";

        var add = await c.PostAsJsonAsync("/api/v1/blocklist",
            new { pattern });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        string? id = (await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync()))
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
            new { pattern = "pkg:npm/anything" });
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

    // ── Policy list validation, denial, and isolation ─────────────────────────

    private async Task<HttpClient> ClientWithCaps(params string[] caps)
    {
        string id = await _factory.CreateUser($"lists-{Guid.NewGuid():N}@example.com", "Password12345");
        return _factory.CreateClientWithBearer(await _factory.CreateUserJwtWithCaps(id, caps));
    }

    private async Task<string> OtherOrgIdAsync()
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        return (await orgs.CreateOrgAsync($"ls-{Guid.NewGuid():N}"[..14])).Id;
    }

    [Theory]
    [InlineData("/api/v1/allowlist")]
    [InlineData("/api/v1/blocklist")]
    [InlineData("/api/v1/reserved-namespaces")]
    [InlineData("/api/v1/install-script-allowlist")]
    public async Task Lists_ReadRequiresReadTenant(string path)
    {
        using var noRead = await ClientWithCaps("read:packages");
        using var reader = await ClientWithCaps("read:tenant");

        await ProblemBody.AssertForbiddenAsync(await noRead.GetAsync(path));
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync(path)).StatusCode);
    }

    [Fact]
    public async Task ReservedNamespaces_AddListDelete_RoundTripNormalizesInput()
    {
        using var c = await AdminClient();
        string pattern = $"acme-{Guid.NewGuid():N}-*";

        var add = await c.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "  NPM ", pattern = $"  {pattern}  " });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        var created = await ProblemBody.ReadAsync(add);
        Assert.Equal("npm", created.GetProperty("ecosystem").GetString());
        Assert.Equal(pattern, created.GetProperty("pattern").GetString());
        string id = created.GetProperty("id").GetString()!;

        var list = await c.GetFromJsonAsync<JsonElement>("/api/v1/reserved-namespaces");
        Assert.Contains(list.EnumerateArray(), e => e.GetProperty("id").GetString() == id);

        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/api/v1/reserved-namespaces/{id}")).StatusCode);
        list = await c.GetFromJsonAsync<JsonElement>("/api/v1/reserved-namespaces");
        Assert.DoesNotContain(list.EnumerateArray(), e => e.GetProperty("id").GetString() == id);
    }

    [Fact]
    public async Task ReservedNamespaces_DuplicateAdd_Is409_AuditsOnce_AndTheFirstIdStillDeletes()
    {
        // A second add of the same (ecosystem, pattern) inserts nothing. It must not answer with
        // or audit an id that was never stored: deleting that id would remove nothing and leave
        // the reservation in force while the audit trail says otherwise.
        using var c = await AdminClient();
        string pattern = $"dup-{Guid.NewGuid():N}-*";

        var first = await c.PostAsJsonAsync("/api/v1/reserved-namespaces", new { ecosystem = "npm", pattern });
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        string id = (await ProblemBody.ReadAsync(first)).GetProperty("id").GetString()!;

        var second = await c.PostAsJsonAsync("/api/v1/reserved-namespaces", new { ecosystem = "npm", pattern });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);

        var list = await c.GetFromJsonAsync<JsonElement>("/api/v1/reserved-namespaces");
        Assert.Single(list.EnumerateArray(), e => e.GetProperty("pattern").GetString() == pattern);

        var store = _factory.Services.GetRequiredService<Dependably.Infrastructure.IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            var auditedIds = (await Dapper.SqlMapper.QueryAsync<string>(conn,
                "SELECT detail FROM audit_log WHERE action = 'reserved_namespace_added' AND detail LIKE @like",
                new { like = $"%{pattern}%" })).ToList();
            Assert.Single(auditedIds);
            Assert.Contains(id, auditedIds[0], StringComparison.Ordinal);
        }

        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/api/v1/reserved-namespaces/{id}")).StatusCode);
        list = await c.GetFromJsonAsync<JsonElement>("/api/v1/reserved-namespaces");
        Assert.DoesNotContain(list.EnumerateArray(), e => e.GetProperty("pattern").GetString() == pattern);
    }

    [Theory]
    [InlineData("pypi", "", "pattern")]
    [InlineData("pypi", "   ", "pattern")]
    [InlineData("docker", "acme-*", "ecosystem")]
    [InlineData("", "acme-*", "ecosystem")]
    [InlineData("npm", "ac*me", "pattern")]
    [InlineData("npm", "TOO_LONG", "pattern")]
    public async Task ReservedNamespaces_InvalidBody_ReturnsValidationProblem(string ecosystem, string pattern, string field)
    {
        using var c = await AdminClient();
        string sent = pattern == "TOO_LONG" ? new string('a', 257) : pattern;
        int before = (await c.GetFromJsonAsync<JsonElement>("/api/v1/reserved-namespaces")).GetArrayLength();

        await ProblemBody.AssertValidationAsync(
            await c.PostAsJsonAsync("/api/v1/reserved-namespaces", new { ecosystem, pattern = sent }), field);

        Assert.Equal(before, (await c.GetFromJsonAsync<JsonElement>("/api/v1/reserved-namespaces")).GetArrayLength());
    }

    [Fact]
    public async Task InstallScriptAllowlist_AddListDelete_RoundTripTrimsInput()
    {
        using var c = await AdminClient();
        string name = $"native-addon-{Guid.NewGuid():N}";

        var add = await c.PostAsJsonAsync("/api/v1/install-script-allowlist",
            new { ecosystem = " NPM", name = $" {name} ", versionPattern = " 2.* " });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        var created = await ProblemBody.ReadAsync(add);
        Assert.Equal("npm", created.GetProperty("ecosystem").GetString());
        Assert.Equal(name, created.GetProperty("name").GetString());
        Assert.Equal("2.*", created.GetProperty("versionPattern").GetString());
        string id = created.GetProperty("id").GetString()!;

        // A blank version pattern is stored as "no pattern" rather than an empty string.
        var blank = await c.PostAsJsonAsync("/api/v1/install-script-allowlist",
            new { ecosystem = "npm", name = $"{name}-all", versionPattern = "   " });
        Assert.Equal(HttpStatusCode.Created, blank.StatusCode);
        var blankBody = await ProblemBody.ReadAsync(blank);
        Assert.Equal(JsonValueKind.Null, blankBody.GetProperty("versionPattern").ValueKind);

        var list = await c.GetFromJsonAsync<JsonElement>("/api/v1/install-script-allowlist");
        Assert.Contains(list.EnumerateArray(), e => e.GetProperty("id").GetString() == id);

        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/api/v1/install-script-allowlist/{id}")).StatusCode);
        await c.DeleteAsync($"/api/v1/install-script-allowlist/{blankBody.GetProperty("id").GetString()}");
        list = await c.GetFromJsonAsync<JsonElement>("/api/v1/install-script-allowlist");
        Assert.DoesNotContain(list.EnumerateArray(), e => e.GetProperty("id").GetString() == id);
    }

    [Theory]
    [InlineData("hex", "left-pad", null, "ecosystem")]
    [InlineData("npm", "", null, "name")]
    [InlineData("npm", "   ", null, "name")]
    [InlineData("npm", "TOO_LONG", null, "name")]
    [InlineData("npm", "left-pad", "TOO_LONG", "version_pattern")]
    [InlineData("npm", "left-pad", "1.*.0", "version_pattern")]
    public async Task InstallScriptAllowlist_InvalidBody_ReturnsValidationProblem(
        string ecosystem, string name, string? versionPattern, string field)
    {
        using var c = await AdminClient();
        string sentName = name == "TOO_LONG" ? new string('n', 513) : name;
        string? sentVersion = versionPattern == "TOO_LONG" ? new string('1', 129) : versionPattern;
        int before = (await c.GetFromJsonAsync<JsonElement>("/api/v1/install-script-allowlist")).GetArrayLength();

        await ProblemBody.AssertValidationAsync(
            await c.PostAsJsonAsync("/api/v1/install-script-allowlist",
                new { ecosystem, name = sentName, versionPattern = sentVersion }), field);

        Assert.Equal(before, (await c.GetFromJsonAsync<JsonElement>("/api/v1/install-script-allowlist")).GetArrayLength());
    }

    [Theory]
    [InlineData("/api/v1/allowlist", "purlPattern", "pkg:npm/denied")]
    [InlineData("/api/v1/blocklist", "pattern", "pkg:npm/denied")]
    [InlineData("/api/v1/reserved-namespaces", "pattern", "denied-*")]
    [InlineData("/api/v1/install-script-allowlist", "name", "denied")]
    public async Task Lists_WriteWithoutTenantConfigure_IsForbiddenAndAddsNothing(string path, string property, string value)
    {
        using var reader = await ClientWithCaps("read:tenant");
        using var admin = await AdminClient();
        int before = (await admin.GetFromJsonAsync<JsonElement>(path)).GetArrayLength();
        var body = new Dictionary<string, string> { [property] = value };
        if (path.Contains("reserved") || path.Contains("install-script"))
        {
            body["ecosystem"] = "npm";
        }

        await ProblemBody.AssertForbiddenAsync(await reader.PostAsJsonAsync(path, body));
        await ProblemBody.AssertForbiddenAsync(await reader.DeleteAsync($"{path}/anything"));

        Assert.Equal(before, (await admin.GetFromJsonAsync<JsonElement>(path)).GetArrayLength());
    }

    [Fact]
    public async Task Blocklist_InvalidBody_ReturnsValidationProblem()
    {
        using var c = await AdminClient();

        await ProblemBody.AssertValidationAsync(await c.PostAsJsonAsync("/api/v1/blocklist", new { pattern = "" }), "pattern");
        await ProblemBody.AssertValidationAsync(
            await c.PostAsJsonAsync("/api/v1/blocklist", new { pattern = new string('a', 513) }), "pattern");
        await ProblemBody.AssertValidationAsync(await c.PostAsJsonAsync("/api/v1/blocklist", new { pattern = "([unclosed" }), "pattern");
    }

    [Fact]
    public async Task Allowlist_InvalidBody_ReturnsValidationProblem()
    {
        using var c = await AdminClient();

        await ProblemBody.AssertValidationAsync(await c.PostAsJsonAsync("/api/v1/allowlist", new { purlPattern = "  " }), "purl_pattern");
        await ProblemBody.AssertValidationAsync(
            await c.PostAsJsonAsync("/api/v1/allowlist", new { purlPattern = new string('a', 513) }), "purl_pattern");
    }

    [Fact]
    public async Task ForeignOrgEntries_AreNotListedAndSurviveDeleteAttempts()
    {
        string other = await OtherOrgIdAsync();
        var allow = await _factory.Services.GetRequiredService<AllowlistRepository>().AddAsync(other, "pkg:npm/foreign");
        var block = await _factory.Services.GetRequiredService<BlocklistRepository>().AddAsync(other, "pkg:npm/foreign");
        var reserved = await _factory.Services.GetRequiredService<ReservedNamespaceService>()
            .AddAsync(other, "npm", "foreign-*", null);
        var script = await _factory.Services.GetRequiredService<InstallScriptAllowlistService>()
            .AddAsync(other, "npm", "foreign", null, null);
        using var c = await AdminClient();

        foreach (var (path, id) in new[]
        {
            ("/api/v1/allowlist", allow.Id),
            ("/api/v1/blocklist", block.Id),
            ("/api/v1/reserved-namespaces", reserved.Id),
            ("/api/v1/install-script-allowlist", script.Id),
        })
        {
            var list = await c.GetFromJsonAsync<JsonElement>(path);
            Assert.DoesNotContain(list.EnumerateArray(), e => e.GetProperty("id").GetString() == id);
            Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"{path}/{id}")).StatusCode);
        }

        // Every foreign row is still present in the owning org after the cross-org deletes.
        Assert.Single(await _factory.Services.GetRequiredService<AllowlistRepository>().ListAsync(other));
        Assert.Single(await _factory.Services.GetRequiredService<BlocklistRepository>().ListAsync(other));
        Assert.Single(await _factory.Services.GetRequiredService<ReservedNamespaceService>().ListAsync(other));
        Assert.Single(await _factory.Services.GetRequiredService<InstallScriptAllowlistService>().ListAsync(other));
    }
}
