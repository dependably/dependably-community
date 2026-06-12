using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class LicenseControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public LicenseControllerTests(DependablyFactory factory) => _factory = factory;
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
        // Members can read policy + lists, but cannot write.
        string id = await _factory.CreateUser($"licm-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    // ── Policy summary ────────────────────────────────────────────────────────

    [Fact]
    public async Task GetPolicy_Default_ReturnsOffMode_WithEmptyLists()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/license-policy");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        // Default mode is "off" — explicitly assert so a default-change is detected.
        Assert.Equal("off", doc.RootElement.GetProperty("mode").GetString());
        Assert.Equal(JsonValueKind.Array, doc.RootElement.GetProperty("allowlist").ValueKind);
        Assert.Equal(JsonValueKind.Array, doc.RootElement.GetProperty("blocklist").ValueKind);
    }

    [Fact]
    public async Task GetPolicy_Member_Allowed()
    {
        using var c = await MemberClient();
        var resp = await c.GetAsync("/api/v1/license-policy");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task GetPolicy_Anonymous_Rejected()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/license-policy");
        Assert.True(resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound);
    }

    // ── Enforcement mode ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task SetMode_AcceptsValidModes(string mode)
    {
        using var c = await AdminClient();
        var resp = await c.PutAsJsonAsync("/api/v1/license-policy/mode", new { mode });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(mode, doc.RootElement.GetProperty("mode").GetString());

        // Audit row written.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'license_policy_mode_changed'");
        Assert.True(count >= 1);
    }

    [Fact]
    public async Task SetMode_InvalidMode_Returns422()
    {
        using var c = await AdminClient();
        var resp = await c.PutAsJsonAsync("/api/v1/license-policy/mode", new { mode = "panic" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task SetMode_Member_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.PutAsJsonAsync("/api/v1/license-policy/mode", new { mode = "warn" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Allowlist ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Allowlist_AddListRemove_RoundTrip()
    {
        using var c = await AdminClient();
        string spdx = $"MIT-{Guid.NewGuid():N}"[..12];

        var add = await c.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = spdx });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);

        var list = await c.GetAsync("/api/v1/license-policy/allowlist");
        list.EnsureSuccessStatusCode();
        var doc = await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync());
        Assert.Contains(doc.RootElement.EnumerateArray(),
            e => e.GetProperty("licenseSpdx").GetString() == spdx);

        var remove = await c.DeleteAsync($"/api/v1/license-policy/allowlist/{spdx}");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);

        // Re-removing returns 404 — confirms the row really went.
        var removeAgain = await c.DeleteAsync($"/api/v1/license-policy/allowlist/{spdx}");
        Assert.Equal(HttpStatusCode.NotFound, removeAgain.StatusCode);
    }

    [Fact]
    public async Task Allowlist_AddDuplicate_Returns409()
    {
        using var c = await AdminClient();
        string spdx = $"Apache-{Guid.NewGuid():N}"[..15];

        var first = await c.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = spdx });
        first.EnsureSuccessStatusCode();
        var second = await c.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = spdx });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Allowlist_AddBlank_Returns422()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = "   " });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Allowlist_AddByMember_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = "GPL-3.0" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Blocklist (mirrors allowlist, but covers the parallel code path) ──────

    [Fact]
    public async Task Blocklist_AddListRemove_RoundTrip()
    {
        using var c = await AdminClient();
        string spdx = $"WTFPL-{Guid.NewGuid():N}"[..12];

        var add = await c.PostAsJsonAsync("/api/v1/license-policy/blocklist", new { licenseSpdx = spdx });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);

        var list = await c.GetAsync("/api/v1/license-policy/blocklist");
        list.EnsureSuccessStatusCode();
        var doc = await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync());
        Assert.Contains(doc.RootElement.EnumerateArray(),
            e => e.GetProperty("licenseSpdx").GetString() == spdx);

        var remove = await c.DeleteAsync($"/api/v1/license-policy/blocklist/{spdx}");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);
    }

    [Fact]
    public async Task Blocklist_AddDuplicate_Returns409()
    {
        using var c = await AdminClient();
        string spdx = $"BSD-{Guid.NewGuid():N}"[..10];
        var first = await c.PostAsJsonAsync("/api/v1/license-policy/blocklist", new { licenseSpdx = spdx });
        first.EnsureSuccessStatusCode();
        var second = await c.PostAsJsonAsync("/api/v1/license-policy/blocklist", new { licenseSpdx = spdx });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Blocklist_RemoveMissing_Returns404()
    {
        using var c = await AdminClient();
        var resp = await c.DeleteAsync($"/api/v1/license-policy/blocklist/never-existed-{Guid.NewGuid():N}");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task GetPolicy_ReflectsAddedEntries()
    {
        // After a write, GET /license-policy includes the new rows in the aggregated view.
        using var c = await AdminClient();
        string allow = $"ZLIB-{Guid.NewGuid():N}"[..12];
        string block = $"AGPL-{Guid.NewGuid():N}"[..12];

        (await c.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = allow })).EnsureSuccessStatusCode();
        (await c.PostAsJsonAsync("/api/v1/license-policy/blocklist", new { licenseSpdx = block })).EnsureSuccessStatusCode();

        var resp = await c.GetAsync("/api/v1/license-policy");
        resp.EnsureSuccessStatusCode();
        var root = (await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync())).RootElement;
        Assert.Contains(root.GetProperty("allowlist").EnumerateArray(),
            e => e.GetProperty("licenseSpdx").GetString() == allow);
        Assert.Contains(root.GetProperty("blocklist").EnumerateArray(),
            e => e.GetProperty("licenseSpdx").GetString() == block);
    }
}
