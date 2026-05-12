using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class InstanceControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public InstanceControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        var jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    [Fact]
    public async Task Anonymous_Get_Returns401Or404()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.True(resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Member_Get_Returns403()
    {
        // tenant:admin is owner-only; a plain member is rejected even though authenticated.
        var memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "Password12345");
        var jwt = await _factory.CreateUserJwt(memberId, "member");
        using var c = _factory.CreateClientWithBearer(jwt);

        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Admin_GetSettings_Returns200WithDictionary_AndOmitsJwtSecret()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);

        // jwt_secret is filtered from the public response — checking the field is missing
        // pins that the controller never accidentally surfaces it.
        Assert.False(doc.RootElement.TryGetProperty("jwt_secret", out _));
    }

    [Fact]
    public async Task Admin_UpdateSettings_PersistsAndAudits()
    {
        using var c = await AdminClient();
        var body = JsonContent.Create(new Dictionary<string, string>
        {
            ["max_upload_bytes"] = "1048576",
            ["max_upload_bytes_npm"] = "524288",
        });

        var resp = await c.PutAsync("/api/v1/instance/settings", body);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        // Verify the rows landed.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var value = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes' LIMIT 1");
        Assert.Equal("1048576", value);

        // Audit row recorded for the change.
        var audited = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'instance_settings_updated'");
        Assert.True(audited >= 1);
    }

    [Fact]
    public async Task Admin_UpdateSettings_RejectsUnknownKey()
    {
        using var c = await AdminClient();
        var body = JsonContent.Create(new Dictionary<string, string> { ["totally_unknown"] = "nope" });

        var resp = await c.PutAsync("/api/v1/instance/settings", body);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var detail = await resp.Content.ReadAsStringAsync();
        Assert.Contains("totally_unknown", detail);
    }
}
