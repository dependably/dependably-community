using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Management API for user-configured webhook subscriptions. The factory runs with no
/// DEPENDABLY_MASTER_KEY — matching the default deployment and the DAST environment —
/// so these exercise the unsigned-webhook paths that a master-key-only unit setup misses.
/// </summary>
[Trait("Category", "Integration")]
public sealed class WebhookControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public WebhookControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    [Fact]
    public async Task CreateThenList_NoMasterKey_ReturnsCamelCaseJsonArray()
    {
        // Create an unsigned webhook, then list. List must materialize the row (a typeless
        // computed column previously failed RawRow materialization → 500) and serialize as
        // a real camelCase JSON array, not a double-encoded string.
        using var c = await AdminClient();

        var create = await c.PostAsJsonAsync("/api/v1/webhooks", new
        {
            url = "https://hooks.example.com/endpoint",
            eventTypes = new[] { "package.publish" }
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);

        var list = await c.GetAsync("/api/v1/webhooks");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);

        using var doc = await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync());
        Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
        Assert.Contains(doc.RootElement.EnumerateArray(), e =>
            e.GetProperty("url").GetString() == "https://hooks.example.com/endpoint"
            && !e.GetProperty("hasSecret").GetBoolean());
    }

    [Fact]
    public async Task Create_WithSecretButNoMasterKey_ReturnsValidationError()
    {
        // A signing secret is credential-class and can only be stored when the master key
        // is configured — otherwise a clean 400, never an unhandled 500.
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/webhooks", new
        {
            url = "https://hooks.example.com/signed",
            eventTypes = new[] { "package.publish" },
            secret = "a-real-secret"
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }
}
