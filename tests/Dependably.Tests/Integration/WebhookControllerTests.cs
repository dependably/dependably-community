using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Api;
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

    /// <summary>
    /// Subscriptions are capped per org. One event fans out to every matching subscription, and
    /// the dispatch queue gives each org's envelope a bounded time budget, so an uncapped list
    /// lets one org queue more delivery work per event than any envelope can attempt — and makes
    /// the size of that fan-out a tenant-chosen number. The cap is refused as a validation error,
    /// not silently accepted, and the existing subscriptions are untouched.
    /// </summary>
    [Fact]
    public async Task Create_PastThePerOrgCap_ReturnsValidationError()
    {
        using var c = await AdminClient();
        var existing = await c.GetFromJsonAsync<JsonElement>("/api/v1/webhooks");
        int already = existing.GetArrayLength();

        var created = new List<string>();
        try
        {
            for (int i = already; i < WebhookController.MaxSubscriptionsPerOrg; i++)
            {
                var fill = await c.PostAsJsonAsync("/api/v1/webhooks", new
                {
                    url = $"https://hooks.example.com/cap-{i}",
                    eventTypes = new[] { "package.publish" }
                });
                Assert.Equal(HttpStatusCode.Created, fill.StatusCode);
                using var doc = JsonDocument.Parse(await fill.Content.ReadAsStringAsync());
                created.Add(doc.RootElement.GetProperty("id").GetString()!);
            }

            var overCap = await c.PostAsJsonAsync("/api/v1/webhooks", new
            {
                url = "https://hooks.example.com/over-the-cap",
                eventTypes = new[] { "package.publish" }
            });
            Assert.Equal(HttpStatusCode.UnprocessableEntity, overCap.StatusCode);

            var list = await c.GetFromJsonAsync<JsonElement>("/api/v1/webhooks");
            Assert.Equal(WebhookController.MaxSubscriptionsPerOrg, list.GetArrayLength());
            Assert.DoesNotContain(list.EnumerateArray(), e =>
                e.GetProperty("url").GetString() == "https://hooks.example.com/over-the-cap");
        }
        finally
        {
            // The factory's org is shared across this class's tests; leave the list as found.
            foreach (string id in created)
            {
                await c.DeleteAsync($"/api/v1/webhooks/{id}");
            }
        }
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
