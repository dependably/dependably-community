using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Webhooks;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

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

    [Fact]
    public async Task Create_WithBlockedEventType_IsAccepted()
    {
        // Pins ValidEventTypes actually containing package.blocked end to end — a deleted
        // registration line would otherwise leave the whole suite green (nothing else exercises
        // the accept path for this specific literal).
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/webhooks", new
        {
            url = "https://hooks.example.com/blocked-events",
            eventTypes = new[] { "package.blocked" }
        });
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal("package.blocked",
            Assert.Single(doc.RootElement.GetProperty("eventTypes").EnumerateArray()).GetString());

        await c.DeleteAsync($"/api/v1/webhooks/{doc.RootElement.GetProperty("id").GetString()}");
    }

    [Fact]
    public async Task Create_WithUnknownEventType_ReturnsValidationError()
    {
        // Pins the reject side of the same validation: an unrecognised event-type literal never
        // reaches a stored subscription.
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/webhooks", new
        {
            url = "https://hooks.example.com/unknown-event",
            eventTypes = new[] { "package.not-a-real-event" }
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"hook-member-{Guid.NewGuid():N}@example.com", "Password12345");
        return _factory.CreateClientWithBearer(await _factory.CreateUserJwt(id, "member"));
    }

    private async Task<HttpClient> ClientWithCaps(params string[] caps)
    {
        string id = await _factory.CreateUser($"hook-caps-{Guid.NewGuid():N}@example.com", "Password12345");
        return _factory.CreateClientWithBearer(await _factory.CreateUserJwtWithCaps(id, caps));
    }

    private static async Task<string> CreateHook(HttpClient c, string path, string? description = null)
    {
        var resp = await c.PostAsJsonAsync("/api/v1/webhooks", new
        {
            url = $"https://hooks.example.com/{path}",
            eventTypes = new[] { "package.publish" },
            description,
        });
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        return (await ProblemBody.ReadAsync(resp)).GetProperty("id").GetString()!;
    }

    /// <summary>Seeds a subscription directly into a second org, outside the admin's tenant.</summary>
    private async Task<(string OrgId, string HookId)> SeedForeignHook()
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var other = await orgs.CreateOrgAsync($"hk-{Guid.NewGuid():N}"[..14]);
        var repo = _factory.Services.GetRequiredService<WebhookSubscriptionRepository>();
        var sub = await repo.AddAsync(other.Id, new NewWebhookSubscription(
            "https://other-org.example.com/hook", new[] { "package.yank" }, null, "foreign"));
        return (other.Id, sub.Id);
    }

    [Fact]
    public async Task Mutations_WithoutTenantConfigure_AreForbiddenAndChangeNothing()
    {
        using var admin = await AdminClient();
        string id = await CreateHook(admin, $"guarded-{Guid.NewGuid():N}");
        int before = (await admin.GetFromJsonAsync<JsonElement>("/api/v1/webhooks")).GetArrayLength();

        using var member = await MemberClient();
        using var reader = await ClientWithCaps("read:tenant");
        foreach (var c in new[] { member, reader })
        {
            var body = new { url = "https://hooks.example.com/changed", eventTypes = new[] { "package.yank" } };

            await ProblemBody.AssertForbiddenAsync(await c.PostAsJsonAsync("/api/v1/webhooks", body));
            await ProblemBody.AssertForbiddenAsync(await c.PutAsJsonAsync($"/api/v1/webhooks/{id}", body));
            await ProblemBody.AssertForbiddenAsync(await c.DeleteAsync($"/api/v1/webhooks/{id}"));
            await ProblemBody.AssertForbiddenAsync(await c.PostAsync($"/api/v1/webhooks/{id}/test", null));
        }

        // The tenant reader still sees the list: the denial is capability-specific.
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/webhooks")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/api/v1/webhooks/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.GetAsync("/api/v1/webhooks")).StatusCode);

        var after = await admin.GetFromJsonAsync<JsonElement>("/api/v1/webhooks");
        Assert.Equal(before, after.GetArrayLength());
        var kept = await admin.GetFromJsonAsync<JsonElement>($"/api/v1/webhooks/{id}");
        Assert.NotEqual("https://hooks.example.com/changed", kept.GetProperty("url").GetString());
        await admin.DeleteAsync($"/api/v1/webhooks/{id}");
    }

    [Fact]
    public async Task Reads_WithoutReadTenant_AreForbidden()
    {
        using var c = await ClientWithCaps("read:packages");

        await ProblemBody.AssertForbiddenAsync(await c.GetAsync("/api/v1/webhooks"));
        await ProblemBody.AssertForbiddenAsync(await c.GetAsync("/api/v1/webhooks/anything"));
    }

    [Theory]
    [InlineData("", "package.publish", null, "url")]
    [InlineData("   ", "package.publish", null, "url")]
    [InlineData("https://hooks.example.com/x", null, null, "eventTypes")]
    [InlineData("http://169.254.169.254/latest/meta-data", "package.publish", null, "url")]
    [InlineData("ftp://hooks.example.com/x", "package.publish", null, "url")]
    [InlineData("https://hooks.example.com/x", "package.publish", "TOO_LONG", "description")]
    public async Task CreateAndUpdate_InvalidBody_ReturnsValidationProblemNamingTheField(
        string url, string? eventType, string? description, string field)
    {
        using var c = await AdminClient();
        string id = await CreateHook(c, $"validate-{Guid.NewGuid():N}");
        string? desc = description == "TOO_LONG" ? new string('d', 501) : description;
        var body = new
        {
            url,
            eventTypes = eventType is null ? Array.Empty<string>() : new[] { eventType },
            description = desc,
        };

        await ProblemBody.AssertValidationAsync(await c.PostAsJsonAsync("/api/v1/webhooks", body), field);
        await ProblemBody.AssertValidationAsync(await c.PutAsJsonAsync($"/api/v1/webhooks/{id}", body), field);

        // The rejected update left the stored subscription as created.
        var kept = await c.GetFromJsonAsync<JsonElement>($"/api/v1/webhooks/{id}");
        Assert.StartsWith("https://hooks.example.com/validate-", kept.GetProperty("url").GetString());
        await c.DeleteAsync($"/api/v1/webhooks/{id}");
    }

    [Fact]
    public async Task Update_ReplacesFieldsAndAllowsDisabling()
    {
        using var c = await AdminClient();
        string id = await CreateHook(c, $"update-{Guid.NewGuid():N}", "before");

        var resp = await c.PutAsJsonAsync($"/api/v1/webhooks/{id}", new
        {
            url = "https://hooks.example.com/updated",
            eventTypes = new[] { "package.yank", "package.unlist" },
            enabled = false,
            description = "after",
        });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await ProblemBody.ReadAsync(resp);
        Assert.Equal("https://hooks.example.com/updated", body.GetProperty("url").GetString());
        Assert.False(body.GetProperty("enabled").GetBoolean());
        Assert.Equal("after", body.GetProperty("description").GetString());
        Assert.Equal(
            new[] { "package.yank", "package.unlist" },
            body.GetProperty("eventTypes").EnumerateArray().Select(e => e.GetString()).ToArray());

        // enabled is optional on the wire and defaults to on.
        var reenabled = await c.PutAsJsonAsync($"/api/v1/webhooks/{id}", new
        {
            url = "https://hooks.example.com/updated",
            eventTypes = new[] { "package.yank" },
        });
        Assert.True((await ProblemBody.ReadAsync(reenabled)).GetProperty("enabled").GetBoolean());
        await c.DeleteAsync($"/api/v1/webhooks/{id}");
    }

    [Fact]
    public async Task UnknownId_Returns404OnGetUpdateAndTest_AndDeleteIsIdempotent()
    {
        using var c = await AdminClient();
        string missing = Guid.NewGuid().ToString("N");
        var body = new { url = "https://hooks.example.com/x", eventTypes = new[] { "package.publish" } };

        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/api/v1/webhooks/{missing}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PutAsJsonAsync($"/api/v1/webhooks/{missing}", body)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PostAsync($"/api/v1/webhooks/{missing}/test", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/api/v1/webhooks/{missing}")).StatusCode);
    }

    [Fact]
    public async Task Delete_RemovesOnlyTheNamedSubscription()
    {
        using var c = await AdminClient();
        string doomed = await CreateHook(c, $"doomed-{Guid.NewGuid():N}");
        string kept = await CreateHook(c, $"kept-{Guid.NewGuid():N}");

        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/api/v1/webhooks/{doomed}")).StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/api/v1/webhooks/{doomed}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync($"/api/v1/webhooks/{kept}")).StatusCode);
        await c.DeleteAsync($"/api/v1/webhooks/{kept}");
    }

    [Fact]
    public async Task TestPing_ForOwnSubscription_Returns204()
    {
        using var c = await AdminClient();
        string id = await CreateHook(c, $"ping-{Guid.NewGuid():N}");

        Assert.Equal(HttpStatusCode.NoContent, (await c.PostAsync($"/api/v1/webhooks/{id}/test", null)).StatusCode);
        await c.DeleteAsync($"/api/v1/webhooks/{id}");
    }

    [Fact]
    public async Task ForeignOrgSubscription_IsInvisibleAndUntouchable()
    {
        var (otherOrgId, foreignId) = await SeedForeignHook();
        using var c = await AdminClient();
        var body = new { url = "https://hooks.example.com/hijack", eventTypes = new[] { "package.publish" } };

        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/api/v1/webhooks/{foreignId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PutAsJsonAsync($"/api/v1/webhooks/{foreignId}", body)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PostAsync($"/api/v1/webhooks/{foreignId}/test", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/api/v1/webhooks/{foreignId}")).StatusCode);
        var list = await c.GetFromJsonAsync<JsonElement>("/api/v1/webhooks");
        Assert.DoesNotContain(list.EnumerateArray(), e => e.GetProperty("id").GetString() == foreignId);

        // The other org's row is exactly as seeded after the delete and update attempts.
        var repo = _factory.Services.GetRequiredService<WebhookSubscriptionRepository>();
        var intact = await repo.GetAsync(otherOrgId, foreignId);
        Assert.NotNull(intact);
        Assert.Equal("https://other-org.example.com/hook", intact.Url);
        Assert.Equal("foreign", intact.Description);
    }

    [Fact]
    public async Task Secret_WithMasterKey_IsStoredRotatedAndKeptWhenOmitted()
    {
        await using var factory = new DependablyFactory
        {
            MasterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
        };
        await factory.InitializeAsync();
        using var c = factory.CreateClientWithBearer(await factory.CreateAdminJwt());

        var created = await c.PostAsJsonAsync("/api/v1/webhooks", new
        {
            url = "https://hooks.example.com/signed",
            eventTypes = new[] { "package.publish" },
            secret = "initial-signing-secret",
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var createdBody = await ProblemBody.ReadAsync(created);
        Assert.True(createdBody.GetProperty("hasSecret").GetBoolean());
        Assert.False(createdBody.TryGetProperty("secret", out _));
        string id = createdBody.GetProperty("id").GetString()!;

        var rotated = await c.PutAsJsonAsync($"/api/v1/webhooks/{id}", new
        {
            url = "https://hooks.example.com/signed",
            eventTypes = new[] { "package.publish" },
            secret = "rotated-signing-secret",
        });
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        Assert.True((await ProblemBody.ReadAsync(rotated)).GetProperty("hasSecret").GetBoolean());

        var kept = await c.PutAsJsonAsync($"/api/v1/webhooks/{id}", new
        {
            url = "https://hooks.example.com/signed",
            eventTypes = new[] { "package.publish" },
        });
        Assert.True((await ProblemBody.ReadAsync(kept)).GetProperty("hasSecret").GetBoolean());
    }

    [Fact]
    public async Task Update_WithSecretButNoMasterKey_ReturnsValidationProblem()
    {
        using var c = await AdminClient();
        string id = await CreateHook(c, $"nokey-{Guid.NewGuid():N}");

        var resp = await c.PutAsJsonAsync($"/api/v1/webhooks/{id}", new
        {
            url = "https://hooks.example.com/nokey",
            eventTypes = new[] { "package.publish" },
            secret = "cannot-be-stored",
        });

        await ProblemBody.AssertValidationAsync(resp, "secret");
        var kept = await c.GetFromJsonAsync<JsonElement>($"/api/v1/webhooks/{id}");
        Assert.False(kept.GetProperty("hasSecret").GetBoolean());
        await c.DeleteAsync($"/api/v1/webhooks/{id}");
    }
}
