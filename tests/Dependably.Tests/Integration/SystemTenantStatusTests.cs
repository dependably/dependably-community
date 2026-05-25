using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage for PATCH /api/v1/system/tenants/{slug}/status — the lifecycle gate
/// toggle the SystemTenants.svelte UI calls. Exercises the full HTTP pipeline (auth, route
/// scoping, validation, audit log emission, list-endpoint projection) so any layer regressing
/// shows up here.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemTenantStatusTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public SystemTenantStatusTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(HttpClient client, string slug)> CreateTenantAsync()
    {
        var slug = "s-" + Guid.NewGuid().ToString("N")[..8];
        var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"{slug}-owner@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return (client, slug);
    }

    [Fact]
    public async Task Suspend_ThenActive_RoundTrips_AndShowsInList()
    {
        var (client, slug) = await CreateTenantAsync();
        try
        {
            var suspend = await client.PatchAsJsonAsync(
                $"/api/v1/system/tenants/{slug}/status", new { status = "suspended" });
            Assert.Equal(HttpStatusCode.NoContent, suspend.StatusCode);

            var listResp = await client.GetAsync("/api/v1/system/tenants?limit=200");
            var doc = JsonDocument.Parse(await listResp.Content.ReadAsStringAsync());
            var match = doc.RootElement.GetProperty("items").EnumerateArray()
                .First(i => i.GetProperty("slug").GetString() == slug);
            Assert.Equal("suspended", match.GetProperty("status").GetString());

            var enable = await client.PatchAsJsonAsync(
                $"/api/v1/system/tenants/{slug}/status", new { status = "active" });
            Assert.Equal(HttpStatusCode.NoContent, enable.StatusCode);

            var listAgain = await client.GetAsync("/api/v1/system/tenants?limit=200");
            var doc2 = JsonDocument.Parse(await listAgain.Content.ReadAsStringAsync());
            var match2 = doc2.RootElement.GetProperty("items").EnumerateArray()
                .First(i => i.GetProperty("slug").GetString() == slug);
            Assert.Equal("active", match2.GetProperty("status").GetString());
        }
        finally { client.Dispose(); }
    }

    [Theory]
    [InlineData("archived")]
    [InlineData("deleting")]
    [InlineData("bogus")]
    public async Task Suspend_InvalidStatus_Returns422(string status)
    {
        var (client, slug) = await CreateTenantAsync();
        try
        {
            var resp = await client.PatchAsJsonAsync(
                $"/api/v1/system/tenants/{slug}/status", new { status });
            Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        }
        finally { client.Dispose(); }
    }

    [Fact]
    public async Task Suspend_UnknownSlug_Returns404()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PatchAsJsonAsync(
            "/api/v1/system/tenants/ghost-status/status", new { status = "suspended" });
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Suspend_WritesAuditEvent_WithPriorStatusInDetail()
    {
        var (client, slug) = await CreateTenantAsync();
        try
        {
            // Default state is 'active' immediately after create.
            await client.PatchAsJsonAsync(
                $"/api/v1/system/tenants/{slug}/status", new { status = "suspended" });

            var db = _factory.Services.GetRequiredService<IMetadataStore>();
            await using var conn = await db.OpenAsync();
            var detail = await conn.QuerySingleAsync<string>(
                """
                SELECT detail FROM audit_log
                WHERE scope = 'system' AND action = 'tenant.status_changed'
                  AND detail LIKE @needle
                ORDER BY created_at DESC LIMIT 1
                """,
                new { needle = $"%{slug}%" });

            var doc = JsonDocument.Parse(detail);
            Assert.Equal(slug, doc.RootElement.GetProperty("slug").GetString());
            Assert.Equal("suspended", doc.RootElement.GetProperty("status").GetString());
            Assert.Equal("active", doc.RootElement.GetProperty("priorStatus").GetString());
        }
        finally { client.Dispose(); }
    }

    [Fact]
    public async Task Suspend_TenantJwt_AtSystemRoute_IsRejected()
    {
        // RouteScopeFilter returns 404 (not 403) to avoid leaking surface existence to
        // non-system callers; unauthenticated tenant calls get 401.
        var (sysClient, slug) = await CreateTenantAsync();
        sysClient.Dispose();

        using var tenantClient = _factory.CreateClient();
        var resp = await tenantClient.PatchAsJsonAsync(
            $"/api/v1/system/tenants/{slug}/status", new { status = "suspended" });
        Assert.True(
            resp.StatusCode == HttpStatusCode.NotFound || resp.StatusCode == HttpStatusCode.Unauthorized,
            $"Unauthenticated tenant call must not succeed; got {(int)resp.StatusCode}.");
    }
}
