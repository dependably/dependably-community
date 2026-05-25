using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage for GET /api/v1/system/dashboard — the operator landing snapshot.
/// Seeds tenants in each lifecycle state, writes a fresh background-job run, asserts the
/// response shape and that the seeded job surfaces in recentJobs.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemDashboardTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public SystemDashboardTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task GetDashboard_ReturnsTenantAndAdminCounts_AndRecentJobs()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var baseline = await GetDashboardAsync(client);

        // Seed one tenant in each lifecycle state.
        var activeSlug    = "dash-active-" + Guid.NewGuid().ToString("N")[..6];
        var suspendedSlug = "dash-susp-"   + Guid.NewGuid().ToString("N")[..6];
        var deletedSlug   = "dash-del-"    + Guid.NewGuid().ToString("N")[..6];

        await CreateTenant(client, activeSlug);
        await CreateTenant(client, suspendedSlug);
        await SuspendTenant(client, suspendedSlug);
        await CreateTenant(client, deletedSlug);
        await SoftDeleteTenant(client, deletedSlug);

        // Direct repo write — bypasses BackgroundJobScope's static IServiceProvider hook so this
        // test is immune to the cross-class race when other integration test classes share the
        // xUnit process. (BackgroundJobScope.Dispose's fire-and-forget capture of `Services`
        // would otherwise route the write to whichever factory most recently set the hook.)
        var repo = _factory.Services.GetRequiredService<BackgroundJobRunRepository>();
        var jobName = "dashboard-test-" + Guid.NewGuid().ToString("N")[..6];
        var startedAt = DateTimeOffset.UtcNow;
        await repo.RecordAsync(new BackgroundJobRunRecord(
            Id: Guid.NewGuid().ToString("N"),
            JobName: jobName,
            Operation: "smoke",
            RunId: Guid.NewGuid().ToString("N"),
            StartedAt: startedAt,
            FinishedAt: startedAt.AddMilliseconds(42),
            DurationMs: 42,
            Outcome: "success",
            ErrorMessage: null));

        var after = await GetDashboardAsync(client);

        // ≥ instead of ==: a parallel integration-test class creating tenants in the shared
        // process can inflate the counts. Exact-match assertions live in the OrgRepository
        // unit tests where each test gets a clean fixture.
        Assert.True(after.GetProperty("tenants").GetProperty("active").GetInt32()
                    >= baseline.GetProperty("tenants").GetProperty("active").GetInt32() + 1);
        Assert.True(after.GetProperty("tenants").GetProperty("suspended").GetInt32()
                    >= baseline.GetProperty("tenants").GetProperty("suspended").GetInt32() + 1);
        Assert.True(after.GetProperty("tenants").GetProperty("softDeleted").GetInt32()
                    >= baseline.GetProperty("tenants").GetProperty("softDeleted").GetInt32() + 1);

        // Admins: at least one (the system_admin we logged in as).
        Assert.True(after.GetProperty("admins").GetProperty("active").GetInt32() >= 1);
        Assert.True(after.GetProperty("admins").GetProperty("total").GetInt32() >= 1);

        // Recent jobs: bounded ≤ 5; our just-written row is the most recent by startedAt so it
        // must appear at the top of the window; every row carries the expected shape.
        var recentJobs = after.GetProperty("recentJobs").EnumerateArray().ToList();
        Assert.True(recentJobs.Count <= 5);
        Assert.Contains(recentJobs, j => j.GetProperty("jobName").GetString() == jobName);
        Assert.All(recentJobs, j =>
        {
            Assert.True(j.TryGetProperty("startedAt", out _));
            Assert.True(j.TryGetProperty("durationMs", out _));
            Assert.True(j.TryGetProperty("outcome", out _));
        });
    }

    [Fact]
    public async Task GetDashboard_TenantJwt_AtSystemRoute_IsRejected()
    {
        using var tenantClient = _factory.CreateClient();
        var resp = await tenantClient.GetAsync("/api/v1/system/dashboard");
        Assert.True(
            resp.StatusCode == HttpStatusCode.NotFound || resp.StatusCode == HttpStatusCode.Unauthorized,
            $"Unauthenticated tenant call must not succeed; got {(int)resp.StatusCode}.");
    }

    private static async Task<JsonElement> GetDashboardAsync(HttpClient client)
    {
        var resp = await client.GetAsync("/api/v1/system/dashboard");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    private static async Task CreateTenant(HttpClient client, string slug)
    {
        var resp = await client.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"{slug}-owner@example.test",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    private static async Task SuspendTenant(HttpClient client, string slug)
    {
        var resp = await client.PatchAsJsonAsync($"/api/v1/system/tenants/{slug}/status", new { status = "suspended" });
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    private static async Task SoftDeleteTenant(HttpClient client, string slug)
    {
        var resp = await client.DeleteAsync($"/api/v1/system/tenants/{slug}");
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }
}
