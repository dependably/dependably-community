using System.Net;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage for GET /api/v1/system/background-jobs — the data behind the new
/// "Background Jobs" tab on the sysadmin Audit page. Verifies that a real
/// <see cref="BackgroundJobScope"/> cycle produces a row visible through the HTTP surface,
/// that filtering works, that the facets endpoint returns the inserted job name, and that
/// the route requires system-admin auth.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemBackgroundJobsTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public SystemBackgroundJobsTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task BackgroundJobScope_RoundTripsThroughTheListEndpoint()
    {
        // Wire the static persistence hook the way Program.cs does at startup. The factory
        // shares one app.Services across all tests in the class fixture, so this is a no-op
        // on subsequent calls — fine, the hook is idempotent.
        BackgroundJobScope.Services = _factory.Services;

        string uniqueJob = "test-job-" + Guid.NewGuid().ToString("N")[..8];
        using (var scope = BackgroundJobScope.Begin(uniqueJob, "smoke-tick"))
        {
            scope.Complete();
        }

        // Persistence is fire-and-forget — give the Task.Run a moment to hit the DB before
        // we read it back. Short retry loop avoids a sleep race on slower CI hardware.
        JsonElement match = default;
        using var client = await _factory.CreateSystemAdminClient();
        for (int attempt = 0; attempt < 30; attempt++)
        {
            var resp = await client.GetAsync($"/api/v1/system/background-jobs?jobName={uniqueJob}&limit=50");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var items = doc.RootElement.GetProperty("items");
            if (items.GetArrayLength() > 0)
            {
                match = items[0].Clone();
                break;
            }
            await Task.Delay(50);
        }

        Assert.True(match.ValueKind == JsonValueKind.Object, "Background-job row must appear via the endpoint.");
        Assert.Equal(uniqueJob, match.GetProperty("jobName").GetString());
        Assert.Equal("smoke-tick", match.GetProperty("operation").GetString());
        Assert.Equal("success", match.GetProperty("outcome").GetString());

        // Facets surface the inserted job name for the filter dropdown.
        var facetsResp = await client.GetAsync("/api/v1/system/background-jobs/facets");
        Assert.Equal(HttpStatusCode.OK, facetsResp.StatusCode);
        var facets = JsonDocument.Parse(await facetsResp.Content.ReadAsStringAsync());
        var jobNames = facets.RootElement.GetProperty("jobNames").EnumerateArray()
            .Select(e => e.GetString()).ToList();
        Assert.Contains(uniqueJob, jobNames);
    }

    [Fact]
    public async Task ListBackgroundJobs_FiltersByOutcome()
    {
        BackgroundJobScope.Services = _factory.Services;
        string name = "test-outcome-" + Guid.NewGuid().ToString("N")[..8];

        using (var ok = BackgroundJobScope.Begin(name, "ok")) { ok.Complete(); }
        using (var bad = BackgroundJobScope.Begin(name, "bad")) { bad.Fail(new InvalidOperationException("boom")); }

        // Wait for both rows to land. We loop on the unfiltered count so we don't race the
        // outcome filter on a partially-flushed pair.
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        for (int attempt = 0; attempt < 30; attempt++)
        {
            await using var conn = await db.OpenAsync();
            int count = await Dapper.SqlMapper.ExecuteScalarAsync<int>(conn,
                "SELECT COUNT(*) FROM background_job_runs WHERE job_name = @name",
                new { name });
            if (count >= 2)
            {
                break;
            }

            await Task.Delay(50);
        }

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync(
            $"/api/v1/system/background-jobs?jobName={name}&outcome=server_error&limit=50");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var items = doc.RootElement.GetProperty("items").EnumerateArray().ToList();

        Assert.NotEmpty(items);
        Assert.All(items, e => Assert.Equal("server_error", e.GetProperty("outcome").GetString()));
        Assert.All(items, e => Assert.Equal("bad", e.GetProperty("operation").GetString()));
    }

    [Fact]
    public async Task ListBackgroundJobs_TenantJwt_AtSystemRoute_IsRejected()
    {
        using var tenantClient = _factory.CreateClient();
        var resp = await tenantClient.GetAsync("/api/v1/system/background-jobs");
        Assert.True(
            resp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Unauthorized,
            $"Unauthenticated tenant call must not succeed; got {(int)resp.StatusCode}.");
    }
}
