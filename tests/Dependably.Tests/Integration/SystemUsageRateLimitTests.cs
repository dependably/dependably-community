using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the per-caller <c>usage-report</c> rate-limit policy on the apex fleet-usage routes
/// (<c>GET /api/v1/system/usage</c>, <c>/usage.csv</c>, <c>/tenants/{slug}/usage</c>).
///
/// <para>
/// Each test boots its own <see cref="DependablyMultiFactory"/> with a tight
/// <c>USAGE_REPORT_RATE_LIMIT_PERMITS</c>, leaving the management default raised, so the only
/// thing that can produce a 429 is the usage-report policy. The system-admin client is one
/// principal, so every request lands in one <c>user:</c> partition. The twins pin the policy's
/// reach: other apex routes keep their own budget, and a tenant caller's request is still refused
/// by route scoping rather than by the limiter.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemUsageRateLimitTests
{
    private const int PermitLimit = 3;
    private const int BurstSize = 8;

    private static DependablyMultiFactory NewFactory() => new()
    {
        Settings = new Dictionary<string, string>
        {
            ["USAGE_REPORT_RATE_LIMIT_PERMITS"] = PermitLimit.ToString(System.Globalization.CultureInfo.InvariantCulture),
        },
    };

    private static async Task<(string OrgId, string Slug)> CreateTenantAsync(DependablyMultiFactory factory)
    {
        string slug = "url-" + Guid.NewGuid().ToString("N")[..8];
        using var sysClient = await factory.CreateSystemAdminClient();
        var createResp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, createResp.StatusCode);
        var createDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync());
        string orgId = createDoc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;
        return (orgId, slug);
    }

    private static async Task<List<HttpResponseMessage>> BurstAsync(HttpClient client, string path, int count)
    {
        var responses = new List<HttpResponseMessage>();
        for (int i = 0; i < count; i++)
        {
            responses.Add(await client.GetAsync(path));
        }

        return responses;
    }

    [Theory]
    [InlineData("/api/v1/system/usage")]
    [InlineData("/api/v1/system/usage.csv")]
    [InlineData("/api/v1/system/tenants/{slug}/usage")]
    public async Task Burst_over_the_ceiling_is_throttled_with_Retry_After(string route)
    {
        await using var factory = NewFactory();
        await factory.InitializeAsync();
        var (_, slug) = await CreateTenantAsync(factory);
        using var client = await factory.CreateSystemAdminClient();

        var responses = await BurstAsync(client, route.Replace("{slug}", slug, StringComparison.Ordinal), BurstSize);
        var statuses = responses.Select(r => r.StatusCode).ToList();

        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
        // The calls before the ceiling trips succeed, so the 429s are the policy tripping rather
        // than every call failing for an unrelated reason.
        Assert.Contains(HttpStatusCode.OK, statuses);

        var rejected = responses.First(r => r.StatusCode == HttpStatusCode.TooManyRequests);
        Assert.True(rejected.Headers.Contains("Retry-After"), "a 429 must carry Retry-After");
    }

    [Fact]
    public async Task Requests_within_the_ceiling_are_never_throttled()
    {
        await using var factory = NewFactory();
        await factory.InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        var statuses = (await BurstAsync(client, "/api/v1/system/usage", PermitLimit)).Select(r => r.StatusCode).ToList();

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, statuses);
        Assert.All(statuses, s => Assert.Equal(HttpStatusCode.OK, s));
    }

    [Fact]
    public async Task Exhausted_usage_budget_does_not_throttle_other_apex_routes()
    {
        await using var factory = NewFactory();
        await factory.InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        var usage = (await BurstAsync(client, "/api/v1/system/usage", BurstSize)).Select(r => r.StatusCode).ToList();
        Assert.Contains(HttpStatusCode.TooManyRequests, usage);

        var tenants = (await BurstAsync(client, "/api/v1/system/tenants", BurstSize)).Select(r => r.StatusCode).ToList();

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, tenants);
        Assert.All(tenants, s => Assert.Equal(HttpStatusCode.OK, s));
    }

    [Fact]
    public async Task Tenant_caller_is_refused_by_route_scoping_not_by_the_exhausted_budget()
    {
        await using var factory = NewFactory();
        await factory.InitializeAsync();
        var (orgId, slug) = await CreateTenantAsync(factory);
        using var client = await factory.CreateSystemAdminClient();

        var usage = (await BurstAsync(client, "/api/v1/system/usage", BurstSize)).Select(r => r.StatusCode).ToList();
        Assert.Contains(HttpStatusCode.TooManyRequests, usage);

        string ownerId;
        await using (var conn = await factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId LIMIT 1", new { orgId })
                ?? throw new InvalidOperationException("owner user missing");
        }

        string ownerJwt = await factory.CreateTenantJwt(userId: ownerId, tenantId: orgId, role: "owner");
        using var tenantClient = factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        tenantClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ownerJwt);

        var resp = await tenantClient.GetAsync("/api/v1/system/usage");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
