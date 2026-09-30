using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// <c>DEFAULT_USAGE_CAPS</c> end to end in multi mode: a tenant with no <c>org_usage_caps</c> rows
/// is enforced by the default, <c>GET .../usage-limits</c> separates explicit from inherited caps,
/// an explicit cap exempts a tenant and clearing it returns the tenant to the default, and a
/// malformed value refuses to boot.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemUsageLimitsDefaultCapsTests : IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory = new()
    {
        Settings = new Dictionary<string, string>
        {
            [DefaultUsageCaps.ConfigKey] = "egress_bytes=1000,artifact_count=500",
        },
    };

    public Task InitializeAsync() => _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private static string Path(string slug) => $"/api/v1/system/tenants/{slug}/usage-limits";

    private static async Task<(string OrgId, string Slug)> CreateTenantAsync(HttpClient sysClient)
    {
        string slug = "dc-" + Guid.NewGuid().ToString("N")[..8];
        var resp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"{slug}-owner@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return (doc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!, slug);
    }

    private static Task<HttpResponseMessage> PatchAsync(HttpClient client, string slug, string capsJson) =>
        client.PatchAsync(Path(slug), new StringContent($$"""{"caps":{{capsJson}}}""", Encoding.UTF8, "application/json"));

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    private async Task SeedEgressAsync(string orgId, long quantity)
    {
        var now = _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow();
        string bucket = new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero).ToUtcIso();
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO usage_hourly (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
            VALUES (@orgId, 'egress_bytes', @bucket, @quantity, 0, 1, @bucket)
            """,
            new { orgId, bucket, quantity });
    }

    private async Task<HttpResponseMessage> PublishOnTenantHostAsync(string orgId, string slug)
    {
        var (raw, _) = await _factory.Services.GetRequiredService<TokenRepository>().CreateServiceTokenAsync(
            orgId, $"pub-{Guid.NewGuid():N}"[..16], """["publish:*","read:artifact","read:metadata"]""", expiresAt: null);
        using var client = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        string name = $"dc-{Guid.NewGuid():N}"[..20];
        return await client.PutAsync(
            $"/npm/{name}",
            new StringContent(NpmFixtures.BuildPublishBody(name, "1.0.0"), Encoding.UTF8, "application/json"));
    }

    [Fact]
    public async Task Get_separates_explicit_default_and_effective_caps()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (_, slug) = await CreateTenantAsync(sys);

        var fresh = await JsonAsync(await sys.GetAsync(Path(slug)));
        Assert.Empty(fresh.GetProperty("caps").EnumerateObject());
        Assert.Equal(1000, fresh.GetProperty("defaultCaps").GetProperty("egress_bytes").GetInt64());
        Assert.Equal(500, fresh.GetProperty("defaultCaps").GetProperty("artifact_count").GetInt64());
        Assert.Equal(1000, fresh.GetProperty("effectiveCaps").GetProperty("egress_bytes").GetInt64());
        Assert.Equal(500, fresh.GetProperty("effectiveCaps").GetProperty("artifact_count").GetInt64());

        using var patch = await PatchAsync(sys, slug, """{"egress_bytes":7,"storage_bytes":9}""");
        var body = await JsonAsync(patch);
        var caps = body.GetProperty("caps");
        Assert.Equal(2, caps.EnumerateObject().Count());
        Assert.Equal(7, caps.GetProperty("egress_bytes").GetInt64());
        Assert.Equal(9, caps.GetProperty("storage_bytes").GetInt64());
        var effective = body.GetProperty("effectiveCaps");
        Assert.Equal(3, effective.EnumerateObject().Count());
        Assert.Equal(7, effective.GetProperty("egress_bytes").GetInt64());
        Assert.Equal(9, effective.GetProperty("storage_bytes").GetInt64());
        Assert.Equal(500, effective.GetProperty("artifact_count").GetInt64());
        Assert.Equal(2, body.GetProperty("defaultCaps").EnumerateObject().Count());
    }

    [Fact]
    public async Task A_tenant_with_no_rows_is_enforced_by_the_default_until_an_explicit_cap_exempts_it()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (orgId, slug) = await CreateTenantAsync(sys);
        await SeedEgressAsync(orgId, 2000);

        // A PATCH naming only an unrelated meter still recomputes against the inherited egress cap.
        using (var recompute = await PatchAsync(sys, slug, """{"storage_bytes":null}"""))
        {
            var body = await JsonAsync(recompute);
            Assert.Empty(body.GetProperty("caps").EnumerateObject());
            Assert.Equal("downloads_throttled", body.GetProperty("usagePosture").GetString());
        }

        using (var refused = await PublishOnTenantHostAsync(orgId, slug))
        {
            Assert.Equal(HttpStatusCode.PaymentRequired, refused.StatusCode);
        }

        // An explicit cap above the default exempts the tenant.
        using (var exempt = await PatchAsync(sys, slug, """{"egress_bytes":9223372036854775807}"""))
        {
            Assert.Equal("normal", (await JsonAsync(exempt)).GetProperty("usagePosture").GetString());
        }

        using (var served = await PublishOnTenantHostAsync(orgId, slug))
        {
            Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        }

        // Clearing the explicit cap returns the meter to the default.
        using var cleared = await PatchAsync(sys, slug, """{"egress_bytes":null}""");
        Assert.Equal("downloads_throttled", (await JsonAsync(cleared)).GetProperty("usagePosture").GetString());
    }

    [Fact]
    public async Task The_hourly_sweep_enforces_the_default_on_a_tenant_nobody_has_touched()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (orgId, _) = await CreateTenantAsync(sys);
        await SeedEgressAsync(orgId, 1000);

        var postures = _factory.Services.GetRequiredService<UsagePostureRepository>();
        await postures.RecomputeAsync();

        Assert.Equal(UsagePostures.UploadsRefused, await postures.GetPostureAsync(orgId));
    }

    [Fact]
    public async Task A_malformed_value_refuses_to_boot()
    {
        await using var bad = new DependablyMultiFactory
        {
            Settings = new Dictionary<string, string> { [DefaultUsageCaps.ConfigKey] = "egress_bytes=1000,requests=5" },
        };

        var ex = await Record.ExceptionAsync(bad.InitializeAsync);

        Assert.NotNull(ex);
        Assert.Contains("requests=5", ex.ToString());
    }
}
