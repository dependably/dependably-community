using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

/// <summary>
/// Every tenant resolver strategy carries <c>orgs.usage_posture</c> into
/// <see cref="TenantContext.UsagePosture"/> from the same lookup that reads <c>status</c>, so the
/// usage-cap gate and the throttled rate-limit partition read it in O(1). A resolver that dropped
/// the column would leave its deployment mode silently unenforced.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantResolverUsagePostureTests : IAsyncLifetime
{
    private const string TrustedProxy = "10.9.9.1";

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, usage_posture) VALUES ('org-acme', 'acme', 'downloads_throttled')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    private async Task SetPostureAsync(string posture)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("UPDATE orgs SET usage_posture = @posture WHERE id = 'org-acme'", new { posture });
    }

    public static TheoryData<string> Strategies => new() { "single", "bound", "header", "subdomain" };

    private async Task<TenantContext> ResolveAsync(string strategy)
    {
        var ctx = new DefaultHttpContext();
        ITenantResolver resolver;
        switch (strategy)
        {
            case "single":
                resolver = new SingleTenantResolver(_db);
                break;
            case "bound":
                resolver = new DeploymentBoundTenantResolver(_db, Cfg(("BOUND_TENANT_SLUG", "acme")));
                break;
            case "header":
                resolver = new HeaderTenantResolver(_db, Cfg(("TRUSTED_PROXIES", TrustedProxy)));
                ctx.Request.Headers["X-Dependably-Tenant"] = "acme";
                ctx.Items[OriginalPeerMiddleware.HttpItemsKey] = IPAddress.Parse(TrustedProxy);
                break;
            default:
                // No cache, so each resolve reads the row as it stands.
                resolver = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")));
                ctx.Request.Host = new HostString("acme.example.com");
                break;
        }

        return await resolver.ResolveAsync(ctx);
    }

    [Theory]
    [MemberData(nameof(Strategies))]
    public async Task Each_resolver_carries_the_stored_posture(string strategy)
    {
        var tenant = await ResolveAsync(strategy);

        Assert.True(tenant.IsTenant);
        Assert.Equal(UsagePostures.DownloadsThrottled, tenant.UsagePosture);

        await SetPostureAsync(UsagePostures.UploadsRefused);
        Assert.Equal(UsagePostures.UploadsRefused, (await ResolveAsync(strategy)).UsagePosture);

        await SetPostureAsync(UsagePostures.Normal);
        Assert.Equal(UsagePostures.Normal, (await ResolveAsync(strategy)).UsagePosture);
    }

    [Fact]
    public void Apex_uninitialized_and_the_default_factory_are_normal()
    {
        Assert.Equal(UsagePostures.Normal, TenantContext.Apex.UsagePosture);
        Assert.Equal(UsagePostures.Normal, TenantContext.Uninitialized.UsagePosture);
        Assert.Equal(UsagePostures.Normal, TenantContext.ForTenant("t", "s").UsagePosture);
    }
}
