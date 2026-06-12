using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class DeploymentBoundTenantResolverTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = "org-acme", slug = "acme" });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static IConfiguration Config(string? boundSlug) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["BOUND_TENANT_SLUG"] = boundSlug
            })
            .Build();

    [Fact]
    public async Task BoundSlug_KnownTenant_AlwaysResolves_RegardlessOfHostOrHeader()
    {
        var r = new DeploymentBoundTenantResolver(_db, Config("acme"));

        var ctxA = new DefaultHttpContext();
        ctxA.Request.Host = new HostString("registry.npmjs.org");
        ctxA.Request.Headers["X-Dependably-Tenant"] = "ghost";
        var t = await r.ResolveAsync(ctxA);

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }

    [Fact]
    public async Task SoftDeletedTenant_Uninitialized()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @ts WHERE slug = 'acme'",
                new { ts = DateTimeOffset.UtcNow });
        }
        var r = new DeploymentBoundTenantResolver(_db, Config("acme"));
        var t = await r.ResolveAsync(new DefaultHttpContext());
        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public void MissingBoundSlug_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new DeploymentBoundTenantResolver(_db, Config(null)));
    }
}
