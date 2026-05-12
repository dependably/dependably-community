using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class HeaderTenantResolverTests : IAsyncLifetime
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

    private static IConfiguration Config(IDictionary<string, string?>? overrides = null) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(overrides ?? new Dictionary<string, string?>())
            .Build();

    private static DefaultHttpContext WithHeader(string name, string? value)
    {
        var ctx = new DefaultHttpContext();
        if (value is not null) ctx.Request.Headers[name] = value;
        return ctx;
    }

    [Fact]
    public async Task DefaultHeader_KnownTenant_Resolves()
    {
        var r = new HeaderTenantResolver(_db, Config());
        var t = await r.ResolveAsync(WithHeader("X-Dependably-Tenant", "acme"));
        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }

    [Fact]
    public async Task NoHeader_Uninitialized()
    {
        var r = new HeaderTenantResolver(_db, Config());
        var t = await r.ResolveAsync(new DefaultHttpContext());
        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public async Task UnknownSlug_Uninitialized()
    {
        var r = new HeaderTenantResolver(_db, Config());
        var t = await r.ResolveAsync(WithHeader("X-Dependably-Tenant", "ghost"));
        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public async Task ReservedSlug_Rejected()
    {
        var r = new HeaderTenantResolver(_db, Config());
        var t = await r.ResolveAsync(WithHeader("X-Dependably-Tenant", "admin"));
        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public async Task CustomHeaderName_Honored()
    {
        var r = new HeaderTenantResolver(_db, Config(new Dictionary<string, string?>
        {
            ["TENANT_HEADER_NAME"] = "X-Custom-Tenant"
        }));
        var t = await r.ResolveAsync(WithHeader("X-Custom-Tenant", "acme"));
        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }
}
