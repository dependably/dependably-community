using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Unit;

/// <summary>
/// Resolution when <c>TENANT_DOMAIN</c> decouples the tenant parent domain from the apex host
/// (<c>APEX_HOST=master.mydomain.com</c>, tenants at <c>slug.mydomain.com</c>). Every positive
/// case is paired with a must-not twin.
/// </summary>
[Trait("Category", "Unit")]
public class SubdomainTenantResolverTenantDomainTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        // Raw SQL on purpose: tenant-create refuses the reserved slugs, so only a direct insert
        // can model an org row that predates its label becoming reserved.
        foreach (string slug in new[] { "acme", "master", "ops", "b" })
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = "org-" + slug, slug });
        }
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    private static DefaultHttpContext WithHost(string host)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Host = new HostString(host);
        return ctx;
    }

    private SubdomainTenantResolver Split(string apex = "master.mydomain.com") =>
        new(_db, Cfg(("DEPLOYMENT_MODE", "multi"), ("APEX_HOST", apex), ("TENANT_DOMAIN", "mydomain.com")));

    [Fact]
    public async Task TenantUnderTenantDomain_ResolvesAsTenant()
    {
        var t = await Split().ResolveAsync(WithHost("acme.mydomain.com"));

        Assert.True(t.IsTenant);
        Assert.Equal("org-acme", t.TenantId);
    }

    [Fact]
    public async Task ApexHost_ResolvesAsApex_EvenWhenAnOrgHoldsItsLeftmostLabel()
    {
        var resolver = Split();

        var apex = await resolver.ResolveAsync(WithHost("master.mydomain.com"));
        var port = await resolver.ResolveAsync(WithHost("master.mydomain.com:8443"));
        var twin = await resolver.ResolveAsync(WithHost("acme.mydomain.com"));

        Assert.True(apex.IsApex);
        Assert.False(apex.IsTenant);
        Assert.True(port.IsApex);
        Assert.True(twin.IsTenant);
        Assert.False(twin.IsApex);
    }

    [Fact]
    public async Task ApexLabelOrg_NonBuiltinLabel_ApexStillWins()
    {
        // "ops" is not a builtin reserved slug and an org row holds it; the apex check still
        // runs before the tenant lookup.
        var resolver = Split("ops.mydomain.com");

        var apex = await resolver.ResolveAsync(WithHost("ops.mydomain.com"));
        var twin = await resolver.ResolveAsync(WithHost("acme.mydomain.com"));

        Assert.True(apex.IsApex);
        Assert.False(apex.IsTenant);
        Assert.True(twin.IsTenant);
    }

    [Fact]
    public async Task DeepApex_ReservesTheLabelBelowTheTenantDomain_NotOtherLabels()
    {
        // APEX_HOST=a.b.mydomain.com reserves "b" (b.mydomain.com is an ancestor of the apex).
        var resolver = Split("a.b.mydomain.com");

        var reserved = await resolver.ResolveAsync(WithHost("b.mydomain.com"));
        var twin = await resolver.ResolveAsync(WithHost("acme.mydomain.com"));
        var otherOrg = await resolver.ResolveAsync(WithHost("ops.mydomain.com"));

        Assert.False(reserved.IsTenant);
        Assert.True(twin.IsTenant);
        Assert.True(otherOrg.IsTenant);
    }

    [Theory]
    [InlineData("acme.master.mydomain.com")]
    [InlineData("a.b.mydomain.com")]
    [InlineData("mydomain.com")]
    [InlineData("acme.evilmydomain.com")]
    [InlineData("acme.mydomain.com.evil.test")]
    [InlineData("acme.other.com")]
    public async Task NonTenantHosts_ResolveUninitialized(string host)
    {
        var t = await Split().ResolveAsync(WithHost(host));

        Assert.False(t.IsTenant);
        Assert.False(t.IsApex);
    }

    [Fact]
    public async Task ApexOutsideTenantDomain_ReservesNothing()
    {
        var resolver = new SubdomainTenantResolver(
            _db, Cfg(("APEX_HOST", "admin.other.test"), ("TENANT_DOMAIN", "mydomain.com")));

        Assert.True((await resolver.ResolveAsync(WithHost("admin.other.test"))).IsApex);
        Assert.True((await resolver.ResolveAsync(WithHost("acme.mydomain.com"))).IsTenant);
        Assert.True((await resolver.ResolveAsync(WithHost("ops.mydomain.com"))).IsTenant);
        Assert.False((await resolver.ResolveAsync(WithHost("acme.admin.other.test"))).IsTenant);
    }

    [Fact]
    public async Task UnsetTenantDomain_BehavesAsTheApexAlwaysDid()
    {
        var resolver = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://mydomain.com")));

        Assert.True((await resolver.ResolveAsync(WithHost("mydomain.com"))).IsApex);
        Assert.True((await resolver.ResolveAsync(WithHost("acme.mydomain.com"))).IsTenant);
        Assert.False((await resolver.ResolveAsync(WithHost("acme.other.com"))).IsTenant);
    }

    [Fact]
    public async Task BlankTenantDomain_FallsBackToTheApex()
    {
        var resolver = new SubdomainTenantResolver(
            _db, Cfg(("BASE_URL", "https://mydomain.com"), ("TENANT_DOMAIN", "  ")));

        Assert.True((await resolver.ResolveAsync(WithHost("acme.mydomain.com"))).IsTenant);
        Assert.False((await resolver.ResolveAsync(WithHost("acme.other.com"))).IsTenant);
    }

    [Fact]
    public async Task ApexAboveTenantDomain_BothResolveAndTenantsStayUnderTheTenantDomain()
    {
        var resolver = new SubdomainTenantResolver(
            _db, Cfg(("APEX_HOST", "mydomain.com"), ("TENANT_DOMAIN", "t.mydomain.com")));

        Assert.True((await resolver.ResolveAsync(WithHost("mydomain.com"))).IsApex);
        Assert.True((await resolver.ResolveAsync(WithHost("acme.t.mydomain.com"))).IsTenant);
        Assert.False((await resolver.ResolveAsync(WithHost("acme.mydomain.com"))).IsTenant);
    }

    // Explicit overrides for every key the wiring reads, so ambient process environment on the
    // machine or CI runner cannot leak a TENANT_DOMAIN or APEX_HOST into the case under test.
    private WebApplicationBuilder BuilderFor(string mode, string? tenantDomain)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = mode,
            ["BASE_URL"] = "https://mydomain.com",
            ["APEX_HOST"] = "",
            ["TENANT_DOMAIN"] = tenantDomain ?? "",
            ["RESERVED_SUBDOMAINS"] = "",
        });
        builder.Services.AddMemoryCache();
        builder.Services.AddSingleton<IMetadataStore>(_db);
        return builder;
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("http://127.0.0.1:8080")]
    [InlineData("https://")]
    [InlineData(":8080")]
    [InlineData("?x")]
    [InlineData("user@")]
    [InlineData("/tenants")]
    [InlineData(".")]
    public void MultiMode_UnusableExplicitTenantDomain_FailsStartup(string tenantDomain)
    {
        var builder = BuilderFor("multi", tenantDomain);

        var ex = Assert.Throws<InvalidOperationException>(() => builder.AddDependablyTenantResolution());

        Assert.Contains("TENANT_DOMAIN", ex.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("   ")]
    [InlineData("example.org")]
    public void MultiMode_UnsetBlankOrUsableTenantDomain_DoesNotFailStartup(string? tenantDomain)
    {
        var builder = BuilderFor("multi", tenantDomain);

        var ex = Record.Exception(() => builder.AddDependablyTenantResolution());

        Assert.Null(ex);
    }

    [Fact]
    public void NonMultiMode_UnusableTenantDomain_DoesNotFailStartup()
    {
        var builder = BuilderFor("single", "localhost");

        var ex = Record.Exception(() => builder.AddDependablyTenantResolution());

        Assert.Null(ex);
    }
}
