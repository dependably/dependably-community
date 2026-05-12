using System.Data.Common;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the host-parsing paths that exit before the DB lookup. The valid-slug → DB lookup
/// branch stays integration-only — here the metadata store stub throws if invoked, which
/// proves the parsing rejected the request before it could hit the database.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SubdomainTenantResolverParsingTests
{
    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    private static DefaultHttpContext WithHost(string? host, string? forwardedHost = null)
    {
        var ctx = new DefaultHttpContext();
        if (host is not null) ctx.Request.Host = new HostString(host);
        if (forwardedHost is not null) ctx.Request.Headers["X-Forwarded-Host"] = new StringValues(forwardedHost);
        return ctx;
    }

    private static SubdomainTenantResolver New(string? apexHost) =>
        new(new ThrowingStore(), Cfg(("APEX_HOST", apexHost)));

    [Fact]
    public async Task NoApexConfigured_AlwaysUninitialized()
    {
        var resolver = New(apexHost: null);

        var result = await resolver.ResolveAsync(WithHost("anything.example.com"));

        Assert.True(result.IsUninitialized);
    }

    [Fact]
    public async Task MissingHostHeader_Uninitialized()
    {
        var resolver = New("example.com");

        var result = await resolver.ResolveAsync(WithHost(host: null));

        Assert.True(result.IsUninitialized);
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("EXAMPLE.com")]
    [InlineData("example.com.")]
    [InlineData("example.com:8443")]
    public async Task ApexMatch_ReturnsApex(string host)
    {
        var resolver = New("example.com");

        var result = await resolver.ResolveAsync(WithHost(host));

        Assert.True(result.IsApex);
    }

    [Fact]
    public async Task HostOutsideApex_Uninitialized()
    {
        var resolver = New("example.com");

        var result = await resolver.ResolveAsync(WithHost("totally-unrelated.org"));

        Assert.True(result.IsUninitialized);
    }

    [Fact]
    public async Task SubSubdomain_Uninitialized()
    {
        // Only single-label slugs are tenants.
        var resolver = New("example.com");

        var result = await resolver.ResolveAsync(WithHost("foo.bar.example.com"));

        Assert.True(result.IsUninitialized);
    }

    [Theory]
    [InlineData("admin.example.com")]
    [InlineData("api.example.com")]
    [InlineData("system.example.com")]
    public async Task ReservedSlug_Uninitialized(string host)
    {
        var resolver = New("example.com");

        var result = await resolver.ResolveAsync(WithHost(host));

        Assert.True(result.IsUninitialized);
    }

    [Fact]
    public async Task ForwardedHostHeader_WinsOverHostHeader()
    {
        // Host header points at apex; X-Forwarded-Host names a sub-subdomain → resolver
        // must pick the forwarded host and reject the sub-subdomain instead of falsely
        // returning Apex from the Host header. Apex-match would be `IsApex`; we expect
        // Uninitialized because the forwarded host has too many labels.
        var resolver = New("example.com");

        var result = await resolver.ResolveAsync(
            WithHost("example.com", forwardedHost: "foo.bar.example.com"));

        Assert.True(result.IsUninitialized);
    }

    private sealed class ThrowingStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;
        public Task<DbConnection> OpenAsync(CancellationToken ct = default)
            => throw new InvalidOperationException("Resolver should reject before hitting the database.");
    }
}
