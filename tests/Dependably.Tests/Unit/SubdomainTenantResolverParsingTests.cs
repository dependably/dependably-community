using System.Data.Common;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

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

    // Simulates the Request.Host value *after* ForwardedHeadersMiddleware has run.
    // The optional rawForwardedHost parameter places a raw header to confirm the resolver
    // reads Request.Host and not the raw X-Forwarded-Host header.
    private static DefaultHttpContext WithHost(string? host, string? rawForwardedHost = null)
    {
        var ctx = new DefaultHttpContext();
        if (host is not null)
        {
            ctx.Request.Host = new HostString(host);
        }

        if (rawForwardedHost is not null)
        {
            ctx.Request.Headers["X-Forwarded-Host"] = new StringValues(rawForwardedHost);
        }

        return ctx;
    }

    // Creates a resolver whose apex is derived from BASE_URL. Pass null to simulate an
    // unconfigured BASE_URL (no apex → all requests are Uninitialized).
    private static SubdomainTenantResolver New(string? apexHost)
    {
        string? baseUrl = apexHost is null ? null : $"https://{apexHost}";
        return new(new ThrowingStore(), Cfg(("BASE_URL", baseUrl)));
    }

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
    public async Task RequestHost_SubSubdomain_Uninitialized()
    {
        // ForwardedHeadersMiddleware rewrites Request.Host from X-Forwarded-Host when the
        // request arrives from a trusted proxy. This test covers the case where the rewritten
        // Request.Host is a sub-subdomain: the resolver must reject it because only
        // single-label slugs are valid tenants. The raw X-Forwarded-Host header is also set
        // (pointing at the apex) to confirm the resolver does not fall back to the raw header
        // when Request.Host is already the authoritative value.
        var resolver = New("example.com");

        // Request.Host = sub-subdomain (post-ForwardedHeaders rewrite from trusted proxy).
        var result = await resolver.ResolveAsync(
            WithHost("foo.bar.example.com", rawForwardedHost: "example.com"));

        Assert.True(result.IsUninitialized);
    }

    [Fact]
    public async Task RawForwardedHostHeader_FromUntrustedClient_DoesNotOverrideRequestHost()
    {
        // When the client is not in TRUSTED_PROXIES, ForwardedHeadersMiddleware leaves
        // Request.Host unchanged. A raw X-Forwarded-Host injected by the client must not
        // affect the resolution result. The resolver reads Request.Host (the apex), so the
        // result is Apex — not the sub-subdomain the client tried to inject.
        var resolver = New("example.com");

        // Request.Host = apex (not rewritten because client is not trusted);
        // raw X-Forwarded-Host carries a sub-subdomain the client is trying to inject.
        var result = await resolver.ResolveAsync(
            WithHost("example.com", rawForwardedHost: "foo.bar.example.com"));

        Assert.True(result.IsApex);
    }

    private sealed class ThrowingStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;
        public Task<DbConnection> OpenAsync(CancellationToken ct = default)
            => throw new InvalidOperationException("Resolver should reject before hitting the database.");
    }
}
