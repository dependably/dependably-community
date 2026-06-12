using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the DB-lookup paths and configuration-fallback branches that the parsing-only
/// tests deliberately skip. Pairs with <see cref="SubdomainTenantResolverParsingTests"/>.
/// </summary>
[Trait("Category", "Unit")]
public class SubdomainTenantResolverTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = "org-acme", slug = "acme" });
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, deleted_at) VALUES (@id, @slug, @deletedAt)",
            new { id = "org-ghost", slug = "ghost", deletedAt = "2026-01-01T00:00:00Z" });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    // Simulates the Request.Host value *after* ForwardedHeadersMiddleware has run.
    // When a trusted proxy is in front, the middleware rewrites Request.Host from
    // X-Forwarded-Host; tests that exercise the post-rewrite state set Request.Host
    // directly. The optional rawForwardedHost parameter places a raw header that the
    // resolver must ignore (it reads Request.Host, not the raw header).
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

    [Fact]
    public async Task KnownSubdomain_ReturnsTenant()
    {
        var r = new SubdomainTenantResolver(_db, Cfg(("APEX_HOST", "example.com")));

        var t = await r.ResolveAsync(WithHost("acme.example.com"));

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
        Assert.Equal("org-acme", t.TenantId);
    }

    [Fact]
    public async Task KnownSubdomain_IsCaseInsensitive()
    {
        var r = new SubdomainTenantResolver(_db, Cfg(("APEX_HOST", "example.com")));

        var t = await r.ResolveAsync(WithHost("ACME.Example.COM"));

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }

    [Fact]
    public async Task KnownSubdomain_StripsPort()
    {
        var r = new SubdomainTenantResolver(_db, Cfg(("APEX_HOST", "example.com")));

        var t = await r.ResolveAsync(WithHost("acme.example.com:8443"));

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }

    [Fact]
    public async Task KnownSubdomain_TrailingDotTolerated()
    {
        var r = new SubdomainTenantResolver(_db, Cfg(("APEX_HOST", "example.com")));

        var t = await r.ResolveAsync(WithHost("acme.example.com."));

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }

    [Fact]
    public async Task UnknownSlug_Uninitialized()
    {
        var r = new SubdomainTenantResolver(_db, Cfg(("APEX_HOST", "example.com")));

        var t = await r.ResolveAsync(WithHost("nobody.example.com"));

        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public async Task SoftDeletedTenant_Uninitialized()
    {
        // Soft-deleted orgs (deleted_at IS NOT NULL) must not resolve, even when the slug
        // matches an existing row. Restoring is a system_admin action.
        var r = new SubdomainTenantResolver(_db, Cfg(("APEX_HOST", "example.com")));

        var t = await r.ResolveAsync(WithHost("ghost.example.com"));

        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public async Task TrustedProxy_ForwardedHostRewritesRequestHost_DrivesTenantResolution()
    {
        // ForwardedHeadersMiddleware rewrites Request.Host from X-Forwarded-Host when the
        // immediate peer appears in TRUSTED_PROXIES. This test simulates the post-rewrite
        // state: Request.Host is set to the subdomain (as the middleware would have done),
        // while a raw X-Forwarded-Host header is also present to confirm the resolver reads
        // Request.Host and not the raw header directly.
        var r = new SubdomainTenantResolver(_db, Cfg(("APEX_HOST", "example.com")));

        // Request.Host = subdomain (post-ForwardedHeaders rewrite); raw header present but ignored.
        var ctx = WithHost("acme.example.com", rawForwardedHost: "attacker.evil.com");
        var t = await r.ResolveAsync(ctx);

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }

    [Fact]
    public async Task UntrustedClient_RawForwardedHostIgnored_DoesNotChangeTenant()
    {
        // When the client is not a trusted proxy, ForwardedHeadersMiddleware leaves
        // Request.Host unchanged. A raw X-Forwarded-Host from an untrusted client must
        // not affect tenant resolution. The resolver reads Request.Host, which still
        // points at the apex, so the result is Apex — not the tenant named in the header.
        var r = new SubdomainTenantResolver(_db, Cfg(("APEX_HOST", "example.com")));

        // Request.Host = apex (not rewritten); raw X-Forwarded-Host carries a tenant subdomain
        // that an untrusted client is trying to inject. The resolver must ignore the raw header.
        var ctx = new DefaultHttpContext();
        ctx.Request.Host = new HostString("example.com");
        ctx.Request.Headers["X-Forwarded-Host"] = new StringValues("acme.example.com");

        var t = await r.ResolveAsync(ctx);

        Assert.True(t.IsApex);
    }

    [Fact]
    public async Task ApexHost_DerivedFromBaseUrl_WhenApexHostMissing()
    {
        // BASE_URL fallback path: single-tenant installs already configure BASE_URL,
        // so promoting to multi-mode without an APEX_HOST flip should still resolve.
        var r = new SubdomainTenantResolver(_db, Cfg(
            ("APEX_HOST", null),
            ("BASE_URL", "https://example.com:443")));

        var apex = await r.ResolveAsync(WithHost("example.com"));
        var tenant = await r.ResolveAsync(WithHost("acme.example.com"));

        Assert.True(apex.IsApex);
        Assert.True(tenant.IsTenant);
        Assert.Equal("acme", tenant.TenantSlug);
    }

    [Fact]
    public async Task BaseUrl_Malformed_FallsThroughToUninitialized()
    {
        // Non-absolute BASE_URL leaves apex empty → resolver short-circuits.
        var r = new SubdomainTenantResolver(_db, Cfg(
            ("APEX_HOST", null),
            ("BASE_URL", "not-a-real-url")));

        var t = await r.ResolveAsync(WithHost("acme.example.com"));

        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public async Task ExtraReservedSubdomain_Rejected()
    {
        // RESERVED_SUBDOMAINS extends the built-in reserved set; the slug must not hit DB.
        var r = new SubdomainTenantResolver(_db, Cfg(
            ("APEX_HOST", "example.com"),
            ("RESERVED_SUBDOMAINS", "acme")));

        var t = await r.ResolveAsync(WithHost("acme.example.com"));

        Assert.True(t.IsUninitialized);
    }
}
