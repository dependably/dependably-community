using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class HeaderTenantResolverTests : IAsyncLifetime
{
    private const string TrustedProxy = "10.9.9.1";

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

    private static IConfiguration Config(IDictionary<string, string?>? overrides = null)
    {
        var settings = new Dictionary<string, string?>(
            overrides ?? new Dictionary<string, string?>());
        if (!settings.ContainsKey("TRUSTED_PROXIES"))
        {
            settings["TRUSTED_PROXIES"] = TrustedProxy;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
    }

    // A request as it arrives from the edge proxy: OriginalPeerMiddleware has recorded the socket
    // peer before forwarded-header processing rewrote Connection.RemoteIpAddress to the client.
    private static DefaultHttpContext WithHeader(string name, string? value, string? peer = TrustedProxy)
    {
        var ctx = new DefaultHttpContext();
        if (value is not null)
        {
            ctx.Request.Headers[name] = value;
        }

        if (peer is not null)
        {
            ctx.Items[OriginalPeerMiddleware.HttpItemsKey] = IPAddress.Parse(peer);
        }

        return ctx;
    }

    [Fact]
    public async Task DefaultHeader_KnownTenant_FromTrustedProxy_Resolves()
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

    // ── Trust boundary ───────────────────────────────────────────────────────

    /// <summary>
    /// The header names the org whose packages the request is served, and the anonymous protocol
    /// surfaces carry no JWT for RouteScopeFilter to cross-check it against — so a caller who can
    /// reach the app port directly must not be able to name a victim tenant and be served its
    /// artifacts. The socket peer is the only thing that distinguishes the edge proxy from anyone
    /// else, and it is exactly the check ForwardedHeadersMiddleware already applies to
    /// X-Forwarded-*.
    ///
    /// Mixed by construction: the same slug, the same header, the same configuration — only the
    /// peer differs, so the rule cannot be satisfied by refusing the header outright.
    /// </summary>
    [Fact]
    public async Task SameHeader_FromUntrustedPeer_IsRefused_ButFromTheProxyResolves()
    {
        var r = new HeaderTenantResolver(_db, Config());

        var forged = await r.ResolveAsync(
            WithHeader("X-Dependably-Tenant", "acme", peer: "203.0.113.7"));
        Assert.True(forged.IsUninitialized);

        var viaProxy = await r.ResolveAsync(WithHeader("X-Dependably-Tenant", "acme"));
        Assert.True(viaProxy.IsTenant);
        Assert.Equal("acme", viaProxy.TenantSlug);
    }

    /// <summary>
    /// TRUSTED_PROXIES unset is the documented fail-closed default for every forwarded header;
    /// the tenant header follows it. No peer qualifies, so not even a loopback caller is trusted.
    /// </summary>
    [Fact]
    public async Task TrustedProxiesUnset_HeaderIsRefusedFromEveryPeer()
    {
        var r = new HeaderTenantResolver(_db, Config(new Dictionary<string, string?>
        {
            ["TRUSTED_PROXIES"] = null
        }));

        Assert.True((await r.ResolveAsync(
            WithHeader("X-Dependably-Tenant", "acme", peer: "127.0.0.1"))).IsUninitialized);
        Assert.True((await r.ResolveAsync(
            WithHeader("X-Dependably-Tenant", "acme", peer: TrustedProxy))).IsUninitialized);
    }

    /// <summary>
    /// No recorded peer at all — a pipeline without OriginalPeerMiddleware, or a request with no
    /// connection — denies rather than falling back to Connection.RemoteIpAddress, which
    /// forwarded-header processing may already have rewritten to a client-supplied address.
    /// </summary>
    [Fact]
    public async Task NoRecordedPeer_IsRefused()
    {
        var r = new HeaderTenantResolver(_db, Config());
        var ctx = WithHeader("X-Dependably-Tenant", "acme", peer: null);
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(TrustedProxy);

        Assert.True((await r.ResolveAsync(ctx)).IsUninitialized);
    }

    [Fact]
    public async Task TrustedProxyCidr_MatchesPeerInsideTheNetwork()
    {
        var r = new HeaderTenantResolver(_db, Config(new Dictionary<string, string?>
        {
            ["TRUSTED_PROXIES"] = "10.9.0.0/16"
        }));

        Assert.True((await r.ResolveAsync(
            WithHeader("X-Dependably-Tenant", "acme", peer: "10.9.4.4"))).IsTenant);
        Assert.True((await r.ResolveAsync(
            WithHeader("X-Dependably-Tenant", "acme", peer: "10.10.4.4"))).IsUninitialized);
    }

    /// <summary>
    /// Kestrel reports a dual-stack socket peer in IPv4-mapped IPv6 form, so an operator's IPv4
    /// TRUSTED_PROXIES entry has to match it — the same normalization ForwardedHeadersMiddleware
    /// performs, and the reason this resolver shares its matcher.
    /// </summary>
    [Fact]
    public async Task Ipv4MappedIpv6Peer_MatchesAnIpv4TrustedEntry()
    {
        var r = new HeaderTenantResolver(_db, Config());
        var t = await r.ResolveAsync(
            WithHeader("X-Dependably-Tenant", "acme", peer: "::ffff:10.9.9.1"));
        Assert.True(t.IsTenant);
    }
}

[Trait("Category", "Unit")]
public class OriginalPeerMiddlewareTests
{
    [Fact]
    public async Task Invoke_RecordsTheSocketPeerForLaterTrustDecisions()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("10.9.9.1");
        var middleware = new OriginalPeerMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(ctx);

        Assert.Equal(IPAddress.Parse("10.9.9.1"), OriginalPeerMiddleware.Read(ctx));
    }

    [Fact]
    public async Task Invoke_WithNoConnectionAddress_RecordsNothing()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = null;
        var middleware = new OriginalPeerMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(ctx);

        Assert.Null(OriginalPeerMiddleware.Read(ctx));
    }
}
