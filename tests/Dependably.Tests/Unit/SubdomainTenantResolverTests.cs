using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
        var r = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")));

        var t = await r.ResolveAsync(WithHost("acme.example.com"));

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
        Assert.Equal("org-acme", t.TenantId);
    }

    [Fact]
    public async Task KnownSubdomain_IsCaseInsensitive()
    {
        var r = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")));

        var t = await r.ResolveAsync(WithHost("ACME.Example.COM"));

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }

    [Fact]
    public async Task KnownSubdomain_StripsPort()
    {
        var r = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")));

        var t = await r.ResolveAsync(WithHost("acme.example.com:8443"));

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }

    [Fact]
    public async Task KnownSubdomain_TrailingDotTolerated()
    {
        var r = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")));

        var t = await r.ResolveAsync(WithHost("acme.example.com."));

        Assert.True(t.IsTenant);
        Assert.Equal("acme", t.TenantSlug);
    }

    [Fact]
    public async Task UnknownSlug_Uninitialized()
    {
        var r = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")));

        var t = await r.ResolveAsync(WithHost("nobody.example.com"));

        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public async Task SoftDeletedTenant_Uninitialized()
    {
        // Soft-deleted orgs (deleted_at IS NOT NULL) must not resolve, even when the slug
        // matches an existing row. Restoring is a system_admin action.
        var r = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")));

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
        var r = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")));

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
        var r = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")));

        // Request.Host = apex (not rewritten); raw X-Forwarded-Host carries a tenant subdomain
        // that an untrusted client is trying to inject. The resolver must ignore the raw header.
        var ctx = new DefaultHttpContext();
        ctx.Request.Host = new HostString("example.com");
        ctx.Request.Headers["X-Forwarded-Host"] = new StringValues("acme.example.com");

        var t = await r.ResolveAsync(ctx);

        Assert.True(t.IsApex);
    }

    [Fact]
    public async Task ApexHost_DerivedFromBaseUrl_WithExplicitPort()
    {
        // BASE_URL with an explicit port: the host portion (not including the port) is used
        // as the apex, matching the behavior of Uri.Host.
        var r = new SubdomainTenantResolver(_db, Cfg(
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
        // Non-absolute, non-parseable BASE_URL leaves apex empty → resolver short-circuits.
        var r = new SubdomainTenantResolver(_db, Cfg(
            ("BASE_URL", "not-a-real-url")));

        var t = await r.ResolveAsync(WithHost("acme.example.com"));

        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public async Task ExtraReservedSubdomain_Rejected()
    {
        // RESERVED_SUBDOMAINS extends the built-in reserved set; the slug must not hit DB.
        var r = new SubdomainTenantResolver(_db, Cfg(
            ("BASE_URL", "https://example.com"),
            ("RESERVED_SUBDOMAINS", "acme")));

        var t = await r.ResolveAsync(WithHost("acme.example.com"));

        Assert.True(t.IsUninitialized);
    }

    [Fact]
    public async Task InvalidateSlugThatRacesAnInFlightResolve_DoesNotServeThePreLifecycleContext()
    {
        // Fill-after-invalidate race: a resolve reads the pre-lifecycle-change orgs row (tenant
        // active); concurrently system_admin soft-deletes the tenant, whose commit + InvalidateSlug
        // lands mid-fill. On the pre-guard code the resolve caches the stale active context AFTER
        // the eviction, so the subdomain keeps resolving for a full 5s TTL despite the delete. The
        // hook fires the soft-delete + InvalidateSlug between the DB read and the cache write —
        // fails on the old code, passes on the generation-token fix.
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var hooked = new AfterDbReadHookStore(_db);
        var r = new SubdomainTenantResolver(hooked, Cfg(("BASE_URL", "https://example.com")), cache);

        hooked.AfterRead = async () =>
        {
            await using var conn = await _db.OpenAsync();
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @d WHERE slug = 'acme'",
                new { d = "2026-02-01T00:00:00Z" });
            r.InvalidateSlug("acme");
        };

        var first = await r.ResolveAsync(WithHost("acme.example.com"));
        Assert.True(first.IsTenant); // legitimately read the pre-delete row

        // Killer assertion: the next resolve must reflect the soft-delete (404), not a stale
        // active tenant context cached by the racing resolve.
        var second = await r.ResolveAsync(WithHost("acme.example.com"));
        Assert.True(second.IsUninitialized);
    }

    [Fact]
    public async Task NeverExistentSlug_DoesNotRetainItsFillGuard()
    {
        // Pre-auth reachability: any syntactically valid non-reserved subdomain that misses the
        // cache mints a generation guard even when no tenant row exists (the fill caches
        // Uninitialized). InvalidateSlug only runs on real tenant lifecycle, so unless the guard's
        // lifetime is tied to the cache entry an unauthenticated client hitting <random>.apex
        // accumulates one permanent CancellationTokenSource per distinct label — a
        // memory-exhaustion amplifier.
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var r = new SubdomainTenantResolver(_db, Cfg(("BASE_URL", "https://example.com")), cache);

        var ctx = await r.ResolveAsync(WithHost("nobody.example.com"));
        Assert.True(ctx.IsUninitialized); // no such tenant, but the negative result was still cached
        Assert.Equal(1, r.FillGuardCount);

        // Evict the negative entry the way a TTL expiry or capacity trim would. The entry's
        // post-eviction callback must retire the guard the never-existent slug minted.
        cache.Compact(1.0);

        await WaitForFillGuardsToDrain(() => r.FillGuardCount);
        Assert.Equal(0, r.FillGuardCount);
    }

    [Fact]
    public async Task DbOpenThrowsAfterGuardIsMinted_DoesNotRetainItsFillGuard()
    {
        // GuardFor mints the guard BEFORE the DB open/read. Under the Singleton registration the
        // guard map is process-lifetime, so if the open or read throws — a cancelled connection
        // (client RST mid-open), a busy/exhausted pool, a transient DB error — with no cache entry
        // ever installed to tie the guard's lifetime to, the guard must not survive the throw. This
        // path is reachable pre-auth and pre-rate-limit (SubdomainTenantMiddleware runs before
        // both) with a caller-controlled, unbounded slug space, so an unretired guard here leaks
        // one CancellationTokenSource per distinct failed label at full anonymous request rate —
        // the exact amplifier CacheFillGuard's own doc names this resolver as reachable through.
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var throwing = new ThrowingAfterGuardStore();
        var r = new SubdomainTenantResolver(throwing, Cfg(("BASE_URL", "https://example.com")), cache);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => r.ResolveAsync(WithHost("acme.example.com")));

        // Killer assertion: the guard GuardFor minted right before the throw must not leak.
        Assert.Equal(0, r.FillGuardCount);
    }

    private sealed class ThrowingAfterGuardStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException(
                "Simulates a cancelled/refused/exhausted DB open after ResolveAsync has already minted the fill guard.");
    }

    // MemoryCache fires post-eviction callbacks on a thread-pool task, so poll briefly for the
    // asynchronous retire rather than assuming it has already run.
    private static async Task WaitForFillGuardsToDrain(Func<int> count)
    {
        for (int i = 0; i < 200 && count() != 0; i++)
        {
            await Task.Delay(10);
        }
    }

    // Builds the resolver through the real DI wiring (AuthStartupExtensions.AddDependablyTenantResolution)
    // rather than `new SubdomainTenantResolver(...)`, so these tests exercise the actual
    // registration lifetime — the lifetime boundary the single-instance tests above cannot cross.
    // DEPLOYMENT_MODE=multi with a real (non-localhost) BASE_URL selects SubdomainTenantResolver.
    //
    // WebApplication.CreateBuilder() layers ambient process environment variables underneath the
    // in-memory overrides below (same as HaDeploymentValidationTests' NewBuilder), which is why
    // every config key the resolver reads gets an explicit override here — an ambient
    // RESERVED_SUBDOMAINS on the machine or CI runner must not leak into what "reserved" means for
    // these tests. This does touch the filesystem (content root/appsettings discovery), so it is
    // not strictly no-I/O; kept under Category=Unit anyway, following the precedent
    // HaDeploymentValidationTests already set for exercising a WebApplicationBuilder-based startup
    // extension directly rather than through a live Kestrel host.
    private static WebApplicationBuilder NewMultiModeBuilder(IMetadataStore db)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = "multi",
            ["BASE_URL"] = "https://example.com",
            ["RESERVED_SUBDOMAINS"] = "",
        });
        builder.Services.AddMemoryCache();
        builder.Services.AddSingleton(db);
        builder.AddDependablyTenantResolution();
        return builder;
    }

    [Fact]
    public void ITenantResolverAndITenantSlugCacheInvalidator_ResolveToTheSameSingletonInstance()
    {
        // The whole fix rests on this identity holding: InvalidateSlug — resolved via
        // ITenantSlugCacheInvalidator, the shape SystemController uses from its own request
        // scope — must land on the exact object whose fill-guard map a DIFFERENT request's
        // ResolveAsync (resolved via ITenantResolver) is filling. Proven by reference identity
        // across three independently created DI scopes rather than assumed from the
        // registration lines alone.
        var builder = NewMultiModeBuilder(_db);
        using var provider = builder.Services.BuildServiceProvider();

        using var scopeA = provider.CreateScope();
        using var scopeB = provider.CreateScope();
        using var scopeC = provider.CreateScope();

        var resolverA = scopeA.ServiceProvider.GetRequiredService<ITenantResolver>();
        var resolverB = scopeB.ServiceProvider.GetRequiredService<ITenantResolver>();
        var invalidatorC = scopeC.ServiceProvider.GetRequiredService<ITenantSlugCacheInvalidator>();

        Assert.Same(resolverA, resolverB);
        Assert.Same(resolverA, invalidatorC);
    }

    [Fact]
    public async Task CrossScope_InvalidateFromDifferentScopeRacesInFlightFill_DoesNotServeStaleContext()
    {
        // Cross-request twin of InvalidateSlugThatRacesAnInFlightResolve_DoesNotServeThePreLifecycleContext
        // above. That test drives ONE resolver instance directly, so InvalidateSlug and the racing
        // fill share a map by construction — it cannot observe the DI-lifetime defect, only the
        // generation-token logic. Here the fill runs on the resolver instance one request's scope
        // resolves, and the racing InvalidateSlug runs through ITenantSlugCacheInvalidator resolved
        // from a SECOND, independent scope — the actual shape of SystemController racing an
        // in-flight ResolveAsync from a concurrent request. Deterministically sequenced (not timed):
        // the DB-read hook fires the status flip + InvalidateSlug in the exact window between the
        // fill's read and its cache write, so this is not an unsequenced concurrency test.
        //
        // On the pre-fix Scoped registration the two scopes are handed two different resolver
        // instances, each with its own empty fill-guard map, so the second scope's InvalidateSlug
        // cancels nothing the first scope's fill is holding and the stale context survives the
        // full TTL — this must fail there and pass once both scopes share the same Singleton.
        var hooked = new AfterDbReadHookStore(_db);
        var builder = NewMultiModeBuilder(hooked);
        using var provider = builder.Services.BuildServiceProvider();

        using var requestScope = provider.CreateScope();
        using var adminScope = provider.CreateScope();

        var resolver = requestScope.ServiceProvider.GetRequiredService<ITenantResolver>();

        hooked.AfterRead = async () =>
        {
            await using var conn = await _db.OpenAsync();
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @d WHERE slug = 'acme'",
                new { d = "2026-02-01T00:00:00Z" });

            // Simulates SystemController handling the status-flip request in its own DI scope.
            var invalidator = adminScope.ServiceProvider.GetRequiredService<ITenantSlugCacheInvalidator>();
            invalidator.InvalidateSlug("acme");
        };

        var first = await resolver.ResolveAsync(WithHost("acme.example.com"));
        Assert.True(first.IsTenant); // legitimately read the pre-delete row

        // Killer assertion: the next resolve — including one served from the SAME requesting
        // scope's resolver, since that resolver is the one whose fill raced the invalidation —
        // must reflect the soft-delete, not a stale active context the race let through.
        var second = await resolver.ResolveAsync(WithHost("acme.example.com"));
        Assert.True(second.IsUninitialized);
    }

    [Fact]
    public async Task CrossScope_NeverExistentSlug_FillGuardVisibleAndDrainsAcrossScopes()
    {
        // Cross-request twin of NeverExistentSlug_DoesNotRetainItsFillGuard above: the fill runs
        // through one scope's resolver, and both "is the guard visible" and "did it drain" are
        // observed through a SECOND scope's resolver instance — proving the guard map, and its
        // unbounded-growth drain, is genuinely shared state rather than per-scope. The drain
        // concern is moot under the pre-fix per-request lifetime (each scope's map is already
        // empty and discarded at end of request) and becomes live again under the fix, which is
        // exactly why it needs re-pinning here rather than left to the single-instance test.
        var builder = NewMultiModeBuilder(_db);
        using var provider = builder.Services.BuildServiceProvider();

        using var scopeA = provider.CreateScope();
        using var scopeB = provider.CreateScope();

        var resolverA = (SubdomainTenantResolver)scopeA.ServiceProvider.GetRequiredService<ITenantResolver>();
        var resolverB = (SubdomainTenantResolver)scopeB.ServiceProvider.GetRequiredService<ITenantResolver>();

        var ctx = await resolverA.ResolveAsync(WithHost("nobody.example.com"));
        Assert.True(ctx.IsUninitialized); // no such tenant, but the negative result was still cached

        // Visible from a different scope's resolver instance, not just the one that did the fill.
        Assert.Equal(1, resolverB.FillGuardCount);

        var cache = (MemoryCache)scopeA.ServiceProvider.GetRequiredService<IMemoryCache>();
        cache.Compact(1.0);

        await WaitForFillGuardsToDrain(() => resolverB.FillGuardCount);
        Assert.Equal(0, resolverB.FillGuardCount);
    }
}
