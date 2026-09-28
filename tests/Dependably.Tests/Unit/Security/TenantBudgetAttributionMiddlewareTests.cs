using System.Data.Common;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// <see cref="TenantBudgetAttributionMiddleware"/> decides which protocol requests are charged to
/// their tenant's rate-limit budget: every request while the org allows anonymous pull, otherwise
/// only those carrying a live credential of that org. Each exemption is paired with the charged
/// twin it must not be confused with, and the default on any failure is to charge.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantBudgetAttributionMiddlewareTests : IAsyncLifetime
{
    private const string OrgA = "org-a";
    private const string OrgB = "org-b";

    private readonly TestMetadataStore _inner = new();
    private readonly FakeTimeProvider _time = TestTime.Frozen();
    private CountingStore _db = null!;
    private TokenRepository _tokens = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_inner).InitializeAsync();
        await using (var conn = await _inner.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-a', 'acme'), ('org-b', 'globex')");
            await conn.ExecuteAsync("""
                INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES
                    ('u-a', 'org-a', 'dev@acme.example', '', 'member'),
                    ('u-b', 'org-b', 'dev@globex.example', '', 'member')
                """);
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, anonymous_pull, allowlist_mode) VALUES ('org-a', 0, 0), ('org-b', 0, 0)");
        }

        _db = new CountingStore(_inner);
        _tokens = new TokenRepository(_db, _time);
    }

    public async Task DisposeAsync() => await _inner.DisposeAsync();

    private async Task SetAnonymousPullAsync(string orgId, bool on)
    {
        await using var conn = await _inner.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @on WHERE org_id = @orgId", new { on = on ? 1 : 0, orgId });
    }

    private Task<string> UserTokenAsync(string orgId, string userId) =>
        _tokens.CreateUserTokenAsync(orgId, userId, "[\"read:metadata\"]", expiresAt: null)
            .ContinueWith(t => t.Result.RawToken, TaskScheduler.Default);

    private Task<string> ServiceTokenAsync(string orgId) =>
        _tokens.CreateServiceTokenAsync(orgId, "ci-" + Guid.NewGuid().ToString("N"), "[\"read:metadata\"]", expiresAt: null)
            .ContinueWith(t => t.Result.RawToken, TaskScheduler.Default);

    private DefaultHttpContext Request(
        TenantContext? tenant, Type? controller = null, bool controllerAction = true, IMetadataStore? store = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/npm/left-pad";
        if (tenant is not null)
        {
            ctx.Items[TenantContext.HttpItemsKey] = tenant;
        }

        var metadata = controllerAction
            ? new EndpointMetadataCollection(new ControllerActionDescriptor
            {
                ControllerTypeInfo = (controller ?? typeof(Dependably.Api.NpmController)).GetTypeInfo(),
            })
            : new EndpointMetadataCollection();
        ctx.SetEndpoint(new Endpoint(_ => Task.CompletedTask, metadata, "test"));

        var backing = store ?? _db;
        ctx.RequestServices = new ServiceCollection()
            .AddSingleton(new OrgRepository(backing))
            .AddSingleton(new TokenRepository(backing, _time))
            .BuildServiceProvider();
        return ctx;
    }

    private static TenantContext TenantA => TenantContext.ForTenant(OrgA, "acme");

    private static string Basic(string token) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("user:" + token));

    private static async Task<bool> RunAsync(HttpContext ctx)
    {
        bool nextCalled = false;
        var middleware = new TenantBudgetAttributionMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            NullLogger<TenantBudgetAttributionMiddleware>.Instance);
        await middleware.InvokeAsync(ctx);
        return nextCalled;
    }

    private static bool IsExempt(HttpContext ctx) =>
        ctx.Items[TenantRateLimiter.NotTenantTrafficItemKey] is true;

    private static TokenRecord? Stashed(HttpContext ctx) =>
        (ctx.Items[TenantBudgetAttributionMiddleware.ResolvedTokenItemKey] as TenantBudgetAttributionMiddleware.PreResolvedToken)?.Token;

    // ── Anonymous pull off: only the org's own credentials are charged ─────────

    [Fact]
    public async Task No_credential_to_an_org_that_refuses_anonymous_pull_is_not_tenant_traffic()
    {
        var ctx = Request(TenantA);

        Assert.True(await RunAsync(ctx));

        Assert.True(IsExempt(ctx));
        Assert.Null(Stashed(ctx));
    }

    [Theory]
    [InlineData("Bearer not-a-real-token")]
    [InlineData("Basic !!!not-base64!!!")]
    public async Task An_unresolvable_credential_is_not_tenant_traffic(string header)
    {
        var ctx = Request(TenantA);
        ctx.Request.Headers.Authorization = header;

        await RunAsync(ctx);

        Assert.True(IsExempt(ctx));
        Assert.Null(Stashed(ctx));
    }

    [Fact]
    public async Task Another_orgs_live_credential_is_not_tenant_traffic()
    {
        string foreign = await ServiceTokenAsync(OrgB);
        var ctx = Request(TenantA);
        ctx.Request.Headers.Authorization = "Bearer " + foreign;

        await RunAsync(ctx);

        Assert.True(IsExempt(ctx));
        Assert.Null(Stashed(ctx));
    }

    [Fact]
    public async Task The_orgs_own_user_token_is_charged_and_its_resolution_recorded()
    {
        string own = await UserTokenAsync(OrgA, "u-a");
        var ctx = Request(TenantA);
        ctx.Request.Headers.Authorization = "Bearer " + own;

        await RunAsync(ctx);

        Assert.False(IsExempt(ctx));
        var token = Assert.IsType<TokenRecord>(Stashed(ctx));
        Assert.Equal(OrgA, token.OrgId);
        Assert.Equal(TokenSource.User, token.Source);
    }

    [Fact]
    public async Task The_orgs_own_service_token_over_basic_is_charged()
    {
        string own = await ServiceTokenAsync(OrgA);
        var ctx = Request(TenantA);
        ctx.Request.Headers.Authorization = Basic(own);

        await RunAsync(ctx);

        Assert.False(IsExempt(ctx));
        Assert.Equal(TokenSource.Service, Assert.IsType<TokenRecord>(Stashed(ctx)).Source);
    }

    [Fact]
    public async Task The_orgs_own_nuget_api_key_is_charged()
    {
        string own = await ServiceTokenAsync(OrgA);
        var ctx = Request(TenantA);
        ctx.Request.Headers["X-NuGet-ApiKey"] = own;

        await RunAsync(ctx);

        Assert.False(IsExempt(ctx));
        Assert.Equal(OrgA, Assert.IsType<TokenRecord>(Stashed(ctx)).OrgId);
    }

    // ── The bare, scheme-less form Cargo and Hex clients send ─────────────────

    [Fact]
    public async Task The_orgs_own_bare_token_is_charged_and_its_resolution_recorded()
    {
        string own = await ServiceTokenAsync(OrgA);
        var ctx = Request(TenantA, controller: typeof(Dependably.Api.CargoController));
        ctx.Request.Headers.Authorization = own;

        await RunAsync(ctx);

        Assert.False(IsExempt(ctx));
        Assert.Equal(OrgA, Assert.IsType<TokenRecord>(Stashed(ctx)).OrgId);
    }

    [Fact]
    public async Task A_bare_unresolvable_value_is_not_tenant_traffic()
    {
        var ctx = Request(TenantA, controller: typeof(Dependably.Api.CargoController));
        ctx.Request.Headers.Authorization = "junk";

        await RunAsync(ctx);

        Assert.True(IsExempt(ctx));
        Assert.Null(Stashed(ctx));
    }

    [Fact]
    public async Task Another_orgs_bare_token_is_not_tenant_traffic()
    {
        string foreign = await ServiceTokenAsync(OrgB);
        var ctx = Request(TenantA, controller: typeof(Dependably.Api.CargoController));
        ctx.Request.Headers.Authorization = foreign;

        await RunAsync(ctx);

        Assert.True(IsExempt(ctx));
        Assert.Null(Stashed(ctx));
    }

    [Fact]
    public async Task A_bare_value_in_an_unknown_scheme_is_not_tenant_traffic()
    {
        // A space means some other scheme the resolvers do not speak; the org's own token
        // behind it is never resolved by a handler, so it must not be charged either.
        string own = await ServiceTokenAsync(OrgA);
        var ctx = Request(TenantA, controller: typeof(Dependably.Api.CargoController));
        ctx.Request.Headers.Authorization = "Token " + own;

        await RunAsync(ctx);

        Assert.True(IsExempt(ctx));
        Assert.Null(Stashed(ctx));
    }

    // ── Anonymous pull on: the org serves everything, so everything is charged ─

    [Fact]
    public async Task With_anonymous_pull_on_a_request_with_no_credential_is_charged()
    {
        await SetAnonymousPullAsync(OrgA, on: true);
        var ctx = Request(TenantA);

        await RunAsync(ctx);

        Assert.False(IsExempt(ctx));
    }

    [Fact]
    public async Task With_anonymous_pull_on_another_orgs_credential_is_charged()
    {
        await SetAnonymousPullAsync(OrgA, on: true);
        string foreign = await ServiceTokenAsync(OrgB);
        var ctx = Request(TenantA);
        ctx.Request.Headers.Authorization = "Bearer " + foreign;

        await RunAsync(ctx);

        Assert.False(IsExempt(ctx));
    }

    // ── Paths that never look anything up ─────────────────────────────────────

    [Theory]
    [InlineData("tid")]
    [InlineData("org_id")]
    public async Task A_principal_already_authenticated_for_the_tenant_is_charged_without_a_lookup(string claim)
    {
        var ctx = Request(TenantA);
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(claim, OrgA)], "ApiToken"));
        int before = _db.Opens;

        Assert.True(await RunAsync(ctx));

        Assert.False(IsExempt(ctx));
        Assert.Equal(before, _db.Opens);
    }

    [Fact]
    public async Task A_principal_authenticated_for_another_tenant_is_looked_up_like_any_request()
    {
        var ctx = Request(TenantA);
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tid", OrgB)], "ApiToken"));

        await RunAsync(ctx);

        Assert.True(IsExempt(ctx));
    }

    [Fact]
    public async Task Non_protocol_and_non_tenant_requests_are_left_alone()
    {
        var management = Request(TenantA, controller: typeof(Dependably.Api.SamlController));
        var noController = Request(TenantA, controllerAction: false);
        var apex = Request(TenantContext.Apex);
        var unresolved = Request(tenant: null);
        var probe = Request(TenantA);
        probe.Request.Path = "/health";
        int before = _db.Opens;

        foreach (var ctx in new[] { management, noController, apex, unresolved, probe })
        {
            Assert.True(await RunAsync(ctx));
            Assert.False(IsExempt(ctx));
            Assert.Null(Stashed(ctx));
        }

        Assert.Equal(before, _db.Opens);
    }

    [Fact]
    public async Task A_failing_lookup_charges_the_request_and_still_serves_it()
    {
        var ctx = Request(TenantA, store: new ThrowingStore());

        Assert.True(await RunAsync(ctx));

        Assert.False(IsExempt(ctx));
        Assert.Null(Stashed(ctx));
    }

    [Fact]
    public async Task An_org_with_no_settings_row_is_charged()
    {
        var ctx = Request(TenantContext.ForTenant("org-without-settings", "nosettings"));

        await RunAsync(ctx);

        Assert.False(IsExempt(ctx));
    }

    // ── The handler's resolution reuses the middleware's ──────────────────────

    [Fact]
    public async Task The_recorded_resolution_is_reused_once_without_a_query()
    {
        var record = new TokenRecord { Id = "t-1", OrgId = OrgA, LastUsedAt = _time.GetUtcNow() };
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = "Bearer raw-1";
        ctx.Items[TenantBudgetAttributionMiddleware.ResolvedTokenItemKey] =
            new TenantBudgetAttributionMiddleware.PreResolvedToken("raw-1", record);

        var resolved = await ctx.Request.ResolveTokenAsync(new TokenRepository(new ThrowingStore(), _time));

        Assert.Same(record, resolved);
        Assert.False(ctx.Items.ContainsKey(TenantBudgetAttributionMiddleware.ResolvedTokenItemKey));
    }

    [Fact]
    public async Task A_recorded_bare_resolution_is_reused_once_without_a_query()
    {
        var record = new TokenRecord { Id = "t-1", OrgId = OrgA, LastUsedAt = _time.GetUtcNow() };
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = "raw-1";
        ctx.Items[TenantBudgetAttributionMiddleware.ResolvedTokenItemKey] =
            new TenantBudgetAttributionMiddleware.PreResolvedToken("raw-1", record);

        var resolved = await ctx.Request.ResolveTokenAsync(new TokenRepository(new ThrowingStore(), _time));

        Assert.Same(record, resolved);
        Assert.False(ctx.Items.ContainsKey(TenantBudgetAttributionMiddleware.ResolvedTokenItemKey));
    }

    [Fact]
    public async Task End_to_end_a_valid_bare_token_is_resolved_once_per_request()
    {
        string own = await ServiceTokenAsync(OrgA);
        var ctx = Request(TenantA, controller: typeof(Dependably.Api.CargoController));
        ctx.Request.Headers.Authorization = own;
        await RunAsync(ctx);
        int afterMiddleware = _db.Opens;

        var repo = ctx.RequestServices.GetRequiredService<TokenRepository>();
        var resolved = await ctx.Request.ResolveTokenAsync(repo, OrgA);

        Assert.Equal(OrgA, resolved?.OrgId);
        Assert.Equal(1, _db.Opens - afterMiddleware);
    }

    [Fact]
    public async Task A_recorded_resolution_for_a_different_credential_is_not_reused()
    {
        // The middleware read the NuGet API key; this overload reads only Authorization, so the
        // recorded resolution must not authenticate a request this overload would have refused.
        var record = new TokenRecord { Id = "t-1", OrgId = OrgA, LastUsedAt = _time.GetUtcNow() };
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = "Bearer something-else";
        ctx.Items[TenantBudgetAttributionMiddleware.ResolvedTokenItemKey] =
            new TenantBudgetAttributionMiddleware.PreResolvedToken("raw-1", record);
        int before = _db.Opens;

        var resolved = await ctx.Request.ResolveTokenAsync(_tokens);

        Assert.Null(resolved);
        Assert.True(_db.Opens > before);

        var apiKeyOnly = new DefaultHttpContext();
        apiKeyOnly.Request.Headers["X-NuGet-ApiKey"] = "raw-1";
        apiKeyOnly.Items[TenantBudgetAttributionMiddleware.ResolvedTokenItemKey] =
            new TenantBudgetAttributionMiddleware.PreResolvedToken("raw-1", record);
        Assert.Null(await apiKeyOnly.Request.ResolveTokenAsync(_tokens));
    }

    [Fact]
    public async Task With_nothing_recorded_the_handler_resolves_as_before()
    {
        string own = await ServiceTokenAsync(OrgA);
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = "Bearer " + own;
        int before = _db.Opens;

        var resolved = await ctx.Request.ResolveTokenAsync(_tokens);

        Assert.Equal(OrgA, resolved?.OrgId);
        Assert.True(_db.Opens > before);
    }

    [Fact]
    public async Task End_to_end_a_valid_token_is_resolved_once_per_request()
    {
        string own = await UserTokenAsync(OrgA, "u-a");
        var ctx = Request(TenantA);
        ctx.Request.Headers.Authorization = "Bearer " + own;
        await RunAsync(ctx);
        int afterMiddleware = _db.Opens;

        var repo = ctx.RequestServices.GetRequiredService<TokenRepository>();
        var resolved = await ctx.Request.ResolveTokenAsync(repo, OrgA);

        Assert.Equal(OrgA, resolved?.OrgId);
        // The touch of last_used_at is the only open the handler's path adds; a second
        // resolution would add another.
        Assert.Equal(1, _db.Opens - afterMiddleware);
    }

    private sealed class CountingStore(IMetadataStore inner) : IMetadataStore
    {
        private int _opens;

        public int Opens => Volatile.Read(ref _opens);

        public DbProvider Provider => inner.Provider;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            Interlocked.Increment(ref _opens);
            return inner.OpenAsync(ct);
        }
    }

    private sealed class ThrowingStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException("the metadata store is unavailable");
    }
}
