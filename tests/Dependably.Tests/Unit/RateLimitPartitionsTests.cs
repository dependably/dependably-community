using System.Security.Claims;
using Dependably.Security;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit;

/// <summary>
/// Acceptance: the download/push/import partition function buckets by validated principal
/// (sub claim) when authentication has already run, and falls back to source IP for
/// unauthenticated requests. The management-API partition function adds a raw-token arm
/// before the principal check, then falls back to IP.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RateLimitPartitionsTests
{
    // ── GetPartitionKey (download / push / import) ────────────────────────────────────

    /// <summary>
    /// A request whose HttpContext.User carries a validated sub claim produces a
    /// per-user partition key, independent of the originating IP.
    /// </summary>
    [Fact]
    public void GetPartitionKey_ValidatedPrincipal_ReturnsUserSub()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        ctx.User = MakePrincipal("user-abc-123");

        string key = RateLimitPartitions.GetPartitionKey(ctx);

        Assert.Equal("user:user-abc-123", key);
    }

    /// <summary>
    /// Two different authenticated users sharing the same egress IP get separate buckets.
    /// NAT-heavy offices with multiple CI principals are not collapsed.
    /// </summary>
    [Fact]
    public void GetPartitionKey_TwoDifferentSubs_SameIp_YieldDifferentBuckets()
    {
        var ctx1 = new DefaultHttpContext();
        ctx1.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        ctx1.User = MakePrincipal("alice");

        var ctx2 = new DefaultHttpContext();
        ctx2.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        ctx2.User = MakePrincipal("bob");

        Assert.NotEqual(
            RateLimitPartitions.GetPartitionKey(ctx1),
            RateLimitPartitions.GetPartitionKey(ctx2));
    }

    /// <summary>
    /// The same authenticated user from two different source IPs lands in the SAME bucket.
    /// A single CI pipeline that makes requests from different pod IPs does not split its
    /// budget, and NAT IP rotation does not create phantom partitions.
    /// </summary>
    [Fact]
    public void GetPartitionKey_SameSub_DifferentIps_YieldSameBucket()
    {
        var ctx1 = new DefaultHttpContext();
        ctx1.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        ctx1.User = MakePrincipal("ci-bot");

        var ctx2 = new DefaultHttpContext();
        ctx2.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.2");
        ctx2.User = MakePrincipal("ci-bot");

        Assert.Equal(
            RateLimitPartitions.GetPartitionKey(ctx1),
            RateLimitPartitions.GetPartitionKey(ctx2));
    }

    /// <summary>
    /// A forged / unauthenticated Bearer header (no validated principal) falls back to the
    /// source IP, not a token-derived bucket. An attacker sending unique forged values on
    /// every request lands in the same per-IP bucket — the unlimited-partition attack is
    /// closed. This is the core regression test: it must fail on a raw-credential
    /// partitioning implementation and pass on the validated-principal implementation.
    /// </summary>
    [Fact]
    public void GetPartitionKey_UniqueForgedHeaders_SameIp_YieldSameBucket()
    {
        var ctx1 = new DefaultHttpContext();
        ctx1.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("198.51.100.7");
        ctx1.Request.Headers.Authorization = "Bearer attacker-random-1";
        // No validated principal — authentication failed or endpoint is anonymous-pull.

        var ctx2 = new DefaultHttpContext();
        ctx2.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("198.51.100.7");
        ctx2.Request.Headers.Authorization = "Bearer attacker-random-2";

        // Both map to the same IP bucket; the distinct forged headers buy nothing.
        Assert.Equal(
            RateLimitPartitions.GetPartitionKey(ctx1),
            RateLimitPartitions.GetPartitionKey(ctx2));
        Assert.Equal("ip:198.51.100.7", RateLimitPartitions.GetPartitionKey(ctx1));
    }

    /// <summary>
    /// An unvalidated Bearer header with no principal falls back to IP, not a token prefix.
    /// </summary>
    [Fact]
    public void GetPartitionKey_UnvalidatedBearerToken_ReturnsIpNotTokenPrefix()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        ctx.Request.Headers.Authorization = "Bearer secret-raw-token";
        // No validated principal set — token was forged or endpoint is anonymous-pull.

        string key = RateLimitPartitions.GetPartitionKey(ctx);

        Assert.Equal("ip:10.0.0.1", key);
        Assert.DoesNotContain("token:", key);
    }

    /// <summary>
    /// An unvalidated Basic auth header also falls back to IP — an attacker using
    /// twine/pip-style forged credentials cannot escape the per-IP limit.
    /// </summary>
    [Fact]
    public void GetPartitionKey_UnvalidatedBasicAuth_UsesIpNotCredential()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.5");
        byte[] raw = System.Text.Encoding.UTF8.GetBytes("anyuser:basic-secret-token");
        ctx.Request.Headers.Authorization = "Basic " + Convert.ToBase64String(raw);
        // No validated principal.

        string key = RateLimitPartitions.GetPartitionKey(ctx);

        Assert.Equal("ip:203.0.113.5", key);
        Assert.DoesNotContain("token:", key);
    }

    [Fact]
    public void GetPartitionKey_NoAuth_ReturnsIp()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.7");

        string key = RateLimitPartitions.GetPartitionKey(ctx);
        Assert.Equal("ip:203.0.113.7", key);
    }

    [Fact]
    public void GetPartitionKey_NoAuthNoIp_ReturnsUnknown()
    {
        var ctx = new DefaultHttpContext();
        string key = RateLimitPartitions.GetPartitionKey(ctx);
        Assert.Equal("unknown", key);
    }

    // ── GetManagementPartitionKey preference order ────────────────────────────

    /// <summary>
    /// An API token in the Authorization header is the highest-priority bucket,
    /// even when an authenticated principal is also present on the context.
    /// </summary>
    [Fact]
    public void GetManagementPartitionKey_ApiToken_TakesPriorityOverAuthenticatedUser()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = "Bearer ci-api-token";
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        // Simulate a session principal with a sub claim also present.
        ctx.User = MakePrincipal("user-abc");

        string key = RateLimitPartitions.GetManagementPartitionKey(ctx);

        Assert.StartsWith("token:", key);
        Assert.Equal("token:".Length + 12, key.Length);
    }

    /// <summary>
    /// A cookie-session SPA user (no Authorization header, authenticated principal via
    /// UseAuthentication) partitions on the JWT sub claim, not on the originating IP.
    /// </summary>
    [Fact]
    public void GetManagementPartitionKey_AuthenticatedUser_NoToken_ReturnsUserSub()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.99");
        ctx.User = MakePrincipal("user-xyz-123");

        string key = RateLimitPartitions.GetManagementPartitionKey(ctx);

        Assert.Equal("user:user-xyz-123", key);
    }

    /// <summary>
    /// Two different SPA users sharing the same egress IP get separate buckets.
    /// </summary>
    [Fact]
    public void GetManagementPartitionKey_TwoUsers_SameIp_YieldDifferentKeys()
    {
        var ctx1 = new DefaultHttpContext();
        ctx1.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        ctx1.User = MakePrincipal("alice");

        var ctx2 = new DefaultHttpContext();
        ctx2.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        ctx2.User = MakePrincipal("bob");

        Assert.NotEqual(
            RateLimitPartitions.GetManagementPartitionKey(ctx1),
            RateLimitPartitions.GetManagementPartitionKey(ctx2));
    }

    /// <summary>
    /// An unauthenticated request with no Authorization header falls back to the
    /// remote IP — same behaviour as the download/push limiter.
    /// </summary>
    [Fact]
    public void GetManagementPartitionKey_Unauthenticated_FallsBackToIp()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("198.51.100.5");

        string key = RateLimitPartitions.GetManagementPartitionKey(ctx);

        Assert.Equal("ip:198.51.100.5", key);
    }

    /// <summary>
    /// No Authorization header, no authenticated principal, no IP — the catch-all
    /// "unknown" bucket (covers in-process test probes and misrouted requests).
    /// </summary>
    [Fact]
    public void GetManagementPartitionKey_NoAuthNoPrincipalNoIp_ReturnsUnknown()
    {
        var ctx = new DefaultHttpContext();

        string key = RateLimitPartitions.GetManagementPartitionKey(ctx);

        Assert.Equal("unknown", key);
    }

    /// <summary>
    /// Regression: an unauthenticated request (no scheme validated the credential — either
    /// the endpoint is anonymous-accessible, or authentication failed) must not mint its own
    /// "token:" partition from the raw Authorization header. Many distinct bogus tokens from
    /// the same source IP all collapse into that IP's single bucket — the unlimited-partition
    /// bypass this test pins. Must fail on the pre-fix implementation (which hashed the raw
    /// header unconditionally) and pass once the token/user branches gate on
    /// <c>User.Identity.IsAuthenticated</c>.
    /// </summary>
    [Fact]
    public void GetManagementPartitionKey_UnauthenticatedRequest_ManyBogusTokens_SameIp_CollapseToOnePartition()
    {
        var keys = new HashSet<string>();
        for (int i = 0; i < 25; i++)
        {
            var ctx = new DefaultHttpContext();
            ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("198.51.100.42");
            ctx.Request.Headers.Authorization = $"Bearer forged-token-{i}-{Guid.NewGuid():N}";
            // ctx.User left at its default, unauthenticated ClaimsPrincipal — no scheme
            // ever validated this header.
            keys.Add(RateLimitPartitions.GetManagementPartitionKey(ctx));
        }

        Assert.Single(keys);
        Assert.Equal("ip:198.51.100.42", keys.Single());
    }

    /// <summary>
    /// Mixed scenario in one pass: an authenticated API-token client keeps its own
    /// "token:" partition, while an unauthenticated request bearing a bogus Authorization
    /// header (same source IP) collapses to the IP bucket rather than minting a fresh one.
    /// </summary>
    [Fact]
    public void GetManagementPartitionKey_MixedAuthenticatedAndForged_SameIp_DoNotShareOrMultiply()
    {
        var authenticatedCtx = new DefaultHttpContext();
        authenticatedCtx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.1.1.1");
        authenticatedCtx.Request.Headers.Authorization = "Bearer legit-ci-token";
        authenticatedCtx.User = MakePrincipal("ci-service-token");

        var forgedCtx1 = new DefaultHttpContext();
        forgedCtx1.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.1.1.1");
        forgedCtx1.Request.Headers.Authorization = "Bearer forged-1";

        var forgedCtx2 = new DefaultHttpContext();
        forgedCtx2.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.1.1.1");
        forgedCtx2.Request.Headers.Authorization = "Bearer forged-2";

        string authenticatedKey = RateLimitPartitions.GetManagementPartitionKey(authenticatedCtx);
        string forgedKey1 = RateLimitPartitions.GetManagementPartitionKey(forgedCtx1);
        string forgedKey2 = RateLimitPartitions.GetManagementPartitionKey(forgedCtx2);

        Assert.StartsWith("token:", authenticatedKey);
        Assert.Equal("ip:10.1.1.1", forgedKey1);
        Assert.Equal(forgedKey1, forgedKey2);
        Assert.NotEqual(authenticatedKey, forgedKey1);
    }

    /// <summary>
    /// The NameIdentifier claim type (used by auth schemes that map claims to URIs)
    /// is also accepted as the user identity when "sub" is absent.
    /// </summary>
    [Fact]
    public void GetManagementPartitionKey_NameIdentifierClaim_UsedWhenSubAbsent()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        var identity = new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.NameIdentifier, "ni-user-id") },
            authenticationType: "Test");
        ctx.User = new ClaimsPrincipal(identity);

        string key = RateLimitPartitions.GetManagementPartitionKey(ctx);

        Assert.Equal("user:ni-user-id", key);
    }

    // ── #427: IPv6 partition keys collapse to the /64 in the IP-fallback arm ───────────

    /// <summary>
    /// Regression (#427): two unauthenticated requests from two addresses in the SAME IPv6 /64
    /// share one "ip:" partition, so an attacker rebinding source addresses inside their own /64
    /// cannot mint fresh per-IP budgets. Must fail on the pre-fix implementation (which keyed on the
    /// full /128 via GetNormalizedRemoteIp) and pass once the fallback keys on the /64.
    /// </summary>
    [Fact]
    public void GetPartitionKey_TwoAddressesInSameIpv6Slash64_ShareOneBucket()
    {
        var ctx1 = new DefaultHttpContext();
        ctx1.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("2001:db8:aa:bb::1");
        var ctx2 = new DefaultHttpContext();
        ctx2.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("2001:db8:aa:bb:ffff::9");

        Assert.Equal(
            RateLimitPartitions.GetPartitionKey(ctx1),
            RateLimitPartitions.GetPartitionKey(ctx2));
        Assert.Equal("ip:2001:db8:aa:bb::/64", RateLimitPartitions.GetPartitionKey(ctx1));
    }

    /// <summary>
    /// Adversarial twin: two DIFFERENT IPv6 /64s do NOT share a bucket — no over-collapsing that
    /// would let one subnet's traffic exhaust an unrelated subnet's budget.
    /// </summary>
    [Fact]
    public void GetPartitionKey_TwoDifferentIpv6Slash64s_YieldDifferentBuckets()
    {
        var ctx1 = new DefaultHttpContext();
        ctx1.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("2001:db8:aa:bb::1");
        var ctx2 = new DefaultHttpContext();
        ctx2.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("2001:db8:aa:cc::1");

        Assert.NotEqual(
            RateLimitPartitions.GetPartitionKey(ctx1),
            RateLimitPartitions.GetPartitionKey(ctx2));
    }

    /// <summary>
    /// The management global limiter's IP-fallback arm collapses to the /64 as well — otherwise the
    /// anonymous /api/v1 surface stays evadable from a routed /64.
    /// </summary>
    [Fact]
    public void GetManagementPartitionKey_SameIpv6Slash64_ShareOneBucket()
    {
        var ctx1 = new DefaultHttpContext();
        ctx1.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("2001:db8:1:2::1");
        var ctx2 = new DefaultHttpContext();
        ctx2.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("2001:db8:1:2::dead");

        Assert.Equal(
            RateLimitPartitions.GetManagementPartitionKey(ctx1),
            RateLimitPartitions.GetManagementPartitionKey(ctx2));
        Assert.Equal("ip:2001:db8:1:2::/64", RateLimitPartitions.GetManagementPartitionKey(ctx1));
    }

    // ── #426: the GlobalLimiter is default-deny for policy-less protocol surfaces ──────

    /// <summary>
    /// Regression (#426): a routed protocol CONTROLLER ACTION with no endpoint policy classifies as
    /// ProtocolDefault, so the GlobalLimiter applies a real per-IP limit instead of NoLimiter. Must
    /// fail on the pre-fix implementation (which returned NoLimiter for every non-/api/v1 path) and
    /// pass once the GlobalLimiter defaults to a limit. This is the durable "missing attribute ≠ no
    /// limit" fix — and it is scoped to controller actions so the SPA/static plane is untouched.
    /// </summary>
    [Fact]
    public void ClassifyGlobalScope_ProtocolControllerActionWithNoPolicy_IsDefaultDenied()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/pypi/somepkg/json";
        // A real registry endpoint carries a ControllerActionDescriptor but no rate-limit policy.
        ctx.SetEndpoint(new Microsoft.AspNetCore.Http.Endpoint(
            requestDelegate: null,
            new Microsoft.AspNetCore.Http.EndpointMetadataCollection(
                new Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor()),
            "test-protocol-controller-action"));

        Assert.Equal(RateLimitPartitions.GlobalScope.ProtocolDefault, RateLimitPartitions.ClassifyGlobalScope(ctx));
    }

    /// <summary>
    /// Regression (the e2e-gate defect): the embedded SPA is served by UseStaticFiles, which is NOT
    /// endpoint routing — index.html, hashed /assets/* bundles, favicon and fonts reach the rate
    /// limiter with NO endpoint at all. They must classify as Deferred, never ProtocolDefault:
    /// a browser fires dozens of asset GETs per navigation from one IP, so a shared per-IP protocol
    /// cap would 429 the SPA and the login page would never render. Must fail on the "no endpoint →
    /// ProtocolDefault" implementation and pass once static serving defers.
    /// </summary>
    [Theory]
    [InlineData("/")]
    [InlineData("/index.html")]
    [InlineData("/assets/index-a1b2c3d4.js")]
    [InlineData("/assets/index-a1b2c3d4.css")]
    [InlineData("/favicon.ico")]
    [InlineData("/fonts/inter.woff2")]
    [InlineData("/docs/swagger-ui.css")]
    public void ClassifyGlobalScope_StaticAssetPathWithNoEndpoint_Defers(string path)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = path;
        // No endpoint: UseStaticFiles is terminal middleware, not a routed endpoint.

        Assert.Equal(RateLimitPartitions.GlobalScope.Deferred, RateLimitPartitions.ClassifyGlobalScope(ctx));
    }

    /// <summary>
    /// Regression (the e2e-gate defect): the SPA MapFallback route DOES produce an endpoint, but it
    /// is not a controller action and carries no policy. It must classify as Deferred so the
    /// index.html fallback that boots the SPA is never throttled by the protocol default.
    /// </summary>
    [Fact]
    public void ClassifyGlobalScope_SpaFallbackEndpoint_Defers()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/dashboard/settings/tokens";
        // A MapFallback endpoint: no ControllerActionDescriptor, no rate-limit policy.
        ctx.SetEndpoint(new Microsoft.AspNetCore.Http.Endpoint(
            requestDelegate: _ => Task.CompletedTask,
            new Microsoft.AspNetCore.Http.EndpointMetadataCollection(),
            "test-spa-fallback"));

        Assert.Equal(RateLimitPartitions.GlobalScope.Deferred, RateLimitPartitions.ClassifyGlobalScope(ctx));
    }

    /// <summary>
    /// A protocol endpoint that DOES declare its own policy defers (NoLimiter from the global) so
    /// the default never double-counts on top of download/metadata/push.
    /// </summary>
    [Fact]
    public void ClassifyGlobalScope_EndpointWithExplicitPolicy_Defers()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/npm/react";
        ctx.SetEndpoint(new Microsoft.AspNetCore.Http.Endpoint(
            requestDelegate: null,
            new Microsoft.AspNetCore.Http.EndpointMetadataCollection(
                new Microsoft.AspNetCore.RateLimiting.EnableRateLimitingAttribute("metadata")),
            "test-metadata-endpoint"));

        Assert.Equal(RateLimitPartitions.GlobalScope.Deferred, RateLimitPartitions.ClassifyGlobalScope(ctx));
    }

    /// <summary>An authenticated management path with no endpoint policy is the management default.</summary>
    [Fact]
    public void ClassifyGlobalScope_ManagementApiPath_IsManagement()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/api/v1/orgs";

        Assert.Equal(RateLimitPartitions.GlobalScope.ManagementApi, RateLimitPartitions.ClassifyGlobalScope(ctx));
    }

    /// <summary>
    /// The management per-principal ceiling STACKS: an /api/v1 endpoint that also declares its own
    /// policy (e.g. the "anon" bootstrap surface) still classifies as ManagementApi, so the global
    /// budget applies on top of the endpoint policy. Pins the behavior the pipeline-hardening
    /// integration test depends on (a policy-bearing /api/v1 endpoint must not defer the global).
    /// </summary>
    [Fact]
    public void ClassifyGlobalScope_ManagementApiPathWithEndpointPolicy_StillManagement()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/api/v1/bootstrap";
        ctx.SetEndpoint(new Microsoft.AspNetCore.Http.Endpoint(
            requestDelegate: null,
            new Microsoft.AspNetCore.Http.EndpointMetadataCollection(
                new Microsoft.AspNetCore.RateLimiting.EnableRateLimitingAttribute("anon")),
            "test-bootstrap-endpoint"));

        Assert.Equal(RateLimitPartitions.GlobalScope.ManagementApi, RateLimitPartitions.ClassifyGlobalScope(ctx));
    }

    /// <summary>Swagger UI docs assets stay exempt (deferred), as before.</summary>
    [Fact]
    public void ClassifyGlobalScope_DocsPath_Defers()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/api/v1/docs/index.html";

        Assert.Equal(RateLimitPartitions.GlobalScope.Deferred, RateLimitPartitions.ClassifyGlobalScope(ctx));
    }

    private static ClaimsPrincipal MakePrincipal(string sub)
    {
        var identity = new ClaimsIdentity(
            new[] { new Claim("sub", sub) },
            authenticationType: "Test");
        return new ClaimsPrincipal(identity);
    }
}
