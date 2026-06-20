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

    private static ClaimsPrincipal MakePrincipal(string sub)
    {
        var identity = new ClaimsIdentity(
            new[] { new Claim("sub", sub) },
            authenticationType: "Test");
        return new ClaimsPrincipal(identity);
    }
}
