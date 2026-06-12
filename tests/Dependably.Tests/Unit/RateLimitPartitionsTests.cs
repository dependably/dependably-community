using System.Security.Claims;
using Dependably.Security;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit;

/// <summary>
/// Acceptance: the partition function must derive a per-token key from the
/// Authorization header so a single misbehaving CI client gets its own bucket, and
/// fall back to client IP when no auth is present so anonymous fetches still get a
/// sane cap.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RateLimitPartitionsTests
{
    [Fact]
    public void GetPartitionKey_BearerToken_ReturnsTokenPrefix()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = "Bearer secret-raw-token";

        string key = RateLimitPartitions.GetPartitionKey(ctx);

        Assert.StartsWith("token:", key);
        // 12 hex chars after the "token:" prefix (6 bytes * 2 hex chars).
        Assert.Equal("token:".Length + 12, key.Length);
    }

    [Fact]
    public void GetPartitionKey_BasicAuth_UsesPasswordAsToken()
    {
        var ctx = new DefaultHttpContext();
        // user:token base64 — twine/pip style
        byte[] raw = System.Text.Encoding.UTF8.GetBytes("anyuser:basic-secret-token");
        ctx.Request.Headers.Authorization = "Basic " + Convert.ToBase64String(raw);

        string key = RateLimitPartitions.GetPartitionKey(ctx);
        Assert.StartsWith("token:", key);
    }

    [Fact]
    public void GetPartitionKey_SameToken_YieldsSameKey()
    {
        var ctx1 = new DefaultHttpContext();
        ctx1.Request.Headers.Authorization = "Bearer same-token";
        var ctx2 = new DefaultHttpContext();
        ctx2.Request.Headers.Authorization = "Bearer same-token";

        Assert.Equal(RateLimitPartitions.GetPartitionKey(ctx1), RateLimitPartitions.GetPartitionKey(ctx2));
    }

    [Fact]
    public void GetPartitionKey_DifferentTokens_YieldDifferentKeys()
    {
        var ctx1 = new DefaultHttpContext();
        ctx1.Request.Headers.Authorization = "Bearer token-A";
        var ctx2 = new DefaultHttpContext();
        ctx2.Request.Headers.Authorization = "Bearer token-B";

        Assert.NotEqual(RateLimitPartitions.GetPartitionKey(ctx1), RateLimitPartitions.GetPartitionKey(ctx2));
    }

    [Fact]
    public void GetPartitionKey_NoAuth_FallsBackToIp()
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

    [Fact]
    public void GetPartitionKey_MalformedBasic_FallsBackToIp()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("1.2.3.4");
        ctx.Request.Headers.Authorization = "Basic not-base64!";

        string key = RateLimitPartitions.GetPartitionKey(ctx);
        Assert.StartsWith("ip:", key);
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
