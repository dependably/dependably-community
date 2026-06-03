using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Xunit;

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

        var key = RateLimitPartitions.GetPartitionKey(ctx);

        Assert.StartsWith("token:", key);
        // 12 hex chars after the "token:" prefix (6 bytes * 2 hex chars).
        Assert.Equal("token:".Length + 12, key.Length);
    }

    [Fact]
    public void GetPartitionKey_BasicAuth_UsesPasswordAsToken()
    {
        var ctx = new DefaultHttpContext();
        // user:token base64 — twine/pip style
        var raw = System.Text.Encoding.UTF8.GetBytes("anyuser:basic-secret-token");
        ctx.Request.Headers.Authorization = "Basic " + Convert.ToBase64String(raw);

        var key = RateLimitPartitions.GetPartitionKey(ctx);
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

        var key = RateLimitPartitions.GetPartitionKey(ctx);
        Assert.Equal("ip:203.0.113.7", key);
    }

    [Fact]
    public void GetPartitionKey_NoAuthNoIp_ReturnsUnknown()
    {
        var ctx = new DefaultHttpContext();
        var key = RateLimitPartitions.GetPartitionKey(ctx);
        Assert.Equal("unknown", key);
    }

    [Fact]
    public void GetPartitionKey_MalformedBasic_FallsBackToIp()
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("1.2.3.4");
        ctx.Request.Headers.Authorization = "Basic not-base64!";

        var key = RateLimitPartitions.GetPartitionKey(ctx);
        Assert.StartsWith("ip:", key);
    }
}
