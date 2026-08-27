using System.Net;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins that the five typed exception middlewares registered INNER to
/// <c>SecurityHeadersMiddleware</c> in both composition roots — <see cref="AirGappedExceptionMiddleware"/>,
/// <see cref="StagingDiskFullExceptionMiddleware"/>,
/// <see cref="TenantStorageQuotaExceededExceptionMiddleware"/>,
/// <see cref="UpstreamFetchFailedExceptionMiddleware"/>, <see cref="SsrfBlockedExceptionMiddleware"/> —
/// each restore the same header set <see cref="TenantNotReadyResponseWriter"/> and
/// <see cref="TerminalExceptionHandler"/> already do. Each one calls <c>Response.Clear()</c> to
/// discard whatever partial state ran before the exception, exactly the pattern
/// <c>ResponseHeaderPreserver</c> exists to fix.
///
/// <para>
/// Requests target <c>/npm/…</c> paths specifically so <c>SecurityHeadersMiddleware.IsRegistryPath</c>
/// classifies them as registry traffic and sets <c>Cache-Control: no-store</c> alongside the
/// registry CSP — these five sites are reachable from every ecosystem's proxy-fetch path, which is
/// exactly the registry-path Cache-Control gap.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class TypedExceptionMiddlewaresSecurityHeadersPipelineTests : IAsyncLifetime
{
    private WebApplication _app = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        _app = builder.Build();

        // Same relative order as Program.ConfigureApp in both composition roots:
        // SecurityHeadersMiddleware first, then the five typed exception middlewares.
        _app.UseMiddleware<SecurityHeadersMiddleware>();
        _app.UseMiddleware<AirGappedExceptionMiddleware>();
        _app.UseMiddleware<StagingDiskFullExceptionMiddleware>();
        _app.UseMiddleware<TenantStorageQuotaExceededExceptionMiddleware>();
        _app.UseMiddleware<UpstreamFetchFailedExceptionMiddleware>();
        _app.UseMiddleware<SsrfBlockedExceptionMiddleware>();
        _app.Run(Throw);

        await _app.StartAsync();
        _client = _app.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
    }

    private static Task Throw(HttpContext ctx) => ctx.Request.Path.Value switch
    {
        "/npm/ok" => ctx.Response.WriteAsync("served"),
        "/npm/air-gapped" => throw new AirGappedException("npm/left-pad"),
        "/npm/disk-full" => throw new StagingDiskFullException(1024, 4096),
        "/npm/quota" => throw new TenantStorageQuotaExceededException("org-1", 999),
        "/npm/upstream" => throw new UpstreamFetchFailedException { Url = "https://u/x", StatusCode = 503, Transient = true },
        "/npm/ssrf" => throw new SsrfBlockedException("http://169.254.169.254/latest"),
        _ => throw new InvalidOperationException("unreachable"),
    };

    private static HttpRequestMessage HttpsRequest(string path)
        // TestServer infers Request.IsHttps directly from the request URI's scheme.
        => new(HttpMethod.Get, new Uri($"https://localhost{path}"));

    private static void AssertRegistryRefusalHeaderSet(HttpResponseMessage resp)
    {
        Assert.Equal("nosniff", Assert.Single(resp.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("DENY", Assert.Single(resp.Headers.GetValues("X-Frame-Options")));
        Assert.Equal(
            "strict-origin-when-cross-origin", Assert.Single(resp.Headers.GetValues("Referrer-Policy")));
        Assert.True(resp.Headers.Contains("Permissions-Policy"));
        Assert.True(resp.Headers.Contains("Content-Security-Policy"));
        Assert.True(resp.Headers.Contains("Strict-Transport-Security"));
        Assert.True(
            resp.Headers.CacheControl?.NoStore,
            "a registry-path refusal must carry Cache-Control: no-store — a bare error status is " +
            "heuristically cacheable (RFC 9111 §4.2.2) without it");
    }

    [Theory]
    [InlineData("/npm/air-gapped", HttpStatusCode.ServiceUnavailable)]
    [InlineData("/npm/disk-full", (HttpStatusCode)507)]
    [InlineData("/npm/quota", HttpStatusCode.RequestEntityTooLarge)]
    [InlineData("/npm/upstream", HttpStatusCode.ServiceUnavailable)]
    [InlineData("/npm/ssrf", HttpStatusCode.BadGateway)]
    public async Task TypedExceptionRefusal_CarriesFullRegistryHeaderSet(string path, HttpStatusCode expectedStatus)
    {
        var resp = await _client.SendAsync(HttpsRequest(path));

        Assert.Equal(expectedStatus, resp.StatusCode);
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        AssertRegistryRefusalHeaderSet(resp);
    }

    [Fact]
    public async Task SuccessfulRequest_CarriesTheSameRegistryHeaderSet_AsTheActiveTwin()
    {
        var resp = await _client.SendAsync(HttpsRequest("/npm/ok"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("served", await resp.Content.ReadAsStringAsync());
        AssertRegistryRefusalHeaderSet(resp);
    }
}
