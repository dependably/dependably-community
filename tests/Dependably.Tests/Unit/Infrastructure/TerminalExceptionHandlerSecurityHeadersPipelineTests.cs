using System.Net;
using Dependably.Infrastructure.Startup;
using Dependably.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the actual production behaviour of an unhandled exception on a browser-facing route:
/// does the resulting 500 carry the same security headers any other response would.
///
/// <para>
/// This is deliberately a separate fixture from <see cref="TerminalExceptionHandlerPipelineTests"/>
/// rather than an addition to its shared pipeline — that class's
/// <c>SuccessfulRequest_IsUnaffected</c> asserts security headers are <em>absent</em> on purpose,
/// because that fixture exists to isolate the terminal handler's own behaviour from
/// <c>SecurityHeadersMiddleware</c>. This fixture puts them back, in the same relative order
/// <c>Program.ConfigureApp</c> registers them in both composition roots: the terminal handler
/// outermost (<c>UseDependablyTerminalExceptionHandler</c>, which wraps
/// <c>UseExceptionHandler</c>), <c>SecurityHeadersMiddleware</c> next.
/// </para>
///
/// <para>
/// That order is exactly what makes the direct-invocation tests in
/// <c>TerminalExceptionHandlerTests</c> insufficient on their own: calling
/// <c>TerminalExceptionHandler.TryHandleAsync</c> directly on a context that already carries live
/// security headers skips ASP.NET Core's own <c>ExceptionHandlerMiddlewareImpl</c>, which calls
/// <c>Response.Clear()</c> itself <em>before</em> invoking any registered <c>IExceptionHandler</c>.
/// Only a pipeline built with <c>UseExceptionHandler</c> — as this fixture is — actually exercises
/// that pre-clear, which is the one place <c>ResponseHeaderPreserver</c>'s
/// <c>HttpContext.Items</c> stash (populated by <c>SecurityHeadersMiddleware</c> before
/// <c>_next</c> runs) is load-bearing rather than redundant.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class TerminalExceptionHandlerSecurityHeadersPipelineTests : IAsyncLifetime
{
    private WebApplication _app = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.AddDependablyLocalization();
        builder.AddDependablyTerminalExceptionHandler();

        _app = builder.Build();

        // Same relative order as Program.ConfigureApp: terminal handler outermost, security
        // headers next, then the endpoint that throws.
        _app.UseDependablyTerminalExceptionHandler();
        _app.UseMiddleware<SecurityHeadersMiddleware>();
        _app.Run(ctx => ctx.Request.Path.Value switch
        {
            "/ok" => ctx.Response.WriteAsync("served"),
            "/npm/ok" => ctx.Response.WriteAsync("served"),
            _ => throw new InvalidOperationException("boom"),
        });

        await _app.StartAsync();
        _client = _app.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
    }

    private static HttpRequestMessage HttpsRequest(string path)
        // TestServer infers Request.IsHttps directly from the request URI's scheme — no
        // TRUSTED_PROXIES / X-Forwarded-Proto plumbing needed for a bare TestServer pipeline like
        // this one (unlike the full DependablyFactory host, which sits behind ForwardedHeaders).
        => new(HttpMethod.Get, new Uri($"https://localhost{path}"));

    [Fact]
    public async Task UnhandledException_PreservesSecurityHeaders_EvenThoughFrameworkClearsResponseFirst()
    {
        var resp = await _client.SendAsync(HttpsRequest("/boom"));

        Assert.Equal(HttpStatusCode.InternalServerError, resp.StatusCode);
        Assert.Equal("nosniff", Assert.Single(resp.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("DENY", Assert.Single(resp.Headers.GetValues("X-Frame-Options")));
        Assert.Equal(
            "strict-origin-when-cross-origin", Assert.Single(resp.Headers.GetValues("Referrer-Policy")));
        Assert.True(resp.Headers.Contains("Permissions-Policy"));
        Assert.True(resp.Headers.Contains("Content-Security-Policy"));
        Assert.True(
            resp.Headers.Contains("Strict-Transport-Security"),
            "An unhandled exception's 500 must still carry HSTS on a browser-facing route — the " +
            "framework's own Response.Clear() (ExceptionHandlerMiddlewareImpl, ahead of any " +
            "IExceptionHandler) must not defeat the restore.");
    }

    [Fact]
    public async Task SuccessfulRequest_CarriesSecurityHeaders_AsTheActiveTwin()
    {
        // The twin: proves the headers come from SecurityHeadersMiddleware running normally, not
        // from some artefact of the exception path that would also fire on a healthy response.
        var resp = await _client.SendAsync(HttpsRequest("/ok"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("served", await resp.Content.ReadAsStringAsync());
        Assert.Equal("nosniff", Assert.Single(resp.Headers.GetValues("X-Content-Type-Options")));
        Assert.True(resp.Headers.Contains("Strict-Transport-Security"));
    }

    /// <summary>
    /// The registry-path twin of <see cref="UnhandledException_PreservesSecurityHeaders_EvenThoughFrameworkClearsResponseFirst"/>:
    /// an unhandled exception on <c>/npm/…</c> (SecurityHeadersMiddleware.IsRegistryPath) must
    /// still carry the registry CSP and Cache-Control: no-store on the resulting 500, not just the
    /// six always-on headers. ASP.NET Core's own ExceptionHandlerMiddlewareImpl additionally
    /// registers its own OnStarting callback that forces Cache-Control to "no-cache,no-store" —
    /// strictly more restrictive than this helper's restore, and it fires after this restore, so
    /// the assertion checks the no-store directive rather than the exact string, which is
    /// whichever of the two produced it.
    /// </summary>
    [Fact]
    public async Task UnhandledException_OnRegistryPath_PreservesRegistryCspAndNoStore()
    {
        var resp = await _client.SendAsync(HttpsRequest("/npm/boom"));

        Assert.Equal(HttpStatusCode.InternalServerError, resp.StatusCode);
        Assert.Equal("nosniff", Assert.Single(resp.Headers.GetValues("X-Content-Type-Options")));
        string csp = Assert.Single(resp.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("default-src 'none'", csp);
        Assert.True(
            resp.Headers.CacheControl?.NoStore,
            "a registry-path 500 must carry Cache-Control: no-store");
    }
}
