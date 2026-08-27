using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Direct coverage for <see cref="ResponseHeaderPreserver"/> — the snapshot-and-restore helper
/// both <see cref="TenantNotReadyResponseWriter"/> and <see cref="TerminalExceptionHandler"/> call
/// around their own <c>Response.Clear()</c>. Each positive case (a preserved header survives) is
/// paired with a negative twin (an excluded header does not), so a helper that preserved
/// everything — which would also pass a "the header is present" assertion — fails these.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ResponseHeaderPreserverTests
{
    private static DefaultHttpContext NewContext() => new();

    [Fact]
    public void Capture_ThenRestoreAfterClear_SecurityAndCorsHeadersSurvive()
    {
        var ctx = NewContext();
        ctx.Response.Headers.XContentTypeOptions = "nosniff";
        ctx.Response.Headers.XFrameOptions = "DENY";
        ctx.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()";
        ctx.Response.Headers.StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload";
        ctx.Response.Headers.ContentSecurityPolicy = "default-src 'self'";
        ctx.Response.Headers.AccessControlAllowOrigin = "https://spa.example.com";
        ctx.Response.Headers.AccessControlAllowCredentials = "true";
        ctx.Response.Headers.AccessControlExposeHeaders = "X-Custom";
        ctx.Response.Headers.Vary = "Origin";
        // Set by SecurityHeadersMiddleware on registry paths — request-derived (keyed on path),
        // not a per-artifact freshness directive, so it belongs with the preserved set.
        ctx.Response.Headers.CacheControl = "no-store";

        var snapshot = ResponseHeaderPreserver.Capture(ctx);
        ctx.Response.Clear();
        ResponseHeaderPreserver.Restore(ctx, snapshot);

        Assert.Equal("nosniff", ctx.Response.Headers.XContentTypeOptions.ToString());
        Assert.Equal("DENY", ctx.Response.Headers.XFrameOptions.ToString());
        Assert.Equal("strict-origin-when-cross-origin", ctx.Response.Headers["Referrer-Policy"].ToString());
        Assert.Equal(
            "geolocation=(), microphone=(), camera=(), payment=()",
            ctx.Response.Headers["Permissions-Policy"].ToString());
        Assert.Equal(
            "max-age=31536000; includeSubDomains; preload",
            ctx.Response.Headers.StrictTransportSecurity.ToString());
        Assert.Equal("default-src 'self'", ctx.Response.Headers.ContentSecurityPolicy.ToString());
        Assert.Equal("https://spa.example.com", ctx.Response.Headers.AccessControlAllowOrigin.ToString());
        Assert.Equal("true", ctx.Response.Headers.AccessControlAllowCredentials.ToString());
        Assert.Equal("X-Custom", ctx.Response.Headers.AccessControlExposeHeaders.ToString());
        Assert.Equal("Origin", ctx.Response.Headers.Vary.ToString());
        Assert.Equal("no-store", ctx.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public void Capture_ThenRestoreAfterClear_DoesNotResurrectContentOrPerArtifactCachingHeaders()
    {
        // The adversarial twin of the test above: headers that describe the aborted response's
        // specific body — never in the preserved allowlist — must not survive Clear(), because
        // Clear() exists specifically to drop them ahead of a different status/body. Cache-Control
        // is deliberately NOT in this set: SecurityHeadersMiddleware sets it request-derived (see
        // the test above), so only the per-artifact freshness headers (ETag, Last-Modified) stay
        // excluded here.
        var ctx = NewContext();
        ctx.Response.Headers.XContentTypeOptions = "nosniff";
        ctx.Response.ContentType = "text/plain";
        ctx.Response.ContentLength = 12345;
        ctx.Response.Headers.ContentEncoding = "gzip";
        ctx.Response.Headers.ETag = "\"abc123\"";
        ctx.Response.Headers.LastModified = "Mon, 01 Jan 2024 00:00:00 GMT";

        var snapshot = ResponseHeaderPreserver.Capture(ctx);
        ctx.Response.Clear();
        ResponseHeaderPreserver.Restore(ctx, snapshot);

        // The one preserved header from this set survives...
        Assert.Equal("nosniff", ctx.Response.Headers.XContentTypeOptions.ToString());

        // ...but nothing that describes the discarded body does.
        Assert.True(string.IsNullOrEmpty(ctx.Response.ContentType));
        Assert.Null(ctx.Response.ContentLength);
        Assert.True(string.IsNullOrEmpty(ctx.Response.Headers.ContentEncoding.ToString()));
        Assert.True(string.IsNullOrEmpty(ctx.Response.Headers.ETag.ToString()));
        Assert.True(string.IsNullOrEmpty(ctx.Response.Headers.LastModified.ToString()));
    }

    [Fact]
    public void Capture_OnlyCapturesHeadersActuallyPresent()
    {
        // No CORS headers were set (a same-origin request never gets them from CorsMiddleware) —
        // the snapshot must not synthesize empty entries for headers that were never there.
        var ctx = NewContext();
        ctx.Response.Headers.XContentTypeOptions = "nosniff";

        var snapshot = ResponseHeaderPreserver.Capture(ctx);

        Assert.Single(snapshot);
        Assert.False(snapshot.ContainsKey("Access-Control-Allow-Origin"));
    }

    [Fact]
    public void Restore_IsCaseInsensitiveOnHeaderName()
    {
        var ctx = NewContext();
        // The lowercase spelling is the subject of this test — Restore must find the header
        // however the upstream wrote its name — so the indexer is deliberate here and the
        // strongly-typed property ASP0015 suggests would erase what is being asserted.
#pragma warning disable ASP0015
        ctx.Response.Headers["x-content-type-options"] = "nosniff";
#pragma warning restore ASP0015

        var snapshot = ResponseHeaderPreserver.Capture(ctx);
        ctx.Response.Clear();
        ResponseHeaderPreserver.Restore(ctx, snapshot);

        Assert.Equal("nosniff", ctx.Response.Headers.XContentTypeOptions.ToString());
    }

    // ── HttpContext.Items stash: the ExceptionHandlerMiddleware scenario ────────

    [Fact]
    public void Capture_FallsBackToItemsStash_WhenLiveHeadersAlreadyGone()
    {
        // Reproduces what actually happens to TerminalExceptionHandler: ASP.NET Core's own
        // ExceptionHandlerMiddlewareImpl clears the response BEFORE invoking any IExceptionHandler,
        // so a live read finds nothing — CaptureIntoItems (called by SecurityHeadersMiddleware
        // earlier in the pipeline) is what Capture() must fall back to here.
        var ctx = NewContext();
        ctx.Response.Headers.XContentTypeOptions = "nosniff";
        ctx.Response.Headers.XFrameOptions = "DENY";
        ctx.Response.Headers.ContentSecurityPolicy = "default-src 'self'";

        ResponseHeaderPreserver.CaptureIntoItems(ctx);

        // Simulates ExceptionHandlerMiddlewareImpl.ClearHttpContext running before any handler
        // (including this test's stand-in for TerminalExceptionHandler) ever sees the context.
        ctx.Response.Clear();

        var snapshot = ResponseHeaderPreserver.Capture(ctx);
        ctx.Response.Clear();
        ResponseHeaderPreserver.Restore(ctx, snapshot);

        Assert.Equal("nosniff", ctx.Response.Headers.XContentTypeOptions.ToString());
        Assert.Equal("DENY", ctx.Response.Headers.XFrameOptions.ToString());
        Assert.Equal("default-src 'self'", ctx.Response.Headers.ContentSecurityPolicy.ToString());
    }

    [Fact]
    public void Capture_PrefersStashOverLiveHeader_WhenBothPresent()
    {
        // The structural fix for the Cache-Control risk: a handler that sets an artifact-specific
        // Cache-Control (e.g. "private, max-age=31536000, immutable") before a later call throws a
        // not-ready exception must NOT have that live value win over SecurityHeadersMiddleware's
        // own request-derived default. A live read alone cannot tell "the middleware's default" from
        // "a handler's still-live override" apart — the stash can, because it can only ever hold
        // what SecurityHeadersMiddleware itself computed.
        var ctx = NewContext();
        ctx.Response.Headers.CacheControl = "no-store";
        ResponseHeaderPreserver.CaptureIntoItems(ctx);

        // A handler downstream (still pre-clear) overwrites it with an artifact-specific value —
        // exactly what would happen if a GetRegistryAsync-shaped call moved below such a write.
        ctx.Response.Headers.CacheControl = "private, max-age=31536000, immutable";

        var snapshot = ResponseHeaderPreserver.Capture(ctx);

        Assert.Equal("no-store", snapshot["Cache-Control"].ToString());
    }

    [Fact]
    public void Capture_FallsBackToLiveHeader_WhenNoStashExists()
    {
        // The adversarial twin: with no SecurityHeadersMiddleware in front of this context at all
        // (e.g. a unit test that sets headers directly, as most in this repo do), the live value is
        // still captured rather than silently dropped just because there is no stash to prefer.
        var ctx = NewContext();
        ctx.Response.Headers.CacheControl = "no-store";

        var snapshot = ResponseHeaderPreserver.Capture(ctx);

        Assert.Equal("no-store", snapshot["Cache-Control"].ToString());
    }

    [Fact]
    public void Capture_CorsHeaders_AreNeverStashed_AlwaysLiveRead()
    {
        // Ordering matters here and is the whole point of the test: in production,
        // SecurityHeadersMiddleware (and its CaptureIntoItems call) runs BEFORE CorsMiddleware, so
        // no CORS header can possibly be live yet when the stash is taken. Setting the CORS headers
        // AFTER CaptureIntoItems — not before, which the previous version of this test did, making
        // the stash accidentally capture them and the assertion pass for the wrong reason — is what
        // actually proves a CORS entry can only ever come from a live read.
        var ctx = NewContext();
        ctx.Response.Headers.XContentTypeOptions = "nosniff";
        ResponseHeaderPreserver.CaptureIntoItems(ctx);

        var stashedBeforeCors = ResponseHeaderPreserver.Capture(ctx);
        Assert.False(stashedBeforeCors.ContainsKey("Access-Control-Allow-Origin"));

        // CorsMiddleware runs later in the pipeline and grants the headers now.
        ctx.Response.Headers.AccessControlAllowOrigin = "https://spa.example.com";
        ctx.Response.Headers.AccessControlAllowCredentials = "true";

        var snapshot = ResponseHeaderPreserver.Capture(ctx);

        // The live read still finds them — the stash was never involved.
        Assert.Equal("https://spa.example.com", snapshot["Access-Control-Allow-Origin"].ToString());
        Assert.Equal("true", snapshot["Access-Control-Allow-Credentials"].ToString());
        // The security header from the stash is unaffected by the later CORS grant.
        Assert.Equal("nosniff", snapshot["X-Content-Type-Options"].ToString());
    }

    [Fact]
    public void Capture_WithNoStashAndNoLiveHeaders_ReturnsEmptySnapshot()
    {
        // No SecurityHeadersMiddleware in front of this context at all (e.g. a raw unit-test
        // context) — Capture() must not throw or synthesize entries from an absent stash.
        var ctx = NewContext();

        var snapshot = ResponseHeaderPreserver.Capture(ctx);

        Assert.Empty(snapshot);
    }
}
