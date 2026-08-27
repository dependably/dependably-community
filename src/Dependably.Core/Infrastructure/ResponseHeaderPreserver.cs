using Microsoft.Extensions.Primitives;

namespace Dependably.Infrastructure;

/// <summary>
/// Snapshots the response headers that must survive <c>Response.Clear()</c> and restores them
/// afterward. A refusal writer (<see cref="TenantNotReadyResponseWriter"/>,
/// <see cref="TerminalExceptionHandler"/>, and the typed exception middlewares registered inner to
/// <c>SecurityHeadersMiddleware</c> in both composition roots — <c>AirGappedExceptionMiddleware</c>,
/// <c>StagingDiskFullExceptionMiddleware</c>, <c>TenantStorageQuotaExceededExceptionMiddleware</c>,
/// <c>UpstreamFetchFailedExceptionMiddleware</c>, <c>SsrfBlockedExceptionMiddleware</c>) calls
/// <c>Response.Clear()</c> to discard whatever a partially-run pipeline already wrote, then
/// replaces the body with its own fixed error shape. That call is indiscriminate: it also wipes
/// every header set earlier in the pipeline, including the ones that never depended on the body it
/// is discarding.
///
/// <para>
/// The preserved set is a fixed allowlist, not a computed re-application of the middlewares'
/// policy logic — capturing whatever value was actually computed is what makes this immune to the
/// drift a hardcoded re-application would accumulate as those middlewares evolve. It is an
/// allowlist rather than a denylist deliberately: an allowlist's failure mode (a header this
/// helper does not yet know to preserve) is a visible gap that shows up as a missing header on the
/// refusal response, while a denylist's failure mode (a header that should have been dropped but
/// slips through the list) is silent. <see cref="ResponseHeaderPreserverComplianceTests"/> closes
/// the other half of that gap: every <c>Response.Clear()</c> under <c>src/**</c> must sit next to a
/// <see cref="Capture"/>/<see cref="Restore"/> pair or a reasoned opt-out, so a future refusal writer
/// that calls Response.Clear() and forgets this helper fails a static scan instead of shipping
/// unnoticed — it cannot see a refusal that short-circuits without ever calling Response.Clear()
/// at all (UploadSizeLimitMiddleware's 413 is that shape; see ResponseHeaderPreserverComplianceTests'
/// own doc comment).
/// </para>
///
/// <para>
/// <b>What is in the allowlist and why.</b> <c>SecurityHeadersMiddleware</c> computes its headers
/// (Content-Security-Policy, X-Frame-Options, Referrer-Policy, Permissions-Policy,
/// Strict-Transport-Security, X-Content-Type-Options, and — on registry paths —
/// <c>Cache-Control: no-store</c>) from the <em>request</em>: the path and whether the connection
/// is HTTPS. None of them describe this particular response's body, so all of them are safe to
/// resurrect verbatim after a clear, regardless of what the aborted response would have contained.
/// <c>Cache-Control</c> sits in that same request-derived bucket here, not with the excluded
/// caching headers below — it is a security control (RFC 9111 §4.2.2 lets an intermediary cache a
/// bare 404, and a "tenant not found" refusal on a registry path must not become cacheable) set
/// unconditionally per path, not a freshness directive computed for a specific artifact.
/// Deliberately excluded: <c>Content-Type</c>, <c>Content-Length</c>, <c>Content-Encoding</c>, and
/// any per-artifact caching header (<c>ETag</c>, <c>Last-Modified</c>) the aborted response may
/// have started setting — those describe the specific bytes <c>Response.Clear()</c> exists to
/// throw away, and resurrecting them next to a different status code and a different body would be
/// a bug, not a fix.
/// </para>
///
/// <para>
/// <b>Why <see cref="Capture"/> prefers the stash over a live read for the
/// <c>SecurityHeadersMiddleware</c> headers.</b> 36 response handlers set an
/// artifact-specific <c>Cache-Control</c> (e.g. <c>"private, max-age=31536000, immutable"</c>)
/// before serving a hit, and several call a <c>GetRegistryAsync</c>-shaped method that can still
/// throw a not-ready exception. If a live read were preferred, one refactor that reordered such a
/// call below its own <c>Cache-Control</c> write would make the refusal inherit a year-long
/// immutable directive — a live read cannot tell "SecurityHeadersMiddleware's request-derived
/// default" from "a handler's body-derived value that happens to still be live" apart, because both
/// occupy the same header slot. The stash <c>CaptureIntoItems</c> populates is unambiguous: it can
/// only ever hold what <c>SecurityHeadersMiddleware</c> itself computed, at the one point in the
/// pipeline before any handler has run. <see cref="Capture"/> therefore prefers it whenever it is
/// present, falling back to a live read only when there is no stash to prefer — a pipeline without
/// <c>SecurityHeadersMiddleware</c> in front of it (a unit test constructing a bare
/// <see cref="HttpContext"/> and setting headers directly, or a future composition root that omits
/// it). CORS headers are never in the stash (<c>SecurityHeadersMiddleware</c> does not set them),
/// so for those the live read is the only mechanism, unaffected by this ordering.
/// </para>
///
/// <para>
/// <b>Why a snapshot in <see cref="HttpContext.Items"/>, not just a live read.</b>
/// <see cref="TerminalExceptionHandler"/> runs as an <c>IExceptionHandler</c> under
/// <c>UseExceptionHandler</c>, and ASP.NET Core's own <c>ExceptionHandlerMiddlewareImpl</c> calls
/// <c>Response.Clear()</c> itself, before invoking any registered handler — so by the time
/// <see cref="TerminalExceptionHandler"/> runs, a live read of <c>Response.Headers</c> already
/// finds nothing from <c>SecurityHeadersMiddleware</c>. <c>SecurityHeadersMiddleware</c> stashes
/// its own snapshot into <see cref="HttpContext.Items"/> immediately after computing its headers —
/// the one point in the pipeline guaranteed to run before anything, framework-owned or
/// application-owned, could have cleared them — and <see cref="Capture"/> falls back to that stash
/// whenever the live headers are already gone. Every other refusal writer this helper serves
/// (<see cref="TenantNotReadyResponseWriter"/>, the five typed exception middlewares above) calls
/// <c>Response.Clear()</c> itself with no framework pre-clear in front of it, so the stash is never
/// strictly needed there — it is read anyway, uniformly, because the alternative is two different
/// capture strategies for two different callers of the same helper.
/// </para>
///
/// <para>
/// <b>CORS is live-only, and only ever live in <c>Dependably</c>'s pipeline, for
/// <see cref="TenantNotReadyResponseWriter"/>.</b> The CORS headers <c>CorsMiddleware</c> may have
/// granted (Access-Control-Allow-Origin, Access-Control-Allow-Credentials,
/// Access-Control-Expose-Headers, and the <c>Vary: Origin</c> it appends) are named in the
/// allowlist as documented intent and as a defence against a future CORS integration that writes
/// them synchronously. <c>Dependably.Edge</c>'s composition root registers no <c>UseCors</c> at
/// all — there is no CORS layer there to defend against, so for every Edge refusal writer the CORS
/// entries are simply never populated, live or stashed, which is a vacuous case rather than a
/// broken one. In the main <c>Dependably</c> root, which does register <c>UseCors</c>, the defence
/// is only real for <see cref="TenantNotReadyResponseWriter"/>, which calls <c>Response.Clear()</c>
/// downstream of both <c>SecurityHeadersMiddleware</c> and <c>UseCors</c> in the pipeline, so a
/// live read at that point can genuinely see whatever <c>CorsMiddleware</c> wrote. For
/// <see cref="TerminalExceptionHandler"/> — present in both roots — the CORS entries are
/// permanently inert even where <c>UseCors</c> exists: <c>SecurityHeadersMiddleware</c> — and the
/// <c>CaptureIntoItems</c> stash it takes — runs <em>before</em> <c>UseCors</c> in the
/// <c>Dependably</c> root, so the stash can never contain a CORS header regardless of how
/// <c>CorsMiddleware</c> applies them, and the live read at that point is always empty because of
/// the framework's own pre-clear described above. In this codebase's ASP.NET Core version the
/// whole question is moot for <c>Dependably</c> anyway: for an actual (non-preflight) request
/// <c>CorsMiddleware</c> applies its headers through <c>Response.OnStarting</c>, a callback that
/// fires after any downstream <c>Response.Clear()</c> — this writer's included — so
/// <c>Access-Control-Allow-Origin</c> already survives independently of this helper.
/// </para>
/// </summary>
public static class ResponseHeaderPreserver
{
    /// <summary>
    /// The <see cref="HttpContext.Items"/> key <see cref="CaptureIntoItems"/> stashes the
    /// request-derived snapshot under.
    /// </summary>
    private const string ItemsKey = "Dependably.ResponseHeaderPreserver.Stash";

    private static readonly string[] PreservedHeaderNames =
    [
        // SecurityHeadersMiddleware — request-derived; Capture() prefers the CaptureIntoItems
        // stash over a live read for these, see the doc comment above.
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "Cache-Control",

        // CorsMiddleware — never stashed; live-read only, and only ever live for
        // TenantNotReadyResponseWriter (see the doc comment above).
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Expose-Headers",
        "Vary",
    ];

    /// <summary>
    /// Captures the current value of every preserved header, preferring the snapshot
    /// <see cref="CaptureIntoItems"/> stashed earlier in the pipeline over a live read — see the
    /// class doc comment for why the stash takes precedence — and falling back to a live read only
    /// when there is no stash (no <c>SecurityHeadersMiddleware</c> ran in front of this call, e.g.
    /// a unit test constructing its own <see cref="HttpContext"/>). Call before
    /// <c>Response.Clear()</c>.
    /// </summary>
    public static Dictionary<string, StringValues> Capture(HttpContext context)
    {
        var stash = context.Items.TryGetValue(ItemsKey, out object? stashed)
            ? stashed as IReadOnlyDictionary<string, StringValues>
            : null;

        var snapshot = new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase);
        var headers = context.Response.Headers;
        foreach (string name in PreservedHeaderNames)
        {
            if (stash is not null && stash.TryGetValue(name, out var stashedValue))
            {
                snapshot[name] = stashedValue;
            }
            else if (headers.TryGetValue(name, out var liveValue))
            {
                snapshot[name] = liveValue;
            }
        }

        return snapshot;
    }

    /// <summary>
    /// Re-applies a snapshot captured by <see cref="Capture"/>. Call after <c>Response.Clear()</c>.
    /// </summary>
    public static void Restore(HttpContext context, Dictionary<string, StringValues> snapshot)
    {
        var headers = context.Response.Headers;
        foreach (var (name, value) in snapshot)
        {
            headers[name] = value;
        }
    }

    /// <summary>
    /// Stashes the request-derived headers <c>SecurityHeadersMiddleware</c> just set into
    /// <see cref="HttpContext.Items"/>, so <see cref="Capture"/> can still recover them later even
    /// if something downstream — including ASP.NET Core's own exception-handler
    /// <c>Response.Clear()</c>, which runs before any <c>IExceptionHandler</c> is invoked, or a
    /// handler that overwrites <c>Cache-Control</c> with an artifact-specific value before later
    /// throwing — changes or clears the live headers first. Call immediately after setting them,
    /// before <c>_next</c> runs.
    /// </summary>
    public static void CaptureIntoItems(HttpContext context)
        => context.Items[ItemsKey] = Capture(context);
}
