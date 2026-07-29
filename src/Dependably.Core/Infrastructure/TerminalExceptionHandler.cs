using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure;

/// <summary>
/// Terminal exception handler: the outermost catch in the request pipeline, for any exception
/// no typed middleware claims. Six typed middlewares translate the known domain exceptions
/// (air-gap, staging-disk-full, tenant quota, upstream fetch, SSRF block, tenant-not-ready);
/// anything else lands here and is turned into a localized RFC 7807 <c>problem+json</c> 500
/// carrying a correlation id, plus exactly one structured <c>Error</c> log.
///
/// The response body is a fixed, localized message: no exception type, message, stack frame,
/// or inner-exception text ever crosses the wire. The correlation id is the only thing tying
/// the caller's report to the server-side record, which holds the full detail.
///
/// The correlation id is the ambient W3C trace id (<see cref="Activity.Current"/>), the same
/// value <c>TenantEnrichmentMiddleware</c> pushes into Serilog's <c>TraceId</c> property and
/// OpenTelemetry stamps on every span, so the id the caller quotes joins straight onto the
/// logs and traces of the failed request. Without an ambient activity it falls back to
/// <see cref="HttpContext.TraceIdentifier"/> (Serilog's <c>RequestId</c>).
/// </summary>
public sealed class TerminalExceptionHandler : IExceptionHandler
{
    private static readonly JsonSerializerOptions BodyJson = new(JsonSerializerDefaults.Web);

    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger<TerminalExceptionHandler> _logger;

    public TerminalExceptionHandler(
        IStringLocalizer<SharedResource> localizer,
        ILogger<TerminalExceptionHandler> logger)
    {
        _localizer = localizer;
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        string correlationId = ResolveCorrelationId(httpContext);

        // Path only — the query string can carry tokens and other caller-supplied secrets.
        _logger.LogError(
            exception,
            "{ExceptionType} escaped the request pipeline unhandled for {Method} {Path}; " +
            "returning a 500 problem+json. CorrelationId={CorrelationId}",
            exception.GetType().Name,
            httpContext.Request.Method,
            httpContext.Request.Path.Value ?? "/",
            correlationId);

        if (httpContext.Response.HasStarted)
        {
            // Bytes are already on the wire: status and headers can no longer be changed, so
            // report the exception as unhandled and let the host tear the connection down
            // rather than append a problem document to a half-written body.
            return false;
        }

        httpContext.Response.Clear();
        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
        httpContext.Response.ContentType = "application/problem+json";

        // Response.Clear() drops the headers SecurityHeadersMiddleware set on the way in.
        // A JSON error body must still be sniff-proof.
        httpContext.Response.Headers.XContentTypeOptions = "nosniff";

        var problem = new ProblemDetails
        {
            Type = "about:blank",
            Status = StatusCodes.Status500InternalServerError,
            Title = Localize(httpContext, "error.internal.title"),
            Detail = Localize(httpContext, "error.internal.detail"),
        };
        problem.Extensions["correlationId"] = correlationId;

        await httpContext.Response.WriteAsync(
            JsonSerializer.Serialize(problem, BodyJson), cancellationToken);
        return true;
    }

    private static string ResolveCorrelationId(HttpContext httpContext)
    {
        var traceId = Activity.Current?.TraceId;
        return traceId is { } id && id != default
            ? id.ToString()
            : httpContext.TraceIdentifier;
    }

    /// <summary>
    /// Resolves a SharedResource key against the culture the request negotiated. This handler
    /// runs outside <c>UseRequestLocalization</c> (it has to, to wrap it), so the ambient
    /// <see cref="CultureInfo.CurrentUICulture"/> is not dependable here; the culture is read
    /// back off <see cref="IRequestCultureFeature"/>, which the localization middleware left
    /// on the context, and applied for the duration of the lookup.
    /// </summary>
    private string Localize(HttpContext httpContext, string key)
    {
        var requested = httpContext.Features.Get<IRequestCultureFeature>()?.RequestCulture;
        if (requested is null)
        {
            return _localizer[key];
        }

        var previousCulture = CultureInfo.CurrentCulture;
        var previousUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = requested.Culture;
            CultureInfo.CurrentUICulture = requested.UICulture;
            return _localizer[key];
        }
        finally
        {
            CultureInfo.CurrentCulture = previousCulture;
            CultureInfo.CurrentUICulture = previousUiCulture;
        }
    }
}
