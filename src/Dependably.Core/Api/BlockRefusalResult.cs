using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Builds the 403 a block-gate refusal returns, carrying the arm that refused it.
///
/// Every policy denial previously reached the client as a bare <c>StatusCodeResult(403)</c> with an
/// empty body — indistinguishable on the wire from an authorization failure, and carrying nothing
/// an operator could correlate against their own policy. A developer whose build broke saw
/// <c>403 Forbidden</c>; the reason existed only in the activity feed, which is not where anyone
/// looks first when a package manager fails.
///
/// The header names the arm using the same vocabulary the quarantine review queue and the
/// dashboard already use, so one refusal has one name across every surface an operator might read.
/// </summary>
public static class BlockRefusalResult
{
    /// <summary>
    /// The response header naming which policy arm refused a request. <c>X-</c>-prefixed and
    /// carrying a closed-vocabulary token, matching the existing <c>X-Cache</c> /
    /// <c>X-Upstream-Status</c> convention on this plane.
    /// </summary>
    public const string ReasonHeader = "X-Dependably-Block-Reason";

    /// <summary>
    /// A 403 that says which arm refused it. Only the arm name goes on the wire — never the
    /// policy's configured values, the tolerances, or the advisory ids behind them. An error body
    /// travels further than the request did, into CI logs, screenshots and support tickets, and a
    /// tenant's configured thresholds are not something a package client needs in order to act:
    /// knowing the hold is <c>release_age</c> is enough to wait or pin, and knowing it is
    /// <c>malicious</c> is enough to stop.
    ///
    /// The header is omitted rather than emitted empty when the arm is unknown, so its presence
    /// always means something.
    /// </summary>
    public static IActionResult Forbidden(HttpContext httpContext, BlockOutcome outcome)
    {
        if (outcome.ReasonToken is { Length: > 0 } token)
        {
            httpContext.Response.Headers[ReasonHeader] = HeaderSanitizer.Sanitize(token);
        }

        return new StatusCodeResult(StatusCodes.Status403Forbidden);
    }
}
