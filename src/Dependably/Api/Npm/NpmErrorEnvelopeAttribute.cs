using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Surfaces a ProblemDetails error reason to the npm CLI. The npm client renders only the
/// <c>error</c> member of a registry error body and ignores RFC 7807 <c>detail</c>/<c>title</c>,
/// so a 4xx publish rejection otherwise reaches the user as a bare "422 Unprocessable Entity"
/// with no reason. This result filter copies <c>detail</c> (falling back to <c>title</c>) into an
/// <c>error</c> problem extension, which serializes as a top-level member — keeping the response
/// valid RFC 7807 for other clients while making the rejection reason visible to npm. Applied to
/// every <see cref="NpmController"/> action so all current and future npm error paths are covered.
/// </summary>
public sealed class NpmErrorEnvelopeAttribute : ResultFilterAttribute
{
    public override void OnResultExecuting(ResultExecutingContext context)
    {
        if (context.Result is ObjectResult { Value: ProblemDetails problem } result
            && (result.StatusCode ?? problem.Status) >= StatusCodes.Status400BadRequest
            && !problem.Extensions.ContainsKey("error"))
        {
            problem.Extensions["error"] = problem.Detail ?? problem.Title ?? "Request rejected.";
        }

        base.OnResultExecuting(context);
    }
}
