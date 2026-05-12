using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Dependably.Resources;

namespace Dependably.Api;

/// <summary>RFC 7807 problem detail helpers for consistent error responses.</summary>
public sealed class ProblemResults
{
    private readonly IStringLocalizer<SharedResource> _localizer;

    public ProblemResults(IStringLocalizer<SharedResource> localizer)
    {
        _localizer = localizer;
    }

    public IResult ValidationError(string detail, string? field = null)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status422UnprocessableEntity,
            Title = _localizer["error.validation.title"],
            Detail = detail,
        };
        if (field is not null)
            problem.Extensions["field"] = field;
        return Results.Json(problem, statusCode: 422);
    }

    public IResult Conflict(string detail)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status409Conflict,
            Title = _localizer["error.conflict.title"],
            Detail = detail,
        };
        return Results.Json(problem, statusCode: 409);
    }

    public IResult PayloadTooLarge(string detail)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status413PayloadTooLarge,
            Title = _localizer["error.payloadTooLarge.title"],
            Detail = detail,
        };
        return Results.Json(problem, statusCode: 413);
    }

    public IResult NotFound(string detail)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status404NotFound,
            Title = _localizer["error.notFound.title"],
            Detail = detail,
        };
        return Results.Json(problem, statusCode: 404);
    }

    public IResult OrgNotFound() => NotFound(_localizer["error.org.notFound"]);

    public IResult Unauthorized(string realm, string scheme = "Basic")
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status401Unauthorized,
            Title = _localizer["error.unauthorized.title"],
            Detail = _localizer["error.auth.required"],
        };
        // Note: callers must set WWW-Authenticate header directly; Results.Json doesn't support headers
        return Results.Json(problem, statusCode: 401);
    }

    public IResult Forbidden(string? detail = null)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status403Forbidden,
            Title = _localizer["error.forbidden.title"],
            Detail = detail ?? _localizer["error.auth.forbidden"],
        };
        return Results.Json(problem, statusCode: 403);
    }

    // ── IActionResult variants for use in [ApiController] controllers ─────────

    public IActionResult ValidationErrorAction(string fieldName, string detail)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status422UnprocessableEntity,
            Title = _localizer["error.validation.title"],
            Detail = detail,
        };
        problem.Extensions["field"] = fieldName;
        return new ObjectResult(problem) { StatusCode = 422 };
    }

    public IActionResult ConflictAction(string detail)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status409Conflict,
            Title = _localizer["error.conflict.title"],
            Detail = detail,
        };
        return new ObjectResult(problem) { StatusCode = 409 };
    }
}
