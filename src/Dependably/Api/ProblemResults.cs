using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;

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
        {
            problem.Extensions["field"] = field;
        }

        return Results.Json(problem, statusCode: StatusCodes.Status422UnprocessableEntity);
    }

    public IResult Conflict(string detail)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status409Conflict,
            Title = _localizer["error.conflict.title"],
            Detail = detail,
        };
        return Results.Json(problem, statusCode: StatusCodes.Status409Conflict);
    }

    public IResult PayloadTooLarge(string detail)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status413PayloadTooLarge,
            Title = _localizer["error.payloadTooLarge.title"],
            Detail = detail,
        };
        return Results.Json(problem, statusCode: StatusCodes.Status413PayloadTooLarge);
    }

    public IResult NotFound(string detail)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status404NotFound,
            Title = _localizer["error.notFound.title"],
            Detail = detail,
        };
        return Results.Json(problem, statusCode: StatusCodes.Status404NotFound);
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
        return Results.Json(problem, statusCode: StatusCodes.Status401Unauthorized);
    }

    public IResult Forbidden(string? detail = null)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status403Forbidden,
            Title = _localizer["error.forbidden.title"],
            Detail = detail ?? _localizer["error.auth.forbidden"],
        };
        return Results.Json(problem, statusCode: StatusCodes.Status403Forbidden);
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
        return new ObjectResult(problem) { StatusCode = StatusCodes.Status422UnprocessableEntity };
    }

    /// <summary>Variant of <see cref="ValidationErrorAction"/> whose detail is a SharedResource
    /// key, resolved against the per-request culture. Optional args are applied as
    /// string.Format placeholders ({0}, {1}, …) in the resource value.</summary>
    public IActionResult ValidationErrorActionKey(string fieldName, string resourceKey, params object[] args)
        => ValidationErrorAction(fieldName, Localize(resourceKey, args));

    /// <summary>Variant of <see cref="ConflictAction"/> whose detail is a SharedResource
    /// key, resolved against the per-request culture.</summary>
    public IActionResult ConflictActionKey(string resourceKey, string? reason = null)
        => ConflictAction(_localizer[resourceKey], reason);

    /// <summary>Like <see cref="ConflictActionKey"/> but with string.Format placeholders.
    /// Separate name because a params overload would bind a lone string argument to the
    /// reason parameter of <see cref="ConflictActionKey"/> instead.</summary>
    public IActionResult ConflictActionKeyFormat(string resourceKey, params object[] args)
        => ConflictAction(Localize(resourceKey, args));

    /// <summary>Variant of <see cref="ForbiddenAction"/> whose detail is a SharedResource
    /// key, resolved against the per-request culture.</summary>
    public IActionResult ForbiddenActionKey(string resourceKey, string? reason = null)
        => ForbiddenAction(_localizer[resourceKey], reason);

    // The two-arg localizer indexer always runs string.Format; route zero-arg lookups
    // through the plain indexer so resource values may contain literal braces.
    private string Localize(string resourceKey, object[] args)
        => args.Length == 0 ? _localizer[resourceKey] : _localizer[resourceKey, args];

    public IActionResult ConflictAction(string detail, string? reason = null)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status409Conflict,
            Title = _localizer["error.conflict.title"],
            Detail = detail,
        };
        if (reason is not null)
        {
            problem.Extensions["reason"] = reason;
        }

        return new ObjectResult(problem) { StatusCode = StatusCodes.Status409Conflict };
    }

    public IActionResult ForbiddenAction(string detail, string? reason = null)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status403Forbidden,
            Title = _localizer["error.forbidden.title"],
            Detail = detail,
        };
        if (reason is not null)
        {
            problem.Extensions["reason"] = reason;
        }

        return new ObjectResult(problem) { StatusCode = StatusCodes.Status403Forbidden };
    }
}
