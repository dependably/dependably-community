using System.Globalization;
using Dependably.Api;
using Dependably.Resources;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class ProblemResultsTests
{
    private static ProblemResults New() => new(new EchoLocalizer());

    private static ProblemDetails StatusJsonBody(IResult r)
    {
        // IResult.Json wraps the value in a JsonHttpResult<T>. Unwrap it without going
        // through a full HttpContext to keep the test free of plumbing.
        var typed = Assert.IsType<JsonHttpResult<ProblemDetails>>(r);
        Assert.NotNull(typed.Value);
        return typed.Value!;
    }

    private static ProblemDetails ActionObjectResultBody(IActionResult r, int expectedStatus)
    {
        var obj = Assert.IsType<ObjectResult>(r);
        Assert.Equal(expectedStatus, obj.StatusCode);
        return Assert.IsType<ProblemDetails>(obj.Value);
    }

    [Fact]
    public void ValidationError_WithField_SetsExtensionAndStatus422()
    {
        var result = New().ValidationError("name is required", "name");

        var body = StatusJsonBody(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, body.Status);
        Assert.Equal("name is required", body.Detail);
        Assert.Equal("error.validation.title", body.Title);
        Assert.Equal("name", body.Extensions["field"]);
    }

    [Fact]
    public void ValidationError_WithoutField_OmitsExtension()
    {
        var result = New().ValidationError("invalid");

        var body = StatusJsonBody(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, body.Status);
        Assert.False(body.Extensions.ContainsKey("field"));
    }

    [Fact]
    public void Conflict_Status409()
    {
        var body = StatusJsonBody(New().Conflict("dupe"));
        Assert.Equal(StatusCodes.Status409Conflict, body.Status);
        Assert.Equal("dupe", body.Detail);
        Assert.Equal("error.conflict.title", body.Title);
    }

    [Fact]
    public void PayloadTooLarge_Status413()
    {
        var body = StatusJsonBody(New().PayloadTooLarge("too big"));
        Assert.Equal(StatusCodes.Status413PayloadTooLarge, body.Status);
        Assert.Equal("too big", body.Detail);
    }

    [Fact]
    public void NotFound_Status404()
    {
        var body = StatusJsonBody(New().NotFound("missing"));
        Assert.Equal(StatusCodes.Status404NotFound, body.Status);
        Assert.Equal("missing", body.Detail);
    }

    [Fact]
    public void OrgNotFound_RoutesThroughNotFound_WithLocalizedDetail()
    {
        var body = StatusJsonBody(New().OrgNotFound());
        Assert.Equal(StatusCodes.Status404NotFound, body.Status);
        Assert.Equal("error.org.notFound", body.Detail);
    }

    [Fact]
    public void Unauthorized_Status401()
    {
        var body = StatusJsonBody(New().Unauthorized("dependably"));
        Assert.Equal(StatusCodes.Status401Unauthorized, body.Status);
        Assert.Equal("error.auth.required", body.Detail);
    }

    [Fact]
    public void Forbidden_DefaultDetail_Status403()
    {
        var body = StatusJsonBody(New().Forbidden());
        Assert.Equal(StatusCodes.Status403Forbidden, body.Status);
        Assert.Equal("error.auth.forbidden", body.Detail);
    }

    [Fact]
    public void Forbidden_CustomDetail_Overrides()
    {
        var body = StatusJsonBody(New().Forbidden("only owners"));
        Assert.Equal("only owners", body.Detail);
    }

    [Fact]
    public void ValidationErrorAction_SetsField_AndStatus422()
    {
        var body = ActionObjectResultBody(
            New().ValidationErrorAction("email", "must be an email"),
            StatusCodes.Status422UnprocessableEntity);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, body.Status);
        Assert.Equal("email", body.Extensions["field"]);
        Assert.Equal("must be an email", body.Detail);
    }

    [Fact]
    public void ConflictAction_Status409()
    {
        var body = ActionObjectResultBody(
            New().ConflictAction("already taken"),
            StatusCodes.Status409Conflict);
        Assert.Equal(StatusCodes.Status409Conflict, body.Status);
        Assert.Equal("already taken", body.Detail);
    }

    /// <summary>
    /// Echoes the key back as the value so assertions can verify which resource key
    /// each helper looked up without depending on the real .resx contents.
    /// </summary>
    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);
        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);
        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}
