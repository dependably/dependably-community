using Dependably.Infrastructure.Observability;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the <see cref="OperationTagger.Map"/> route→operation table so every documented
/// taxonomy mapping (and the null/unmatched fall-throughs) is locked in.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OperationTaggerTests
{
    [Theory]
    // PyPI
    [InlineData("/simple/", "GET", "index.simple")]
    [InlineData("/simple/{package}/", "GET", "index.simple")]
    [InlineData("/packages/{file}", "GET", "package.download")]
    [InlineData("/pypi/legacy/", "POST", "package.publish")]
    // npm
    [InlineData("/npm/{package}", "GET", "index.metadata")]
    [InlineData("/npm/@{scope}/{package}", "GET", "index.metadata")]
    [InlineData("/npm/{package}/{version}", "GET", "index.metadata")]
    [InlineData("/npm/{package}", "PUT", "package.publish")]
    [InlineData("/npm/@{scope}/{package}", "PUT", "package.publish")]
    [InlineData("/npm/tarballs/{pkg}/{file}", "GET", "package.download")]
    [InlineData("/npm/tarballs/@{scope}/{pkg}/{file}", "GET", "package.download")]
    [InlineData("/npm/{pkg}/-/{file}", "GET", "package.download")]
    [InlineData("/npm/@{scope}/{pkg}/-/{file}", "GET", "package.download")]
    // NuGet
    [InlineData("/nuget/v3/index.json", "GET", "index.simple")]
    [InlineData("/nuget/index.json", "GET", "index.simple")]
    [InlineData("/nuget/query", "GET", "index.search")]
    [InlineData("/nuget/registration/{id}/", "GET", "index.metadata")]
    [InlineData("/nuget/registration5-semver1/{id}/", "GET", "index.metadata")]
    [InlineData("/nuget/registration5-gz-semver1/{id}/", "GET", "index.metadata")]
    [InlineData("/nuget/registration5-semver2/{id}/", "GET", "index.metadata")]
    [InlineData("/nuget/registration5-gz-semver2/{id}/", "GET", "index.metadata")]
    [InlineData("/nuget/flatcontainer/{id}/index.json", "GET", "index.metadata")]
    [InlineData("/nuget/flatcontainer/{id}/{version}/{file}", "GET", "package.download")]
    [InlineData("/nuget/publish", "PUT", "package.publish")]
    [InlineData("/nuget/symbols", "PUT", "package.publish")]
    [InlineData("/nuget/publish/{id}/{version}", "DELETE", "package.unlist")]
    [InlineData("/nuget/symbols/{id}/{version}/{file}", "GET", "package.download")]
    // Auth
    [InlineData("api/v1/auth/login", "POST", "auth.sso_signin")]
    [InlineData("login", "GET", "auth.sso_signin")]
    public void Map_KnownRoutes_ReturnCanonicalOperation(string route, string method, string expected)
    {
        Assert.Equal(expected, OperationTagger.Map(route, method));
    }

    [Fact]
    public void Map_NullRoute_ReturnsNull()
    {
        Assert.Null(OperationTagger.Map(null, "GET"));
    }

    [Theory]
    [InlineData("/unmatched/route", "GET")]
    [InlineData("/nuget/publish", "GET")]   // right route, wrong method → no match
    [InlineData("/pypi/legacy/", "GET")]    // publish is POST-only
    public void Map_UnknownRouteOrMethod_ReturnsNull(string route, string method)
    {
        Assert.Null(OperationTagger.Map(route, method));
    }
}
