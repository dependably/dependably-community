using Dependably.Infrastructure.Observability;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Covers the route → <c>dependably.operation</c> mapping table in
/// <see cref="OperationTagger"/>. Each documented operation in
/// <c>taxonomy.md#operation-vocabulary</c> should have at least one
/// representative route that maps to it.
///
/// <para>
/// Route strings here are the templates ASP.NET emits in <c>http.route</c> — no leading slash,
/// no trailing slash. These assertions alone cannot prove that: they would pass just as happily
/// against URL-form literals the app never emits, which is exactly how this table's protocol
/// half went inert while staying green. <c>OperationTaggerRouteTableTests</c> is the gate that
/// checks the keys against the real endpoint table; this file covers the mapping logic.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class OperationTaggerTests
{
    [Theory]
    [InlineData("simple", "GET", "index.simple")]
    [InlineData("simple/{package}", "GET", "index.simple")]
    [InlineData("nuget/v3/index.json", "GET", "index.simple")]
    [InlineData("nuget/index.json", "GET", "index.simple")]
    public void MapsToIndexSimple(string route, string method, string expected)
        => Assert.Equal(expected, OperationTagger.Map(route, method));

    [Theory]
    [InlineData("npm/{package}", "GET", "index.metadata")]
    [InlineData("npm/@{scope}/{package}", "GET", "index.metadata")]
    [InlineData("npm/{package}/{version}", "GET", "index.metadata")]
    [InlineData("nuget/flatcontainer/{id}/index.json", "GET", "index.metadata")]
    public void MapsToIndexMetadata(string route, string method, string expected)
        => Assert.Equal(expected, OperationTagger.Map(route, method));

    [Theory]
    // The registration surface resolves by prefix: five client-compatibility flavours times
    // three shapes (bare id, index.json, and the {version}.json leaf) are all metadata reads.
    [InlineData("nuget/registration/{id}")]
    [InlineData("nuget/registration/{id}/index.json")]
    [InlineData("nuget/registration/{id}/{version}.json")]
    [InlineData("nuget/registration5-semver1/{id}/index.json")]
    [InlineData("nuget/registration5-gz-semver1/{id}/{version}.json")]
    [InlineData("nuget/registration5-semver2/{id}")]
    [InlineData("nuget/registration5-gz-semver2/{id}/index.json")]
    public void RegistrationRoutesMapToIndexMetadata(string route)
        => Assert.Equal("index.metadata", OperationTagger.Map(route, "GET"));

    [Fact]
    public void NuGetQueryMapsToIndexSearch()
        => Assert.Equal("index.search", OperationTagger.Map("nuget/query", "GET"));

    [Theory]
    [InlineData("packages/{file}", "GET")]
    [InlineData("npm/tarballs/{pkg}/{file}", "GET")]
    [InlineData("npm/tarballs/@{scope}/{pkg}/{file}", "GET")]
    [InlineData("npm/{pkg}/-/{file}", "GET")]
    [InlineData("npm/@{scope}/{pkg}/-/{file}", "GET")]
    [InlineData("nuget/flatcontainer/{id}/{version}/{file}", "GET")]
    [InlineData("nuget/symbols/{id}/{version}/{file}", "GET")]
    public void MapsToPackageDownload(string route, string method)
        => Assert.Equal("package.download", OperationTagger.Map(route, method));

    [Fact]
    public void SsqpSymbolRouteMapsToPackageDownload()
        => Assert.Equal("package.download", OperationTagger.Map(OperationTagger.SsqpSymbolRoute, "GET"));

    [Theory]
    [InlineData("pypi/legacy", "POST")]
    [InlineData("npm/{package}", "PUT")]
    [InlineData("npm/@{scope}/{package}", "PUT")]
    [InlineData("nuget/publish", "PUT")]
    [InlineData("nuget/symbols", "PUT")]
    public void MapsToPackagePublish(string route, string method)
        => Assert.Equal("package.publish", OperationTagger.Map(route, method));

    [Fact]
    public void NuGetDeleteMapsToPackageUnlist()
        => Assert.Equal("package.unlist", OperationTagger.Map("nuget/publish/{id}/{version}", "DELETE"));

    [Fact]
    public void LoginMapsToAuthSsoSignin()
        => Assert.Equal("auth.sso_signin", OperationTagger.Map("api/v1/auth/login", "POST"));

    [Fact]
    public void NpmPutMapsToPublish_NotMetadataRead()
    {
        // Same route, different method must produce different operations.
        Assert.Equal("index.metadata", OperationTagger.Map("npm/{package}", "GET"));
        Assert.Equal("package.publish", OperationTagger.Map("npm/{package}", "PUT"));
    }

    [Theory]
    [InlineData("unmatched/route", "GET")]
    [InlineData("nuget/publish", "GET")]   // right route, wrong method → no match
    [InlineData("pypi/legacy", "GET")]     // publish is POST-only
    public void UnknownRouteOrMethodReturnsNull(string route, string method)
        => Assert.Null(OperationTagger.Map(route, method));

    [Theory]
    // URL-form keys are what the table used to hold, and every one of them was inert. Locking
    // these to null keeps a "helpful" leading slash from being reintroduced.
    [InlineData("/simple/", "GET")]
    [InlineData("/nuget/flatcontainer/{id}/{version}/{file}", "GET")]
    [InlineData("/nuget/symbols/{id}/{version}/{file}", "GET")]
    public void UrlFormRoutesDoNotMatch(string route, string method)
        => Assert.Null(OperationTagger.Map(route, method));

    [Fact]
    public void NullRouteReturnsNull()
        => Assert.Null(OperationTagger.Map(null, "GET"));

    [Fact]
    public void UnknownManagementRouteReturnsNull()
        => Assert.Null(OperationTagger.Map("api/v1/some-management-endpoint", "GET"));
}
