using Dependably.Infrastructure.Observability;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Covers the route → <c>dependably.operation</c> mapping table in
/// <see cref="OperationTagger"/>. Each documented operation in
/// <c>taxonomy.md#operation-vocabulary</c> should have at least one
/// representative route that maps to it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OperationTaggerTests
{
    [Theory]
    [InlineData("/simple/", "GET", "index.simple")]
    [InlineData("/simple/{package}/", "GET", "index.simple")]
    [InlineData("/nuget/v3/index.json", "GET", "index.simple")]
    [InlineData("/nuget/index.json", "GET", "index.simple")]
    public void MapsToIndexSimple(string route, string method, string expected)
        => Assert.Equal(expected, OperationTagger.Map(route, method));

    [Theory]
    [InlineData("/npm/{package}", "GET", "index.metadata")]
    [InlineData("/npm/@{scope}/{package}", "GET", "index.metadata")]
    [InlineData("/npm/{package}/{version}", "GET", "index.metadata")]
    [InlineData("/nuget/registration/{id}/", "GET", "index.metadata")]
    [InlineData("/nuget/registration5-semver2/{id}/", "GET", "index.metadata")]
    [InlineData("/nuget/flatcontainer/{id}/index.json", "GET", "index.metadata")]
    public void MapsToIndexMetadata(string route, string method, string expected)
        => Assert.Equal(expected, OperationTagger.Map(route, method));

    [Fact]
    public void NuGetQueryMapsToIndexSearch()
        => Assert.Equal("index.search", OperationTagger.Map("/nuget/query", "GET"));

    [Theory]
    [InlineData("/packages/{file}", "GET")]
    [InlineData("/npm/tarballs/{pkg}/{file}", "GET")]
    [InlineData("/npm/tarballs/@{scope}/{pkg}/{file}", "GET")]
    [InlineData("/npm/{pkg}/-/{file}", "GET")]
    [InlineData("/npm/@{scope}/{pkg}/-/{file}", "GET")]
    [InlineData("/nuget/flatcontainer/{id}/{version}/{file}", "GET")]
    [InlineData("/nuget/symbols/{id}/{version}/{file}", "GET")]
    public void MapsToPackageDownload(string route, string method)
        => Assert.Equal("package.download", OperationTagger.Map(route, method));

    [Theory]
    [InlineData("/pypi/legacy/", "POST")]
    [InlineData("/npm/{package}", "PUT")]
    [InlineData("/npm/@{scope}/{package}", "PUT")]
    [InlineData("/nuget/publish", "PUT")]
    [InlineData("/nuget/symbols", "PUT")]
    public void MapsToPackagePublish(string route, string method)
        => Assert.Equal("package.publish", OperationTagger.Map(route, method));

    [Fact]
    public void NuGetDeleteMapsToPackageUnlist()
        => Assert.Equal("package.unlist", OperationTagger.Map("/nuget/publish/{id}/{version}", "DELETE"));

    [Theory]
    [InlineData("api/v1/auth/login", "POST")]
    [InlineData("login", "GET")]
    public void MapsToAuthSsoSignin(string route, string method)
        => Assert.Equal("auth.sso_signin", OperationTagger.Map(route, method));

    [Fact]
    public void NpmPutMapsToPublish_NotMetadataRead()
    {
        // Same route, different method must produce different operations.
        Assert.Equal("index.metadata", OperationTagger.Map("/npm/{package}", "GET"));
        Assert.Equal("package.publish", OperationTagger.Map("/npm/{package}", "PUT"));
    }

    [Fact]
    public void UnknownRouteReturnsNull()
        => Assert.Null(OperationTagger.Map("/api/v1/some-management-endpoint", "GET"));

    [Fact]
    public void NullRouteReturnsNull()
        => Assert.Null(OperationTagger.Map(null, "GET"));
}
