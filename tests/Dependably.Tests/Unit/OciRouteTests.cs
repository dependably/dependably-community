using Dependably.Api;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Routing acceptance for #98: the OCI Distribution Spec catches the three GET-side
/// surfaces — manifests/, blobs/, tags/list — out of an arbitrary-depth repository path.
/// Repository names can contain slashes (e.g. <c>library/ubuntu</c>) which is why we
/// can't use the ASP.NET catch-all-with-trailing-segments pattern.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciRouteTests
{
    [Fact]
    public void Parse_SimpleManifest()
    {
        var r = OciRoute.Parse("library/ubuntu/manifests/latest");
        Assert.NotNull(r);
        Assert.Equal(OciRouteKind.Manifest, r!.Kind);
        Assert.Equal("library/ubuntu", r.Name);
        Assert.Equal("latest", r.Reference);
    }

    [Fact]
    public void Parse_DeepRepoNameManifest()
    {
        var r = OciRoute.Parse("acme/web/api/manifests/v1.2.3");
        Assert.NotNull(r);
        Assert.Equal("acme/web/api", r!.Name);
        Assert.Equal("v1.2.3", r.Reference);
    }

    [Fact]
    public void Parse_BlobDigest()
    {
        var r = OciRoute.Parse("library/ubuntu/blobs/sha256:abc123");
        Assert.NotNull(r);
        Assert.Equal(OciRouteKind.Blob, r!.Kind);
        Assert.Equal("library/ubuntu", r.Name);
        Assert.Equal("sha256:abc123", r.Reference);
    }

    [Fact]
    public void Parse_TagsList()
    {
        var r = OciRoute.Parse("library/ubuntu/tags/list");
        Assert.NotNull(r);
        Assert.Equal(OciRouteKind.TagsList, r!.Kind);
        Assert.Equal("library/ubuntu", r.Name);
        Assert.Null(r.Reference);
    }

    [Fact]
    public void Parse_BlobUploadsPath_ReturnsNull()
    {
        // /blobs/uploads/... is the push-path the proxy MVP doesn't implement;
        // surfacing null lets the controller return UNSUPPORTED cleanly.
        Assert.Null(OciRoute.Parse("library/ubuntu/blobs/uploads/abc"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("noop")]
    [InlineData("repo/unsupported/path")]
    public void Parse_Garbage_ReturnsNull(string path)
        => Assert.Null(OciRoute.Parse(path));
}
