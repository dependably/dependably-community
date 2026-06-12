using Dependably.Api;

namespace Dependably.Tests.Unit;

/// <summary>
/// Routing acceptance: the OCI Distribution Spec surfaces parsed out of an arbitrary-depth
/// repository path — manifests/, blobs/, tags/list (read side) plus blobs/uploads and
/// blobs/uploads/{id} (push side). Repository names can contain slashes (e.g.
/// <c>library/ubuntu</c>) which is why we can't use the ASP.NET catch-all-with-trailing-segments
/// pattern.
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
    public void Parse_BlobUploadInit()
    {
        var r = OciRoute.Parse("library/ubuntu/blobs/uploads");
        Assert.NotNull(r);
        Assert.Equal(OciRouteKind.BlobUploadInit, r!.Kind);
        Assert.Equal("library/ubuntu", r.Name);
        Assert.Null(r.Reference);
    }

    [Fact]
    public void Parse_BlobUploadInit_TrailingSlashTrimmed()
    {
        // POST /v2/{name}/blobs/uploads/ — the catch-all may carry a trailing slash; Parse
        // trims it and still resolves to the init kind.
        var r = OciRoute.Parse("library/ubuntu/blobs/uploads/");
        Assert.NotNull(r);
        Assert.Equal(OciRouteKind.BlobUploadInit, r!.Kind);
        Assert.Equal("library/ubuntu", r.Name);
    }

    [Fact]
    public void Parse_BlobUploadSession()
    {
        var r = OciRoute.Parse("library/ubuntu/blobs/uploads/9f8e7d6c5b4a");
        Assert.NotNull(r);
        Assert.Equal(OciRouteKind.BlobUploadSession, r!.Kind);
        Assert.Equal("library/ubuntu", r.Name);
        Assert.Equal("9f8e7d6c5b4a", r.Reference);
    }

    [Theory]
    [InlineData("")]
    [InlineData("noop")]
    [InlineData("repo/unsupported/path")]
    public void Parse_Garbage_ReturnsNull(string path)
        => Assert.Null(OciRoute.Parse(path));
}
