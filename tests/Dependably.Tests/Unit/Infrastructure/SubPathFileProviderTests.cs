using Dependably.Infrastructure;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using NSubstitute;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Coverage for SubPathFileProvider — verifies the Combine helper re-roots all three
/// IFileProvider calls (GetFileInfo, GetDirectoryContents, Watch) under the configured
/// prefix and copes with the edge-cases the production wiring hits (empty path from
/// the Swagger UI mount, slash-only path, traversal-looking input).
/// </summary>
[Trait("Category", "Unit")]
public sealed class SubPathFileProviderTests
{
    [Fact]
    public void Constructor_StripsLeadingAndTrailingSlashes_OnSubPath()
    {
        // The Combine helper builds "/{trimmed}" — both leading and trailing slashes
        // are trimmed off the supplied sub-path so callers can use either convention.
        var inner = Substitute.For<IFileProvider>();
        var sut = new SubPathFileProvider(inner, "/swagger/");

        sut.GetFileInfo("index.html");

        inner.Received(1).GetFileInfo("/swagger/index.html");
    }

    [Fact]
    public void GetFileInfo_RootedAtSubPath_WhenPathEmpty()
    {
        var inner = Substitute.For<IFileProvider>();
        var sut = new SubPathFileProvider(inner, "swagger");

        sut.GetFileInfo("");

        // Empty path collapses to the sub-path root (no trailing slash).
        inner.Received(1).GetFileInfo("/swagger");
    }

    [Fact]
    public void GetFileInfo_RootedAtSubPath_WhenPathIsJustSlash()
    {
        var inner = Substitute.For<IFileProvider>();
        var sut = new SubPathFileProvider(inner, "swagger");

        sut.GetFileInfo("/");

        // "/" is the second collapse-to-root branch.
        inner.Received(1).GetFileInfo("/swagger");
    }

    [Fact]
    public void GetFileInfo_PrefixesSubPath_WhenPathHasLeadingSlash()
    {
        var inner = Substitute.For<IFileProvider>();
        var sut = new SubPathFileProvider(inner, "swagger");

        sut.GetFileInfo("/index.html");

        // Leading slash on the request path is trimmed before joining.
        inner.Received(1).GetFileInfo("/swagger/index.html");
    }

    [Fact]
    public void GetFileInfo_PrefixesSubPath_WhenPathHasNoLeadingSlash()
    {
        var inner = Substitute.For<IFileProvider>();
        var sut = new SubPathFileProvider(inner, "swagger");

        sut.GetFileInfo("index.html");

        inner.Received(1).GetFileInfo("/swagger/index.html");
    }

    [Fact]
    public void GetDirectoryContents_PrefixesSubPath()
    {
        var inner = Substitute.For<IFileProvider>();
        var contents = Substitute.For<IDirectoryContents>();
        inner.GetDirectoryContents("/swagger/css").Returns(contents);
        var sut = new SubPathFileProvider(inner, "swagger");

        var result = sut.GetDirectoryContents("css");

        Assert.Same(contents, result);
        inner.Received(1).GetDirectoryContents("/swagger/css");
    }

    [Fact]
    public void GetDirectoryContents_EmptyPath_ReturnsSubPathRoot()
    {
        var inner = Substitute.For<IFileProvider>();
        var sut = new SubPathFileProvider(inner, "swagger");

        sut.GetDirectoryContents("");

        inner.Received(1).GetDirectoryContents("/swagger");
    }

    [Fact]
    public void Watch_PrefixesSubPath()
    {
        var inner = Substitute.For<IFileProvider>();
        var token = Substitute.For<IChangeToken>();
        inner.Watch("/swagger/**/*.html").Returns(token);
        var sut = new SubPathFileProvider(inner, "swagger");

        var result = sut.Watch("**/*.html");

        Assert.Same(token, result);
        inner.Received(1).Watch("/swagger/**/*.html");
    }

    [Fact]
    public void Watch_EmptyFilter_ReturnsSubPathRoot()
    {
        var inner = Substitute.For<IFileProvider>();
        var sut = new SubPathFileProvider(inner, "swagger");

        sut.Watch("");

        inner.Received(1).Watch("/swagger");
    }

    [Fact]
    public void Combine_TraversalLookingInput_PassesThroughUnchanged()
    {
        // SubPathFileProvider is not a security boundary — path sanitization is the
        // inner provider's responsibility. Verify dot-segments are forwarded verbatim
        // so we don't accidentally develop a security expectation that doesn't hold.
        var inner = Substitute.For<IFileProvider>();
        var sut = new SubPathFileProvider(inner, "swagger");

        sut.GetFileInfo("../etc/passwd");

        inner.Received(1).GetFileInfo("/swagger/../etc/passwd");
    }

    [Fact]
    public void Constructor_HandlesSubPathWithoutLeadingSlash()
    {
        // Production wiring passes "swagger" (no leading slash) — verify it still produces
        // the right join key.
        var inner = Substitute.For<IFileProvider>();
        var sut = new SubPathFileProvider(inner, "swagger");

        sut.GetFileInfo("oauth2-redirect.html");

        inner.Received(1).GetFileInfo("/swagger/oauth2-redirect.html");
    }

    [Fact]
    public void WorksOverPhysicalFileProvider_ResolvesRealFile()
    {
        // Integration-ish smoke: compose against a real PhysicalFileProvider rooted at a
        // temp directory. Exercises the full code path against a non-mocked inner.
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            string sub = Path.Combine(dir.FullName, "swagger");
            Directory.CreateDirectory(sub);
            string file = Path.Combine(sub, "index.html");
            File.WriteAllText(file, "<html/>");

            var inner = new PhysicalFileProvider(dir.FullName);
            var sut = new SubPathFileProvider(inner, "swagger");

            var info = sut.GetFileInfo("index.html");
            Assert.True(info.Exists);
            Assert.Equal("index.html", info.Name);
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }
}
