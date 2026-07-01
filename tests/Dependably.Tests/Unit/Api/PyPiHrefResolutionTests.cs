using Dependably.Api.PyPiProtocol;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// PyPI simple-index href resolution (<see cref="PyPiProxyFetcher.ResolvePyPiHref"/>): absolute
/// hrefs (public PyPI) and root-relative hrefs (chaining through another dependably upstream),
/// with and without the PEP 503 <c>#sha256=</c> fragment.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiHrefResolutionTests
{
    private const string SimpleIndexUrl = "https://cache.example/simple/requests/";
    private const string File = "requests-2.31.0-py3-none-any.whl";
    private const string Sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 64 hex chars

    [Fact]
    public void AbsoluteHref_WithSha_IsReturnedVerbatim()
    {
        string html = $"<a href=\"https://files.pythonhosted.org/packages/aa/bb/{File}#sha256={Sha}\">{File}</a>";
        var result = PyPiProxyFetcher.ResolvePyPiHref(SimpleIndexUrl, html, File);
        Assert.NotNull(result);
        Assert.Equal($"https://files.pythonhosted.org/packages/aa/bb/{File}", result.Value.Url);
        Assert.Equal(Sha, result.Value.Sha256Hex);
    }

    [Fact]
    public void RootRelativeHref_IsResolvedAgainstSimpleIndexHost()
    {
        // Another dependably upstream emits a root-relative href; it must resolve to the upstream host.
        string html = $"<a href=\"/packages/{File}#sha256={Sha}\">{File}</a>";
        var result = PyPiProxyFetcher.ResolvePyPiHref(SimpleIndexUrl, html, File);
        Assert.NotNull(result);
        Assert.Equal($"https://cache.example/packages/{File}", result.Value.Url);
        Assert.Equal(Sha, result.Value.Sha256Hex);
    }

    [Fact]
    public void RelativeHref_WithoutFragment_ResolvesWithNullSha()
    {
        string html = $"<a href=\"/packages/{File}\">{File}</a>";
        var result = PyPiProxyFetcher.ResolvePyPiHref(SimpleIndexUrl, html, File);
        Assert.NotNull(result);
        Assert.Equal($"https://cache.example/packages/{File}", result.Value.Url);
        Assert.Null(result.Value.Sha256Hex);
    }

    [Fact]
    public void FileNotInIndex_ReturnsNull()
    {
        string html = "<a href=\"/packages/other-1.0.0.whl\">other</a>";
        Assert.Null(PyPiProxyFetcher.ResolvePyPiHref(SimpleIndexUrl, html, File));
    }
}
