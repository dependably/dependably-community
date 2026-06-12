using System.Diagnostics;
using Dependably.Api;

namespace Dependably.Tests.Unit;

/// <summary>
/// The upstream simple-index rewriter parses attacker-controllable HTML (a hostile or
/// MITM'd upstream), so its anchor pattern must be linear — no super-linear backtracking —
/// while still rewriting real PEP 503 pages correctly.
/// </summary>
[Trait("Category", "Unit")]
public class PyPiSimpleIndexRewriteTests
{
    // Shaped like a real pypi.org simple page for the mypy-extensions fixture package
    // (tests/Dependably.Tests/Fixtures/packages/pypi): sha256 fragments, requires-python
    // and metadata-sidecar attributes, multiple files per release.
    private const string FixtureSimpleIndexHtml = """
        <!DOCTYPE html>
        <html>
          <head>
            <meta name="pypi:repository-version" content="1.1">
            <title>Links for mypy-extensions</title>
          </head>
          <body>
            <h1>Links for mypy-extensions</h1>
            <a href="https://files.pythonhosted.org/packages/98/a4/abc/mypy_extensions-1.0.0-py3-none-any.whl#sha256=4392f6c0eb8a5668a69e23d168ffa70f0be9ccfd32b5cc2d26a34ae5b844552d" data-requires-python="&gt;=3.5" data-dist-info-metadata="sha256=deadbeef" data-core-metadata="sha256=deadbeef">mypy_extensions-1.0.0-py3-none-any.whl</a><br/>
            <a href="https://files.pythonhosted.org/packages/02/fe/def/mypy_extensions-1.0.0.tar.gz#sha256=75dbf8955dc00442a438fc4d0666508a9a97b6bd41aa2f0ffe9d2f2725af0782" data-requires-python="&gt;=3.5">mypy_extensions-1.0.0.tar.gz</a><br/>
          </body>
        </html>
        """;

    [Fact]
    public void FixtureIndex_AnchorsRewrittenToLocalPackagesRoute()
    {
        string rewritten = PyPiController.RewriteUpstreamSimpleIndexHtml(FixtureSimpleIndexHtml);

        // Both anchors point at the local proxy route, keeping the PEP 503 sha256 fragment.
        Assert.Contains(
            "href=\"/packages/mypy_extensions-1.0.0-py3-none-any.whl#sha256=4392f6c0eb8a5668a69e23d168ffa70f0be9ccfd32b5cc2d26a34ae5b844552d\"",
            rewritten);
        Assert.Contains(
            "href=\"/packages/mypy_extensions-1.0.0.tar.gz#sha256=75dbf8955dc00442a438fc4d0666508a9a97b6bd41aa2f0ffe9d2f2725af0782\"",
            rewritten);

        // Anchor text (the filename pip displays) survives.
        Assert.Contains(">mypy_extensions-1.0.0-py3-none-any.whl</a>", rewritten);
        Assert.Contains(">mypy_extensions-1.0.0.tar.gz</a>", rewritten);

        // No anchor still points upstream, and the metadata-sidecar attributes are stripped.
        Assert.DoesNotContain("files.pythonhosted.org", rewritten);
        Assert.DoesNotContain("data-dist-info-metadata", rewritten);
        Assert.DoesNotContain("data-core-metadata", rewritten);
    }

    [Fact]
    public void AnchorWithoutAbsoluteHref_IsLeftUntouched()
    {
        const string html = """<a href="/packages/local-1.0.0.tar.gz">local-1.0.0.tar.gz</a>""";

        string rewritten = PyPiController.RewriteUpstreamSimpleIndexHtml(html);

        Assert.Equal(html, rewritten);
    }

    [Fact]
    public void SingleQuotedAttributes_AreParsed()
    {
        const string html =
            "<a href=\"https://files.pythonhosted.org/packages/aa/bb/pkg-2.0.tar.gz\" data-requires-python='>=3.8'>pkg-2.0.tar.gz</a>";

        string rewritten = PyPiController.RewriteUpstreamSimpleIndexHtml(html);

        Assert.Contains("href=\"/packages/pkg-2.0.tar.gz\"", rewritten);
    }

    [Fact]
    public void PathologicalUnterminatedAnchor_CompletesLinearly()
    {
        // Worst case for a backtracking-prone attribute pattern: a long run of attribute
        // characters and quote flips after "<a " with no closing ">" — the nested-quantifier
        // form of this pattern goes super-linear here. The atomic-group pattern must finish
        // (well inside the 2 s RegexTimeout) and leave the input unchanged.
        string attackRun = string.Concat(Enumerable.Repeat("x'y'\"z\"", 20_000));
        string html = "<a " + attackRun;

        var sw = Stopwatch.StartNew();
        string rewritten = PyPiController.RewriteUpstreamSimpleIndexHtml(html);
        sw.Stop();

        Assert.Equal(html, rewritten);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2),
            $"Rewrite took {sw.Elapsed.TotalMilliseconds:F0}ms — expected linear-time matching.");
    }
}
