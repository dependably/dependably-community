using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

// Presentation-metadata (homepage / repository / description) extraction added alongside the
// existing license extraction. Each positive case is paired with an adversarial "absent → null"
// or "not a URL → dropped" twin, since these strings are rendered as clickable links in the UI.
[Trait("Category", "Unit")]
public class PackageMetadataExtractionTests
{
    // ── npm ───────────────────────────────────────────────────────────────────

    [Fact]
    public void Npm_PackageJson_CapturesHomepageRepositoryDescription()
    {
        var node = JsonNode.Parse("""
            {
              "homepage": "https://lodash.com/",
              "repository": { "type": "git", "url": "git+https://github.com/lodash/lodash.git" },
              "description": "Lodash modular utilities."
            }
            """);

        var m = LicenseExtractor.FromNpmPackumentVersion(node);

        Assert.Equal("https://lodash.com/", m.Homepage);
        // git+ prefix stripped and .git suffix removed → browsable URL.
        Assert.Equal("https://github.com/lodash/lodash", m.Repository);
        Assert.Equal("Lodash modular utilities.", m.Description);
    }

    [Fact]
    public void Npm_RepositoryAsString_And_Shorthand_Normalized()
    {
        var node = JsonNode.Parse("""{ "repository": "github:sindresorhus/got" }""");
        Assert.Equal("https://github.com/sindresorhus/got", LicenseExtractor.FromNpmPackumentVersion(node).Repository);
    }

    [Fact]
    public void Npm_NoPresentationFields_AllNull()
    {
        var node = JsonNode.Parse("""{ "license": "MIT" }""");
        var m = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Null(m.Homepage);
        Assert.Null(m.Repository);
        Assert.Null(m.Description);
    }

    [Fact]
    public void Npm_NonHttpHomepage_Dropped()
    {
        // A non-URL homepage would render as a broken link, so it is dropped.
        var node = JsonNode.Parse("""{ "homepage": "see the README" }""");
        Assert.Null(LicenseExtractor.FromNpmPackumentVersion(node).Homepage);
    }

    // ── NuGet ─────────────────────────────────────────────────────────────────

    [Fact]
    public void NuGet_Nuspec_CapturesProjectUrlRepositoryDescription()
    {
        const string xml = """
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Newtonsoft.Json</id>
                <projectUrl>https://www.newtonsoft.com/json</projectUrl>
                <repository type="git" url="https://github.com/JamesNK/Newtonsoft.Json.git" />
                <description>Json.NET is a popular JSON framework for .NET</description>
              </metadata>
            </package>
            """;

        var m = LicenseExtractor.FromNuspecXml(xml);

        Assert.Equal("https://www.newtonsoft.com/json", m.Homepage);
        Assert.Equal("https://github.com/JamesNK/Newtonsoft.Json", m.Repository);
        Assert.Equal("Json.NET is a popular JSON framework for .NET", m.Description);
    }

    [Fact]
    public void NuGet_Nuspec_NoPresentationFields_AllNull()
    {
        const string xml = """
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata><id>Bare</id></metadata>
            </package>
            """;
        var m = LicenseExtractor.FromNuspecXml(xml);
        Assert.Null(m.Homepage);
        Assert.Null(m.Repository);
        Assert.Null(m.Description);
    }

    // ── PyPI ──────────────────────────────────────────────────────────────────

    [Fact]
    public void PyPi_Metadata_CapturesHomepageAndSummary()
    {
        byte[] wheel = BuildWheel("""
            Metadata-Version: 2.1
            Name: flask
            Version: 3.0.0
            Home-page: https://palletsprojects.com/p/flask
            Summary: A simple framework for building complex web applications.
            License-Expression: BSD-3-Clause

            body
            """);

        var m = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(wheel), "flask-3.0.0-py3-none-any.whl");

        Assert.Equal("https://palletsprojects.com/p/flask", m.Homepage);
        Assert.Equal("A simple framework for building complex web applications.", m.Description);
    }

    [Fact]
    public void PyPi_ProjectUrl_FeedsHomepageAndRepository()
    {
        // Modern PyPI packages drop Home-page and use Project-URL "Label, url" lines.
        byte[] wheel = BuildWheel("""
            Metadata-Version: 2.3
            Name: httpx
            Version: 0.27.0
            Project-URL: Homepage, https://www.python-httpx.org
            Project-URL: Source, https://github.com/encode/httpx
            Summary: The next generation HTTP client.

            body
            """);

        var m = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(wheel), "httpx-0.27.0-py3-none-any.whl");

        Assert.Equal("https://www.python-httpx.org", m.Homepage);
        Assert.Equal("https://github.com/encode/httpx", m.Repository);
    }

    [Fact]
    public void PyPi_NoPresentationFields_AllNull()
    {
        byte[] wheel = BuildWheel("Metadata-Version: 2.1\nName: bare\nVersion: 1.0\n\nbody");
        var m = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(wheel), "bare-1.0-py3-none-any.whl");
        Assert.Null(m.Homepage);
        Assert.Null(m.Repository);
        Assert.Null(m.Description);
    }

    // ── Maven ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Maven_Pom_CapturesUrlScmDescription()
    {
        const string pom = """
            <?xml version="1.0"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <url>https://commons.apache.org/proper/commons-lang/</url>
              <description>Apache Commons Lang</description>
              <scm><url>https://github.com/apache/commons-lang</url></scm>
            </project>
            """;

        var m = LicenseExtractor.FromPomXml(new MemoryStream(Encoding.UTF8.GetBytes(pom)));

        Assert.Equal("https://commons.apache.org/proper/commons-lang/", m.Homepage);
        Assert.Equal("https://github.com/apache/commons-lang", m.Repository);
        Assert.Equal("Apache Commons Lang", m.Description);
    }

    [Fact]
    public void Maven_Pom_NoPresentationFields_AllNull()
    {
        const string pom = """
            <?xml version="1.0"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0"><artifactId>bare</artifactId></project>
            """;
        var m = LicenseExtractor.FromPomXml(new MemoryStream(Encoding.UTF8.GetBytes(pom)));
        Assert.Null(m.Homepage);
        Assert.Null(m.Repository);
        Assert.Null(m.Description);
    }

    // ── Cargo ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Cargo_Toml_CapturesHomepageRepositoryDescription()
    {
        byte[] crate = BuildCrateTarball("serde-1.0.0/Cargo.toml", """
            [package]
            name = "serde"
            version = "1.0.0"
            license = "MIT OR Apache-2.0"
            homepage = "https://serde.rs"
            repository = "https://github.com/serde-rs/serde"
            description = "A generic serialization/deserialization framework"
            """);

        var m = LicenseExtractor.FromCrateTarball(new MemoryStream(crate));

        Assert.Equal("https://serde.rs", m.Homepage);
        Assert.Equal("https://github.com/serde-rs/serde", m.Repository);
        Assert.Equal("A generic serialization/deserialization framework", m.Description);
    }

    [Fact]
    public void Cargo_PublishEnvelope_PresentationOnly_NormalizesRepo()
    {
        var m = LicenseExtractor.PresentationOnly(
            "https://tokio.rs", "git+https://github.com/tokio-rs/tokio.git", "An async runtime.");

        Assert.Equal("https://tokio.rs", m.Homepage);
        Assert.Equal("https://github.com/tokio-rs/tokio", m.Repository);
        Assert.Equal("An async runtime.", m.Description);
        // PresentationOnly carries no license signal.
        Assert.Empty(m.Spdx);
    }

    [Fact]
    public void PresentationOnly_AllNullInputs_AllNull()
    {
        var m = LicenseExtractor.PresentationOnly(null, null, null);
        Assert.Null(m.Homepage);
        Assert.Null(m.Repository);
        Assert.Null(m.Description);
    }

    // ── Shared: length cap ─────────────────────────────────────────────────────

    [Fact]
    public void Description_ExceedingCap_IsTruncated()
    {
        string huge = new('x', 5000);
        var m = LicenseExtractor.PresentationOnly(null, null, huge);
        Assert.NotNull(m.Description);
        Assert.Equal(2048, m.Description!.Length);
    }

    [Fact]
    public void Description_SurrogatePairStraddlesCapBoundary_DropsWholePairInsteadOfSplitting()
    {
        // 2047 ASCII chars + one astral-plane emoji (a 2-char UTF-16 surrogate pair) straddles
        // the 2048-char cap exactly: the high surrogate lands at index 2047 and the low surrogate
        // would land at 2048. A naive char-index cut keeps the lone high surrogate; a hostile
        // manifest can engineer this deliberately since the description is unvalidated free text
        // re-served verbatim in package metadata.
        string huge = new string('x', 2047) + "\U0001F600"; // 😀
        var m = LicenseExtractor.PresentationOnly(null, null, huge);

        Assert.NotNull(m.Description);
        Assert.Equal(2047, m.Description!.Length);
        Assert.Equal(new string('x', 2047), m.Description);
        Assert.False(char.IsSurrogate(m.Description[^1]));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static byte[] BuildWheel(string metadata)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("foo-1.0.dist-info/METADATA");
            using var s = entry.Open();
            using var w = new StreamWriter(s, new UTF8Encoding(false));
            w.Write(metadata);
        }
        return ms.ToArray();
    }

    private static byte[] BuildCrateTarball(string entryName, string content)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)),
            });
        }
        return ms.ToArray();
    }
}
