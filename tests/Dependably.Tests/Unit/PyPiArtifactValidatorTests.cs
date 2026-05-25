using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class PyPiArtifactValidatorTests
{
    // ── Normalize (PEP 503) ──────────────────────────────────────────────────

    [Theory]
    [InlineData("Django", "django")]
    [InlineData("MY_PACKAGE", "my-package")]
    [InlineData("foo.bar", "foo-bar")]
    [InlineData("a--b__c..d", "a-b-c-d")]
    [InlineData("already-lower", "already-lower")]
    public void Normalize_AppliesPep503Rules(string input, string expected)
    {
        Assert.Equal(expected, PyPiArtifactValidator.Normalize(input));
    }

    // ── ValidateWheel (content-only) ─────────────────────────────────────────

    [Fact]
    public void ValidateWheel_RealFixture_Succeeds()
    {
        var (bytes, _) = PyPiFixtures.RealWheel();
        var result = PyPiArtifactValidator.ValidateWheel(bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("mypy-extensions", name);
        Assert.Equal("1.0.0", version);
    }

    [Fact]
    public void ValidateWheel_SyntheticWheel_Succeeds_AndNormalisesName()
    {
        var (bytes, _) = PyPiFixtures.BuildWheel("My.Package", "2.3.4");
        var result = PyPiArtifactValidator.ValidateWheel(bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("my-package", name);
        Assert.Equal("2.3.4", version);
    }

    [Fact]
    public void ValidateWheel_MissingMetadata_FailsWithContentField()
    {
        // ZIP with no dist-info/METADATA entry.
        var bytes = BuildZip(("README.txt", "no metadata here"));
        var result = PyPiArtifactValidator.ValidateWheel(bytes, out var name, out var version);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Null(name);
        Assert.Null(version);
    }

    [Fact]
    public void ValidateWheel_NotAZip_FailsGracefully()
    {
        var result = PyPiArtifactValidator.ValidateWheel("not a zip"u8.ToArray(), out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    [Fact]
    public void ValidateWheel_InvalidPep508Name_Fails()
    {
        // Name starts with a space, breaks PEP 508.
        var bytes = BuildWheelWithMetadata("Name:  has-leading-space\nVersion: 1.0.0\n");
        var result = PyPiArtifactValidator.ValidateWheel(bytes, out _, out _);
        // The name with leading whitespace gets trimmed; what we really care about is
        // that names containing forbidden characters are rejected. Use a clear violation:
        bytes = BuildWheelWithMetadata("Name: bad name with spaces\nVersion: 1.0.0\n");
        result = PyPiArtifactValidator.ValidateWheel(bytes, out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    [Fact]
    public void ValidateWheel_InvalidPep440Version_Fails()
    {
        var bytes = BuildWheelWithMetadata("Name: pkg\nVersion: not-a-version\n");
        var result = PyPiArtifactValidator.ValidateWheel(bytes, out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    [Fact]
    public void ValidateWheel_MissingNameHeader_Fails()
    {
        var bytes = BuildWheelWithMetadata("Version: 1.0.0\n");
        var result = PyPiArtifactValidator.ValidateWheel(bytes, out _, out _);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void ValidateWheel_MissingVersionHeader_Fails()
    {
        var bytes = BuildWheelWithMetadata("Name: pkg\n");
        var result = PyPiArtifactValidator.ValidateWheel(bytes, out _, out _);
        Assert.False(result.IsValid);
    }

    // ── ValidateSdist ────────────────────────────────────────────────────────

    [Fact]
    public void ValidateSdist_RealFixture_Succeeds()
    {
        var (bytes, _) = PyPiFixtures.RealSdist();
        var result = PyPiArtifactValidator.ValidateSdist(bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("mypy-extensions", name);
        Assert.Equal("1.0.0", version);
    }

    [Fact]
    public void ValidateSdist_Synthetic_Succeeds()
    {
        var (bytes, _) = PyPiFixtures.BuildSdist("pkg", "0.1.0");
        var result = PyPiArtifactValidator.ValidateSdist(bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("pkg", name);
        Assert.Equal("0.1.0", version);
    }

    [Fact]
    public void ValidateSdist_MissingPkgInfo_Fails()
    {
        var bytes = BuildSdistWithEntries(("only-readme.txt", "no PKG-INFO here"));
        var result = PyPiArtifactValidator.ValidateSdist(bytes, out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    [Fact]
    public void ValidateSdist_NotGzip_FailsGracefully()
    {
        var result = PyPiArtifactValidator.ValidateSdist("nope"u8.ToArray(), out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    // ── Extension-dispatch Validate ──────────────────────────────────────────

    [Fact]
    public void Validate_UnknownExtension_FailsWithFilenameField()
    {
        var result = PyPiArtifactValidator.Validate(
            "package.zip", Array.Empty<byte>(), out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("filename", result.FieldName);
    }

    [Fact]
    public void Validate_Wheel_FilenameMatchesMetadata_Succeeds()
    {
        var (bytes, _) = PyPiFixtures.BuildWheel("acme", "1.0.0");
        var result = PyPiArtifactValidator.Validate(
            "acme-1.0.0-py3-none-any.whl", bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("acme", name);
        Assert.Equal("1.0.0", version);
    }

    [Fact]
    public void Validate_Wheel_FilenameLiesAboutVersion_RejectedByCrossCheck()
    {
        // Filename claims 9.9.9 but METADATA says 1.0.0.
        var (bytes, _) = PyPiFixtures.BuildWheel("acme", "1.0.0");
        var result = PyPiArtifactValidator.Validate(
            "acme-9.9.9-py3-none-any.whl", bytes, out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Contains("does not match", result.Message);
    }

    [Fact]
    public void Validate_Wheel_FilenameLiesAboutName_RejectedByCrossCheck()
    {
        var (bytes, _) = PyPiFixtures.BuildWheel("acme", "1.0.0");
        var result = PyPiArtifactValidator.Validate(
            "fake-1.0.0-py3-none-any.whl", bytes, out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    [Fact]
    public void Validate_Wheel_FilenameTooFewSegments_Fails()
    {
        var (bytes, _) = PyPiFixtures.BuildWheel("acme", "1.0.0");
        var result = PyPiArtifactValidator.Validate("acme-1.0.0.whl", bytes, out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("filename", result.FieldName);
    }

    [Fact]
    public void Validate_Sdist_TarGz_Succeeds()
    {
        var (bytes, _) = PyPiFixtures.BuildSdist("acme", "1.2.3");
        var result = PyPiArtifactValidator.Validate("acme-1.2.3.tar.gz", bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("acme", name);
        Assert.Equal("1.2.3", version);
    }

    [Fact]
    public void Validate_CorruptArchive_FailsWithContentField()
    {
        // ".whl" extension routes to wheel parser, but bytes aren't a valid ZIP — caught by
        // the outer try/catch wrapping ValidateWheelStrict.
        var result = PyPiArtifactValidator.Validate("acme-1.0.0-py3-none-any.whl",
            "garbage"u8.ToArray(), out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    // ── TryParseFilename ─────────────────────────────────────────────────────

    [Theory]
    // Sdist with hyphenated name — the bug from issue: pip 404'd because the old parser
    // returned "psycopg2" as the name, sending the lazy-fetch to /simple/psycopg2/.
    [InlineData("psycopg2-binary-2.9.10.tar.gz", "psycopg2-binary", "2.9.10")]
    // Wheel of the same package — PEP 427 substitutes underscores in the distribution segment.
    [InlineData("psycopg2_binary-2.9.10-cp311-cp311-manylinux_2_17_x86_64.whl", "psycopg2-binary", "2.9.10")]
    // Plain sdist, single-segment name.
    [InlineData("requests-2.31.0.tar.gz", "requests", "2.31.0")]
    // Sdist with mixed-case name → normalised.
    [InlineData("Flask-3.0.0.tar.gz", "flask", "3.0.0")]
    // Sdist with a dot in the name → PEP 503 collapses to a single hyphen.
    [InlineData("zope.interface-6.1.tar.gz", "zope-interface", "6.1")]
    // Wheel of a package with an underscore in the distribution segment.
    [InlineData("tensorflow_gpu-2.15.0-cp311-cp311-manylinux_2_17_x86_64.whl", "tensorflow-gpu", "2.15.0")]
    // PEP 440 pre-release.
    [InlineData("my-pkg-1.0.0a1.tar.gz", "my-pkg", "1.0.0a1")]
    // PEP 440 local version (contains '+').
    [InlineData("my-pkg-1.0.0+local.tar.gz", "my-pkg", "1.0.0+local")]
    // Alternative archive extensions.
    [InlineData("my-pkg-1.2.3.tgz", "my-pkg", "1.2.3")]
    [InlineData("my-pkg-1.2.3.zip", "my-pkg", "1.2.3")]
    [InlineData("my-pkg-1.2.3.tar.bz2", "my-pkg", "1.2.3")]
    public void TryParseFilename_HappyPath(string filename, string expectedName, string expectedVersion)
    {
        Assert.True(PyPiArtifactValidator.TryParseFilename(filename, out var name, out var version));
        Assert.Equal(expectedName, name);
        Assert.Equal(expectedVersion, version);
    }

    [Theory]
    [InlineData("garbage.txt")]              // unknown extension
    [InlineData("pkg-noversion.tar.gz")]     // no PEP 440-shaped suffix
    [InlineData("nodash.tar.gz")]            // no hyphen at all
    [InlineData("short-1.0.whl")]            // wheel with too few dash segments
    [InlineData("")]                         // empty
    public void TryParseFilename_Rejects(string filename)
    {
        Assert.False(PyPiArtifactValidator.TryParseFilename(filename, out var name, out var version));
        Assert.Null(name);
        Assert.Null(version);
    }

    [Fact]
    public void TryParseFilename_WheelWithNonPep440SecondSegment_Rejects()
    {
        // Five+ dash segments so we get past the length check, but parts[1] ("notaversion")
        // is not PEP 440-shaped — exercises the Pep440VersionRegex().IsMatch(parts[1])
        // false branch on line 242 of the SUT.
        Assert.False(PyPiArtifactValidator.TryParseFilename(
            "pkg-notaversion-py3-none-any.whl", out var name, out var version));
        Assert.Null(name);
        Assert.Null(version);
    }

    // ── Additional branch coverage ────────────────────────────────────────────

    [Fact]
    public void Validate_Sdist_Tgz_Succeeds()
    {
        // Existing tests only cover .tar.gz; .tgz hits the second branch of the
        // extension check in Validate (line 45).
        var (bytes, _) = PyPiFixtures.BuildSdist("acme", "1.2.3");
        var result = PyPiArtifactValidator.Validate("acme-1.2.3.tgz", bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("acme", name);
        Assert.Equal("1.2.3", version);
    }

    [Fact]
    public void ValidateSdist_PkgInfoWithInvalidVersion_FailsAtNameVersionCheck()
    {
        // Build an sdist whose PKG-INFO has a bad version header. This exercises
        // line 147 (ValidationResult.Fail("content", error) inside ValidateSdist)
        // and the false branch of ValidateNameVersion on line 146.
        var pkgInfo = "Metadata-Version: 2.1\nName: pkg\nVersion: not-a-version\n";
        var bytes = BuildSdistWithEntries(("pkg-0.0.0/PKG-INFO", pkgInfo));
        var result = PyPiArtifactValidator.ValidateSdist(bytes, out var name, out var version);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Contains("Invalid PEP 440 version", result.Message);
        Assert.Null(name);
        Assert.Null(version);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] BuildZip(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (n, c) in entries)
            {
                var e = zip.CreateEntry(n);
                using var w = new StreamWriter(e.Open());
                w.Write(c);
            }
        }
        return ms.ToArray();
    }

    private static byte[] BuildWheelWithMetadata(string metadataBody)
    {
        // Path must end in .dist-info/METADATA for ValidateWheel to find it.
        return BuildZip(("pkg-1.0.0.dist-info/METADATA", metadataBody));
    }

    private static byte[] BuildSdistWithEntries(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            foreach (var (n, c) in entries)
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, n)
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes(c))
                };
                tw.WriteEntry(entry);
            }
        }
        return ms.ToArray();
    }
}
