using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the less-common PyPI sdist code paths in <see cref="LicenseExtractor"/>: the
/// buffered probe used when the filename extension doesn't pre-select tar.gz (a .zip sdist
/// or an unknown extension), and the non-seekable-stream branch of the shared zip opener.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LicenseExtractorSdistProbeTests
{
    private const string PkgInfo = """
        Metadata-Version: 2.3
        Name: pkg
        Version: 1.0
        License-Expression: MIT

        body
        """;

    [Fact]
    public void Sdist_UnknownExtension_BufferedTarProbeFindsPkgInfo()
    {
        // Unknown extension => buffered probe; the payload is tar.gz so the tar branch wins.
        byte[] bytes = BuildSdistTarGz(PkgInfo);
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "pkg-1.0.sdist");
        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    [Fact]
    public void Sdist_ZipExtension_BufferedZipProbeFindsPkgInfo()
    {
        // .zip => buffered probe; the tar attempt fails, the zip branch finds PKG-INFO.
        byte[] bytes = BuildSdistZip(PkgInfo);
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "pkg-1.0.zip");
        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    [Fact]
    public void Sdist_ZipExtension_NoPkgInfo_ReturnsEmpty()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var e = zip.CreateEntry("pkg-1.0/README.txt");
            using var w = new StreamWriter(e.Open());
            w.Write("no metadata here");
        }
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(ms.ToArray()), "pkg-1.0.zip");
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void Wheel_NonSeekableStream_IsBufferedBeforeZipOpen()
    {
        // A non-seekable upstream forces OpenZipArchive's buffering branch.
        byte[] wheel = BuildWheel("""
            Metadata-Version: 2.3
            Name: foo
            Version: 1.0
            License-Expression: Apache-2.0

            body
            """);
        var result = LicenseExtractor.FromPyPiPackageBytes(
            new NonSeekableStream(new MemoryStream(wheel)), "foo-1.0-py3-none-any.whl");
        Assert.Equal(new[] { "Apache-2.0" }, result.Spdx);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static byte[] BuildSdistTarGz(string pkgInfo)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tar = new TarWriter(gz, leaveOpen: true))
        {
            byte[] data = Encoding.UTF8.GetBytes(pkgInfo);
            tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "pkg-1.0/PKG-INFO")
            {
                DataStream = new MemoryStream(data),
            });
        }
        return ms.ToArray();
    }

    private static byte[] BuildSdistZip(string pkgInfo)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("pkg-1.0/PKG-INFO");
            using var w = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            w.Write(pkgInfo);
        }
        return ms.ToArray();
    }

    private static byte[] BuildWheel(string metadata)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("foo-1.0.dist-info/METADATA");
            using var w = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            w.Write(metadata);
        }
        return ms.ToArray();
    }

    /// <summary>Forward-only wrapper that reports <c>CanSeek == false</c>.</summary>
    private sealed class NonSeekableStream(Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
