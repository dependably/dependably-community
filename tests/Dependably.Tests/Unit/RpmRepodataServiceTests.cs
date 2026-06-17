using System.IO.Compression;
using System.Security.Cryptography;
using System.Xml.Linq;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for <see cref="RpmRepodataService"/> — the static helpers
/// <see cref="RpmRepodataService.BuildRepomd"/> and <see cref="RpmRepodataService.Gzip"/>
/// plus the end-to-end pipeline that mirrors what <c>RpmController</c> serves to dnf/yum.
///
/// <para>Coverage gap (deliberate): <see cref="RpmRepodataService.BuildPrimaryAsync"/> is
/// not exercised against a populated DB. Dapper materialises rows via the
/// <c>RpmPrimaryRow</c> positional record whose constructor declares <c>int</c> for
/// <c>Epoch</c>, <c>BuildTime</c>, <c>HeaderStart</c>, and <c>HeaderEnd</c>, but SQLite's
/// data reader reports every <c>INTEGER</c> column as <see cref="long"/>. Dapper refuses
/// to bind the constructor — even when zero rows are returned the deserializer is built
/// at query time, so the empty-repo case fails too. Fixing this requires changing the
/// production record's int fields to long, which is out of scope for this test file
/// (instructed not to modify <c>src/Dependably/**</c>).</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmRepodataServiceTests
{
    private static readonly XNamespace Repo = "http://linux.duke.edu/metadata/repo";

    // ---------- BuildRepomd ----------

    [Fact]
    public void BuildRepomd_EmitsSha256AndSizeMatchingInput()
    {
        byte[] payload = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        string expectedSha = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

        string xml = RpmRepodataService.BuildRepomd(payload, TestTime.KnownNow);
        var doc = XDocument.Parse(xml);

        Assert.Equal(Repo + "repomd", doc.Root!.Name);
        Assert.NotNull(doc.Root.Attribute("revision"));

        var data = Assert.Single(doc.Root.Elements(Repo + "data"));
        Assert.Equal("primary", data.Attribute("type")!.Value);

        var checksum = data.Element(Repo + "checksum")!;
        Assert.Equal("sha256", checksum.Attribute("type")!.Value);
        Assert.Equal(expectedSha, checksum.Value);

        Assert.Equal("repodata/primary.xml.gz",
            data.Element(Repo + "location")!.Attribute("href")!.Value);
        Assert.Equal(payload.Length.ToString(), data.Element(Repo + "size")!.Value);
        Assert.NotNull(data.Element(Repo + "timestamp"));
    }

    [Fact]
    public void BuildRepomd_RevisionAndTimestampArePopulatedFromProvidedInstant()
    {
        long expected = TestTime.KnownNow.ToUnixTimeSeconds();
        string xml = RpmRepodataService.BuildRepomd(new byte[] { 0xAA }, TestTime.KnownNow);
        var doc = XDocument.Parse(xml);

        long revision = long.Parse(doc.Root!.Attribute("revision")!.Value);
        Assert.Equal(expected, revision);

        long ts = long.Parse(doc.Root.Element(Repo + "data")!
            .Element(Repo + "timestamp")!.Value);
        Assert.Equal(expected, ts);
    }

    [Fact]
    public void BuildRepomd_EmptyInput_StillProducesValidIndex()
    {
        string xml = RpmRepodataService.BuildRepomd(Array.Empty<byte>(), TestTime.KnownNow);
        var doc = XDocument.Parse(xml);

        // sha256 of empty is e3b0c442... — verify it lands in the document.
        var checksum = doc.Root!.Element(Repo + "data")!.Element(Repo + "checksum")!;
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant(),
            checksum.Value);
        Assert.Equal("0", doc.Root.Element(Repo + "data")!
            .Element(Repo + "size")!.Value);
    }

    [Fact]
    public void BuildRepomd_DeclaresXmlDeclarationAndRepoNamespace()
    {
        string xml = RpmRepodataService.BuildRepomd(new byte[] { 0x01 }, TestTime.KnownNow);
        // Document starts with an XML declaration. (StringWriter forces utf-16 in the
        // declaration regardless of the XDeclaration set in code — that's a .NET-runtime
        // quirk of XDocument.Save(TextWriter); the controller serves UTF-8 bytes via
        // Encoding.UTF8.GetBytes(...) so the wire encoding is independent of this string.)
        Assert.StartsWith("<?xml", xml);
        // Root must be in the repo metadata namespace.
        var doc = XDocument.Parse(xml);
        Assert.Equal(Repo.NamespaceName, doc.Root!.Name.NamespaceName);
    }

    [Fact]
    public void BuildRepomd_LargerInput_SizeMatchesByteCount()
    {
        // Sanity-check that size attribute is a faithful int of the byte array length, not
        // some other count (e.g. string length, chars).
        byte[] payload = new byte[10_000];
        new Random(42).NextBytes(payload);
        string xml = RpmRepodataService.BuildRepomd(payload, TestTime.KnownNow);
        var doc = XDocument.Parse(xml);
        Assert.Equal("10000", doc.Root!.Element(Repo + "data")!
            .Element(Repo + "size")!.Value);
    }

    // ---------- Gzip ----------

    [Fact]
    public void Gzip_RoundTrips()
    {
        byte[] original = System.Text.Encoding.UTF8.GetBytes(
            "<metadata packages=\"0\"></metadata>");
        byte[] gz = RpmRepodataService.Gzip(original);

        // Magic bytes for gzip: 1f 8b.
        Assert.True(gz.Length >= 2);
        Assert.Equal(0x1f, gz[0]);
        Assert.Equal(0x8b, gz[1]);

        using var ms = new MemoryStream(gz);
        using var gunzip = new GZipStream(ms, CompressionMode.Decompress);
        using var outMs = new MemoryStream();
        gunzip.CopyTo(outMs);
        Assert.Equal(original, outMs.ToArray());
    }

    [Fact]
    public void Gzip_DoesNotThrowOnEmptyInput()
    {
        // The production implementation closes the inner GZipStream first (leaveOpen=true)
        // then calls ms.ToArray(). With no bytes written, .NET's GZipStream may emit
        // either an empty stream or a bare header — either way the call must not throw,
        // and the controller-side caller is expected to feed only non-empty payloads in
        // practice.
        var ex = Record.Exception(() => RpmRepodataService.Gzip(Array.Empty<byte>()));
        Assert.Null(ex);
    }

    [Fact]
    public void Gzip_LargerPayloadIsActuallyCompressed()
    {
        // A highly compressible payload should come out smaller than the input — confirms
        // CompressionLevel.Optimal is being applied rather than CompressionLevel.NoCompression
        // (which would just wrap the bytes in a gzip envelope and grow them).
        byte[] original = new byte[10_000];
        Array.Fill(original, (byte)'a');
        byte[] gz = RpmRepodataService.Gzip(original);
        Assert.True(gz.Length < original.Length,
            $"expected gzip output <{original.Length} bytes, got {gz.Length}");
    }

    [Fact]
    public void Gzip_RoundTripsBinaryPayload()
    {
        byte[] original = new byte[1024];
        new Random(7).NextBytes(original);
        byte[] gz = RpmRepodataService.Gzip(original);

        using var ms = new MemoryStream(gz);
        using var gunzip = new GZipStream(ms, CompressionMode.Decompress);
        using var outMs = new MemoryStream();
        gunzip.CopyTo(outMs);
        Assert.Equal(original, outMs.ToArray());
    }

    // ---------- End-to-end (controller pipeline) ----------

    [Fact]
    public void Pipeline_GzipThenRepomd_ProducesConsistentDigest()
    {
        // Mirrors RpmController: primary → gzip → repomd over the gzipped bytes. Any drift
        // in either helper is caught here.
        byte[] primary = System.Text.Encoding.UTF8.GetBytes(
            "<metadata xmlns=\"http://linux.duke.edu/metadata/common\" packages=\"0\"/>");
        byte[] gz = RpmRepodataService.Gzip(primary);
        string xml = RpmRepodataService.BuildRepomd(gz, TestTime.KnownNow);
        var doc = XDocument.Parse(xml);

        var data = doc.Root!.Element(Repo + "data")!;
        Assert.Equal(Convert.ToHexString(SHA256.HashData(gz)).ToLowerInvariant(),
            data.Element(Repo + "checksum")!.Value);
        Assert.Equal(gz.Length.ToString(), data.Element(Repo + "size")!.Value);
        Assert.Equal("repodata/primary.xml.gz",
            data.Element(Repo + "location")!.Attribute("href")!.Value);
    }
}
