using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Hex;

[Trait("Category", "Unit")]
public sealed class HexTarballTests
{
    private const long ContentsCap = 64 * 1024 * 1024;

    private static byte[] RealDecimal() =>
        File.ReadAllBytes(Path.Combine(FixtureManifest.FixturesRoot, "hex", "decimal-2.3.0.tar"));

    [Fact]
    public void RealDecimalTarball_ParsesAndBothChecksumsMatchTheRegistry()
    {
        var parsed = HexTarball.Parse(RealDecimal(), ContentsCap);

        Assert.Equal("3", parsed.Version);
        Assert.Equal("3AD6255AA77B4A3C4F818171B12D237500E63525C2FD056699967A3E7EA20F62", Convert.ToHexString(parsed.InnerChecksum));
        Assert.Equal(FixtureManifest.HexDecimalTarballSha256, Convert.ToHexString(parsed.OuterChecksum).ToLowerInvariant());
        Assert.Contains("{<<\"name\">>,<<\"decimal\">>}.", parsed.MetadataText);
        Assert.True(parsed.ContentsBytes > 1000);
    }

    [Fact]
    public void Build_ThenParse_RoundTrips_AndIsReproducible()
    {
        byte[] contents = TinyContents();
        string metadata = "{<<\"name\">>,<<\"demo\">>}.\n{<<\"version\">>,<<\"1.0.0\">>}.\n";

        byte[] first = HexTarball.Build(metadata, contents);
        byte[] second = HexTarball.Build(metadata, contents);
        var parsed = HexTarball.Parse(first, ContentsCap);

        Assert.Equal(first, second);
        Assert.Equal(metadata, parsed.MetadataText);
        Assert.Equal(HexTarball.ComputeInnerChecksum("3"u8.ToArray(), Encoding.UTF8.GetBytes(metadata), contents), parsed.InnerChecksum);
    }

    [Fact]
    public void ChecksumMismatch_IsRefused()
    {
        byte[] tar = HexTarball.Build("{<<\"name\">>,<<\"demo\">>}.\n", TinyContents());
        // Flip a byte inside metadata.config without touching CHECKSUM.
        int at = Array.IndexOf(tar, (byte)'d', 0);
        tar[IndexOfSequence(tar, "demo"u8) + 1] ^= 0x01;

        var ex = Assert.Throws<HexProtocolException>(() => HexTarball.Parse(tar, ContentsCap));
        Assert.Contains("CHECKSUM does not match", ex.Message);
        _ = at;
    }

    [Fact]
    public void MissingEntry_IsRefusedNamingIt()
    {
        byte[] tar = TarOf(("VERSION", "3"u8.ToArray()), ("metadata.config", "{}."u8.ToArray()), ("contents.tar.gz", TinyContents()));

        var ex = Assert.Throws<HexProtocolException>(() => HexTarball.Parse(tar, ContentsCap));
        Assert.Contains("CHECKSUM", ex.Message);
    }

    [Fact]
    public void UnsupportedVersion_IsRefused()
    {
        byte[] contents = TinyContents();
        byte[] meta = "{}."u8.ToArray();
        byte[] checksum = Encoding.ASCII.GetBytes(Convert.ToHexString(HexTarball.ComputeInnerChecksum("2"u8.ToArray(), meta, contents)));
        byte[] tar = TarOf(("VERSION", "2"u8.ToArray()), ("CHECKSUM", checksum), ("metadata.config", meta), ("contents.tar.gz", contents));

        var ex = Assert.Throws<HexProtocolException>(() => HexTarball.Parse(tar, ContentsCap));
        Assert.Contains("version '2'", ex.Message);
    }

    [Fact]
    public void NotATar_IsRefused()
    {
        Assert.Throws<HexProtocolException>(() => HexTarball.Parse("definitely not a tar"u8.ToArray(), ContentsCap));
    }

    [Fact]
    public void GzippedTarball_IsRefused_TheFormatIsPlainTar()
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(HexTarball.Build("{}.\n", TinyContents()));
        }

        Assert.Throws<HexProtocolException>(() => HexTarball.Parse(ms.ToArray(), ContentsCap));
    }

    [Fact]
    public void OversizedMetadata_IsRefusedBeforeItIsRead()
    {
        byte[] meta = new byte[HexTarball.MaxMetadataBytes + 1];
        Array.Fill(meta, (byte)'%');
        byte[] tar = HexTarball.Build(Encoding.ASCII.GetString(meta), TinyContents());

        var ex = Assert.Throws<HexProtocolException>(() => HexTarball.Parse(tar, ContentsCap));
        Assert.Contains("metadata.config exceeds", ex.Message);
    }

    [Fact]
    public void ContentsOverTheCallerCap_IsRefused()
    {
        byte[] tar = HexTarball.Build("{}.\n", TinyContents());

        Assert.Throws<HexProtocolException>(() => HexTarball.Parse(tar, maxContentsBytes: 4));
    }

    [Fact]
    public void ExtraEntries_AreIgnored_ButTooManyAreRefused()
    {
        byte[] contents = TinyContents();
        byte[] meta = "{}."u8.ToArray();
        byte[] checksum = Encoding.ASCII.GetBytes(Convert.ToHexString(HexTarball.ComputeInnerChecksum("3"u8.ToArray(), meta, contents)));
        var entries = new List<(string, byte[])>
        {
            ("VERSION", "3"u8.ToArray()), ("CHECKSUM", checksum), ("metadata.config", meta), ("contents.tar.gz", contents), ("extra", "x"u8.ToArray()),
        };
        Assert.Equal("3", HexTarball.Parse(TarOf(entries.ToArray()), ContentsCap).Version);

        for (int i = 0; i < HexTarball.MaxEntries; i++)
        {
            entries.Add(($"pad{i}", "x"u8.ToArray()));
        }

        Assert.Throws<HexProtocolException>(() => HexTarball.Parse(TarOf(entries.ToArray()), ContentsCap));
    }

    private static byte[] TinyContents()
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "lib/demo.ex") { DataStream = new MemoryStream("defmodule Demo do end\n"u8.ToArray()) });
        }

        return ms.ToArray();
    }

    private static byte[] TarOf(params (string Name, byte[] Data)[] entries)
    {
        using var ms = new MemoryStream();
        using (var tw = new TarWriter(ms, TarEntryFormat.Ustar, leaveOpen: true))
        {
            foreach (var (name, data) in entries)
            {
                tw.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(data) });
            }
        }

        return ms.ToArray();
    }

    private static int IndexOfSequence(byte[] haystack, ReadOnlySpan<byte> needle) => haystack.AsSpan().IndexOf(needle);
}
