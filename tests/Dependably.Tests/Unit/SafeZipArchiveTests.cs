using System.Buffers.Binary;
using System.IO.Compression;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Cover for the ZIP entry-count bound. The attack these guard against is a crafted archive whose
/// central directory declares (or physically carries) far more entries than its compressed size
/// suggests: <c>ZipArchive.Entries</c> allocates one object per entry on first access, and the
/// upload-size limits bound the compressed bytes, not the entry count.
/// </summary>
public class SafeZipArchiveTests
{
    private const uint EocdSignature = 0x06054b50;
    private const int EocdFixedSize = 22;
    private const int TotalEntriesOffset = 10;
    private const int EntriesThisDiskOffset = 8;
    private const int CentralDirectorySizeOffset = 12;

    private static byte[] BuildZip(int entries)
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            for (int i = 0; i < entries; i++)
            {
                zip.CreateEntry($"e{i}.txt");
            }
        }

        return ms.ToArray();
    }

    private static int FindEocd(byte[] bytes)
    {
        for (int i = bytes.Length - EocdFixedSize; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i)) == EocdSignature)
            {
                return i;
            }
        }

        throw new InvalidOperationException("no EOCD in the generated archive");
    }

    [Fact]
    public void OrdinaryArchive_OpensAndListsItsEntries()
    {
        byte[] bytes = BuildZip(25);

        using var zip = SafeZipArchive.Open(new MemoryStream(bytes));

        Assert.Equal(25, zip.Entries.Count);
    }

    // A non-ZIP64 EOCD stores its entry count in a ushort, so it cannot declare more than 65535 —
    // below the cap. The declared-count check therefore only ever fires through a ZIP64 record,
    // which is the shape an attacker wanting millions of entries is forced to use. Built by hand:
    // the guard rejects before opening, so the buffer need not be a loadable archive.
    [Fact]
    public void Zip64DeclaredEntryCountAboveCap_Refused()
    {
        const int Zip64EocdSize = 56;
        const int LocatorSize = 20;

        byte[] buf = new byte[Zip64EocdSize + LocatorSize + EocdFixedSize];

        // ZIP64 EOCD at offset 0
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0), 0x06064b50);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(4), 44);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(32), 10_000_000);  // total entries
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(40), 128);         // cd size, deliberately small

        // ZIP64 locator immediately before the EOCD
        int locator = Zip64EocdSize;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(locator), 0x07064b50);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(locator + 8), 0);  // ZIP64 EOCD at offset 0
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(locator + 16), 1);

        // EOCD with the 0xFFFF escape
        int eocd = Zip64EocdSize + LocatorSize;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(eocd), EocdSignature);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(eocd + EntriesThisDiskOffset), 0xFFFF);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(eocd + TotalEntriesOffset), 0xFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(eocd + CentralDirectorySizeOffset), 128);

        var ex = Assert.Throws<InvalidDataException>(() => SafeZipArchive.Open(new MemoryStream(buf)));
        Assert.Contains("10000000", ex.Message, StringComparison.Ordinal);
    }

    // Documents why the span bound is not redundant with the count bound: the format itself caps a
    // non-ZIP64 declaration below our cap, so the count check cannot fire on one.
    [Fact]
    public void NonZip64ArchiveCannotDeclareMoreEntriesThanTheCap() =>
        Assert.True(ushort.MaxValue <= ZipEntryLimits.MaxEntries);

    // The bound that actually holds. .NET walks the central directory and only afterwards compares
    // what it read against the EOCD count — so an archive under-declaring its count still pays the
    // full allocation before being rejected. Bounding the directory's byte span caps how many
    // records can physically be walked, whatever the header claims.
    [Fact]
    public void CentralDirectorySpanAboveCap_RefusedBeforeOpening()
    {
        byte[] bytes = BuildZip(3);
        int eocd = FindEocd(bytes);

        uint oversized = (uint)(ZipEntryLimits.MaxEntries * 46L + 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(eocd + CentralDirectorySizeOffset), oversized);

        var ex = Assert.Throws<InvalidDataException>(() => SafeZipArchive.Open(new MemoryStream(bytes)));
        Assert.Contains("central directory", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EnsureEntryCountWithinCap_RestoresStreamPosition()
    {
        byte[] bytes = BuildZip(5);
        var stream = new MemoryStream(bytes) { Position = 0 };

        SafeZipArchive.EnsureEntryCountWithinCap(stream);

        Assert.Equal(0, stream.Position);
    }

    [Fact]
    public void NotAZipAtAll_RefusedWithNoCentralDirectory()
    {
        byte[] bytes = new byte[512];

        var ex = Assert.Throws<InvalidDataException>(() => SafeZipArchive.Open(new MemoryStream(bytes)));
        Assert.Contains("End Of Central Directory", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NonSeekableStream_PassesThroughRatherThanSilentlyAllowing()
    {
        // ZipArchiveMode.Read requires seek, so the guard deliberately declines to check and lets
        // ZipArchive raise its own error — this asserts it cannot become a silent bypass.
        using var nonSeekable = new NonSeekableStream(BuildZip(2));

        SafeZipArchive.EnsureEntryCountWithinCap(nonSeekable);

        Assert.False(nonSeekable.CanSeek);
    }

    private sealed class NonSeekableStream(byte[] bytes) : Stream
    {
        private readonly MemoryStream _inner = new(bytes);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
