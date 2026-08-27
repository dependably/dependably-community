using System.Buffers.Binary;
using System.IO.Compression;

namespace Dependably.Protocol;

/// <summary>
/// The only place a <see cref="ZipArchive"/> is opened over untrusted bytes.
///
/// <para>
/// <see cref="ZipArchive.Entries"/> materialises the archive's entire central directory into a
/// <c>List&lt;ZipArchiveEntry&gt;</c> on first access, and the entry count is attacker-controlled
/// independently of the compressed size the upload limits bound. A central-directory record is
/// ~46 bytes plus a filename that may be a single byte, and — critically — the local file data
/// those records point at does not have to exist for the listing to succeed. So a crafted
/// <c>.nupkg</c>/<c>.whl</c> well inside the route's upload ceiling can carry millions of minimal
/// entries and cost millions of object allocations on a single request.
/// </para>
///
/// <para>
/// The tar path has bounded this since it was written — <see cref="TarScanLimits.MaxEntries"/>,
/// whose comment states the reasoning exactly: the compressed input is bounded by upload limits,
/// but the entry count is not. The ZIP path never inherited it.
/// <see cref="ZipEntryLimits.MaxMetadataEntryBytes"/> bounds only the *matched* entry's
/// decompressed bytes, which is a different quantity — it says nothing about the cost of finding it.
/// </para>
///
/// <para>
/// The count is read from the End Of Central Directory record <b>before</b> the archive is opened,
/// rather than by checking <c>zip.Entries.Count</c>, because the latter has already paid the
/// allocation it is meant to prevent.
/// </para>
/// </summary>
public static class SafeZipArchive
{
    // EOCD: signature(4) diskNo(2) cdDisk(2) entriesThisDisk(2) totalEntries(2) cdSize(4)
    //       cdOffset(4) commentLen(2) = 22 bytes fixed, plus a comment of up to 0xFFFF.
    private const int EocdFixedSize = 22;
    private const int MaxCommentLength = 0xFFFF;
    private const int TotalEntriesOffset = 10;
    private const uint EocdSignature = 0x06054b50;
    private const uint Zip64LocatorSignature = 0x07064b50;
    private const uint Zip64EocdSignature = 0x06064b50;

    /// <summary>Fixed size of one central-directory file header, before its variable-length name.</summary>
    private const int MinCentralDirectoryRecordSize = 46;

    private const int CentralDirectorySizeOffset = 12;

    /// <summary>
    /// Opens <paramref name="stream"/> as a ZIP archive after refusing an entry count above
    /// <see cref="ZipEntryLimits.MaxEntries"/>.
    /// </summary>
    /// <exception cref="InvalidDataException">
    /// The archive declares more entries than the cap allows, or its central directory cannot be
    /// located.
    /// </exception>
    public static ZipArchive Open(Stream stream, bool leaveOpen = false)
    {
        EnsureEntryCountWithinCap(stream);
        return new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen);
    }

    /// <summary>
    /// Throws if the archive's declared entry count exceeds <see cref="ZipEntryLimits.MaxEntries"/>.
    /// Leaves <paramref name="stream"/>'s position where it found it.
    /// </summary>
    /// <remarks>
    /// A non-seekable stream is passed through unchecked: <see cref="ZipArchiveMode.Read"/> requires
    /// seek and throws on its own, so this cannot become a silent bypass.
    /// </remarks>
    public static void EnsureEntryCountWithinCap(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (!stream.CanSeek)
        {
            return;
        }

        long entered = stream.Position;
        try
        {
            (long declared, long centralDirectoryBytes) = ReadCentralDirectoryFacts(stream);

            if (declared > ZipEntryLimits.MaxEntries)
            {
                throw new InvalidDataException(
                    $"ZIP archive declares {declared} entries, above the {ZipEntryLimits.MaxEntries} " +
                    $"cap. Enumerating them would allocate one object per entry before any size " +
                    $"limit applies.");
            }

            // The declared count alone is not a sufficient bound. .NET walks the central directory
            // and only then compares what it read against the EOCD's count, raising
            // InvalidDataException on a mismatch — so an archive declaring 1 entry while carrying
            // millions of records still pays the full allocation before it is rejected. Bounding the
            // central directory's byte span caps how many records can physically be walked,
            // whatever the header claims.
            long maxCentralDirectoryBytes = (long)ZipEntryLimits.MaxEntries * MinCentralDirectoryRecordSize;
            if (centralDirectoryBytes > maxCentralDirectoryBytes)
            {
                throw new InvalidDataException(
                    $"ZIP archive's central directory is {centralDirectoryBytes} bytes, above the " +
                    $"{maxCentralDirectoryBytes} cap ({ZipEntryLimits.MaxEntries} entries x " +
                    $"{MinCentralDirectoryRecordSize} bytes minimum per record).");
            }
        }
        finally
        {
            stream.Position = entered;
        }
    }

    /// <summary>
    /// The declared entry count and the central directory's byte span, following the ZIP64 record
    /// when the 32-bit fields are escaped.
    /// </summary>
    private static (long DeclaredEntries, long CentralDirectoryBytes) ReadCentralDirectoryFacts(Stream stream)
    {
        long eocd = FindEocdOffset(stream)
            ?? throw new InvalidDataException("ZIP archive has no End Of Central Directory record.");

        Span<byte> eocdBuf = stackalloc byte[EocdFixedSize];
        stream.Position = eocd;
        stream.ReadExactly(eocdBuf);

        long total = BinaryPrimitives.ReadUInt16LittleEndian(eocdBuf[TotalEntriesOffset..]);
        long cdSize = BinaryPrimitives.ReadUInt32LittleEndian(eocdBuf[CentralDirectorySizeOffset..]);

        // A non-ZIP64 archive cannot express more than 0xFFFF entries, so the escape is the only
        // way a larger count is declared at all — but cdSize is the bound that actually holds, and
        // it is read either way.
        var zip64 = ReadZip64Facts(stream, eocd);
        if (zip64 is { } z)
        {
            total = Math.Max(total, z.DeclaredEntries);
            cdSize = Math.Max(cdSize, z.CentralDirectoryBytes);
        }

        return (total, cdSize);
    }

    /// <summary>
    /// The ZIP64 EOCD's entry count and central-directory size, or null when the locator is absent.
    /// </summary>
    private static (long DeclaredEntries, long CentralDirectoryBytes)? ReadZip64Facts(Stream stream, long eocdOffset)
    {
        // The ZIP64 locator (20 bytes) sits immediately before the EOCD when ZIP64 is in use.
        const int LocatorSize = 20;
        const int LocatorTargetOffset = 8;    // signature(4) + disk(4)
        const int Zip64TotalEntriesOffset = 32;
        const int Zip64CentralDirectorySizeOffset = 40;

        long locator = eocdOffset - LocatorSize;
        if (locator < 0)
        {
            return null;
        }

        Span<byte> buf = stackalloc byte[LocatorSize];
        stream.Position = locator;
        stream.ReadExactly(buf);

        if (BinaryPrimitives.ReadUInt32LittleEndian(buf) != Zip64LocatorSignature)
        {
            return null;
        }

        long zip64Eocd = (long)BinaryPrimitives.ReadUInt64LittleEndian(buf[LocatorTargetOffset..]);
        if (zip64Eocd < 0 || zip64Eocd + Zip64CentralDirectorySizeOffset + sizeof(ulong) > stream.Length)
        {
            return null;
        }

        Span<byte> head = stackalloc byte[Zip64CentralDirectorySizeOffset + sizeof(ulong)];
        stream.Position = zip64Eocd;
        stream.ReadExactly(head);

        if (BinaryPrimitives.ReadUInt32LittleEndian(head) != Zip64EocdSignature)
        {
            return null;
        }

        ulong total = BinaryPrimitives.ReadUInt64LittleEndian(head[Zip64TotalEntriesOffset..]);
        ulong cdSize = BinaryPrimitives.ReadUInt64LittleEndian(head[Zip64CentralDirectorySizeOffset..]);
        return (Clamp(total), Clamp(cdSize));

        static long Clamp(ulong v) => v > long.MaxValue ? long.MaxValue : (long)v;
    }

    /// <summary>
    /// Offset of the EOCD signature, scanning back from the end over the largest region it may
    /// occupy (its fixed size plus the maximum comment length).
    /// </summary>
    private static long? FindEocdOffset(Stream stream)
    {
        long length = stream.Length;
        if (length < EocdFixedSize)
        {
            return null;
        }

        int window = (int)Math.Min(length, EocdFixedSize + MaxCommentLength);
        long start = length - window;

        byte[] buf = new byte[window];
        stream.Position = start;
        stream.ReadExactly(buf, 0, window);

        // Scan backwards: the last signature is the real EOCD when archive bytes coincidentally
        // contain the same four bytes earlier on.
        for (int i = window - EocdFixedSize; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(i)) == EocdSignature)
            {
                return start + i;
            }
        }

        return null;
    }
}
