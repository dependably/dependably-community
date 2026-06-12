namespace Dependably.Protocol;

/// <summary>
/// Caps applied when scanning gzipped-tar archives (<see cref="NpmTarballValidator"/>,
/// <see cref="EcosystemDetector"/>). The compressed input is bounded by the upload size
/// limits, but the decompressed size is attacker-controlled (gzip expands up to ~1000:1),
/// so every decompression pass runs under an explicit budget.
/// </summary>
public static class TarScanLimits
{
    /// <summary>Total decompressed bytes allowed across one tar enumeration (1 GiB).</summary>
    public const long MaxTotalDecompressedBytes = 1L * 1024 * 1024 * 1024;

    /// <summary>Maximum tar entries inspected in one enumeration.</summary>
    public const int MaxEntries = 100_000;

    /// <summary>Maximum decompressed size of a manifest entry such as <c>package.json</c> (4 MiB).</summary>
    public const long MaxManifestBytes = 4L * 1024 * 1024;
}

/// <summary>
/// Caps applied when decompressing RPM repodata XML (primary.xml.gz, filelists.xml.gz,
/// other.xml.gz). Repodata is smaller than a full artifact archive; the tighter cap
/// limits the blast radius of a high-ratio gzip payload from an upstream mirror.
/// </summary>
public static class RepodataDecompressLimits
{
    /// <summary>Maximum decompressed bytes for a single repodata document (256 MiB).</summary>
    public const long MaxDecompressedBytes = 256L * 1024 * 1024;
}

/// <summary>
/// Caps applied when decompressing PyPI sdist and npm tarball archives for metadata
/// and license extraction. Uses the same 1 GiB ceiling as the full tar scan so metadata
/// extraction paths share one consistent decompression budget.
/// </summary>
public static class ArchiveDecompressLimits
{
    /// <summary>Maximum decompressed bytes for a metadata/license extraction pass (1 GiB).</summary>
    public const long MaxDecompressedBytes = TarScanLimits.MaxTotalDecompressedBytes;
}

/// <summary>
/// Read-only pass-through stream that throws <see cref="InvalidDataException"/> once more than
/// <c>maxBytes</c> have been read from the inner stream. Wrapped around decompression streams
/// (and individual tar entry streams) so a small compressed upload cannot expand into an
/// unbounded decompressed read — the zip-bomb guard for archive inspection paths.
/// </summary>
public sealed class LimitedReadStream : Stream
{
    private readonly Stream _inner;
    private readonly long _maxBytes;
    private readonly string _description;
    private long _bytesRead;

    public LimitedReadStream(Stream inner, long maxBytes, string description)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentOutOfRangeException.ThrowIfNegative(maxBytes);
        _inner = inner;
        _maxBytes = maxBytes;
        _description = description;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Account(_inner.Read(buffer, offset, count));

    public override int Read(Span<byte> buffer) =>
        Account(_inner.Read(buffer));

    public override int ReadByte()
    {
        int value = _inner.ReadByte();
        if (value >= 0)
        {
            Account(1);
        }
        return value;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        Account(await _inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken));

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        Account(await _inner.ReadAsync(buffer, cancellationToken));

    public override void Flush()
    {
        // Read-only stream: nothing to flush.
    }

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

    private int Account(int read)
    {
        _bytesRead += read;
        return _bytesRead > _maxBytes
            ? throw new InvalidDataException(
                $"{_description} exceeds the {_maxBytes}-byte decompression limit.")
            : read;
    }
}
