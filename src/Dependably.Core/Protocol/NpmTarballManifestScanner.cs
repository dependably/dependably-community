using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Dependably.Protocol;

/// <summary>How an npm tarball's top-level manifest scan ended.</summary>
public enum NpmManifestScanOutcome
{
    /// <summary>Exactly one top-level manifest was found and its bytes are available.</summary>
    Found,

    /// <summary>No top-level manifest, or the sole one is not a regular file.</summary>
    Missing,

    /// <summary>More than one top-level manifest (any wrapper, any case): the installed one is unknowable.</summary>
    Ambiguous,

    /// <summary>The archive could not be read to the end (corrupt, or over the decompression budget).</summary>
    Unscannable,

    /// <summary>The archive exceeds <see cref="TarScanLimits.MaxEntries"/> before the scan finished.</summary>
    TooManyEntries,

    /// <summary>
    /// Reading the bytes failed (storage or network I/O), as opposed to the bytes being a malformed
    /// archive. Says nothing about the tarball itself, so callers that persist a verdict must retry
    /// rather than record one. <see cref="NpmTarballManifestScanner.ScanOrUnscannable"/> reports it as
    /// <see cref="Unscannable"/> for callers that only need to fail closed.
    /// </summary>
    ReadFailed,
}

/// <summary>Result of <see cref="NpmTarballManifestScanner.Scan"/>.</summary>
public sealed record NpmManifestScan(NpmManifestScanOutcome Outcome, string? EntryName = null, byte[]? Bytes = null);

/// <summary>
/// The single place that selects an npm tarball's top-level <c>package.json</c>. npm extracts with
/// last-write-wins, so an archive with several top-level manifests installs a different one than a
/// first-match reader inspects. The scan therefore walks every entry (bounded by
/// <see cref="TarScanLimits"/>) and fails closed with <see cref="NpmManifestScanOutcome.Ambiguous"/>
/// when more than one entry matches <see cref="NpmTarballValidator.IsTopLevelPackageJson"/>, which is
/// case-insensitive and spans the root and every single-wrapper directory. Entries are found by
/// <see cref="NodeTarReader"/>, which reads tar blocks the way node-tar does, so the scan cannot
/// step over a header npm extracts. The validator, the install-script detector, and the licence
/// extractor all read through it so they cannot disagree.
/// </summary>
public static class NpmTarballManifestScanner
{
    /// <summary>
    /// Scans <paramref name="gzipSource"/>. Decompression failures propagate to the caller.
    /// </summary>
    public static NpmManifestScan Scan(Stream gzipSource, bool leaveOpen)
    {
        using var gzip = new LimitedReadStream(
            new GZipStream(gzipSource, CompressionMode.Decompress, leaveOpen),
            TarScanLimits.MaxTotalDecompressedBytes, "Tarball");

        // Entry boundaries come from a walk that mirrors node-tar's parser, not System.Formats.Tar:
        // the two disagree about headers node-tar skips (a bad checksum, an empty path, a link name
        // on a regular file) and about directory sizes, so a body one reader steps over is a
        // header the other extracts. Any block whose node-tar reading is uncertain ends the scan.
        var tar = new NodeTarReader(gzip);
        int entryCount = 0;
        string? foundName = null;
        byte[]? foundBytes = null;
        bool matched = false;

        try
        {
            while (tar.Next() is { } entry)
            {
                if (++entryCount > TarScanLimits.MaxEntries)
                {
                    return new NpmManifestScan(NpmManifestScanOutcome.TooManyEntries);
                }

                var kind = NpmTarballValidator.ClassifyEntry(entry.Path);
                if (kind == NpmTarballValidator.ManifestEntryKind.None)
                {
                    continue;
                }

                if (kind == NpmTarballValidator.ManifestEntryKind.Traversal || matched)
                {
                    return new NpmManifestScan(NpmManifestScanOutcome.Ambiguous);
                }

                // A manifest-named entry of any type counts toward ambiguity, but only a regular
                // file (the types pacote's extraction filter writes) has bytes npm would read.
                matched = true;
                if (entry.IsFile)
                {
                    foundName = entry.Path;
                    foundBytes = tar.ReadBody(TarScanLimits.MaxManifestBytes, "package.json");
                }
            }
        }
        catch (NodeTarDivergenceException)
        {
            return new NpmManifestScan(NpmManifestScanOutcome.Unscannable);
        }

        if (foundBytes is null)
        {
            return new NpmManifestScan(NpmManifestScanOutcome.Missing);
        }

        // JSON.parse keeps the last of two equal keys while a first-wins reader keeps the first, so
        // a manifest with a duplicate key is read differently by npm and by this server. It is
        // reported as unscannable rather than handed to the readers downstream.
        return TryParseManifest(foundBytes) is null
            ? new NpmManifestScan(NpmManifestScanOutcome.Unscannable)
            : new NpmManifestScan(NpmManifestScanOutcome.Found, foundName, foundBytes);
    }

    private static readonly JsonDocumentOptions StrictManifestOptions = new() { AllowDuplicateProperties = false };

    /// <summary>
    /// Parses package.json bytes strictly: a duplicate property name anywhere in the document, or
    /// malformed JSON, yields null instead of a node whose accessors throw or pick a side lazily.
    /// </summary>
    public static JsonNode? TryParseManifest(byte[] manifestBytes)
    {
        try
        {
            return JsonNode.Parse(manifestBytes, nodeOptions: null, StrictManifestOptions);
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// <see cref="Scan"/> for callers that must fail closed: a corrupt archive or one that blows the
    /// decompression budget comes back as <see cref="NpmManifestScanOutcome.Unscannable"/> instead of
    /// throwing. Cancellation still propagates.
    /// </summary>
    public static NpmManifestScan ScanOrUnscannable(Stream gzipSource, bool leaveOpen)
    {
        var scan = ScanClassified(gzipSource, leaveOpen);
        return scan.Outcome == NpmManifestScanOutcome.ReadFailed
            ? new NpmManifestScan(NpmManifestScanOutcome.Unscannable)
            : scan;
    }

    /// <summary>
    /// <see cref="Scan"/> that separates a malformed archive (<see cref="NpmManifestScanOutcome.Unscannable"/>:
    /// bad gzip or tar framing, truncation, a breached decompression budget) from a failed read
    /// (<see cref="NpmManifestScanOutcome.ReadFailed"/>: storage or network I/O). Cancellation propagates.
    /// </summary>
    public static NpmManifestScan ScanClassified(Stream gzipSource, bool leaveOpen)
    {
        // Classified by origin, not exception type: only a failure raised by the source stream's own
        // reads is a read failure. Whatever the gzip or tar parser throws, of any type, means the
        // bytes could not be understood, so the archive is unscannable (fail closed).
        var source = new FaultTrackingStream(gzipSource);
        try
        {
            return Scan(source, leaveOpen);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new NpmManifestScan(source.ReadFaulted
                ? NpmManifestScanOutcome.ReadFailed
                : NpmManifestScanOutcome.Unscannable);
        }
    }

    // Read-only passthrough that records whether the wrapped stream itself threw while being read.
    private sealed class FaultTrackingStream(Stream inner) : Stream
    {
        public bool ReadFaulted { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            try
            {
                return inner.Read(buffer);
            }
            catch (Exception ex)
            {
                RecordFault(ex);
                throw;
            }
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            await ReadAsync(buffer.AsMemory(offset, count), cancellationToken);

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            try
            {
                return await inner.ReadAsync(buffer, cancellationToken);
            }
            catch (Exception ex)
            {
                RecordFault(ex);
                throw;
            }
        }

        private void RecordFault(Exception ex) => ReadFaulted |= ex is not OperationCanceledException;

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

    /// <summary>
    /// True for an outcome that must not be ingested or trusted: the installed manifest is
    /// ambiguous, or the archive could not be scanned to the end. Malformed content, not a policy
    /// question, so it holds whatever the tenant's install-script and licence settings.
    /// </summary>
    public static bool IsRefusable(NpmManifestScanOutcome outcome) =>
        outcome is NpmManifestScanOutcome.Ambiguous
            or NpmManifestScanOutcome.TooManyEntries
            or NpmManifestScanOutcome.Unscannable;
}
