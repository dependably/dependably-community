using System.Numerics;
using System.Text;

namespace Dependably.Protocol;

/// <summary>
/// Raised when <see cref="NodeTarReader"/> reaches a block whose meaning to node-tar it cannot
/// reproduce with certainty: a header node-tar would warn about and skip, a field only other tar
/// readers interpret, or a decode that depends on how the gzip stream happened to be chunked.
/// </summary>
internal sealed class NodeTarDivergenceException(string message) : IOException(message);

/// <summary>A non-metadata archive entry as node-tar's parser hands it to the extractor.</summary>
/// <param name="Path">The entry path after PAX and GNU long-name records, before <c>strip</c>.</param>
/// <param name="TypeFlag">The effective type code: NUL reads as <c>0</c>, a <c>0</c> named with a trailing <c>/</c> as <c>5</c>, an unknown code as <c>?</c>.</param>
/// <param name="Size">Body bytes that follow the header (zero for a directory, whatever its header says).</param>
internal sealed record NodeTarEntry(string Path, char TypeFlag, long Size)
{
    /// <summary>True for the types pacote's extraction filter writes to disk (names ending in <c>File</c>).</summary>
    public bool IsFile => TypeFlag is '0' or '7';
}

/// <summary>
/// Walks the 512-byte blocks of an uncompressed tar stream with node-tar's parser semantics
/// (<c>parse.js</c>, <c>header.js</c>, <c>pax.js</c>, <c>read-entry.js</c> in tar 7.x, non-strict
/// as pacote runs it), so entry boundaries are the ones npm sees rather than the ones
/// System.Formats.Tar sees. Where node-tar would warn and skip a block (bad checksum, empty path,
/// a link name on a non-link type, an undecodable number), and wherever node-tar's reading cannot
/// be reproduced with certainty, it throws <see cref="NodeTarDivergenceException"/> instead of
/// guessing. node-tar ends an archive only at two consecutive null blocks, so a lone null block
/// followed by a further header throws, and so does a stream that ends before two null blocks.
/// </summary>
internal sealed class NodeTarReader(Stream source)
{
    private const int BlockSize = 512;

    // node-tar's maxMetaEntrySize default: a larger PAX/GNU metadata entry is ignored, not applied.
    private const int MaxMetaEntrySize = 1024 * 1024;

    private static readonly Encoding Utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

    private readonly byte[] _block = new byte[BlockSize];
    private readonly byte[] _scratch = new byte[64 * 1024];
    private long _pendingDataBytes;
    private long _pendingPaddingBytes;
    private PendingExtended? _ex;
    private bool _sawNullBlock;
    private bool _ended;

    /// <summary>
    /// Advances past the current entry's unread body and returns the next non-metadata entry, or
    /// null at the end of the archive.
    /// </summary>
    public NodeTarEntry? Next()
    {
        while (!_ended)
        {
            SkipPendingBody();
            ReadHeaderBlock();
            var header = DecodeHeader(_block, _ex);
            if (header.NullBlock)
            {
                if (_sawNullBlock)
                {
                    _ended = true;
                    return null;
                }

                _sawNullBlock = true;
                continue;
            }

            if (_sawNullBlock)
            {
                // node-tar keeps reading after a single null block; System.Formats.Tar and most
                // other readers stop there, so the two disagree about what the archive holds.
                throw new NodeTarDivergenceException("A header follows a single end-of-archive block.");
            }

            ValidateHeader(header);

            if (header.IsMeta)
            {
                ConsumeMeta(header);
                continue;
            }

            CheckAlternativePath(header);
            _ex = null;
            BeginBody(header.Size);
            return new NodeTarEntry(header.EntryPath, header.TypeFlag, header.Size);
        }

        return null;
    }

    private void ReadHeaderBlock()
    {
        int read = ReadFull(_block);
        if (read == 0)
        {
            // Only two null blocks stop node-tar reading headers. Without them it parses
            // whatever a further gzip member decodes to, and whether zlib reads that member at
            // all depends on where the stream's chunk boundaries fall.
            throw new NodeTarDivergenceException("Archive ends without two end-of-archive blocks.");
        }

        if (read < BlockSize)
        {
            throw new NodeTarDivergenceException("Archive ends inside a header block.");
        }
    }

    private void CheckAlternativePath(DecodedHeader header)
    {
        if (_ex is not { HasAlternativePath: true } ex)
        {
            return;
        }

        var alternative = DecodeHeader(_block, ex with { Path = ex.AlternativePath, HasAlternativePath = false });
        if (!SameOutcome(header, alternative))
        {
            throw new NodeTarDivergenceException(
                "A non-ASCII PAX path record may be read or dropped depending on stream chunking.");
        }
    }

    /// <summary>Reads the current entry's whole body, refusing one larger than <paramref name="maxBytes"/>.</summary>
    public byte[] ReadBody(long maxBytes, string description)
    {
        if (_pendingDataBytes > maxBytes)
        {
            throw new InvalidDataException($"{description} exceeds the {maxBytes}-byte decompression limit.");
        }

        byte[] body = new byte[_pendingDataBytes];
        if (ReadFull(body) < body.Length)
        {
            throw new NodeTarDivergenceException("Archive ends inside an entry body.");
        }

        _pendingDataBytes = 0;
        return body;
    }

    private void BeginBody(long size)
    {
        _pendingDataBytes = size;
        _pendingPaddingBytes = (BlockSize - (size % BlockSize)) % BlockSize;
    }

    private void SkipPendingBody()
    {
        long remaining = _pendingDataBytes + _pendingPaddingBytes;
        _pendingDataBytes = 0;
        _pendingPaddingBytes = 0;
        while (remaining > 0)
        {
            int read = source.Read(_scratch, 0, (int)Math.Min(_scratch.Length, remaining));
            if (read == 0)
            {
                throw new NodeTarDivergenceException("Archive ends inside an entry body.");
            }

            remaining -= read;
        }
    }

    private int ReadFull(Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = source.Read(buffer[total..]);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    // CONSUMEHEADER's checks, in its order. Each is a warn-and-skip-one-block in node-tar.
    private static void ValidateHeader(DecodedHeader header)
    {
        if (!header.ChecksumValid)
        {
            throw new NodeTarDivergenceException("Header checksum does not verify.");
        }

        if (header.HeaderPath.Length == 0)
        {
            throw new NodeTarDivergenceException("Header has an empty path.");
        }

        bool isLink = header.TypeFlag is '1' or '2';
        if (isLink && header.LinkPath.Length == 0)
        {
            throw new NodeTarDivergenceException("Link header has no link path.");
        }

        if (!isLink && header.TypeFlag is not ('g' or 'x') && header.LinkPath.Length > 0)
        {
            throw new NodeTarDivergenceException("Non-link header carries a link path.");
        }
    }

    private void ConsumeMeta(DecodedHeader header)
    {
        if (header.Size > MaxMetaEntrySize)
        {
            throw new NodeTarDivergenceException("Metadata entry exceeds node-tar's 1 MiB limit and would be ignored.");
        }

        BeginBody(header.Size);
        if (header.Size == 0)
        {
            return;
        }

        byte[] body = ReadBody(MaxMetaEntrySize, "Tar metadata entry");
        string meta = Utf8.GetString(body);
        switch (header.TypeFlag)
        {
            case 'x' or 'X':
                _ex = ParsePax(meta, _ex ?? PendingExtended.Empty, global: false);
                break;
            case 'g':
                ParsePax(meta, PendingExtended.Empty, global: true);
                break;
            case 'L' or 'N':
                if (meta.Contains('\0') && meta.AsSpan().IndexOfAny('\u2028', '\u2029') >= 0)
                {
                    throw new NodeTarDivergenceException(
                        "GNU long name mixes NUL and a multi-byte line terminator; its decode depends on stream chunking.");
                }

                _ex = (_ex ?? PendingExtended.Empty) with
                {
                    Path = StripFirstNulRun(meta),
                    HasAlternativePath = false,
                    AlternativePath = null,
                };
                break;
        }
    }

    // Pax.parse / parseKVLine. Only `path` and `size` influence entry boundaries or names; every
    // other key is ignored here exactly as it is irrelevant to which bytes npm installs.
    private static PendingExtended ParsePax(string meta, PendingExtended previous, bool global)
    {
        string body = meta.EndsWith('\n') ? meta[..^1] : meta;
        var result = previous;
        int pathRecords = 0;
        bool fragilePath = false;
        foreach (string line in body.Split('\n'))
        {
            if (JsParseIntBase10(line) is not { } n)
            {
                continue;
            }

            bool accepted = n == Encoding.UTF8.GetByteCount(line) + 1;
            string digits = n.ToString(System.Globalization.CultureInfo.InvariantCulture);
            string rest = digits.Length + 1 >= line.Length ? string.Empty : line[(digits.Length + 1)..];
            int eq = rest.IndexOf('=');
            string key = eq < 0 ? rest : rest[..eq];
            if (key.Length == 0 || key is not ("path" or "size"))
            {
                continue;
            }

            // node-tar decodes the stream chunk by chunk, so a multi-byte character can straddle a
            // chunk boundary and decode as replacement characters. That changes the record's byte
            // length, and so whether the record is kept, depending on how the bytes arrived.
            bool fragile = line.Any(c => c > 0x7F);
            string value = eq < 0 ? string.Empty : StripFirstNulRun(rest[(eq + 1)..]);
            if (key == "size")
            {
                if (fragile)
                {
                    throw new NodeTarDivergenceException("A non-ASCII PAX size record may be read or dropped depending on stream chunking.");
                }

                if (!accepted)
                {
                    continue;
                }

                if (global)
                {
                    throw new NodeTarDivergenceException("A global PAX size record applies to every later entry only in node-tar.");
                }

                if (value.Length == 0 || value.Length > 18 || !value.All(char.IsAsciiDigit))
                {
                    throw new NodeTarDivergenceException("PAX size record is not a plain decimal number.");
                }

                result = result with { Size = long.Parse(value, System.Globalization.CultureInfo.InvariantCulture) };
                continue;
            }

            if (global)
            {
                // A global path is never applied to an entry.
                continue;
            }

            pathRecords++;
            fragilePath |= fragile;
            if (fragile)
            {
                result = accepted
                    ? result with { Path = value, HasAlternativePath = true, AlternativePath = result.Path }
                    : result with { HasAlternativePath = true, AlternativePath = value };
            }
            else if (accepted)
            {
                result = result with { Path = value, HasAlternativePath = false, AlternativePath = null };
            }
        }

        return fragilePath && (pathRecords > 1 || previous.HasAlternativePath)
            ? throw new NodeTarDivergenceException("Several PAX path records, one of them chunking-dependent.")
            : result;
    }

    private static bool SameOutcome(DecodedHeader a, DecodedHeader b) =>
        a.TypeFlag == b.TypeFlag
        && (a.HeaderPath.Length == 0) == (b.HeaderPath.Length == 0)
        && (a.EntryPath.Length == 0) == (b.EntryPath.Length == 0)
        && NpmTarballValidator.ClassifyEntry(a.EntryPath) == NpmTarballValidator.ClassifyEntry(b.EntryPath);

    private static (char Type, bool NormalFs) DecodeTypeFlag(byte[] block)
    {
        string typeString = DecodeString(block, 156, 1);
        bool normalFs = typeString is "0" or "" or "1" or "2" or "3" or "4" or "5" or "6" or "7" or "D";
        bool known = normalFs || typeString is "g" or "x" or "A" or "I" or "K" or "L" or "M" or "N" or "S" or "V" or "X";
        char type = !known ? '?' : typeString.Length == 0 ? '0' : typeString[0];
        return (type, normalFs);
    }

    private static DecodedHeader DecodeHeader(byte[] block, PendingExtended? ex)
    {
        var (type, normalFs) = DecodeTypeFlag(block);
        var fieldEx = normalFs ? ex : null;

        // Every numeric field node-tar may decode: a malformed base-256 value throws in node-tar
        // and the whole block is skipped. node-tar skips some of these reads when a pending PAX
        // record supplies the value; decoding them regardless is at least as strict.
        bool ustar = block.AsSpan(257, 6).SequenceEqual("ustar\0"u8) && block[263] == '0' && block[264] == '0';
        DecodeNumericFields(block, ustar);

        string path = fieldEx?.Path ?? DecodeString(block, 0, 100);
        long? rawSize = DecodeNumber(block, 124, 12) is { } s && s >= 0 ? (long)s : null;
        long size = (fieldEx?.Size ?? rawSize) ?? 0;
        if (type == '0' && path.EndsWith('/'))
        {
            type = '5';
        }

        if (type == '5')
        {
            size = 0;
        }

        string linkPath = DecodeString(block, 157, 100);
        if (ustar)
        {
            path = PrefixedPath(block, path);
        }

        long sum = HeaderSum(block);
        double? checksum = DecodeNumber(block, 148, 12);
        bool meta = type is 'g' or 'x' or 'X' or 'K' or 'L' or 'N';

        // ReadEntry takes the pending extended path over the header's for every entry type.
        string entryPath = ex?.Path ?? path;
        return new DecodedHeader(
            HeaderPath: path,
            EntryPath: entryPath,
            LinkPath: linkPath,
            TypeFlag: type,
            Size: size,
            IsMeta: meta,
            ChecksumValid: checksum == sum,
            NullBlock: checksum is null && sum == 8 * 0x20);
    }

    private static void DecodeNumericFields(byte[] block, bool ustar)
    {
        foreach (var (offset, length) in BaseNumericFields)
        {
            DecodeNumber(block, offset, length);
        }

        if (!ustar)
        {
            return;
        }

        DecodeNumber(block, 329, 8);
        DecodeNumber(block, 337, 8);
        if (block[475] == 0)
        {
            DecodeNumber(block, 476, 12);
            DecodeNumber(block, 488, 12);
        }
    }

    private static string PrefixedPath(byte[] block, string path)
    {
        if (block[475] != 0)
        {
            return DecodeString(block, 345, 155) + "/" + path;
        }

        string prefix = DecodeString(block, 345, 130);
        return prefix.Length > 0 ? prefix + "/" + path : path;
    }

    private static long HeaderSum(byte[] block)
    {
        long sum = 8 * 0x20;
        for (int i = 0; i < 148; i++)
        {
            sum += block[i];
        }

        for (int i = 156; i < BlockSize; i++)
        {
            sum += block[i];
        }

        return sum;
    }

    private static readonly (int Offset, int Length)[] BaseNumericFields =
    [
        (100, 8), (108, 8), (116, 8), (124, 12), (136, 12), (148, 12),
    ];

    // header.js decNumber: base-256 when the high bit of the first byte is set (only 0x80 and 0xff
    // prefixes are valid, and the value must be a JS safe integer), otherwise decSmallNumber.
    private static double? DecodeNumber(byte[] block, int offset, int length)
    {
        var field = block.AsSpan(offset, length);
        if ((field[0] & 0x80) == 0)
        {
            return DecodeSmallNumber(field);
        }

        var value = field[0] switch
        {
            0x80 => new BigInteger(field[1..], isUnsigned: true, isBigEndian: true),
            0xff => new BigInteger(field, isUnsigned: false, isBigEndian: true),
            _ => throw new NodeTarDivergenceException("Header number has an invalid base-256 prefix."),
        };

        const long MaxSafeInteger = (1L << 53) - 1;
        return BigInteger.Abs(value) > MaxSafeInteger
            ? throw new NodeTarDivergenceException("Header number exceeds the JavaScript safe-integer range.")
            : (double)value;
    }

    // parseInt(field.toString('utf8').replace(/\0.*$/, '').trim(), 8), with NaN as null.
    private static double? DecodeSmallNumber(ReadOnlySpan<byte> field)
    {
        string text = Utf8.GetString(field);
        int lastTerminator = text.AsSpan().LastIndexOfAny(JsLineTerminators);
        int nul = text.IndexOf('\0', lastTerminator + 1);
        if (nul >= 0)
        {
            text = text[..nul];
        }

        text = JsTrim(text);
        int i = 0;
        bool negative = false;
        if (i < text.Length && text[i] is '+' or '-')
        {
            negative = text[i] == '-';
            i++;
        }

        int start = i;
        double value = 0;
        while (i < text.Length && text[i] is >= '0' and <= '7')
        {
            value = (value * 8) + (text[i] - '0');
            i++;
        }

        return i == start ? null : negative ? -value : value;
    }

    // header.js decString: field.toString('utf8').replace(/\0.*/, '').
    private static string DecodeString(byte[] block, int offset, int length) =>
        StripFirstNulRun(Utf8.GetString(block, offset, length));

    // JS `s.replace(/\0.*/, '')`: removes the first NUL and what follows it up to, not including,
    // the next line terminator (`.` does not match one), rather than truncating at the NUL.
    private static string StripFirstNulRun(string s)
    {
        int nul = s.IndexOf('\0');
        if (nul < 0)
        {
            return s;
        }

        int end = s.AsSpan(nul).IndexOfAny(JsLineTerminators);
        return end < 0 ? s[..nul] : string.Concat(s.AsSpan(0, nul), s.AsSpan(nul + end));
    }

    private const string JsLineTerminators = "\n\r\u2028\u2029";

    // JS parseInt(line, 10) for the record-length prefix: leading JS whitespace, optional sign,
    // decimal digits. Values too long to be a record length are reported as no match.
    private static long? JsParseIntBase10(string line)
    {
        int i = 0;
        while (i < line.Length && IsJsWhitespace(line[i]))
        {
            i++;
        }

        bool negative = false;
        if (i < line.Length && line[i] is '+' or '-')
        {
            negative = line[i] == '-';
            i++;
        }

        int start = i;
        long value = 0;
        while (i < line.Length && char.IsAsciiDigit(line[i]))
        {
            if (i - start >= 15)
            {
                return null;
            }

            value = (value * 10) + (line[i] - '0');
            i++;
        }

        return i == start ? null : negative ? -value : value;
    }

    private static string JsTrim(string s)
    {
        int start = 0;
        int end = s.Length;
        while (start < end && IsJsWhitespace(s[start]))
        {
            start++;
        }

        while (end > start && IsJsWhitespace(s[end - 1]))
        {
            end--;
        }

        return s[start..end];
    }

    // ECMAScript WhiteSpace and LineTerminator code points, which String.prototype.trim and
    // parseInt skip.
    private static bool IsJsWhitespace(char c) =>
        c is '\t' or '\n' or '\v' or '\f' or '\r' or ' ' or '\u00a0' or '\u1680' or (>= '\u2000' and <= '\u200a')
            or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000' or '\ufeff';

    private sealed record DecodedHeader(
        string HeaderPath, string EntryPath, string LinkPath, char TypeFlag, long Size,
        bool IsMeta, bool ChecksumValid, bool NullBlock);

    // The extended-header state node-tar carries to the next entry. A path whose record node-tar
    // may or may not keep (see ParsePax) carries the other reading as an alternative.
    private sealed record PendingExtended(string? Path, long? Size, bool HasAlternativePath, string? AlternativePath)
    {
        public static readonly PendingExtended Empty = new(null, null, false, null);
    }
}
