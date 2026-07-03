using System.Buffers;
using System.Buffers.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Protocol;

namespace Dependably.Api.NpmProtocol;

// Staging file paths are "publish-stage-{server-GUID}.json/.tmp" under the operator-configured
// staging root; the request body reaches file CONTENT, never file NAMES. SCS's interprocedural
// taint from Request.Body into the constructed paths is a false positive.
#pragma warning disable SCS0018

/// <summary>
/// Memory-bounded parser for an npm publish body (<c>PUT /npm/{pkg}</c>). The body is a JSON
/// packument whose <c>_attachments.{filename}.data</c> field carries the tarball as a base64
/// string — for a near-cap publish that single field is hundreds of MB, so parsing the whole body
/// into a UTF-16 string plus a <see cref="JsonNode"/> DOM (which also retains a copy of the base64)
/// costs multiple gigabytes of managed memory.
///
/// <para>Instead this parser:
/// <list type="number">
///   <item>streams the raw body to a staging JSON file (bounded by the upload cap), so the whole
///         body never becomes a managed string;</item>
///   <item>walks the staged file with a small streaming <see cref="Utf8JsonReader"/> to locate the
///         byte offset of the <c>_attachments.{key}.data</c> value <b>without</b> reading that
///         value into the buffer;</item>
///   <item>base64-decodes that value incrementally (a small carry buffer at a time) straight to a
///         tarball staging file — the decoded tarball never enters managed memory;</item>
///   <item>builds a small <see cref="JsonNode"/> envelope DOM from a redacted copy of the file
///         (the giant <c>data</c> value replaced with <c>""</c>) so the handler still reads
///         <c>name</c> / <c>versions</c> / <c>dist-tags</c> / <c>_attachments</c> normally.</item>
/// </list>
/// Peak managed memory is bounded by the small streaming buffers regardless of tarball size.</para>
/// </summary>
internal static class NpmPublishBodyParser
{
    // Outcome discriminator so the handler maps to the exact HTTP result it produced before.
    internal enum NpmParseErrorKind
    {
        None,
        TooLarge,        // 413 — body/attachment exceeds the upload cap
        InvalidJson,     // 422 — body is not valid JSON
        AttachmentShape, // 422 — _attachments not exactly one entry / data missing / length mismatch / bad base64
    }

    /// <summary>
    /// Result of parsing a publish body. On success <see cref="Envelope"/> is the small redacted
    /// DOM; when the body carried an attachment, <see cref="TarballPath"/> points at the staged
    /// tarball. On failure <see cref="ErrorKind"/> is non-<see cref="NpmParseErrorKind.None"/> and
    /// <see cref="ErrorDetail"/> carries the message.
    /// </summary>
    internal sealed record NpmParseResult(
        JsonNode? Envelope,
        string? AttachmentKey,
        string? TarballPath,
        long TarballSize,
        NpmParseErrorKind ErrorKind,
        string? ErrorDetail);

    private static NpmParseResult Fail(NpmParseErrorKind kind, string detail) =>
        new(null, null, null, 0, kind, detail);

    /// <summary>
    /// Parses the publish body from <paramref name="body"/>. The caller owns deletion of
    /// <see cref="NpmParseResult.TarballPath"/> (via the handler's staging-cleanup helper).
    /// </summary>
    internal static async Task<NpmParseResult> ParseAsync(
        Stream body, long cap, string stagingRoot, CancellationToken ct)
    {
        // deepcode ignore PT: staging file name is "publish-stage-{server-guid}.json" under the operator-configured staging root — no user input reaches the path.
        string jsonPath = Path.Combine(stagingRoot, $"publish-stage-{Guid.NewGuid():N}.json");
        string? tarballPath = null;
        bool keepTarball = false;
        try
        {
            // 1. Stream the raw body to a staging file, capped. A cap breach becomes a 413 before
            //    any JSON parsing or decode — mirroring the old LimitedReadStream behaviour.
            try
            {
                await using var jsonFile = new FileStream(
                    jsonPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true);
                await using var limited = new LimitedReadStream(body, cap, "npm publish body");
                await limited.CopyToAsync(jsonFile, ct);
            }
            catch (InvalidDataException)
            {
                return Fail(NpmParseErrorKind.TooLarge,
                    $"Request body exceeds the npm publish limit of {cap} bytes.");
            }

            await using var json = new FileStream(
                jsonPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);

            // 2. Locate the _attachments.{key}.data property token (byte offset in the file), or
            //    -1 when the body carries no attachment (the npm-deprecate shape).
            long dataTokenStart;
            try
            {
                dataTokenStart = await LocateAttachmentDataTokenAsync(json, ct);
            }
            catch (JsonException)
            {
                return Fail(NpmParseErrorKind.InvalidJson, "Invalid JSON body.");
            }

            if (dataTokenStart < 0)
            {
                // No attachment-data value: the file is small (no giant base64), parse it whole.
                json.Seek(0, SeekOrigin.Begin);
                JsonNode? node;
                try
                {
                    node = JsonNode.Parse(json);
                }
                catch (JsonException)
                {
                    return Fail(NpmParseErrorKind.InvalidJson, "Invalid JSON body.");
                }

                // No _attachments key at all is the npm-deprecate shape — a valid body the handler
                // routes to the deprecation path. An _attachments key that is present but carried no
                // resolvable data is an invalid publish, mapped to the same 422s the handler emitted
                // before streaming.
                var att = node?["_attachments"];
                return att switch
                {
                    null => new NpmParseResult(node, null, null, 0, NpmParseErrorKind.None, null),
                    JsonObject { Count: 1 } => Fail(NpmParseErrorKind.AttachmentShape, "_attachments.data is required."),
                    _ => Fail(NpmParseErrorKind.AttachmentShape, "_attachments must contain exactly one entry."),
                };
            }

            // 3. Raw-scan from the "data" property token to the value's byte range, then decode the
            //    base64 content incrementally to the tarball staging file.
            var span = await ResolveDataValueSpanAsync(json, dataTokenStart, ct);
            if (span is null)
            {
                return Fail(NpmParseErrorKind.AttachmentShape, "_attachments.data is required.");
            }

            // deepcode ignore PT: staging file name is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            tarballPath = Path.Combine(stagingRoot, $"publish-stage-{Guid.NewGuid():N}.tmp");
            long tarballSize;
            try
            {
                tarballSize = await DecodeBase64RangeToFileAsync(
                    json, span.Value.ContentStart, span.Value.ContentEnd, tarballPath, ct);
            }
            catch (FormatException)
            {
                return Fail(NpmParseErrorKind.AttachmentShape, "Invalid base64 in _attachments.data.");
            }

            // 4. Build the small redacted envelope (data value replaced with "") and parse it.
            JsonNode? envelope;
            try
            {
                envelope = await ParseRedactedEnvelopeAsync(json, span.Value.ColonEnd, span.Value.ValueEnd, ct);
            }
            catch (JsonException)
            {
                return Fail(NpmParseErrorKind.InvalidJson, "Invalid JSON body.");
            }

            var attachments = envelope?["_attachments"]?.AsObject();
            if (attachments is null || attachments.Count != 1)
            {
                return Fail(NpmParseErrorKind.AttachmentShape, "_attachments must contain exactly one entry.");
            }

            var (attachmentKey, attachmentNode) = attachments.First();

            // Declared-length checks preserved from the pre-streaming handler.
            long declaredLength = attachmentNode?["length"]?.GetValue<long>() ?? -1;
            if (declaredLength > cap)
            {
                return Fail(NpmParseErrorKind.TooLarge,
                    $"Attachment declared length {declaredLength} exceeds the npm publish limit of {cap} bytes.");
            }
            if (declaredLength >= 0 && tarballSize != declaredLength)
            {
                return Fail(NpmParseErrorKind.AttachmentShape,
                    $"Attachment length mismatch: declared {declaredLength}, actual {tarballSize}.");
            }

            keepTarball = true;
            return new NpmParseResult(envelope, attachmentKey, tarballPath, tarballSize, NpmParseErrorKind.None, null);
        }
        finally
        {
            TryDelete(jsonPath);
            if (!keepTarball)
            {
                TryDelete(tarballPath);
            }
        }
    }

    // True when the object-nesting path is exactly root → "_attachments" → {attachment key}, so a
    // "data" property at that level is the tarball attachment (and not, e.g., a "data" field that
    // happens to appear inside a version object).
    private static bool IsAttachmentDataPath(List<string?> path) =>
        path.Count == 3 && path[0] is null && path[1] == "_attachments";

    // Walks the staged JSON with a small streaming Utf8JsonReader and returns the absolute byte
    // offset of the `_attachments.{key}.data` PROPERTY-NAME token, or -1 when no such property
    // exists. Stops BEFORE reading the (potentially huge) value, so the reader buffer never has to
    // hold the base64.
    private static async Task<long> LocateAttachmentDataTokenAsync(FileStream json, CancellationToken ct)
    {
        json.Seek(0, SeekOrigin.Begin);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(32768);
        try
        {
            int inBuffer = 0;
            long segStart = 0; // absolute file offset of buffer[0]
            var state = new JsonReaderState();
            var path = new List<string?>();
            string? pendingProp = null;

            while (true)
            {
                int read = await json.ReadAsync(buffer.AsMemory(inBuffer), ct);
                int available = inBuffer + read;
                bool isFinal = read == 0;

                var reader = new Utf8JsonReader(buffer.AsSpan(0, available), isFinal, state);
                while (reader.Read())
                {
                    switch (reader.TokenType)
                    {
                        case JsonTokenType.StartObject:
                        case JsonTokenType.StartArray:
                            path.Add(pendingProp);
                            pendingProp = null;
                            break;
                        case JsonTokenType.EndObject:
                        case JsonTokenType.EndArray:
                            if (path.Count > 0)
                            {
                                path.RemoveAt(path.Count - 1);
                            }
                            break;
                        case JsonTokenType.PropertyName:
                            string name = reader.GetString() ?? string.Empty;
                            if (name == "data" && IsAttachmentDataPath(path))
                            {
                                return segStart + reader.TokenStartIndex;
                            }
                            pendingProp = name;
                            break;
                    }
                }

                if (isFinal)
                {
                    return -1;
                }

                state = reader.CurrentState;
                int consumed = (int)reader.BytesConsumed;
                int leftover = available - consumed;
                if (consumed == 0)
                {
                    // A single token larger than the buffer (should not happen before `data`, which
                    // we stop at) — grow so parsing can make progress.
                    byte[] bigger = ArrayPool<byte>.Shared.Rent(buffer.Length * 2);
                    Array.Copy(buffer, bigger, available);
                    ArrayPool<byte>.Shared.Return(buffer);
                    buffer = bigger;
                    inBuffer = available;
                }
                else
                {
                    Array.Copy(buffer, consumed, buffer, 0, leftover);
                    inBuffer = leftover;
                    segStart += consumed;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private readonly record struct DataValueSpan(long ColonEnd, long ContentStart, long ContentEnd, long ValueEnd);

    // Starting at the `data` property-name token, scans forward over the property name, the colon,
    // and the opening quote to find the value's byte range. Base64 contains no '"' or '\', so the
    // value ends at the next '"'. Returns null when the value is not a JSON string (e.g. null).
    private static async Task<DataValueSpan?> ResolveDataValueSpanAsync(
        FileStream json, long tokenStart, CancellationToken ct)
    {
        var cursor = new ForwardByteCursor(json, tokenStart);

        // Property name: opening quote, then bytes until an unescaped quote.
        if (await cursor.NextAsync(ct) != (byte)'"')
        {
            return null;
        }
        while (true)
        {
            int b = await cursor.NextAsync(ct);
            if (b < 0)
            {
                return null;
            }
            if (b == '\\')
            {
                await cursor.NextAsync(ct); // skip the escaped char
                continue;
            }
            if (b == '"')
            {
                break;
            }
        }

        int c = await SkipWhitespaceAsync(cursor, ct);
        if (c != ':')
        {
            return null;
        }
        long colonEnd = cursor.Position; // just after the ':'

        c = await SkipWhitespaceAsync(cursor, ct);
        if (c != '"')
        {
            // Value is not a string (null / number / object) — treat as missing attachment data.
            return null;
        }
        long contentStart = cursor.Position; // just after the opening quote

        // Find the closing quote, honouring backslash escapes: base64 itself contains no '"',
        // but a producer's JSON encoder may escape the '+' / '/' base64 characters as + /
        // /, so a '\' must never be mistaken for the terminator and its escaped char skipped.
        while (true)
        {
            int b = await cursor.NextAsync(ct);
            if (b < 0)
            {
                return null; // unterminated string
            }
            if (b == '\\')
            {
                await cursor.NextAsync(ct); // skip the escaped indicator char (u/"/\// etc.)
                continue;
            }
            if (b == '"')
            {
                long contentEnd = cursor.Position - 1; // the quote position
                long valueEnd = cursor.Position;       // just after the closing quote
                return new DataValueSpan(colonEnd, contentStart, contentEnd, valueEnd);
            }
        }
    }

    private static async Task<int> SkipWhitespaceAsync(ForwardByteCursor cursor, CancellationToken ct)
    {
        while (true)
        {
            int b = await cursor.NextAsync(ct);
            if (b is not (' ' or '\t' or '\n' or '\r'))
            {
                return b;
            }
        }
    }

    // Streams the string value bytes in [contentStart, contentEnd) from the JSON file, JSON-unescapes
    // them (a producer's encoder may escape the base64 '+'/'/' characters as + / /, or as
    // + /), and base64-decodes the result to `tarballPath` — never holding more than a small chunk
    // in managed memory. Returns the decoded byte count. Throws FormatException on invalid base64.
    private static async Task<long> DecodeBase64RangeToFileAsync(
        FileStream json, long contentStart, long contentEnd, string tarballPath, CancellationToken ct)
    {
        json.Seek(contentStart, SeekOrigin.Begin);
        long remaining = contentEnd - contentStart;

        const int Window = 48 * 1024;
        byte[] raw = ArrayPool<byte>.Shared.Rent(Window);
        // Unescaping never grows the byte count (+ → '+', \/ → '/', …), so a same-sized clean
        // buffer plus room for the ≤3-byte base64 carry is always sufficient.
        byte[] clean = ArrayPool<byte>.Shared.Rent(Window + 8);
        byte[] output = ArrayPool<byte>.Shared.Rent((Window / 4 * 3) + 8);
        byte[] escapeCarry = new byte[8]; // an incomplete escape straddling a chunk boundary
        int escapeCarryLen = 0;
        int b64Carry = 0;                  // < 4 clean base64 bytes not yet decoded (kept at clean[0..])
        long decoded = 0;

        await using var tar = new FileStream(
            tarballPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true);
        try
        {
            while (true)
            {
                int want = (int)Math.Min(Window - escapeCarryLen, remaining);
                int got = 0;
                while (got < want)
                {
                    int n = await json.ReadAsync(raw.AsMemory(got, want - got), ct);
                    if (n == 0)
                    {
                        break;
                    }
                    got += n;
                }
                remaining -= got;
                bool lastChunk = remaining <= 0;

                // Unescape (escapeCarry ++ raw[0..got]) into clean[b64Carry..], leaving any trailing
                // partial escape in escapeCarry for the next iteration.
                int cleanLen = b64Carry;
                // allowIncomplete is true for every non-final chunk: a '\' escape straddling an
                // intermediate decode-window boundary is carried into escapeCarry for the next
                // iteration. Only a partial escape at the final chunk is a genuine truncation error.
                cleanLen = Unescape(escapeCarry, ref escapeCarryLen, raw.AsSpan(0, got), !lastChunk, clean, cleanLen);

                bool finalDecode = lastChunk && escapeCarryLen == 0;
                var status = Base64.DecodeFromUtf8(
                    clean.AsSpan(0, cleanLen), output, out int consumed, out int written, isFinalBlock: finalDecode);
                if (status == OperationStatus.InvalidData)
                {
                    throw new FormatException("Invalid base64.");
                }
                if (written > 0)
                {
                    await tar.WriteAsync(output.AsMemory(0, written), ct);
                    decoded += written;
                }

                b64Carry = cleanLen - consumed;
                if (b64Carry > 0)
                {
                    Array.Copy(clean, consumed, clean, 0, b64Carry);
                }

                if (finalDecode)
                {
                    return status == OperationStatus.NeedMoreData || b64Carry > 0
                        ? throw new FormatException("Truncated base64.")
                        : decoded;
                }
                if (lastChunk && escapeCarryLen != 0)
                {
                    throw new FormatException("Truncated escape in base64 value.");
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(raw);
            ArrayPool<byte>.Shared.Return(clean);
            ArrayPool<byte>.Shared.Return(output);
        }
    }

    // JSON-unescapes a partial-escape carry followed by a chunk into dest starting at destOffset,
    // returning the new dest length. A '\' escape whose bytes are not all present yet is written
    // back into escapeCarry (unless allowIncomplete is false — the final chunk — where it is a
    // FormatException). Only ASCII-range escapes occur in base64 (+, /) but the general
    // \uXXXX / two-char forms are handled for robustness. Allocation-free in the common case
    // (no straddling escape).
    private static int Unescape(
        byte[] escapeCarry, ref int escapeCarryLen, ReadOnlySpan<byte> chunk, bool allowIncomplete,
        byte[] dest, int destOffset)
    {
        int di = destOffset;
        int ci = 0;

        // Complete an escape carried over from the previous chunk boundary.
        if (escapeCarryLen > 0)
        {
            while (!EscapeComplete(escapeCarry.AsSpan(0, escapeCarryLen)) && ci < chunk.Length)
            {
                escapeCarry[escapeCarryLen++] = chunk[ci++];
            }
            if (!EscapeComplete(escapeCarry.AsSpan(0, escapeCarryLen)))
            {
                if (!allowIncomplete) { throw new FormatException("Truncated escape."); }
                return di; // still incomplete: carry preserved, nothing emitted
            }
            di += DecodeEscape(escapeCarry.AsSpan(0, escapeCarryLen), dest, di);
            escapeCarryLen = 0;
        }

        while (ci < chunk.Length)
        {
            byte c = chunk[ci];
            if (c != (byte)'\\')
            {
                dest[di++] = c;
                ci++;
                continue;
            }

            int need = ci + 1 < chunk.Length && chunk[ci + 1] == (byte)'u' ? 6 : 2;
            if (ci + need > chunk.Length)
            {
                // A partial escape at the chunk end — carry it forward.
                if (!allowIncomplete) { throw new FormatException("Truncated escape."); }
                chunk[ci..].CopyTo(escapeCarry);
                escapeCarryLen = chunk.Length - ci;
                break;
            }
            di += DecodeEscape(chunk.Slice(ci, need), dest, di);
            ci += need;
        }
        return di;
    }

    // True when esc holds a complete JSON escape: "\x" (2 bytes) or "\uXXXX" (6 bytes).
    private static bool EscapeComplete(ReadOnlySpan<byte> esc) =>
        esc.Length >= 2 && (esc[1] != (byte)'u' || esc.Length >= 6);

    // Decodes a single complete escape sequence (starting with '\') into dest; returns bytes written.
    private static int DecodeEscape(ReadOnlySpan<byte> esc, byte[] dest, int offset)
    {
        byte ind = esc[1];
        if (ind == (byte)'u')
        {
            int cp = (HexVal(esc[2]) << 12) | (HexVal(esc[3]) << 8) | (HexVal(esc[4]) << 4) | HexVal(esc[5]);
            return WriteUtf8(dest, offset, cp);
        }
        dest[offset] = ind switch
        {
            (byte)'"' => (byte)'"',
            (byte)'\\' => (byte)'\\',
            (byte)'/' => (byte)'/',
            (byte)'b' => 0x08,
            (byte)'f' => 0x0C,
            (byte)'n' => 0x0A,
            (byte)'r' => 0x0D,
            (byte)'t' => 0x09,
            _ => ind,
        };
        return 1;
    }

    private static int HexVal(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - (byte)'0',
        >= (byte)'a' and <= (byte)'f' => b - (byte)'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - (byte)'A' + 10,
        _ => throw new FormatException("Invalid \\u hex digit."),
    };

    private static int WriteUtf8(byte[] dest, int offset, int cp)
    {
        if (cp < 0x80)
        {
            dest[offset] = (byte)cp;
            return 1;
        }
        if (cp < 0x800)
        {
            dest[offset] = (byte)(0xC0 | (cp >> 6));
            dest[offset + 1] = (byte)(0x80 | (cp & 0x3F));
            return 2;
        }
        dest[offset] = (byte)(0xE0 | (cp >> 12));
        dest[offset + 1] = (byte)(0x80 | ((cp >> 6) & 0x3F));
        dest[offset + 2] = (byte)(0x80 | (cp & 0x3F));
        return 3;
    }

    // Builds a small redacted copy of the JSON — everything up to and including the `data` colon,
    // then an empty string in place of the giant value, then everything after the value — and
    // parses it into a JsonNode. The redacted document is tiny (the base64 is excised), so this DOM
    // is safe to hold.
    private static async Task<JsonNode?> ParseRedactedEnvelopeAsync(
        FileStream json, long colonEnd, long valueEnd, CancellationToken ct)
    {
        long fileLen = json.Length;
        using var ms = new MemoryStream();

        json.Seek(0, SeekOrigin.Begin);
        await CopyRangeAsync(json, ms, colonEnd, ct);
        ms.WriteByte((byte)'"');
        ms.WriteByte((byte)'"');
        json.Seek(valueEnd, SeekOrigin.Begin);
        await CopyRangeAsync(json, ms, fileLen - valueEnd, ct);

        ms.Seek(0, SeekOrigin.Begin);
        return JsonNode.Parse(ms);
    }

    private static async Task CopyRangeAsync(FileStream src, Stream dst, long count, CancellationToken ct)
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            long remaining = count;
            while (remaining > 0)
            {
                int want = (int)Math.Min(buf.Length, remaining);
                int n = await src.ReadAsync(buf.AsMemory(0, want), ct);
                if (n == 0)
                {
                    break;
                }
                await dst.WriteAsync(buf.AsMemory(0, n), ct);
                remaining -= n;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    private static void TryDelete(string? path)
    {
        if (path is null)
        {
            return;
        }
        try
        {
            if (File.Exists(path))
            {
                // deepcode ignore PT: path is a "publish-stage-{server-guid}" file under the operator-configured staging root — no user input reaches the path.
                File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup only.
        }
    }

    // Small forward-only byte cursor over a FileStream from a starting offset, with an internal
    // buffer so per-byte scanning of the JSON structure doesn't issue a syscall per byte.
    private sealed class ForwardByteCursor
    {
        private readonly FileStream _stream;
        private readonly long _start;
        private readonly byte[] _buf = new byte[8192];
        private int _len;
        private int _pos;
        private bool _seeked;

        public ForwardByteCursor(FileStream stream, long start)
        {
            _stream = stream;
            _start = start;
            Position = start;
        }

        // Absolute file offset of the NEXT byte to be returned.
        public long Position { get; private set; }

        public async Task<int> NextAsync(CancellationToken ct)
        {
            if (!_seeked)
            {
                _stream.Seek(_start, SeekOrigin.Begin);
                _seeked = true;
            }
            if (_pos >= _len)
            {
                _len = await _stream.ReadAsync(_buf, ct);
                _pos = 0;
                if (_len == 0)
                {
                    return -1;
                }
            }
            Position++;
            return _buf[_pos++];
        }
    }
}
