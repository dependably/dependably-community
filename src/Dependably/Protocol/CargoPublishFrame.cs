using System.Buffers.Binary;
using System.Text.Json;

namespace Dependably.Protocol;

/// <summary>
/// Parser for the Cargo <c>PUT /api/v1/crates/new</c> request frame. The body is a binary
/// envelope, not multipart: a little-endian <c>u32</c> JSON-metadata length, the JSON
/// metadata bytes, a little-endian <c>u32</c> <c>.crate</c> length, then the <c>.crate</c>
/// bytes. See the Cargo registry web API specification.
///
/// The two-stage <see cref="ReadHeader"/> / <see cref="SliceCrate"/> split lets the caller
/// validate the declared crate length against the upload size cap <em>before</em> the crate
/// bytes are touched, so an oversized declared length is rejected without buffering the
/// payload.
/// </summary>
public static class CargoPublishFrame
{
    // Byte length of the little-endian u32 length prefix used in the Cargo publish frame.
    private const int LengthPrefixBytes = sizeof(uint);
    /// <summary>Outcome codes for frame parsing, mapped to HTTP status by the controller.</summary>
    public enum FrameError
    {
        None = 0,

        /// <summary>The buffer is too short to contain a declared length prefix or its payload.</summary>
        Truncated,

        /// <summary>A declared length is implausibly large (overflows the remaining buffer).</summary>
        LengthOverflow,

        /// <summary>The metadata segment is not valid JSON or is missing required fields.</summary>
        InvalidMetadata,
    }

    /// <summary>
    /// The parsed frame header: the decoded metadata and the byte range of the <c>.crate</c>
    /// payload within the original buffer. <see cref="CrateLength"/> is the declared crate
    /// length; <see cref="CrateOffset"/> is where the crate bytes begin.
    /// </summary>
    public sealed record Header(CargoPublishMetadata Metadata, int CrateOffset, int CrateLength);

    /// <summary>
    /// Reads the metadata segment and the crate length prefix from the front of the frame,
    /// without copying the crate bytes. Validates every length against the buffer extent so a
    /// malformed or hostile prefix can never drive an out-of-range slice. Returns
    /// <see cref="FrameError.None"/> and a non-null <see cref="Header"/> on success.
    /// </summary>
    public static (FrameError Error, Header? Header) ReadHeader(ReadOnlySpan<byte> body)
    {
        // LengthPrefixBytes-byte metadata length prefix.
        if (body.Length < LengthPrefixBytes)
        {
            return (FrameError.Truncated, null);
        }
        uint metaLen = BinaryPrimitives.ReadUInt32LittleEndian(body);

        // metaLen must fit in the buffer after its own prefix, with room for the crate prefix.
        // The cast to long avoids uint→int overflow on a hostile length.
        long metaEnd = (long)LengthPrefixBytes + metaLen;
        if (metaLen > int.MaxValue || metaEnd + LengthPrefixBytes > body.Length)
        {
            return metaLen > int.MaxValue || metaEnd > body.Length
                ? (FrameError.LengthOverflow, null)
                : (FrameError.Truncated, null);
        }

        var metaBytes = body.Slice(LengthPrefixBytes, (int)metaLen);
        var metadata = ParseMetadata(metaBytes);
        if (metadata is null)
        {
            return (FrameError.InvalidMetadata, null);
        }

        // LengthPrefixBytes-byte crate length prefix immediately after the metadata.
        int cratePrefixOffset = (int)metaEnd;
        uint crateLen = BinaryPrimitives.ReadUInt32LittleEndian(body[cratePrefixOffset..]);
        int crateOffset = cratePrefixOffset + LengthPrefixBytes;

        // The declared crate length must not run past the buffer. A length that overflows is
        // reported as LengthOverflow so the caller returns 400 rather than a generic truncation.
        if (crateLen > int.MaxValue || crateOffset + (long)crateLen > body.Length)
        {
            return (FrameError.LengthOverflow, null);
        }

        return (FrameError.None, new Header(metadata, crateOffset, (int)crateLen));
    }

    /// <summary>
    /// Extracts the <c>.crate</c> bytes for a header already validated by
    /// <see cref="ReadHeader"/>. The slice bounds were range-checked there, so this copy is
    /// always in-range.
    /// </summary>
    public static byte[] SliceCrate(ReadOnlySpan<byte> body, Header header)
        => body.Slice(header.CrateOffset, header.CrateLength).ToArray();

    private static CargoPublishMetadata? ParseMetadata(ReadOnlySpan<byte> metaBytes)
    {
        try
        {
            var meta = JsonSerializer.Deserialize<CargoPublishMetadata>(metaBytes,
                CargoPublishJsonContext.Options);
            return meta is null || string.IsNullOrWhiteSpace(meta.Name) || string.IsNullOrWhiteSpace(meta.Vers)
                ? null
                : meta;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
