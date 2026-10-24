using System.Text.Json;

namespace Dependably.Protocol;

/// <summary>
/// The digests an OCI manifest references and must have present before the manifest itself
/// can be accepted (Distribution Spec: a registry MUST verify referenced blobs/manifests
/// exist on <c>PUT .../manifests/...</c>).
///
/// For an image manifest these are the config blob plus every layer blob; for an image index
/// (manifest list) they are the child manifest digests. <see cref="IsIndex"/> distinguishes
/// the two so callers can word errors appropriately.
///
/// <see cref="ConfigDigest"/> carries the image manifest's <c>config.digest</c> (null for an
/// index, which has no config blob) so the license-capture path can locate the config bytes
/// without re-parsing the manifest.
/// </summary>
public sealed record OciManifestReferences(
    IReadOnlyList<string> Digests,
    bool IsIndex,
    string? ConfigDigest = null);

/// <summary>
/// Media types accepted on a manifest push, and a tolerant reader that extracts the set of
/// digests a manifest depends on. Parsing is deliberately permissive about unknown fields
/// (forward-compatibility with newer manifest schemas) but strict about JSON validity.
/// </summary>
public static class OciManifestParser
{
    /// <summary>Manifest + index media types accepted by current Docker and OCI clients.</summary>
    public static readonly IReadOnlySet<string> AcceptedMediaTypes = new HashSet<string>(StringComparer.Ordinal)
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    };

    /// <summary>True when <paramref name="mediaType"/> is a manifest/index type we accept on push.</summary>
    public static bool IsAcceptedMediaType(string? mediaType) =>
        mediaType is not null && AcceptedMediaTypes.Contains(mediaType);

    /// <summary>
    /// The largest blob read back to check whether it is in fact a manifest. Matches the cap on a
    /// pushed manifest body: a real manifest or index is a few kilobytes.
    /// </summary>
    public const long ManifestSniffMaxBytes = 4L * 1024 * 1024;

    /// <summary>
    /// The manifest media type of <paramref name="bytes"/> when they are an image manifest or an
    /// image index whatever label they arrived under, or null when they are not. A manifest is a
    /// JSON object with <c>schemaVersion</c> 2 and either a <c>manifests</c> array (an index) or a
    /// <c>config</c> object with a <c>layers</c> array; a config blob or a layer is neither. The
    /// document's own <c>mediaType</c> wins when it is one this registry accepts.
    /// </summary>
    public static string? SniffManifestMediaType(byte[] bytes) => SniffManifestMediaType(bytes.AsMemory());

    /// <inheritdoc cref="SniffManifestMediaType(byte[])"/>
    public static string? SniffManifestMediaType(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is 0 or > (int)ManifestSniffMaxBytes)
        {
            return null;
        }

        ReadOnlySpan<byte> bom = [0xEF, 0xBB, 0xBF];
        if (bytes.Span.StartsWith(bom))
        {
            bytes = bytes[bom.Length..];
        }

        try
        {
            using var doc = JsonDocument.Parse(bytes);
            return ClassifyManifestRoot(doc.RootElement);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException)
        {
            return null;
        }
    }

    private static string? ClassifyManifestRoot(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("schemaVersion", out var version)
            || version.ValueKind != JsonValueKind.Number || version.GetInt32() != 2)
        {
            return null;
        }

        string? declared = root.TryGetProperty("mediaType", out var mt) && mt.ValueKind == JsonValueKind.String
            ? mt.GetString()
            : null;
        bool isIndex = root.TryGetProperty("manifests", out var manifests) && manifests.ValueKind == JsonValueKind.Array;
        bool isImage = root.TryGetProperty("config", out var config) && config.ValueKind == JsonValueKind.Object
            && root.TryGetProperty("layers", out var layers) && layers.ValueKind == JsonValueKind.Array;
        return !isIndex && !isImage ? null
            : IsAcceptedMediaType(declared) ? declared
            : isIndex ? "application/vnd.oci.image.index.v1+json"
            : "application/vnd.oci.image.manifest.v1+json";
    }

    /// <summary>What the first non-whitespace byte of a document says about whether it is a JSON object.</summary>
    public enum JsonLead
    {
        /// <summary>Nothing but whitespace (and an optional UTF-8 byte-order mark) so far.</summary>
        Undecided,

        /// <summary>The document opens a JSON object.</summary>
        Object,

        /// <summary>The document opens with something other than an object, so it cannot be a manifest.</summary>
        NotObject,
    }

    /// <summary>
    /// Classifies a document by its first non-whitespace byte, so a reader can stop at the first
    /// chunk of a blob that is plainly not JSON (a compressed layer) instead of reading it whole.
    /// </summary>
    public static JsonLead ClassifyLeadingByte(ReadOnlySpan<byte> prefix)
    {
        ReadOnlySpan<byte> bom = [0xEF, 0xBB, 0xBF];
        if (prefix.Length < bom.Length && bom[..prefix.Length].SequenceEqual(prefix))
        {
            return JsonLead.Undecided;
        }

        if (prefix.StartsWith(bom))
        {
            prefix = prefix[bom.Length..];
        }

        foreach (byte b in prefix)
        {
            if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
            {
                continue;
            }

            return b == (byte)'{' ? JsonLead.Object : JsonLead.NotObject;
        }

        return JsonLead.Undecided;
    }

    /// <summary>
    /// Reads <paramref name="stream"/> into memory while it could still be a manifest: it holds no
    /// more than <see cref="ManifestSniffMaxBytes"/>, and its first non-whitespace byte opens a
    /// JSON object. Returns null (with the stream partly consumed) as soon as either is false, so
    /// a compressed layer is read no further than its first chunk. The caller owns the returned
    /// stream, positioned at its start.
    /// </summary>
    public static async Task<MemoryStream?> ReadManifestCandidateAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new MemoryStream();
        byte[] chunk = System.Buffers.ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            bool opensObject = false;
            int read;
            while ((read = await stream.ReadAsync(chunk.AsMemory(0, 81920), ct)) > 0)
            {
                if (buffer.Length + read > ManifestSniffMaxBytes)
                {
                    await buffer.DisposeAsync();
                    return null;
                }

                buffer.Write(chunk, 0, read);
                if (opensObject)
                {
                    continue;
                }

                // Only the bytes before the first non-whitespace one matter, and they are all in
                // the buffer from its start.
                var lead = ClassifyLeadingByte(buffer.GetBuffer().AsSpan(0, (int)buffer.Length));
                if (lead == JsonLead.NotObject)
                {
                    await buffer.DisposeAsync();
                    return null;
                }

                opensObject = lead == JsonLead.Object;
            }

            buffer.Position = 0;
            return buffer;
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(chunk);
        }
    }

    /// <summary>
    /// Extracts the digests an OCI manifest references. Returns null when the bytes are not
    /// valid JSON or the structure is not a recognizable manifest/index (caller maps null to
    /// <c>MANIFEST_INVALID</c>).
    ///
    /// An index is detected by a top-level <c>manifests</c> array; otherwise the document is
    /// treated as an image manifest and the <c>config.digest</c> + each <c>layers[].digest</c>
    /// are collected.
    /// </summary>
    public static OciManifestReferences? ParseReferences(byte[] bytes)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(bytes);
        }
        catch (JsonException)
        {
            return null;
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            // Image index / manifest list: digests live under "manifests".
            if (root.TryGetProperty("manifests", out var manifests) &&
                manifests.ValueKind == JsonValueKind.Array)
            {
                return new OciManifestReferences(CollectDigests(manifests), IsIndex: true);
            }

            // Image manifest: config blob + layer blobs.
            var digests = new List<string>();
            string? configDigest = null;
            if (root.TryGetProperty("config", out var config))
            {
                AddDigest(config, digests);
                if (config.ValueKind == JsonValueKind.Object &&
                    config.TryGetProperty("digest", out var cd) &&
                    cd.ValueKind == JsonValueKind.String)
                {
                    configDigest = cd.GetString();
                }
            }

            if (root.TryGetProperty("layers", out var layers) &&
                layers.ValueKind == JsonValueKind.Array)
            {
                digests.AddRange(CollectDigests(layers));
            }

            // A document with neither config/layers nor a manifests array isn't a manifest
            // we can validate — reject as invalid rather than accept an unverifiable blob.
            return digests.Count == 0
                ? null
                : new OciManifestReferences(digests, IsIndex: false, ConfigDigest: configDigest);
        }
    }

    /// <summary>Collects each well-typed string <c>digest</c> from an array of JSON objects.</summary>
    private static List<string> CollectDigests(JsonElement array)
    {
        var digests = new List<string>();
        foreach (var entry in array.EnumerateArray())
        {
            AddDigest(entry, digests);
        }

        return digests;
    }

    /// <summary>Appends <paramref name="element"/>'s string <c>digest</c> property when present and well-typed.</summary>
    private static void AddDigest(JsonElement element, List<string> digests)
    {
        if (element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty("digest", out var d) &&
            d.ValueKind == JsonValueKind.String)
        {
            digests.Add(d.GetString()!);
        }
    }
}
