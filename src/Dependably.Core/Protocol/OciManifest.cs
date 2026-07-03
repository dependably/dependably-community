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
/// </summary>
public sealed record OciManifestReferences(IReadOnlyList<string> Digests, bool IsIndex);

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
            if (root.TryGetProperty("config", out var config))
            {
                AddDigest(config, digests);
            }

            if (root.TryGetProperty("layers", out var layers) &&
                layers.ValueKind == JsonValueKind.Array)
            {
                digests.AddRange(CollectDigests(layers));
            }

            // A document with neither config/layers nor a manifests array isn't a manifest
            // we can validate — reject as invalid rather than accept an unverifiable blob.
            return digests.Count == 0 ? null : new OciManifestReferences(digests, IsIndex: false);
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
