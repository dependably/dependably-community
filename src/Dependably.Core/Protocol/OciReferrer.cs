using System.Text.Json;

namespace Dependably.Protocol;

/// <summary>
/// Descriptor for a manifest that references a subject digest, as returned by
/// the OCI 1.1 Referrers API (<c>GET /v2/{name}/referrers/{digest}</c>).
/// </summary>
public sealed record OciReferrerDescriptor(
    string MediaType,
    string Digest,
    long SizeBytes,
    string? ArtifactType,
    IReadOnlyDictionary<string, string>? Annotations);

/// <summary>
/// Parses a stored OCI manifest blob to determine whether it is a referrer of a given
/// subject digest, and extracts the descriptor fields needed for the Referrers API response.
///
/// The OCI 1.1 spec defines a referrer as a manifest with a <c>subject</c> field whose
/// <c>digest</c> matches the queried digest. <c>artifactType</c> is taken from the
/// manifest's top-level <c>artifactType</c> field if present, falling back to
/// <c>config.mediaType</c> for OCI image manifests.
/// </summary>
public static class OciReferrerParser
{
    /// <summary>
    /// Tries to parse <paramref name="manifestBytes"/> as an OCI manifest with a
    /// <c>subject.digest</c> equal to <paramref name="subjectDigest"/>.
    ///
    /// Returns a populated <see cref="OciReferrerDescriptor"/> when the manifest is a
    /// referrer of the requested subject, or null otherwise (including malformed JSON,
    /// missing subject field, or non-matching subject digest).
    /// </summary>
    public static OciReferrerDescriptor? TryParseReferrer(
        byte[] manifestBytes,
        string candidateDigest,
        string mediaType,
        long sizeBytes,
        string subjectDigest)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(manifestBytes);
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

            // Must have subject.digest matching the requested digest.
            if (!root.TryGetProperty("subject", out var subject) ||
                subject.ValueKind != JsonValueKind.Object ||
                !subject.TryGetProperty("digest", out var subjDigest) ||
                subjDigest.ValueKind != JsonValueKind.String ||
                !string.Equals(subjDigest.GetString(), subjectDigest, StringComparison.Ordinal))
            {
                return null;
            }

            // artifactType: prefer top-level field (OCI 1.1 artifact manifests), fall back
            // to config.mediaType (OCI image manifests used as referrers).
            string? artifactType = null;
            if (root.TryGetProperty("artifactType", out var at) && at.ValueKind == JsonValueKind.String)
            {
                artifactType = at.GetString();
            }
            else if (root.TryGetProperty("config", out var config) &&
                     config.ValueKind == JsonValueKind.Object &&
                     config.TryGetProperty("mediaType", out var configMt) &&
                     configMt.ValueKind == JsonValueKind.String)
            {
                artifactType = configMt.GetString();
            }

            // annotations: optional top-level object.
            Dictionary<string, string>? annotations = null;
            if (root.TryGetProperty("annotations", out var annots) &&
                annots.ValueKind == JsonValueKind.Object)
            {
                annotations = [];
                foreach (var prop in annots.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.String)
                    {
                        annotations[prop.Name] = prop.Value.GetString()!;
                    }
                }
            }

            return new OciReferrerDescriptor(mediaType, candidateDigest, sizeBytes, artifactType, annotations);
        }
    }
}
