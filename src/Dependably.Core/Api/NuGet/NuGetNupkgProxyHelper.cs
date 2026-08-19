using System.IO.Compression;
using System.Text.Json.Nodes;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Static helpers for the NuGet flatcontainer proxy-fetch path: nupkg ID extraction,
/// first-fetch metadata retrieval, and ProxyFetchRequest construction. Separated from
/// NuGetFlatContainerHandler to bound that handler's coupling count.
/// </summary>
internal static class NuGetNupkgProxyHelper
{
    // Minimum valid NuGet published year: timestamps at or before 1900 are sentinel "unset" values.
    internal const int MinValidPublishedYear = 1901;

    // Reads the canonical-case NuGet ID from the cached blob. Opens one blob-store stream to
    // parse the nuspec inside a .nupkg ZIP, or the nuspec file directly. Falls back to the
    // lowercase URL-derived ID on any error so PURL construction is never blocked on a parse
    // failure of the upstream content.
    internal static async Task<string> ResolveCanonicalNuGetIdFromBlobAsync(
        IBlobStore blobs, string file, string blobKey, string normalizedId, CancellationToken ct)
    {
        try
        {
            await using var stream = await blobs.GetAsync(blobKey, ct);
            if (stream is null)
            {
                return normalizedId;
            }

            string? parsed = await TryParseNuGetIdFromStreamAsync(file, stream, ct);
            return parsed ?? normalizedId;
        }
        catch { /* malformed content — fall back to lowercase */ }

        return normalizedId;
    }

    // Parses the canonical NuGet package ID from the given stream based on the file extension.
    // Returns null when the extension is unrecognised or parsing yields no usable ID.
    private static async Task<string?> TryParseNuGetIdFromStreamAsync(string file, Stream stream, CancellationToken ct)
    {
        if (file.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase))
        {
            var doc = await System.Xml.Linq.XDocument.LoadAsync(stream, System.Xml.Linq.LoadOptions.None, ct);
            string ns = doc.Root?.Name.NamespaceName ?? "";
            System.Xml.Linq.XNamespace xns = ns;
            string? parsedId = doc.Root?.Element(xns + "metadata")?.Element(xns + "id")?.Value?.Trim();
            return string.IsNullOrEmpty(parsedId) ? null : parsedId;
        }

        return file.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase)
            ? await ExtractIdFromNupkgStreamAsync(stream, ct)
            : null;
    }

    // Buffers up to 50 MB of the nupkg stream, opens it as a ZIP, finds the root-level
    // .nuspec entry, and parses the <id> element. Returns null when not found or unparseable.
    private static async Task<string?> ExtractIdFromNupkgStreamAsync(Stream stream, CancellationToken ct)
    {
        // ZipArchive needs a seekable stream, so the blob must be buffered first.
        // Cap at 50 MB to bound the allocation: nupkgs with a nuspec as the first
        // ZIP entry (the common case) parse correctly from a truncated read; packages
        // larger than the cap fall back to the lowercase ID with no functional harm.
        const int maxNupkgBytes = 50 * 1024 * 1024;
        using var ms = new MemoryStream();
        byte[] buf = new byte[81920];
        int totalRead = 0, read;
        while (totalRead < maxNupkgBytes &&
               (read = await stream.ReadAsync(buf.AsMemory(0, Math.Min(buf.Length, maxNupkgBytes - totalRead)), ct)) > 0)
        {
            ms.Write(buf, 0, read);
            totalRead += read;
        }
        ms.Position = 0;
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var nuspecEntry = zip.Entries.FirstOrDefault(e =>
            e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) &&
            !e.FullName.Contains('/'));
        if (nuspecEntry is null)
        {
            return null;
        }
        using var nuspecStream = new LimitedReadStream(
            nuspecEntry.Open(), ZipEntryLimits.MaxMetadataEntryBytes, "nuspec");
        var nuspecDoc = System.Xml.Linq.XDocument.Load(nuspecStream);
        string docNs = nuspecDoc.Root?.Name.NamespaceName ?? "";
        System.Xml.Linq.XNamespace xns2 = docNs;
        string? parsedId = nuspecDoc.Root?.Element(xns2 + "metadata")?.Element(xns2 + "id")?.Value?.Trim();
        return string.IsNullOrEmpty(parsedId) ? null : parsedId;
    }

    /// <summary>
    /// Fetches a single NuGet registration leaf and pulls out everything we capture at
    /// first-fetch: the <c>published</c> timestamp, a SHA-512 verification spec from
    /// <c>packageHash</c> + <c>packageHashAlgorithm</c>, and the raw base64 hash so the UI
    /// can surface what upstream claims. Fail-soft on any error. The unlisted sentinel
    /// (<c>1900-01-01</c>) is coerced to null so callers see "unknown" rather than a
    /// misleading timestamp.
    /// </summary>
    internal static async Task<NuGetFirstFetchMetadata> TryFetchNuGetFirstFetchMetadataAsync(
        UpstreamClient upstream, UpstreamSource upstreamSource, string normalizedId, string normalizedVersion, CancellationToken ct)
    {
        try
        {
            string leafUrl = $"{upstreamSource.Url}/registration5-semver1/{normalizedId}/{normalizedVersion}.json";
            // Route through single-flight — this leaf fetch is called inline with
            // every NuGet first-fetch download, so concurrent fan-out would otherwise
            // stampede the registration URL too.
            var resp = await upstream.GetOrFetchMetadataAsync(leafUrl, upstreamSource.AuthorizationHeader, ct);
            if (!resp.IsSuccessStatusCode)
            {
                return NuGetFirstFetchMetadata.Empty;
            }

            var node = JsonNode.Parse(resp.BodyAsString());

            var publishedAt = ParsePublishedAt(node);

            // packageHash + packageHashAlgorithm live at the leaf root on most NuGet
            // sources; fall back to catalogEntry.* for older feeds that nest them there.
            string? hash = node?["packageHash"]?.GetValue<string>()
                ?? node?["catalogEntry"]?["packageHash"]?.GetValue<string>();
            string? algorithm = node?["packageHashAlgorithm"]?.GetValue<string>()
                ?? node?["catalogEntry"]?["packageHashAlgorithm"]?.GetValue<string>();
            var checksum = ChecksumVerifier.ParseNuGetHash(hash, algorithm);

            // Only surface the raw value when it's the SHA-512-base64 form we recognise —
            // otherwise the UI label would lie about the algorithm. The verification spec
            // above is gated the same way (ParseNuGetHash returns null for non-SHA512).
            string? integrityB64 = !string.IsNullOrEmpty(hash)
                && string.Equals(algorithm, "SHA512", StringComparison.OrdinalIgnoreCase)
                ? hash : null;

            string? deprecated = ParseUnlistedDeprecation(node);

            return new NuGetFirstFetchMetadata(publishedAt, checksum, integrityB64, deprecated);
        }
        catch { return NuGetFirstFetchMetadata.Empty; }
    }

    /// <summary>
    /// Parses NuGet's <c>published</c> timestamp off either the leaf root or, on older feeds,
    /// nested under <c>catalogEntry</c> — the same fallback shape the registration leaf and the
    /// registration index's per-leaf <c>catalogEntry</c> both use. The <c>1900-01-01</c> sentinel
    /// NuGet emits for "no publish timestamp recorded" is coerced to null via
    /// <see cref="MinValidPublishedYear"/>, so an index filter or a first-fetch caller never
    /// treats it as a real timestamp. Shared by <see cref="TryFetchNuGetFirstFetchMetadataAsync"/>
    /// (first-fetch) and the registration-index upstream-leaf gate, so the sentinel handling
    /// cannot drift between the two call sites.
    /// </summary>
    internal static DateTimeOffset? ParsePublishedAt(JsonNode? leafOrCatalogRoot)
    {
        string? published = TryGetString(leafOrCatalogRoot?["published"])
            ?? TryGetString(leafOrCatalogRoot?["catalogEntry"]?["published"]);
        return DateTimeOffset.TryParse(published, null,
                System.Globalization.DateTimeStyles.RoundtripKind, out var ts)
            && ts.Year >= MinValidPublishedYear
            ? ts
            : null;
    }

    /// <summary>
    /// Parses NuGet's <c>listed</c> flag (leaf root or nested under <c>catalogEntry</c>) into the
    /// deprecation reason the block gate's deprecated arm reads. NuGet carries no separate unlist
    /// reason, so <c>listed: false</c> maps to a fixed label rather than an upstream-supplied
    /// string. Shared with <see cref="TryFetchNuGetFirstFetchMetadataAsync"/> for the same reason
    /// as <see cref="ParsePublishedAt"/>.
    /// </summary>
    internal static string? ParseUnlistedDeprecation(JsonNode? leafOrCatalogRoot)
    {
        var listed = leafOrCatalogRoot?["listed"] ?? leafOrCatalogRoot?["catalogEntry"]?["listed"];
        return listed is JsonValue lv && lv.TryGetValue<bool>(out bool listedVal) && !listedVal
            ? "Unlisted upstream"
            : null;
    }

    // Reads a string member of a JsonNode, or null when absent or not a JSON string — upstream
    // JSON is untrusted input, so a wrong-typed member degrades a single field rather than
    // throwing out of the whole parse.
    private static string? TryGetString(JsonNode? node) =>
        node is JsonValue jv && jv.TryGetValue<string>(out string? s) ? s : null;

    // Builds the ProxyFetchRequest record for a NuGet package, including integrity metadata
    // from the upstream registration leaf. The license extractor branches on file extension:
    // .nupkg files contain a nuspec; other sidecar files (e.g. .snupkg) carry no license data.
    // The parameters are the assembly inputs of the ProxyFetchRequest record; grouping them
    // into an intermediate carrier would add indirection without cohesion.
#pragma warning disable S107
    internal static ProxyFetchRequest BuildNuGetProxyFetchRequest(
        string orgId, string normalizedId, string normalizedVersion, string purl,
        string file, BlobHandle blob, string upstreamBase,
        TokenRecord? token, OrgSettings settings, NuGetFirstFetchMetadata meta,
        string? sourceIp, Dependably.Protocol.Provenance.ProvenanceResult prov)
#pragma warning restore S107
    {
        return new ProxyFetchRequest(
            OrgId: orgId, Ecosystem: "nuget",
            PackageName: normalizedId, PurlName: normalizedId,
            Version: normalizedVersion, Purl: purl, File: file, Blob: blob,
            ExtractLicenses: stream => file.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase)
                ? LicenseExtractor.FromNuspec(stream)
                : LicenseExtractor.ExtractedMetadata.Empty,
            AuditActorId: token?.AuditActorId, AuditActorLabel: token?.AuditActorLabel,
            ActorKind: token?.ActorKind,
            SourceIp: sourceIp,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            CacheAccess: new CacheAccess(orgId, "nuget", normalizedId, normalizedVersion, file,
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: $"{upstreamBase}/flatcontainer/{normalizedId}/{normalizedVersion}/{file}",
                // ProxyFetchService overwrites the three bytes fields with the values it computed
                // over the package it just staged before handing this to the recorder.
                Origin: CacheAccessOrigin.FirstFetch),
            UpstreamUrl: upstreamBase,
            PublishedAt: meta.PublishedAt,
            UpstreamChecksum: meta.Checksum,
            UpstreamIntegrityValue: meta.IntegrityBase64,
            UpstreamIntegrityAlgorithm: meta.IntegrityBase64 is not null ? "sha512-b64" : null,
            Deprecated: meta.Deprecated,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            BlockRevokedMode: settings.BlockRevoked,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            ProvenanceStatus: Dependably.Protocol.Provenance.ProvenanceStatuses.ToColumn(prov.Status),
            ProvenanceSigner: prov.Signer,
            VerifyProvenanceMode: settings.VerifyNuGetSignatures,
            LicenseEnforcementMode: settings.LicenseEnforcementMode);
    }
}

// Carries the metadata harvested from the upstream registration leaf during a NuGet first-fetch.
// All fields are nullable so callers see "unknown" rather than a misleading default when the
// upstream leaf is absent or unparseable.
internal readonly record struct NuGetFirstFetchMetadata(
    DateTimeOffset? PublishedAt,
    ChecksumSpec? Checksum,
    string? IntegrityBase64,
    string? Deprecated)
{
    internal static NuGetFirstFetchMetadata Empty => new(null, null, null, null);
}
