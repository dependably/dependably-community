using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Shared constants and small record types used across multiple PyPI handler classes.
/// Extracted so no single handler needs to reference them inline, keeping coupling counts low.
/// </summary>
internal static class PyPiConstants
{
    // PyPI CDN URL layout: sha256[..2] / sha256[2..4] / sha256 / filename.
    internal const int CdnPrefixLength = 2;
    internal const int CdnSecondSegmentStart = 2;
    internal const int CdnSecondSegmentEnd = 4;

    // SHA-256 hex digest prefix length used for ETags (16 hex chars = 64 bits of entropy).
    internal const int ETagHexPrefixLength = 16;

    // Route-level hard ceiling for PyPI uploads (500 MiB).
    internal const long UploadSizeLimitBytes = 500L * 1024 * 1024;

    // TTL for proxy-merged simple indices (upstream can change); local-only indices use a
    // longer TTL because invalidation on mutation is the primary expiry mechanism.
    internal static readonly TimeSpan SimpleIndexProxyTtl = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan SimpleIndexLocalTtl = TimeSpan.FromMinutes(10);

    // Bounded regex evaluation — guards against ReDoS on user-supplied/upstream HTML inputs.
    internal static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);
}

/// <summary>
/// Filename + normalized purl name parsed from a PyPI artifact path segment.
/// </summary>
public sealed record PyPiFilename(string PurlName, string Version);

/// <summary>
/// Tenant + caller context for proxy fetch operations. Carries the OrgId, token attribution,
/// settings snapshot, and source IP so block-gate evaluation at first-fetch can fire without
/// re-reading settings.
/// </summary>
public sealed record ProxyContext(string OrgId, string? UserId, string? ActorKind, OrgSettings Settings, string? SourceIp = null);

/// <summary>
/// Minimal tenant context used by the publish handler to associate a token with a request.
/// SourceIp is resolved from the HttpContext at the call site and carried here so
/// StoreAndRecord can emit the correct IP on the audit row.
/// </summary>
public sealed record ProxyTenantContext(string OrgId, TokenRecord? Token, string? SourceIp = null);

/// <summary>
/// Outcome of a proxy blob fetch: the resolved blob handle and whether it was a cache hit.
/// </summary>
public sealed record PyPiFetchOutcome(BlobHandle Blob, bool IsHit);

/// <summary>
/// Supplementary metadata fetched from the PyPI JSON API on first fetch. All fields are
/// optional — the upstream JSON endpoint is consulted as a best-effort source for
/// published_at, sha256, and the PEP 740 provenance URL when the simple-index fragment is absent.
/// <paramref name="ProvenanceUrl"/> is the file's <c>provenance</c> attribute (a URL to the PEP
/// 740 provenance document carrying the Sigstore attestation bundles); null when the file has none.
/// </summary>
public readonly record struct PyPiJsonMetadata(
    DateTimeOffset? PublishedAt, string? Sha256Hex, string? Deprecated, string? ProvenanceUrl = null)
{
    public static PyPiJsonMetadata Empty => new(null, null, null, null);
}

/// <summary>
/// Coordinates of an artifact staged for upload, passed from the upload handler to
/// StoreAndRecord so the method stays within the S107 parameter limit.
/// </summary>
public sealed record PyPiUpload(
    string Name, string Version, string Filename, string StagingPath, long SizeBytes, string ActualSha256);

/// <summary>
/// Download target for a proxy-fetch call: the resolved upstream URL, the filename,
/// the parsed name/version, the optional upstream SHA-256 fragment, and any locally
/// cached version row (null on a cold miss). Bundled so
/// <see cref="PyPiProxyFetcher.FetchAndCacheUpstreamAsync"/> stays within the S107
/// parameter limit.
/// </summary>
public sealed record PyPiProxyDownload(
    string File,
    string UpstreamUrl,
    string? UpstreamSha256,
    PyPiFilename Parsed,
    (Package Package, PackageVersion Version)? PkgVersions);
