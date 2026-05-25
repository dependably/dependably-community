using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Records a first-fetch proxy version: get-or-create the parent package, create the
/// version row with a content-addressed blob key, emit the <c>first_fetch</c> activity
/// row, and run an ecosystem-specific licence extractor. Wraps the unique-constraint
/// race-handling pattern (concurrent first-fetch already inserted the row → re-read it).
///
/// Each ecosystem controller previously inlined a near-identical copy of this flow
/// (NuGet/PyPi/Npm). The only ecosystem-specific bit is licence extraction, which
/// callers pass in as a delegate.
/// </summary>
public sealed class ProxyVersionRecorder
{
    private readonly PackageRepository _packages;
    private readonly AuditRepository _audit;
    private readonly LicenseRepository _licenses;

    public ProxyVersionRecorder(PackageRepository packages, AuditRepository audit, LicenseRepository licenses)
    {
        _packages = packages;
        _audit = audit;
        _licenses = licenses;
    }

    /// <summary>
    /// Returns the recorded version id (new or existing on race), or null when the
    /// concurrent insert succeeded but its row can't be re-located (rare: package
    /// row was hard-deleted between the unique-constraint catch and the lookup).
    /// </summary>
    public async Task<string?> RecordAsync(
        ProxyVersionRequest req,
        Func<byte[], LicenseExtractor.ExtractedMetadata>? extractLicenses,
        CancellationToken ct = default)
    {
        try
        {
            var pkg = await _packages.GetOrCreateAsync(
                req.OrgId, req.Ecosystem, req.PackageName, req.PurlName, isProxy: true, ct);

            // Proxy DB blob keys embed the filename as a suffix: "proxy/{sha256}/{filename}".
            // The blob *store* key is content-addressed ("proxy/{sha256}"); the filename suffix
            // is metadata-only so the simple index / flatcontainer responses can recover it.
            var dbBlobKey = $"{BlobKeys.Proxy(req.Sha256)}/{req.File}";
            var newVer = await _packages.CreateVersionAsync(
                new NewPackageVersion(pkg.Id, req.Version, req.Purl, dbBlobKey, req.Bytes.Length, req.Sha256,
                    FirstFetch: true, PublishedAt: req.PublishedAt, ChecksumSha1: req.Sha1Hex,
                    UpstreamIntegrityValue: req.UpstreamIntegrityValue,
                    UpstreamIntegrityAlgorithm: req.UpstreamIntegrityAlgorithm),
                ct);
            await _audit.LogActivityAsync(req.OrgId, req.Ecosystem, req.Purl, "first_fetch", req.UserId, sourceIp: req.SourceIp, ct: ct);

            if (extractLicenses is not null)
            {
                var extracted = extractLicenses(req.Bytes);
                if (extracted.Spdx.Count > 0)
                    await _licenses.SetLicensesAsync(newVer.Id, extracted.Spdx, "upstream", ct);
            }

            return newVer.Id;
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            // Concurrent first-fetch already recorded this version — look it up so the
            // caller can still gate / scan against the existing row.
            var pkg = await _packages.GetByPurlNameAsync(req.OrgId, req.Ecosystem, req.PurlName, ct);
            if (pkg is null) return null;
            var existing = await _packages.GetVersionAsync(pkg.Id, req.Version, ct);
            return existing?.Id;
        }
    }
}

/// <summary>
/// Per-fetch context for <see cref="ProxyVersionRecorder.RecordAsync"/>. <c>PackageName</c>
/// is the display name used on creation (NuGet preserves canonical case from the .nuspec);
/// <c>PurlName</c> is the normalised lookup key.
/// </summary>
public sealed record ProxyVersionRequest(
    string OrgId,
    string Ecosystem,
    string PackageName,
    string PurlName,
    string Version,
    string Purl,
    string Sha256,
    string File,
    byte[] Bytes,
    string? UserId,
    string? SourceIp = null,
    /// <summary>
    /// Upstream first-publish timestamp extracted on the cache-miss path (PyPI upload_time,
    /// npm time[version], NuGet catalogEntry.published). Null if the metadata couldn't be
    /// fetched or parsed — capture is fail-soft, never blocks the artefact write.
    /// </summary>
    DateTimeOffset? PublishedAt = null,
    /// <summary>
    /// Hex SHA-1 of the artefact bytes — captured from the upstream npm packument's
    /// <c>dist.shasum</c> so the merged/local-only packument we re-emit later carries the
    /// correct SHA-1. Null outside npm and when upstream didn't supply it.
    /// </summary>
    string? Sha1Hex = null,
    /// <summary>
    /// Upstream-published integrity hash captured verbatim in upstream's native encoding,
    /// surfaced in the UI so operators can cross-check against the public registry's listing.
    /// </summary>
    string? UpstreamIntegrityValue = null,
    string? UpstreamIntegrityAlgorithm = null);
