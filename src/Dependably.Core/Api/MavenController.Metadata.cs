using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Logging;

namespace Dependably.Api;

/// <summary>maven-metadata.xml serving and SNAPSHOT coordinate resolution for <see cref="MavenController"/>.</summary>
public sealed partial class MavenController
{
    // Resolves the SNAPSHOT coordinates to a timestamped filename by fetching the upstream
    // version-level maven-metadata.xml. Prefers the explicit snapshotVersions list (Maven 3);
    // falls back to the top-level timestamp + buildNumber (Maven 2). Returns the original
    // coords unchanged when metadata is unreachable or no timestamped name resolves.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private async Task<MavenCoordinates> ResolveSnapshotCoordsAsync(
        MavenCoordinates coords, string groupPath, IReadOnlyList<UpstreamSource> bases, CancellationToken ct)
    {
        MavenSnapshotMetadata? snapMeta = null;
        foreach (var source in bases)
        {
            snapMeta = await _svc.Upstream!.FetchSnapshotMetadataAsync(
                source.Url, groupPath, coords.ArtifactId, coords.Version!, ct, source.AuthorizationHeader);
            if (snapMeta is not null)
            {
                break;
            }
        }

        if (snapMeta is null || coords.Extension is null)
        {
            return coords;
        }

        // Prefer the explicit snapshotVersions list (Maven 3 metadata).
        string? timestampedValue = snapMeta.ResolveTimestampedValue(coords.Extension, coords.Classifier);
        if (timestampedValue is not null)
        {
            string classifier = coords.Classifier is not null ? $"-{coords.Classifier}" : "";
            string timestampedFilename = $"{coords.ArtifactId}-{timestampedValue}{classifier}.{coords.Extension}";
            return coords with { Filename = timestampedFilename };
        }

        // Fall back to the top-level <snapshot> timestamp + buildNumber (Maven 2 style).
        if (snapMeta.Timestamp is not null && snapMeta.BuildNumber is not null)
        {
            string classifier = coords.Classifier is not null ? $"-{coords.Classifier}" : "";
            string baseVer = coords.Version![..^"-SNAPSHOT".Length];
            string tsFilename = $"{coords.ArtifactId}-{baseVer}-{snapMeta.Timestamp}-{snapMeta.BuildNumber}{classifier}.{coords.Extension}";
            return coords with { Filename = tsFilename };
        }

        return coords;
    }

    /// <summary>
    /// Resolves the current upstream timestamped filename for a literal SNAPSHOT coordinate
    /// (e.g. <c>lib-1.0-SNAPSHOT.jar</c>) by fetching the version-level
    /// <c>maven-metadata.xml</c> from the org's configured upstreams. Returns the resolved
    /// timestamped filename (e.g. <c>lib-1.0-20240101.120000-3.jar</c>), or null when
    /// upstream metadata is unreachable or does not contain a matching entry.
    /// </summary>
    private async Task<string?> ResolveCurrentSnapshotFilenameAsync(
        string orgId, MavenCoordinates coords, CancellationToken ct)
    {
        var bases = await _svc.Registries.ResolveAsync(orgId, "maven", ct);
        if (bases.Count == 0 || coords.Extension is null)
        {
            return null;
        }

        string groupPath = coords.GroupId.Replace('.', '/');
        MavenSnapshotMetadata? snapMeta = null;
        foreach (var source in bases)
        {
            snapMeta = await _svc.Upstream.FetchSnapshotMetadataAsync(
                source.Url, groupPath, coords.ArtifactId, coords.Version!, ct, source.AuthorizationHeader);
            if (snapMeta is not null)
            {
                break;
            }
        }

        if (snapMeta is null)
        {
            return null;
        }

        // Prefer the explicit snapshotVersions list (Maven 3 metadata).
        string? timestampedValue = snapMeta.ResolveTimestampedValue(coords.Extension, coords.Classifier);
        if (timestampedValue is not null)
        {
            string classifierPart = coords.Classifier is not null ? $"-{coords.Classifier}" : "";
            return $"{coords.ArtifactId}-{timestampedValue}{classifierPart}.{coords.Extension}";
        }

        // Fall back to the top-level <snapshot> timestamp + buildNumber (Maven 2 style).
        if (snapMeta.Timestamp is not null && snapMeta.BuildNumber is not null)
        {
            string classifierPart = coords.Classifier is not null ? $"-{coords.Classifier}" : "";
            string baseVer = coords.Version![..^"-SNAPSHOT".Length];
            return $"{coords.ArtifactId}-{baseVer}-{snapMeta.Timestamp}-{snapMeta.BuildNumber}{classifierPart}.{coords.Extension}";
        }

        return null;
    }

    private async Task<IActionResult> ServeMetadataAsync(
        string orgId, MavenCoordinates coords, CancellationToken ct)
    {
        // Version-level SNAPSHOT metadata (g/a/{version}/maven-metadata.xml, coords.Version set
        // and IsSnapshot) is a different document from the artifact-level version list
        // (g/a/maven-metadata.xml) — it carries the <snapshot>/<snapshotVersions> block a
        // client needs to resolve 1.0-SNAPSHOT to the latest timestamped build. It gets its own
        // cache key so the two flavours never collide. A release version-level request keeps
        // the pre-existing (artifact-level) behavior — Maven clients don't fetch that path.
        bool isSnapshotVersionMetadata = coords.Version is not null && coords.IsSnapshot;
        var cacheKey = isSnapshotVersionMetadata
            ? new MavenMetadataKey(orgId, coords.GroupId, coords.ArtifactId, coords.Version)
            : new MavenMetadataKey(orgId, coords.GroupId, coords.ArtifactId);

        // Decide proxy-vs-local up front from the cheap checks: a configured upstream registry
        // and a non-reserved groupId. This drives both the in-memory cache TTL and the HTTP
        // Cache-Control header. On a cache HIT the rebuild below is skipped, so the only work
        // these incur is a registry resolve + reserved-namespace lookup (DB/registry reads,
        // not the upstream HTTP fetch that the cache exists to avoid).
        var bases = await _svc.Registries.ResolveAsync(orgId, "maven", ct);
        bool useUpstream = _svc.Upstream is not null &&
            bases.Count > 0 &&
            !await _svc.ReservedNamespaces.IsReservedAsync(orgId, "maven", coords.GroupId, ct);
        var ttl = useUpstream ? MetadataProxyTtl : MetadataLocalTtl;

        // Both the metadata response and the checksum sidecar must read the SAME rendered bytes —
        // the sidecar hashes the document we serve. Producing the body once through the cache
        // guarantees the .sha1/.md5 can't diverge from the served XML.
        byte[]? bodyBytes = await _svc.MetadataCache.GetOrRebuildAsync(
            cacheKey, ttl,
            rebuildCt => isSnapshotVersionMetadata
                ? BuildMavenSnapshotMetadataBytesAsync(orgId, coords, rebuildCt)
                : BuildMavenMetadataBytesAsync(orgId, coords, bases, useUpstream, rebuildCt),
            ct);

        if (bodyBytes is null)
        {
            return NotFound();
        }

        if (coords.IsChecksumSidecar)
        {
            // Hash the SAME cached bytes the metadata path serves.
            string hex = ComputeHex(coords.ChecksumAlgorithm!, bodyBytes);
            return new ContentResult
            {
                Content = hex,
                ContentType = "text/plain",
                StatusCode = StatusCodes.Status200OK,
            };
        }

        string metaETag = ComputeETagFromBytes(bodyBytes);
        if (Request.Headers.IfNoneMatch.FirstOrDefault() == metaETag)
        {
            Response.Headers.ETag = metaETag;
            return StatusCode(StatusCodes.Status304NotModified);
        }
        Response.Headers.ETag = metaETag;
        // HTTP cache header (distinct from the in-memory TTL): proxy-merged responses may include
        // upstream versions, so a short max-age; local-only responses are stable, so longer.
        Response.Headers.CacheControl = useUpstream
            ? "private, max-age=60"
            : "private, max-age=300";
        return Content(Encoding.UTF8.GetString(bodyBytes), "application/xml", Encoding.UTF8);
    }

    // Builds the version-level maven-metadata.xml bytes for a hosted SNAPSHOT version, so
    // mvn/Gradle can auto-resolve {artifactId}-{version} to the latest timestamped build
    // instead of a literal filename guess. Returns null when no hosted file exists for this
    // version (caller surfaces as 404). Used as the GetOrRebuildAsync factory inside
    // ServeMetadataAsync.
    private async Task<byte[]?> BuildMavenSnapshotMetadataBytesAsync(
        string orgId, MavenCoordinates coords, CancellationToken ct)
    {
        // A SNAPSHOT's per-build timestamp/buildNumber and per-file classifier/extension
        // granularity live only on maven_version_files rows (a hosted publish); proxy-origin
        // SNAPSHOT resolution is served separately by ResolveSnapshotCoordsAsync /
        // ResolveCurrentSnapshotFilenameAsync against the upstream's own metadata document.
        // plane-ok: no cache-plane row shape carries that per-build breakdown to union in here.
        await using var conn = await _svc.Db.OpenAsync(ct);
        var rows = (await conn.QueryAsync<(string Filename, string? Classifier, string Extension, string CreatedAt)>(
            """
            SELECT mvf.filename AS Filename, mvf.classifier AS Classifier,
                   mvf.extension AS Extension, mvf.created_at AS CreatedAt
            FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven' AND p.purl_name = @purlName
              AND pv.version = @version AND mvf.owner_kind = 'package_version'
            ORDER BY mvf.created_at ASC
            """,
            new { orgId, purlName = coords.PackageName, version = coords.Version })).ToList();

        if (rows.Count == 0)
        {
            return null;
        }

        string groupPath = coords.GroupPath;
        var files = new List<MavenSnapshotFile>(rows.Count);
        DateTimeOffset? lastUpdated = null;
        foreach (var (filename, classifier, extension, createdAt) in rows)
        {
            // Reparse the full repository path to recover the deploy timestamp/buildNumber
            // MavenPathParser already knows how to pull out of a timestamped filename — the
            // classifier/extension come straight from the stored columns instead, since those
            // were already validated at publish time.
            var parsed = MavenPathParser.Parse($"{groupPath}/{coords.ArtifactId}/{coords.Version}/{filename}");
            var updated = DateTimeOffset.Parse(
                createdAt, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            if (lastUpdated is null || updated > lastUpdated)
            {
                lastUpdated = updated;
            }

            files.Add(new MavenSnapshotFile(
                classifier, extension,
                parsed?.SnapshotTimestamp, parsed?.SnapshotBuildNumber, updated));
        }

        string body = MavenMetadataBuilder.BuildSnapshotVersion(
            coords.GroupId, coords.ArtifactId, coords.Version!, files, lastUpdated);
        return Encoding.UTF8.GetBytes(body);
    }

    // Builds the maven-metadata.xml bytes from local DB rows merged with upstream versions.
    // Returns null when the version list is empty (caller surfaces as 404).
    // Used as the GetOrRebuildAsync factory inside ServeMetadataAsync.
    private async Task<byte[]?> BuildMavenMetadataBytesAsync(
        string orgId, MavenCoordinates coords, IReadOnlyList<UpstreamSource> bases,
        bool useUpstream, CancellationToken ct)
    {
        // The org can serve a version from either catalogue — a hosted publish in
        // package_versions, or a proxy fetch on the shared cache plane (cache_artifact +
        // tenant_artifact_access), where every current Maven proxy artifact lands. Both are
        // unioned so the document lists every version the org actually serves; reading
        // package_versions alone would drop cached versions whenever proxying is off (reserved
        // groupId / passthrough disabled) or upstream is unreachable and the upstream merge below
        // returns nothing. GROUP BY version collapses a version present on both planes and the
        // several cache rows one Maven version carries (jar, pom, checksum sidecars) into one
        // entry; the representative timestamp is the newest across those rows.
        await using var conn = await _svc.Db.OpenAsync(ct);
        var localRows = (await conn.QueryAsync<(string Version, string CreatedAt)>(
            """
            SELECT version AS Version, MAX(created_at) AS CreatedAt
            FROM (
                SELECT pv.version AS version, pv.created_at AS created_at
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND p.ecosystem = 'maven' AND p.purl_name = @purlName
                UNION ALL
                SELECT ca.version AS version, ca.first_cached_at AS created_at
                FROM cache_artifact ca
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                WHERE taa.org_id = @orgId AND ca.ecosystem = 'maven' AND ca.name = @purlName
            ) v
            GROUP BY version
            ORDER BY MAX(created_at) ASC, version ASC
            """,
            new { orgId, purlName = coords.PackageName })).ToList();

        // created_at alone is not a total order over these rows, so the SQL adds the version
        // text as a tiebreak and the sort below re-breaks those ties under Maven's own version
        // ordering (a SQL text sort ranks 1.10 below 1.9). Ties are the common case rather than
        // an edge case: the cache plane is populated for existing deployments by a single bulk
        // backfill that stamps one shared timestamp into every row it writes, so every proxied
        // version of a coordinate lands on the identical first_cached_at. Without a tiebreak the
        // engine's tie order is unspecified, and a version list that reshuffles between rebuilds
        // takes the content-derived ETag and the .sha1/.md5 sidecars with it. MavenVersionComparer
        // falls back to an ordinal compare for Maven-equal spellings (1.0 vs 1.0.0), which keeps
        // the result a total order and therefore reproducible.
        var ordered = localRows
            .OrderBy(r => r.CreatedAt, StringComparer.Ordinal)
            .ThenBy(r => r.Version, MavenVersionComparer.Instance)
            .ToList();
        var localVersions = ordered.Select(r => r.Version).ToList();

        // lastUpdated comes from the newest local publish, not the wall clock — the metadata
        // body must be byte-stable for a given version set so the ETag honours If-None-Match
        // and the generated checksum sidecars match the document clients fetched. The rows are
        // ordered by created_at first, so the last one carries the newest timestamp.
        DateTimeOffset? lastUpdated = ordered.Count > 0
            ? DateTimeOffset.Parse(
                ordered[^1].CreatedAt, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal)
            : null;

        // Merge upstream versions when proxying is live for this coordinate. An empty
        // registry list (proxying disabled) or a reserved groupId leaves it local-only.
        var mergedVersions = localVersions;
        if (useUpstream)
        {
            string groupPath = coords.GroupId.Replace('.', '/');
            string artifactPath = $"{groupPath}/{coords.ArtifactId}";

            // Walk upstreams in priority order; the first that returns versions wins.
            foreach (var source in bases)
            {
                var upstreamVersions = await _svc.Upstream!.FetchUpstreamVersionsAsync(source.Url, artifactPath, ct, source.AuthorizationHeader);
                if (upstreamVersions is { Count: > 0 })
                {
                    // Union: local wins on collision; preserve order (local first, then upstream-only additions).
                    var localSet = new HashSet<string>(localVersions, StringComparer.OrdinalIgnoreCase);
                    mergedVersions = [.. localVersions, .. upstreamVersions.Where(v => !localSet.Contains(v))];
                    break;
                }
            }
        }

        // Null caches nothing and surfaces as the empty-version-set 404 below.
        if (mergedVersions.Count == 0)
        {
            return null;
        }

        string body = MavenMetadataBuilder.Build(coords.GroupId, coords.ArtifactId, mergedVersions, lastUpdated);
        return Encoding.UTF8.GetBytes(body);
    }
}
