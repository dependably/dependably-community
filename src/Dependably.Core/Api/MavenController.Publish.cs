using System.Text;
using Dapper;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

// The hosted publish path: staging, validating and storing an uploaded file, and the POM
// licence handling that runs alongside it.
public sealed partial class MavenController
{
    // The staged file path is a server-generated GUID under the operator-configured staging root;
    // the request body reaches the file content, not the file name. SCS's taint from Request.Body
    // into staged.Path is a false positive.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "SCS0018",
        Justification = "Staging path is a server-generated GUID under the operator-configured root, not user input.")]
    private async Task<IActionResult> StoreFileAsync(
        string orgId, MavenCoordinates coords, RequestBodyStager.StagedBody staged,
        OrgSettings? settings, TokenRecord token, CancellationToken ct)
    {
        // Sidecar checksums: clients upload them next to the primary. We don't store the
        // sidecar bytes — we accept, validate that the hex matches what we'd compute,
        // and discard. Sidecars are tiny (a hex digest), so reading the staged file back is
        // cheap. This keeps sidecars consistent with the primary artifact in the happy case
        // and rejects a deliberately mismatched upload.
        if (coords.IsChecksumSidecar)
        {
            // staged.Path is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            byte[] sidecarBytes = await System.IO.File.ReadAllBytesAsync(staged.Path, ct);
            return await ValidateAndAcknowledgeSidecarAsync(orgId, coords, sidecarBytes, ct);
        }

        // License hard-block. Maven licenses live only in the .pom, uploaded after the .jar, so
        // a version row may already exist by the time this fires — the "no version row on
        // block" invariant the shared publish pipeline gives every other hosted-push ecosystem
        // is not achievable here. Instead the .pom PUT itself is rejected before it is stored;
        // the serve-path license arm (BlockGateService) then covers the already-stored jar via
        // the shared package_versions row's license entries.
        if (string.Equals(coords.Extension, "pom", StringComparison.OrdinalIgnoreCase)
            && await EvaluateMavenPomLicenseGateAsync(orgId, settings, staged.Path, ct) is { } licenseReject)
        {
            return licenseReject;
        }

        // Name-level publish authorization. Keys on the authenticated token principal (never a
        // request field), so a token holding only publish:maven cannot seize a groupId:artifactId
        // a different principal already owns. No-op unless PUBLISH_NAME_BINDING=on.
        var namePrincipal = Dependably.Infrastructure.NamePrincipal.FromToken(token);
        if (_svc.NameBinding is { } nameGate
            && !await nameGate.IsPublishAuthorizedAsync(orgId, "maven", coords.PackageName, namePrincipal, ct))
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                $"Publishing to '{coords.PackageName}' is not permitted: the name is owned by a " +
                "different principal in this org and you hold no publish grant for it.");
        }

        string purl = PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version!);
        // Digests were computed inline while streaming the body to disk — no re-hash of a
        // fully-buffered artifact.
        string sha256Hex = staged.Sha256;
        string sha1Hex = staged.Sha1!;

        // Content-addressed hosted key: the artefact's SHA-256 (computed inline while the body
        // streamed to the staging file) is a key segment, so the bytes under a key always hash
        // to the digest the key names. Two concurrent publishes of one file coordinate carrying
        // different bytes therefore address disjoint keys and cannot overwrite one another —
        // the (blob_key, checksum_sha256) pair each of package_versions and maven_version_files
        // commits stays true of the stored bytes with no lock and no ordering constraint between
        // the blob write and the metadata write. A republish with different bytes repoints the
        // maven_version_files row at the new key and leaves the superseded blob unreferenced for
        // the orphan reconciler, rather than overwriting bytes a committed row still names.
        // Readers resolve hosted blobs from the stored blob_key (never by rebuilding the
        // coordinate), so rows written under the older coordinate-only key shape keep resolving.
        string blobKey = BlobKeys.HostedArtifact(
            orgId, "maven",
            coords.PackageName.Replace(':', '/'),  // groupId/artifactId in the blob path
            coords.Version!,
            sha256Hex,
            coords.Filename);

        // PackageRepository.GetOrCreateAsync + manual package_versions / maven_version_files
        // because Maven's multi-file shape doesn't fit IPackagePublishService's
        // one-blob-one-version contract. The package_versions row is shared across all
        // files of a version; maven_version_files carries the per-file mapping.
        var pkg = await _svc.Packages.GetOrCreateAsync(orgId, "maven", coords.PackageName, coords.PackageName, isProxy: false, ct);

        // Store the artifact by streaming the staged file into the blob store — the cap was
        // already enforced during staging, so no blob is ever written for an oversize upload.
        // staged.Path is under the operator-configured staging root — no user input reaches the path.
        await using (var artifactStream = new FileStream(
            staged.Path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: true))
        {
            await _svc.Blobs.PutAsync(blobKey, artifactStream, ct);
        }

        await using var conn = await _svc.Db.OpenAsync(ct);

        string versionId = await GetOrCreateVersionRowAsync(
            conn, pkg.Id, coords, purl, blobKey, sha256Hex, sha1Hex, staged.Size);

        await UpsertMavenVersionFileAsync(conn, versionId, coords, blobKey, staged);

        // Record first-publisher ownership now that the artefact and its rows are durably stored
        // (the remaining license-extraction step is best-effort and never fails the publish).
        if (_svc.NameBinding is { } ownerGate)
        {
            await ownerGate.RecordOwnershipAsync(orgId, "maven", coords.PackageName, namePrincipal, ct);
        }

        // Licenses live only in the POM. On a .pom publish, parse the staged bytes and attach
        // the resolved SPDX identifiers to the shared package_versions row so hosted Maven
        // artifacts feed license governance the same way proxied ones do. Extraction failures
        // never fail the publish — the artifact is already stored and the row already written.
        if (string.Equals(coords.Extension, "pom", StringComparison.OrdinalIgnoreCase))
        {
            await ExtractAndAttachPomLicensesAsync(staged.Path, pkg.Id, versionId, purl, ct);
        }

        await _svc.Audit.LogActivityAsync(orgId, "maven", purl, "push",
            actorId: token.AuditActorId, actorKind: token.ActorKind, actorLabel: token.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        EvictMavenMetadataCacheAfterPublish(orgId, coords);

        Response.Headers["X-Dependably-PURL"] = HeaderSanitizer.Sanitize(purl);
        return StatusCode(StatusCodes.Status201Created);
    }

    // Insert / replace the maven_version_files row. ON CONFLICT(package_version_id, filename)
    // WHERE owner_kind='package_version' overwrites so a republished file gets the new hash.
    private static async Task UpsertMavenVersionFileAsync(
        System.Data.Common.DbConnection conn, string versionId, MavenCoordinates coords, string blobKey,
        RequestBodyStager.StagedBody staged)
    {
        // xtenant: keyed by versionId from GetOrCreateVersionRowAsync(pkg.Id, …), and pkg came from
        // GetOrCreateAsync(orgId, …) — the FK chain package_versions → packages carries the org_id.
        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin, owner_kind)
            VALUES (@id, @pvId, @filename, @classifier, @extension, @blobKey, @sizeBytes,
                    @sha256, @sha1, @md5, 'uploaded', 'package_version')
            ON CONFLICT(package_version_id, filename) WHERE owner_kind = 'package_version' DO UPDATE SET
                blob_key = @blobKey,
                size_bytes = @sizeBytes,
                checksum_sha256 = @sha256,
                checksum_sha1 = @sha1,
                checksum_md5 = @md5
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pvId = versionId,
                filename = coords.Filename,
                classifier = coords.Classifier,
                extension = coords.Extension ?? "",
                blobKey,
                sizeBytes = staged.Size,
                sha256 = staged.Sha256,
                sha1 = staged.Sha1,
                md5 = staged.Md5,
            });
    }

    // staged.Path is under the operator-configured staging root — no user input reaches the path.
    // FromPomXml takes ownership of and disposes the stream (class stream-ownership contract).
    private async Task ExtractAndAttachPomLicensesAsync(
        string stagedPath, string packageId, string versionId, string purl, CancellationToken ct)
    {
        try
        {
            var pomStream = new FileStream(
                stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: true);
            var licenses = LicenseExtractor.FromPomXml(pomStream);
            if (licenses.Spdx.Count > 0)
            {
                await _svc.Licenses.SetLicensesAsync(versionId, licenses.Spdx, "upstream", ct);
            }

            // The POM's <url>/<scm><url>/<description> feed the per-tenant packages presentation row.
            await _svc.Packages.UpdateMetadataAsync(
                packageId, licenses.Homepage, licenses.Repository, licenses.Description,
                licenses.Author, ct);
        }
        catch (Exception ex)
        {
            _svc.Log.LogWarning(ex, "Maven POM license extraction failed for {Purl}; publish unaffected.", purl);
        }
    }

    // A real-artifact publish changed this coordinate's version set; invalidate the rendered
    // maven-metadata.xml so a publish-then-resolve sees the new version immediately instead
    // of waiting out the TTL. (The metadata-acknowledge path changes no versions and is
    // handled before StoreFileAsync, so it never reaches here.) A SNAPSHOT publish also names
    // its version so the version-level document goes too — the new file changes the <snapshot>/
    // <snapshotVersions> build list that document reports.
    private void EvictMavenMetadataCacheAfterPublish(string orgId, MavenCoordinates coords)
    {
        _svc.Invalidation.Invalidate(MetadataInvalidation.ForMaven(
            orgId, coords.GroupId, coords.ArtifactId, coords.IsSnapshot ? coords.Version : null));
    }

    /// <summary>
    /// License hard-block for the .pom PUT, governed by the existing
    /// <c>org_settings.license_enforcement_mode</c> ('off'/'warn'/'block'). Parses the staged
    /// POM the same way the post-store license-mirroring step does; a parse failure or a POM
    /// with no license entries fails open (no rejection) — matching the persisted mirroring
    /// step's "extraction failures never fail the publish" contract. Only 'block' can reject.
    /// </summary>
    private async Task<IActionResult?> EvaluateMavenPomLicenseGateAsync(
        string orgId, OrgSettings? settings, string stagedPath, CancellationToken ct)
    {
        if (settings?.LicenseEnforcementMode != "block")
        {
            return null;
        }

        LicenseExtractor.ExtractedMetadata licenses;
        try
        {
            // stagedPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            var pomStream = new FileStream(
                stagedPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, useAsync: true);
            // FromPomXml takes ownership of and disposes the stream (class stream-ownership contract).
            licenses = LicenseExtractor.FromPomXml(pomStream);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _svc.Log.LogWarning(ex, "Maven POM license gate parse failed; publish unaffected.");
            return null;
        }

        if (licenses.Spdx.Count == 0)
        {
            return null;
        }

        var verdict = await _svc.Licenses.CheckPolicyAsync(orgId, "block", licenses.Spdx, ct);
        return verdict.Allowed
            ? null
            : new ObjectResult(new ProblemDetails
            {
                Detail = $"License '{verdict.BlockedLicense}' is not permitted by this org's license policy.",
                Status = StatusCodes.Status403Forbidden,
            })
            { StatusCode = StatusCodes.Status403Forbidden };
    }

    // Get-or-create the shared package_versions row for this coordinate/version: Maven's
    // multi-file shape means the row is shared across every file of a version (the per-file
    // mapping lives in maven_version_files), so a second file of an already-seen version reuses
    // the existing row rather than inserting a duplicate.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Each argument is a distinct coordinate/checksum input for the row upsert; bundling would add no cohesion.")]
    private static async Task<string> GetOrCreateVersionRowAsync(
        System.Data.Common.DbConnection conn, string packageId, MavenCoordinates coords, string purl,
        string blobKey, string sha256Hex, string sha1Hex, long sizeBytes)
    {
        // xtenant: packageId came from GetOrCreateAsync(orgId, ...), so this lookup is keyed
        // by a tenant-scoped FK target. package_versions joins through packages.org_id.
        var (id, _) = await conn.QuerySingleOrDefaultAsync<(string Id, string BlobKey)>(
            "SELECT id AS Id, blob_key AS BlobKey FROM package_versions WHERE package_id = @pkgId AND version = @version",
            new { pkgId = packageId, version = coords.Version });

        if (id is not null)
        {
            return id;
        }

        string versionId = Guid.NewGuid().ToString("N");
        // xtenant: package_id was just obtained via GetOrCreateAsync(orgId,...), so the
        // FK to packages(id) carries the tenant binding. Inserting against that id is
        // implicitly tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, checksum_sha1, origin)
            VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, @sizeBytes, @sha256, @sha1, 'uploaded')
            """,
            new
            {
                id = versionId,
                pkgId = packageId,
                version = coords.Version,
                purl,
                blobKey,
                filename = coords.Filename,
                sizeBytes,
                sha256 = sha256Hex,
                sha1 = sha1Hex,
            });
        return versionId;
    }

    private async Task<IActionResult> ValidateAndAcknowledgeSidecarAsync(
        string orgId, MavenCoordinates coords, byte[] bytes, CancellationToken ct)
    {
        // We don't persist sidecar bytes — they're a function of the primary file's
        // content, which we already store. But we DO sanity-check the hex matches our
        // record so a mismatched sidecar can't pollute the index.
        string primaryFilename = MavenPathParser.PrimaryFilename(coords.Filename);
        await using var conn = await _svc.Db.OpenAsync(ct);
        var (Sha256, Sha1, Md5) = await conn.QuerySingleOrDefaultAsync<(string Sha256, string? Sha1, string? Md5)>(
            // plane-ok: sidecar checksum validation on the hosted PUT/publish path; sidecars exist only for hosted maven_version_files rows.
            """
            SELECT mvf.checksum_sha256 AS Sha256, mvf.checksum_sha1 AS Sha1, mvf.checksum_md5 AS Md5
            FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven'
              AND p.purl_name = @purlName AND pv.version = @version
              AND mvf.filename = @filename
            LIMIT 1
            """,
            new
            {
                orgId,
                purlName = coords.PackageName,
                version = coords.Version,
                filename = primaryFilename,
            });

        if (Sha256 is null)
        {
            // No primary yet — Maven clients usually upload the primary first, but we
            // accept the sidecar order-of-arrival anyway. The next primary upload will
            // compute and store the real checksum; this sidecar is informational only.
            return StatusCode(StatusCodes.Status201Created);
        }

        string uploadedHex = Encoding.UTF8.GetString(bytes).Trim().ToLowerInvariant();
        // Some Maven clients prefix or suffix the hex with garbage; pull out the first
        // continuous hex run.
        string hex = ExtractHex(uploadedHex);
        string? expected = coords.ChecksumAlgorithm switch
        {
            "sha256" => Sha256,
            "sha1" => Sha1,
            "md5" => Md5,
            _ => null,
        };
        return expected is not null && !string.Equals(hex, expected, StringComparison.OrdinalIgnoreCase)
            ? BadRequest("Maven checksum sidecar mismatch.")
            : StatusCode(StatusCodes.Status201Created);
    }

    private async Task<long?> ResolveSizeCapAsync(string orgId, CancellationToken ct)
    {
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        if (settings is null)
        {
            return null;
        }

        // Read max_upload_bytes_maven dynamically because the column was added after the
        // strongly-typed OrgSettings model, which doesn't surface it yet.
        await using var conn = await _svc.Db.OpenAsync(ct);
        long? orgMaven = await conn.ExecuteScalarAsync<long?>(
            "SELECT max_upload_bytes_maven FROM org_settings WHERE org_id = @orgId",
            new { orgId });

        return orgMaven ?? settings.MaxUploadBytes;
    }
}
