using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;

namespace Dependably.Tests.Infrastructure.Seeding;

/// <summary>A finding to seed on a component; the advisory is created on first use.</summary>
public sealed record SeedFinding(
    string OsvId, string Reachability = "unknown", string? Severity = "HIGH", double? CvssScore = 7.5,
    string? NotObservedBasis = null, string? Confidence = null);

/// <summary>A component to seed into a scan result.</summary>
public sealed record SeedComponent(
    string Name,
    int? LayerIndex,
    IReadOnlyList<SeedFinding> Findings,
    string Version = "1.0-1",
    string Ecosystem = "deb",
    string? SourceName = null,
    string? LayerInstruction = null,
    bool? InEntrypointClosure = null,
    string? OwnedByPurl = null);

/// <summary>
/// Seeds OCI images and per-org scan results straight into the tables the scan API writes, so a
/// read test can shape a result (several platforms, many findings, two orgs on one manifest)
/// that the HTTP ingest would take many round trips to build.
/// </summary>
public static class OciScanSeeder
{
    public const string ScannedAt = "2026-06-15T12:00:00.000Z";

    /// <summary>A hosted image: the org's OCI package (created on first use) and a version row.</summary>
    public static async Task<string> HostedImageAsync(IMetadataStore db, string orgId, string repository, string digest)
    {
        string? packageId;
        await using (var conn = await db.OpenAsync())
        {
            packageId = await conn.QueryFirstOrDefaultAsync<string?>(
                "SELECT id FROM packages WHERE org_id = @orgId AND ecosystem = 'oci' AND purl_name = @repository",
                new { orgId, repository });
        }

        packageId ??= await PackageSeeder.InsertAsync(db, orgId, "oci", repository);
        return await PackageSeeder.InsertVersionAsync(
            db, packageId, digest, $"pkg:oci/{repository.Split('/')[^1]}@{Uri.EscapeDataString(digest)}?seed={Guid.NewGuid():N}",
            blobKey: $"oci/sha256/{digest[7..]}");
    }

    /// <summary>A proxied manifest on the shared cache plane, reached by no org yet.</summary>
    public static async Task<string> ProxiedManifestAsync(IMetadataStore db, string repository, string digest)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES (@id, 'oci', @repository, @digest, 'manifest', @blobKey, @digest, 100, @purl)
            """,
            new
            {
                id,
                repository,
                digest,
                blobKey = $"oci/sha256/{digest[7..]}",
                purl = $"pkg:oci/{repository.Split('/')[^1]}@{Uri.EscapeDataString(digest)}",
            });
        return id;
    }

    /// <summary>Records that <paramref name="orgId"/> pulled the proxied manifest.</summary>
    public static async Task GrantAsync(IMetadataStore db, string orgId, string cacheArtifactId)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @cacheArtifactId)",
            new { orgId, cacheArtifactId });
    }

    /// <summary>Marks the org's scanner as having called the scan API at <paramref name="at"/>.</summary>
    public static async Task ScannerSeenAsync(IMetadataStore db, string orgId, DateTimeOffset at)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_scanners (org_id, last_seen_at) VALUES (@orgId, @at)
            ON CONFLICT (org_id) DO UPDATE SET last_seen_at = excluded.last_seen_at
            """,
            new { orgId, at = at.ToUtcIsoMillis() });
    }

    /// <summary>
    /// Records a scanner for the org that called once, a day before <paramref name="now"/>, unless
    /// one is already recorded. Moving OCI scan enforcement off 'off' needs a scanner that has
    /// called at least once; a call a day old is far outside the heartbeat window, so the org
    /// still reads as having no live scanner.
    /// </summary>
    public static async Task StaleScannerAsync(IMetadataStore db, string orgId, DateTimeOffset now)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_scanners (org_id, last_seen_at) VALUES (@orgId, @at)
            ON CONFLICT (org_id) DO NOTHING
            """,
            new { orgId, at = now.AddDays(-1).ToUtcIsoMillis() });
    }

    /// <summary>A scan job row for the image, with a free-text error the read must never return.</summary>
    public static async Task JobAsync(
        IMetadataStore db, string orgId, OciScanOwner owner, string repository, string digest, string state,
        int attempts, string? lastError)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_scan_jobs (
                id, org_id, owner_kind, package_version_id, cache_artifact_id, repository, digest,
                kind, state, attempts, last_error, created_at, updated_at)
            VALUES (
                @id, @orgId, @ownerKind, @pv, @ca, @repository, @digest,
                'scan', @state, @attempts, @lastError, @now, @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                ownerKind = owner.Kind,
                pv = owner.PackageVersionId,
                ca = owner.CacheArtifactId,
                repository,
                digest,
                state,
                attempts,
                lastError,
                now = ScannedAt,
            });
    }

    /// <summary>One platform of the org's result for the image.</summary>
    public static async Task ResultAsync(
        IMetadataStore db, string orgId, OciScanOwner owner, string platform, IReadOnlyList<string> gaps,
        IReadOnlyList<SeedComponent> components)
    {
        foreach (var finding in components.SelectMany(c => c.Findings))
        {
            await AdvisoryAsync(db, finding);
        }

        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_scan_coverage (
                id, org_id, owner_kind, package_version_id, cache_artifact_id, platform, scanner_version,
                extraction_version, osv_source, scanned_at, gaps_json, gap_count, entrypoint_kind, closure_bounded)
            VALUES (@id, @orgId, @ownerKind, @pv, @ca, @platform, '0.3.0', '1', 'remote', @scannedAt,
                    @gapsJson, @gapCount, 'native', 1)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                ownerKind = owner.Kind,
                pv = owner.PackageVersionId,
                ca = owner.CacheArtifactId,
                platform,
                scannedAt = ScannedAt,
                gapsJson = JsonSerializer.Serialize(gaps),
                gapCount = gaps.Count,
            });

        foreach (var c in components)
        {
            string componentId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_image_components (
                    id, org_id, owner_kind, package_version_id, cache_artifact_id, platform, purl, ecosystem,
                    name, version, source_name, source_version, layer_index, layer_diff_id, layer_instruction,
                    in_entrypoint_closure, owned_by_purl)
                VALUES (@id, @orgId, @ownerKind, @pv, @ca, @platform, @purl, @ecosystem,
                        @name, @version, @sourceName, @version, @layerIndex, @diffId, @instruction,
                        @inClosure, @ownedBy)
                """,
                new
                {
                    id = componentId,
                    orgId,
                    ownerKind = owner.Kind,
                    pv = owner.PackageVersionId,
                    ca = owner.CacheArtifactId,
                    platform,
                    purl = $"pkg:{c.Ecosystem}/{c.Name}@{c.Version}",
                    ecosystem = c.Ecosystem,
                    name = c.Name,
                    version = c.Version,
                    sourceName = c.SourceName,
                    layerIndex = c.LayerIndex,
                    diffId = c.LayerIndex is null ? null : $"sha256:{c.LayerIndex.Value:D64}",
                    instruction = c.LayerInstruction,
                    inClosure = c.InEntrypointClosure is null ? (int?)null : c.InEntrypointClosure.Value ? 1 : 0,
                    ownedBy = c.OwnedByPurl,
                });

            foreach (var f in c.Findings)
            {
                await conn.ExecuteAsync(
                    """
                    INSERT INTO oci_component_vulns (
                        id, org_id, component_id, vuln_id, reachability_status, not_observed_basis, confidence)
                    SELECT @id, @orgId, @componentId, v.id, @reachability, @basis, @confidence
                    FROM vulnerabilities v WHERE v.osv_id = @osvId
                    """,
                    new
                    {
                        id = Guid.NewGuid().ToString("N"),
                        orgId,
                        componentId,
                        reachability = f.Reachability,
                        basis = f.NotObservedBasis,
                        confidence = f.Confidence,
                        osvId = f.OsvId,
                    });
            }
        }
    }

    private static async Task AdvisoryAsync(IMetadataStore db, SeedFinding finding)
    {
        await using (var conn = await db.OpenAsync())
        {
            if (await conn.ExecuteScalarAsync<int>(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = finding.OsvId }) > 0)
            {
                return;
            }
        }

        await VulnerabilitySeeder.InsertVulnAsync(
            db, finding.OsvId, ecosystem: "Debian:12", packageName: "openssl", severity: finding.Severity,
            cvssScore: finding.CvssScore, aliases: $"[\"CVE-{finding.OsvId}\"]");
    }

    /// <summary>A proxied manifest row (shared across orgs) and this org's access to it.</summary>
    public static async Task<string> InsertProxiedManifestAsync(
        IMetadataStore db, string orgId, string repository, string digest, string? existingId = null)
    {
        string id = existingId ?? Guid.NewGuid().ToString("N");
        await using var conn = await db.OpenAsync();
        if (existingId is null)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
                VALUES (@id, 'oci', @repository, @digest, 'manifest', @blobKey, @hash, @purl)
                """,
                new
                {
                    id,
                    repository,
                    digest,
                    blobKey = $"proxy/{id}/manifest",
                    hash = new string('a', 64),
                    purl = $"pkg:oci/{repository}@{digest}",
                });
        }

        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @id)",
            new { orgId, id });
        return id;
    }

    /// <summary>
    /// Records <paramref name="orgId"/>'s scan of one image (hosted version or proxied manifest):
    /// one coverage row carrying <paramref name="gaps"/>, plus one matched advisory per entry in
    /// <paramref name="advisoryScores"/>.
    /// </summary>
    public static async Task InsertScanAsync(
        IMetadataStore db, string orgId, string ownerId, bool proxied, int gaps = 0,
        params double[] advisoryScores)
    {
        string ownerKind = proxied ? "cache_artifact" : "package_version";
        string? pv = proxied ? null : ownerId;
        string? ca = proxied ? ownerId : null;
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_scan_coverage (
                    id, org_id, owner_kind, package_version_id, cache_artifact_id, platform, scanner_version,
                    extraction_version, osv_source, scanned_at, gaps_json, gap_count)
                VALUES (@id, @orgId, @ownerKind, @pv, @ca, 'linux/amd64', '1', '1', 'remote', @at, '[]', @gaps)
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId, ownerKind, pv, ca, at = ScannedAt, gaps });
        }

        foreach (double score in advisoryScores)
        {
            string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
                db, "DSA-" + Guid.NewGuid().ToString("N")[..8], ecosystem: "Debian:12",
                packageName: "openssl", severity: "HIGH", cvssScore: score);
            string componentId = Guid.NewGuid().ToString("N");
            await using var conn = await db.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_image_components (
                    id, org_id, owner_kind, package_version_id, cache_artifact_id, platform, purl,
                    ecosystem, name, version)
                VALUES (@componentId, @orgId, @ownerKind, @pv, @ca, 'linux/amd64',
                        @purl, 'deb', 'openssl', '3.0')
                """,
                new { componentId, orgId, ownerKind, pv, ca, purl = "pkg:deb/debian/openssl@" + componentId });
            await conn.ExecuteAsync(
                "INSERT INTO oci_component_vulns (id, org_id, component_id, vuln_id) VALUES (@id, @orgId, @componentId, @vulnId)",
                new { id = Guid.NewGuid().ToString("N"), orgId, componentId, vulnId });
        }
    }
}
