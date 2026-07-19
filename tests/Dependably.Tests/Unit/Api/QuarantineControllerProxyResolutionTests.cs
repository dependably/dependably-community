using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Regression coverage for the bug where an approved/denied version-less (proxy) quarantine
/// entry never wrote any override: <see cref="Dependably.Api.QuarantineController.Decide"/>
/// only dispatched to <c>PackageRepository.SetManualBlockStateAsync</c> when
/// <c>entry.PackageVersionId</c> was set, and proxy quarantine rows always carry a NULL
/// <c>package_version_id</c> (no <c>package_versions</c> row exists for them). An approved
/// proxy artifact therefore kept 403ing forever on the cache-hit serve gate, which reads
/// <c>tenant_artifact_access.manual_block_state</c>.
///
/// These tests fail on pre-fix code (the override column stays NULL after the decision) and
/// pass once <see cref="Dependably.Api.QuarantineController"/> resolves the entry's purl against
/// the cache plane and writes through <see cref="TenantArtifactAccessRepository.SetManualBlockStateAsync"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class QuarantineControllerProxyResolutionTests
{
    /// <summary>Seeds a cache_artifact + tenant_artifact_access row, simulating a version that
    /// has only ever been proxy-fetched (never hosted-pushed, so no package_versions row).</summary>
    private static async Task<CacheArtifact> SeedProxyArtifactAsync(
        ControllerScenarioResult b, string orgId, string name, string version, DateTimeOffset now)
    {
        var artifact = await b.CacheArtifacts.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = name,
            Version = version,
            Filename = $"{name}-{version}.tgz",
            BlobKey = $"cache/npm/{name}/{version}",
            ContentHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
            SizeBytes = 1024,
            FirstCachedAt = now,
            LastAccessedAt = now,
        });
        await b.TenantAccess.UpsertAsync(orgId, artifact.Id, now);
        return artifact;
    }

    private static async Task<string?> ReadManualBlockStateAsync(
        ControllerScenarioResult b, string orgId, string name, string version)
    {
        await using var conn = await b.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT taa.manual_block_state FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'npm' AND ca.name = @name AND ca.version = @version
            """,
            new { orgId, name, version });
    }

    [Fact]
    public async Task Decide_Approved_VersionlessProxyEntry_ClearsCacheHitBlock()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string name = "quarantine-proxy-approve";
        string version = "1.0.0";
        string purl = $"pkg:npm/{name}@{version}";
        await SeedProxyArtifactAsync(b, b.PrimaryOrgId, name, version, s.Clock.GetUtcNow());

        var quarantine = new QuarantineRepository(b.Db, s.Clock);
        // Version-less pending row — the shape a proxy first-fetch block writes:
        // package_version_id is NULL because no package_versions row exists for this coordinate.
        var upserted = await quarantine.UpsertPendingAsync(
            b.PrimaryOrgId, "npm", purl, "malicious", detail: null, packageVersionId: null);

        var result = await b.QuarantineController.Decide(
            upserted.RowId, new QuarantineDecisionRequest("approved"));
        Assert.IsType<OkObjectResult>(result);

        // Pre-fix: this stays NULL forever — the cache-hit serve gate keeps 403ing the artifact
        // even though an admin explicitly approved it.
        Assert.Equal("allowed", await ReadManualBlockStateAsync(b, b.PrimaryOrgId, name, version));
    }

    [Fact]
    public async Task Decide_Denied_VersionlessProxyEntry_SetsBlockedOverride()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string name = "quarantine-proxy-deny";
        string version = "1.0.0";
        string purl = $"pkg:npm/{name}@{version}";
        await SeedProxyArtifactAsync(b, b.PrimaryOrgId, name, version, s.Clock.GetUtcNow());

        var quarantine = new QuarantineRepository(b.Db, s.Clock);
        var upserted = await quarantine.UpsertPendingAsync(
            b.PrimaryOrgId, "npm", purl, "malicious", detail: null, packageVersionId: null);

        var result = await b.QuarantineController.Decide(
            upserted.RowId, new QuarantineDecisionRequest("denied"));
        Assert.IsType<OkObjectResult>(result);

        Assert.Equal("blocked", await ReadManualBlockStateAsync(b, b.PrimaryOrgId, name, version));
    }

    [Fact]
    public async Task Decide_Reset_VersionlessProxyEntry_ClearsOverride()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string name = "quarantine-proxy-reset";
        string version = "1.0.0";
        string purl = $"pkg:npm/{name}@{version}";
        await SeedProxyArtifactAsync(b, b.PrimaryOrgId, name, version, s.Clock.GetUtcNow());

        var quarantine = new QuarantineRepository(b.Db, s.Clock);
        var upserted = await quarantine.UpsertPendingAsync(
            b.PrimaryOrgId, "npm", purl, "malicious", detail: null, packageVersionId: null);

        Assert.IsType<OkObjectResult>(
            await b.QuarantineController.Decide(upserted.RowId, new QuarantineDecisionRequest("approved")));
        Assert.Equal("allowed", await ReadManualBlockStateAsync(b, b.PrimaryOrgId, name, version));

        var reset = await b.QuarantineController.Decide(
            upserted.RowId, new QuarantineDecisionRequest("pending"));
        Assert.IsType<OkObjectResult>(reset);

        Assert.Null(await ReadManualBlockStateAsync(b, b.PrimaryOrgId, name, version));
    }
}
