using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The management lookups that resolve a proxied version by the version string the operator typed.
/// For an ecosystem whose versions are case-sensitive, two proxied versions that differ only in
/// case are two coordinates, and an action on one must never reach the other.
/// </summary>
[Trait("Category", "Unit")]
public sealed class VersionCaseIdentityControllerTests
{
    private const string Name = "case-pkg";
    private const string Upper = "1.0.0-RC1";
    private const string Lower = "1.0.0-rc1";

    // The lowercase version is cached later, so a case-folding first-match lookup that is asked for
    // the uppercase one returns the lowercase row first (ListServeFactsForNameAsync orders newest
    // first).
    private static async Task<(CacheArtifact Upper, CacheArtifact Lower)> SeedPairAsync(
        ControllerScenarioResult b, string ecosystem = "npm")
    {
        var older = new DateTimeOffset(2026, 6, 1, 10, 0, 0, TimeSpan.Zero);
        var newer = new DateTimeOffset(2026, 6, 1, 11, 0, 0, TimeSpan.Zero);
        var upper = await SeedAsync(b, ecosystem, Upper, older);
        var lower = await SeedAsync(b, ecosystem, Lower, newer);
        return (upper, lower);
    }

    private static async Task<CacheArtifact> SeedAsync(
        ControllerScenarioResult b, string ecosystem, string version, DateTimeOffset cachedAt)
    {
        var artifact = await b.CacheArtifacts.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = ecosystem,
            Name = Name,
            Version = version,
            Filename = $"{Name}-{version}.tgz",
            BlobKey = $"proxy/{Guid.NewGuid():N}",
            ContentHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
            SizeBytes = 3,
            FirstCachedAt = cachedAt,
            LastAccessedAt = cachedAt,
        });
        await b.TenantAccess.UpsertAsync(b.PrimaryOrgId, artifact.Id, cachedAt, TenantContentBinding.None);
        await b.CacheBlobs.PutAsync(BlobKeys.StoreKey(artifact.BlobKey), new MemoryStream([1, 2, 3]), default);
        return artifact;
    }

    private static async Task<string?> ManualBlockStateAsync(ControllerScenarioResult b, string version)
    {
        await using var conn = await b.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT taa.manual_block_state FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'npm' AND ca.name = @name AND ca.version = @version
            """,
            new { orgId = b.PrimaryOrgId, name = Name, version });
    }

    private static async Task<long> AccessRowsAsync(ControllerScenarioResult b, string version)
    {
        await using var conn = await b.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.name = @name AND ca.version = @version
            """,
            new { orgId = b.PrimaryOrgId, name = Name, version });
    }

    private static async Task<ControllerScenarioResult> BuildAsync(ControllerScenario s, string ecosystem = "npm")
    {
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync(Name, ecosystem: ecosystem, isProxy: true);
        return await s.BuildAsync();
    }

    [Fact]
    public async Task DeleteVersion_NpmCasePair_RemovesOnlyTheExactVersion()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildAsync(s);
        await SeedPairAsync(b);

        Assert.IsType<NoContentResult>(
            await b.OrgController.DeleteVersion("npm", Name, Upper, CancellationToken.None));

        Assert.Equal(0, await AccessRowsAsync(b, Upper));
        Assert.Equal(1, await AccessRowsAsync(b, Lower));
    }

    [Fact]
    public async Task DeleteVersion_NuGetCasePair_FoldsCase()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildAsync(s, "nuget");
        await SeedPairAsync(b, "nuget");

        Assert.IsType<NoContentResult>(
            await b.OrgController.DeleteVersion("nuget", Name, "1.0.0-Rc1", CancellationToken.None));
    }

    [Fact]
    public async Task DownloadVersion_NpmCasePair_ServesTheExactVersion()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildAsync(s);
        await SeedPairAsync(b);

        var file = Assert.IsType<FileStreamResult>(
            await b.OrgController.DownloadVersion("npm", Name, Upper, CancellationToken.None));

        Assert.Equal($"{Name}-{Upper}.tgz", file.FileDownloadName);
        await file.FileStream.DisposeAsync();
    }

    [Fact]
    public async Task BlockVersion_NpmCasePair_FlipsOnlyTheExactVersion()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildAsync(s);
        await SeedPairAsync(b);

        Assert.IsType<OkObjectResult>(
            await b.VulnerabilityController.BlockVersion("npm", Name, Upper, CancellationToken.None));

        Assert.Equal("blocked", await ManualBlockStateAsync(b, Upper));
        Assert.Null(await ManualBlockStateAsync(b, Lower));
    }

    [Fact]
    public async Task QuarantineDeny_NpmCasePair_BlocksOnlyTheExactVersion()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildAsync(s);
        await SeedPairAsync(b);

        var quarantine = new QuarantineRepository(b.Db, s.Clock);
        var upserted = await quarantine.UpsertPendingAsync(
            b.PrimaryOrgId, "npm", $"pkg:npm/{Name}@{Upper}", "malicious", detail: null, packageVersionId: null);

        Assert.IsType<OkObjectResult>(
            await b.QuarantineController.Decide(upserted.RowId, new QuarantineDecisionRequest("denied")));

        Assert.Equal("blocked", await ManualBlockStateAsync(b, Upper));
        Assert.Null(await ManualBlockStateAsync(b, Lower));
    }
}
