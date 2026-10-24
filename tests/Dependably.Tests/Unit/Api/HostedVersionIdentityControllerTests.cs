using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The management lookups that take a version from the route resolve the uploaded row through the
/// ecosystem's version identity, the same rule the proxied plane applies. A respelled version
/// (PEP 440 for PyPI, case for NuGet) must act on the uploaded release, never fall through to a
/// proxied row that happens to match, and a genuinely different version must cross-match nothing.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HostedVersionIdentityControllerTests
{
    private const string Name = "ident-pkg";

    private static async Task<ControllerScenarioResult> BuildAsync(
        string ecosystem, string uploadedVersion, string? extraUploadedVersion = null)
    {
        var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync(Name, ecosystem: ecosystem, isProxy: true);
        await s.WithPackageVersionAsync(Name, uploadedVersion, ecosystem);
        if (extraUploadedVersion is not null)
        {
            await s.WithPackageVersionAsync(Name, extraUploadedVersion, ecosystem);
        }

        var built = await s.BuildAsync();
        return built;
    }

    private static async Task SeedProxiedAsync(ControllerScenarioResult b, string ecosystem, string version)
    {
        var at = new DateTimeOffset(2026, 6, 1, 10, 0, 0, TimeSpan.Zero);
        var artifact = await b.CacheArtifacts.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = ecosystem,
            Name = Name,
            Version = version,
            Filename = $"{Name}-{version}.whl",
            BlobKey = $"proxy/{Guid.NewGuid():N}",
            ContentHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
            SizeBytes = 3,
            FirstCachedAt = at,
            LastAccessedAt = at,
        });
        await b.TenantAccess.UpsertAsync(b.PrimaryOrgId, artifact.Id, at, TenantContentBinding.None);
        await b.CacheBlobs.PutAsync(BlobKeys.StoreKey(artifact.BlobKey), new MemoryStream([1, 2, 3]), default);
    }

    private static async Task<long> UploadedRowsAsync(ControllerScenarioResult b, string ecosystem, string version)
    {
        await using var conn = await b.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = @ecosystem AND p.name = @name AND pv.version = @version
            """,
            new { orgId = b.PrimaryOrgId, ecosystem, name = Name, version });
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

    private static async Task<string?> UploadedBlockStateAsync(ControllerScenarioResult b, string ecosystem, string version)
    {
        await using var conn = await b.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pv.manual_block_state FROM package_versions pv JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = @ecosystem AND p.name = @name AND pv.version = @version
            """,
            new { orgId = b.PrimaryOrgId, ecosystem, name = Name, version });
    }

    private static async Task<string?> ProxiedBlockStateAsync(ControllerScenarioResult b, string version)
    {
        await using var conn = await b.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT taa.manual_block_state FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.name = @name AND ca.version = @version
            """,
            new { orgId = b.PrimaryOrgId, name = Name, version });
    }

    [Fact]
    public async Task DeleteVersion_PyPiRespelledRoute_RemovesTheUploadedRelease_NotTheProxiedFile()
    {
        var b = await BuildAsync("pypi", "1.0.0rc1");
        await SeedProxiedAsync(b, "pypi", "1.0.0-rc1");

        Assert.IsType<NoContentResult>(
            await b.OrgController.DeleteVersion("pypi", Name, "1.0.0-rc1", CancellationToken.None));

        Assert.Equal(0, await UploadedRowsAsync(b, "pypi", "1.0.0rc1"));
        Assert.Equal(1, await AccessRowsAsync(b, "1.0.0-rc1"));
    }

    [Fact]
    public async Task DeleteVersion_NuGetMixedCaseRoute_RemovesTheUploadedRelease_NotTheProxiedFile()
    {
        var b = await BuildAsync("nuget", "1.0.0-rc1");
        await SeedProxiedAsync(b, "nuget", "1.0.0-Rc1");

        Assert.IsType<NoContentResult>(
            await b.OrgController.DeleteVersion("nuget", Name, "1.0.0-RC1", CancellationToken.None));

        Assert.Equal(0, await UploadedRowsAsync(b, "nuget", "1.0.0-rc1"));
        Assert.Equal(1, await AccessRowsAsync(b, "1.0.0-Rc1"));
    }

    [Fact]
    public async Task DeleteVersion_PyPiDifferentVersions_TouchesOnlyTheProxiedFile()
    {
        var b = await BuildAsync("pypi", "1.0.0rc1");
        await SeedProxiedAsync(b, "pypi", "1.0.0rc2");

        Assert.IsType<NoContentResult>(
            await b.OrgController.DeleteVersion("pypi", Name, "1.0.0rc2", CancellationToken.None));

        Assert.Equal(1, await UploadedRowsAsync(b, "pypi", "1.0.0rc1"));
        Assert.Equal(0, await AccessRowsAsync(b, "1.0.0rc2"));
    }

    [Fact]
    public async Task DeleteVersion_PyPiTrailingZeroStaysDistinct_TouchesOnlyTheProxiedFile()
    {
        var b = await BuildAsync("pypi", "1.0.0");
        await SeedProxiedAsync(b, "pypi", "1.0");

        Assert.IsType<NoContentResult>(
            await b.OrgController.DeleteVersion("pypi", Name, "1.0", CancellationToken.None));

        Assert.Equal(1, await UploadedRowsAsync(b, "pypi", "1.0.0"));
        Assert.Equal(0, await AccessRowsAsync(b, "1.0"));
    }

    [Fact]
    public async Task DeleteVersion_NuGetDifferentVersions_TouchesOnlyTheProxiedFile()
    {
        var b = await BuildAsync("nuget", "1.0.0");
        await SeedProxiedAsync(b, "nuget", "2.0.0");

        Assert.IsType<NoContentResult>(
            await b.OrgController.DeleteVersion("nuget", Name, "2.0.0", CancellationToken.None));

        Assert.Equal(1, await UploadedRowsAsync(b, "nuget", "1.0.0"));
        Assert.Equal(0, await AccessRowsAsync(b, "2.0.0"));
    }

    [Fact]
    public async Task BlockVersion_NuGetMixedCaseRoute_BlocksTheUploadedRelease_NotTheProxiedFile()
    {
        var b = await BuildAsync("nuget", "1.0.0-rc1");
        await SeedProxiedAsync(b, "nuget", "1.0.0-Rc1");

        Assert.IsType<OkObjectResult>(
            await b.VulnerabilityController.BlockVersion("nuget", Name, "1.0.0-RC1", CancellationToken.None));

        Assert.Equal("blocked", await UploadedBlockStateAsync(b, "nuget", "1.0.0-rc1"));
        Assert.Null(await ProxiedBlockStateAsync(b, "1.0.0-Rc1"));
    }

    [Fact]
    public async Task BlockVersion_PyPiRespelledRoute_BlocksTheUploadedReleaseAndItsProxiedSpelling()
    {
        var b = await BuildAsync("pypi", "1.0.0rc1");
        await SeedProxiedAsync(b, "pypi", "1.0.0-rc1");

        Assert.IsType<OkObjectResult>(
            await b.VulnerabilityController.BlockVersion("pypi", Name, "1.0.0-rc1", CancellationToken.None));

        Assert.Equal("blocked", await UploadedBlockStateAsync(b, "pypi", "1.0.0rc1"));
        Assert.Equal("blocked", await ProxiedBlockStateAsync(b, "1.0.0-rc1"));
    }

    [Fact]
    public async Task BlockVersion_NuGetDifferentVersions_BlocksNothingOnTheOtherVersion()
    {
        var b = await BuildAsync("nuget", "1.0.0");
        await SeedProxiedAsync(b, "nuget", "2.0.0");

        Assert.IsType<OkObjectResult>(
            await b.VulnerabilityController.BlockVersion("nuget", Name, "2.0.0", CancellationToken.None));

        Assert.Null(await UploadedBlockStateAsync(b, "nuget", "1.0.0"));
        Assert.Equal("blocked", await ProxiedBlockStateAsync(b, "2.0.0"));
    }

    [Fact]
    public async Task BlockVersion_NuGetUnknownVersion_Is404()
    {
        var b = await BuildAsync("nuget", "1.0.0");

        Assert.IsType<NotFoundResult>(
            await b.VulnerabilityController.BlockVersion("nuget", Name, "3.0.0", CancellationToken.None));
        Assert.Null(await UploadedBlockStateAsync(b, "nuget", "1.0.0"));
    }
}
