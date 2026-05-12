using System.Net;
using System.Net.Http.Headers;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression: deleting the last <c>package_versions</c> row used to leave an orphan
/// <c>packages</c> row behind. Delete-then-republish cycles accumulated empty package
/// cards in the UI. <c>OrgController.DeleteVersion</c> now GCs the parent row via
/// <c>PackageRepository.DeletePackageIfEmptyAsync</c>, race-safe through a NOT EXISTS
/// guard. These tests assert both the GC happens when the last version goes and that
/// it does NOT happen while other versions remain.
/// </summary>
[Trait("Category", "Integration")]
public sealed class DeleteVersionPackageGcTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public DeleteVersionPackageGcTests(DependablyFactory factory) => _factory = factory;

    private async Task<HttpClient> AdminClient()
    {
        var jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private static MultipartFormDataContent OneFile(byte[] bytes, string name)
    {
        var part = new ByteArrayContent(bytes);
        part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var content = new MultipartFormDataContent();
        content.Add(part, "files", name);
        return content;
    }

    [Fact]
    public async Task DeletingLastVersion_RemovesParentPackageRow()
    {
        using var c = await AdminClient();
        var (bytes, _, _) = NpmFixtures.BuildTarball("acme-gc-last", "1.0.0");
        using var content = OneFile(bytes, "acme-gc-last-1.0.0.tgz");
        var upload = await c.PostAsync("/api/v1/admin/upload", content);
        upload.EnsureSuccessStatusCode();

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        long pkgCountBeforeDelete;
        await using (var conn = await db.OpenAsync())
        {
            pkgCountBeforeDelete = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM packages WHERE ecosystem = 'npm' AND purl_name = 'acme-gc-last'");
        }
        Assert.Equal(1, pkgCountBeforeDelete);

        var del = await c.DeleteAsync("/api/v1/packages/npm/acme-gc-last/1.0.0");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        await using (var conn = await db.OpenAsync())
        {
            var pkgCountAfter = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM packages WHERE ecosystem = 'npm' AND purl_name = 'acme-gc-last'");
            Assert.Equal(0, pkgCountAfter);

            var verCountAfter = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM package_versions pv " +
                "JOIN packages p ON p.id = pv.package_id " +
                "WHERE p.ecosystem = 'npm' AND p.purl_name = 'acme-gc-last'");
            Assert.Equal(0, verCountAfter);
        }
    }

    [Fact]
    public async Task DeletingOneOfTwoVersions_LeavesParentPackageRow()
    {
        using var c = await AdminClient();
        var (b1, _, _) = NpmFixtures.BuildTarball("acme-gc-two", "1.0.0");
        var (b2, _, _) = NpmFixtures.BuildTarball("acme-gc-two", "2.0.0");
        (await c.PostAsync("/api/v1/admin/upload", OneFile(b1, "acme-gc-two-1.0.0.tgz"))).EnsureSuccessStatusCode();
        (await c.PostAsync("/api/v1/admin/upload", OneFile(b2, "acme-gc-two-2.0.0.tgz"))).EnsureSuccessStatusCode();

        var del = await c.DeleteAsync("/api/v1/packages/npm/acme-gc-two/1.0.0");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        var pkgCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM packages WHERE ecosystem = 'npm' AND purl_name = 'acme-gc-two'");
        Assert.Equal(1, pkgCount);

        var versions = (await conn.QueryAsync<string>(
            "SELECT pv.version FROM package_versions pv " +
            "JOIN packages p ON p.id = pv.package_id " +
            "WHERE p.ecosystem = 'npm' AND p.purl_name = 'acme-gc-two'")).AsList();
        Assert.Single(versions);
        Assert.Equal("2.0.0", versions[0]);
    }
}
