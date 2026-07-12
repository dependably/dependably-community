using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Hard-block enforcement for the SPDX license policy on the PUBLISH path, governed by the
/// existing <c>org_settings.license_enforcement_mode</c> ('off'/'warn'/'block'). Sibling of
/// <see cref="LicenseEnforcementTests"/> (which covers the serve/proxy path).
///
/// Two enforcement shapes are covered:
///   • The shared pipeline (npm, NuGet, PyPI, Cargo, admin import — all funnel through
///     <c>PackagePublishService.StoreAndRecordAsync</c>): a blocked publish rejects with 403
///     AND leaves no <c>package_versions</c> row behind — the check runs before the row is
///     persisted, so "reject" and "never wrote it" are the same outcome. npm exercises the
///     compound OR/AND cases too.
///   • Maven (bypasses the shared pipeline — licenses live only in the <c>.pom</c>, uploaded
///     after the <c>.jar</c>): the <c>.pom</c> PUT itself is rejected under 'block'.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PublishLicenseEnforcementTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string AllowedLicense = "MIT";
    private const string BlockedLicense = "GPL-3.0-only";

    private readonly DependablyFactory _factory;

    public PublishLicenseEnforcementTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── npm (shared pipeline — compound + no-version-row coverage) ────────────

    [Fact]
    public async Task Npm_BlocklistedLicense_UnderBlock_403_NoVersionRowPersisted()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        try
        {
            string name = PackageName("npm-block");
            var resp = await PublishNpmAsync(name, "1.0.0", BlockedLicense);
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
            Assert.False(await VersionExistsAsync(orgId, "npm", name, "1.0.0"));
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task Npm_BlocklistedLicense_UnderWarn_Succeeds()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "warn");
        try
        {
            string name = PackageName("npm-warn");
            var resp = await PublishNpmAsync(name, "1.0.0", BlockedLicense);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.True(await VersionExistsAsync(orgId, "npm", name, "1.0.0"));
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task Npm_BlocklistedLicense_UnderOff_Succeeds()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "off");
        try
        {
            string name = PackageName("npm-off");
            var resp = await PublishNpmAsync(name, "1.0.0", BlockedLicense);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.True(await VersionExistsAsync(orgId, "npm", name, "1.0.0"));
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task Npm_AllowedLicense_UnderBlock_Succeeds()
    {
        string orgId = await ResetOrgAsync();
        await SeedAllowAsync(orgId, AllowedLicense);
        await SetLicenseModeAsync(orgId, "block");
        try
        {
            string name = PackageName("npm-allow");
            var resp = await PublishNpmAsync(name, "1.0.0", AllowedLicense);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.True(await VersionExistsAsync(orgId, "npm", name, "1.0.0"));
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task Npm_CompoundOr_OneAllowed_UnderBlock_Succeeds()
    {
        string orgId = await ResetOrgAsync();
        await SeedAllowAsync(orgId, AllowedLicense);
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        try
        {
            string name = PackageName("npm-or");
            // OR is satisfied by the allowlisted MIT even though the sibling is blocklisted.
            var resp = await PublishNpmAsync(name, "1.0.0", $"{AllowedLicense} OR {BlockedLicense}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.True(await VersionExistsAsync(orgId, "npm", name, "1.0.0"));
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task Npm_CompoundAnd_OneBlocked_UnderBlock_403_NoVersionRowPersisted()
    {
        string orgId = await ResetOrgAsync();
        await SeedAllowAsync(orgId, AllowedLicense);
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        try
        {
            string name = PackageName("npm-and");
            // AND requires every leaf; the blocklisted GPL leaf sinks it.
            var resp = await PublishNpmAsync(name, "1.0.0", $"{AllowedLicense} AND {BlockedLicense}");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
            Assert.False(await VersionExistsAsync(orgId, "npm", name, "1.0.0"));
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    private async Task<HttpResponseMessage> PublishNpmAsync(string name, string version, string license)
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        string body = NpmFixtures.BuildPublishBody(name, version, tarballLicense: license);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        return await client.PutAsync($"/npm/{name}", content);
    }

    // ── NuGet (shared pipeline — second ecosystem, no-version-row coverage) ───

    [Fact]
    public async Task NuGet_BlocklistedLicense_UnderBlock_403_NoVersionRowPersisted()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        try
        {
            string id = PackageName("NuGetBlock");
            var resp = await PublishNuGetAsync(id, "1.0.0", BlockedLicense);
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
            Assert.False(await VersionExistsAsync(orgId, "nuget", id.ToLowerInvariant(), "1.0.0"));
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task NuGet_BlocklistedLicense_UnderWarn_Succeeds()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "warn");
        try
        {
            string id = PackageName("NuGetWarn");
            var resp = await PublishNuGetAsync(id, "1.0.0", BlockedLicense);
            Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
            Assert.True(await VersionExistsAsync(orgId, "nuget", id.ToLowerInvariant(), "1.0.0"));
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    private async Task<HttpResponseMessage> PublishNuGetAsync(string id, string version, string license)
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        var (bytes, _) = BuildNupkgWithLicense(id, version, license);
        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", $"{id}.{version}.nupkg");
        return await client.PutAsync("/nuget/publish", content);
    }

    private static (byte[] Bytes, string Sha256Hex) BuildNupkgWithLicense(string id, string version, string license)
    {
        string nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>{id}</id>
                <version>{version}</version>
                <authors>dependably-test</authors>
                <description>Synthetic license-enforcement test package</description>
                <license type="expression">{license}</license>
              </metadata>
            </package>
            """;

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteZipEntry(zip, $"{id}.nuspec", nuspec);
            WriteZipEntry(zip, "lib/netstandard2.0/_._", "");
        }

        byte[] bytes = ms.ToArray();
        string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return (bytes, hash);
    }

    private static void WriteZipEntry(ZipArchive zip, string entryName, string content)
    {
        var entry = zip.CreateEntry(entryName);
        using var writer = new StreamWriter(entry.Open());
        writer.Write(content);
    }

    // ── Maven (bypasses the shared pipeline — .pom PUT gate) ──────────────────

    [Fact]
    public async Task Maven_PomPut_BlocklistedLicense_UnderBlock_403()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        try
        {
            string artifactId = PackageName("mvn-lic").ToLowerInvariant();
            string token = await _factory.CreateToken("push");
            using var client = _factory.CreateClientWithBearer(token);
            string basePath = $"/maven/com/example/{artifactId}/1.0.0/{artifactId}-1.0.0";

            using var jarContent = new ByteArrayContent(Encoding.UTF8.GetBytes("dummy-jar-bytes"));
            jarContent.Headers.ContentType = new MediaTypeHeaderValue("application/java-archive");
            var jarResp = await client.PutAsync($"{basePath}.jar", jarContent);
            Assert.Equal(HttpStatusCode.Created, jarResp.StatusCode);

            string pom = $"""
                <?xml version="1.0" encoding="UTF-8"?>
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>{artifactId}</artifactId>
                  <version>1.0.0</version>
                  <licenses>
                    <license>
                      <name>{BlockedLicense}</name>
                    </license>
                  </licenses>
                </project>
                """;
            using var pomContent = new ByteArrayContent(Encoding.UTF8.GetBytes(pom));
            pomContent.Headers.ContentType = new MediaTypeHeaderValue("application/xml");
            var pomResp = await client.PutAsync($"{basePath}.pom", pomContent);

            Assert.Equal(HttpStatusCode.Forbidden, pomResp.StatusCode);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task Maven_PomPut_BlocklistedLicense_UnderWarn_Succeeds()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "warn");
        try
        {
            string artifactId = PackageName("mvn-warn").ToLowerInvariant();
            string token = await _factory.CreateToken("push");
            using var client = _factory.CreateClientWithBearer(token);
            string basePath = $"/maven/com/example/{artifactId}/1.0.0/{artifactId}-1.0.0";

            using var jarContent = new ByteArrayContent(Encoding.UTF8.GetBytes("dummy-jar-bytes"));
            jarContent.Headers.ContentType = new MediaTypeHeaderValue("application/java-archive");
            Assert.Equal(HttpStatusCode.Created, (await client.PutAsync($"{basePath}.jar", jarContent)).StatusCode);

            string pom = $"""
                <?xml version="1.0" encoding="UTF-8"?>
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>{artifactId}</artifactId>
                  <version>1.0.0</version>
                  <licenses>
                    <license>
                      <name>{BlockedLicense}</name>
                    </license>
                  </licenses>
                </project>
                """;
            using var pomContent = new ByteArrayContent(Encoding.UTF8.GetBytes(pom));
            pomContent.Headers.ContentType = new MediaTypeHeaderValue("application/xml");
            var pomResp = await client.PutAsync($"{basePath}.pom", pomContent);

            Assert.Equal(HttpStatusCode.Created, pomResp.StatusCode);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private static string PackageName(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24].ToLowerInvariant();

    private async Task<bool> VersionExistsAsync(string orgId, string ecosystem, string purlName, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? id = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pv.id FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = @ecosystem AND p.purl_name = @purlName AND pv.version = @version
            """,
            new { orgId, ecosystem, purlName, version });
        return id is not null;
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    // Restores the org to a clean baseline (mode off, empty allow/block lists) so tests are
    // order-independent within the shared fixture. Returns the default org id.
    private async Task<string> ResetOrgAsync()
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET license_enforcement_mode = 'off' WHERE org_id = @orgId",
            new { orgId });
        await conn.ExecuteAsync("DELETE FROM license_allowlist WHERE org_id = @orgId", new { orgId });
        await conn.ExecuteAsync("DELETE FROM license_blocklist WHERE org_id = @orgId", new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        return orgId;
    }

    private async Task SetLicenseModeAsync(string orgId, string mode)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET license_enforcement_mode = @mode WHERE org_id = @orgId",
            new { mode, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SeedAllowAsync(string orgId, string licenseSpdx)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_allowlist (id, org_id, license_spdx) VALUES (@id, @orgId, @spdx)",
            new { id = Guid.NewGuid().ToString("N"), orgId, spdx = licenseSpdx });
    }

    private async Task SeedBlockAsync(string orgId, string licenseSpdx)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_blocklist (id, org_id, license_spdx) VALUES (@id, @orgId, @spdx)",
            new { id = Guid.NewGuid().ToString("N"), orgId, spdx = licenseSpdx });
    }
}
