using System.Net;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Compliance;

/// <summary>
/// npm registry protocol compliance tests.
/// Verifies CouchDB-compatible metadata structure, scoped package routing, and tarball URL rewriting.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class NpmComplianceTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NpmComplianceTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Metadata structure ────────────────────────────────────────────────────

    [Fact]
    public async Task NpmMetadata_HasRequiredFields()
    {
        await _factory.PushNpmPackage("meta-check", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/meta-check");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // CouchDB-compatible required fields
        Assert.True(root.TryGetProperty("name", out _), "Missing 'name'");
        Assert.True(root.TryGetProperty("_id", out _), "Missing '_id'");
        Assert.True(root.TryGetProperty("dist-tags", out var distTags), "Missing 'dist-tags'");
        Assert.True(distTags.TryGetProperty("latest", out _), "Missing 'dist-tags.latest'");
        Assert.True(root.TryGetProperty("versions", out var versions), "Missing 'versions'");

        // Version object must have dist.tarball
        Assert.True(versions.TryGetProperty("1.0.0", out var v), "Missing version '1.0.0'");
        Assert.True(v.TryGetProperty("dist", out var dist), "Missing 'dist' in version");
        Assert.True(dist.TryGetProperty("tarball", out _), "Missing 'dist.tarball'");
    }

    [Fact]
    public async Task NpmMetadata_Id_MatchesName()
    {
        await _factory.PushNpmPackage("idcheck", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string json = await client.GetStringAsync("/npm/idcheck");
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal(root.GetProperty("name").GetString(), root.GetProperty("_id").GetString());
    }

    [Fact]
    public async Task NpmMetadata_TarballUrl_PointsToDependably()
    {
        await _factory.PushNpmPackage("tarball-url", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string json = await client.GetStringAsync("/npm/tarball-url");
        using var doc = JsonDocument.Parse(json);

        string tarball = doc.RootElement
            .GetProperty("versions")
            .GetProperty("1.0.0")
            .GetProperty("dist")
            .GetProperty("tarball")
            .GetString()!;

        // Must point to Dependably's own tarball endpoint, not npmjs.org
        Assert.Contains("/npm/tarballs/", tarball);
        Assert.DoesNotContain("registry.npmjs.org", tarball);
    }

    // ── Scoped packages ───────────────────────────────────────────────────────

    [Fact]
    public async Task NpmMetadata_ScopedPackage_RoutesCorrectly()
    {
        await _factory.PushNpmPackage("@myorg/utils", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/@myorg/utils");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task NpmMetadata_ScopedPackage_NamePreserved()
    {
        await _factory.PushNpmPackage("@scope/lib", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string json = await client.GetStringAsync("/npm/@scope/lib");
        using var doc = JsonDocument.Parse(json);

        string? name = doc.RootElement.GetProperty("name").GetString();
        Assert.Equal("@scope/lib", name);
    }

    [Fact]
    public async Task NpmTarball_ScopedPackage_Downloads()
    {
        await _factory.PushNpmPackage("@myorg/utils", "2.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string json = await client.GetStringAsync("/npm/@myorg/utils");
        using var doc = JsonDocument.Parse(json);
        string tarballUrl = doc.RootElement
            .GetProperty("versions").GetProperty("2.0.0")
            .GetProperty("dist").GetProperty("tarball").GetString()!;

        Assert.Contains("/tarballs/@myorg/utils/", tarballUrl);

        var resp = await client.GetAsync(new Uri(tarballUrl).PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Push validation ───────────────────────────────────────────────────────

    [Fact]
    public async Task NpmPush_NoToken_Returns401()
    {
        string body = NpmFixtures.BuildPublishBody("noauth-pkg", "1.0.0");
        using var client = _factory.CreateClient();
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/noauth-pkg", content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task NpmPush_PullToken_Returns403()
    {
        string token = await _factory.CreateToken("pull");
        string body = NpmFixtures.BuildPublishBody("scope-check-npm", "1.0.0");

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/scope-check-npm", content);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task NpmPush_DuplicateVersion_Returns409()
    {
        await _factory.PushNpmPackage("npm-dup", "1.0.0");

        string token = await _factory.CreateToken("push");
        string body = NpmFixtures.BuildPublishBody("npm-dup", "1.0.0");

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/npm-dup", content);

        Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
    }

    [Fact]
    public async Task NpmPush_NameMismatch_Returns422()
    {
        string token = await _factory.CreateToken("push");
        // Build body for "actual-name" but push to URL with "different-name"
        string body = NpmFixtures.BuildPublishBody("actual-name", "1.0.0");

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/different-name", content);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── License extraction on hosted publish ─────────────────────────────────
    //
    // Hosted npm publish must read the license from the tarball's package.json
    // (matching the proxy first-fetch path). The npm CLI ≥7 commonly omits the
    // license field from the packument's per-version object, so trusting the
    // packument alone meant uploaded packages landed with no SPDX row even when
    // the tarball explicitly declared a license.

    [Fact]
    public async Task HostedPublish_LicenseInTarball_NotInPackument_StoresSpdxRow()
    {
        string token = await _factory.CreateToken("push");
        // Default fixture shape: tarball package.json has license="MIT"; packument has none.
        string body = NpmFixtures.BuildPublishBody("hosted-lic-tarball", "1.0.0");

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/hosted-lic-tarball", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var licenses = await ReadStoredLicensesAsync("pkg:npm/hosted-lic-tarball@1.0.0");
        var (Spdx, Source) = Assert.Single(licenses);
        Assert.Equal("MIT", Spdx);
        Assert.Equal("upstream", Source);
    }

    [Fact]
    public async Task HostedPublish_LicenseOnlyInPackument_FallsBackAndStores()
    {
        string token = await _factory.CreateToken("push");
        // Tarball package.json has NO license; packument carries it. The fallback
        // path inside PublishPackage should pick this up so we don't regress the
        // (rare) case where only the packument has a license.
        string body = NpmFixtures.BuildPublishBody(
            "hosted-lic-packument", "1.0.0",
            tarballLicense: null, packumentLicense: "Apache-2.0");

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/hosted-lic-packument", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var licenses = await ReadStoredLicensesAsync("pkg:npm/hosted-lic-packument@1.0.0");
        var (Spdx, Source) = Assert.Single(licenses);
        Assert.Equal("Apache-2.0", Spdx);
        Assert.Equal("upstream", Source);
    }

    [Fact]
    public async Task HostedPublish_NoLicenseAnywhere_StoresNoRow()
    {
        string token = await _factory.CreateToken("push");
        string body = NpmFixtures.BuildPublishBody(
            "hosted-lic-missing", "1.0.0",
            tarballLicense: null, packumentLicense: null);

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/hosted-lic-missing", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var licenses = await ReadStoredLicensesAsync("pkg:npm/hosted-lic-missing@1.0.0");
        Assert.Empty(licenses);
    }

    private async Task<List<(string Spdx, string Source)>> ReadStoredLicensesAsync(string purl)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        var rows = await conn.QueryAsync<(string Spdx, string Source)>(
            """
            SELECT l.license_spdx, l.source
            FROM package_version_licenses l
            JOIN package_versions v ON v.id = l.package_version_id
            WHERE v.purl = @purl
            ORDER BY l.license_spdx
            """,
            new { purl });
        return rows.ToList();
    }
}
