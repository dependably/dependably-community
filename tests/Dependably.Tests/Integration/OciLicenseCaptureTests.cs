using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of OCI image-license capture on the hosted push path and its enforcement
/// on the manifest serve path. A pushed image whose config carries an
/// <c>org.opencontainers.image.licenses</c> label has its SPDX expression captured onto the
/// manifest's <c>oci_blobs</c> row; the license-review queue surfaces the leaf; and when the
/// tenant enforces licenses in 'block' mode with the leaf blocklisted, both GET and HEAD of the
/// manifest return 403 and record a <c>blocked_license</c> activity row. Re-pushing the same
/// manifest does not re-stamp <c>license_checked_at</c> (idempotence, asserted against the frozen
/// clock).
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciLicenseCaptureTests : IAsyncLifetime
{
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task PushImageWithLicenseLabel_StampsManifestRow()
    {
        string repo = Repo("lic-push");
        string manifestDigest = await PushImageAsync(repo, "1.0", "MIT");

        var row = await ReadLicenseRowAsync(manifestDigest);
        Assert.NotNull(row.ConfigDigest);
        Assert.Equal("MIT", row.LicenseSpdx);
        Assert.NotNull(row.LicenseCheckedAt);
    }

    [Fact]
    public async Task ReviewQueue_SurfacesOciLicenseLeaf()
    {
        string repo = Repo("lic-review");
        // Use an SPDX id that is not on any allow/block list so it lands in the review queue.
        await PushImageAsync(repo, "1.0", "BSD-3-Clause");

        string jwt = await _factory.CreateAdminJwt();
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        using var resp = await admin.GetAsync("/api/v1/license-policy/review");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var leaves = doc.RootElement.EnumerateArray()
            .Select(e => e.GetProperty("licenseSpdx").GetString())
            .ToList();
        Assert.Contains("BSD-3-Clause", leaves);
    }

    [Fact]
    public async Task BlockMode_BlocklistedLicense_ManifestServeDenied()
    {
        string repo = Repo("lic-block");
        string orgId = await DefaultOrgIdAsync();
        await SetLicenseModeAsync(orgId, "block");
        await SeedBlockAsync(orgId, "GPL-3.0-only");

        string manifestDigest = await PushImageAsync(repo, "1.0", "GPL-3.0-only");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // GET denied.
        using (var get = await client.GetAsync($"/v2/{repo}/manifests/1.0"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, get.StatusCode);
        }

        // HEAD denied.
        using (var head = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Head, $"/v2/{repo}/manifests/1.0")))
        {
            Assert.Equal(HttpStatusCode.Forbidden, head.StatusCode);
        }

        // The license block records a pending quarantine review row (written synchronously,
        // unlike the batched activity feed) under the 'license' gate for the image PURL.
        string purl = $"pkg:oci/{repo}@{manifestDigest}";
        Assert.Equal("license", await QuarantineGateAsync(orgId, purl));
    }

    [Fact]
    public async Task BlockMode_UnblockedLicense_ManifestServeAllowed()
    {
        string repo = Repo("lic-allow");
        string orgId = await DefaultOrgIdAsync();
        await SetLicenseModeAsync(orgId, "block");
        await SeedAllowAsync(orgId, "MIT"); // allowlisted so 'block' mode admits it
        await SeedBlockAsync(orgId, "GPL-3.0-only");

        await PushImageAsync(repo, "1.0", "MIT");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        using var get = await client.GetAsync($"/v2/{repo}/manifests/1.0");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
    }

    [Fact]
    public async Task NullLicense_NotEnforced()
    {
        string repo = Repo("lic-null");
        string orgId = await DefaultOrgIdAsync();
        await SetLicenseModeAsync(orgId, "block");
        await SeedBlockAsync(orgId, "GPL-3.0-only");

        // Image config with no license label → license_spdx stays NULL → never gated.
        string manifestDigest = await PushImageAsync(repo, "1.0", license: null);
        var row = await ReadLicenseRowAsync(manifestDigest);
        Assert.Null(row.LicenseSpdx);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        using var get = await client.GetAsync($"/v2/{repo}/manifests/1.0");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
    }

    [Fact]
    public async Task WarnMode_BlocklistedLicense_ManifestServeAllowed()
    {
        string repo = Repo("lic-warn");
        string orgId = await DefaultOrgIdAsync();
        await SetLicenseModeAsync(orgId, "warn");
        await SeedBlockAsync(orgId, "GPL-3.0-only");

        await PushImageAsync(repo, "1.0", "GPL-3.0-only");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        using var get = await client.GetAsync($"/v2/{repo}/manifests/1.0");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode); // warn never denies
    }

    [Fact]
    public async Task RePushManifest_LicenseCheckedAtUnchanged()
    {
        string repo = Repo("lic-idem");
        string manifestDigest = await PushImageAsync(repo, "1.0", "MIT");
        string? first = (await ReadLicenseRowAsync(manifestDigest)).LicenseCheckedAt;
        Assert.NotNull(first);

        // Advance the frozen clock and re-push the identical manifest under the same tag.
        Clock.Advance(TimeSpan.FromHours(3));
        string token = await _factory.CreateToken("push");
        using var pushClient = _factory.CreateClientWithBearer(token);
        byte[] configBytes = ConfigJson("MIT");
        byte[] manifest = BuildManifest(Digest(configBytes), configBytes.Length);
        using (var r = await PutManifestAsync(pushClient, repo, "1.0", manifest))
        {
            Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        }

        string? second = (await ReadLicenseRowAsync(manifestDigest)).LicenseCheckedAt;
        Assert.Equal(first, second); // license_checked_at IS NULL guard: no reparse, exact instant held
    }

    // ── push helper ────────────────────────────────────────────────────────────

    private async Task<string> PushImageAsync(string repo, string tag, string? license)
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        byte[] configBytes = ConfigJson(license);
        byte[] layerBytes = new byte[256];
        RandomNumberGenerator.Fill(layerBytes);
        string configDigest = Digest(configBytes);
        string layerDigest = Digest(layerBytes);

        await PushBlobAsync(client, repo, configBytes, configDigest);
        await PushBlobAsync(client, repo, layerBytes, layerDigest);

        byte[] manifest = BuildManifest(configDigest, configBytes.Length, layerDigest, layerBytes.Length);
        string manifestDigest = Digest(manifest);
        using var r = await PutManifestAsync(client, repo, tag, manifest);
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return manifestDigest;
    }

    private static async Task PushBlobAsync(HttpClient client, string repo, byte[] bytes, string digest)
    {
        using var resp = await client.PostAsync(
            $"/v2/{repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(bytes));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    private static async Task<HttpResponseMessage> PutManifestAsync(
        HttpClient client, string repo, string reference, byte[] manifest)
    {
        var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(ManifestMediaType);
        return await client.PutAsync($"/v2/{repo}/manifests/{reference}", content);
    }

    private static byte[] ConfigJson(string? license)
    {
        string json = license is null
            ? """{ "architecture": "amd64", "os": "linux" }"""
            : $$"""{ "architecture": "amd64", "os": "linux", "config": { "Labels": { "org.opencontainers.image.licenses": "{{license}}" } } }""";
        return Encoding.UTF8.GetBytes(json);
    }

    private static byte[] BuildManifest(string configDigest, long configSize, string? layerDigest = null, long layerSize = 0)
    {
        string layers = layerDigest is null
            ? "[]"
            : $$"""
              [ { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "{{layerDigest}}", "size": {{layerSize}} } ]
              """;
        string json = $$"""
        {
          "schemaVersion": 2,
          "mediaType": "{{ManifestMediaType}}",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "{{configDigest}}",
            "size": {{configSize}}
          },
          "layers": {{layers}}
        }
        """;
        return Encoding.UTF8.GetBytes(json);
    }

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string Repo(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..28].ToLowerInvariant();

    // ── DB / policy helpers ──────────────────────────────────────────────────────

    private sealed record LicenseRow(string? ConfigDigest, string? LicenseSpdx, string? LicenseCheckedAt);

    private async Task<LicenseRow> ReadLicenseRowAsync(string manifestDigest)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.QuerySingleAsync<LicenseRow>(
            "SELECT config_digest AS ConfigDigest, license_spdx AS LicenseSpdx, " +
            "license_checked_at AS LicenseCheckedAt FROM oci_blobs WHERE digest = @digest",
            new { digest = manifestDigest });
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
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

    private async Task SeedAllowAsync(string orgId, string spdx)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_allowlist (id, org_id, license_spdx) VALUES (@id, @orgId, @spdx)",
            new { id = Guid.NewGuid().ToString("N"), orgId, spdx });
    }

    private async Task SeedBlockAsync(string orgId, string spdx)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_blocklist (id, org_id, license_spdx) VALUES (@id, @orgId, @spdx)",
            new { id = Guid.NewGuid().ToString("N"), orgId, spdx });
    }

    private async Task<string?> QuarantineGateAsync(string orgId, string purl)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT gate FROM quarantine WHERE org_id = @orgId AND purl = @purl AND state = 'pending'",
            new { orgId, purl });
    }
}
