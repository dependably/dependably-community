using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression coverage for the packument manifest round-trip: a hosted npm publish must
/// persist the install-relevant manifest subset (bin, dependencies, engines, …) and the
/// sha512 integrity SRI, and the packument endpoint must emit them in the per-version
/// objects on BOTH build paths (fully-local <c>BuildNpmMetadata</c> and the proxy-merge
/// splice <c>MergeLocalVersionsIntoPackument</c>).
///
/// Fail-before/pass-after: the old code emitted only {name, version, dist{tarball,shasum}}
/// for uploaded versions, so npx could not resolve <c>bin</c> ("could not determine
/// executable to run") and npm install resolved no transitive dependencies.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmPackumentManifestTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── helpers ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Publishes a synthetic package whose tarball package.json carries the given extra
    /// manifest fields. Returns the tarball bytes and the sha512 SRI the publish body
    /// declared (mirroring the npm CLI, which always sends dist.integrity). The tarball is
    /// built once and reused for both the attachment and the integrity value because
    /// tar/gzip metadata makes two builds non-byte-identical.
    /// </summary>
    private async Task<(byte[] Tarball, string BodyIntegrity)> PublishAsync(
        string name, string version,
        Dictionary<string, object>? manifestFields = null,
        bool includeBodyIntegrity = true)
    {
        string token = await _factory.CreateToken("push");
        var (tarball, _, integrity) = NpmFixtures.BuildTarball(name, version, "MIT", manifestFields);
        string base64 = Convert.ToBase64String(tarball);
        string filename = $"{name}-{version}.tgz";

        var dist = new JsonObject { ["tarball"] = $"https://reg/{filename}" };
        if (includeBodyIntegrity)
        {
            dist["integrity"] = integrity;
        }

        var body = new JsonObject
        {
            ["name"] = name,
            ["versions"] = new JsonObject
            {
                [version] = new JsonObject
                {
                    ["name"] = name,
                    ["version"] = version,
                    ["dist"] = dist,
                }
            },
            ["_attachments"] = new JsonObject
            {
                [filename] = new JsonObject
                {
                    ["content_type"] = "application/octet-stream",
                    ["data"] = base64,
                    ["length"] = tarball.Length,
                }
            }
        };

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        var resp = await client.PutAsync($"/npm/{name}", content);
        resp.EnsureSuccessStatusCode();
        return (tarball, integrity);
    }

    private async Task<JsonDocument> GetPackumentAsync(string name, string? accept = null)
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        if (accept is not null)
        {
            client.DefaultRequestHeaders.Accept.ParseAdd(accept);
        }

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
    }

    private static Dictionary<string, object> CliManifestFields() => new()
    {
        ["bin"] = "./bin/cli.js",
        ["dependencies"] = new Dictionary<string, string> { ["yaml"] = "^2.0.0" },
        ["engines"] = new Dictionary<string, string> { ["node"] = ">=18" },
        ["os"] = new[] { "linux", "darwin" },
        ["cpu"] = new[] { "x64", "arm64" },
    };

    // ── acceptance: round-trip on the fully-local build path ────────────────────

    /// <summary>
    /// Publish with bin/dependencies/engines/os/cpu → the packument's version object
    /// carries them all, plus dist.integrity matching the publish body's declared SRI.
    /// The string-form bin is normalised to the object form npx resolves executables from.
    /// name/version/dist.tarball stay registry-authoritative (tarball URL points at this
    /// registry, not the URL the publish body claimed).
    /// </summary>
    [Fact]
    public async Task Publish_WithInstallManifest_PackumentCarriesManifestAndIntegrity()
    {
        string pkg = $"manifest-rt-{Guid.NewGuid():N}"[..26].ToLowerInvariant();
        var (_, bodyIntegrity) = await PublishAsync(pkg, "1.0.0", CliManifestFields());

        using var doc = await GetPackumentAsync(pkg);
        var ver = doc.RootElement.GetProperty("versions").GetProperty("1.0.0");

        // bin: string form in package.json → object form keyed by the package name.
        Assert.Equal("./bin/cli.js", ver.GetProperty("bin").GetProperty(pkg).GetString());
        Assert.Equal("^2.0.0", ver.GetProperty("dependencies").GetProperty("yaml").GetString());
        Assert.Equal(">=18", ver.GetProperty("engines").GetProperty("node").GetString());
        Assert.Equal(2, ver.GetProperty("os").GetArrayLength());
        Assert.Equal(2, ver.GetProperty("cpu").GetArrayLength());

        // dist.integrity: the publisher-declared sha512 SRI, verbatim.
        Assert.Equal(bodyIntegrity, ver.GetProperty("dist").GetProperty("integrity").GetString());

        // Registry-authoritative core survives: tarball URL points at this registry.
        Assert.Equal(pkg, ver.GetProperty("name").GetString());
        Assert.Equal("1.0.0", ver.GetProperty("version").GetString());
        Assert.Contains("/npm/tarballs/", ver.GetProperty("dist").GetProperty("tarball").GetString());

        // No install script in the fixture → no hasInstallScript flag.
        Assert.False(ver.TryGetProperty("hasInstallScript", out _));
    }

    /// <summary>Both content negotiations serve the manifest fields (same rendered bytes).</summary>
    [Fact]
    public async Task Packument_InstallV1Accept_CarriesManifestFields()
    {
        string pkg = $"manifest-iv1-{Guid.NewGuid():N}"[..26].ToLowerInvariant();
        await PublishAsync(pkg, "1.0.0", CliManifestFields());

        using var doc = await GetPackumentAsync(pkg, accept: "application/vnd.npm.install-v1+json");
        var ver = doc.RootElement.GetProperty("versions").GetProperty("1.0.0");
        Assert.True(ver.TryGetProperty("bin", out _));
        Assert.True(ver.TryGetProperty("dependencies", out _));
    }

    /// <summary>The per-version endpoint (GET /npm/{pkg}/{version}) carries the same fields.</summary>
    [Fact]
    public async Task VersionEndpoint_CarriesManifestFields()
    {
        string pkg = $"manifest-ver-{Guid.NewGuid():N}"[..26].ToLowerInvariant();
        await PublishAsync(pkg, "1.0.0", CliManifestFields());

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        string json = await client.GetStringAsync($"/npm/{pkg}/1.0.0");
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("./bin/cli.js", doc.RootElement.GetProperty("bin").GetProperty(pkg).GetString());
        Assert.Equal("^2.0.0", doc.RootElement.GetProperty("dependencies").GetProperty("yaml").GetString());
    }

    // ── integrity fallback ───────────────────────────────────────────────────────

    /// <summary>
    /// A publish body with no dist.integrity (non-CLI clients) still yields dist.integrity:
    /// the server computes the sha512 SRI from the uploaded bytes.
    /// </summary>
    [Fact]
    public async Task Publish_WithoutBodyIntegrity_ServerComputesSriFromUploadedBytes()
    {
        string pkg = $"manifest-sri-{Guid.NewGuid():N}"[..26].ToLowerInvariant();
        var (tarball, _) = await PublishAsync(pkg, "1.0.0", CliManifestFields(), includeBodyIntegrity: false);

        string expectedSri = "sha512-" + Convert.ToBase64String(SHA512.HashData(tarball));

        using var doc = await GetPackumentAsync(pkg);
        var ver = doc.RootElement.GetProperty("versions").GetProperty("1.0.0");
        Assert.Equal(expectedSri, ver.GetProperty("dist").GetProperty("integrity").GetString());
    }

    // ── hasInstallScript ─────────────────────────────────────────────────────────

    /// <summary>
    /// A tarball with a postinstall hook sets hasInstallScript in the packument (the flag
    /// was already stored at publish; it was never emitted). The scripts object itself is
    /// NOT emitted — it is not part of the abbreviated packument allowlist.
    /// </summary>
    [Fact]
    public async Task Publish_WithPostinstallScript_PackumentSetsHasInstallScript()
    {
        string pkg = $"manifest-his-{Guid.NewGuid():N}"[..26].ToLowerInvariant();
        var fields = CliManifestFields();
        fields["scripts"] = new Dictionary<string, string> { ["postinstall"] = "node setup.js" };
        await PublishAsync(pkg, "1.0.0", fields);

        using var doc = await GetPackumentAsync(pkg);
        var ver = doc.RootElement.GetProperty("versions").GetProperty("1.0.0");
        Assert.True(ver.GetProperty("hasInstallScript").GetBoolean());
        Assert.False(ver.TryGetProperty("scripts", out _),
            "scripts must not be emitted — only the hasInstallScript flag");
    }

    // ── same-version re-push refresh ────────────────────────────────────────────

    /// <summary>
    /// A same-version re-push (org policy 'allow') refreshes the stored manifest and
    /// integrity: the packument must describe the NEW artefact, never the replaced one.
    /// </summary>
    [Fact]
    public async Task Repush_SameVersion_RefreshesManifestAndIntegrity()
    {
        await SetVersionOverwritePolicyAsync("allow");
        try
        {
            string pkg = $"manifest-rp-{Guid.NewGuid():N}"[..26].ToLowerInvariant();
            await PublishAsync(pkg, "1.0.0", new Dictionary<string, object>
            {
                ["dependencies"] = new Dictionary<string, string> { ["left-pad"] = "^1.0.0" },
            });

            var (_, secondIntegrity) = await PublishAsync(pkg, "1.0.0", new Dictionary<string, object>
            {
                ["dependencies"] = new Dictionary<string, string> { ["yaml"] = "^2.0.0" },
                ["engines"] = new Dictionary<string, string> { ["node"] = ">=20" },
            });

            using var doc = await GetPackumentAsync(pkg);
            var ver = doc.RootElement.GetProperty("versions").GetProperty("1.0.0");
            var deps = ver.GetProperty("dependencies");
            Assert.True(deps.TryGetProperty("yaml", out _));
            Assert.False(deps.TryGetProperty("left-pad", out _),
                "the replaced artefact's dependencies must not survive the re-push");
            Assert.Equal(">=20", ver.GetProperty("engines").GetProperty("node").GetString());
            Assert.Equal(secondIntegrity, ver.GetProperty("dist").GetProperty("integrity").GetString());
        }
        finally
        {
            await SetVersionOverwritePolicyAsync("block");
        }
    }

    // ── legacy rows ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Rows published before the manifest column existed (manifest_json NULL, no stored
    /// SRI) must still render — the historical minimal shape, no crash, no integrity.
    /// </summary>
    [Fact]
    public async Task LegacyRow_NullManifestAndIntegrity_RendersMinimalShapeWithoutError()
    {
        string pkg = $"manifest-leg-{Guid.NewGuid():N}"[..26].ToLowerInvariant();
        await PublishAsync(pkg, "1.0.0", CliManifestFields());

        // Simulate a pre-column row: null out the captured manifest + integrity.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                UPDATE package_versions
                   SET manifest_json = NULL,
                       upstream_integrity_value = NULL,
                       upstream_integrity_algorithm = NULL
                 WHERE id IN (SELECT pv.id FROM package_versions pv
                              JOIN packages p ON p.id = pv.package_id
                              WHERE p.name = @pkg)
                """,
                new { pkg });
        }

        await EvictPackumentCacheAsync(pkg);

        using var doc = await GetPackumentAsync(pkg);
        var ver = doc.RootElement.GetProperty("versions").GetProperty("1.0.0");
        Assert.Equal(pkg, ver.GetProperty("name").GetString());
        Assert.False(ver.TryGetProperty("bin", out _));
        Assert.False(ver.TryGetProperty("dependencies", out _));
        Assert.False(ver.GetProperty("dist").TryGetProperty("integrity", out _));
    }

    // ── proxy-merge build path ───────────────────────────────────────────────────

    /// <summary>
    /// The proxy-merge splice (hosted version merged into an upstream packument under a
    /// 'mixed' claim) must emit the same manifest fields, integrity, AND the deprecation
    /// message — the merge path previously omitted 'deprecated' even though the fully-local
    /// path emitted it.
    /// </summary>
    [Fact]
    public async Task MergePath_HostedVersion_CarriesManifestIntegrityAndDeprecated()
    {
        string pkg = $"manifestmrg{Guid.NewGuid():N}"[..24].ToLowerInvariant();

        // Upstream knows 1.0.0 only; the local hosted 2.0.0 gets spliced in.
        string upstreamBase = _factory.MockUpstream.Urls[0];
        string upstreamJson = $$"""
            {
              "name": "{{pkg}}",
              "dist-tags": {"latest":"1.0.0"},
              "versions": {
                "1.0.0": {
                  "name": "{{pkg}}",
                  "version": "1.0.0",
                  "dist": {"tarball":"{{upstreamBase}}/{{pkg}}/-/{{pkg}}-1.0.0.tgz","shasum":"aabbcc"}
                }
              },
              "time": {"1.0.0": "2020-01-01T00:00:00.000Z"}
            }
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{pkg}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBody(upstreamJson));

        // Publish hosted 2.0.0 with a manifest, opt in to upstream merging, deprecate it.
        var (_, bodyIntegrity) = await PublishAsync(pkg, "2.0.0", CliManifestFields());
        await _factory.SeedMixedClaim("npm", pkg);

        string token = await _factory.CreateToken("push");
        using (var client = _factory.CreateClientWithBearer(token))
        {
            string deprecateBody = JsonSerializer.Serialize(new
            {
                name = pkg,
                versions = new Dictionary<string, object>
                {
                    ["2.0.0"] = new { name = pkg, version = "2.0.0", deprecated = "use 3.x" }
                }
            });
            using var content = new StringContent(deprecateBody, Encoding.UTF8, "application/json");
            (await client.PutAsync($"/npm/{pkg}", content)).EnsureSuccessStatusCode();
        }

        await EvictPackumentCacheAsync(pkg);

        using var doc = await GetPackumentAsync(pkg);
        var versions = doc.RootElement.GetProperty("versions");

        // Upstream version survives untouched.
        Assert.True(versions.TryGetProperty("1.0.0", out _));

        // Spliced hosted version carries the manifest, integrity, and deprecation message.
        var ver = versions.GetProperty("2.0.0");
        Assert.Equal("./bin/cli.js", ver.GetProperty("bin").GetProperty(pkg).GetString());
        Assert.Equal("^2.0.0", ver.GetProperty("dependencies").GetProperty("yaml").GetString());
        Assert.Equal(bodyIntegrity, ver.GetProperty("dist").GetProperty("integrity").GetString());
        Assert.Equal("use 3.x", ver.GetProperty("deprecated").GetString());
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task EvictPackumentCacheAsync(string pkgName)
    {
        string orgId = await DefaultOrgIdAsync();
        _factory.Services
            .GetRequiredService<RenderedResponseCache<NpmPackumentKey>>()
            .Evict(new NpmPackumentKey(orgId, pkgName));
    }

    private async Task SetVersionOverwritePolicyAsync(string policy)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET version_overwrite_policy = @policy WHERE org_id = @orgId",
            new { policy, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }
}
