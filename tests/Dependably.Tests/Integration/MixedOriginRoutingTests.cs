using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Mixed-origin routing: a package name is a namespace that can hold both privately uploaded
/// versions and proxy-fetched/upstream versions. Uploading one private build must not lock
/// the rest of the namespace out of proxy passthrough.
///
/// Per memory feedback_per_version_origin_routing.md and feedback_test_partial_failure_scenarios.md,
/// these tests exercise the "some uploaded, some proxy, request a third uncached upstream version"
/// scenario in one flow per ecosystem.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MixedOriginRoutingTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public MixedOriginRoutingTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── NuGet: index merges upstream even when a hosted version exists ─────────

    [Fact]
    public async Task NuGet_Index_HostedNamespace_StillMergesUpstreamVersions()
    {
        string id = $"mixednuget{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        // Push a private 99.0.0 — this flips packages.is_proxy to false.
        await _factory.PushNuGetPackage(id, "99.0.0");
        // Hosted names are implicit local_only; merging upstream needs the explicit operator opt-in.
        await _factory.SeedMixedClaim("nuget", id);

        // Stub upstream flatcontainer to return public versions for this name.
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody("{\"versions\":[\"1.0.0\",\"2.0.0\"]}"));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var versions = doc.RootElement.GetProperty("versions").EnumerateArray()
            .Select(v => v.GetString()).ToHashSet();

        Assert.Contains("99.0.0", versions);
        Assert.Contains("1.0.0", versions);
        Assert.Contains("2.0.0", versions);
    }

    [Fact]
    public async Task NuGet_Index_UpstreamFailure_SetsXUpstreamStatusErrorHeader()
    {
        string id = $"upstreamerr{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");
        await _factory.SeedMixedClaim("nuget", id);

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("error", resp.Headers.GetValues("X-Upstream-Status").FirstOrDefault());
    }

    // ── NuGet: download routes by version origin, not package flag ─────────────

    [Fact]
    public async Task NuGet_Download_UncachedUpstreamVersion_HostedNamespace_ProxyFetches()
    {
        string id = $"mixeddl{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "99.0.0");
        await _factory.SeedMixedClaim("nuget", id);

        // Build a valid .nupkg for the upstream version so the proxy-fetch path can verify
        // checksums and produce a sane DB row.
        var (upstreamBytes, _) = NuGetFixtures.BuildNupkg(id, "1.2.3");
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/1.2.3/{id}.1.2.3.nupkg")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(upstreamBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Despite packages.is_proxy=false (private upload exists), the public version is
        // still proxy-fetchable because routing now branches on per-version origin.
        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/1.2.3/{id}.1.2.3.nupkg");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task NuGet_Download_PrivateVersion_StillRequiresAuth()
    {
        string id = $"privatedl{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");

        // Anonymous request for the private version must still 401 — per-version routing
        // doesn't loosen the hosted-version auth requirement.
        using var anon = _factory.CreateClient();
        var resp = await anon.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── PyPi: simple index merges upstream + local ─────────────────────────────

    [Fact]
    public async Task PyPi_SimpleIndex_HostedNamespace_StillMergesUpstreamVersions()
    {
        string name = $"mixedpypi{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "99.0.0");
        await _factory.SeedMixedClaim("pypi", name);

        string upstreamHtml = $"""
            <!DOCTYPE html>
            <html><body>
            <a href="https://files.pythonhosted.org/packages/aa/bb/{name}-1.0.0.tar.gz#sha256=cafe">{name}-1.0.0.tar.gz</a><br/>
            </body></html>
            """;

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/simple/{name}/")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html").WithBody(upstreamHtml));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string html = await resp.Content.ReadAsStringAsync();
        Assert.Contains($"{name}-1.0.0.tar.gz", html);
        // Local 99.0.0 wheel filename pattern: {name_underscored}-99.0.0-py3-none-any.whl
        string underscored = name.Replace('-', '_');
        Assert.Contains($"{underscored}-99.0.0-py3-none-any.whl", html);
    }

    // ── Npm: packument merges upstream + local ─────────────────────────────────

    [Fact]
    public async Task Npm_Packument_HostedNamespace_StillMergesUpstreamVersions()
    {
        string name = $"mixednpm{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNpmPackage(name, "99.0.0");
        await _factory.SeedMixedClaim("npm", name);

        string upstreamJson = $$"""
        {
          "_id": "{{name}}",
          "name": "{{name}}",
          "dist-tags": {"latest":"1.0.0"},
          "versions": {
            "1.0.0": {
              "name": "{{name}}",
              "version": "1.0.0",
              "dist": {"tarball":"https://registry.npmjs.org/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"deadbeef"}
            }
          }
        }
        """;

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{name}")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var versions = doc.RootElement.GetProperty("versions");
        Assert.True(versions.TryGetProperty("1.0.0", out _), "upstream version should be present");
        Assert.True(versions.TryGetProperty("99.0.0", out _), "uploaded local version should be merged in");
    }

    // ── NuGet: mixed origin in one flow ─────────────────────────────────────────

    [Fact]
    public async Task NuGet_MixedOrigin_PrivateAndProxiedVersionsCoexistOnSameName()
    {
        // Scenario from the failure report: a tenant uploaded a private version of a name
        // (origin='uploaded'), then later wants to proxy-fetch a different upstream version.
        // The proxy-fetched version is anonymously readable; the uploaded one still requires
        // auth. Both live under the same packages.id row.
        string id = $"coexist{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "99.0.0");
        await _factory.SeedMixedClaim("nuget", id);

        // Mock upstream's nupkg for 1.0.0 so the proxy-fetch leg actually caches a row.
        var (nupkg100, _) = NuGetFixtures.BuildNupkg(id, "1.0.0");
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(nupkg100));

        // First fetch primes the cache: authenticated request for 1.0.0 succeeds and writes
        // a package_versions row with origin='proxy'.
        string token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBasic(token);
        var primeResp = await authClient.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

        // Confirm the DB has the correct mixed-origin shape:
        // - 99.0.0 is origin='uploaded' in package_versions (tenant-local row)
        // - 1.0.0 is in the global plane (cache_artifact + tenant_artifact_access) with NO package_versions row
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        // Uploaded version lives in package_versions.
        string? uploadedOrigin = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.origin
            FROM package_versions pv JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem='nuget' AND p.purl_name=@id AND pv.version='99.0.0'
            """,
            new { id });
        Assert.Equal("uploaded", uploadedOrigin);

        // Proxy version lives only in the global plane — no package_versions row.
        int proxyInPackageVersions = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)
            FROM package_versions pv JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem='nuget' AND p.purl_name=@id AND pv.version='1.0.0'
            """,
            new { id });
        Assert.Equal(0, proxyInPackageVersions);

        // Proxy version is accessible via the global plane for this tenant.
        int proxyInGlobalPlane = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
            JOIN orgs o ON o.id = taa.org_id
            WHERE ca.ecosystem='nuget' AND ca.name=@id AND ca.version='1.0.0'
              AND o.slug='default'
            """,
            new { id });
        Assert.Equal(1, proxyInGlobalPlane);

        // Now: anon request for the proxy version should succeed (cache hit, no auth required).
        using var anonClient = _factory.CreateClient();
        var anonProxyResp = await anonClient.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.OK, anonProxyResp.StatusCode);

        // Anon request for the private version on the same name should still 401.
        var anonPrivateResp = await anonClient.GetAsync($"/nuget/flatcontainer/{id}/99.0.0/{id}.99.0.0.nupkg");
        Assert.Equal(HttpStatusCode.Unauthorized, anonPrivateResp.StatusCode);
    }

    // ── PyPi: download routes by per-version origin ────────────────────────────

    [Fact]
    public async Task PyPi_Download_RoutesByVersionOrigin_PrivateRequiresAuth_ProxyDoesNot()
    {
        string name = $"pypiroute{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "99.0.0");
        await _factory.SeedMixedClaim("pypi", name);

        // Default test org has AnonymousPull=false. Turn it on for this test so anon access
        // to the proxy-cached version is allowed by tenant policy. The point being tested is
        // that uploaded versions still gate even when anon access is permitted; not the
        // tenant-wide anon toggle itself. The DependablyFactory is shared across tests in
        // this class (IClassFixture), so we restore the setting in a finally block below.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn0 = await store.OpenAsync();
        string orgId = await conn0.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        await conn0.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        try
        {

            // Prime a proxy-fetched version. The simplest path is to mock the simple index
            // and the file download so the proxy flow creates a package_versions row.
            string underscored = name.Replace('-', '_');
            string publicFilename = $"{underscored}-1.0.0-py3-none-any.whl";

            var (wheelBytes, wheelSha) = PyPiFixtures.BuildWheel(name, "1.0.0");
            // The simple-index href must point at a URL the test environment can reach. Use the
            // MockUpstream's own base so DownloadAndCacheAsync's GET resolves to a mocked response.
            // The #sha256= fragment is now verified on first-fetch — supply the real hash so the
            // proxy fetch doesn't 502 on the integrity check.
            string mockBase = _factory.MockUpstream.Urls[0];
            string simpleHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="{mockBase}/files/{publicFilename}#sha256={wheelSha}">{publicFilename}</a><br/>
            </body></html>
            """;
            _factory.MockUpstream.Given(
                    Request.Create().WithPath($"/simple/{name}/").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                    .WithHeader("Content-Type", "text/html").WithBody(simpleHtml));
            _factory.MockUpstream.Given(
                    Request.Create().WithPath($"/files/{publicFilename}").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                    .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

            // Prime cache via authenticated request.
            string token = await _factory.CreateToken("pull");
            using var authClient = _factory.CreateClientWithBasic(token);
            var primeResp = await authClient.GetAsync($"/packages/{publicFilename}");
            Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

            // Anon request for the proxy version → 200 (no auth required for proxy-cached).
            using var anonClient = _factory.CreateClient();
            var anonProxyResp = await anonClient.GetAsync($"/packages/{publicFilename}");
            Assert.Equal(HttpStatusCode.OK, anonProxyResp.StatusCode);

            // Anon request for the privately uploaded version → 401.
            string privateFilename = $"{underscored}-99.0.0-py3-none-any.whl";
            var anonPrivateResp = await anonClient.GetAsync($"/packages/{privateFilename}");
            Assert.Equal(HttpStatusCode.Unauthorized, anonPrivateResp.StatusCode);
        }
        finally
        {
            await conn0.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        }
    }

    // ── Npm: tarball routes by per-version origin ─────────────────────────────

    [Fact]
    public async Task Npm_Tarball_RoutesByVersionOrigin_PrivateRequiresAuth_ProxyDoesNot()
    {
        string name = $"npmroute{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNpmPackage(name, "99.0.0");
        await _factory.SeedMixedClaim("npm", name);

        // Mock the upstream packument so the proxy-fetch path can resolve version 1.0.0,
        // and the tarball blob itself.
        string publicTarball = $"{name}-1.0.0.tgz";
        var (tarballBytes, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        // dist.shasum is now verified against tarball bytes on first-fetch; emit the real
        // SHA-1 so the proxy fetch doesn't 502 on the integrity check.
        string tarballSha1 = Convert.ToHexString(
            System.Security.Cryptography.SHA1.HashData(tarballBytes)).ToLowerInvariant();
        string packumentJson = $$"""
        {
          "_id": "{{name}}",
          "name": "{{name}}",
          "dist-tags": {"latest":"1.0.0"},
          "versions": {
            "1.0.0": {
              "name": "{{name}}",
              "version": "1.0.0",
              "dist": {"tarball":"http://upstream/{{name}}/-/{{publicTarball}}","shasum":"{{tarballSha1}}"}
            }
          }
        }
        """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packumentJson));
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{name}/-/{publicTarball}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(tarballBytes));

        // Prime cache for 1.0.0 (proxy origin).
        string token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBearer(token);
        var primeResp = await authClient.GetAsync($"/npm/tarballs/{name}/{publicTarball}");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

        // Anon request for the proxy version → 200.
        using var anonClient = _factory.CreateClient();
        var anonProxyResp = await anonClient.GetAsync($"/npm/tarballs/{name}/{publicTarball}");
        Assert.Equal(HttpStatusCode.OK, anonProxyResp.StatusCode);

        // Anon request for the private version → 401.
        string privateTarball = $"{name}-99.0.0.tgz";
        var anonPrivateResp = await anonClient.GetAsync($"/npm/tarballs/{name}/{privateTarball}");
        Assert.Equal(HttpStatusCode.Unauthorized, anonPrivateResp.StatusCode);
    }

    // ── Maven: download routes by per-version origin ──────────────────────────

    [Fact]
    public async Task Maven_Download_UploadedArtifact_AnonRequest_Returns401_EvenWithAnonymousPullOn()
    {
        string groupId = "com.example";
        string artifactId = $"mvnpriv{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        string version = "1.0.0";

        // Push an artifact — creates origin='uploaded' row.
        string filename = await _factory.PushMavenArtifact(groupId, artifactId, version);
        string path = $"/maven/{groupId.Replace('.', '/')}/{artifactId}/{version}/{filename}";

        // Enable AnonymousPull so the tenant-level gate does not block the request.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn0 = await store.OpenAsync();
        string orgId = await conn0.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        await conn0.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        try
        {
            // Anonymous request for the uploaded artifact → 401 even though AnonymousPull is on.
            using var anonClient = _factory.CreateClient();
            var anonResp = await anonClient.GetAsync(path);
            Assert.Equal(HttpStatusCode.Unauthorized, anonResp.StatusCode);
        }
        finally
        {
            await conn0.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        }
    }

    [Fact]
    public async Task Maven_Download_UploadedArtifact_WithReadArtifactToken_Returns200()
    {
        string groupId = "com.example";
        string artifactId = $"mvnauth{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        string version = "1.0.0";

        string filename = await _factory.PushMavenArtifact(groupId, artifactId, version);
        string path = $"/maven/{groupId.Replace('.', '/')}/{artifactId}/{version}/{filename}";

        // A token carrying read:artifact is allowed through the origin gate.
        string token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBasic(token);
        var resp = await authClient.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Maven_Download_MixedOrigin_UploadedDenied_ProxyCachedAllowed_InSameFlow()
    {
        // House-rule mixed/partial-failure scenario: an uploaded artifact is denied to an
        // anonymous caller while a proxy-cached artifact from the same package namespace
        // is served without auth — both handled in a single flow, same org, same AnonymousPull
        // setting. Validates that the origin gate is per-version, not per-package.
        string groupId = "com.example";
        string artifactId = $"mvnmixed{Guid.NewGuid():N}"[..12].ToLowerInvariant();

        // Push a private version (origin='uploaded').
        string filename99 = await _factory.PushMavenArtifact(groupId, artifactId, "99.0.0");
        string uploadedPath = $"/maven/{groupId.Replace('.', '/')}/{artifactId}/99.0.0/{filename99}";

        // Directly seed a proxy-cached version in the DB so we don't need an upstream HTTP stub.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        string purlName = $"{groupId}:{artifactId}";
        string pkgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM packages WHERE org_id = @orgId AND purl_name = @purl AND ecosystem = 'maven' LIMIT 1",
            new { orgId, purl = purlName })
            ?? throw new InvalidOperationException("Package row not found after push.");

        // Add a proxy version row and its maven_version_files record.
        string proxyFilename = $"{artifactId}-1.0.0.jar";
        byte[] proxyBytes = [0x50, 0x4B];
        string proxySha256 = Convert.ToHexString(SHA256.HashData(proxyBytes)).ToLowerInvariant();
        // deepcode ignore InsecureHash: Maven sidecar compatibility — SHA-1 and MD5 are required by the Maven repo spec.
        string proxySha1 = Convert.ToHexString(SHA1.HashData(proxyBytes)).ToLowerInvariant();
        // deepcode ignore InsecureHash: Maven sidecar compatibility — see above.
        string proxyMd5 = Convert.ToHexString(MD5.HashData(proxyBytes)).ToLowerInvariant();

        // Write the proxy blob so the cache-hit serve path can stream it. The DB key for a
        // proxy artifact is proxy/{sha256}/{filename}; StoreKey strips the filename suffix
        // to get proxy/{sha256}, which is what the blob store holds.
        string proxyStoreKey = BlobKeys.Proxy(proxySha256);
        string proxyDbKey = $"{proxyStoreKey}/{proxyFilename}";
        await _factory.BlobStore.PutAsync(proxyStoreKey, new System.IO.MemoryStream(proxyBytes), CancellationToken.None);

        string proxyVersionId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
            VALUES (@id, @pkgId, '1.0.0', @purl, @blobKey, @filename, 2, @sha256, 'proxy')
            """,
            new { id = proxyVersionId, pkgId, purl = $"pkg:maven/{groupId}/{artifactId}@1.0.0", blobKey = proxyDbKey, filename = proxyFilename, sha256 = proxySha256 });
        string proxyFileId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin)
            VALUES (@id, @pvId, @filename, NULL, 'jar', @blobKey, 2, @sha256, @sha1, @md5, 'proxy')
            """,
            new { id = proxyFileId, pvId = proxyVersionId, filename = proxyFilename, blobKey = proxyDbKey, sha256 = proxySha256, sha1 = proxySha1, md5 = proxyMd5 });

        // Enable AnonymousPull to confirm the per-version gate fires independently.
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        try
        {
            using var anonClient = _factory.CreateClient();

            // Uploaded version → 401 despite AnonymousPull.
            var anonUploadedResp = await anonClient.GetAsync(uploadedPath);
            Assert.Equal(HttpStatusCode.Unauthorized, anonUploadedResp.StatusCode);

            // Proxy-cached version → 200 (cache hit, anon-OK under AnonymousPull).
            string proxyPath = $"/maven/{groupId.Replace('.', '/')}/{artifactId}/1.0.0/{proxyFilename}";
            var anonProxyResp = await anonClient.GetAsync(proxyPath);
            Assert.Equal(HttpStatusCode.OK, anonProxyResp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        }
    }

    // ── Cross-cutting: ProxyPassthroughDisabled honors the gate ─────────────────

    [Fact]
    public async Task NuGet_Index_PassthroughDisabled_ReturnsLocalOnlyWithSkippedHeader()
    {
        string id = $"passthroughoff{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");

        // Turn off passthrough.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, proxy_passthrough_enabled, max_osv_score_tolerance)
            VALUES (@orgId, 0, 10.0)
            ON CONFLICT(org_id) DO UPDATE SET proxy_passthrough_enabled = 0
            """,
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal("skipped", resp.Headers.GetValues("X-Upstream-Status").FirstOrDefault());

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var versions = doc.RootElement.GetProperty("versions").EnumerateArray()
                .Select(v => v.GetString()).ToList();
            Assert.Single(versions);
            Assert.Equal("1.0.0", versions[0]);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        }
    }
}
