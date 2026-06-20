using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for the Cargo sparse registry surface:
/// config.json shape, sparse index file with a local version, crate download from the
/// blob store, and anonymous-pull auth gate.
/// </summary>
[Trait("Category", "Integration")]
public sealed class CargoControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public CargoControllerTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SeedCargoUpstreamAsync(string upstreamUrl)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @orgId, 'cargo', @url, 0)
            ON CONFLICT (org_id, ecosystem, url) DO NOTHING
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, url = upstreamUrl });
    }

    private async Task RemoveCargoUpstreamsAsync()
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM upstream_registry WHERE org_id = @orgId AND ecosystem = 'cargo'",
            new { orgId });
    }

    // Inserts a package + version + cargo_metadata row for a local crate.
    private async Task SeedLocalCrateAsync(string name, string version, string indexLine)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        string pkgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@id, @orgId, 'cargo', @name, @purlName, 0)
            ON CONFLICT (org_id, ecosystem, purl_name) DO UPDATE SET id = packages.id
            """,
            new { id = pkgId, orgId, name, purlName = name });

        // Re-read in case conflict resolved.
        pkgId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM packages WHERE org_id = @orgId AND ecosystem = 'cargo' AND purl_name = @name",
            new { orgId, name }))!;

        string blobKey = Dependably.Storage.BlobKeys.Cargo(orgId, name, version);
        string purl = $"pkg:cargo/{name}@{version}";
        string versionId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin)
            VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, 0, 'uploaded')
            ON CONFLICT DO NOTHING
            """,
            new { id = versionId, pkgId, version, purl, blobKey, filename = $"{name}-{version}.crate" });

        versionId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM package_versions WHERE package_id = @pkgId AND version = @version",
            new { pkgId, version }))!;

        await conn.ExecuteAsync(
            """
            INSERT INTO cargo_metadata (version_id, index_line, owner_kind)
            VALUES (@versionId, @indexLine, 'package_version')
            ON CONFLICT (version_id) WHERE owner_kind = 'package_version' DO UPDATE SET index_line = excluded.index_line
            """,
            new { versionId, indexLine });
    }

    // ── config.json ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GetConfig_WithToken_Returns200WithDlAndApi()
    {
        await SetAnonymousPullAsync(false);
        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);
            var resp = await client.GetAsync("/cargo/config.json");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);
            Assert.True(doc.RootElement.TryGetProperty("dl", out var dl));
            Assert.True(doc.RootElement.TryGetProperty("api", out var api));
            Assert.Contains("/cargo/api/v1/crates", dl.GetString());
            Assert.Contains("/cargo", api.GetString());
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task GetConfig_AnonymousPullEnabled_NoToken_Returns200()
    {
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/cargo/config.json");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task GetConfig_NoToken_AnonymousPullOff_Returns401()
    {
        await SetAnonymousPullAsync(false);
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/cargo/config.json");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("cargo", resp.Headers.WwwAuthenticate.ToString());
    }

    // ── Sparse index ──────────────────────────────────────────────────────────

    [Fact]
    public async Task GetIndex_LocalVersion_ReturnsIndexLine()
    {
        string name = $"localcrate{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string version = "1.0.0";
        string indexLine = $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"abc","features":{},"yanked":false}""";

        await SeedLocalCrateAsync(name, version, indexLine);
        await RemoveCargoUpstreamsAsync();

        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            // Derive the index path for a 4+-char name.
            string idx = Dependably.Api.CargoController.IndexPath(name);
            var resp = await client.GetAsync($"/cargo/{idx}");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            Assert.Contains(version, body);
            Assert.Contains(name, body);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task GetIndex_NoCrate_NoUpstream_Returns404()
    {
        await RemoveCargoUpstreamsAsync();
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/cargo/se/rd/serde");
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task GetIndex_WithUpstreamProxy_MergesUpstreamLines()
    {
        string name = $"proxycrate{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string version = "2.0.0";
        string upstreamLine = $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"def","features":{},"yanked":false}""";

        string mockBase = _factory.MockUpstream.Urls[0];
        string indexPath = Dependably.Api.CargoController.IndexPath(name);
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{indexPath}").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/plain")
                .WithBody(upstreamLine));

        await SeedCargoUpstreamAsync(mockBase);
        await SetAnonymousPullAsync(true);
        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);
            var resp = await client.GetAsync($"/cargo/{indexPath}");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            Assert.Contains(version, body);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
            await RemoveCargoUpstreamsAsync();
        }
    }

    // ── Crate download ────────────────────────────────────────────────────────

    [Fact]
    public async Task GetCrate_StoredInBlobStore_Returns200WithBytes()
    {
        string name = $"blobcrate{Guid.NewGuid():N}"[..15].ToLowerInvariant();
        string version = "1.2.3";
        byte[] fakeBytes = "fake-crate-contents"u8.ToArray();

        // Pre-store the crate blob.
        string orgId = await DefaultOrgIdAsync();
        string blobKey = Dependably.Storage.BlobKeys.Cargo(orgId, name, version);
        await _factory.BlobStore.PutAsync(blobKey, new MemoryStream(fakeBytes));

        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            byte[] body = await resp.Content.ReadAsByteArrayAsync();
            Assert.Equal(fakeBytes, body);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task GetCrate_NoBlobNoUpstream_Returns404()
    {
        await RemoveCargoUpstreamsAsync();
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/cargo/api/v1/crates/nonexistent-crate/9.9.9/download");
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    // ── Cache-access recording ──────────────────────────────────────────────────

    private void StubCrateDownload(string name, string version, byte[] bytes)
    {
        // BuildCrateDownloadUrl appends /api/v1/crates/{name}/{version}/download for a
        // non-crates.io upstream base.
        _factory.MockUpstream
            .Given(Request.Create()
                .WithPath($"/api/v1/crates/{name}/{version}/download")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(bytes));
    }

    private async Task<(long? AccessCount, bool ArtifactExists)> ReadCacheStateAsync(
        string orgId, string name, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        bool exists = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM cache_artifact
            WHERE ecosystem = 'cargo' AND name = @name AND version = @version
            """,
            new { name, version }) > 0;
        long? count = await conn.ExecuteScalarAsync<long?>(
            """
            SELECT taa.access_count
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE ca.ecosystem = 'cargo' AND ca.name = @name AND ca.version = @version
              AND taa.org_id = @orgId
            """,
            new { name, version, orgId });
        return (count, exists);
    }

    [Fact]
    public async Task GetCrate_ProxyFetch_IndexCksumMatches_Returns200AndCaches()
    {
        string name = $"ckokcrate{Guid.NewGuid():N}"[..15].ToLowerInvariant();
        string version = "1.0.0";
        byte[] crateBytes = "verified-crate-bytes"u8.ToArray();
        string cksum = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(crateBytes)).ToLowerInvariant();
        string upstreamLine =
            $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"{{cksum}}","features":{},"yanked":false}""";

        string mockBase = _factory.MockUpstream.Urls[0];
        string indexPath = Dependably.Api.CargoController.IndexPath(name);
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{indexPath}").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/plain")
                .WithBody(upstreamLine));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/api/v1/crates/{name}/{version}/download").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(crateBytes));

        await SeedCargoUpstreamAsync(mockBase);
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            byte[] body = await resp.Content.ReadAsByteArrayAsync();
            Assert.Equal(crateBytes, body);

            // The verified blob is cached under the org-scoped Cargo key.
            string orgId = await DefaultOrgIdAsync();
            Assert.True(await _factory.BlobStore.ExistsAsync(
                Dependably.Storage.BlobKeys.Cargo(orgId, name, version)));
        }
        finally
        {
            await SetAnonymousPullAsync(false);
            await RemoveCargoUpstreamsAsync();
        }
    }

    [Fact]
    public async Task GetCrate_ProxyFetch_IndexCksumMismatch_Returns502AndDoesNotCache()
    {
        string name = $"ckbadcrate{Guid.NewGuid():N}"[..15].ToLowerInvariant();
        string version = "1.0.0";
        byte[] crateBytes = "tampered-crate-bytes"u8.ToArray();
        // A valid-shape SHA-256 hex that cannot match the body.
        string wrongCksum = new('a', 64);
        string upstreamLine =
            $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"{{wrongCksum}}","features":{},"yanked":false}""";

        string mockBase = _factory.MockUpstream.Urls[0];
        string indexPath = Dependably.Api.CargoController.IndexPath(name);
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{indexPath}").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/plain")
                .WithBody(upstreamLine));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/api/v1/crates/{name}/{version}/download").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(crateBytes));

        await SeedCargoUpstreamAsync(mockBase);
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");

            Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);

            // The tampered bytes must not be cached for later requests to hit.
            string orgId = await DefaultOrgIdAsync();
            Assert.False(await _factory.BlobStore.ExistsAsync(
                Dependably.Storage.BlobKeys.Cargo(orgId, name, version)));
        }
        finally
        {
            await SetAnonymousPullAsync(false);
            await RemoveCargoUpstreamsAsync();
        }
    }

    [Fact]
    public async Task GetCrate_ProxyFirstFetch_RecordsCacheArtifactAndTenantAccess()
    {
        string name = $"cachecrate{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string version = "3.1.4";
        byte[] crateBytes = "proxied-crate-bytes"u8.ToArray();
        string orgId = await DefaultOrgIdAsync();

        string mockBase = _factory.MockUpstream.Urls[0];
        StubCrateDownload(name, version, crateBytes);
        await SeedCargoUpstreamAsync(mockBase);
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();

            // First fetch (cache miss → proxy).
            var resp1 = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");
            Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);

            var (firstCount, firstExists) = await ReadCacheStateAsync(orgId, name, version);
            Assert.True(firstExists, "cache_artifact row should exist after proxy fetch.");
            Assert.Equal(1, firstCount);

            // Second fetch (cache hit) bumps the per-tenant access count.
            var resp2 = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");
            Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);

            var (secondCount, secondExists) = await ReadCacheStateAsync(orgId, name, version);
            Assert.True(secondExists);
            Assert.Equal(2, secondCount);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
            await RemoveCargoUpstreamsAsync();
        }
    }

    [Fact]
    public async Task GetCrate_HostedCrate_DoesNotRecordCacheArtifact()
    {
        string name = $"hostedcrate{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string version = "1.0.0";
        string indexLine = $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"abc","features":{},"yanked":false}""";
        byte[] crateBytes = "hosted-crate-bytes"u8.ToArray();

        // Seed a hosted (origin='uploaded') version + its blob.
        await SeedLocalCrateAsync(name, version, indexLine);
        string orgId = await DefaultOrgIdAsync();
        string blobKey = Dependably.Storage.BlobKeys.Cargo(orgId, name, version);
        await _factory.BlobStore.PutAsync(blobKey, new MemoryStream(crateBytes));

        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            var (_, hostedExists) = await ReadCacheStateAsync(orgId, name, version);
            Assert.False(hostedExists, "hosted crate must not create a cache_artifact row.");
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    private async Task<string> CreateOtherOrgPullTokenAsync()
    {
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var other = await orgRepo.CreateOrgAsync($"cargo-other-{Guid.NewGuid():N}"[..16]);
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            other.Id,
            $"xcargo-{Guid.NewGuid():N}"[..16],
            """["read:artifact","read:metadata"]""",
            expiresAt: null);
        return raw;
    }

    // ── ETag / conditional GET (sparse index) ───────────────────────────────────

    [Fact]
    public async Task GetIndex_LocalVersion_EmitsStrongETag_And304OnIfNoneMatch()
    {
        string name = $"etagcrate{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string version = "1.0.0";
        string indexLine = $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"abc","features":{},"yanked":false}""";

        await SeedLocalCrateAsync(name, version, indexLine);
        await RemoveCargoUpstreamsAsync();
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            string idx = Dependably.Api.CargoController.IndexPath(name);

            var first = await client.GetAsync($"/cargo/{idx}");
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            string? etag = first.Headers.ETag?.Tag;
            Assert.False(string.IsNullOrEmpty(etag));
            // Strong ETag: quoted, no weak (W/) prefix.
            Assert.StartsWith("\"", etag);
            Assert.False(first.Headers.ETag!.IsWeak);
            // Local-only (no upstream) response carries the longer cache TTL.
            Assert.Contains("max-age=300", first.Headers.CacheControl?.ToString() ?? "");

            // A conditional GET with the same ETag yields 304 and re-emits the ETag.
            using var conditional = _factory.CreateClient();
            conditional.DefaultRequestHeaders.IfNoneMatch.Add(
                EntityTagHeaderValue.Parse(etag));
            var second = await conditional.GetAsync($"/cargo/{idx}");
            Assert.Equal(HttpStatusCode.NotModified, second.StatusCode);
            Assert.Equal(etag, second.Headers.ETag?.Tag);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task GetIndex_StaleIfNoneMatch_Returns200WithFreshBody()
    {
        string name = $"etagstale{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string version = "1.0.0";
        string indexLine = $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"abc","features":{},"yanked":false}""";

        await SeedLocalCrateAsync(name, version, indexLine);
        await RemoveCargoUpstreamsAsync();
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            string idx = Dependably.Api.CargoController.IndexPath(name);

            // A non-matching ETag must not short-circuit; the body is served fresh.
            client.DefaultRequestHeaders.IfNoneMatch.Add(
                EntityTagHeaderValue.Parse("\"0000000000000000\""));
            var resp = await client.GetAsync($"/cargo/{idx}");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            Assert.Contains(version, body);
            Assert.NotEqual("\"0000000000000000\"", resp.Headers.ETag?.Tag);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task GetConfig_TokenFromOtherOrg_AnonymousPullOff_Returns401()
    {
        await SetAnonymousPullAsync(false);
        try
        {
            string crossToken = await CreateOtherOrgPullTokenAsync();
            using var client = _factory.CreateClientWithBearer(crossToken);
            var resp = await client.GetAsync("/cargo/config.json");

            // Cross-org token coerces to null, so AnonymousPull governs — and it is off.
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task GetIndex_TokenFromOtherOrg_AnonymousPullOff_Returns401()
    {
        string name = $"xorgidx{Guid.NewGuid():N}"[..15].ToLowerInvariant();
        string version = "1.0.0";
        string indexLine = $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"abc","features":{},"yanked":false}""";

        // Seed a real local crate in the default org so the gate — not a 404 — is what 401s.
        await SeedLocalCrateAsync(name, version, indexLine);
        await RemoveCargoUpstreamsAsync();
        await SetAnonymousPullAsync(false);
        try
        {
            string crossToken = await CreateOtherOrgPullTokenAsync();
            using var client = _factory.CreateClientWithBearer(crossToken);
            string idx = Dependably.Api.CargoController.IndexPath(name);
            var resp = await client.GetAsync($"/cargo/{idx}");

            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task UpstreamFetch_CargoDownloadUrl_OverSizeCap_ThrowsTooLargeAndCachesNothing()
    {
        long overCap = UpstreamClient.MaxUpstreamResponseBytes + 1;
        var handler = new CargoSizeCapHandler(overCap);
        var blob = new Dependably.Storage.InMemoryBlobStore();
        var audit = new AuditRepository(new CargoAuditMetadataStore());
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build();

        var client = new UpstreamClient(
            new CargoSingleClientFactory(handler),
            new TieredBlobStorage(blob, blob),
            audit,
            new CargoAllowAllValidator(),
            new CargoNoAirGap(),
            new CargoUnlimitedDisk(),
            Dependably.Infrastructure.StagingOptions.Resolve(config),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<UpstreamClient>.Instance);

        string blobKey = Dependably.Storage.BlobKeys.Cargo("org-x", "bigcrate", "1.0.0");
        string downloadUrl = "http://upstream.test/api/v1/crates/bigcrate/1.0.0/download";

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() =>
            client.GetOrFetchStreamAsync(blobKey, downloadUrl, null, "cargo", "org-x"));

        // The fail-fast happens before the body is read, so nothing is cached.
        Assert.False(await blob.ExistsAsync(blobKey));
    }

    [Fact]
    public void RealUpstreamUrlValidator_CargoShapedMetadataEndpointUrl_IsBlocked()
    {
        // A crate-download URL aimed at the AWS/GCP link-local metadata service (169.254.169.254).
        string ssrfUrl = "http://169.254.169.254/api/v1/crates/evil/1.0.0/download";
        string? problem = UpstreamUrlValidator.ValidateUrl(ssrfUrl);
        Assert.NotNull(problem);
        Assert.Contains("blocked", problem, StringComparison.OrdinalIgnoreCase);

        // And the sparse-index metadata URL shape is rejected identically.
        string ssrfIndexUrl = "https://169.254.169.254/ev/il/evil";
        Assert.NotNull(UpstreamUrlValidator.ValidateUrl(ssrfIndexUrl));
    }

    // ── Publish ─────────────────────────────────────────────────────────────────

    // Builds the binary publish frame: LE u32 metadata length, JSON metadata, LE u32 crate
    // length, crate bytes. A declaredCrateLen override lets a test lie about the crate size
    // to exercise the pre-storage 413 gate.
    private static byte[] BuildPublishFrame(string metadataJson, byte[] crateBytes, uint? declaredCrateLen = null)
    {
        byte[] meta = System.Text.Encoding.UTF8.GetBytes(metadataJson);
        byte[] buf = new byte[4 + meta.Length + 4 + crateBytes.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)meta.Length);
        meta.CopyTo(buf, 4);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            buf.AsSpan(4 + meta.Length), declaredCrateLen ?? (uint)crateBytes.Length);
        crateBytes.CopyTo(buf, 4 + meta.Length + 4);
        return buf;
    }

    private static ByteArrayContent FrameContent(byte[] frame)
    {
        var content = new ByteArrayContent(frame);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return content;
    }

    private static string MetadataJson(string name, string version) =>
        $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"features":{},"description":"a test crate"}""";

    [Fact]
    public async Task Publish_HappyPath_StoresVersionAndServesIndexAndDownload()
    {
        string name = $"pubcrate{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string version = "1.0.0";
        byte[] crate = "real-crate-bytes-for-publish"u8.ToArray();
        string expectedCksum = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(crate)).ToLowerInvariant();

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var pubResp = await client.PutAsync("/cargo/api/v1/crates/new",
            FrameContent(BuildPublishFrame(MetadataJson(name, version), crate)));

        Assert.Equal(HttpStatusCode.OK, pubResp.StatusCode);
        string warningsBody = await pubResp.Content.ReadAsStringAsync();
        using (var doc = JsonDocument.Parse(warningsBody))
        {
            Assert.True(doc.RootElement.TryGetProperty("warnings", out var w));
            Assert.True(w.TryGetProperty("invalid_categories", out _));
            Assert.True(w.TryGetProperty("other", out _));
        }

        // Index shows the line with the correct cksum and yanked:false.
        string idx = Dependably.Api.CargoController.IndexPath(name);
        var indexResp = await client.GetAsync($"/cargo/{idx}");
        Assert.Equal(HttpStatusCode.OK, indexResp.StatusCode);
        string indexBody = await indexResp.Content.ReadAsStringAsync();
        Assert.Contains($"\"cksum\":\"{expectedCksum}\"", indexBody);
        Assert.Contains("\"yanked\":false", indexBody);

        // The crate is downloadable and serves the exact bytes.
        var dlResp = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");
        Assert.Equal(HttpStatusCode.OK, dlResp.StatusCode);
        Assert.Equal(crate, await dlResp.Content.ReadAsByteArrayAsync());

        // The version row has origin='uploaded'.
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? origin = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.origin FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'cargo' AND p.name = @name AND pv.version = @version
            """,
            new { orgId, name, version });
        Assert.Equal("uploaded", origin);
    }

    [Fact]
    public async Task Publish_DuplicateVersion_Returns409()
    {
        string name = $"dupcrate{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string version = "1.0.0";
        byte[] crate = "crate-bytes"u8.ToArray();

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var first = await client.PutAsync("/cargo/api/v1/crates/new",
            FrameContent(BuildPublishFrame(MetadataJson(name, version), crate)));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var second = await client.PutAsync("/cargo/api/v1/crates/new",
            FrameContent(BuildPublishFrame(MetadataJson(name, version), crate)));
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Publish_NoToken_Returns401()
    {
        string name = $"noauth{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        using var client = _factory.CreateClient();
        var resp = await client.PutAsync("/cargo/api/v1/crates/new",
            FrameContent(BuildPublishFrame(MetadataJson(name, "1.0.0"), "x"u8.ToArray())));
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Publish_PullOnlyToken_Returns403()
    {
        string name = $"pullonly{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.PutAsync("/cargo/api/v1/crates/new",
            FrameContent(BuildPublishFrame(MetadataJson(name, "1.0.0"), "x"u8.ToArray())));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Publish_DeclaredCrateLengthOverflow_Returns400BeforeStorage()
    {
        // Declare a crate length larger than the bytes actually present: the frame header
        // range-check rejects it as malformed before any storage.
        string name = $"overflow{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        byte[] crate = "tiny"u8.ToArray();
        byte[] frame = BuildPublishFrame(MetadataJson(name, "1.0.0"), crate, declaredCrateLen: 100_000_000u);

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.PutAsync("/cargo/api/v1/crates/new", FrameContent(frame));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);

        // Nothing was stored.
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM packages WHERE org_id = @orgId AND ecosystem = 'cargo' AND name = @name",
            new { orgId, name });
        Assert.Equal(0, count);
    }

    // ── Yank / unyank ─────────────────────────────────────────────────────────────

    private static async Task PublishCrateAsync(HttpClient client, string name, string version, byte[] crate)
    {
        var resp = await client.PutAsync("/cargo/api/v1/crates/new",
            FrameContent(BuildPublishFrame(MetadataJson(name, version), crate)));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Yank_MarksIndexYankedAndReturnsOk_VersionStillDownloadable()
    {
        string name = $"yankcrate{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string version = "1.0.0";
        byte[] crate = "yankable-crate"u8.ToArray();

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        await PublishCrateAsync(client, name, version, crate);

        var yankResp = await client.DeleteAsync($"/cargo/api/v1/crates/{name}/{version}/yank");
        Assert.Equal(HttpStatusCode.OK, yankResp.StatusCode);
        using (var doc = JsonDocument.Parse(await yankResp.Content.ReadAsStringAsync()))
        {
            Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        }

        // Index line now shows yanked:true.
        string idx = Dependably.Api.CargoController.IndexPath(name);
        string indexBody = await (await client.GetAsync($"/cargo/{idx}")).Content.ReadAsStringAsync();
        Assert.Contains("\"yanked\":true", indexBody);

        // Yank hides from resolution but does not delete — the crate is still downloadable.
        var dl = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");
        Assert.Equal(HttpStatusCode.OK, dl.StatusCode);
        Assert.Equal(crate, await dl.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task Unyank_RestoresIndexYankedFalse()
    {
        string name = $"unyank{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string version = "2.0.0";

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        await PublishCrateAsync(client, name, version, "bytes"u8.ToArray());

        await client.DeleteAsync($"/cargo/api/v1/crates/{name}/{version}/yank");
        var unyankResp = await client.PutAsync($"/cargo/api/v1/crates/{name}/{version}/unyank", null);
        Assert.Equal(HttpStatusCode.OK, unyankResp.StatusCode);

        string idx = Dependably.Api.CargoController.IndexPath(name);
        string indexBody = await (await client.GetAsync($"/cargo/{idx}")).Content.ReadAsStringAsync();
        Assert.Contains("\"yanked\":false", indexBody);
    }

    [Fact]
    public async Task Yank_UnknownCrate_Returns404()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.DeleteAsync("/cargo/api/v1/crates/nonexistent-yank/9.9.9/yank");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Yank_PullOnlyToken_Returns403()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.DeleteAsync("/cargo/api/v1/crates/anything/1.0.0/yank");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Search ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Search_NoMatch_ReturnsEmptyWellFormedPayload()
    {
        await RemoveCargoUpstreamsAsync();
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/cargo/api/v1/crates?q=zzz-no-such-crate");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);
            Assert.True(doc.RootElement.TryGetProperty("crates", out var crates));
            Assert.Equal(JsonValueKind.Array, crates.ValueKind);
            Assert.Equal(0, crates.GetArrayLength());
            Assert.True(doc.RootElement.TryGetProperty("meta", out var meta));
            Assert.Equal(0, meta.GetProperty("total").GetInt32());
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task Search_MatchesHostedCrate_ReturnsSnakeCaseShape()
    {
        string name = $"srch{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        string version = "1.2.3";
        string indexLine = $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"abc","features":{},"yanked":false}""";

        await SeedLocalCrateAsync(name, version, indexLine);
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates?q={name}");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);

            var crates = doc.RootElement.GetProperty("crates");
            Assert.Equal(JsonValueKind.Array, crates.ValueKind);
            Assert.Equal(1, crates.GetArrayLength());

            var entry = crates[0];
            // The Cargo client expects snake_case keys — verify max_version is present.
            Assert.Equal(name, entry.GetProperty("name").GetString());
            Assert.True(entry.TryGetProperty("max_version", out var maxVer),
                "Response must carry max_version (snake_case, not maxVersion).");
            Assert.Equal(version, maxVer.GetString());
            Assert.True(entry.TryGetProperty("description", out _),
                "Response must carry description field.");

            Assert.Equal(1, doc.RootElement.GetProperty("meta").GetProperty("total").GetInt32());
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task Search_NoToken_AnonymousPullOff_Returns401()
    {
        await SetAnonymousPullAsync(false);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/cargo/api/v1/crates?q=anything");
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task Search_MixedHostedCrates_ReturnsOnlyMatchingCrate()
    {
        // Seed two crates with distinct names; search only returns the one matching the query.
        string nameA = $"srchaa{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        string nameB = $"srchbb{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        string idxA = $$"""{"name":"{{nameA}}","vers":"1.0.0","deps":[],"cksum":"aaa","features":{},"yanked":false}""";
        string idxB = $$"""{"name":"{{nameB}}","vers":"2.0.0","deps":[],"cksum":"bbb","features":{},"yanked":false}""";

        await SeedLocalCrateAsync(nameA, "1.0.0", idxA);
        await SeedLocalCrateAsync(nameB, "2.0.0", idxB);
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            // Query with nameA prefix — should only see nameA.
            var resp = await client.GetAsync($"/cargo/api/v1/crates?q={nameA}");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);

            var crates = doc.RootElement.GetProperty("crates");
            Assert.Equal(1, crates.GetArrayLength());
            Assert.Equal(nameA, crates[0].GetProperty("name").GetString());
            Assert.Equal("1.0.0", crates[0].GetProperty("max_version").GetString());

            // nameB is not present in the result.
            bool hasBInResult = false;
            foreach (var c in crates.EnumerateArray())
            {
                if (c.GetProperty("name").GetString() == nameB)
                {
                    hasBInResult = true;
                    break;
                }
            }
            Assert.False(hasBInResult, "Non-matching crate must not appear in search results.");

            // Total reflects only the matching crate, not both seeded ones.
            Assert.Equal(1, doc.RootElement.GetProperty("meta").GetProperty("total").GetInt32());
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task Search_SomeCratesHaveAllVersionsYanked_StillReturnsVersionFallback()
    {
        // Mixed-state scenario: one crate has a live version, one has all versions yanked.
        // The search result should return both crates; the all-yanked one falls back to the
        // most-recently-created version as max_version (house rule: yanked versions are still
        // visible in search results so operators can discover them).
        string nameOk = $"srchok{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        string nameYanked = $"srchyk{Guid.NewGuid():N}"[..12].ToLowerInvariant();

        string idxOk = $$"""{"name":"{{nameOk}}","vers":"1.0.0","deps":[],"cksum":"c1","features":{},"yanked":false}""";
        string idxYanked = $$"""{"name":"{{nameYanked}}","vers":"2.0.0","deps":[],"cksum":"c2","features":{},"yanked":true}""";

        await SeedLocalCrateAsync(nameOk, "1.0.0", idxOk);
        await SeedLocalCrateAsync(nameYanked, "2.0.0", idxYanked);

        // Mark the yanked crate's version as yanked in the DB so ResolveMaxVersionAsync
        // falls through to the all-yanked fallback path.
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE package_versions SET yanked = 1
            WHERE package_id = (
                SELECT id FROM packages WHERE org_id = @orgId AND ecosystem = 'cargo' AND purl_name = @name
            )
            """,
            new { orgId, name = nameYanked });

        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates?q=srch");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);

            var crates = doc.RootElement.GetProperty("crates");
            // Both crates appear (the yanked one falls back to its only version).
            Assert.True(crates.GetArrayLength() >= 2,
                "Both crates (including the all-yanked one) must appear in search results.");

            // Every entry carries a non-empty max_version.
            foreach (var entry in crates.EnumerateArray())
            {
                string entryName = entry.GetProperty("name").GetString() ?? "";
                if (entryName == nameOk || entryName == nameYanked)
                {
                    string mv = entry.GetProperty("max_version").GetString() ?? "";
                    Assert.False(string.IsNullOrEmpty(mv),
                        $"max_version must not be empty for {entryName}.");
                }
            }
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    // Inserts a package row with is_proxy=1 and one version with origin='proxy'.
    // Simulates the state left by a successful cargo proxy fetch (no cargo_metadata row
    // is needed because ListPaginatedAsync works off the packages table directly).
    private async Task SeedProxyCrateAsync(string name, string version)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        string pkgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@id, @orgId, 'cargo', @name, @purlName, 1)
            ON CONFLICT (org_id, ecosystem, purl_name) DO UPDATE SET id = packages.id
            """,
            new { id = pkgId, orgId, name, purlName = name });

        pkgId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM packages WHERE org_id = @orgId AND ecosystem = 'cargo' AND purl_name = @name",
            new { orgId, name }))!;

        string blobKey = Dependably.Storage.BlobKeys.Cargo(orgId, name, version);
        string purl = $"pkg:cargo/{name}@{version}";
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin)
            VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, 0, 'proxy')
            ON CONFLICT DO NOTHING
            """,
            new { id = Guid.NewGuid().ToString("N"), pkgId, version, purl, blobKey, filename = $"{name}-{version}.crate" });
    }

    [Fact]
    public async Task Search_ProxyCachedCrate_AppearsInResults()
    {
        // Pins the behavior: ListPaginatedAsync applies no is_proxy filter so proxy-cached
        // crates are searchable. Both a hosted crate and a proxy-cached crate in the same
        // org must surface in cargo search results.
        string hostedName = $"hosted{Guid.NewGuid():N}"[..13].ToLowerInvariant();
        string proxyName = $"proxied{Guid.NewGuid():N}"[..13].ToLowerInvariant();
        string idxLine = $$"""{"name":"{{hostedName}}","vers":"1.0.0","deps":[],"cksum":"h1","features":{},"yanked":false}""";

        await SeedLocalCrateAsync(hostedName, "1.0.0", idxLine);
        await SeedProxyCrateAsync(proxyName, "2.0.0");

        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();

            // Search for the proxy crate specifically.
            var resp = await client.GetAsync($"/cargo/api/v1/crates?q={proxyName}");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);

            var crates = doc.RootElement.GetProperty("crates");
            Assert.Equal(JsonValueKind.Array, crates.ValueKind);

            bool proxyFound = false;
            foreach (var entry in crates.EnumerateArray())
            {
                if (entry.GetProperty("name").GetString() == proxyName)
                {
                    proxyFound = true;
                    // max_version reflects the proxy-cached version.
                    Assert.Equal("2.0.0", entry.GetProperty("max_version").GetString());
                    break;
                }
            }
            Assert.True(proxyFound, "Proxy-cached crate must appear in cargo search results.");

            // Total reflects the proxy crate (search was scoped to proxyName).
            Assert.True(
                doc.RootElement.GetProperty("meta").GetProperty("total").GetInt32() >= 1,
                "meta.total must be at least 1 when a proxy-cached crate matches the query.");
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    // ── Owners ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetOwners_KnownCrate_ReturnsOrgMembersAsOwners()
    {
        string name = $"owncrate{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string version = "1.0.0";
        string indexLine = $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"abc","features":{},"yanked":false}""";

        await SeedLocalCrateAsync(name, version, indexLine);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/owners");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);

        Assert.True(doc.RootElement.TryGetProperty("users", out var users));
        Assert.Equal(JsonValueKind.Array, users.ValueKind);
        // At least the admin user is an owner in the default org.
        Assert.True(users.GetArrayLength() > 0);

        // Each entry carries id, login, kind in the crates.io protocol shape.
        foreach (var u in users.EnumerateArray())
        {
            Assert.True(u.TryGetProperty("id", out _));
            Assert.True(u.TryGetProperty("login", out _));
            Assert.Equal("user", u.GetProperty("kind").GetString());
        }
    }

    [Fact]
    public async Task GetOwners_UnknownCrate_Returns404()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync("/cargo/api/v1/crates/nonexistent-crate-owners/owners");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task GetOwners_NoToken_Returns401()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/cargo/api/v1/crates/anything/owners");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task AddOwners_Returns501WithExplicitMessage()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.PutAsync(
            "/cargo/api/v1/crates/some-crate/owners",
            new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.NotImplemented, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        string? detail = doc.RootElement.GetProperty("detail").GetString();
        Assert.NotNull(detail);
        Assert.Contains("not supported", detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RemoveOwners_Returns501WithExplicitMessage()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.DeleteAsync("/cargo/api/v1/crates/some-crate/owners");

        Assert.Equal(HttpStatusCode.NotImplemented, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        string? detail = doc.RootElement.GetProperty("detail").GetString();
        Assert.NotNull(detail);
        Assert.Contains("not supported", detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Search_AnonymousPullOn_NoToken_Returns200()
    {
        // Validate the anonymous-pull gate works for search without auth.
        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/cargo/api/v1/crates?q=foo");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }
}

/// <summary>
/// HttpMessageHandler that returns a 200 declaring a Content-Length above the cap with a
/// tiny body. The declared length alone trips UpstreamClient's fail-fast; the body is never
/// read (and would throw if it were).
/// </summary>
file sealed class CargoSizeCapHandler : HttpMessageHandler
{
    private readonly long _declaredLength;

    public CargoSizeCapHandler(long declaredLength) => _declaredLength = declaredLength;

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var content = new ByteArrayContent("x"u8.ToArray());
        content.Headers.ContentLength = _declaredLength;
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        return Task.FromResult(response);
    }
}

/// <summary>IHttpClientFactory backed by a single fake handler.</summary>
file sealed class CargoSingleClientFactory : IHttpClientFactory
{
    private readonly HttpClient _client;
    public CargoSingleClientFactory(HttpMessageHandler handler) => _client = new HttpClient(handler);
    public HttpClient CreateClient(string name) => _client;
}

/// <summary>Allows every URL — the size-cap path under test is upstream of any SSRF check here.</summary>
file sealed class CargoAllowAllValidator : IUpstreamUrlValidator
{
    public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
        => Task.FromResult(true);
}

/// <summary>Air-gap disabled so the fetch proceeds to the size-cap check.</summary>
file sealed class CargoNoAirGap : IAirGapMode
{
    public bool IsEnabled => false;
    public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
    public bool IsJobDisabled(string jobName) => false;
}

/// <summary>Staging disk reports ample free space so the disk-floor guard is satisfied.</summary>
file sealed class CargoUnlimitedDisk : IStagingDiskInfo
{
    public long GetAvailableBytes() => long.MaxValue;
    public long GetTotalBytes() => long.MaxValue;
    public long GetStagingDirectoryUsedBytes() => 0;
}

/// <summary>
/// In-memory metadata store carrying just the audit_log table AuditRepository writes to —
/// the size-cap path emits an "upstream_response_too_large" audit event before throwing.
/// </summary>
file sealed class CargoAuditMetadataStore : IMetadataStore
{
    public DbProvider Provider => DbProvider.Sqlite;

    public Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
    {
        var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL DEFAULT 'tenant',
                org_id TEXT, actor_id TEXT, actor_kind TEXT, action TEXT NOT NULL,
                ecosystem TEXT, purl TEXT, detail TEXT, source_ip TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
            """;
        cmd.ExecuteNonQuery();
        return Task.FromResult<System.Data.Common.DbConnection>(conn);
    }
}
