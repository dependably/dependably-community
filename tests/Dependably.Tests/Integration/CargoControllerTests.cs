using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
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
            INSERT INTO cargo_metadata (version_id, index_line)
            VALUES (@versionId, @indexLine)
            ON CONFLICT (version_id) DO UPDATE SET index_line = excluded.index_line
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
}
