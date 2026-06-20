using System.Net;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression tests for the PyPI proxy first-fetch global-plane flip: after a first-fetch,
/// proxy versions must live in <c>cache_artifact</c> + <c>tenant_artifact_access</c> with
/// zero <c>package_versions</c> rows of proxy origin — matching npm, NuGet, Maven, RPM, and
/// Cargo. Before this fix, PyPI dual-wrote: one <c>cache_artifact</c> row plus one
/// <c>package_versions</c> row per tenant per version.
///
/// Mixed partial-failure scenario: two tenants each fetch the same upstream wheel. After
/// both fetches there must be exactly ONE shared <c>cache_artifact</c> row (dedup works),
/// two <c>tenant_artifact_access</c> rows (one per tenant), and zero <c>package_versions</c>
/// rows with origin='proxy' for this coordinate.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiProxyGlobalPlaneTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public PyPiProxyGlobalPlaneTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── helpers ────────────────────────────────────────────────────────────────

    private async Task<string> GetDefaultOrgIdAsync()
    {
        // A real HTTP request ensures the hosted service pipeline (schema init + first-boot)
        // has completed before any direct DB query runs.
        using var bootClient = _factory.CreateClient();
        await bootClient.GetAsync("/health");
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    // Stubs the WireMock upstream to serve the given wheel bytes at the simple-index and file
    // download paths. The simple-index fragment carries the SHA-256 so UpstreamClient can verify
    // inline and take the known-sha (streaming) path rather than the buffered cold-start path.
    private void StubWheelUpstream(string name, string filename, byte[] wheelBytes, string sha256Hex)
    {
        string mockBase = _factory.MockUpstream.Urls[0];
        string simpleHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="{mockBase}/files/{filename}#sha256={sha256Hex}">{filename}</a>
            </body></html>
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody(simpleHtml));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(wheelBytes));
    }

    // ── core regression: no package_versions row on proxy first-fetch ─────────

    /// <summary>
    /// PyPI proxy first-fetch must write to the global plane only: exactly one
    /// <c>cache_artifact</c> row for the coordinate, one <c>tenant_artifact_access</c> row
    /// for the tenant, and zero <c>package_versions</c> rows with origin='proxy'.
    ///
    /// Regression: before the fix the first-fetch pipeline received a null cacheArtifactId
    /// (because the id returned by CacheAccessRecorder was discarded) and fell through to
    /// RecordViaPvRowAsync, writing a duplicate package_versions row.
    ///
    /// This test fails on the pre-fix code (package_versions count = 1, not 0) and passes
    /// after the fix.
    /// </summary>
    [Fact]
    public async Task ProxyFirstFetch_WritesGlobalPlaneOnly_NoPackageVersionsRow()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        string name = $"gp-pypi-ff-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";
        var (wheelBytes, sha256Hex) = PyPiFixtures.BuildWheel(name, "1.0.0");

        StubWheelUpstream(name, filename, wheelBytes, sha256Hex);

        // Trigger the proxy first-fetch via the download endpoint.
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("MISS", resp.Headers.GetValues("X-Cache").FirstOrDefault());

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();

        // Exactly one cache_artifact row for this coordinate.
        long caCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM cache_artifact
            WHERE ecosystem = 'pypi' AND name = @name AND version = '1.0.0' AND filename = @filename
            """,
            new { name, filename });
        Assert.Equal(1, caCount);

        // Exactly one tenant_artifact_access row for this org.
        long taaCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'pypi' AND ca.name = @name
            """,
            new { orgId = defaultOrgId, name });
        Assert.Equal(1, taaCount);

        // Zero package_versions rows with proxy origin for this coordinate (global plane is authoritative).
        long pvCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'pypi' AND p.name = @name
              AND pv.origin = 'proxy'
            """,
            new { orgId = defaultOrgId, name });
        Assert.Equal(0, pvCount);
    }

    /// <summary>
    /// After a proxy first-fetch, a subsequent request for the same file serves from the
    /// cache (X-Cache: HIT) and does not write additional <c>cache_artifact</c> rows.
    /// Confirms the blob is reachable after the global-plane flip.
    /// </summary>
    [Fact]
    public async Task ProxyFirstFetch_SubsequentRequest_ServesFromCache_NoAdditionalCaRow()
    {
        // A real HTTP request ensures the hosted service pipeline has completed before any
        // direct API call runs.
        using (var bootClient = _factory.CreateClient())
        {
            await bootClient.GetAsync("/health");
        }

        string name = $"gp-pypi-hit-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-2.0.0-py3-none-any.whl";
        var (wheelBytes, sha256Hex) = PyPiFixtures.BuildWheel(name, "2.0.0");

        StubWheelUpstream(name, filename, wheelBytes, sha256Hex);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // First request — MISS.
        var resp1 = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);
        Assert.Equal("MISS", resp1.Headers.GetValues("X-Cache").FirstOrDefault());

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();

        long caAfterFirst = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM cache_artifact
            WHERE ecosystem = 'pypi' AND name = @name AND version = '2.0.0' AND filename = @filename
            """,
            new { name, filename });
        Assert.Equal(1, caAfterFirst);

        // Second request — must hit the cache (blob stored under BlobKeys.Proxy(sha256)).
        var resp2 = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);
        Assert.Equal("HIT", resp2.Headers.GetValues("X-Cache").FirstOrDefault());

        // No additional cache_artifact row was inserted.
        long caAfterSecond = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM cache_artifact
            WHERE ecosystem = 'pypi' AND name = @name AND version = '2.0.0' AND filename = @filename
            """,
            new { name, filename });
        Assert.Equal(1, caAfterSecond);
    }

    /// <summary>
    /// Mixed partial-failure scenario (house rule): tenant A performs a real HTTP PyPI proxy
    /// first-fetch, which writes the shared <c>cache_artifact</c> row and tenant A's
    /// <c>tenant_artifact_access</c> row. Tenant B then establishes access to the same shared
    /// coordinate via <c>CacheAccessRecorder</c> — mirroring the global-plane write path —
    /// without performing its own HTTP fetch (the DependablyFactory runs in single-deployment
    /// mode and cannot route an HTTP request to an unregistered second org). After both access
    /// recordings:
    ///   — exactly ONE <c>cache_artifact</c> row exists (dedup; shared global plane).
    ///   — TWO <c>tenant_artifact_access</c> rows exist (one per tenant; per-tenant isolation).
    ///   — ZERO <c>package_versions</c> rows with origin='proxy' for this coordinate.
    ///
    /// Before the fix, the real first-fetch path inserted a <c>package_versions</c> row, so
    /// pvCountA would be 1 and the dedup invariant would be broken. This test fails on the
    /// pre-fix code.
    /// </summary>
    [Fact]
    public async Task ProxyFirstFetch_TwoTenants_SharedCaRow_PerTenantAccessRow_NoPvRows()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();

        // Create a second org (tenant B).
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var orgB = await orgRepo.CreateOrgAsync($"pypi-gp-b-{Guid.NewGuid():N}"[..20]);

        string name = $"gp-pypi-2t-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string version = "3.0.0";
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, sha256Hex) = PyPiFixtures.BuildWheel(name, version);

        StubWheelUpstream(name, filename, wheelBytes, sha256Hex);

        // Tenant A performs a real HTTP proxy first-fetch. This is what proves the production
        // path writes to the global plane only (no package_versions row).
        string tokenA = await _factory.CreateToken("pull");
        using var clientA = _factory.CreateClientWithBasic(tokenA);
        var respA = await clientA.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, respA.StatusCode);
        Assert.Equal("MISS", respA.Headers.GetValues("X-Cache").FirstOrDefault());

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();

        // Confirm the cache_artifact row was created by tenant A's fetch, and retrieve its
        // content hash so tenant B's access recording uses the same coordinate.
        string? contentHash = await conn.ExecuteScalarAsync<string>(
            """
            SELECT ca.content_hash FROM cache_artifact ca
            WHERE ca.ecosystem = 'pypi' AND ca.name = @name
              AND ca.version = @version AND ca.filename = @filename
            LIMIT 1
            """,
            new { name, version, filename });
        Assert.NotNull(contentHash);

        // Tenant B establishes access to the same shared cache_artifact coordinate via
        // CacheAccessRecorder — the same recorder the production first-fetch path calls.
        // Because cache_artifact already exists for this (ecosystem, name, version, filename),
        // RecordAccessAsync finds the existing row and only inserts a tenant_artifact_access
        // row for orgB, preserving the single shared global-plane entry.
        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        await recorder.RecordAccessAsync(new CacheAccess(
            orgB.Id, "pypi", name, version, filename,
            Sha256: contentHash,
            SizeBytes: wheelBytes.Length,
            BlobKey: $"{BlobKeys.Proxy(contentHash)}/{filename}",
            UpstreamUrl: $"{_factory.MockUpstream.Urls[0]}/files/{filename}"));

        // Mirror what the production proxy path also does: ensure orgB has a per-tenant
        // packages row so the package is discoverable in orgB's listings.
        await _factory.Services.GetRequiredService<PackageRepository>()
            .GetOrCreateAsync(orgB.Id, "pypi", name, name, isProxy: true, CancellationToken.None);

        // Exactly one cache_artifact row (shared global plane — dedup is the whole point).
        long caCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM cache_artifact
            WHERE ecosystem = 'pypi' AND name = @name AND version = @version AND filename = @filename
            """,
            new { name, version, filename });
        Assert.Equal(1, caCount);

        // Two tenant_artifact_access rows (one per tenant).
        long taaA = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'pypi' AND ca.name = @name
            """,
            new { orgId = defaultOrgId, name });
        long taaB = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'pypi' AND ca.name = @name
            """,
            new { orgId = orgB.Id, name });
        Assert.Equal(1, taaA);
        Assert.Equal(1, taaB);

        // Zero proxy package_versions rows — the real first-fetch must not dual-write, and
        // orgB's recorder-based access must not create one either.
        long pvCountA = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'pypi' AND p.name = @name AND pv.origin = 'proxy'
            """,
            new { orgId = defaultOrgId, name });
        long pvCountB = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'pypi' AND p.name = @name AND pv.origin = 'proxy'
            """,
            new { orgId = orgB.Id, name });
        Assert.Equal(0, pvCountA);
        Assert.Equal(0, pvCountB);

        // Both tenants discover the package via the global plane.
        var cacheRepo = _factory.Services.GetRequiredService<CacheArtifactRepository>();
        var serveFactsA = await cacheRepo.ListServeFactsForNameAsync(defaultOrgId, "pypi", name);
        var serveFactsB = await cacheRepo.ListServeFactsForNameAsync(orgB.Id, "pypi", name);
        Assert.Single(serveFactsA);
        Assert.Single(serveFactsB);
        Assert.Equal(version, serveFactsA[0].Version);
        Assert.Equal(version, serveFactsB[0].Version);
    }
}
