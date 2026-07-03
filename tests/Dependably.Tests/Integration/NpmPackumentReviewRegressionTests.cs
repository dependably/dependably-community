using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Fail-before/pass-after regressions for the npm packument serving path:
///
///  1. Scoped per-version metadata (<c>GET /npm/@scope%2Fname/{version}</c>) decodes the
///     route name — undecoded it fails the upstream-safety check and 404s for every
///     scoped package.
///  2. A claim flip (local_only → mixed) serves the fresh merged view immediately: the
///     local and passthrough paths cache under distinct key variants, so neither path
///     can serve the other's stale body until TTL.
///  3. A revalidating request (If-None-Match) on a cold cache still populates the rendered
///     cache and answers 304 — the conditional-request decision happens against the rebuilt
///     bytes, never inside the rebuild.
///  4. The local packument path checks the AnonymousPull auth gate before package existence,
///     so anonymous callers cannot enumerate private hosted names via 404-vs-401.
///  5. The tenant's persisted dist-tags are applied to the proxy-merged packument (local
///     tags win on collision), and spliced local versions get a time[] entry.
///  6. An upstream packument entry whose local row is hard-blocked (e.g. scanned malicious)
///     is removed from the merged packument, with dist-tags repaired — parity with the
///     tarball endpoint's 403. Yanked local versions are likewise not spliced.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmPackumentReviewRegressionTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── 1. scoped per-version metadata route-name decoding ────────────────────

    [Fact]
    public async Task ScopedPerVersionMetadata_EncodedSlash_ReturnsVersionObject()
    {
        string scope = $"@fixscope{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        string shortName = $"pkg{Guid.NewGuid():N}"[..10].ToLowerInvariant();
        string fullName = $"{scope}/{shortName}";

        await _factory.PushNpmPackage(fullName, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // npm requests scoped per-version metadata with the slash percent-encoded; ASP.NET
        // keeps %2F encoded in the route value, so the handler must decode it.
        var resp = await client.GetAsync($"/npm/{scope}%2f{shortName}/1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(fullName, doc.RootElement.GetProperty("name").GetString());
        Assert.Equal("1.0.0", doc.RootElement.GetProperty("version").GetString());
        Assert.True(doc.RootElement.GetProperty("dist").TryGetProperty("tarball", out _),
            "per-version object must carry dist.tarball");
    }

    [Fact]
    public async Task UnscopedPerVersionMetadata_StillReturnsVersionObject()
    {
        string pkg = $"perver{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.2.3");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{pkg}/1.2.3");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("1.2.3", doc.RootElement.GetProperty("version").GetString());
    }

    // ── 2. claim flip serves the fresh path immediately ───────────────────────

    [Fact]
    public async Task ClaimFlip_LocalOnlyToMixed_NextRequestServesMergedPackument()
    {
        string pkg = $"claimflip{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "2.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Warm the local-only cache: the hosted name is implicitly local_only, so the
        // packument shows only the hosted version.
        var localResp = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, localResp.StatusCode);
        using (var localDoc = JsonDocument.Parse(await localResp.Content.ReadAsStringAsync()))
        {
            Assert.False(localDoc.RootElement.GetProperty("versions").TryGetProperty("1.0.0", out _),
                "upstream version must not appear while the name is implicitly local_only");
        }

        StubUpstreamPackument(pkg, "1.0.0");

        // Flip the claim to mixed — the very next request must serve the merged view.
        // No cache eviction here: the local and proxy paths must not share a cache entry.
        await _factory.SeedMixedClaim("npm", pkg);

        var mergedResp = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, mergedResp.StatusCode);
        using var mergedDoc = JsonDocument.Parse(await mergedResp.Content.ReadAsStringAsync());
        var versions = mergedDoc.RootElement.GetProperty("versions");
        Assert.True(versions.TryGetProperty("1.0.0", out _),
            "upstream 1.0.0 must appear immediately after the mixed claim — not after a TTL");
        Assert.True(versions.TryGetProperty("2.0.0", out _),
            "hosted 2.0.0 must remain in the merged packument");
    }

    // ── 3. revalidation populates the rendered cache ──────────────────────────

    [Fact]
    public async Task Revalidation_ColdCache_Returns304_AndPopulatesRenderedCache()
    {
        string pkg = $"revalidate{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        StubUpstreamPackument(pkg, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // First GET: builds and caches the merged packument; capture its ETag.
        var first = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        string etag = Assert.Single(first.Headers.GetValues("ETag"));

        // Go cold again — evict both cache variants directly.
        string orgId = await DefaultOrgIdAsync();
        var packumentCache = _factory.Services.GetRequiredService<RenderedResponseCache<NpmPackumentKey>>();
        packumentCache.Evict(new NpmPackumentKey(orgId, pkg));
        packumentCache.Evict(new NpmPackumentKey(orgId, pkg) { IsProxy = true });

        // Revalidating request on the cold cache: must 304 AND leave the cache populated.
        using var revalidate = new HttpRequestMessage(HttpMethod.Get, $"/npm/{pkg}");
        revalidate.Headers.TryAddWithoutValidation("If-None-Match", etag);
        var notModified = await client.SendAsync(revalidate);
        Assert.Equal(HttpStatusCode.NotModified, notModified.StatusCode);

        Assert.True(packumentCache.TryGet(new NpmPackumentKey(orgId, pkg) { IsProxy = true }, out byte[]? cached)
            && cached is not null,
            "a revalidating request must populate the rendered cache, not bypass it");

        // A plain GET now serves the cached bytes with the same ETag.
        var second = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(etag, Assert.Single(second.Headers.GetValues("ETag")));
    }

    // ── 4. no 404-vs-401 name-existence oracle ────────────────────────────────

    [Fact]
    public async Task AnonymousProbe_LocalPath_HostedAndMissingNames_BothReturn401()
    {
        // Force the local-only serving path for every name in this test: with passthrough
        // off, both a hosted name and a missing name route to ServeLocalPackumentAsync.
        await SetProxyPassthroughAsync(enabled: false);
        try
        {
            string hostedPkg = $"oraclehosted{Guid.NewGuid():N}"[..20].ToLowerInvariant();
            string missingPkg = $"oraclemissing{Guid.NewGuid():N}"[..20].ToLowerInvariant();
            await _factory.PushNpmPackage(hostedPkg, "1.0.0");

            using var anon = _factory.CreateClient();

            var hostedResp = await anon.GetAsync($"/npm/{hostedPkg}");
            Assert.Equal(HttpStatusCode.Unauthorized, hostedResp.StatusCode);

            // The missing name must be indistinguishable from the hosted one: 401, not 404.
            var missingResp = await anon.GetAsync($"/npm/{missingPkg}");
            Assert.Equal(HttpStatusCode.Unauthorized, missingResp.StatusCode);
        }
        finally
        {
            await SetProxyPassthroughAsync(enabled: true);
        }
    }

    // ── 5. local dist-tags in the merged packument ────────────────────────────

    [Fact]
    public async Task MergedPackument_LocalDistTags_WinOverUpstream_AndSplicedTimeEntryAdded()
    {
        string pkg = $"disttag{Guid.NewGuid():N}"[..16].ToLowerInvariant();

        // Hosted publish persists latest → 2.0.0; set a custom tag as well.
        await _factory.PushNpmPackage(pkg, "2.0.0");
        string pushToken = await _factory.CreateToken("push");
        using (var publisher = _factory.CreateClientWithBearer(pushToken))
        {
            using var body = new StringContent("\"2.0.0\"", Encoding.UTF8, "application/json");
            var tagResp = await publisher.PutAsync($"/npm/-/package/{pkg}/dist-tags/beta", body);
            tagResp.EnsureSuccessStatusCode();
        }

        // Upstream knows 1.0.0 and calls it latest.
        StubUpstreamPackument(pkg, "1.0.0");
        await _factory.SeedMixedClaim("npm", pkg);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var versions = doc.RootElement.GetProperty("versions");
        Assert.True(versions.TryGetProperty("1.0.0", out _), "upstream 1.0.0 must be merged in");
        Assert.True(versions.TryGetProperty("2.0.0", out _), "hosted 2.0.0 must be spliced in");

        // The tenant's persisted tags are authoritative: latest points at the hosted
        // version even though upstream's dist-tags said 1.0.0.
        var distTags = doc.RootElement.GetProperty("dist-tags");
        Assert.Equal("2.0.0", distTags.GetProperty("latest").GetString());
        Assert.Equal("2.0.0", distTags.GetProperty("beta").GetString());

        // The spliced hosted version gets a time[] entry from its stored publish timestamp.
        Assert.True(doc.RootElement.GetProperty("time").TryGetProperty("2.0.0", out _),
            "spliced local versions must appear in the time map");
    }

    // ── 6. stored-state parity for colliding upstream entries ─────────────────

    [Fact]
    public async Task MergedPackument_MaliciousLocalRow_RemovesCollidingUpstreamEntry()
    {
        await SetBlockMaliciousAsync("block");
        try
        {
            string pkg = $"malmerge{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            await _factory.PushNpmPackage(pkg, "1.0.0");
            await _factory.PushNpmPackage(pkg, "2.0.0");
            await SeedMalAdvisoryAsync(pkg, "1.0.0");

            // Upstream lists the same two versions and calls the malicious one latest.
            StubUpstreamPackument(pkg, new[] { "1.0.0", "2.0.0" }, latest: "1.0.0");
            await _factory.SeedMixedClaim("npm", pkg);
            await EvictPackumentCacheAsync(pkg);

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);
            var resp = await client.GetAsync($"/npm/{pkg}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var versions = doc.RootElement.GetProperty("versions");
            Assert.False(versions.TryGetProperty("1.0.0", out _),
                "the upstream entry for a locally hard-blocked version must be removed — " +
                "the tarball endpoint 403s it");
            Assert.True(versions.TryGetProperty("2.0.0", out _), "the clean version must survive");

            // latest pointed at the removed version — it must be repaired to a servable one.
            Assert.Equal("2.0.0",
                doc.RootElement.GetProperty("dist-tags").GetProperty("latest").GetString());
            Assert.False(doc.RootElement.GetProperty("time").TryGetProperty("1.0.0", out _),
                "time[] entry for the removed version must be dropped");
        }
        finally
        {
            await SetBlockMaliciousAsync("off");
        }
    }

    [Fact]
    public async Task MergedPackument_YankedLocalVersion_NotSpliced()
    {
        string pkg = $"yankmerge{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.5.0");
        await _factory.PushNpmPackage(pkg, "2.0.0");
        await _factory.SetVersionYanked("default", "npm", pkg, "1.5.0");

        StubUpstreamPackument(pkg, "1.0.0");
        await _factory.SeedMixedClaim("npm", pkg);
        await EvictPackumentCacheAsync(pkg);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var versions = doc.RootElement.GetProperty("versions");
        Assert.False(versions.TryGetProperty("1.5.0", out _),
            "yanked local versions are hidden from the local packument and must not be " +
            "spliced into the merged one either");
        Assert.True(versions.TryGetProperty("1.0.0", out _), "upstream version must be present");
        Assert.True(versions.TryGetProperty("2.0.0", out _), "active hosted version must be present");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Stubs the mock upstream's packument for <paramref name="pkg"/>: the given versions
    /// with time entries safely in the past (frozen far from any release-age window) and
    /// dist-tags.latest set to <paramref name="latest"/> (defaults to the first version).
    /// </summary>
    private void StubUpstreamPackument(string pkg, params string[] versions)
        => StubUpstreamPackument(pkg, versions, latest: versions[0]);

    private void StubUpstreamPackument(string pkg, string[] versions, string latest)
    {
        string upstreamBase = _factory.MockUpstream.Urls[0];
        string versionObjs = string.Join(",", versions.Select(v => $$"""
            "{{v}}": {
              "name": "{{pkg}}",
              "version": "{{v}}",
              "dist": {"tarball":"{{upstreamBase}}/{{pkg}}/-/{{pkg}}-{{v}}.tgz","shasum":"aabbcc"}
            }
            """));
        string timeEntries = string.Join(",", versions.Select(v => $"\"{v}\": \"2020-01-01T00:00:00.000Z\""));
        string upstreamJson = $$"""
            {
              "name": "{{pkg}}",
              "dist-tags": {"latest":"{{latest}}"},
              "versions": { {{versionObjs}} },
              "time": { {{timeEntries}} }
            }
            """;

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{pkg}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose(); // ensure first-boot ran
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task EvictPackumentCacheAsync(string pkgName)
    {
        string orgId = await DefaultOrgIdAsync();
        var packumentCache = _factory.Services.GetRequiredService<RenderedResponseCache<NpmPackumentKey>>();
        packumentCache.Evict(new NpmPackumentKey(orgId, pkgName));
        packumentCache.Evict(new NpmPackumentKey(orgId, pkgName) { IsProxy = true });
    }

    private async Task SetProxyPassthroughAsync(bool enabled)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @enabled WHERE org_id = @orgId",
            new { orgId, enabled = enabled ? 1 : 0 });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetBlockMaliciousAsync(string mode)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET block_malicious = @mode WHERE org_id = @orgId",
            new { orgId, mode });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SeedMalAdvisoryAsync(string pkgName, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        string? versionId = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.id FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.name = @pkgName AND pv.version = @version LIMIT 1
            """,
            new { pkgName, version });
        Assert.NotNull(versionId);

        string vulnId = Guid.NewGuid().ToString("N");
        string malId = $"MAL-2026-{Guid.NewGuid():N}";
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities
                (id, osv_id, ecosystem, package_name, severity, cvss_score, summary, modified_at, fetched_at)
            VALUES
                (@vulnId, @malId, 'npm', @pkgName, NULL, NULL, 'Malicious code',
                 strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { vulnId, malId, pkgName });
        string pvvId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind) VALUES (@pvvId, @versionId, @vulnId, 'package_version')",
            new { pvvId, versionId, vulnId });
        await conn.ExecuteAsync(
            "UPDATE package_versions SET vuln_checked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @versionId",
            new { versionId });
    }
}
