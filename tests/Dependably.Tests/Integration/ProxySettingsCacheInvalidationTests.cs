using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that a proxy-settings policy change (<c>PUT /api/v1/proxy-settings</c>) is
/// reflected on the version-level rendered surfaces (PyPI simple index, npm packument, NuGet
/// registration) on the very next request — without any manual cache eviction and without
/// waiting for <c>METADATA_LOCAL_CACHE_TTL_SECONDS</c>.
///
/// Each case is a fail-before/pass-after regression: on the old code, <c>OrgSettingsController</c>
/// performed no rendered-cache invalidation on the policy PUT, so the pre-flip rendering (with
/// the gate's old verdict baked in) kept being served from the warm cache until its TTL expired.
/// These tests never call <c>RenderedResponseCache.Evict</c> directly — unlike the block-gate
/// parity tests, which evict manually to isolate the renderer's filtering logic from the cache —
/// so they exercise exactly the production invalidation path this fix adds.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProxySettingsCacheInvalidationTests : IAsyncLifetime
{
    // FrozenClock so the release-age gate's age arithmetic is deterministic.
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    /// <summary>
    /// Mixed/partial-failure scenario: a package has one version within a release-age hold and
    /// one version past it. Warm the simple index cache with the pre-policy rendering (both
    /// versions visible), then PUT a 24h release-age hold, then re-GET without any manual evict.
    /// The too-young version must disappear immediately; the old-enough sibling stays listed.
    /// Flipping the hold back off must immediately un-hide the version too — proving the fix
    /// closes the "gate re-permits, but stays HIDDEN for up to the TTL" direction as well as the
    /// "gate blocks, but stays ADVERTISED" direction.
    /// </summary>
    [Fact]
    public async Task PyPiSimpleIndex_ReflectsProxySettingsPolicyFlip_WithoutManualEvictOrTtlWait()
    {
        string name = $"cacheinval{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        await _factory.PushPyPiPackage(name, "2.0.0");

        string underscored = name.Replace('-', '_');
        string youngFile = $"{underscored}-1.0.0-py3-none-any.whl";
        string oldFile = $"{underscored}-2.0.0-py3-none-any.whl";

        var frozenNow = TestTime.KnownNow;
        await StampPublishedAtAsync(name, "1.0.0", frozenNow.AddHours(-1));   // within a 24h hold
        await StampPublishedAtAsync(name, "2.0.0", frozenNow.AddDays(-30));  // past any hold

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Warm the cache with the pre-policy-change rendering: both versions visible.
        var warm = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
        string warmHtml = await warm.Content.ReadAsStringAsync();
        Assert.Contains(youngFile, warmHtml);
        Assert.Contains(oldFile, warmHtml);

        try
        {
            // Flip the policy — no manual cache eviction. Production code (OrgSettingsController)
            // must invalidate the org's rendered-cache epoch as part of this call.
            await SetMinReleaseAgeHoursAsync(24);

            var afterBlock = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, afterBlock.StatusCode);
            string afterBlockHtml = await afterBlock.Content.ReadAsStringAsync();
            Assert.DoesNotContain(youngFile, afterBlockHtml);
            Assert.Contains(oldFile, afterBlockHtml);

            // Flip the policy back off — again no manual eviction. The previously-hidden version
            // must reappear on the very next request.
            await SetMinReleaseAgeHoursAsync(null);

            var afterUnblock = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, afterUnblock.StatusCode);
            string afterUnblockHtml = await afterUnblock.Content.ReadAsStringAsync();
            Assert.Contains(youngFile, afterUnblockHtml);
            Assert.Contains(oldFile, afterUnblockHtml);
        }
        finally
        {
            await SetMinReleaseAgeHoursAsync(null);
        }
    }

    /// <summary>
    /// Same policy-flip-without-manual-eviction proof for the npm packument surface. Mixed
    /// scenario: one version within the hold (excluded), one past it (still listed) in the same
    /// GET, immediately after the PUT.
    /// </summary>
    [Fact]
    public async Task NpmPackument_ReflectsProxySettingsPolicyFlip_WithoutManualEvictOrTtlWait()
    {
        string pkg = $"cacheinvalnpm{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");
        await _factory.PushNpmPackage(pkg, "2.0.0");

        var frozenNow = TestTime.KnownNow;
        await StampPublishedAtAsync(pkg, "1.0.0", frozenNow.AddHours(-1));
        await StampPublishedAtAsync(pkg, "2.0.0", frozenNow.AddDays(-30));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var warm = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
        using (var warmDoc = JsonDocument.Parse(await warm.Content.ReadAsStringAsync()))
        {
            var versions = warmDoc.RootElement.GetProperty("versions");
            Assert.True(versions.TryGetProperty("1.0.0", out _));
            Assert.True(versions.TryGetProperty("2.0.0", out _));
        }

        try
        {
            await SetMinReleaseAgeHoursAsync(24);

            var afterBlock = await client.GetAsync($"/npm/{pkg}");
            Assert.Equal(HttpStatusCode.OK, afterBlock.StatusCode);
            using var afterBlockDoc = JsonDocument.Parse(await afterBlock.Content.ReadAsStringAsync());
            var afterBlockVersions = afterBlockDoc.RootElement.GetProperty("versions");
            Assert.False(afterBlockVersions.TryGetProperty("1.0.0", out _),
                "too-young version must vanish from the packument on the very next request");
            Assert.True(afterBlockVersions.TryGetProperty("2.0.0", out _));
        }
        finally
        {
            await SetMinReleaseAgeHoursAsync(null);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task StampPublishedAtAsync(string pkgName, string version, DateTimeOffset publishedAt)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE package_versions SET published_at = @ts
            WHERE id = (
                SELECT pv.id FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.name = @pkgName AND pv.version = @version LIMIT 1)
            """,
            new { ts = publishedAt.ToString("o"), pkgName, version });
    }

    private async Task SetMinReleaseAgeHoursAsync(int? minReleaseAgeHours)
    {
        string jwt = await _factory.CreateAdminJwt();
        using var adminClient = _factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var put = await adminClient.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            minReleaseAgeHours,
        });
        put.EnsureSuccessStatusCode();
    }
}
