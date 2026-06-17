using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that every block-gate arm that <c>BlockGateService.EvaluateAsync</c> treats as
/// a hard block is also honoured by the simple-index renderers, so a client can never
/// discover an artifact in <c>/simple/{pkg}/</c> that <c>/packages/{file}</c> will deny
/// with 403.
///
/// Release-age tests use a factory with a frozen host clock so the age arithmetic is
/// deterministic. Other arms (malicious, soft-state guard) live in
/// <see cref="PyPiControllerExtendedTests"/>.
///
/// Each case is a fail-before/pass-after regression: on the old code, which only filtered
/// manual-block and deprecated-block_all, the assertions about absent versions would have
/// failed because the gate arm was not mirrored in the index renderer.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiSimpleIndexBlockGateParityTests : IAsyncLifetime
{
    // FrozenClock is set to TestTime.KnownNow so time-based assertions are deterministic.
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── release-age gate ──────────────────────────────────────────────────────

    /// <summary>
    /// A version published 1 hour ago under a 24-hour hold must be absent from the simple
    /// index AND return 403 on download — fail-before/pass-after for the release-age arm.
    ///
    /// Old code: release-age was not checked in the index renderer, so the version appeared
    /// in the index even though the download gate blocked it.
    /// New code: BlockGateService.IsHardBlockedByStoredState covers the release-age arm, so
    /// the index now hides the version.
    ///
    /// Also verifies partial-failure (mixed) scenario: a second version (older than the hold)
    /// is still listed and downloadable in the same request.
    /// </summary>
    [Fact]
    public async Task SimpleIndex_ReleaseAge_TooYoung_IsAbsentFromIndex_And_DownloadReturns403()
    {
        await SetProxyPassthroughAsync(false);
        try
        {
            string name = $"ageblock{Guid.NewGuid():N}"[..16].ToLowerInvariant();

            // Push two versions: 1.0.0 will be within the hold; 2.0.0 will be well past it.
            await _factory.PushPyPiPackage(name, "1.0.0");
            await _factory.PushPyPiPackage(name, "2.0.0");

            string underscored = name.Replace('-', '_');
            string youngFile = $"{underscored}-1.0.0-py3-none-any.whl";
            string oldFile = $"{underscored}-2.0.0-py3-none-any.whl";

            // Stamp published_at: 1.0.0 = 1 hour before frozen now (within 24h hold).
            //                     2.0.0 = 30 days before frozen now (past the hold).
            var frozenNow = TestTime.KnownNow;
            string youngTs = frozenNow.AddHours(-1).ToString("o");
            string oldTs = frozenNow.AddDays(-30).ToString("o");

            var store = _factory.Services.GetRequiredService<IMetadataStore>();
            await using (var conn = await store.OpenAsync())
            {
                await conn.ExecuteAsync(
                    """
                    UPDATE package_versions SET published_at = @ts
                    WHERE id = (
                        SELECT pv.id FROM package_versions pv
                        JOIN packages p ON p.id = pv.package_id
                        WHERE p.name = @name AND pv.version = '1.0.0' LIMIT 1)
                    """,
                    new { ts = youngTs, name });
                await conn.ExecuteAsync(
                    """
                    UPDATE package_versions SET published_at = @ts
                    WHERE id = (
                        SELECT pv.id FROM package_versions pv
                        JOIN packages p ON p.id = pv.package_id
                        WHERE p.name = @name AND pv.version = '2.0.0' LIMIT 1)
                    """,
                    new { ts = oldTs, name });
            }

            // Set MinReleaseAgeHours = 24 via the proxy-settings API.
            await SetProxySettingsAsync(minReleaseAgeHours: 24);

            // Evict the simple-index cache so the rebuild picks up the new settings.
            var cache = _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>();
            var orgs = _factory.Services.GetRequiredService<OrgRepository>();
            string orgId = (await orgs.GetBySlugAsync("default"))!.Id;
            cache.Evict(new PyPiSimpleIndexKey(orgId, name));

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Simple index must omit the too-young version and retain the old enough version.
            var indexResp = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, indexResp.StatusCode);
            string html = await indexResp.Content.ReadAsStringAsync();
            Assert.DoesNotContain(youngFile, html);   // too young — absent
            Assert.Contains(oldFile, html);            // old enough — still listed

            // Download gate must still return 403 for the too-young file.
            var dlResp = await client.GetAsync($"/packages/{youngFile}");
            Assert.Equal(HttpStatusCode.Forbidden, dlResp.StatusCode);

            // Download of the old-enough file must succeed.
            var dlOkResp = await client.GetAsync($"/packages/{oldFile}");
            Assert.Equal(HttpStatusCode.OK, dlOkResp.StatusCode);
        }
        finally
        {
            await SetProxyPassthroughAsync(true);
            await SetProxySettingsAsync(minReleaseAgeHours: null);
        }
    }

    /// <summary>
    /// Proxy-merge path: a too-young local version must not be injected into the merged
    /// upstream+local index — even when upstream HTML is present and the merge path runs.
    /// The clean local version IS merged in. Fail-before/pass-after: old code did not
    /// filter by release-age in MergeLocalVersionsIntoUpstreamIndex.
    /// </summary>
    [Fact]
    public async Task SimpleIndex_ProxyMerge_ReleaseAge_TooYoungLocalVersion_IsExcludedFromMergedIndex()
    {
        string name = $"amerge{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        await _factory.PushPyPiPackage(name, "2.0.0");
        await _factory.SeedMixedClaim("pypi", name);

        string underscored = name.Replace('-', '_');
        string youngFile = $"{underscored}-1.0.0-py3-none-any.whl";
        string oldFile = $"{underscored}-2.0.0-py3-none-any.whl";

        // 1.0.0: 1 hour ago (too young); 2.0.0: 30 days ago (past the hold).
        var frozenNow = TestTime.KnownNow;
        string youngTs = frozenNow.AddHours(-1).ToString("o");
        string oldTs = frozenNow.AddDays(-30).ToString("o");

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                UPDATE package_versions SET published_at = @ts
                WHERE id = (
                    SELECT pv.id FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.name = @name AND pv.version = '1.0.0' LIMIT 1)
                """,
                new { ts = youngTs, name });
            await conn.ExecuteAsync(
                """
                UPDATE package_versions SET published_at = @ts
                WHERE id = (
                    SELECT pv.id FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.name = @name AND pv.version = '2.0.0' LIMIT 1)
                """,
                new { ts = oldTs, name });
        }

        await SetProxySettingsAsync(minReleaseAgeHours: 24);

        // Evict cache so the rebuild reflects the updated release-age setting.
        var cache = _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>();
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        string orgId = (await orgs.GetBySlugAsync("default"))!.Id;
        cache.Evict(new PyPiSimpleIndexKey(orgId, name));

        // Mock upstream advertising an upstream-only file.
        string upstreamFile = $"{underscored}-0.9.0.tar.gz";
        string mockBase = _factory.MockUpstream.Urls[0];
        string upstreamHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="{mockBase}/files/{upstreamFile}">{upstreamFile}</a>
            </body></html>
            """;
        _factory.MockUpstream
            .Given(WireMock.RequestBuilders.Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(WireMock.ResponseBuilders.Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody(upstreamHtml));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var indexResp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, indexResp.StatusCode);
        string html = await indexResp.Content.ReadAsStringAsync();

        // Upstream-only file is present (verbatim from upstream, not filtered).
        Assert.Contains(upstreamFile, html);
        // Old-enough local version merged in.
        Assert.Contains(oldFile, html);
        // Too-young local version excluded from the merge.
        Assert.DoesNotContain(youngFile, html);

        await SetProxySettingsAsync(minReleaseAgeHours: null);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task SetProxyPassthroughAsync(bool enabled)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetProxySettingsAsync(int? minReleaseAgeHours)
    {
        string jwt = await _factory.CreateAdminJwt();
        using var adminClient = _factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", jwt);
        var put = await adminClient.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            minReleaseAgeHours,
        });
        put.EnsureSuccessStatusCode();
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose(); // ensure first-boot ran
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }
}
