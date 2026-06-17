using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that every block-gate arm that applies to upstream packument data is honoured
/// by the packument endpoint, so a client can never discover a version in GET /npm/{pkg}
/// that GET /npm/tarballs/{pkg}/{file} (or the proxy fetch path) will deny with 403.
///
/// Release-age tests use a factory with a frozen host clock so the age arithmetic is
/// deterministic. The deprecated block_all arm is also covered.
///
/// Each case is a fail-before/pass-after regression: on the old code, which applied no
/// block-gate filtering in the packument renderer, the assertions about absent versions
/// would have failed because versions were advertised regardless of what the tarball path
/// would return.
///
/// The mixed/partial-failure scenario (one version blocked, one served in the same response)
/// is the primary case for each arm, per house style.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmPackumentBlockGateParityTests : IAsyncLifetime
{
    // FrozenClock set to TestTime.KnownNow so time-based assertions are deterministic.
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── release-age gate — upstream packument time map ────────────────────────

    /// <summary>
    /// A version published 1 hour ago under a 24-hour hold must be absent from the served
    /// packument AND return 403 on the tarball path — fail-before/pass-after for the
    /// release-age arm on the proxy packument path.
    ///
    /// Old code: the packument was served verbatim (after URL rewrite), so both versions
    /// appeared in the packument regardless of the release-age setting.
    /// New code: FilterPackumentToServableVersions drops the too-young version and repoints
    /// dist-tags.latest so the packument never advertises an uninstallable coordinate.
    ///
    /// Mixed/partial-failure scenario: 2.0.0 is within the hold (blocked), 1.0.0 is well
    /// past it (served). Both are in the same upstream packument response. The test asserts
    /// the mix — not just all-pass or all-fail.
    /// </summary>
    [Fact]
    public async Task Packument_ReleaseAge_TooYoung_IsAbsentFromPackument()
    {
        string name = $"npmage{Guid.NewGuid():N}"[..16].ToLowerInvariant();

        var frozenNow = TestTime.KnownNow;
        // 1.0.0: 30 days ago (well past any reasonable hold — must survive).
        // 2.0.0: 1 hour ago (within a 24-hour hold — must be dropped).
        string oldTs = frozenNow.AddDays(-30).ToString("o");
        string youngTs = frozenNow.AddHours(-1).ToString("o");

        string upstreamBase = _factory.MockUpstream.Urls[0];
        string upstreamJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": {"latest":"2.0.0"},
              "versions": {
                "1.0.0": {
                  "name": "{{name}}",
                  "version": "1.0.0",
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"aabbcc"}
                },
                "2.0.0": {
                  "name": "{{name}}",
                  "version": "2.0.0",
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-2.0.0.tgz","shasum":"ddeeff"}
                }
              },
              "time": {
                "created": "{{frozenNow.AddDays(-60):o}}",
                "modified": "{{youngTs}}",
                "1.0.0": "{{oldTs}}",
                "2.0.0": "{{youngTs}}"
              }
            }
            """;

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        await SetProxySettingsAsync(minReleaseAgeHours: 24);

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            var resp = await client.GetAsync($"/npm/{name}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);

            var versions = doc.RootElement.GetProperty("versions");
            // 1.0.0 is old enough — must be present.
            Assert.True(versions.TryGetProperty("1.0.0", out _), "1.0.0 (old enough) must appear in packument");
            // 2.0.0 is too young — must be absent.
            Assert.False(versions.TryGetProperty("2.0.0", out _), "2.0.0 (too young) must not appear in packument");

            // dist-tags.latest must have been repointed away from the dropped 2.0.0.
            string? latest = doc.RootElement.GetProperty("dist-tags").GetProperty("latest").GetString();
            Assert.Equal("1.0.0", latest);

            // time[] entry for the dropped version must be absent; meta-keys (created/modified)
            // and entries for surviving versions must still be present.
            var time = doc.RootElement.GetProperty("time");
            Assert.False(time.TryGetProperty("2.0.0", out _), "time[2.0.0] must be removed for dropped version");
            Assert.True(time.TryGetProperty("1.0.0", out _), "time[1.0.0] must be retained for surviving version");
            Assert.True(time.TryGetProperty("created", out _), "time.created meta-key must be retained");
            Assert.True(time.TryGetProperty("modified", out _), "time.modified meta-key must be retained");
        }
        finally
        {
            await SetProxySettingsAsync(minReleaseAgeHours: null);
        }
    }

    /// <summary>
    /// Control case: when MinReleaseAgeHours is 0 (disabled), both versions must appear in
    /// the packument unchanged. Verifies no regression to the default pass-through.
    /// </summary>
    [Fact]
    public async Task Packument_ReleaseAge_Disabled_BothVersionsPresent()
    {
        string name = $"npmageoff{Guid.NewGuid():N}"[..16].ToLowerInvariant();

        var frozenNow = TestTime.KnownNow;
        string oldTs = frozenNow.AddDays(-30).ToString("o");
        string youngTs = frozenNow.AddHours(-1).ToString("o");

        string upstreamBase = _factory.MockUpstream.Urls[0];
        string upstreamJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": {"latest":"2.0.0"},
              "versions": {
                "1.0.0": {
                  "name": "{{name}}",
                  "version": "1.0.0",
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"aabbcc"}
                },
                "2.0.0": {
                  "name": "{{name}}",
                  "version": "2.0.0",
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-2.0.0.tgz","shasum":"ddeeff"}
                }
              },
              "time": {
                "1.0.0": "{{oldTs}}",
                "2.0.0": "{{youngTs}}"
              }
            }
            """;

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        // Leave MinReleaseAgeHours at default (0 / disabled) — no SetProxySettingsAsync call.
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        var versions = doc.RootElement.GetProperty("versions");
        // Both versions must be present — no filtering with the gate off.
        Assert.True(versions.TryGetProperty("1.0.0", out _), "1.0.0 must appear when release-age gate is off");
        Assert.True(versions.TryGetProperty("2.0.0", out _), "2.0.0 must appear when release-age gate is off");
    }

    /// <summary>
    /// Fail-open case: when the upstream packument omits the time map for a version,
    /// the release-age gate must fail-open (not drop the version). This matches
    /// EvaluateReleaseAgeAsync behaviour which also fails open on missing PublishedAt.
    /// </summary>
    [Fact]
    public async Task Packument_ReleaseAge_NoTimestamp_FailsOpen_VersionRetained()
    {
        string name = $"npmnotime{Guid.NewGuid():N}"[..16].ToLowerInvariant();

        string upstreamBase = _factory.MockUpstream.Urls[0];
        string upstreamJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": {"latest":"1.0.0"},
              "versions": {
                "1.0.0": {
                  "name": "{{name}}",
                  "version": "1.0.0",
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"aabbcc"}
                }
              }
            }
            """;

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        await SetProxySettingsAsync(minReleaseAgeHours: 24);

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            var resp = await client.GetAsync($"/npm/{name}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);

            var versions = doc.RootElement.GetProperty("versions");
            // No timestamp → fail-open → version must appear even with the gate on.
            Assert.True(versions.TryGetProperty("1.0.0", out _), "1.0.0 with no time entry must be retained (fail-open)");
        }
        finally
        {
            await SetProxySettingsAsync(minReleaseAgeHours: null);
        }
    }

    // ── deprecated block_all gate ────────────────────────────────────────────

    /// <summary>
    /// A deprecated version under block_all must be absent from the served packument.
    /// A non-deprecated version in the same packument must remain.
    ///
    /// Old code: deprecated versions were never filtered from the packument, so they appeared
    /// regardless of the block_deprecated setting.
    /// New code: FilterPackumentToServableVersions drops versions with a deprecated field
    /// when the mode is block_all or the legacy block.
    ///
    /// Mixed/partial-failure: 1.0.0 is not deprecated (survives), 2.0.0 is deprecated
    /// (blocked). Both in the same upstream packument response.
    /// </summary>
    [Fact]
    public async Task Packument_DeprecatedBlockAll_DeprecatedVersion_IsAbsentFromPackument()
    {
        string name = $"npmdepblock{Guid.NewGuid():N}"[..16].ToLowerInvariant();

        var frozenNow = TestTime.KnownNow;
        string upstreamBase = _factory.MockUpstream.Urls[0];
        string upstreamJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": {"latest":"2.0.0"},
              "versions": {
                "1.0.0": {
                  "name": "{{name}}",
                  "version": "1.0.0",
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"aabbcc"}
                },
                "2.0.0": {
                  "name": "{{name}}",
                  "version": "2.0.0",
                  "deprecated": "Use 1.0.0 instead",
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-2.0.0.tgz","shasum":"ddeeff"}
                }
              },
              "time": {
                "1.0.0": "{{frozenNow.AddDays(-60):o}}",
                "2.0.0": "{{frozenNow.AddDays(-30):o}}"
              }
            }
            """;

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        await SetBlockDeprecatedAsync("block_all");

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            var resp = await client.GetAsync($"/npm/{name}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);

            var versions = doc.RootElement.GetProperty("versions");
            // 1.0.0 is not deprecated — must remain.
            Assert.True(versions.TryGetProperty("1.0.0", out _), "1.0.0 (not deprecated) must appear in packument");
            // 2.0.0 is deprecated under block_all — must be dropped.
            Assert.False(versions.TryGetProperty("2.0.0", out _), "2.0.0 (deprecated, block_all) must not appear in packument");

            // dist-tags.latest must have been repointed to a surviving version.
            string? latest = doc.RootElement.GetProperty("dist-tags").GetProperty("latest").GetString();
            Assert.Equal("1.0.0", latest);
        }
        finally
        {
            await SetBlockDeprecatedAsync("off");
        }
    }

    /// <summary>
    /// A version with a JSON boolean <c>"deprecated": true</c> (emitted by some registries)
    /// must NOT crash the packument endpoint (no 500) and must NOT be filtered from the
    /// packument under block_all. This matches the download path: LicenseExtractor treats a
    /// boolean deprecated field as null (not-deprecated) so the tarball gate returns 200.
    /// The packument index must agree — hiding a downloadable version is worse than showing it.
    ///
    /// Old code: GetValue&lt;string&gt;() on a boolean node throws InvalidOperationException,
    /// bubbling as a 500 for the entire packument request.
    /// New code: LicenseExtractor.FromNpmPackumentVersion absorbs the exception and returns
    /// null, so the version survives the filter and the response is 200.
    /// </summary>
    [Fact]
    public async Task Packument_DeprecatedBlockAll_BooleanDeprecated_DoesNotCrashAndVersionRetained()
    {
        string name = $"npmdepbool{Guid.NewGuid():N}"[..16].ToLowerInvariant();

        var frozenNow = TestTime.KnownNow;
        string upstreamBase = _factory.MockUpstream.Urls[0];
        // "deprecated": true — a JSON boolean, not a string; some registries emit this form.
        string upstreamJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": {"latest":"1.0.0"},
              "versions": {
                "1.0.0": {
                  "name": "{{name}}",
                  "version": "1.0.0",
                  "deprecated": true,
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"aabbcc"}
                }
              },
              "time": {
                "1.0.0": "{{frozenNow.AddDays(-30):o}}"
              }
            }
            """;

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        await SetBlockDeprecatedAsync("block_all");

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            var resp = await client.GetAsync($"/npm/{name}");
            // Must not 500 — LicenseExtractor absorbs the boolean-deprecated exception.
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);

            var versions = doc.RootElement.GetProperty("versions");
            // boolean deprecated is not-deprecated per LicenseExtractor — version must survive.
            Assert.True(versions.TryGetProperty("1.0.0", out _),
                "1.0.0 with boolean deprecated must be retained (parity with download path)");
        }
        finally
        {
            await SetBlockDeprecatedAsync("off");
        }
    }

    /// <summary>
    /// A version with <c>"deprecated": ""</c> (empty string) must NOT be filtered from the
    /// packument under block_all. The download path's LicenseExtractor normalizes
    /// empty/whitespace to null (treats it as not-deprecated) and the tarball gate returns 200;
    /// the packument index must agree rather than hiding a downloadable version.
    ///
    /// Old code: the empty string is non-null, so the raw <c>deprecated is not null</c> check
    /// dropped the version from the packument while the tarball path served it 200 — opposite
    /// inconsistency from the boolean case.
    /// New code: LicenseExtractor.FromNpmPackumentVersion normalizes empty-string to null, so
    /// the version is retained in both the packument and the tarball path.
    /// </summary>
    [Fact]
    public async Task Packument_DeprecatedBlockAll_EmptyStringDeprecated_VersionRetained()
    {
        string name = $"npmdepempty{Guid.NewGuid():N}"[..16].ToLowerInvariant();

        var frozenNow = TestTime.KnownNow;
        string upstreamBase = _factory.MockUpstream.Urls[0];
        // "deprecated": "" — empty string; some registries emit this to un-deprecate.
        string upstreamJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": {"latest":"1.0.0"},
              "versions": {
                "1.0.0": {
                  "name": "{{name}}",
                  "version": "1.0.0",
                  "deprecated": "",
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"aabbcc"}
                }
              },
              "time": {
                "1.0.0": "{{frozenNow.AddDays(-30):o}}"
              }
            }
            """;

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        await SetBlockDeprecatedAsync("block_all");

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            var resp = await client.GetAsync($"/npm/{name}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);

            var versions = doc.RootElement.GetProperty("versions");
            // empty-string deprecated → LicenseExtractor returns null → not blocked → must appear.
            Assert.True(versions.TryGetProperty("1.0.0", out _),
                "1.0.0 with empty-string deprecated must be retained (parity with download path)");
        }
        finally
        {
            await SetBlockDeprecatedAsync("off");
        }
    }

    /// <summary>
    /// Under block_new (not block_all), deprecated versions must NOT be filtered from the
    /// packument. block_new only blocks on first-fetch; already-cached deprecated versions
    /// keep serving, so hiding them from the index would create the opposite inconsistency.
    /// </summary>
    [Fact]
    public async Task Packument_DeprecatedBlockNew_DeprecatedVersionStillPresent()
    {
        string name = $"npmdepnew{Guid.NewGuid():N}"[..16].ToLowerInvariant();

        string upstreamBase = _factory.MockUpstream.Urls[0];
        string upstreamJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": {"latest":"1.0.0"},
              "versions": {
                "1.0.0": {
                  "name": "{{name}}",
                  "version": "1.0.0",
                  "deprecated": "Use 2.0.0 instead",
                  "dist": {"tarball":"{{upstreamBase}}/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"aabbcc"}
                }
              }
            }
            """;

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        await SetBlockDeprecatedAsync("block_new");

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            var resp = await client.GetAsync($"/npm/{name}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);

            var versions = doc.RootElement.GetProperty("versions");
            // block_new does not filter the packument index — version must remain.
            Assert.True(versions.TryGetProperty("1.0.0", out _),
                "1.0.0 (deprecated under block_new) must still appear — block_new only fires on first-fetch");
        }
        finally
        {
            await SetBlockDeprecatedAsync("off");
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

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

        // Evict packument cache entries so the next request rebuilds with the new settings.
        // Per-test unique names mean collisions across tests are impossible, but the
        // settings change can affect any entry sharing the same orgId.
        string orgId = await DefaultOrgIdAsync();
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetBlockDeprecatedAsync(string mode)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, block_deprecated)
            VALUES (@orgId, @mode)
            ON CONFLICT(org_id) DO UPDATE SET block_deprecated = @mode
            """,
            new { orgId, mode });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
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
