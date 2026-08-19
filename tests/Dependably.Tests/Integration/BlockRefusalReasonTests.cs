using System.Net;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// A policy refusal used to reach the client as a bare 403 with an empty body — on the wire,
/// indistinguishable from an authorization failure, and carrying nothing an operator could
/// correlate against their own configuration. The reason existed only in the activity feed, which
/// is not where anyone looks when a package manager fails a build.
///
/// The incident that prompted this work read, in full, <c>HTTP error 403 while getting …</c>. These
/// tests pin that a refusal now names the arm that produced it.
/// </summary>
[Trait("Category", "Integration")]
public sealed class BlockRefusalReasonTests : IAsyncLifetime
{
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    /// <summary>
    /// The manual arm on a hosted artifact: the operator blocked it by hand, so the header must say
    /// so rather than leaving them to guess between a policy block and a credential problem.
    /// </summary>
    [Fact]
    public async Task ManuallyBlockedDownload_NamesTheManualArm()
    {
        string name = $"reason{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        await BlockAsync(name, "1.0.0", "blocked");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string file = $"{name.Replace('-', '_')}-1.0.0-py3-none-any.whl";
        var resp = await client.GetAsync($"/packages/{file}");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Equal("manual", Header(resp));
    }

    /// <summary>
    /// The release-age arm, which is the one a developer is most likely to meet and least likely to
    /// interpret: the artifact exists, their credentials are fine, and the hold resolves on its own.
    /// A header naming it is the difference between waiting and filing a bug.
    /// </summary>
    [Fact]
    public async Task ReleaseAgeHeldDownload_NamesTheReleaseAgeArm()
    {
        string name = $"reasonage{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");

        // published_at alone; origin stays 'uploaded', which IsCooldownEligible already admits
        // (it exempts only 'hosted'/'local_only'). Rewriting origin would change how the download
        // path resolves the artifact and test a different code path than the one under test.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            Assert.Equal(1, await conn.ExecuteAsync(
                """
                UPDATE package_versions SET published_at = @ts
                WHERE version = '1.0.0' AND package_id IN (
                    SELECT id FROM packages WHERE ecosystem = 'pypi' AND purl_name = @name)
                """,
                new { ts = TestTime.KnownNow.AddHours(-1).ToUtcIso(), name }));
        }

        await SetMinReleaseAgeHoursAsync(24);
        EvictIndex(name);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string file = $"{name.Replace('-', '_')}-1.0.0-py3-none-any.whl";
        var resp = await client.GetAsync($"/packages/{file}");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Equal("release_age", Header(resp));
    }

    /// <summary>
    /// The control that keeps the header meaningful: a successful download carries no reason. A
    /// header stamped unconditionally would say nothing, and a client could not use its presence
    /// to distinguish a policy refusal from any other 403.
    /// </summary>
    [Fact]
    public async Task SuccessfulDownload_CarriesNoReasonHeader()
    {
        string name = $"reasonok{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string file = $"{name.Replace('-', '_')}-1.0.0-py3-none-any.whl";
        var resp = await client.GetAsync($"/packages/{file}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Null(Header(resp));
    }

    /// <summary>
    /// A 403 that is not a policy refusal — here an unauthenticated request — must not carry the
    /// header either, or its presence stops meaning "your policy did this".
    /// </summary>
    [Fact]
    public async Task NonPolicyRefusal_CarriesNoReasonHeader()
    {
        string name = $"reasonauth{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        await SetAnonymousPullAsync(false);

        try
        {
            using var client = _factory.CreateClient();
            string file = $"{name.Replace('-', '_')}-1.0.0-py3-none-any.whl";
            var resp = await client.GetAsync($"/packages/{file}");

            Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
            Assert.Null(Header(resp));
        }
        finally
        {
            await SetAnonymousPullAsync(true);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static string? Header(HttpResponseMessage resp) =>
        resp.Headers.TryGetValues(BlockRefusalResult.ReasonHeader, out var values)
            ? values.FirstOrDefault()
            : null;

    private async Task BlockAsync(string name, string version, string state)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        Assert.Equal(1, await conn.ExecuteAsync(
            """
            UPDATE package_versions SET manual_block_state = @state
            WHERE version = @version AND package_id IN (
                SELECT id FROM packages WHERE ecosystem = 'pypi' AND purl_name = @name)
            """,
            new { state, version, name }));
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

    private async Task SetMinReleaseAgeHoursAsync(int? hours)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET min_release_age_hours = @hours WHERE org_id = @orgId",
            new { hours, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private void EvictIndex(string name)
    {
        string orgId = DefaultOrgIdAsync().GetAwaiter().GetResult();
        var cache = _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>();
        cache.Evict(new PyPiSimpleIndexKey(orgId, name));
        cache.Evict(new PyPiSimpleIndexKey(orgId, name) { WantsJson = true });
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }
}
