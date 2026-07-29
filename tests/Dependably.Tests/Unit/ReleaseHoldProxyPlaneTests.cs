using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// The release-age gate blocks artifacts on either plane. A tag push queues the hold against a
/// <c>package_versions</c> row; a proxy fetch queues it with <c>package_version_id = NULL</c>,
/// because the artifact it blocked lives on the cache plane — and its publish date lives there too.
///
/// Reading the publish date from <c>package_versions</c> alone yields NULL for every proxied hold,
/// which <see cref="QuarantineRepository.IsReleaseHoldStale"/> reads as "unknown publish date, so the
/// hold no longer applies". The hold the gate had just raised is then purged before any admin sees
/// it, and the dashboard count that mirrors the purge never shows it either. The artifact stays
/// blocked; the record of why silently disappears.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ReleaseHoldProxyPlaneTests : IAsyncLifetime
{
    // Frozen now is 2026-06-15T12:00:00Z; a 72-hour hold window.
    private const int HoldHours = 72;

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id, min_release_age_hours) VALUES ('o1', @HoldHours)",
            new { HoldHours });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task A_release_hold_on_a_proxied_artifact_survives_the_queue_purge()
    {
        await SeedProxiedHoldAsync(publishedAt: _clock.GetUtcNow().AddHours(-1));

        var repo = new QuarantineRepository(_db, _clock);
        int purged = await repo.PurgeAgedReleaseHoldsAsync("o1", HoldHours);

        // Published an hour ago, held for 72 — the gate is still holding it, so the queue must too.
        Assert.Equal(0, purged);
        var (items, total) = await repo.ListAsync(new QuarantineListQuery("o1", State: "pending", Limit: 50));
        Assert.Equal(1, total);
        Assert.Equal("release_age", Assert.Single(items).Gate);
    }

    [Fact]
    public async Task The_dashboard_counts_a_release_hold_on_a_proxied_artifact()
    {
        await SeedProxiedHoldAsync(publishedAt: _clock.GetUtcNow().AddHours(-1));

        var stats = await new PackageAnalyticsRepository(_db, time: _clock).GetOrgStatsAsync("o1");

        // The count mirrors the queue. If it disagreed, one of them would be lying to the operator.
        Assert.Equal(1, stats.QuarantinePending);
    }

    [Fact]
    public async Task A_proxied_hold_whose_artifact_has_aged_out_is_still_purged()
    {
        // The fix must not make holds immortal — one published well past the window is genuinely
        // stale, and the queue is right to drop it.
        await SeedProxiedHoldAsync(publishedAt: _clock.GetUtcNow().AddHours(-(HoldHours + 24)));

        var repo = new QuarantineRepository(_db, _clock);
        int purged = await repo.PurgeAgedReleaseHoldsAsync("o1", HoldHours);

        Assert.Equal(1, purged);
        var stats = await new PackageAnalyticsRepository(_db, time: _clock).GetOrgStatsAsync("o1");
        Assert.Equal(0, stats.QuarantinePending);
    }

    [Fact]
    public async Task A_hold_with_no_artifact_in_the_catalogue_is_still_purged()
    {
        // A first-fetch block can be recorded before any catalogue row exists. There is genuinely no
        // publish date to hold against, so "unknown means stale" remains the honest reading.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO quarantine (id, org_id, package_version_id, ecosystem, purl, gate, state)
                VALUES ('qghost', 'o1', NULL, 'npm', 'pkg:npm/never-fetched@1.0.0', 'release_age', 'pending')
                """);
        }

        int purged = await new QuarantineRepository(_db, _clock).PurgeAgedReleaseHoldsAsync("o1", HoldHours);

        Assert.Equal(1, purged);
    }

    // A proxy fetch the release-age gate blocked: the artifact is on the cache plane, and the
    // quarantine row carries no package_version_id — only the purl that reaches it.
    private async Task SeedProxiedHoldAsync(DateTimeOffset publishedAt)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl, published_at)
            VALUES ('ca1', 'npm', 'fresh-pkg', '1.0.0', 'fresh-pkg-1.0.0.tgz', 'proxy/ca1', 'ca1',
                    'pkg:npm/fresh-pkg@1.0.0', @publishedAt)
            """,
            new { publishedAt = publishedAt.ToUtcIso() });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca1')");
        await conn.ExecuteAsync(
            """
            INSERT INTO quarantine (id, org_id, package_version_id, ecosystem, purl, gate, state)
            VALUES ('q1', 'o1', NULL, 'npm', 'pkg:npm/fresh-pkg@1.0.0', 'release_age', 'pending')
            """);
    }
}
