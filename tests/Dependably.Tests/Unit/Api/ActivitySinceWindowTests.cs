using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The activity feed's time window. The dashboard's blocked-pull tiles count a 30-day window, so
/// the drill-down they link to has to be able to scope the feed to the same window — an all-time
/// list under a 30-day count reads as a bug. The window vocabulary is closed (24h/7d/30d/90d) and
/// the cutoff instant comes from the injected clock, never the wall clock.
///
/// Rows are seeded a day and sixty days back from the frozen now, well clear of the 30-day
/// boundary, so neither can straddle it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ActivitySinceWindowTests
{
    // TestTime.KnownNow is 2026-06-15T12:00:00Z; the 30-day cutoff therefore lands on 2026-05-16.
    private const string RecentAt = "2026-06-14T12:00:00Z";   // 1 day back  — inside every window but 24h
    private const string OldAt = "2026-04-16T12:00:00Z";      // 60 days back — outside the 30-day window

    [Fact]
    public async Task Repository_since_bound_filters_the_rows_and_the_total_together()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        await SeedBlockedEventsAsync(b.Db, b.PrimaryOrgId);

        var repo = new AuditRepository(b.Db);
        var (items, total, _) = await repo.ListActivityAsync(
            b.PrimaryOrgId, limit: 50, offset: 0, eventType: "blocked", since: "2026-05-16T12:00:00Z");

        // A COUNT that forgot the bound would report 2 against a single row and mis-size the pager.
        Assert.Equal(1, total);
        Assert.Equal("blocked_malicious", Assert.Single(items).EventType);
    }

    [Fact]
    public async Task Thirty_day_window_returns_only_the_events_the_dashboard_tile_counts()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        await SeedBlockedEventsAsync(b.Db, b.PrimaryOrgId);

        var scoped = (OkObjectResult)await b.OrgAuditController.GetActivity(eventType: "blocked", since: "30d");
        var allTime = (OkObjectResult)await b.OrgAuditController.GetActivity(eventType: "blocked");

        // The window resolves against the frozen clock: the 60-day-old block falls outside it.
        Assert.Equal(1, TotalOf(scoped));
        // Without a window the feed is unchanged — the whole block-gate family, all time.
        Assert.Equal(2, TotalOf(allTime));
    }

    [Fact]
    public async Task An_unknown_window_is_rejected_rather_than_silently_ignored()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgAuditController.GetActivity(since: "last-tuesday");

        // Falling back to "all time" on a typo would quietly show more than the caller asked for.
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(422, problem.StatusCode);
    }

    [Fact]
    public async Task Csv_export_honours_the_window_so_it_matches_the_list_it_was_exported_from()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        await SeedBlockedEventsAsync(b.Db, b.PrimaryOrgId);

        var export = Assert.IsType<FileContentResult>(
            await b.OrgAuditController.GetActivity(eventType: "blocked", since: "30d", format: "csv"));
        string csv = System.Text.Encoding.UTF8.GetString(export.FileContents);

        Assert.Contains("blocked_malicious", csv, StringComparison.Ordinal);
        Assert.DoesNotContain("blocked_kev", csv, StringComparison.Ordinal);   // the 60-day-old row
    }

    private static int TotalOf(OkObjectResult ok) =>
        (int)ok.Value!.GetType().GetProperty("total")!.GetValue(ok.Value)!;

    // One recent block and one well outside the 30-day window.
    private static async Task SeedBlockedEventsAsync(IMetadataStore db, string orgId)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO activity (id, org_id, ecosystem, purl, event_type, created_at) VALUES
              ('a-recent', @orgId, 'npm', 'pkg:npm/evil@1.0.0', 'blocked_malicious', @recent),
              ('a-old',    @orgId, 'npm', 'pkg:npm/old@1.0.0',  'blocked_kev',       @old)
            """,
            new { orgId, recent = RecentAt, old = OldAt });
    }
}
