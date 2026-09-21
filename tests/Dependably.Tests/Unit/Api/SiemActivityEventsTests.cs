using System.Security.Claims;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Coverage for <c>GET /api/v1/siem/events/activity</c> — the block-gate refusal feed. The
/// properties under test are the ones a collector cannot detect for itself when they break: a
/// tenant caller must never be able to read another tenant's refusals (including by naming one
/// in <c>?org=</c>), a disabled event class must be refused rather than silently omitted (an
/// omission reads as a quiet registry), and the write-lag cap must actually hold rows back —
/// serving up to "now" would permanently lose every row whose INSERT lands after the poll that
/// already moved the watermark past its timestamp.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SiemActivityEventsTests
{
    private static ClaimsPrincipal SystemAdminPrincipal() =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "system-admin-user"),
                new Claim("sub", "system-admin-user"),
                new Claim("role", "system_admin"),
                new Claim("scope", "system"),
            ],
            authenticationType: "test"));

    private static readonly JsonSerializerOptions WireOptions = new(JsonSerializerDefaults.Web);

    /// <summary>Serializes the JSON envelope the way the pipeline does, so assertions read the wire shape.</summary>
    private static JsonElement Envelope(IActionResult result) =>
        JsonSerializer.SerializeToElement(Assert.IsType<OkObjectResult>(result).Value, WireOptions);

    private static string[] Purls(IActionResult result) =>
        Envelope(result).GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("purl").GetString()!).ToArray();

    private static string[] Actions(IActionResult result) =>
        Envelope(result).GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("action").GetString()!).ToArray();

    private static async Task<string> OrgIdAsync(IMetadataStore db, string slug)
    {
        await using var conn = await db.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = @slug", new { slug }))!;
    }

    /// <summary>
    /// Writes through the real writer (<see cref="AuditRepository.LogActivityAsync"/>) on the
    /// scenario clock, so the stored timestamp is the one production would store.
    /// </summary>
    private static Task WriteActivityAsync(
        ControllerScenarioResult b, ControllerScenario s, string orgId, string eventType, string purl)
        => new AuditRepository(b.Db, time: s.Clock).LogActivityAsync(
            orgId, "npm", purl, eventType,
            actorId: "tok-1", actorKind: ActorKinds.Service, sourceIp: "203.0.113.7");

    // ── Tenant isolation ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetActivityEvents_TenantOwner_NeverSeesAnotherTenantsBlockedEvents()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithOrgAsync("other"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string otherOrgId = await OrgIdAsync(b.Db, "other");
        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/mine@1");
        await WriteActivityAsync(b, s, otherOrgId, "blocked_license", "pkg:npm/theirs@1");
        s.Clock.Advance(TimeSpan.FromMinutes(5)); // clear the write-lag horizon

        var result = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);

        Assert.Equal(new[] { "pkg:npm/mine@1" }, Purls(result));
    }

    [Fact]
    public async Task GetActivityEvents_OrgQueryParam_IsIgnoredForATenantCaller()
    {
        // ?org= naming a real, populated tenant must not widen a tenant-scoped caller's read:
        // ResolveOrgFilterAsync returns early on the pinned org and the parameter is inert.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithOrgAsync("other"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string otherOrgId = await OrgIdAsync(b.Db, "other");
        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/mine@1");
        await WriteActivityAsync(b, s, otherOrgId, "blocked_malicious", "pkg:npm/theirs@1");
        s.Clock.Advance(TimeSpan.FromMinutes(5));

        var result = await b.SiemController.GetActivityEvents(
            since: null, until: null, org: "other", events: null, limit: 100, cursor: null);

        Assert.Equal(new[] { "pkg:npm/mine@1" }, Purls(result));
    }

    [Fact]
    public async Task GetActivityEvents_Anonymous_Returns401()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);

        int? status = result switch
        {
            ObjectResult o => o.StatusCode,
            UnauthorizedResult => 401,
            _ => null,
        };
        Assert.Equal(401, status);
    }

    [Fact]
    public async Task GetActivityEvents_Member_Returns403_NoReadAuditCapability()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    [Fact]
    public async Task GetActivityEvents_PlatformAdmin_WithoutOrg_Returns400()
    {
        // The activity query takes a non-nullable org id, so "every tenant at once" is not
        // expressible. A platform admin reads one named tenant per poll instead.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = SystemAdminPrincipal();

        var result = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task GetActivityEvents_PlatformAdmin_WithOrgSlug_ReadsThatTenant()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithOrgAsync("other"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = SystemAdminPrincipal();

        string otherOrgId = await OrgIdAsync(b.Db, "other");
        await WriteActivityAsync(b, s, otherOrgId, "blocked_malicious", "pkg:npm/theirs@1");
        s.Clock.Advance(TimeSpan.FromMinutes(5));

        var result = await b.SiemController.GetActivityEvents(
            since: null, until: null, org: "other", events: null, limit: 100, cursor: null);

        Assert.Equal(new[] { "pkg:npm/theirs@1" }, Purls(result));
    }

    // ── Allowlist ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetActivityEvents_Default_ReturnsBlockedFamilyOnly()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/a@1");
        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_kev", "pkg:npm/b@1");
        await WriteActivityAsync(b, s, b.PrimaryOrgId, "download", "pkg:npm/c@1");
        await WriteActivityAsync(b, s, b.PrimaryOrgId, "first_fetch", "pkg:npm/d@1");
        s.Clock.Advance(TimeSpan.FromMinutes(5));

        var result = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);

        Assert.Equal(
            new[] { "blocked_kev", "blocked_license" },
            Actions(result).OrderBy(a => a, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task GetActivityEvents_DownloadRequested_FlagOff_Returns400_NotASilentOmission()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await WriteActivityAsync(b, s, b.PrimaryOrgId, "download", "pkg:npm/a@1");
        s.Clock.Advance(TimeSpan.FromMinutes(5));

        var result = await b.SiemController.GetActivityEvents(
            since: null, until: null, org: null, events: ["download"], limit: 100, cursor: null);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("SIEM_ACTIVITY_DOWNLOAD_EVENTS", JsonSerializer.Serialize(bad.Value, WireOptions),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetActivityEvents_DownloadRequested_FlagOn_ReturnsDownloadRows()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        s.WithSetting("SIEM_ACTIVITY_DOWNLOAD_EVENTS", "true");
        var b = await s.BuildAsync();

        await WriteActivityAsync(b, s, b.PrimaryOrgId, "download", "pkg:npm/a@1");
        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/b@1");
        s.Clock.Advance(TimeSpan.FromMinutes(5));

        var result = await b.SiemController.GetActivityEvents(
            since: null, until: null, org: null, events: ["download"], limit: 100, cursor: null);

        Assert.Equal(new[] { "pkg:npm/a@1" }, Purls(result));
    }

    [Fact]
    public async Task GetActivityEvents_UnknownEventType_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetActivityEvents(
            since: null, until: null, org: null, events: ["push"], limit: 100, cursor: null);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task GetActivityEvents_SpecificBlockedArm_SelectsOnlyThatArm()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/a@1");
        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_kev", "pkg:npm/b@1");
        s.Clock.Advance(TimeSpan.FromMinutes(5));

        var result = await b.SiemController.GetActivityEvents(
            since: null, until: null, org: null, events: ["blocked_kev"], limit: 100, cursor: null);

        Assert.Equal(new[] { "pkg:npm/b@1" }, Purls(result));
    }

    // ── Write-lag cap ────────────────────────────────────────────────────────

    [Fact]
    public async Task GetActivityEvents_LagCap_WithholdsRowsNewerThanNowMinusLag()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/fresh@1");

        // Default cap is 30 s; at +10 s the row is still inside the horizon another replica's
        // INSERT could still be landing in.
        s.Clock.Advance(TimeSpan.FromSeconds(10));
        var withheld = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);
        Assert.Empty(Purls(withheld));

        // The served window is reported, and it is exactly now − lag.
        var envelope = Envelope(withheld);
        Assert.Equal(30, envelope.GetProperty("lag_seconds").GetInt32());
        Assert.Equal(
            s.Clock.GetUtcNow().AddSeconds(-30).ToUtcIsoMillis(),
            envelope.GetProperty("until").GetString());

        // Past the horizon the same row is served.
        s.Clock.Advance(TimeSpan.FromSeconds(25));
        var served = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);
        Assert.Equal(new[] { "pkg:npm/fresh@1" }, Purls(served));
    }

    [Fact]
    public async Task GetActivityEvents_LagCap_IsConfigurable()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        s.WithSetting("SIEM_ACTIVITY_LAG_SECONDS", "5");
        var b = await s.BuildAsync();

        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/fresh@1");
        s.Clock.Advance(TimeSpan.FromSeconds(10));

        var result = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);

        Assert.Equal(new[] { "pkg:npm/fresh@1" }, Purls(result));
        Assert.Equal(5, Envelope(result).GetProperty("lag_seconds").GetInt32());
    }

    [Fact]
    public async Task GetActivityEvents_CallerUntilInsideTheLagHorizon_ServesAnEmptyWindow_NotAnError()
    {
        // A collector polling faster than the cap asks for a window that is entirely unwritable.
        // It gets an empty page whose `until` does not advance, rather than a 400 or — worse — a
        // window whose end it would go on to use as its next watermark.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/fresh@1");
        s.Clock.Advance(TimeSpan.FromSeconds(1));

        string since = s.Clock.GetUtcNow().AddSeconds(-2).ToUtcIsoMillis();
        var result = await b.SiemController.GetActivityEvents(
            since: since, until: null, org: null, events: null, limit: 100, cursor: null);

        var envelope = Envelope(result);
        Assert.Empty(Purls(result));
        Assert.Equal(since, envelope.GetProperty("since").GetString());
        Assert.Equal(since, envelope.GetProperty("until").GetString());
    }

    // ── Paging and rendering ─────────────────────────────────────────────────

    [Fact]
    public async Task GetActivityEvents_CursorPaging_ReturnsEveryRowExactlyOnce()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        const int rows = 12;
        for (int i = 0; i < rows; i++)
        {
            await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", $"pkg:npm/p{i}@1");
            s.Clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        s.Clock.Advance(TimeSpan.FromMinutes(5));

        var seen = new List<string>();
        string? cursor = null;
        int pages = 0;
        const int maxPages = 8; // bounds a runaway loop if paging never terminates

        while (pages < maxPages)
        {
            var page = await b.SiemController.GetActivityEvents(
                since: null, until: null, org: null, events: null, limit: 5, cursor: cursor);
            pages++;
            seen.AddRange(Purls(page));

            var envelope = Envelope(page);
            var next = envelope.GetProperty("next_cursor");
            if (next.ValueKind == JsonValueKind.Null)
            {
                break;
            }

            cursor = next.GetString();
        }

        Assert.True(pages < maxPages, "paging did not terminate within the page budget");
        Assert.Equal(rows, seen.Count);
        Assert.Equal(rows, seen.Distinct().Count());
    }

    [Fact]
    public async Task GetActivityEvents_TruncatedPage_WithholdsTheWatermark_UntilTheLastPage()
    {
        // Rows come newest-first, so a page carrying a cursor has served only the newest slice of
        // the window. A collector that advanced its watermark to that page's `until` would step
        // over every older row still behind the cursor and never come back for them — so the
        // truncated page carries no `until` at all, and the last page carries it.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        for (int i = 0; i < 12; i++)
        {
            await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", $"pkg:npm/p{i}@1");
            s.Clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        s.Clock.Advance(TimeSpan.FromMinutes(5));

        var first = Envelope(await b.SiemController.GetActivityEvents(
            since: null, until: null, org: null, events: null, limit: 5, cursor: null));
        Assert.Equal(JsonValueKind.String, first.GetProperty("next_cursor").ValueKind);
        Assert.Equal(JsonValueKind.Null, first.GetProperty("until").ValueKind);

        string? cursor = first.GetProperty("next_cursor").GetString();
        var page = first;
        int pages = 1;
        const int maxPages = 6; // bounds a runaway loop if paging never terminates

        while (cursor is not null && pages < maxPages)
        {
            page = Envelope(await b.SiemController.GetActivityEvents(
                since: null, until: null, org: null, events: null, limit: 5, cursor: cursor));
            pages++;
            cursor = page.GetProperty("next_cursor").ValueKind == JsonValueKind.Null
                ? null
                : page.GetProperty("next_cursor").GetString();
        }

        Assert.True(pages < maxPages, "paging did not terminate within the page budget");
        Assert.Equal(
            s.Clock.GetUtcNow().AddSeconds(-30).ToUtcIsoMillis(),
            page.GetProperty("until").GetString());
    }

    [Fact]
    public async Task GetActivityEvents_CefTruncatedPage_OmitsTheServedWindowLine()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        for (int i = 0; i < 4; i++)
        {
            await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", $"pkg:npm/p{i}@1");
            s.Clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        s.Clock.Advance(TimeSpan.FromMinutes(5));
        b.SiemController.Request.Headers.Accept = "application/x-cef";

        var truncated = Assert.IsType<ContentResult>(await b.SiemController.GetActivityEvents(
            since: null, until: null, org: null, events: null, limit: 2, cursor: null));

        Assert.Contains("# next_cursor=", truncated.Content!, StringComparison.Ordinal);
        Assert.DoesNotContain("# window_until=", truncated.Content!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetActivityEvents_NdjsonAccept_RendersOneObjectPerLine_PlusAWindowTrailer()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/a@1");
        s.Clock.Advance(TimeSpan.FromMinutes(5));
        b.SiemController.Request.Headers.Accept = "application/x-ndjson";

        var result = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);

        var content = Assert.IsType<ContentResult>(result);
        Assert.StartsWith("application/x-ndjson", content.ContentType, StringComparison.Ordinal);
        string[] lines = content.Content!.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Contains("\"action\":\"blocked_license\"", lines[0], StringComparison.Ordinal);
        // The trailer is written on every page: the served window is the collector's watermark
        // and cannot be derived from the rows.
        Assert.Contains("\"until\":", lines[1], StringComparison.Ordinal);
        Assert.Contains("\"lag_seconds\":", lines[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetActivityEvents_CefAccept_RendersCefRecordsAndTheServedWindow()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await WriteActivityAsync(b, s, b.PrimaryOrgId, "blocked_license", "pkg:npm/a@1");
        s.Clock.Advance(TimeSpan.FromMinutes(5));
        b.SiemController.Request.Headers.Accept = "application/x-cef";

        var result = await b.SiemController.GetActivityEvents(null, null, null, null, 100, null);

        var content = Assert.IsType<ContentResult>(result);
        Assert.StartsWith("application/x-cef", content.ContentType, StringComparison.Ordinal);
        Assert.Contains("CEF:0|Dependably|dependably|1.0|blocked_license|", content.Content!, StringComparison.Ordinal);
        Assert.Contains("src=203.0.113.7", content.Content!, StringComparison.Ordinal);
        Assert.Contains("suid=tok-1", content.Content!, StringComparison.Ordinal);
        // The cs1-cs4 slots are positional and each carries its own Label pair: a value written
        // without its label is a field the collector has no name for, which is indistinguishable
        // from a custom-string slot this product never populated.
        Assert.Contains($"cs1={b.PrimaryOrgId} cs1Label=OrgId", content.Content!, StringComparison.Ordinal);
        Assert.Contains("cs2=npm cs2Label=Ecosystem", content.Content!, StringComparison.Ordinal);
        Assert.Contains("cs3=pkg:npm/a@1 cs3Label=Purl", content.Content!, StringComparison.Ordinal);
        // The tenant feed resolves no slug, and this row carries no detail. Both slots are omitted
        // outright rather than written empty — an empty cs4=/msg= reads as a known-blank value.
        Assert.DoesNotContain(" cs4=", content.Content!, StringComparison.Ordinal);
        Assert.DoesNotContain(" msg=", content.Content!, StringComparison.Ordinal);
        Assert.Contains("# window_until=", content.Content!, StringComparison.Ordinal);
    }
}
