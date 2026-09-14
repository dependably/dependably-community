using System.Security.Claims;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Regression coverage for the <c>latest_event_at</c>/<c>matched</c>/<c>matched_capped</c> fields
/// added to the <c>GET /api/v1/siem/events/auth</c> JSON envelope. These exist so a collector can
/// tell "the registry is quiet" from "the audit writer is broken" from "my action filter matches
/// nothing" — all three otherwise present as an identical HTTP 200 with empty <c>items</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SiemFeedIntegrityTests
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

    private static async Task SeedAuditAsync(
        IMetadataStore db, string orgId, string action, DateTimeOffset createdAt, string? actorId = null)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, actor_id, action, created_at)
            VALUES (@id, 'tenant', @orgId, @actorId, @action, @createdAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                actorId,
                action,
                createdAt = createdAt.ToUtcIsoMillis(),
            });
    }

    private static JsonElement ParseBody(OkObjectResult ok) =>
        JsonDocument.Parse(JsonSerializer.Serialize(ok.Value)).RootElement;

    [Fact]
    public async Task GetAuthEvents_JsonEnvelope_CarriesLatestEventAtIgnoringFilter_AndMatchedCount()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var now = s.Clock.GetUtcNow();
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", now.AddMinutes(-10), actorId: "login-actor");
        // Doesn't match the "login" action filter below, but is the most recent row overall.
        var lockoutAt = now.AddMinutes(-1);
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "lockout.triggered", lockoutAt, actorId: "lockout-actor");

        var result = await b.SiemController.GetAuthEvents(
            since: now.AddMinutes(-20).ToString("o"), until: now.ToString("o"),
            org: null, action: new[] { "login" }, limit: 100, cursor: null);

        var ok = Assert.IsType<OkObjectResult>(result);
        var root = ParseBody(ok);

        Assert.Equal(1, root.GetProperty("matched").GetInt32());
        Assert.False(root.GetProperty("matched_capped").GetBoolean());
        var latest = DateTimeOffset.Parse(root.GetProperty("latest_event_at").GetString()!);
        Assert.Equal(lockoutAt, latest);
    }

    /// <summary>
    /// <c>latest_event_at</c> must serialize at the same millisecond precision
    /// <c>audit_log.created_at</c> is written and paginated at — a second-precision render would
    /// silently round an instant like <c>:00.500Z</c> down to <c>:00Z</c>, which can then sort
    /// BEFORE an item's own <c>createdAt</c> in the very same response even though the field
    /// claims to be at least as recent as every row visible to the caller. The seeded whole-minute
    /// offsets in the other tests in this file wouldn't catch that truncation — they carry no
    /// sub-second component to lose — so this test deliberately seeds one that does.
    /// </summary>
    [Fact]
    public async Task GetAuthEvents_JsonEnvelope_LatestEventAtPreservesMillisecondPrecision()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var preciseAt = s.Clock.GetUtcNow().AddMinutes(-1).AddMilliseconds(500);
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", preciseAt, actorId: "actor-a");

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: null, limit: 100, cursor: null);
        var ok = Assert.IsType<OkObjectResult>(result);
        var root = ParseBody(ok);

        string raw = root.GetProperty("latest_event_at").GetString()!;
        Assert.EndsWith(".500Z", raw);
        Assert.Equal(preciseAt, DateTimeOffset.Parse(raw));
    }

    [Fact]
    public async Task GetAuthEvents_JsonEnvelope_MatchedIndependentOfPageLimit()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var now = s.Clock.GetUtcNow();
        for (int i = 0; i < 5; i++)
        {
            await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", now.AddMinutes(-i), actorId: $"a{i}");
        }

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: null, limit: 2, cursor: null);
        var ok = Assert.IsType<OkObjectResult>(result);
        var root = ParseBody(ok);

        Assert.Equal(2, root.GetProperty("items").GetArrayLength());
        Assert.Equal(5, root.GetProperty("matched").GetInt32());
    }

    [Fact]
    public async Task GetAuthEvents_EmptyRegistry_LatestEventAtIsNull_DistinctFromFilterMismatch()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // No rows seeded at all — the "registry is quiet" / "writer is broken" case.
        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: null, limit: 100, cursor: null);
        var ok = Assert.IsType<OkObjectResult>(result);
        var root = ParseBody(ok);

        Assert.Equal(0, root.GetProperty("items").GetArrayLength());
        Assert.Equal(0, root.GetProperty("matched").GetInt32());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("latest_event_at").ValueKind);
    }

    [Fact]
    public async Task GetAuthEvents_FilterMatchesNothing_LatestEventAtStillReportsTheQuietWriterIsAlive()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var now = s.Clock.GetUtcNow();
        var rowAt = now.AddMinutes(-1);
        // Nothing in this org matches "rbac." — a hardcoded/wrong action filter, the exact PoC bug.
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", rowAt, actorId: "actor");

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: new[] { "rbac" }, limit: 100, cursor: null);
        var ok = Assert.IsType<OkObjectResult>(result);
        var root = ParseBody(ok);

        Assert.Equal(0, root.GetProperty("items").GetArrayLength());
        Assert.Equal(0, root.GetProperty("matched").GetInt32());
        // The writer is alive and recently active — a collector reading this distinguishes
        // its own bad filter from a dead writer, which an all-null/zero response could not.
        var latest = DateTimeOffset.Parse(root.GetProperty("latest_event_at").GetString()!);
        Assert.Equal(rowAt, latest);
    }

    /// <summary>
    /// Adversarial pair for tenant isolation at the wired-up controller layer: a tenant-scoped
    /// caller (JWT pinned via <c>TokenOrgId</c>, exactly the code path <c>ResolveOrgFilterAsync</c>
    /// takes for a non-platform-admin) must not see another org's later event reflected in
    /// <c>latest_event_at</c>, even though that other org's row is the true table-wide max.
    /// </summary>
    [Fact]
    public async Task GetAuthEvents_TenantCaller_LatestEventAtDoesNotLeakAnotherOrgsLaterEvent()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        await s.WithOrgAsync("other"); // second tenant, no user — never the authenticated caller
        var b = await s.BuildAsync();

        var now = s.Clock.GetUtcNow();
        var ownOrgLatest = now.AddMinutes(-5);
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", ownOrgLatest, actorId: "own-actor");

        // The other org's row is strictly more recent than anything in the caller's own org.
        string? otherOrgId;
        await using (var lookupConn = await b.Db.OpenAsync())
        {
            otherOrgId = await lookupConn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'other'");
        }
        await SeedAuditAsync(b.Db, otherOrgId!, "login.success", now.AddMinutes(-1), actorId: "other-actor");

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: null, limit: 100, cursor: null);
        var ok = Assert.IsType<OkObjectResult>(result);
        var root = ParseBody(ok);

        var latest = DateTimeOffset.Parse(root.GetProperty("latest_event_at").GetString()!);
        Assert.Equal(ownOrgLatest, latest);
        Assert.Equal(1, root.GetProperty("matched").GetInt32());
    }

    /// <summary>
    /// Positive counterpart: a platform admin (system_admin, unscoped) IS supposed to see
    /// across tenants, so <c>latest_event_at</c> must reflect the table-wide max in that case —
    /// proving the isolation above is a deliberate scope, not an accidental blindness to org
    /// "other" for every caller.
    /// </summary>
    [Fact]
    public async Task GetAuthEvents_PlatformAdmin_LatestEventAtSeesAcrossTenants()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        await s.WithOrgAsync("other");
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = SystemAdminPrincipal();

        var now = s.Clock.GetUtcNow();
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", now.AddMinutes(-5), actorId: "own-actor");

        string? otherOrgId;
        await using (var lookupConn = await b.Db.OpenAsync())
        {
            otherOrgId = await lookupConn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'other'");
        }
        var otherOrgLatest = now.AddMinutes(-1);
        await SeedAuditAsync(b.Db, otherOrgId!, "login.success", otherOrgLatest, actorId: "other-actor");

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: null, limit: 100, cursor: null);
        var ok = Assert.IsType<OkObjectResult>(result);
        var root = ParseBody(ok);

        var latest = DateTimeOffset.Parse(root.GetProperty("latest_event_at").GetString()!);
        Assert.Equal(otherOrgLatest, latest);
    }

    [Fact]
    public async Task GetAuthEvents_Ndjson_ShapeUnchanged_NoNewFieldsOnItemLines()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", s.Clock.GetUtcNow().AddMinutes(-1), actorId: "actor-a");
        b.SiemController.Request.Headers.Accept = "application/x-ndjson";

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        var content = Assert.IsType<ContentResult>(result);
        Assert.NotNull(content.Content);
        string[] lines = content.Content!.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Single(lines); // one item line, no cursor, no envelope-level fields
        Assert.DoesNotContain("latest_event_at", lines[0]);
        Assert.DoesNotContain("matched", lines[0]);
    }

    [Fact]
    public async Task GetAuthEvents_Cef_ShapeUnchanged_NoNewFieldsInBody()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", s.Clock.GetUtcNow().AddMinutes(-1), actorId: "actor-a");
        b.SiemController.Request.Headers.Accept = "application/x-cef";

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        var content = Assert.IsType<ContentResult>(result);
        Assert.NotNull(content.Content);
        Assert.DoesNotContain("latest_event_at", content.Content);
        Assert.DoesNotContain("matched=", content.Content);
    }
}
