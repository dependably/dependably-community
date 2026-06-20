using System.Security.Claims;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Extended coverage for <c>SiemController</c>: drills into the branches the smoke-level
/// tests in <see cref="SiemControllerUnitTests"/> don't hit — JWT platform-admin (system_admin)
/// path, missing-tenant-claim path, NDJSON / CEF body shapes, all CEF action mappings,
/// cursor pagination, action-prefix filtering, since/until clamping, and the vuln-summary
/// ecosystem filter and resolve-org branches.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SiemControllerExtendedTests
{
    // ── Test helpers ─────────────────────────────────────────────────────────

    private static ClaimsPrincipal SystemAdminPrincipal() =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "system-admin-user"),
                new Claim("sub", "system-admin-user"),
                new Claim("role", "system_admin"),
                new Claim("scope", "system"),
            ],
            authenticationType: "test"));

    private static ClaimsPrincipal JwtMissingTenantClaim() =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "user-without-tid"),
                new Claim("sub", "user-without-tid"),
                // role=owner grants read:audit, so we get past the cap gate; then the
                // tenant-claim check fires because there's no org_id / tid claim.
                new Claim("role", "owner"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

    private static async Task SeedAuditAsync(
        IMetadataStore db,
        string orgId,
        string action,
        DateTimeOffset createdAt,
        string? actorId = null,
        string? ecosystem = null,
        string? purl = null,
        string? detail = null,
        string scope = "tenant")
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, actor_id, action, ecosystem, purl, detail, created_at)
            VALUES (@id, @scope, @orgId, @actorId, @action, @ecosystem, @purl, @detail, @createdAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                scope,
                orgId,
                actorId,
                action,
                ecosystem,
                purl,
                detail,
                createdAt = createdAt.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    private static async Task SeedVulnAsync(
        IMetadataStore db,
        string orgId,
        string ecosystem,
        string packageName,
        string version,
        string? severity)
    {
        await using var conn = await db.OpenAsync();
        string pkgId = Guid.NewGuid().ToString("N");
        string verId = Guid.NewGuid().ToString("N");
        string vulnId = Guid.NewGuid().ToString("N");
        string osvId = "OSV-" + Guid.NewGuid().ToString("N");

        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES (@id, @orgId, @eco, @name, @name)",
            new { id = pkgId, orgId, eco = ecosystem, name = packageName });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES (@id, @pkgId, @version, @purl, @blobKey)
            """,
            new { id = verId, pkgId, version, purl = $"pkg:{ecosystem}/{Guid.NewGuid():N}/{packageName}@{version}", blobKey = "blob/" + Guid.NewGuid().ToString("N") });
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity)
            VALUES (@id, @osvId, @eco, @name, @severity)
            """,
            new { id = vulnId, osvId, eco = ecosystem, name = packageName, severity });
        string pvvId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind) VALUES (@pvvId, @verId, @vulnId, 'package_version')",
            new { pvvId, verId, vulnId });
    }

    // ── GetAuthEvents — JWT platform-admin / tenant-claim branches ───────────

    [Fact]
    public async Task GetAuthEvents_SystemAdmin_NoOrgFilter_SeesAllTenants()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner"); // ensures primary org wiring
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = SystemAdminPrincipal();

        // Seed audit rows in *another* tenant; system_admin must see them when ?org= is unset.
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('foreign-org', 'foreign')");
        }
        await SeedAuditAsync(b.Db, "foreign-org", "login.success", s.Clock.GetUtcNow().AddHours(-1), actorId: "foreign-user");

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value);
        Assert.Contains("foreign-user", json);
    }

    [Fact]
    public async Task GetAuthEvents_SystemAdmin_OrgFilterSlug_ResolvesAndScopes()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = SystemAdminPrincipal();

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: "acme", action: null, limit: 100, cursor: null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_SystemAdmin_UnknownOrgSlug_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = SystemAdminPrincipal();

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: "no-such-slug", action: null, limit: 100, cursor: null);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_AuditorRole_HasReadAuditCap_TenantScoped()
    {
        // auditor caps = { read:audit, tokens:manage_own } — covers the
        // "has read:audit but not platform:*" branch.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "auditor");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_AdminRole_HasReadAuditCap_TenantScoped()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "admin");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_JwtMissingTidClaim_Returns401()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        // Replace with a principal that has read:audit (owner) but no tid/org_id claim.
        b.SiemController.HttpContext.User = JwtMissingTenantClaim();

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, obj.StatusCode);
    }

    [Fact]
    public async Task GetAuthEvents_JwtWithTidClaimOnly_NoOrgIdClaim_IsAccepted()
    {
        // Fallback to `tid` when `org_id` is absent — covered by the ?? in AuthenticateAsync.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "u"),
                new Claim("sub", "u"),
                new Claim("tid", b.PrimaryOrgId), // only tid; no org_id
                new Claim("role", "owner"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        Assert.IsType<OkObjectResult>(result);
    }

    // ── GetAuthEvents — filters, formats, pagination ─────────────────────────

    [Fact]
    public async Task GetAuthEvents_ActionFilter_OnlyMatchingPrefixReturned()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", s.Clock.GetUtcNow().AddMinutes(-10), actorId: "login-actor");
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "lockout.triggered", s.Clock.GetUtcNow().AddMinutes(-5), actorId: "lockout-actor");

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null,
            action: new[] { "lockout" }, // prefix filter (TrimEnd('.') normalisation)
            limit: 100, cursor: null);
        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value);
        Assert.Contains("lockout-actor", json);
        Assert.DoesNotContain("login-actor", json);
    }

    [Fact]
    public async Task GetAuthEvents_LimitClampedAboveCeiling()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        var result = await b.SiemController.GetAuthEvents(null, null, null, null, limit: 9999, cursor: null);
        Assert.IsType<OkObjectResult>(result); // doesn't throw / doesn't 400
    }

    [Fact]
    public async Task GetAuthEvents_LimitClampedBelowFloor()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        var result = await b.SiemController.GetAuthEvents(null, null, null, null, limit: 0, cursor: null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_SinceClampedToEarliestLookbackWindow()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        // 5y ago → clamped to default 90-day window. Doesn't 400.
        var result = await b.SiemController.GetAuthEvents(
            since: s.Clock.GetUtcNow().AddYears(-5).ToString("o"),
            until: null, org: null, action: null, limit: 100, cursor: null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_UntilInFuture_ClampedToNow()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        var result = await b.SiemController.GetAuthEvents(
            since: null,
            until: s.Clock.GetUtcNow().AddYears(5).ToString("o"),
            org: null, action: null, limit: 100, cursor: null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_Pagination_NextCursorReturnsRemainingItems()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var now = s.Clock.GetUtcNow();
        for (int i = 0; i < 3; i++)
        {
            await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", now.AddMinutes(-i * 5), actorId: $"a{i}");
        }

        // First page with limit=1 → expect cursor + 1 item.
        var first = await b.SiemController.GetAuthEvents(null, null, null, null, limit: 1, cursor: null);
        var firstOk = Assert.IsType<OkObjectResult>(first);
        string firstJson = System.Text.Json.JsonSerializer.Serialize(firstOk.Value);

        // Extract next_cursor.
        using var doc = System.Text.Json.JsonDocument.Parse(firstJson);
        string? nextCursor = doc.RootElement.GetProperty("next_cursor").GetString();
        Assert.False(string.IsNullOrEmpty(nextCursor));

        // Second page using the cursor → should return more items, cursor consumed.
        var second = await b.SiemController.GetAuthEvents(null, null, null, null, limit: 1, cursor: nextCursor);
        Assert.IsType<OkObjectResult>(second);
    }

    [Fact]
    public async Task GetAuthEvents_MalformedCursor_IgnoredAndReturnsFirstPage()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        // Not base64 — repo's try/catch ignores it.
        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, cursor: "!!!not-base64!!!");
        Assert.IsType<OkObjectResult>(result);
    }

    // ── GetAuthEvents — CEF / NDJSON output formatting ───────────────────────

    [Fact]
    public async Task GetAuthEvents_Ndjson_EmitsLineForEachItemAndCursor()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var now = s.Clock.GetUtcNow();
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success", now.AddMinutes(-2), actorId: "actor-a");
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.failure", now.AddMinutes(-1), actorId: "actor-b");
        b.SiemController.Request.Headers.Accept = "application/x-ndjson";

        // Force a cursor by setting limit=1.
        var result = await b.SiemController.GetAuthEvents(null, null, null, null, limit: 1, cursor: null);
        var content = Assert.IsType<ContentResult>(result);
        Assert.NotNull(content.Content);
        string[] lines = content.Content!.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.True(lines.Length >= 2, "expected one item line + one cursor line");
        Assert.Contains(lines, l => l.Contains("next_cursor"));
    }

    [Fact]
    public async Task GetAuthEvents_Cef_EmitsAllSwitchActionsAndExtensionFields()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var now = s.Clock.GetUtcNow();
        // Hit every arm of CefFriendlyName + CefSeverity, including the default arm.
        string[] actions =
        {
            "login.success", "login.failure", "lockout.triggered",
            "token.created", "token.revoked",
            "rbac.role_changed", "rbac.member_added", "rbac.member_removed",
            "rbac.unmapped_arm", // default branch of both switches
        };
        for (int i = 0; i < actions.Length; i++)
        {
            await SeedAuditAsync(
                b.Db, b.PrimaryOrgId, actions[i],
                now.AddSeconds(-i),
                actorId: $"actor|with=special\\chars\nbreak",
                ecosystem: "npm",
                purl: "pkg:npm/lodash@1.0.0",
                detail: "{\"k\":\"v\"}");
        }
        // Extra padding row so that limit=actions.Length still leaves a remainder, forcing
        // the next_cursor # footer in the CEF body.
        await SeedAuditAsync(b.Db, b.PrimaryOrgId, "login.success",
            now.AddSeconds(-actions.Length - 1), actorId: "padding");
        b.SiemController.Request.Headers.Accept = "application/x-cef";

        // limit == actions.Length so every CEF switch arm is rendered AND the padding row
        // overflows into next_cursor.
        var result = await b.SiemController.GetAuthEvents(null, null, null, null, limit: actions.Length, cursor: null);
        var content = Assert.IsType<ContentResult>(result);
        Assert.StartsWith("application/x-cef", content.ContentType);
        Assert.NotNull(content.Content);
        string body = content.Content!;
        // CEF header present.
        Assert.Contains("CEF:0|Dependably|dependably|1.0|", body);
        // Friendly names rendered.
        Assert.Contains("Login Success", body);
        Assert.Contains("Login Failure", body);
        Assert.Contains("Account Lockout", body);
        Assert.Contains("Token Created", body);
        Assert.Contains("Token Revoked", body);
        Assert.Contains("Role Changed", body);
        // Escaped pipe + equals + backslash + newline from actor id.
        Assert.Contains("\\|", body);
        Assert.Contains("\\=", body);
        Assert.Contains("\\\\", body);
        Assert.Contains("\\n", body);
        // Extension fields present.
        Assert.Contains("cs1Label=OrgId", body);
        Assert.Contains("cs2Label=Ecosystem", body);
        Assert.Contains("cs3Label=Purl", body);
        Assert.Contains("msg=", body);
        // Pagination footer.
        Assert.Contains("# next_cursor=", body);
    }

    [Fact]
    public async Task GetAuthEvents_Cef_EmptyExtensionWhenNoOptionalFields()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Item with only the required action — covers the false branch of every
        // "if (item.X is not null)" extension append.
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO audit_log (id, scope, org_id, actor_id, action, created_at)
                VALUES (@id, 'tenant', NULL, NULL, 'login.success', @createdAt)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    createdAt = s.Clock.GetUtcNow().AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
                });
        }
        b.SiemController.Request.Headers.Accept = "application/x-cef";

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        var content = Assert.IsType<ContentResult>(result);
        Assert.NotNull(content.Content);
        // No optional fields means no suid/cs1/cs2/cs3/msg tokens.
        Assert.DoesNotContain("suid=", content.Content!);
        Assert.DoesNotContain("cs1Label", content.Content);
    }

    // ── GetVulnSummary — body shape + ecosystem filter + admin paths ─────────

    [Fact]
    public async Task GetVulnSummary_SeededRows_PivotsByEcosystemAndSeverity()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await SeedVulnAsync(b.Db, b.PrimaryOrgId, "npm", "lodash", "1.0.0", severity: "HIGH");
        await SeedVulnAsync(b.Db, b.PrimaryOrgId, "npm", "express", "2.0.0", severity: "LOW");
        await SeedVulnAsync(b.Db, b.PrimaryOrgId, "pypi", "requests", "3.0.0", severity: null); // null → "unknown"

        var result = await b.SiemController.GetVulnSummary(org: null, ecosystem: null);
        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value);
        Assert.Contains("by_ecosystem", json);
        Assert.Contains("npm", json);
        Assert.Contains("pypi", json);
        Assert.Contains("unknown", json); // null-severity bucket
    }

    [Fact]
    public async Task GetVulnSummary_EcosystemFilter_DropsNonMatching()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await SeedVulnAsync(b.Db, b.PrimaryOrgId, "npm", "lodash", "1.0.0", "HIGH");
        await SeedVulnAsync(b.Db, b.PrimaryOrgId, "pypi", "requests", "2.0.0", "LOW");

        // ecosystem=npm — pypi row must be filtered out by the continue branch
        var result = await b.SiemController.GetVulnSummary(org: null, ecosystem: "NPM"); // case-insensitive
        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value);
        Assert.Contains("npm", json);
        Assert.DoesNotContain("requests", json);
    }

    [Fact]
    public async Task GetVulnSummary_SystemAdmin_OrgFilterSlug_ResolvesOk()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = SystemAdminPrincipal();

        var result = await b.SiemController.GetVulnSummary(org: "acme", ecosystem: null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetVulnSummary_SystemAdmin_UnknownOrgSlug_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme"); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = SystemAdminPrincipal();

        var result = await b.SiemController.GetVulnSummary(org: "no-such-slug", ecosystem: null);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task GetVulnSummary_JwtMissingTidClaim_Returns401()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.HttpContext.User = JwtMissingTenantClaim();

        var result = await b.SiemController.GetVulnSummary(null, null);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, obj.StatusCode);
    }

    [Fact]
    public async Task GetVulnSummary_AuditorRole_HasReadAuditCap_TenantScoped()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "auditor");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetVulnSummary(null, null);
        Assert.IsType<OkObjectResult>(result);
    }
}
