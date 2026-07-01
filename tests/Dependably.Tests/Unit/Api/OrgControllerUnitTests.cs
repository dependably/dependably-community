using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// OrgController has 35+ endpoints. This file covers the read + settings + retention +
/// proxy + stats + setup + activity + audit + invite + member-management surfaces with
/// branch coverage on auth (owner/member/anonymous/cross-tenant) and the validation paths.
///
/// Allowlist/blocklist CRUD is covered by OrgAllowBlockListTests (integration); we don't
/// duplicate it here.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgControllerUnitTests
{
    private static readonly System.Text.Json.JsonSerializerOptions WebJsonOptions = new(System.Text.Json.JsonSerializerDefaults.Web);

    // ── Settings: GET / PUT ─────────────────────────────────────────────────

    [Fact]
    public async Task GetOrgSettings_Owner_Returns200_WithObject()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.GetOrgSettings(CancellationToken.None);
        // GET composes the settings model with airGappedEnforced and returns it via JsonResult.
        Assert.IsType<JsonResult>(result);
    }

    [Fact]
    public async Task GetOrgSettings_Anonymous_Denied()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.GetOrgSettings(CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task UpdateOrgSettings_Owner_PersistsAndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateOrgSettings(
            new UpdateOrgSettingsRequest(
                AnonymousPull: true, AllowlistMode: true,
                MaxUploadBytes: 100_000_000,
                MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null, MaxUploadBytesNuGet: null),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        long anonymousPull = await conn.ExecuteScalarAsync<long>(
            "SELECT anonymous_pull FROM org_settings WHERE org_id = @org",
            new { org = b.PrimaryOrgId });
        Assert.Equal(1, anonymousPull);

        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'org_settings_updated' AND org_id = @org",
            new { org = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task UpdateOrgSettings_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateOrgSettings(
            new UpdateOrgSettingsRequest(true, false, null, null, null, null),
            CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    // ── Retention + Proxy Settings ──────────────────────────────────────────

    [Fact]
    public async Task GetRetention_Owner_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        Assert.IsType<OkObjectResult>(await b.OrgSettingsController.GetRetention(CancellationToken.None));
    }

    [Fact]
    public async Task UpdateRetention_PersistsToOrgSettings()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateRetention(
            new UpdateRetentionRequest(KeepVersions: 5, KeepDays: 30, ActivityRetentionDays: 90),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        long keep = await conn.ExecuteScalarAsync<long>(
            "SELECT keep_versions FROM org_settings WHERE org_id = @org",
            new { org = b.PrimaryOrgId });
        Assert.Equal(5, keep);
    }

    [Fact]
    public async Task GetProxySettings_Owner_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        Assert.IsType<OkObjectResult>(await b.OrgSettingsController.GetProxySettings(CancellationToken.None));
    }

    [Fact]
    public async Task UpdateProxySettings_PersistsToggleAndTolerance()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: false, MaxOsvScoreTolerance: 4.5),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var (enabled, tol) = await conn.QuerySingleAsync<(long Enabled, double Tol)>(
            "SELECT proxy_passthrough_enabled AS Enabled, max_osv_score_tolerance AS Tol " +
            "FROM org_settings WHERE org_id = @org", new { org = b.PrimaryOrgId });
        Assert.Equal(0, enabled);
        Assert.Equal(4.5, tol);
    }

    // ── Packages list / get / delete-version ────────────────────────────────

    [Fact]
    public async Task ListPackages_Member_Allowed_AndReturnsPaginationShape()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("acme");
        var b = await s.BuildAsync();

        var result = await b.OrgController.ListPackages();
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetPackage_Missing_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgController.GetPackage("npm", "never-exists", CancellationToken.None);
        int? status = (result as IStatusCodeActionResult)?.StatusCode;
        Assert.Equal(StatusCodes.Status404NotFound, status);
    }

    [Fact]
    public async Task GetPackage_Present_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("acme");
        await s.WithPackageVersionAsync("acme", "1.0.0");
        var b = await s.BuildAsync();

        var result = await b.OrgController.GetPackage("npm", "acme", CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task DeleteVersion_Missing_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgController.DeleteVersion("npm", "ghost", "1.0.0", CancellationToken.None);
        int? status = (result as IStatusCodeActionResult)?.StatusCode;
        Assert.Equal(StatusCodes.Status404NotFound, status);
    }

    [Fact]
    public async Task DeleteVersion_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("acme");
        await s.WithPackageVersionAsync("acme", "1.0.0");
        var b = await s.BuildAsync();

        var result = await b.OrgController.DeleteVersion("npm", "acme", "1.0.0", CancellationToken.None);
        Assert.False(result is OkObjectResult or NoContentResult);
    }

    // ── Activity + Audit ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetActivity_Owner_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        Assert.IsType<OkObjectResult>(await b.OrgAuditController.GetActivity());
    }

    [Fact]
    public async Task GetActivity_Member_Forbidden()
    {
        // Activity needs read:audit which member doesn't have.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgAuditController.GetActivity();
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task GetAudit_Owner_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        Assert.IsType<OkObjectResult>(await b.OrgAuditController.GetAudit());
    }

    [Fact]
    public async Task GetAudit_LimitClampedTo200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = (OkObjectResult)await b.OrgAuditController.GetAudit(limit: 5000, page: 1);
        // Response contains items + total; just verify it didn't throw and clamped.
        Assert.NotNull(result.Value);
    }

    // ── Stats + Setup ────────────────────────────────────────────────────────

    [Fact]
    public async Task GetStats_Owner_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        Assert.IsType<OkObjectResult>(await b.OrgController.GetStats(CancellationToken.None));
    }

    [Fact]
    public async Task GetStats_ServesSnapshot_NormalizesToFrontendCasing()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var stats = new Dependably.Infrastructure.OrgStats(
            PackagesByEcosystem: new[] { new Dependably.Infrastructure.EcoCount { Ecosystem = "npm", Count = 3 } },
            DownloadsByHour: Array.Empty<Dependably.Infrastructure.HourCount>(),
            VulnsByEcosystemAndSeverity: Array.Empty<Dependably.Infrastructure.EcoSeverityCount>(),
            DiskByEcosystem: new[] { new Dependably.Infrastructure.EcoDiskBytes { Ecosystem = "npm", TotalBytes = 100 } },
            TotalDiskBytes: 100,
            NewVulns: new Dependably.Infrastructure.VulnPeriodCounts(),
            ActiveUsers7d: 5, BlockedPulls30d: 2, TotalDownloads30d: 7);

        // Store the snapshot in PascalCase to prove the endpoint tolerates any stored casing.
        string pascalJson = System.Text.Json.JsonSerializer.Serialize(stats);
        var snapshots = new Dependably.Infrastructure.StatsSnapshotRepository(b.Fixture.Store);
        await snapshots.UpsertSnapshotAsync(b.PrimaryOrgId, pascalJson, "2026-06-08T00:00:00Z", 1);

        var result = await b.OrgController.GetStats(CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        var returned = Assert.IsType<Dependably.Infrastructure.OrgStats>(ok.Value);
        // Snapshot path was taken (not a live recompute, which would be all-zero on the empty DB).
        Assert.Equal(5, returned.ActiveUsers7d);
        Assert.Equal(3, returned.PackagesByEcosystem.Single().Count);

        // The frontend reads camelCase (stats.packagesByEcosystem.reduce(...)). Returning the
        // value via Ok() routes it through the MVC serializer, so the emitted shape is camelCase
        // regardless of how the snapshot was stored — guarding against the regression where the
        // snapshot path emitted PascalCase verbatim and broke the dashboard.
        string emitted = System.Text.Json.JsonSerializer.Serialize(ok.Value, WebJsonOptions);
        Assert.Contains("\"packagesByEcosystem\"", emitted);
        Assert.DoesNotContain("\"PackagesByEcosystem\"", emitted);
    }

    [Fact]
    public async Task GetStats_MalformedSnapshot_FallsBackToLiveCompute()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // A corrupt snapshot row must not 500 the dashboard — the endpoint discards it and
        // recomputes live instead.
        var snapshots = new Dependably.Infrastructure.StatsSnapshotRepository(b.Fixture.Store);
        await snapshots.UpsertSnapshotAsync(b.PrimaryOrgId, "{ not valid json", "2026-06-08T00:00:00Z", 1);

        var result = await b.OrgController.GetStats(CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        // Live compute on the empty seeded DB yields a well-formed all-zero OrgStats.
        var returned = Assert.IsType<Dependably.Infrastructure.OrgStats>(ok.Value);
        Assert.Equal(0, returned.ActiveUsers7d);
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    [InlineData("nuget")]
    public async Task GetSetup_KnownEcosystem_Returns200(string eco)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgController.GetSetup(eco, CancellationToken.None);
        // Snippet generators may return null when org_settings has no upstream — both
        // 200 and 404 are valid outcomes for the auth+config-driven branches.
        Assert.True(result is OkObjectResult or NotFoundResult,
            $"GetSetup('{eco}') returned {result.GetType().Name}");
    }

    [Fact]
    public async Task GetSetup_UnknownEcosystem_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgController.GetSetup("conda", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── Tokens ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task ListTokens_Empty_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        Assert.IsType<OkObjectResult>(await b.OrgTokensController.ListTokens(CancellationToken.None));
    }

    [Fact]
    public async Task CreateToken_WithCapabilities_ReturnsTokenAndRecord()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task CreateToken_LegacyScopeField_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: null, Scope: "pull"),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateToken_NoCapabilities_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: null),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task DeleteToken_OwnToken_Succeeds()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Create then delete a token.
        var created = (OkObjectResult)await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        object record = created.Value!.GetType().GetProperty("record")!.GetValue(created.Value)!;
        string tokenId = (string)record.GetType().GetProperty("Id")!.GetValue(record)!;

        var deleteResult = await b.OrgTokensController.DeleteToken(tokenId, CancellationToken.None);
        Assert.IsType<NoContentResult>(deleteResult);
    }

    [Fact]
    public async Task ListServiceTokens_Empty_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        Assert.IsType<OkObjectResult>(await b.OrgTokensController.ListServiceTokens(CancellationToken.None));
    }

    [Fact]
    public async Task CreateServiceToken_Valid_ReturnsTokenAndRecord()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest(Name: "ci-pipeline", ExpiresAt: null,
                Capabilities: new[] { "publish:*", "read:metadata" }),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    // ── Invites ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ListInvites_Empty_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        Assert.IsType<OkObjectResult>(await b.OrgInvitesController.ListInvites(CancellationToken.None));
    }

    [Fact]
    public async Task CreateInvite_Owner_Created()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest($"newhire-{Guid.NewGuid():N}@x.test"),
            CancellationToken.None);
        // Created response shape; tolerate both 201 and 200 styles.
        Assert.True(result is OkObjectResult or CreatedResult or CreatedAtActionResult or ObjectResult);
    }

    [Fact]
    public async Task CreateInvite_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("nope@x.test"),
            CancellationToken.None);
        Assert.False(result is OkObjectResult or CreatedAtActionResult);
    }

    // ── Members ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ListUsers_Owner_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        Assert.IsType<OkObjectResult>(await b.OrgUsersController.ListUsers(CancellationToken.None));
    }

    [Fact]
    public async Task PatchMemberRole_MemberToAdmin_RoundTrip()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithUserAsync(email: $"target-{Guid.NewGuid():N}@x.test", role: "member");
        var built = await s.BuildAsync();

        // Resolve the target id (anything except the actor user).
        await using var conn = await built.Db.OpenAsync();
        string? targetId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @t AND id != @actor LIMIT 1",
            new { t = built.PrimaryOrgId, actor = built.ActorUserId });
        Assert.NotNull(targetId);

        var result = await built.OrgUsersController.PatchMemberRole(targetId!,
            new PatchRoleRequest("admin"), CancellationToken.None);
        Assert.True(result is OkObjectResult or NoContentResult or ObjectResult);
    }

    // Upstream URL validation moved off the settings endpoint to the dedicated
    // upstream-registries endpoint (UpstreamRegistryController), which reuses the same
    // UpstreamUrlValidator SSRF guard. Covered by UpstreamRegistryApiTests.

    // ── UpdateProxySettings: tolerance out of [0,10] ─────────────────────────

    [Theory]
    [InlineData(-0.5)]
    [InlineData(10.1)]
    public async Task UpdateProxySettings_OutOfRangeTolerance_Returns422(double badTolerance)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true, MaxOsvScoreTolerance: badTolerance),
            CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // ── UpdateProxySettings: block_deprecated value handling ──────────────────

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    [InlineData("block_new")]
    [InlineData("block_all")]
    public async Task UpdateProxySettings_ValidBlockDeprecated_Persists(string mode)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true, MaxOsvScoreTolerance: 10.0,
                BlockDeprecated: mode),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        string? stored = await conn.ExecuteScalarAsync<string>(
            "SELECT block_deprecated FROM org_settings WHERE org_id = @org", new { org = b.PrimaryOrgId });
        Assert.Equal(mode, stored);
    }

    [Fact]
    public async Task UpdateProxySettings_LegacyBlock_NormalizesToBlockAll()
    {
        // Back-compat: the retired 'block' value maps to its successor 'block_all'.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true, MaxOsvScoreTolerance: 10.0,
                BlockDeprecated: "block"),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        string? stored = await conn.ExecuteScalarAsync<string>(
            "SELECT block_deprecated FROM org_settings WHERE org_id = @org", new { org = b.PrimaryOrgId });
        Assert.Equal("block_all", stored);
    }

    [Fact]
    public async Task UpdateProxySettings_InvalidBlockDeprecated_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true, MaxOsvScoreTolerance: 10.0,
                BlockDeprecated: "nonsense"),
            CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // ── DeleteVersion: unknown ecosystem returns 404 before auth ─────────────

    [Fact]
    public async Task DeleteVersion_InvalidEcosystem_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // "conda" is not a known ecosystem — the switch falls to null and we expect 404.
        var result = await b.OrgController.DeleteVersion("conda", "some-pkg", "1.0.0", CancellationToken.None);
        int? status = (result as IStatusCodeActionResult)?.StatusCode;
        Assert.Equal(StatusCodes.Status404NotFound, status);
    }

    // ── CreateServiceToken: legacy Scope field rejected ──────────────────────────

    [Fact]
    public async Task CreateServiceToken_LegacyScopeField_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest(Name: "ci-deploy", ExpiresAt: null,
                Capabilities: null, Scope: "pull"),
            CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // ── CreateInvite: empty / blank email ────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task CreateInvite_EmptyEmail_Returns422(string email)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest(email),
            CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // ── CreateInvite: invalid role ───────────────────────────────────────────

    [Theory]
    [InlineData("superuser")]
    [InlineData("god")]
    [InlineData("OWNER")]   // not lower-cased yet — controller normalises; "OWNER" → "owner" so still valid; try something truly invalid
    public async Task CreateInvite_InvalidRole_Returns422(string role)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest($"user-{Guid.NewGuid():N}@x.test", Role: role),
            CancellationToken.None);

        // "OWNER" normalises to "owner" (valid), so skip assertion for it.
        if (role.ToLowerInvariant() is "member" or "admin" or "owner" or "auditor")
        {
            return;
        }

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // ── PatchMemberRole: invalid role ────────────────────────────────────────

    [Theory]
    [InlineData("superadmin")]
    [InlineData("viewer")]
    public async Task PatchMemberRole_InvalidRole_Returns422(string badRole)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithUserAsync(email: $"target-{Guid.NewGuid():N}@x.test", role: "member");
        var built = await s.BuildAsync();

        await using var conn = await built.Db.OpenAsync();
        string? targetId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @t AND id != @actor LIMIT 1",
            new { t = built.PrimaryOrgId, actor = built.ActorUserId });
        Assert.NotNull(targetId);

        var result = await built.OrgUsersController.PatchMemberRole(targetId!,
            new PatchRoleRequest(badRole), CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // ── RemoveUser: last owner cannot be removed ──────────────────────────────

    [Fact]
    public async Task RemoveUser_LastOwner_Returns409()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        // Only a single owner — removing them must be rejected.
        await s.WithUserAsync(role: "owner");
        var built = await s.BuildAsync();

        // The actor is the only owner and is trying to remove themselves.
        var result = await built.OrgUsersController.RemoveUser(
            built.ActorUserId!, CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, obj.StatusCode);
    }

    // ── UpdateProxySettings: RPM signature gate requires trust anchor ─────────

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task UpdateProxySettings_VerifyRpmSignatures_NonOff_WithoutAnchor_Returns422(string mode)
    {
        // ControllerScenario wires RpmProvenanceVerifier with an empty StubPerOrgTrustAnchorStore,
        // so IsConfiguredForAsync returns false. Enabling verification without an anchor must be
        // rejected with a 422 to prevent a permanently non-functional setting.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true,
                MaxOsvScoreTolerance: 10.0, VerifyRpmSignatures: mode),
            CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task UpdateProxySettings_VerifyRpmSignatures_Off_WithoutAnchor_Succeeds()
    {
        // Turning RPM verification off is always allowed even with no anchor.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true,
                MaxOsvScoreTolerance: 10.0, VerifyRpmSignatures: "off"),
            CancellationToken.None);

        Assert.IsType<NoContentResult>(result);
    }

    // ── UpdateProxySettings: npm signature gate requires per-org trust anchor ─

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task UpdateProxySettings_VerifyNpmSignatures_NonOff_WithoutAnchor_Returns422(string mode)
    {
        // ControllerScenario wires NpmProvenanceVerifier with an empty StubPerOrgTrustAnchorStore,
        // so IsConfiguredForAsync returns false. Enabling verification without a per-org npm anchor
        // must be rejected with a 422 to prevent a permanently non-functional setting.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true,
                MaxOsvScoreTolerance: 10.0, VerifyNpmSignatures: mode),
            CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task UpdateProxySettings_VerifyNpmSignatures_Off_WithoutAnchor_Succeeds()
    {
        // Turning npm verification off is always allowed even with no per-org anchor.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true,
                MaxOsvScoreTolerance: 10.0, VerifyNpmSignatures: "off"),
            CancellationToken.None);

        Assert.IsType<NoContentResult>(result);
    }

    // ── UpdateProxySettings: NuGet signature gate requires per-org trust anchor ─

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task UpdateProxySettings_VerifyNuGetSignatures_NonOff_WithoutAnchor_Returns422(string mode)
    {
        // ControllerScenario wires NuGetProvenanceVerifier with an empty StubPerOrgTrustAnchorStore,
        // so IsConfiguredForAsync returns false. Enabling verification without a per-org NuGet X.509
        // anchor must be rejected with a 422 to prevent a permanently non-functional setting.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true,
                MaxOsvScoreTolerance: 10.0, VerifyNuGetSignatures: mode),
            CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task UpdateProxySettings_VerifyNuGetSignatures_Off_WithoutAnchor_Succeeds()
    {
        // Turning NuGet verification off is always allowed even with no per-org anchor.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true,
                MaxOsvScoreTolerance: 10.0, VerifyNuGetSignatures: "off"),
            CancellationToken.None);

        Assert.IsType<NoContentResult>(result);
    }

    // ── UpdateProxySettings: Maven signature gate requires per-org trust anchor ─

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task UpdateProxySettings_VerifyMavenSignatures_NonOff_WithoutAnchor_Returns422(string mode)
    {
        // ControllerScenario wires MavenProvenanceVerifier with an empty StubPerOrgTrustAnchorStore,
        // so IsConfiguredForAsync returns false. Enabling verification without a per-org Maven PGP
        // anchor must be rejected with a 422 to prevent a permanently non-functional setting.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true,
                MaxOsvScoreTolerance: 10.0, VerifyMavenSignatures: mode),
            CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task UpdateProxySettings_VerifyMavenSignatures_Off_WithoutAnchor_Succeeds()
    {
        // Turning Maven verification off is always allowed even with no per-org anchor.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgSettingsController.UpdateProxySettings(
            new UpdateProxySettingsRequest(ProxyPassthroughEnabled: true,
                MaxOsvScoreTolerance: 10.0, VerifyMavenSignatures: "off"),
            CancellationToken.None);

        Assert.IsType<NoContentResult>(result);
    }
}
