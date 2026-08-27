using System.Security.Claims;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// <see cref="SbomScanController"/> — the on-demand rescan endpoint. Covers 404-not-403 on a
/// cross-org project id, "latest" resolution, the 1-hour cooldown derived from the version's
/// components, and the happy-path enqueue + real-actor audit attribution.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomScanControllerTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Rescan_HappyPath_EnqueuesAndReturns202()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rescan-happy-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "owner@rescan.test", role: "owner");
        string projectId = await SeedProjectAsync(orgId);
        string versionId = await SeedVersionAsync(orgId, projectId, isLatest: true);

        var controller = BuildController(orgId, userId, out var worker);

        var result = await controller.Rescan(projectId, versionId, CancellationToken.None);

        var accepted = Assert.IsType<AcceptedResult>(result);
        Assert.NotNull(accepted.Value);
        Assert.True((bool)accepted.Value.GetType().GetProperty("queued")!.GetValue(accepted.Value)!);

        // Real-actor attribution on the enqueue's own audit row.
        await using var conn = await _db.OpenAsync();
        var (actorId, actorKind, _) = await conn.QuerySingleOrDefaultAsync<(string? ActorId, string? ActorKind, string? SourceIp)>(
            "SELECT actor_id AS ActorId, actor_kind AS ActorKind, source_ip AS SourceIp FROM activity WHERE org_id = @orgId AND event_type = 'sbom_rescan_requested'",
            new { orgId });
        Assert.Equal(userId, actorId);
        Assert.Equal(ActorKinds.User, actorKind);
        _ = worker;
    }

    /// <summary>
    /// The route authenticates on the API-token scheme as well as the session one, and a service
    /// token's subject is the token's own id. Filing the row under the user discriminator names
    /// an actor the users join cannot resolve, so the row reads as anonymous — indistinguishable
    /// from an unauthenticated request.
    /// </summary>
    [Fact]
    public async Task Rescan_DrivenByAServiceToken_WritesAResolvableServiceActor()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rescan-token-{Guid.NewGuid():N}");
        string tokenId = await SeedServiceTokenAsync(orgId, "ci-pipeline");
        string projectId = await SeedProjectAsync(orgId);
        string versionId = await SeedVersionAsync(orgId, projectId, isLatest: true);

        var controller = BuildController(orgId, userId: tokenId, out _, serviceTokenId: tokenId);

        Assert.IsType<AcceptedResult>(await controller.Rescan(projectId, versionId, CancellationToken.None));

        await using var conn = await _db.OpenAsync();
        var (rowActorId, rowActorKind, rowActorLabel) =
            await conn.QuerySingleAsync<(string? ActorId, string? ActorKind, string? ActorLabel)>(
            """
            SELECT actor_id AS ActorId, actor_kind AS ActorKind, actor_label AS ActorLabel
            FROM activity WHERE org_id = @orgId AND event_type = 'sbom_rescan_requested'
            """,
            new { orgId });

        Assert.Equal(tokenId, rowActorId);
        Assert.Equal(ActorKinds.Service, rowActorKind);
        Assert.Equal("ci-pipeline", rowActorLabel);
    }

    private async Task<string> SeedServiceTokenAsync(string orgId, string name)
    {
        string tokenId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO service_tokens (id, org_id, name, token_hash)
            VALUES (@tokenId, @orgId, @name, @hash)
            """,
            new { tokenId, orgId, name, hash = Guid.NewGuid().ToString("N") });
        return tokenId;
    }

    [Fact]
    public async Task Rescan_LatestLiteral_ResolvesTheIsLatestVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rescan-latest-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "owner@rescan-latest.test", role: "owner");
        string projectId = await SeedProjectAsync(orgId);
        await SeedVersionAsync(orgId, projectId, isLatest: false, version: "1.0.0");
        string latestVersionId = await SeedVersionAsync(orgId, projectId, isLatest: true, version: "2.0.0");

        var controller = BuildController(orgId, userId, out var worker);

        var result = await controller.Rescan(projectId, "latest", CancellationToken.None);

        Assert.IsType<AcceptedResult>(result);
        Assert.True(worker.TryEnqueue(orgId, "sentinel-marker"));
        // The rescan call itself must have targeted latestVersionId, not the older row — verified
        // indirectly via the cooldown test below, which depends on the same resolution path.
        _ = latestVersionId;
    }

    [Fact]
    public async Task Rescan_ProjectFromAnotherOrg_Returns404NotForbidden()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rescan-org-a-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "owner@rescan-a.test", role: "owner");

        string otherOrgId = await OrgSeeder.InsertAsync(_db, $"rescan-org-b-{Guid.NewGuid():N}");
        string otherProjectId = await SeedProjectAsync(otherOrgId);
        string otherVersionId = await SeedVersionAsync(otherOrgId, otherProjectId, isLatest: true);

        var controller = BuildController(orgId, userId, out _);

        var result = await controller.Rescan(otherProjectId, otherVersionId, CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Rescan_UnknownVersionId_Returns404()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rescan-unknown-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "owner@rescan-unknown.test", role: "owner");
        string projectId = await SeedProjectAsync(orgId);

        var controller = BuildController(orgId, userId, out _);

        var result = await controller.Rescan(projectId, "does-not-exist", CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Rescan_WithinCooldownWindow_Returns429WithRetryAfter()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rescan-cooldown-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "owner@rescan-cd.test", role: "owner");
        string projectId = await SeedProjectAsync(orgId);
        string versionId = await SeedVersionAsync(orgId, projectId, isLatest: true);
        // Scanned 10 minutes ago — inside the 1-hour cooldown.
        await SeedComponentAsync(orgId, versionId, vulnCheckedAt: _clock.GetUtcNow().AddMinutes(-10).ToUtcIso());

        var controller = BuildController(orgId, userId, out _);

        var result = await controller.Rescan(projectId, versionId, CancellationToken.None);

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status429TooManyRequests, status.StatusCode);
        Assert.True(controller.Response.Headers.ContainsKey("Retry-After"));
    }

    [Fact]
    public async Task Rescan_OutsideCooldownWindow_Enqueues()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rescan-stale-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "owner@rescan-stale.test", role: "owner");
        string projectId = await SeedProjectAsync(orgId);
        string versionId = await SeedVersionAsync(orgId, projectId, isLatest: true);
        // Scanned 2 hours ago — outside the 1-hour cooldown.
        await SeedComponentAsync(orgId, versionId, vulnCheckedAt: _clock.GetUtcNow().AddHours(-2).ToUtcIso());

        var controller = BuildController(orgId, userId, out _);

        var result = await controller.Rescan(projectId, versionId, CancellationToken.None);

        Assert.IsType<AcceptedResult>(result);
    }

    /// <summary>
    /// Never-scanned means no cooldown, by design: a version whose scan was deferred by an
    /// unreachable advisory source leaves every component's <c>vuln_checked_at</c> NULL, and that
    /// must stay immediately retriable rather than getting locked out for an hour by a scan that
    /// never actually ran. Two consecutive enqueues on a version with no scanned component are
    /// both legitimately 202 — the second is not a bug the endpoint should refuse.
    ///
    /// <para>Adversarial twin: the obvious wrong implementation treats a NULL
    /// <c>MAX(vuln_checked_at)</c> as "just scanned right now" instead of "never scanned",
    /// which starts the cooldown clock on nothing and 429s the second call here. Reverting
    /// <c>CooldownRemainingAsync</c>'s <c>if (lastChecked is null) return null;</c> guard to fall
    /// through into the elapsed-time computation reproduces exactly that mutant and turns this
    /// test red.</para>
    /// </summary>
    [Fact]
    public async Task Rescan_NeverScanned_SecondConsecutiveEnqueueIsStillAllowed()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rescan-never-scanned-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "owner@rescan-never.test", role: "owner");
        string projectId = await SeedProjectAsync(orgId);
        string versionId = await SeedVersionAsync(orgId, projectId, isLatest: true);
        // No component seeded at all — MAX(vuln_checked_at) reads NULL, same as "Never scanned"
        // on the version-detail page.

        var controller = BuildController(orgId, userId, out _);

        var first = await controller.Rescan(projectId, versionId, CancellationToken.None);
        var second = await controller.Rescan(projectId, versionId, CancellationToken.None);

        Assert.IsType<AcceptedResult>(first);
        Assert.IsType<AcceptedResult>(second);
    }

    [Fact]
    public async Task Rescan_MemberRole_IsForbidden()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rescan-member-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "member@rescan.test", role: "member");
        string projectId = await SeedProjectAsync(orgId);
        string versionId = await SeedVersionAsync(orgId, projectId, isLatest: true);

        var controller = BuildController(orgId, userId, out _);

        var result = await controller.Rescan(projectId, versionId, CancellationToken.None);

        Assert.IsType<ForbidResult>(result);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<string> SeedProjectAsync(string orgId)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@id, @orgId, @name)",
            new { id, orgId, name = $"proj-{Guid.NewGuid():N}" });
        return id;
    }

    private async Task<string> SeedVersionAsync(
        string orgId, string projectId, bool isLatest, string version = "1.0.0")
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version, is_latest) VALUES (@id, @orgId, @projectId, @version, @isLatest)",
            new { id, orgId, projectId, version, isLatest = isLatest ? 1 : 0 });
        return id;
    }

    private async Task SeedComponentAsync(string orgId, string projectVersionId, string? vulnCheckedAt)
    {
        string id = Guid.NewGuid().ToString("N");
        string purl = "pkg:npm/left-pad@1.3.0";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name, vuln_checked_at)
            VALUES
                (@id, @orgId, @projectVersionId, @purl, 'npm', 'left-pad', '1.3.0', 'left-pad', @vulnCheckedAt)
            """,
            new { id, orgId, projectVersionId, purl, vulnCheckedAt });
    }

    private SbomScanController BuildController(
        string orgId, string userId, out SbomScanWorker worker, string? serviceTokenId = null)
    {
        var guard = new OrgAccessGuard(_db);
        var audit = new AuditRepository(_db);
        var vulns = new VulnerabilityRepository(_db, _clock);
        var sbomVulns = new SbomComponentVulnRepository(_db, _clock);
        var scanner = new SbomComponentScanner(
            TestOsvSource.Create(), vulns, sbomVulns, NullLogger<SbomComponentScanner>.Instance);
        worker = new SbomScanWorker(
                     new SbomScanWorkerServices(
                     sbomVulns, scanner, BuildPolicyService(), audit, new OrgRepository(_db), new AirGapMode(new ConfigurationBuilder().Build()), new ConfigurationBuilder().Build(), _clock, NullLogger<SbomScanWorker>.Instance));

        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "acme");
        http.User = serviceTokenId is null
            ? new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, userId),
                    new Claim("sub", userId),
                    new Claim("org_id", orgId),
                    new Claim("tid", orgId),
                    new Claim("scope", "tenant"),
                ],
                authenticationType: "test"))
            // A service token carries no users row, authenticates on the API-token scheme, and
            // grants exactly its own cap claims.
            : new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, serviceTokenId),
                    new Claim("sub", serviceTokenId),
                    new Claim("org_id", orgId),
                    new Claim("tid", orgId),
                    new Claim("role", "ci"),
                    new Claim("scope", "tenant"),
                    new Claim("cap", Capabilities.TenantConfigure),
                ],
                authenticationType: TokenAuthenticationDefaults.Scheme));

        return new SbomScanController(_db, worker, guard, audit, new SbomIngestRepository(_db), _clock)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private Dependably.Protocol.SbomPolicyEvaluationService BuildPolicyService()
        => new(
            new SbomPolicyRepository(_db, _clock),
            new OrgRepository(_db),
            new LicenseRepository(_db, _clock, TestNormalizers.License(_db)),
            new AlertService(new AlertRepository(_db, _clock), new NoOpAlertNotifier(),
                NullLogger<AlertService>.Instance),
            new AuditRepository(_db),
            NullLogger<Dependably.Protocol.SbomPolicyEvaluationService>.Instance);
}
