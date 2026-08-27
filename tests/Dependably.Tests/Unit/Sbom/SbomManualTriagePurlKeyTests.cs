using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Sbom;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The manual-triage endpoint's own <c>purl_key</c> handling, driven end to end: the API write,
/// then the policy evaluator reading the row back.
///
/// <para>Every writer and reader of the column derives the key through
/// <see cref="SbomPurlKey"/>, so a caller spelling a purl its own way has to be folded before it
/// addresses a row. Stored verbatim it addresses a row the evaluator's canonical derivation never
/// finds — and the failure is silent in the worst possible direction: the endpoint answers 200,
/// the editor renders the decision as saved, and the finding survives with its alert re-firing on
/// the next pass. The fixtures use the spellings canonicalization actually changes; one that
/// happens to already be canonical would pass either way.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomManualTriagePurlKeyTests : IAsyncLifetime
{
    private const string MixedNuGetPurl = "pkg:nuget/Newtonsoft.Json@12.0.1";
    private const string CallerSpelledKey = "pkg:nuget/Newtonsoft.Json";
    private const string CanonicalKey = "pkg:nuget/newtonsoft.json";
    private const string Advisory = "CVE-2100-0003";

    private static readonly DateTimeOffset Now = TestTime.KnownNow;

    private readonly TestMetadataStore _db = new();
    private string _orgId = "";
    private string _projectId = "";
    private string _versionId = "";
    private SbomAnalysisController _controller = null!;
    private SbomPolicyEvaluationService _policy = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_db, $"triage-{Guid.NewGuid():N}");
        _projectId = Guid.NewGuid().ToString("N");
        _versionId = Guid.NewGuid().ToString("N");

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier)
                VALUES (@projectId, @orgId, 'project', 'storefront', 'application')
                """,
                new { projectId = _projectId, orgId = _orgId });
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest)
                VALUES (@versionId, @orgId, @projectId, '1.0.0', 1)
                """,
                new { versionId = _versionId, orgId = _orgId, projectId = _projectId });
            await conn.ExecuteAsync(
                "UPDATE org_settings SET max_osv_score_tolerance = 5.0 WHERE org_id = @orgId",
                new { orgId = _orgId });
        }

        var ingest = new SbomIngestRepository(_db);
        await new SbomMergeService(ingest).MergeComponentsAsync(_orgId, _versionId, Inventory(), Now);
        await LinkAdvisoryAsync();

        BuildServices();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task ATriageOnANonCanonicalPurlActuallySuppressesTheFinding()
    {
        var before = await _policy.EvaluateAndPersistAsync(_orgId, _versionId);
        Assert.Equal("violation", before.PolicyStatus);
        Assert.Equal(1, before.FindingCount);

        var result = await _controller.Triage(_projectId, "latest", new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = CallerSpelledKey,
            VulnKey = Advisory,
            VexState = Optional<string?>.Of("not_affected"),
            VexJustification = Optional<string?>.Of("code_not_reachable"),
        });
        Assert.IsType<OkObjectResult>(result);

        var after = await _policy.EvaluateAndPersistAsync(_orgId, _versionId);

        Assert.Equal(CanonicalKey, await StoredPurlKeyAsync());
        Assert.Equal("pass", after.PolicyStatus);
        Assert.Equal(0, after.FindingCount);
    }

    /// <summary>
    /// An analysis row that matched no component legitimately keys on a scanner's rule id rather
    /// than a purl, so a key that is not purl-shaped is stored exactly as written.
    /// </summary>
    [Fact]
    public async Task AKeyThatIsNotAPurlIsStoredVerbatim()
    {
        var result = await _controller.Triage(_projectId, "latest", new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "RUSTSEC-2100-0001",
            VulnKey = "RUSTSEC-2100-0001",
            VexState = Optional<string?>.Of("exploitable"),
        });
        Assert.IsType<OkObjectResult>(result);

        await using var conn = await _db.OpenAsync();
        string? stored = await conn.ExecuteScalarAsync<string>(
            """
            SELECT purl_key FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId AND vuln_key = @vulnKey
            """,
            new { orgId = _orgId, versionId = _versionId, vulnKey = "RUSTSEC-2100-0001" });

        Assert.Equal("RUSTSEC-2100-0001", stored);
    }

    // ── harness ───────────────────────────────────────────────────────────────

    private static CycloneDxDocument Inventory()
    {
        using var doc = JsonDocument.Parse("""
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.6",
              "components": [
                { "type": "library", "name": "Newtonsoft.Json", "version": "12.0.1",
                  "purl": "pkg:nuget/Newtonsoft.Json@12.0.1" }
              ]
            }
            """);
        return CycloneDxParser.Parse(doc.RootElement);
    }

    private async Task LinkAdvisoryAsync()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, Advisory, ecosystem: "nuget", packageName: "newtonsoft.json", cvssScore: 9.1);

        await using var conn = await _db.OpenAsync();
        string componentId = (await conn.ExecuteScalarAsync<string>(
            """
            SELECT id FROM sbom_components
            WHERE org_id = @orgId AND project_version_id = @versionId AND purl = @purl
            """,
            new { orgId = _orgId, versionId = _versionId, purl = MixedNuGetPurl }))!;
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });
        await conn.ExecuteAsync(
            "UPDATE sbom_components SET vuln_checked_at = @now WHERE id = @componentId",
            new { componentId, now = Now.ToUtcIso() });
    }

    private async Task<string?> StoredPurlKeyAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            """
            SELECT purl_key FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId AND vuln_key = @vulnKey
            """,
            new { orgId = _orgId, versionId = _versionId, vulnKey = Advisory });
    }

    private void BuildServices()
    {
        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(Now);
        string actorId = UserSeeder.InsertAsync(_db, _orgId, "owner@acme.test", role: "owner")
            .GetAwaiter().GetResult();

        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.7");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, actorId),
                new Claim("sub", actorId),
                new Claim("org_id", _orgId),
                new Claim("tid", _orgId),
                new Claim("role", "owner"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        _controller = new SbomAnalysisController(
            new SbomAnalysisRepository(_db, clock),
            new OrgAccessGuard(_db),
            new ProblemResults(new EchoLocalizer()),
            new AuditRepository(_db, time: clock),
            new NoOpReevaluator())
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };

        var licenses = new LicenseRepository(
            _db, clock, new LicenseNormalizer(_db, NullLogger<LicenseNormalizer>.Instance));
        _policy = new SbomPolicyEvaluationService(
            new SbomPolicyRepository(_db, clock),
            new OrgRepository(_db),
            licenses,
            new AlertService(
                new AlertRepository(_db, clock), new NoOpAlertNotifier(), NullLogger<AlertService>.Instance),
            new AuditRepository(_db, activityWriter: null, clock),
            NullLogger<SbomPolicyEvaluationService>.Instance);
    }

    private sealed class NoOpReevaluator : ISbomPolicyReevaluator
    {
        public Task ReevaluateAsync(string orgId, string projectVersionId, CancellationToken ct = default) =>
            Task.CompletedTask;
    }

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);

        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);

        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}
