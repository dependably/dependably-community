using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The reverse blast-radius read: "I just quarantined this package — which of my applications ship
/// it?", by coordinate and by advisory, plus the batch count a table renders one cell per row from.
///
/// <para>Every case runs against a real schema, because the whole feature is a join across four
/// tables and the interesting failures (a tenant filter on the wrong row, a superseded release
/// counted as current, a cross-product count leaking between coordinates) are all things only the
/// database can demonstrate.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomBlastRadiusTests
{
    [Fact]
    public async Task ByPackage_NamesTheApplicationsShippingTheCoordinate()
    {
        await using var world = await World.CreateAsync();
        await world.SeedAppAsync("storefront", "2.1.0", isLatest: true, componentVersion: "1.2.5");
        await world.SeedAppAsync("billing", "0.9.0", isLatest: true, componentVersion: "1.1.0");

        using var body = await world.ByPackageAsync("npm", "left-pad");

        Assert.Equal(2, body.RootElement.GetProperty("total").GetInt32());
        Assert.Equal(2, body.RootElement.GetProperty("projectCount").GetInt32());
        var names = body.RootElement.GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("projectName").GetString()).ToList();
        Assert.Equal(["billing", "storefront"], names);
        // The version the application actually ships, which need not be the one the operator asked
        // about — remediation needs to know which.
        Assert.Equal("1.1.0", body.RootElement.GetProperty("items")[0].GetProperty("componentVersion").GetString());
    }

    [Fact]
    public async Task ByPackage_HeadlineCountIsTheWholeResultNotThePageThatFitted()
    {
        // Adversarial twin for the number the UI headlines. Deriving projectCount from the
        // returned rows caps it at the page limit, so a coordinate shipped by five applications
        // reads as "2 applications ship this" on a page of two — the same failure the counts
        // endpoint refuses an over-large batch to avoid: a security number that reads safer than
        // reality. `total` still counts rows, because that is what paginates.
        await using var world = await World.CreateAsync();
        for (int i = 0; i < 5; i++)
        {
            await world.SeedAppAsync($"app-{i}", "1.0.0", isLatest: true, componentVersion: "1.2.5");
        }

        using var body = await world.ByPackageAsync("npm", "left-pad", limit: 2);

        Assert.Equal(2, body.RootElement.GetProperty("items").GetArrayLength());
        Assert.Equal(5, body.RootElement.GetProperty("projectCount").GetInt32());
        Assert.Equal(5, body.RootElement.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task ByAdvisory_HeadlineCountIsTheWholeResultNotThePageThatFitted()
    {
        await using var world = await World.CreateAsync();
        for (int i = 0; i < 4; i++)
        {
            await world.SeedAppAsync($"app-{i}", "1.0.0", isLatest: true, componentVersion: "1.2.5", advisory: Osv);
        }

        using var body = await world.ByAdvisoryAsync(Osv, limit: 1);

        Assert.Equal(1, body.RootElement.GetProperty("items").GetArrayLength());
        Assert.Equal(4, body.RootElement.GetProperty("projectCount").GetInt32());
    }

    [Fact]
    public async Task ByPackage_HeadlineCountStillCollapsesAnApplicationShippingTheCoordinateTwice()
    {
        // The companion constraint: the headline is DISTINCT applications, so a version-wide count
        // must not become a row count. One application listing the coordinate twice is one
        // application, and `total` — which paginates — is the one that sees both rows.
        await using var world = await World.CreateAsync();
        await world.SeedAppAsync("storefront", "2.1.0", isLatest: true, componentVersion: "1.2.5");
        await world.AddComponentToLatestAsync("storefront", componentVersion: "1.1.0");

        using var body = await world.ByPackageAsync("npm", "left-pad");

        Assert.Equal(1, body.RootElement.GetProperty("projectCount").GetInt32());
        Assert.Equal(2, body.RootElement.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task ByPackage_AnotherTenantsApplicationIsNotInTheBlastRadius()
    {
        // Adversarial twin. The org filter sits on sbom_components — the only row in the join that
        // carries one — and it is bound from the authenticated principal, never from the request.
        // A filter written on projects alone, or omitted, turns this endpoint into a cross-tenant
        // inventory read.
        await using var world = await World.CreateAsync();
        await world.SeedAppAsync("storefront", "2.1.0", isLatest: true, componentVersion: "1.2.5");
        await world.SeedForeignAppAsync("their-app", componentVersion: "1.2.5");

        using var body = await world.ByPackageAsync("npm", "left-pad");

        Assert.Equal(1, body.RootElement.GetProperty("total").GetInt32());
        Assert.Equal(
            "storefront",
            Assert.Single(body.RootElement.GetProperty("items").EnumerateArray())
                .GetProperty("projectName").GetString());
    }

    [Fact]
    public async Task ByPackage_ASupersededReleaseIsNotCountedAsShipping()
    {
        // Latest versions only. An older release is neither what the tenant ships nor something
        // the nightly scan keeps current, so counting it mixes a live answer with a stale one.
        await using var world = await World.CreateAsync();
        await world.SeedAppAsync("storefront", "1.0.0", isLatest: false, componentVersion: "1.2.5");

        using var body = await world.ByPackageAsync("npm", "left-pad");

        Assert.Equal(0, body.RootElement.GetProperty("total").GetInt32());
        Assert.Empty(body.RootElement.GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task ByPackage_AnUnshippedCoordinateAnswersEmptyRatherThanFailing()
    {
        await using var world = await World.CreateAsync();
        using var body = await world.ByPackageAsync("npm", "never-heard-of-it");

        Assert.Equal(0, body.RootElement.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task ByPackage_RequiresBothHalvesOfTheCoordinate()
    {
        await using var world = await World.CreateAsync();
        var missingName = await world.Controller.ByPackage(
            new BlastRadiusPackageRequest { Ecosystem = "npm" });
        var missingEcosystem = await world.Controller.ByPackage(
            new BlastRadiusPackageRequest { Name = "left-pad" });

        Assert.Equal(
            StatusCodes.Status422UnprocessableEntity,
            Assert.IsType<ObjectResult>(missingName).StatusCode);
        Assert.Equal(
            StatusCodes.Status422UnprocessableEntity,
            Assert.IsType<ObjectResult>(missingEcosystem).StatusCode);
    }

    [Fact]
    public async Task ByAdvisory_NamesTheApplicationsShippingAComponentLinkedToIt()
    {
        await using var world = await World.CreateAsync();
        await world.SeedAppAsync("storefront", "2.1.0", isLatest: true, componentVersion: "1.2.5", advisory: Osv);

        using var body = await world.ByAdvisoryAsync(Osv);

        var item = Assert.Single(body.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal("storefront", item.GetProperty("projectName").GetString());
        Assert.Equal("2.1.0", item.GetProperty("projectVersion").GetString());
    }

    [Fact]
    public async Task ByAdvisory_AnotherTenantsApplicationIsNotInTheBlastRadius()
    {
        // Adversarial twin: sbom_component_vulns carries no org_id of its own, so the filter has
        // to reach sbom_components. Joining vulnerabilities straight to the projects plane without
        // that hop reports every tenant's exposure to every tenant.
        await using var world = await World.CreateAsync();
        await world.SeedForeignAppAsync("their-app", componentVersion: "1.2.5", advisory: Osv);

        using var body = await world.ByAdvisoryAsync(Osv);

        Assert.Equal(0, body.RootElement.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Counts_AnswersAWholePageOfAdvisoriesInOneRequest()
    {
        await using var world = await World.CreateAsync();
        await world.SeedAppAsync("storefront", "2.1.0", isLatest: true, componentVersion: "1.2.5", advisory: Osv);
        await world.SeedAppAsync("billing", "0.9.0", isLatest: true, componentVersion: "1.1.0", advisory: Osv);

        using var body = await world.CountsAsync("advisory", Osv, "GHSA-nothing-ships-this");
        var counts = body.RootElement.GetProperty("counts");

        Assert.Equal(2, counts.GetProperty(Osv).GetInt32());
        // An advisory nobody ships is simply absent — the query answered and found none, and the
        // caller renders a zero rather than an unknown.
        Assert.False(counts.TryGetProperty("GHSA-nothing-ships-this", out _));
    }

    [Fact]
    public async Task Counts_ByCoordinateDoesNotLeakBetweenTheEcosystemsAndNamesAsked()
    {
        // Adversarial twin of the two-IN-list lookup. Binding the ecosystems and the names as two
        // separate lists matches their cross product, which is a superset of the pairs asked for;
        // the pair set has to be re-selected in C# or `pypi/left-pad` inherits `npm/left-pad`'s
        // count and reports an exposure the tenant does not have.
        await using var world = await World.CreateAsync();
        await world.SeedAppAsync("storefront", "2.1.0", isLatest: true, componentVersion: "1.2.5");
        await world.SeedAppAsync("analytics", "3.0.0", isLatest: true, componentVersion: "2.28.1",
            ecosystem: "pypi", purlName: "requests");

        // Neither pair asked about exists; both ecosystems and both names do, so the cross product
        // the two IN lists match is exactly the two pairs that DO exist and were NOT asked about.
        using var body = await world.CountsAsync("package", "pypi/left-pad", "npm/requests");

        Assert.Empty(body.RootElement.GetProperty("counts").EnumerateObject());

        // …and the pairs that were asked about and do exist still answer.
        using var asked = await world.CountsAsync("package", "npm/left-pad", "pypi/requests");
        var counts = asked.RootElement.GetProperty("counts");
        Assert.Equal(1, counts.GetProperty("npm/left-pad").GetInt32());
        Assert.Equal(1, counts.GetProperty("pypi/requests").GetInt32());
        Assert.Equal(2, counts.EnumerateObject().Count());
    }

    [Fact]
    public async Task Counts_CountsAnApplicationOnceEvenWhenItShipsTheCoordinateTwice()
    {
        await using var world = await World.CreateAsync();
        await world.SeedAppAsync("storefront", "2.1.0", isLatest: true, componentVersion: "1.2.5");
        await world.AddComponentToLatestAsync("storefront", componentVersion: "1.1.0");

        using var body = await world.CountsAsync("package", "npm/left-pad");

        Assert.Equal(1, body.RootElement.GetProperty("counts").GetProperty("npm/left-pad").GetInt32());
    }

    [Fact]
    public async Task Counts_RejectsAnUnrecognisedKind()
    {
        await using var world = await World.CreateAsync();
        var result = await world.Controller.Counts(
            new BlastRadiusCountsRequest { Kind = "sideways", Key = ["x"] });

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task Counts_RefusesABatchLargerThanItAnswersRatherThanTruncating()
    {
        // Truncating would render zeros on the keys that fell off the end, which reads as
        // "nothing ships this" — the one answer a blast-radius count must never invent.
        await using var world = await World.CreateAsync();
        string[] keys = Enumerable
            .Range(0, SbomBlastRadiusRepository.MaxCountKeys + 1)
            .Select(i => $"GHSA-{i:0000}")
            .ToArray();

        var result = await world.Controller.Counts(
            new BlastRadiusCountsRequest { Kind = "advisory", Key = keys });

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    private const string Osv = "GHSA-xvch-5gv4-984h";

    private sealed class World : IAsyncDisposable
    {
        private const string OtherOrgSlug = "other";

        private readonly InMemoryDbFixture _fixture = new();

        public TestMetadataStore Store => _fixture.Store;
        public string OrgId { get; private set; } = "";
        public BlastRadiusController Controller { get; private set; } = null!;

        public static async Task<World> CreateAsync()
        {
            var world = new World();
            await world._fixture.InitializeAsync();
            world.OrgId = await OrgSeeder.InsertAsync(world.Store, "acme");
            string actorId = await UserSeeder.InsertAsync(world.Store, world.OrgId, "owner@acme.test", role: "owner");
            world.BuildController(actorId);
            return world;
        }

        public async ValueTask DisposeAsync() => await _fixture.DisposeAsync();

        public async Task<JsonDocument> ByPackageAsync(string ecosystem, string name, int limit = 50)
        {
            var result = await Controller.ByPackage(
                new BlastRadiusPackageRequest { Ecosystem = ecosystem, Name = name, Limit = limit });
            return Serialize(Assert.IsType<OkObjectResult>(result).Value);
        }

        public async Task<JsonDocument> ByAdvisoryAsync(string osvId, int limit = 50)
        {
            var result = await Controller.ByAdvisory(
                new BlastRadiusAdvisoryRequest { OsvId = osvId, Limit = limit });
            return Serialize(Assert.IsType<OkObjectResult>(result).Value);
        }

        public async Task<JsonDocument> CountsAsync(string kind, params string[] keys)
        {
            var result = await Controller.Counts(new BlastRadiusCountsRequest { Kind = kind, Key = keys });
            return Serialize(Assert.IsType<OkObjectResult>(result).Value);
        }

        /// <summary>One application version whose SBOM lists the coordinate.</summary>
        public async Task SeedAppAsync(
            string projectName, string version, bool isLatest, string componentVersion,
            string? advisory = null, string ecosystem = "npm", string purlName = "left-pad") =>
            await SeedAppInOrgAsync(OrgId, projectName, version, isLatest, componentVersion, advisory, ecosystem, purlName);

        /// <summary>The same shape, in a tenant the caller is not a member of.</summary>
        public async Task SeedForeignAppAsync(
            string projectName, string componentVersion, string? advisory = null)
        {
            string foreignOrg = await OrgSeeder.InsertAsync(Store, OtherOrgSlug);
            await SeedAppInOrgAsync(
                foreignOrg, projectName, "1.0.0", isLatest: true, componentVersion, advisory, "npm", "left-pad");
        }

        /// <summary>A second row for the same coordinate on an application already seeded.</summary>
        public async Task AddComponentToLatestAsync(string projectName, string componentVersion)
        {
            await using var conn = await Store.OpenAsync();
            string versionId = await conn.ExecuteScalarAsync<string>(
                """
                SELECT pv.id FROM project_versions pv
                JOIN projects p ON p.id = pv.project_id AND p.org_id = pv.org_id
                WHERE pv.org_id = @orgId AND p.name = @projectName AND pv.is_latest = 1
                """,
                new { orgId = OrgId, projectName }) ?? "";
            await InsertComponentAsync(conn, OrgId, versionId, "npm", "left-pad", componentVersion);
        }

        private async Task SeedAppInOrgAsync(
            string orgId, string projectName, string version, bool isLatest, string componentVersion,
            string? advisory, string ecosystem, string purlName)
        {
            string projectId = Guid.NewGuid().ToString("N");
            string versionId = Guid.NewGuid().ToString("N");
            await using var conn = await Store.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier)
                VALUES (@projectId, @orgId, 'project', @projectName, 'application')
                """,
                new { projectId, orgId, projectName });
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest, policy_status)
                VALUES (@versionId, @orgId, @projectId, @version, @isLatest, 'pass')
                """,
                new { versionId, orgId, projectId, version, isLatest = isLatest ? 1 : 0 });
            string componentId = await InsertComponentAsync(
                conn, orgId, versionId, ecosystem, purlName, componentVersion);

            if (advisory is null)
            {
                return;
            }

            // vulnerabilities is instance-global with UNIQUE(osv_id): two applications shipping the
            // same advisory share one row, which is the whole point of the join being counted here.
            string vulnId = await conn.ExecuteScalarAsync<string>(
                    "SELECT id FROM vulnerabilities WHERE osv_id = @advisory", new { advisory })
                ?? await VulnerabilitySeeder.InsertVulnAsync(
                    Store, advisory, severity: "CRITICAL", cvssScore: 9.8);
            await conn.ExecuteAsync(
                "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
                new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });
        }

        private static async Task<string> InsertComponentAsync(
            System.Data.Common.DbConnection conn, string orgId, string versionId,
            string ecosystem, string purlName, string componentVersion)
        {
            string componentId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name, dependency_scope)
                VALUES (@componentId, @orgId, @versionId, @purl, @ecosystem, @purlName, @componentVersion,
                        @purlName, 'runtime')
                """,
                new
                {
                    componentId,
                    orgId,
                    versionId,
                    purl = $"pkg:{ecosystem}/{purlName}@{componentVersion}",
                    ecosystem,
                    purlName,
                    componentVersion,
                });
            return componentId;
        }

        private void BuildController(string actorId)
        {
            var http = new DefaultHttpContext();
            http.Request.Scheme = "https";
            http.Request.Host = new HostString("acme.example.test");
            http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.7");
            http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(OrgId, "acme");
            http.User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, actorId),
                    new Claim("sub", actorId),
                    new Claim("org_id", OrgId),
                    new Claim("tid", OrgId),
                    new Claim("role", "owner"),
                    new Claim("scope", "tenant"),
                ],
                authenticationType: "test"));

            Controller = new BlastRadiusController(
                new SbomBlastRadiusRepository(Store),
                new OrgAccessGuard(Store),
                new ProblemResults(new EchoLocalizer()))
            {
                ControllerContext = new ControllerContext { HttpContext = http },
            };
        }
    }

    private static JsonDocument Serialize(object? value) =>
        JsonDocument.Parse(JsonSerializer.Serialize(value, JsonOptions));

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);
        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);
        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}
