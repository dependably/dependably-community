using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// End-to-end behaviour of the analysis read surface and the manual-triage write against a real
/// schema: tenant scoping, the <c>latest</c> alias, registry cross-links across both planes, the
/// derived document filename, the partial-update semantics of the triage body, and the suppression
/// counts flipping when an operator triages an advisory.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomAnalysisControllerTests
{
    private const string OtherOrgSlug = "other";

    // ── Reads ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Analysis_ReturnsTheRollupAndTheRowsForTheResolvedVersion()
    {
        await using var world = await World.CreateAsync();
        using var body = await world.GetAnalysisAsync();

        var rollup = body.RootElement.GetProperty("rollup");
        Assert.Equal(3, rollup.GetProperty("componentTotal").GetInt32());
        Assert.Equal(2, rollup.GetProperty("prodCount").GetInt32());
        Assert.Equal(1, rollup.GetProperty("devCount").GetInt32());
        Assert.Equal("violation", rollup.GetProperty("policyStatus").GetString());
        Assert.Equal(1, rollup.GetProperty("violationCount").GetInt32());
        Assert.Equal(3, body.RootElement.GetProperty("total").GetInt32());
        Assert.Equal(1, body.RootElement.GetProperty("page").GetInt32());
    }

    [Fact]
    public async Task Analysis_ResolvesTheLatestAlias()
    {
        await using var world = await World.CreateAsync();
        using var byId = await world.GetAnalysisAsync();
        using var byAlias = await world.GetAnalysisAsync(versionId: "latest");

        Assert.Equal(
            byId.RootElement.GetProperty("total").GetInt32(),
            byAlias.RootElement.GetProperty("total").GetInt32());
    }

    // ── Inherited triage — the wiring both ResolveVersionAsync branches must supply ─────────

    /// <summary>
    /// <c>SbomAnalysisRepository.ResolveVersionAsync</c> has two branches — the <c>latest</c>
    /// alias and an explicit version id — and both must select <c>created_at</c>, because that is
    /// the comparison point <c>SbomAnalysisProjection.IsInherited</c> reads. Every link that
    /// matters (project-detail links, a CI upload's own response, an SPA route the reader actually
    /// lands on) addresses the page by concrete version id, never by the <c>latest</c> alias — so a
    /// regression that drops the column from only the id branch renders a feature that looks wired
    /// (the alias path still works) but is silently dead on its main path.
    /// </summary>
    [Fact]
    public async Task Analysis_IdPath_MarksAStatementPredatingTheVersionAsInherited()
    {
        await using var world = await World.CreateAsync();
        // World seeds qs's statement at `Now`; move the version's own created_at a day later so
        // the statement — carried forward from whatever produced it — reads as inherited.
        await world.SetVersionCreatedAtAsync(World.Now.AddDays(1));

        using var body = await world.GetAnalysisAsync(); // the id path: the default, concrete VersionId

        Assert.True(InheritedFlagFor(body, "qs", "CVE-2022-24999"));
    }

    /// <summary>Adversarial twin: the same fixture through the <c>latest</c> alias, which already
    /// selected <c>created_at</c> before this fix and must keep doing so.</summary>
    [Fact]
    public async Task Analysis_LatestAliasPath_MarksAStatementPredatingTheVersionAsInherited()
    {
        await using var world = await World.CreateAsync();
        await world.SetVersionCreatedAtAsync(World.Now.AddDays(1));

        using var body = await world.GetAnalysisAsync(versionId: "latest");

        Assert.True(InheritedFlagFor(body, "qs", "CVE-2022-24999"));
    }

    [Fact]
    public async Task Analysis_StatementNotOlderThanTheVersion_IsNotInherited()
    {
        // Adversarial twin of both tests above: a statement recorded for this exact release
        // (updated_at == created_at, i.e. not strictly older) must not read as inherited — the
        // predicate is "predates", not "is not newer than".
        await using var world = await World.CreateAsync();
        await world.SetVersionCreatedAtAsync(World.Now);

        using var body = await world.GetAnalysisAsync();

        Assert.False(InheritedFlagFor(body, "qs", "CVE-2022-24999"));
    }

    private static bool InheritedFlagFor(JsonDocument body, string componentName, string vulnKey)
    {
        foreach (var item in body.RootElement.GetProperty("items").EnumerateArray())
        {
            if (item.GetProperty("name").GetString() != componentName)
            {
                continue;
            }

            foreach (var advisory in item.GetProperty("advisories").EnumerateArray())
            {
                if (advisory.GetProperty("vulnKey").GetString() == vulnKey)
                {
                    return advisory.GetProperty("inherited").GetBoolean();
                }
            }
        }

        throw new InvalidOperationException($"No advisory {vulnKey} found on component {componentName}.");
    }

    [Fact]
    public async Task Analysis_CrossOrgProjectIs404NotForbidden()
    {
        await using var world = await World.CreateAsync();
        string foreignProject = await world.SeedForeignProjectAsync();

        var result = await world.Controller.Analysis(foreignProject, "latest", new ProjectAnalysisFilterRequest());

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status404NotFound, problem.StatusCode);
    }

    [Fact]
    public async Task Analysis_UnknownVersionIs404()
    {
        await using var world = await World.CreateAsync();
        var result = await world.Controller.Analysis(world.ProjectId, "no-such-version", new ProjectAnalysisFilterRequest());

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status404NotFound, problem.StatusCode);
    }

    /// <summary>
    /// Every sort key the table's headers can emit is accepted. A rejected key does not mis-order
    /// the page — it 422s the whole request, and the table state is persisted to the query string,
    /// so the failure survives the reload.
    /// </summary>
    [Theory]
    [InlineData("priority")]
    [InlineData("name")]
    [InlineData("version")]
    [InlineData("severity")]
    [InlineData("scope")]
    [InlineData("sbomScope")]
    [InlineData("type")]
    [InlineData("dep")]
    [InlineData("licenses")]
    [InlineData("reach")]
    public async Task Analysis_AcceptsEverySortKey(string sort)
    {
        await using var world = await World.CreateAsync();
        var filter = new ProjectAnalysisFilterRequest { Sort = sort };

        var result = await world.Controller.Analysis(world.ProjectId, world.VersionId, filter);

        Assert.IsType<OkObjectResult>(result);
    }

    /// <summary>
    /// An unrecognised sort or direction falls back rather than 422ing. These arrive from
    /// bookmarks as often as from the UI, and a saved link naming a retired column must still
    /// render the table — differently ordered, never as an error page.
    /// </summary>
    [Theory]
    [InlineData("sort", "depScope")]
    [InlineData("sort", "sideways")]
    [InlineData("dir", "sidewards")]
    public async Task Analysis_FallsBackOnAnUnrecognisedSortOrDirection(string field, string value)
    {
        await using var world = await World.CreateAsync();
        var filter = new ProjectAnalysisFilterRequest();
        if (field == "sort") { filter.Sort = value; } else { filter.Dir = value; }

        var result = await world.Controller.Analysis(world.ProjectId, world.VersionId, filter);

        Assert.IsType<OkObjectResult>(result);
    }

    [Theory]
    [InlineData("scope", "staging")]
    [InlineData("sev", "hgih")]
    [InlineData("reach", "maybe")]
    public async Task Analysis_RejectsAnUnrecognisedFilterValue(string field, string value)
    {
        await using var world = await World.CreateAsync();
        var filter = new ProjectAnalysisFilterRequest();
        switch (field)
        {
            case "scope": filter.Scope = value; break;
            case "sev": filter.Sev = value; break;
            default: filter.Reach = value; break;
        }

        var result = await world.Controller.Analysis(world.ProjectId, world.VersionId, filter);

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, problem.StatusCode);
        Assert.Equal(field, Assert.IsType<ProblemDetails>(problem.Value).Extensions["field"]);
    }

    [Fact]
    public async Task Analysis_PageSizeIsClamped()
    {
        await using var world = await World.CreateAsync();
        using var body = await world.GetAnalysisAsync(filter: new ProjectAnalysisFilterRequest { Limit = 5000, Page = 0 });

        Assert.Equal(SbomAnalysisProjection.MaxPageSize, body.RootElement.GetProperty("limit").GetInt32());
        Assert.Equal(1, body.RootElement.GetProperty("page").GetInt32());
    }

    // ── Registry cross-links ─────────────────────────────────────────────────

    [Fact]
    public async Task Analysis_LinksAHostedComponentToItsRegistryPage()
    {
        await using var world = await World.CreateAsync();
        await world.SeedHostedPackageAsync("npm", "@scope/minimist");

        using var body = await world.GetAnalysisAsync();
        var row = Row(body, "minimist");

        Assert.True(row.GetProperty("inRegistry").GetBoolean());
        // Each name segment is escaped on its own, so the scope separator survives for the SPA route.
        Assert.Equal("/package/npm/%40scope/minimist", row.GetProperty("registryLink").GetString());
    }

    [Fact]
    public async Task Analysis_LinksAProxyCachedComponentThroughTheTenantBinding()
    {
        await using var world = await World.CreateAsync();
        await world.SeedCachedArtifactAsync("pypi", "requests", boundToOrg: true);

        using var body = await world.GetAnalysisAsync();
        Assert.True(Row(body, "requests").GetProperty("inRegistry").GetBoolean());
    }

    [Fact]
    public async Task Analysis_DoesNotLinkACacheArtifactAnotherTenantFetched()
    {
        await using var world = await World.CreateAsync();
        await world.SeedCachedArtifactAsync("pypi", "requests", boundToOrg: false);

        using var body = await world.GetAnalysisAsync();
        var row = Row(body, "requests");

        // cache_artifact is instance-global. Without this tenant's own tenant_artifact_access
        // binding the coordinate is another tenant's, and lighting the link would claim otherwise.
        Assert.False(row.GetProperty("inRegistry").GetBoolean());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("registryLink").ValueKind);
    }

    [Fact]
    public async Task Analysis_ComponentNotInAnyPlaneCarriesNoLink()
    {
        await using var world = await World.CreateAsync();
        using var body = await world.GetAnalysisAsync();

        Assert.False(Row(body, "minimist").GetProperty("inRegistry").GetBoolean());
        Assert.Equal(JsonValueKind.Null, Row(body, "minimist").GetProperty("registryLink").ValueKind);
    }

    // ── Registry facts on the component row ──────────────────────────────────

    [Fact]
    public async Task Analysis_ReportsTheBlockedChipAtVersionGranularityWhenTheShippedVersionMatches()
    {
        await using var world = await World.CreateAsync();
        await world.SeedHostedPackageAsync("npm", "minimist");
        await world.SeedHostedVersionAsync("npm", "minimist", "1.2.5", manualBlockState: "blocked");

        using var body = await world.GetAnalysisAsync();
        var registry = Row(body, "minimist").GetProperty("registry");

        Assert.Equal("present", registry.GetProperty("presence").GetString());
        Assert.Equal("version", registry.GetProperty("blocked").GetString());
    }

    [Fact]
    public async Task Analysis_ReportsABlockOnAnotherVersionAsAPackageLevelChipNotACleanRow()
    {
        // Adversarial twin of the test above. A version-level match alone would answer "not
        // blocked" here, which is a false all-clear on a package the operator has quarantined —
        // and the exact shape a NuGet-normalized version spelling produces by accident.
        await using var world = await World.CreateAsync();
        await world.SeedHostedPackageAsync("npm", "minimist");
        await world.SeedHostedVersionAsync("npm", "minimist", "0.0.8", manualBlockState: "blocked");

        using var body = await world.GetAnalysisAsync();
        var registry = Row(body, "minimist").GetProperty("registry");

        Assert.Equal("package", registry.GetProperty("blocked").GetString());
    }

    [Fact]
    public async Task Analysis_ReportsDeprecationAndTheKnownUpstreamLatestVersion()
    {
        await using var world = await World.CreateAsync();
        await world.SeedHostedPackageAsync("npm", "minimist", upstreamLatestVersion: "1.2.8");
        await world.SeedHostedVersionAsync("npm", "minimist", "1.2.5", deprecated: "use 1.2.8");

        using var body = await world.GetAnalysisAsync();
        var registry = Row(body, "minimist").GetProperty("registry");

        Assert.Equal("version", registry.GetProperty("deprecated").GetString());
        Assert.Equal("1.2.8", registry.GetProperty("latestVersion").GetString());
        // 1.2.5 < 1.2.8 under npm's native ordering, decided server-side.
        Assert.True(registry.GetProperty("outdated").GetBoolean());
    }

    [Fact]
    public async Task Analysis_TwoSpellingsOfTheSameVersionAreNotOutdated()
    {
        // Adversarial twin of the test above. `1.0.0.0` and `1.0.0` are the same NuGet release
        // spelled two ways — the SBOM producer's way and the registry's normalized way — so a
        // string-inequality "outdated" rule reports every such row as behind, which is a false
        // alarm on exactly the rows most likely to be spelled differently. The comparison is
        // NuGet's own ordering, not a text diff.
        await using var world = await World.CreateAsync();
        await world.SeedNuGetComponentAsync("Acme.Widgets", "1.0.0.0");
        await world.SeedHostedPackageAsync("nuget", "acme.widgets", upstreamLatestVersion: "1.0.0");

        using var body = await world.GetAnalysisAsync();
        var registry = Row(body, "Acme.Widgets").GetProperty("registry");

        Assert.Equal("present", registry.GetProperty("presence").GetString());
        Assert.False(registry.GetProperty("outdated").GetBoolean());
    }

    [Fact]
    public async Task Analysis_ProxyBlockStateIsReadFromThisTenantsOwnBinding()
    {
        await using var world = await World.CreateAsync();
        await world.SeedCachedArtifactAsync("pypi", "requests", boundToOrg: true, manualBlockState: "blocked");

        using var body = await world.GetAnalysisAsync();
        var registry = Row(body, "requests").GetProperty("registry");

        Assert.True(registry.GetProperty("cached").GetBoolean());
        Assert.Equal("version", registry.GetProperty("blocked").GetString());
    }

    [Fact]
    public async Task Analysis_AnotherTenantsProxyBlockOnTheSameArtifactIsNotThisTenantsBlock()
    {
        // Adversarial twin. cache_artifact is instance-global; manual_block_state lives on the
        // per-tenant tenant_artifact_access binding. Both tenants have pulled this coordinate, so
        // presence is not what separates them — only the org-bound join is. Reading the block
        // state without it renders another tenant's quarantine decision as this tenant's.
        await using var world = await World.CreateAsync();
        await world.SeedSharedCachedArtifactAsync(
            "pypi", "requests", blockedForThisOrg: false, blockedForOtherOrg: true);

        using var body = await world.GetAnalysisAsync();
        var registry = Row(body, "requests").GetProperty("registry");

        Assert.Equal("present", registry.GetProperty("presence").GetString());
        Assert.Equal(JsonValueKind.Null, registry.GetProperty("blocked").ValueKind);
    }

    [Fact]
    public async Task Analysis_ACoordinateOnlyAnotherTenantCachedIsNotInThisRegistry()
    {
        await using var world = await World.CreateAsync();
        await world.SeedCachedArtifactAsync("pypi", "requests", boundToOrg: false, manualBlockState: "blocked");

        using var body = await world.GetAnalysisAsync();
        var registry = Row(body, "requests").GetProperty("registry");

        Assert.Equal("absent", registry.GetProperty("presence").GetString());
        Assert.Equal(JsonValueKind.Null, registry.GetProperty("blocked").ValueKind);
    }

    [Fact]
    public async Task Analysis_OutdatedIsNullForAnEcosystemWithNoNativeVersionOrdering()
    {
        // Go has no ordering registered in EcosystemVersionOrdering, so the answer is "unknown",
        // never "up to date" — the UI renders the known upstream version as a fact instead of a
        // reassuring verdict.
        await using var world = await World.CreateAsync();
        await world.SeedGoComponentAsync("example.com/mod", "v1.0.0");
        await world.SeedHostedPackageAsync("golang", "example.com/mod", upstreamLatestVersion: "v1.4.0");

        using var body = await world.GetAnalysisAsync();
        var registry = Row(body, "example.com/mod").GetProperty("registry");

        Assert.Equal(JsonValueKind.Null, registry.GetProperty("outdated").ValueKind);
        Assert.Equal("v1.4.0", registry.GetProperty("latestVersion").GetString());
    }

    // ── The blind-spot count ─────────────────────────────────────────────────

    [Fact]
    public async Task Analysis_RollupCountsComponentsTheRegistryHasNeverServed()
    {
        await using var world = await World.CreateAsync();
        await world.SeedHostedPackageAsync("npm", "minimist");

        using var body = await world.GetAnalysisAsync();
        var counts = body.RootElement.GetProperty("rollup").GetProperty("registryCounts");

        // Three components: minimist is now hosted, qs and requests are not.
        Assert.Equal(1, counts.GetProperty("inRegistry").GetInt32());
        Assert.Equal(2, counts.GetProperty("notInRegistry").GetInt32());
        Assert.Equal(0, counts.GetProperty("unknown").GetInt32());
    }

    [Fact]
    public async Task Analysis_ComponentWithNoCoordinateIsCountedUnknownNotAsABlindSpot()
    {
        // Adversarial twin: folding the unanswerable rows into notInRegistry inflates the number
        // an operator is meant to act on. A vendored blob carries no purl, so the registry cannot
        // be asked about it at all — a different statement from "never vetted".
        await using var world = await World.CreateAsync();
        await world.SeedUncoordinatedComponentAsync("vendored-blob.so");

        using var body = await world.GetAnalysisAsync();
        var counts = body.RootElement.GetProperty("rollup").GetProperty("registryCounts");

        Assert.Equal(1, counts.GetProperty("unknown").GetInt32());
        Assert.Equal(3, counts.GetProperty("notInRegistry").GetInt32());
        Assert.Equal(
            body.RootElement.GetProperty("rollup").GetProperty("componentTotal").GetInt32(),
            counts.GetProperty("inRegistry").GetInt32()
                + counts.GetProperty("notInRegistry").GetInt32()
                + counts.GetProperty("unknown").GetInt32());
    }

    [Fact]
    public async Task Analysis_RegistryFilterNarrowsToTheBlindSpotRowsButNotTheRollup()
    {
        await using var world = await World.CreateAsync();
        await world.SeedHostedPackageAsync("npm", "minimist");

        using var body = await world.GetAnalysisAsync(
            filter: new ProjectAnalysisFilterRequest { Registry = "absent" });

        Assert.Equal(2, body.RootElement.GetProperty("total").GetInt32());
        // The rollup describes the whole version and never moves with a row filter.
        Assert.Equal(3, body.RootElement.GetProperty("rollup").GetProperty("componentTotal").GetInt32());
        foreach (var item in body.RootElement.GetProperty("items").EnumerateArray())
        {
            Assert.False(item.GetProperty("inRegistry").GetBoolean());
        }
    }

    [Fact]
    public async Task Analysis_RejectsAnUnrecognisedRegistryFilterValue()
    {
        await using var world = await World.CreateAsync();
        var result = await world.Controller.Analysis(
            world.ProjectId, world.VersionId,
            new ProjectAnalysisFilterRequest { Registry = "somewhere" });

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, problem.StatusCode);
    }

    // ── Payload shape the shipped UI binds to ────────────────────────────────

    [Fact]
    public async Task Analysis_ShipsThePurlKeyTheTriageBodyRequires()
    {
        await using var world = await World.CreateAsync();
        using var body = await world.GetAnalysisAsync();

        // The purl carries a version; the triage key never does. A UI falling back to `purl` would
        // address a row that does not exist.
        Assert.Equal("pkg:pypi/requests@2.28.1", Row(body, "requests").GetProperty("purl").GetString());
        Assert.Equal("pkg:pypi/requests", Row(body, "requests").GetProperty("purlKey").GetString());
    }

    [Fact]
    public async Task Analysis_ShipsVexProvenanceResolvedToADisplayName()
    {
        await using var world = await World.CreateAsync();
        await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:pypi/requests",
            VulnKey = "CVE-2023-32681",
            VexState = Optional<string?>.Of("not_affected"),
            VexJustification = Optional<string?>.Of("code_not_reachable"),
        });

        using var body = await world.GetAnalysisAsync(filter: new ProjectAnalysisFilterRequest { Suppressed = true });
        var advisory = Row(body, "requests").GetProperty("advisories")[0];

        Assert.Equal("manual", advisory.GetProperty("vexSource").GetString());
        Assert.Equal(World.ActorEmail, advisory.GetProperty("vexUpdatedBy").GetString());
        Assert.Equal(
            World.Now,
            DateTimeOffset.Parse(
                advisory.GetProperty("vexUpdatedAt").GetString()!,
                CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind));
    }

    [Fact]
    public async Task Analysis_OrphanStatementIsSurfacedNotDropped()
    {
        await using var world = await World.CreateAsync();
        using var body = await world.GetAnalysisAsync();

        var orphan = Assert.Single(body.RootElement.GetProperty("orphanAnalysis").EnumerateArray());
        Assert.Equal("pkg:npm/event-stream", orphan.GetProperty("purlKey").GetString());
        Assert.Equal("GHSA-mh6f-8j2x-4483", orphan.GetProperty("vulnKey").GetString());
    }

    [Fact]
    public async Task Analysis_ShipsVersionWideLicenceCounts()
    {
        await using var world = await World.CreateAsync();
        using var body = await world.GetAnalysisAsync(filter: new ProjectAnalysisFilterRequest { Scope = "dev" });

        var counts = body.RootElement.GetProperty("rollup").GetProperty("licenseCounts");
        Assert.Equal(3, counts.GetProperty("total").GetInt32());
        Assert.Equal(1, counts.GetProperty("undeclared").GetInt32());
        Assert.Equal(1, counts.GetProperty("byIdentifier").GetProperty("MIT").GetInt32());
    }

    // ── Documents ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Documents_DerivesTheFilenameFromTheProjectAndVersion()
    {
        await using var world = await World.CreateAsync();
        var result = await world.Controller.Documents(world.ProjectId, "latest");
        using var body = Serialize(Assert.IsType<OkObjectResult>(result).Value);

        var doc = Assert.Single(body.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal("sbom", doc.GetProperty("docType").GetString());
        // The project name carries a slash and a space; neither may reach a filename.
        Assert.Equal("acme-storefront-1.4.0-sbom.json", doc.GetProperty("fileName").GetString());
    }

    [Fact]
    public async Task Documents_CrossOrgProjectIs404()
    {
        await using var world = await World.CreateAsync();
        string foreignProject = await world.SeedForeignProjectAsync();

        var result = await world.Controller.Documents(foreignProject, "latest");
        Assert.Equal(StatusCodes.Status404NotFound, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    // ── CISA conformance scorecard ──────────────────────────────────────────────

    [Fact]
    public async Task Conformance_ScoresTheSeededDocumentAgainstStoredComponents()
    {
        // World seeds a cyclonedx-json document (no tool name, no lifecycles) with three direct
        // components: minimist (dev, MIT), qs (no licence), requests (Apache-2.0). No component
        // carries a producer.
        await using var world = await World.CreateAsync();
        var result = await world.Controller.Conformance(world.ProjectId, "latest");
        using var body = Serialize(Assert.IsType<OkObjectResult>(result).Value);
        var root = body.RootElement;

        Assert.Equal("cyclonedx-json", root.GetProperty("format").GetString());
        Assert.Equal(3, root.GetProperty("componentTotal").GetInt32());

        var elements = root.GetProperty("elements").EnumerateArray()
            .ToDictionary(e => e.GetProperty("elementId").GetString()!, e => e);

        // D16 Component Licence: mixed present/silent-absent, no explicit-unknown (CycloneDX has
        // no NOASSERTION mechanism).
        var license = elements["D16"];
        Assert.Equal(3, license.GetProperty("total").GetInt32());
        Assert.Equal(2, license.GetProperty("presentCount").GetInt32());
        Assert.Equal(0, license.GetProperty("explicitUnknownCount").GetInt32());
        Assert.Equal(1, license.GetProperty("absentCount").GetInt32());
        Assert.Equal("absent", license.GetProperty("state").GetString());

        // D10 Component Producer: none of the seeded rows carry one.
        var producer = elements["D10"];
        Assert.Equal(0, producer.GetProperty("presentCount").GetInt32());
        Assert.Equal(3, producer.GetProperty("absentCount").GetInt32());

        // D17: every seeded component is dependency_kind='direct'.
        Assert.Equal("present", elements["D17"].GetProperty("state").GetString());

        // P4 Explicit Unknowns: CycloneDX cannot demonstrate this practice at all.
        Assert.Equal("notApplicable", elements["P4"].GetProperty("state").GetString());

        // D7/D8: no tool named on the seeded document.
        Assert.Equal("absent", elements["D7"].GetProperty("state").GetString());
        Assert.Equal("notApplicable", elements["D8"].GetProperty("state").GetString());
    }

    [Fact]
    public async Task Conformance_CrossOrgProjectIs404()
    {
        await using var world = await World.CreateAsync();
        string foreignProject = await world.SeedForeignProjectAsync();

        var result = await world.Controller.Conformance(foreignProject, "latest");
        Assert.Equal(StatusCodes.Status404NotFound, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task Conformance_WhenTheVersionHasNoSbomDocument_Is404()
    {
        await using var world = await World.CreateAsync();
        string versionWithNoDocument = await world.SeedVersionWithNoDocumentAsync();

        var result = await world.Controller.Conformance(world.ProjectId, versionWithNoDocument);
        Assert.Equal(StatusCodes.Status404NotFound, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    // ── Manual triage ────────────────────────────────────────────────────────

    [Fact]
    public async Task Triage_RoundTripsAndFlipsTheSuppressionCounts()
    {
        await using var world = await World.CreateAsync();

        using var before = await world.GetAnalysisAsync();
        var beforeCounts = before.RootElement.GetProperty("rollup");
        Assert.Equal(1, beforeCounts.GetProperty("severityCounts").GetProperty("medium").GetInt32());
        Assert.Equal(0, beforeCounts.GetProperty("priorityCounts").GetProperty("suppressed").GetInt32());

        using var refreshed = await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:pypi/requests",
            VulnKey = "CVE-2023-32681",
            VexState = Optional<string?>.Of("not_affected"),
            VexJustification = Optional<string?>.Of("code_not_reachable"),
            VexDetail = Optional<string?>.Of("Vendored TLS stack does not call the affected path."),
        });

        Assert.Equal("not_affected", refreshed.RootElement.GetProperty("vexState").GetString());
        Assert.Equal("manual", refreshed.RootElement.GetProperty("vexSource").GetString());

        using var after = await world.GetAnalysisAsync();
        var afterCounts = after.RootElement.GetProperty("rollup");
        Assert.Equal(0, afterCounts.GetProperty("severityCounts").GetProperty("medium").GetInt32());
        Assert.Equal(1, afterCounts.GetProperty("priorityCounts").GetProperty("suppressed").GetInt32());
    }

    [Fact]
    public async Task Triage_AnAbsentFieldIsLeftUnchangedAndAnExplicitNullClearsIt()
    {
        await using var world = await World.CreateAsync();

        await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexState = Optional<string?>.Of("exploitable"),
            VexResponse = Optional<string?>.Of("will_not_fix"),
            VexDetail = Optional<string?>.Of("Mitigated at the gateway."),
        });

        // A second write that names only the detail must not silently reset the state or response.
        using var second = await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexDetail = Optional<string?>.Of("Mitigated at the gateway and in the client."),
        });

        Assert.Equal("exploitable", second.RootElement.GetProperty("vexState").GetString());
        Assert.Equal("will_not_fix", second.RootElement.GetProperty("vexResponse").GetString());
        Assert.Equal("Mitigated at the gateway and in the client.", second.RootElement.GetProperty("vexDetail").GetString());

        // An explicit null is a decision, not an absence.
        using var third = await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexResponse = Optional<string?>.Of(null),
        });

        Assert.Equal("exploitable", third.RootElement.GetProperty("vexState").GetString());
        Assert.Equal(JsonValueKind.Null, third.RootElement.GetProperty("vexResponse").ValueKind);
    }

    [Fact]
    public async Task Triage_NeverTouchesTheSarifOwnedColumns()
    {
        await using var world = await World.CreateAsync();

        using var refreshed = await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexState = Optional<string?>.Of("in_triage"),
        });

        Assert.Equal("reachable", refreshed.RootElement.GetProperty("reachability").GetString());
        Assert.Equal("high", refreshed.RootElement.GetProperty("confidence").GetString());
    }

    [Fact]
    public async Task Triage_CreatesTheRowWhenNoStatementExistsYet()
    {
        await using var world = await World.CreateAsync();

        using var refreshed = await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/minimist",
            VulnKey = "CVE-2021-44906",
            VexState = Optional<string?>.Of("false_positive"),
        });

        Assert.Equal("false_positive", refreshed.RootElement.GetProperty("vexState").GetString());
        Assert.Equal("manual", refreshed.RootElement.GetProperty("vexSource").GetString());
    }

    [Fact]
    public async Task Triage_TriggersPolicyReevaluationForTheVersion()
    {
        await using var world = await World.CreateAsync();
        await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexState = Optional<string?>.Of("resolved"),
        });

        Assert.Equal([(world.OrgId, world.VersionId)], world.Reevaluator.Calls);
    }

    [Fact]
    public async Task Triage_WritesAnAttributedAuditRow()
    {
        await using var world = await World.CreateAsync();
        await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexState = Optional<string?>.Of("resolved"),
        });

        await using var conn = await world.Store.OpenAsync();
        var row = await conn.QuerySingleAsync<(string Action, string OrgId, string ActorId, string ActorKind, string? SourceIp)>(
            """
            SELECT action AS Action, org_id AS OrgId, actor_id AS ActorId,
                   actor_kind AS ActorKind, source_ip AS SourceIp
            FROM audit_log WHERE action = 'sbom.analysis.triage'
            """);

        Assert.Equal(world.OrgId, row.OrgId);
        Assert.Equal(world.ActorId, row.ActorId);
        Assert.Equal(ActorKinds.User, row.ActorKind);
        Assert.Equal("203.0.113.7", row.SourceIp);
    }

    [Fact]
    public async Task Triage_CrossOrgProjectIs404BeforeAnythingIsWritten()
    {
        await using var world = await World.CreateAsync();
        string foreignProject = await world.SeedForeignProjectAsync();

        var result = await world.Controller.Triage(foreignProject, "latest", new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexState = Optional<string?>.Of("resolved"),
        });

        Assert.Equal(StatusCodes.Status404NotFound, Assert.IsType<ObjectResult>(result).StatusCode);
        await using var conn = await world.Store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM project_vuln_analysis WHERE vex_source = 'manual'"));
        Assert.Empty(world.Reevaluator.Calls);
    }

    [Theory]
    [InlineData(null, "CVE-1", "in_triage", null, "purlKey")]
    [InlineData("pkg:npm/qs", null, "in_triage", null, "vulnKey")]
    [InlineData("pkg:npm/qs", "CVE-1", "invented_state", null, "vexState")]
    [InlineData("pkg:npm/qs", "CVE-1", "not_affected", "invented_justification", "vexJustification")]
    [InlineData("pkg:npm/qs", "CVE-1", "in_triage", "code_not_present", "vexJustification")]
    public async Task Triage_RejectsABodyOutsideTheCycloneDxVocabulary(
        string? purlKey, string? vulnKey, string state, string? justification, string expectedField)
    {
        await using var world = await World.CreateAsync();
        var req = new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = purlKey,
            VulnKey = vulnKey,
            VexState = Optional<string?>.Of(state),
            VexJustification = justification is null ? default : Optional<string?>.Of(justification),
        };

        var result = await world.Controller.Triage(world.ProjectId, "latest", req);

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, problem.StatusCode);
        Assert.Equal(expectedField, Assert.IsType<ProblemDetails>(problem.Value).Extensions["field"]);
    }

    // A present-but-empty string is a fourth Optional<T> state distinct from absent (leave
    // unchanged) and explicit null (clear the field): "" never satisfies any of the three closed
    // VEX vocabularies, so it is rejected as a validation error the same way an unrecognised value
    // like "invented_state" already is, rather than reaching the schema CHECK and 500ing.
    [Theory]
    [InlineData("", null, null, "vexState")]
    [InlineData("not_affected", "", null, "vexJustification")]
    [InlineData(null, null, "", "vexResponse")]
    public async Task Triage_RejectsAPresentButEmptyVexField(
        string? state, string? justification, string? response, string expectedField)
    {
        await using var world = await World.CreateAsync();
        var req = new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexState = state is null ? default : Optional<string?>.Of(state),
            VexJustification = justification is null ? default : Optional<string?>.Of(justification),
            VexResponse = response is null ? default : Optional<string?>.Of(response),
        };

        var result = await world.Controller.Triage(world.ProjectId, "latest", req);

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, problem.StatusCode);
        Assert.Equal(expectedField, Assert.IsType<ProblemDetails>(problem.Value).Extensions["field"]);

        // No CHECK-constraint failure ever reached SQL: the row for this (purlKey, vulnKey) pair
        // still does not exist.
        await using var conn = await world.Store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM project_vuln_analysis WHERE vuln_key = 'CVE-2022-24999' AND vex_source = 'manual'"));
    }

    [Fact]
    public async Task Triage_JustificationIsAllowedWhenTheStoredStateIsAlreadyNotAffected()
    {
        await using var world = await World.CreateAsync();
        await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexState = Optional<string?>.Of("not_affected"),
        });

        // The state is not resent; the rule is checked against the row as it will actually stand.
        using var refreshed = await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexJustification = Optional<string?>.Of("requires_configuration"),
        });

        Assert.Equal("requires_configuration", refreshed.RootElement.GetProperty("vexJustification").GetString());
    }

    [Fact]
    public async Task Triage_RejectsABodyThatChangesNothing()
    {
        await using var world = await World.CreateAsync();
        var result = await world.Controller.Triage(world.ProjectId, "latest", new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
        });

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task Triage_WritesAJustificationTheIngestNormalizerRoundTrips()
    {
        await using var world = await World.CreateAsync();
        using var refreshed = await world.TriageAsync(new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexState = Optional<string?>.Of("not_affected"),
            VexJustification = Optional<string?>.Of("protected_at_perimeter"),
        });

        string? stored = refreshed.RootElement.GetProperty("vexJustification").GetString();
        Assert.Equal("protected_at_perimeter", stored);

        // The round trip is the point: the editor writes it, the exporter renders it, and
        // re-uploading that export has to land the same value rather than drop it. A value the
        // write path admits and this normalizer does not is a triage decision that survives
        // exactly until someone re-uploads their own export.
        Assert.Equal(stored, VexVocabulary.NormalizeJustification(stored));
    }

    [Fact]
    public async Task Triage_RejectsAJustificationCycloneDxDoesNotDefine()
    {
        await using var world = await World.CreateAsync();
        var result = await world.Controller.Triage(world.ProjectId, "latest", new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexState = Optional<string?>.Of("not_affected"),
            VexJustification = Optional<string?>.Of("protected_by_perimeter"),
        });

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task Triage_RejectsAnOverlongRationale()
    {
        await using var world = await World.CreateAsync();
        var result = await world.Controller.Triage(world.ProjectId, "latest", new UpdateProjectVulnAnalysisRequest
        {
            PurlKey = "pkg:npm/qs",
            VulnKey = "CVE-2022-24999",
            VexDetail = Optional<string?>.Of(new string('x', VexVocabulary.MaxDetailLength + 1)),
        });

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, Assert.IsType<ObjectResult>(result).StatusCode);
    }


    // ── Helpers ──────────────────────────────────────────────────────────────

    private static JsonElement Row(JsonDocument body, string name) =>
        body.RootElement.GetProperty("items").EnumerateArray()
            .Single(i => i.GetProperty("name").GetString() == name);

    /// <summary>
    /// Re-serializes an action result's payload through the web defaults the app configures, so the
    /// assertions read exactly the camelCase JSON the browser receives.
    /// </summary>
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private static JsonDocument Serialize(object? payload) =>
        JsonDocument.Parse(JsonSerializer.Serialize(payload, WebJson));

    /// <summary>
    /// One seeded tenant with a project version carrying three components, three advisories, two
    /// analysis statements and one orphan statement, plus the controller wired against it.
    /// </summary>
    private sealed class World : IAsyncDisposable
    {
        public const string ActorEmail = "owner@acme.test";
        public static readonly DateTimeOffset Now = new(2026, 4, 1, 12, 0, 0, TimeSpan.Zero);

        private readonly InMemoryDbFixture _fixture = new();

        public TestMetadataStore Store => _fixture.Store;
        public string OrgId { get; private set; } = "";
        public string ActorId { get; private set; } = "";
        public string ProjectId { get; private set; } = "";
        public string VersionId { get; private set; } = "";
        public SbomAnalysisController Controller { get; private set; } = null!;
        public RecordingReevaluator Reevaluator { get; } = new();

        public static async Task<World> CreateAsync()
        {
            var world = new World();
            await world._fixture.InitializeAsync();
            await world.SeedAsync();
            return world;
        }

        public async ValueTask DisposeAsync() => await _fixture.DisposeAsync();

        public async Task<JsonDocument> GetAnalysisAsync(
            string? versionId = null, ProjectAnalysisFilterRequest? filter = null)
        {
            var result = await Controller.Analysis(
                ProjectId, versionId ?? VersionId, filter ?? new ProjectAnalysisFilterRequest());
            return Serialize(Assert.IsType<OkObjectResult>(result).Value);
        }

        public async Task<JsonDocument> TriageAsync(UpdateProjectVulnAnalysisRequest req)
        {
            var result = await Controller.Triage(ProjectId, "latest", req);
            return Serialize(Assert.IsType<OkObjectResult>(result).Value);
        }

        /// <summary>A project in a different tenant — the BOLA probe target.</summary>
        public async Task<string> SeedForeignProjectAsync()
        {
            string foreignOrg = await OrgSeeder.InsertAsync(Store, OtherOrgSlug);
            string projectId = Guid.NewGuid().ToString("N");
            await using var conn = await Store.OpenAsync();
            await conn.ExecuteAsync(
                "INSERT INTO projects (id, org_id, kind, name, classifier) VALUES (@projectId, @foreignOrg, 'project', 'secret', 'application')",
                new { projectId, foreignOrg });
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest)
                VALUES (@id, @foreignOrg, @projectId, '9.9.9', 1)
                """,
                new { id = Guid.NewGuid().ToString("N"), foreignOrg, projectId });
            return projectId;
        }

        /// <summary>
        /// A second version of the seeded project, in the same tenant, with no <c>project_documents</c>
        /// row at all — a version an operator created but never uploaded an SBOM against, distinct
        /// from the cross-org 404 <see cref="SeedForeignProjectAsync"/> exercises.
        /// </summary>
        public async Task<string> SeedVersionWithNoDocumentAsync()
        {
            string versionId = Guid.NewGuid().ToString("N");
            await using var conn = await Store.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest)
                VALUES (@versionId, @OrgId, @ProjectId, '1.5.0', 0)
                """,
                new { versionId, OrgId, ProjectId });
            return versionId;
        }

        public async Task SeedHostedPackageAsync(
            string ecosystem, string purlName, string? upstreamLatestVersion = null)
        {
            await using var conn = await Store.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name, upstream_latest_version)
                VALUES (@id, @orgId, @ecosystem, @purlName, @purlName, @upstreamLatestVersion)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId = OrgId,
                    ecosystem,
                    purlName,
                    upstreamLatestVersion,
                });

            // The component's own purl_name has to match what the registry stores, or the key never
            // lines up. Point the seeded component at the hosted name — except for a coordinate a
            // test seeded its own component for, which already names itself.
            await conn.ExecuteAsync(
                """
                UPDATE sbom_components SET purl_name = @purlName
                WHERE org_id = @orgId AND name = 'minimist'
                  AND NOT EXISTS (SELECT 1 FROM sbom_components other
                                  WHERE other.org_id = @orgId AND other.purl_name = @purlName)
                """,
                new { purlName, orgId = OrgId });
        }

        /// <summary>One hosted version row under an already-seeded package.</summary>
        public async Task SeedHostedVersionAsync(
            string ecosystem, string purlName, string version,
            string? manualBlockState = null, string? deprecated = null)
        {
            await using var conn = await Store.OpenAsync();
            string packageId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM packages WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName",
                new { orgId = OrgId, ecosystem, purlName }) ?? "";
            await conn.ExecuteAsync(
                """
                INSERT INTO package_versions
                    (id, package_id, version, purl, blob_key, manual_block_state, deprecated)
                VALUES (@id, @packageId, @version, @purl, @blobKey, @manualBlockState, @deprecated)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    packageId,
                    version,
                    purl = $"pkg:{ecosystem}/{purlName}@{version}",
                    blobKey = $"registry/{Guid.NewGuid():N}",
                    manualBlockState,
                    deprecated,
                });
        }

        /// <summary>
        /// One global cache_artifact row bound to BOTH this tenant and another, each with its own
        /// block state. The shape that separates a per-tenant read from a tenant-blind one.
        /// </summary>
        public async Task SeedSharedCachedArtifactAsync(
            string ecosystem, string name, bool blockedForThisOrg, bool blockedForOtherOrg)
        {
            string artifactId = Guid.NewGuid().ToString("N");
            string otherOrg = await OrgSeeder.InsertAsync(Store, OtherOrgSlug);
            await using var conn = await Store.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@artifactId, @ecosystem, @name, '2.28.1', 'requests-2.28.1.whl', 'proxy/abc', 'abc')
                """,
                new { artifactId, ecosystem, name });
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, manual_block_state)
                VALUES (@orgId, @artifactId, @state)
                """,
                new { orgId = OrgId, artifactId, state = blockedForThisOrg ? "blocked" : null });
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, manual_block_state)
                VALUES (@otherOrg, @artifactId, @state)
                """,
                new { otherOrg, artifactId, state = blockedForOtherOrg ? "blocked" : null });
        }

        /// <summary>
        /// A NuGet component whose SBOM version spelling is the 4-part form. <c>purl_name</c> is
        /// the folded, lowercase id the registry stores, while <c>name</c> keeps the id as the SBOM
        /// wrote it — the same split every NuGet row on this plane has.
        /// </summary>
        public async Task SeedNuGetComponentAsync(string id, string version)
        {
            await using var conn = await Store.OpenAsync();
            await InsertComponentAsync(
                conn, id, $"pkg:nuget/{id}@{version}", "nuget", id.ToLowerInvariant(), version,
                dependencyScope: "runtime", sbomScope: null, license: null);
        }

        /// <summary>A component in an ecosystem with no native version ordering registered.</summary>
        public async Task SeedGoComponentAsync(string module, string version)
        {
            await using var conn = await Store.OpenAsync();
            await InsertComponentAsync(
                conn, module, $"pkg:golang/{module}@{version}", "golang", module, version,
                dependencyScope: "runtime", sbomScope: null, license: null);
        }

        /// <summary>A component carrying no purl at all — nothing the registry can be asked about.</summary>
        public async Task SeedUncoordinatedComponentAsync(string name)
        {
            await using var conn = await Store.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name, component_type)
                VALUES (@id, @orgId, @versionId, NULL, NULL, NULL, '1.0.0', @name, 'file')
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId = OrgId, versionId = VersionId, name });
        }

        public async Task SeedCachedArtifactAsync(
            string ecosystem, string name, bool boundToOrg, string? manualBlockState = null)
        {
            string artifactId = Guid.NewGuid().ToString("N");
            await using var conn = await Store.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@artifactId, @ecosystem, @name, '2.28.1', 'requests-2.28.1.whl', 'proxy/abc', 'abc')
                """,
                new { artifactId, ecosystem, name });

            if (boundToOrg)
            {
                await conn.ExecuteAsync(
                    """
                    INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, manual_block_state)
                    VALUES (@orgId, @artifactId, @manualBlockState)
                    """,
                    new { orgId = OrgId, artifactId, manualBlockState });
            }
            else
            {
                string otherOrg = await OrgSeeder.InsertAsync(Store, OtherOrgSlug);
                await conn.ExecuteAsync(
                    """
                    INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, manual_block_state)
                    VALUES (@otherOrg, @artifactId, @manualBlockState)
                    """,
                    new { otherOrg, artifactId, manualBlockState });
            }
        }

        private async Task SeedAsync()
        {
            OrgId = await OrgSeeder.InsertAsync(Store, "acme");
            ActorId = await UserSeeder.InsertAsync(Store, OrgId, ActorEmail, role: "owner");

            ProjectId = Guid.NewGuid().ToString("N");
            VersionId = Guid.NewGuid().ToString("N");

            await using (var conn = await Store.OpenAsync())
            {
                // The project name deliberately carries a separator and a space so the derived
                // document filename has something to sanitize.
                await conn.ExecuteAsync(
                    """
                    INSERT INTO projects (id, org_id, kind, name, classifier)
                    VALUES (@ProjectId, @OrgId, 'project', 'acme/storefront', 'application')
                    """, this);
                await conn.ExecuteAsync(
                    """
                    INSERT INTO project_versions (id, org_id, project_id, version, is_latest, policy_status)
                    VALUES (@VersionId, @OrgId, @ProjectId, '1.4.0', 1, 'violation')
                    """, this);
                await conn.ExecuteAsync(
                    """
                    INSERT INTO project_documents
                        (id, org_id, project_version_id, doc_type, format, spec_version, sha256, size_bytes, blob_key, uploaded_at)
                    VALUES (@id, @OrgId, @VersionId, 'sbom', 'cyclonedx-json', '1.6', @sha, 2048, 'hosted/x', @now)
                    """,
                    new
                    {
                        id = Guid.NewGuid().ToString("N"),
                        OrgId,
                        VersionId,
                        sha = new string('a', 64),
                        now = Now.ToUtcIso(),
                    });

                await InsertComponentAsync(conn, "minimist", "pkg:npm/minimist@1.2.5", "npm", "minimist", "1.2.5",
                    dependencyScope: "dev", sbomScope: null, license: "MIT");
                await InsertComponentAsync(conn, "qs", "pkg:npm/qs@6.10.2", "npm", "qs", "6.10.2",
                    dependencyScope: "runtime", sbomScope: "required", license: null);
                await InsertComponentAsync(conn, "requests", "pkg:pypi/requests@2.28.1", "pypi", "requests", "2.28.1",
                    dependencyScope: "runtime", sbomScope: null, license: "Apache-2.0");
            }

            await LinkAdvisoryAsync("minimist", "GHSA-xvch-5gv4-984h", """["CVE-2021-44906"]""", "CRITICAL", 9.8);
            await LinkAdvisoryAsync("qs", "GHSA-hrpp-h998-j3pp", """["CVE-2022-24999"]""", "HIGH", 7.5);
            await LinkAdvisoryAsync("requests", "GHSA-j8r2-6x86-q33q", """["CVE-2023-32681"]""", "MEDIUM", 6.1);

            await InsertAnalysisAsync("pkg:npm/qs", "CVE-2022-24999", reachability: "reachable", confidence: "high");
            await InsertAnalysisAsync("pkg:npm/event-stream", "GHSA-mh6f-8j2x-4483", vexState: "exploitable");

            await using (var conn = await Store.OpenAsync())
            {
                string componentId = await conn.ExecuteScalarAsync<string>(
                    "SELECT id FROM sbom_components WHERE org_id = @OrgId AND name = 'qs'", this) ?? "";
                await conn.ExecuteAsync(
                    """
                    INSERT INTO sbom_policy_findings (id, org_id, project_version_id, component_id, arm, vuln_key)
                    VALUES (@id, @OrgId, @VersionId, @componentId, 'cvss', 'CVE-2022-24999')
                    """,
                    new { id = Guid.NewGuid().ToString("N"), OrgId, VersionId, componentId });
            }

            BuildController();
        }

        private async Task InsertComponentAsync(
            System.Data.Common.DbConnection conn, string name, string purl, string ecosystem,
            string purlName, string version, string dependencyScope, string? sbomScope, string? license)
            => await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                     component_type, sbom_scope, dependency_scope, dependency_kind, license_spdx)
                VALUES (@id, @orgId, @versionId, @purl, @ecosystem, @purlName, @version, @name,
                        'library', @sbomScope, @dependencyScope, 'direct', @license)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId = OrgId,
                    versionId = VersionId,
                    purl,
                    ecosystem,
                    purlName,
                    version,
                    name,
                    sbomScope,
                    dependencyScope,
                    license,
                });

        private async Task LinkAdvisoryAsync(
            string componentName, string osvId, string aliases, string severity, double cvss)
        {
            string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
                Store, osvId, severity: severity, cvssScore: cvss, aliases: aliases);
            await using var conn = await Store.OpenAsync();
            string componentId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM sbom_components WHERE org_id = @orgId AND name = @componentName",
                new { orgId = OrgId, componentName }) ?? "";
            await conn.ExecuteAsync(
                "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
                new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });
        }

        private async Task InsertAnalysisAsync(
            string purlKey, string vulnKey, string? vexState = null,
            string? reachability = null, string? confidence = null, DateTimeOffset? updatedAt = null)
        {
            await using var conn = await Store.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO project_vuln_analysis
                    (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_source,
                     reachability, confidence, updated_at)
                VALUES (@id, @orgId, @versionId, @purlKey, @vulnKey, @vexState, 'upload',
                        @reachability, @confidence, @now)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId = OrgId,
                    versionId = VersionId,
                    purlKey,
                    vulnKey,
                    vexState,
                    reachability,
                    confidence,
                    now = (updatedAt ?? Now).ToUtcIso(),
                });
        }

        /// <summary>
        /// Overrides the seeded version's <c>created_at</c> directly, for tests asserting the
        /// "inherited triage" comparison point — <c>SbomAnalysisRepository.ResolveVersionAsync</c>
        /// must select this column on both its <c>latest</c>-alias and explicit-id branches.
        /// </summary>
        public async Task SetVersionCreatedAtAsync(DateTimeOffset createdAt)
        {
            await using var conn = await Store.OpenAsync();
            await conn.ExecuteAsync(
                "UPDATE project_versions SET created_at = @createdAt WHERE id = @VersionId",
                new { createdAt = createdAt.ToUtcIso(), VersionId });
        }

        /// <summary>Exposes <see cref="InsertAnalysisAsync"/> for tests seeding their own timestamp.</summary>
        public Task InsertAnalysisWithTimestampAsync(
            string purlKey, string vulnKey, DateTimeOffset updatedAt, string? vexState = null) =>
            InsertAnalysisAsync(purlKey, vulnKey, vexState, updatedAt: updatedAt);

        private void BuildController()
        {
            var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(Now);
            var http = new DefaultHttpContext();
            http.Request.Scheme = "https";
            http.Request.Host = new HostString("acme.example.test");
            http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.7");
            http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(OrgId, "acme");
            http.User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, ActorId),
                    new Claim("sub", ActorId),
                    new Claim("org_id", OrgId),
                    new Claim("tid", OrgId),
                    new Claim("role", "owner"),
                    new Claim("scope", "tenant"),
                ],
                authenticationType: "test"));

            Controller = new SbomAnalysisController(
                new SbomAnalysisRepository(Store, clock),
                new OrgAccessGuard(Store, TestProblems.Create()),
                new ProblemResults(new EchoLocalizer()),
                new AuditRepository(Store, time: clock),
                Reevaluator,
                new ProjectDocumentRepository(Store),
                new SbomIngestRepository(Store))
            {
                ControllerContext = new ControllerContext { HttpContext = http },
            };
        }
    }

    /// <summary>Records the versions whose policy the triage path asked to re-evaluate.</summary>
    private sealed class RecordingReevaluator : ISbomPolicyReevaluator
    {
        public List<(string OrgId, string ProjectVersionId)> Calls { get; } = [];

        public Task ReevaluateAsync(string orgId, string projectVersionId, CancellationToken ct = default)
        {
            Calls.Add((orgId, projectVersionId));
            return Task.CompletedTask;
        }
    }

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);
        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);
        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}
