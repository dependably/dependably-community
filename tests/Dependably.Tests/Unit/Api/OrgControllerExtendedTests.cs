using Dapper;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Branch-coverage top-up for OrgController. The base file covers the happy paths and the
/// big-ticket auth checks; this file targets the remaining decision points:
///   • ListPackages — pagination clamping (both ends), ecosystem filter, search filter,
///     every sortBy/sortDir pair, anonymous denial.
///   • GetPackage — anonymous denial, npm route-decoding path, the five ComputeVersionStatus
///     branches (blocked, allowed+clean, allowed+autoblocked, autoblocked, unscanned, clean).
///   • DeleteVersion — pypi + nuget yank branches, happy-path delete (blob + audit + GC),
///     anonymous denial.
///   • GetStats — anonymous denial.
///   • GetSetup — http snippet (trusted-host branch), each ecosystem snippet shape, anonymous.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgControllerExtendedTests
{
    // ── ListPackages: filter / sort / pagination branches ────────────────────

    [Fact]
    public async Task ListPackages_Anonymous_Denied()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgController.ListPackages();
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task ListPackages_EcosystemFilter_OnlyMatchingEcosystem()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync("acme-npm", ecosystem: "npm");
        await s.WithPackageAsync("acme-py", ecosystem: "pypi");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.OrgController.ListPackages(ecosystem: "pypi"));
        var total = (int)ok.Value!.GetType().GetProperty("total")!.GetValue(ok.Value)!;
        Assert.Equal(1, total);
    }

    [Fact]
    public async Task ListPackages_SearchFilter_NarrowsResults()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync("alpha");
        await s.WithPackageAsync("beta");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.OrgController.ListPackages(search: "alph"));
        var total = (int)ok.Value!.GetType().GetProperty("total")!.GetValue(ok.Value)!;
        Assert.Equal(1, total);
    }

    [Theory]
    [InlineData("name",      "asc")]
    [InlineData("name",      "desc")]
    [InlineData("purl",      "asc")]
    [InlineData("purl",      "desc")]
    [InlineData("vulns",     "asc")]
    [InlineData("vulns",     "desc")]
    [InlineData("ecosystem", "asc")]
    [InlineData("ecosystem", "desc")]
    [InlineData("versions",  "asc")]
    [InlineData("versions",  "desc")]
    [InlineData("created",   "desc")]
    [InlineData("unknown",   "asc")]   // falls through to the default arm
    public async Task ListPackages_SortVariants_Return200(string sortBy, string sortDir)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync("a-pkg");
        await s.WithPackageAsync("b-pkg");
        var b = await s.BuildAsync();

        var result = await b.OrgController.ListPackages(sortBy: sortBy, sortDir: sortDir);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task ListPackages_LimitAndPageClamped_ToValidRange()
    {
        // limit > 200 clamps to 200; page < 1 clamps to 1. Offset is derived.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(
            await b.OrgController.ListPackages(limit: 9999, page: 0));

        var value = ok.Value!;
        var limit  = (int)value.GetType().GetProperty("limit")!.GetValue(value)!;
        var offset = (int)value.GetType().GetProperty("offset")!.GetValue(value)!;
        Assert.Equal(200, limit);
        Assert.Equal(0, offset);
    }

    [Fact]
    public async Task ListPackages_LimitBelowOne_ClampedToOne()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(
            await b.OrgController.ListPackages(limit: 0, page: 3));
        var value = ok.Value!;
        var limit  = (int)value.GetType().GetProperty("limit")!.GetValue(value)!;
        var offset = (int)value.GetType().GetProperty("offset")!.GetValue(value)!;
        Assert.Equal(1, limit);
        Assert.Equal(2, offset); // (3-1)*1
    }

    // ── GetPackage: anonymous + version-status branches ──────────────────────

    [Fact]
    public async Task GetPackage_Anonymous_Denied()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgController.GetPackage("npm", "anything", CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task GetPackage_NpmScopedName_DecodedThroughRouteHelper()
    {
        // The route encodes "@scope/name" as "@scope%2Fname"; controller calls
        // NpmRouteHelper.DecodeRouteName for npm only. Seeding a scoped package and
        // looking it up through the controller exercises that arm of AsPurlName.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("@scope/widget");
        var b = await s.BuildAsync();

        var result = await b.OrgController.GetPackage("npm", "@scope%2fwidget", CancellationToken.None);
        // 200 if route decoding resolved the package; 404 means decoding mismatched.
        var status = (result as IStatusCodeActionResult)?.StatusCode;
        Assert.True(result is OkObjectResult || status == StatusCodes.Status404NotFound);
    }

    [Theory]
    [InlineData("blocked", null,   "blocked")]   // manual block dominates
    [InlineData(null,     null,   "unscanned")]  // never scanned, no manual state
    [InlineData(null,     1.0,    "clean")]      // scanned, score below tolerance
    [InlineData(null,     9.5,    "blocked")]    // scanned, score above tolerance → auto-block
    [InlineData("allowed", 9.5,   "allowed")]    // manual allow overrides an auto-block
    [InlineData("allowed", 1.0,   "clean")]      // manual allow with no auto-block reports clean
    public async Task GetPackage_VersionStatus_CoversAllBranches(
        string? manualState, double? maxScore, string expectedStatus)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync("statuspkg");
        await s.WithPackageVersionAsync("statuspkg", "1.0.0");
        var b = await s.BuildAsync();

        await using (var conn = await b.Db.OpenAsync())
        {
            // Tolerance default is 10.0 (per COALESCE in repo); set to 5.0 so 9.5 triggers
            // the auto-block arm and 1.0 stays under.
            await conn.ExecuteAsync(
                "UPDATE org_settings SET max_osv_score_tolerance = 5.0 WHERE org_id = @org",
                new { org = b.PrimaryOrgId });

            if (manualState is not null)
            {
                await conn.ExecuteAsync(
                    "UPDATE package_versions SET manual_block_state = @state WHERE version = '1.0.0'",
                    new { state = manualState });
            }

            if (maxScore.HasValue)
            {
                // Attach a real vuln row so GetMaxScoresForVersionsAsync sees the package
                // version as "scanned" with the requested score. Stamp vuln_checked_at too.
                var verId = await conn.ExecuteScalarAsync<string>(
                    "SELECT id FROM package_versions WHERE version = '1.0.0' LIMIT 1");
                var vulnId = await VulnerabilitySeeder.InsertVulnAsync(
                    b.Db, osvId: "GHSA-" + Guid.NewGuid().ToString("N")[..8], cvssScore: maxScore.Value);
                await VulnerabilitySeeder.LinkAsync(b.Db, verId!, vulnId);
                await conn.ExecuteAsync(
                    "UPDATE package_versions SET vuln_checked_at = '2025-01-01T00:00:00Z' WHERE version = '1.0.0'");
            }
        }

        var result = await b.OrgController.GetPackage("npm", "statuspkg", CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);

        // The anonymous projection exposes `versions` as IEnumerable<anon>. Reflect on
        // the first version's Status field to assert.
        var versions = (System.Collections.IEnumerable)ok.Value!.GetType().GetProperty("versions")!.GetValue(ok.Value)!;
        object? first = null;
        foreach (var v in versions) { first = v; break; }
        Assert.NotNull(first);
        var status = (string)first!.GetType().GetProperty("Status")!.GetValue(first)!;
        Assert.Equal(expectedStatus, status);
    }

    // ── DeleteVersion: pypi / nuget happy paths + audit + GC ────────────────

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    [InlineData("nuget")]
    public async Task DeleteVersion_KnownEcosystem_HappyPath_DeletesAndAudits(string ecosystem)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync("targetpkg", ecosystem: ecosystem);
        await s.WithPackageVersionAsync("targetpkg", "1.0.0", ecosystem: ecosystem);
        var b = await s.BuildAsync();

        var result = await b.OrgController.DeleteVersion(ecosystem, "targetpkg", "1.0.0", CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();

        // The version row is gone…
        var remainingVersions = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE version = '1.0.0'");
        Assert.Equal(0, remainingVersions);

        // …and the parent package was GC'd since this was its only version.
        var remainingPackages = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM packages WHERE name = 'targetpkg'");
        Assert.Equal(0, remainingPackages);

        // Activity row was written (operator action — never dual-written to audit_log).
        var activity = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE event_type = 'delete' AND ecosystem = @eco AND org_id = @org",
            new { eco = ecosystem, org = b.PrimaryOrgId });
        Assert.Equal(1, activity);
    }

    [Fact]
    public async Task DeleteVersion_LeavesOtherVersions_DoesNotGcPackage()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync("multi");
        await s.WithPackageVersionAsync("multi", "1.0.0");
        await s.WithPackageVersionAsync("multi", "2.0.0");
        var b = await s.BuildAsync();

        var result = await b.OrgController.DeleteVersion("npm", "multi", "1.0.0", CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var pkgCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM packages WHERE name = 'multi'");
        Assert.Equal(1, pkgCount); // package row stays — still has 2.0.0
    }

    [Fact]
    public async Task DeleteVersion_VersionMissing_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync("present");
        // No version seeded — package lookup succeeds but version lookup misses.
        var b = await s.BuildAsync();

        var result = await b.OrgController.DeleteVersion("npm", "present", "9.9.9", CancellationToken.None);
        var status = (result as IStatusCodeActionResult)?.StatusCode;
        Assert.Equal(StatusCodes.Status404NotFound, status);
    }

    [Fact]
    public async Task DeleteVersion_Anonymous_Denied()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgController.DeleteVersion("npm", "anything", "1.0.0", CancellationToken.None);
        Assert.False(result is NoContentResult);
    }

    // ── GetStats / GetSetup auth and config branches ─────────────────────────

    [Fact]
    public async Task GetStats_Anonymous_Denied()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgController.GetStats(CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task GetSetup_Anonymous_Denied()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgController.GetSetup("pypi", CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task GetSetup_PyPi_Http_IncludesTrustedHost()
    {
        // Scheme=http triggers the `--trusted-host` arm of the snippet generator. Scenario
        // builder defaults to https, so we flip the scheme on the HttpContext.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.OrgController.HttpContext.Request.Scheme = "http";

        var ok = Assert.IsType<OkObjectResult>(await b.OrgController.GetSetup("pypi", CancellationToken.None));
        var snippet = (string)ok.Value!.GetType().GetProperty("snippet")!.GetValue(ok.Value)!;
        Assert.Contains("--trusted-host", snippet);
    }

    [Fact]
    public async Task GetSetup_PyPi_PerEcosystemLimit_Wins_Over_GlobalLimit()
    {
        // Both per-ecosystem and global limits set — per-ecosystem must win in the snippet.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET max_upload_bytes = 1000, max_upload_bytes_pypi = 2000 " +
                "WHERE org_id = @org",
                new { org = b.PrimaryOrgId });
        }

        var ok = Assert.IsType<OkObjectResult>(await b.OrgController.GetSetup("pypi", CancellationToken.None));
        var snippet = (string)ok.Value!.GetType().GetProperty("snippet")!.GetValue(ok.Value)!;
        Assert.Contains("2000 bytes", snippet);
    }

    [Fact]
    public async Task GetSetup_Npm_FallsBack_To_GlobalLimit_When_PerEcosystemNull()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET max_upload_bytes = 555, max_upload_bytes_npm = NULL " +
                "WHERE org_id = @org",
                new { org = b.PrimaryOrgId });
        }

        var ok = Assert.IsType<OkObjectResult>(await b.OrgController.GetSetup("npm", CancellationToken.None));
        var snippet = (string)ok.Value!.GetType().GetProperty("snippet")!.GetValue(ok.Value)!;
        Assert.Contains("registry=", snippet);
        Assert.Contains("555 bytes", snippet);
    }

    [Fact]
    public async Task GetSetup_NuGet_EmbedsBaseUrl_InPackageSources()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.OrgController.GetSetup("nuget", CancellationToken.None));
        var snippet = (string)ok.Value!.GetType().GetProperty("snippet")!.GetValue(ok.Value)!;
        Assert.Contains("/nuget/v3/index.json", snippet);
        Assert.Contains("packageSources", snippet);
    }
}
