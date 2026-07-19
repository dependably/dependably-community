using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The drill-downs behind the Overview dashboard's operational-risk and license-risk tiles.
/// They gate on ReadPackages — the same capability that serves the tiles themselves — so a member
/// who can see a number can open the list behind it; this is deliberately not an admin surface.
/// The payload is projected in camelCase because that is what the Svelte frontend reads.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RiskControllerTests
{
    [Fact]
    public async Task A_member_can_open_both_drill_downs()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        // Not an admin surface: read:packages is a member capability, and every role that can see
        // the tile must be able to see the rows behind it.
        Assert.IsType<OkObjectResult>(await b.RiskController.Operational());
        Assert.IsType<OkObjectResult>(await b.RiskController.License());
    }

    [Fact]
    public async Task Operational_drill_down_projects_the_rows_and_the_tiles_package_count()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        await SeedOperationalAsync(b.Db, b.PrimaryOrgId);

        var ok = (OkObjectResult)await b.RiskController.Operational();

        Assert.Equal(2, Prop<int>(ok, "total"));           // the uploaded + proxy rows
        Assert.Equal(2, Prop<int>(ok, "packageCount"));    // what the tile itself shows
        Assert.Equal(PackageAnalyticsRepository.VersionsBehindDashboardThreshold, Prop<int>(ok, "threshold"));

        // camelCase, not PascalCase: a PascalCase payload is a silent runtime break in the page,
        // not a compile error.
        object first = Prop<System.Collections.IEnumerable>(ok, "items").Cast<object>().First();
        Assert.NotNull(first.GetType().GetProperty("versionsBehind"));
        Assert.NotNull(first.GetType().GetProperty("displayName"));
    }

    [Fact]
    public async Task License_drill_down_labels_each_reason_and_carries_the_spdx_ids()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        await SeedLicenseAsync(b.Db, b.PrimaryOrgId);

        var ok = (OkObjectResult)await b.RiskController.License();
        var rows = Prop<System.Collections.IEnumerable>(ok, "items").Cast<object>().ToList();

        Assert.Equal(2, Prop<int>(ok, "total"));   // the blocklisted version + the one with no license

        object blocked = rows.Single(r => (string)Get(r, "reason")! == "blocklisted");
        object unknown = rows.Single(r => (string)Get(r, "reason")! == "unknown");

        // The blocklisted row says which license got it flagged; the unknown row has none to show.
        Assert.Equal(["GPL-3.0-only"], (IEnumerable<string>)Get(blocked, "licenses")!);
        Assert.Empty((IEnumerable<string>)Get(unknown, "licenses")!);
    }

    [Fact]
    public async Task License_drill_down_rejects_a_reason_it_does_not_know()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.RiskController.License(ecosystem: null, reason: "bogus");

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(422, problem.StatusCode);
    }

    [Fact]
    public async Task Page_size_is_clamped_so_a_caller_cannot_ask_for_the_whole_table()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = (OkObjectResult)await b.RiskController.Operational(ecosystem: null, limit: 9999, page: 0);

        Assert.Equal(200, Prop<int>(ok, "limit"));   // clamped to the max page size
        Assert.Equal(0, Prop<int>(ok, "offset"));    // page floored at 1
    }

    private static T Prop<T>(OkObjectResult ok, string name) => (T)Get(ok.Value!, name)!;

    private static object? Get(object target, string name) =>
        target.GetType().GetProperty(name)!.GetValue(target);

    // One uploaded version at the threshold and one proxied artifact over it — the two rows the
    // operational tile counts as two distinct packages.
    private static async Task SeedOperationalAsync(IMetadataStore db, string orgId)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES ('p1',@orgId,'npm','behind','behind',0)",
            new { orgId });
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, versions_behind) " +
            "VALUES ('v1','p1','1.0.0','pkg:npm/behind@1.0.0','registry/v1','uploaded'," +
            PackageAnalyticsRepository.VersionsBehindDashboardThreshold + ")");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, versions_behind) " +
            "VALUES ('ca1','npm','proxy-behind','1.0.0','proxy-behind-1.0.0.tgz','proxy/aaa','aaa'," +
            (PackageAnalyticsRepository.VersionsBehindDashboardThreshold + 3) + ")");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId,'ca1')", new { orgId });
    }

    // One version on a blocklisted license and one with no license row at all.
    private static async Task SeedLicenseAsync(IMetadataStore db, string orgId)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_blocklist (id, org_id, license_spdx) VALUES ('bl1',@orgId,'GPL-3.0-only')",
            new { orgId });
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('p1',@orgId,'npm','gpl-pkg','gpl-pkg',0), ('p2',@orgId,'npm','no-license','no-license',0)",
            new { orgId });
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) VALUES " +
            "('v1','p1','1.0.0','pkg:npm/gpl-pkg@1.0.0','registry/v1','uploaded'), " +
            "('v2','p2','1.0.0','pkg:npm/no-license@1.0.0','registry/v2','uploaded')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, package_version_id, license_spdx, owner_kind) " +
            "VALUES ('l1','v1','GPL-3.0-only','package_version')");
    }
}
