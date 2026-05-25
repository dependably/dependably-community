using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Coverage for <see cref="SpdxLicenseController"/> — read-only typeahead + detail
/// endpoints backed by the seeded <c>spdx_license</c> reference table. Tests run the
/// controller against a real <see cref="SpdxLicenseRepository"/> + in-memory SQLite,
/// reusing <see cref="ControllerScenario"/> to wire up tenant context + claims.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SpdxLicenseControllerUnitTests
{
    private static async Task SeedSpdxAsync(IMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT OR REPLACE INTO spdx_license
              (identifier, name, is_osi_approved, is_fsf_libre, is_deprecated, reference_url, copyleft)
            VALUES
              ('MIT',         'MIT License',                     1, 1, 0, 'https://spdx.org/licenses/MIT.html',         'permissive'),
              ('Apache-2.0',  'Apache License 2.0',              1, 1, 0, 'https://spdx.org/licenses/Apache-2.0.html',  'permissive'),
              ('GPL-3.0-only','GNU General Public License v3.0', 1, 1, 0, 'https://spdx.org/licenses/GPL-3.0-only.html','strong-copyleft'),
              ('GPL-2.0',     'GNU GPL v2.0 (deprecated)',       1, 1, 1, 'https://spdx.org/licenses/GPL-2.0.html',     'strong-copyleft'),
              ('BSD-3-Clause','BSD 3-Clause',                    1, 1, 0, 'https://spdx.org/licenses/BSD-3-Clause.html','permissive');
            """);
    }

    private static SpdxLicenseController BuildController(ControllerScenarioResult b)
    {
        // Reuse the ControllerContext (tenant + principal) from a sibling controller.
        var repo = new SpdxLicenseRepository(b.Db);
        var guard = new Dependably.Security.OrgAccessGuard(b.Db);
        return new SpdxLicenseController(repo, guard)
        {
            ControllerContext = b.LicenseController.ControllerContext
        };
    }

    // ── List ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_Member_NoQuery_ReturnsNonDeprecatedRows()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();
        await SeedSpdxAsync(b.Db);

        var controller = BuildController(b);
        var result = await controller.List(q: null, includeDeprecated: false, limit: null, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        var rows = Assert.IsAssignableFrom<IReadOnlyList<SpdxLicense>>(ok.Value);
        Assert.NotEmpty(rows);
        // No-query path returns alphabetically up to the (clamped) limit. Verify the
        // deprecated filter took effect — no deprecated rows in the result set.
        Assert.All(rows, r => Assert.False(r.IsDeprecated));
    }

    [Fact]
    public async Task List_Member_QueryFilters_AndPrefixMatchesFirst()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();
        await SeedSpdxAsync(b.Db);

        var controller = BuildController(b);
        var result = await controller.List(q: "gpl", includeDeprecated: false, limit: null, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        var rows = Assert.IsAssignableFrom<IReadOnlyList<SpdxLicense>>(ok.Value);
        Assert.NotEmpty(rows);
        Assert.All(rows, r => Assert.True(
            r.Identifier.Contains("GPL", StringComparison.OrdinalIgnoreCase)
            || r.Name.Contains("GPL", StringComparison.OrdinalIgnoreCase)));
        // GPL-2.0 is deprecated → excluded; GPL-3.0-only stays.
        Assert.DoesNotContain(rows, r => r.Identifier == "GPL-2.0");
        Assert.Contains(rows, r => r.Identifier == "GPL-3.0-only");
    }

    [Fact]
    public async Task List_IncludeDeprecatedTrue_SurfacesDeprecatedRows()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();
        await SeedSpdxAsync(b.Db);

        var controller = BuildController(b);
        var result = await controller.List(q: "gpl", includeDeprecated: true, limit: null, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        var rows = Assert.IsAssignableFrom<IReadOnlyList<SpdxLicense>>(ok.Value);
        Assert.Contains(rows, r => r.Identifier == "GPL-2.0");
    }

    [Fact]
    public async Task List_LimitOverCap_ClampedTo500_AndStillReturnsRows()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();
        await SeedSpdxAsync(b.Db);

        var controller = BuildController(b);
        // limit=9999 — controller clamps to 500 before passing to the repo. We have <500 rows
        // seeded, so the result count is bounded by the seeded set and the call must succeed.
        var result = await controller.List(q: null, includeDeprecated: true, limit: 9999, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        var rows = Assert.IsAssignableFrom<IReadOnlyList<SpdxLicense>>(ok.Value);
        Assert.True(rows.Count <= 500);
        Assert.True(rows.Count >= 5);
    }

    [Fact]
    public async Task List_LimitBelowFloor_ClampedToOne()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();
        await SeedSpdxAsync(b.Db);

        var controller = BuildController(b);
        var result = await controller.List(q: null, includeDeprecated: false, limit: 0, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        var rows = Assert.IsAssignableFrom<IReadOnlyList<SpdxLicense>>(ok.Value);
        Assert.Single(rows); // clamped to 1
    }

    [Fact]
    public async Task List_Anonymous_DeniedBeforeReadingData()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();
        await SeedSpdxAsync(b.Db);

        var controller = BuildController(b);
        var result = await controller.List(q: null, includeDeprecated: false, limit: null, CancellationToken.None);

        Assert.False(result is OkObjectResult);
    }

    // ── Get ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Get_Member_KnownIdentifier_Returns200WithRow()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();
        await SeedSpdxAsync(b.Db);

        var controller = BuildController(b);
        var result = await controller.Get("MIT", CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        var row = Assert.IsType<SpdxLicense>(ok.Value);
        Assert.Equal("MIT", row.Identifier);
        Assert.Equal("permissive", row.Copyleft);
    }

    [Fact]
    public async Task Get_Member_UnknownIdentifier_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();
        await SeedSpdxAsync(b.Db);

        var controller = BuildController(b);
        var result = await controller.Get("Never-Heard-Of-It-9.9", CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Get_Anonymous_DeniedBeforeReadingData()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();
        await SeedSpdxAsync(b.Db);

        var controller = BuildController(b);
        var result = await controller.Get("MIT", CancellationToken.None);

        Assert.False(result is OkObjectResult);
    }
}
