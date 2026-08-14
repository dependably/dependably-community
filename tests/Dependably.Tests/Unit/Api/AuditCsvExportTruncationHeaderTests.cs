using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// A CSV export whose search was bounded to the newest <see cref="AuditRepository.SearchScanCap"/>
/// rows must say so. The bound is what stops <c>?format=csv&amp;search=…</c> from being an
/// unindexable full-history scan any <c>read:audit</c> holder can re-issue at will; the header is
/// what stops the resulting truncation from being silent, which is the property a compliance
/// export needs. An export whose search fits inside the window, and an export with no search term
/// at all, both set no header — the second is how a complete export of a large history is taken.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditCsvExportTruncationHeaderTests
{
    private const string TruncatedHeader = "X-Export-Truncated";

    [Fact]
    public async Task Audit_csv_export_with_a_truncated_search_window_flags_the_response()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        await SeedAuditRowsAsync(b.Db, b.PrimaryOrgId, AuditRepository.SearchScanCap + 10);

        Assert.IsType<FileContentResult>(
            await b.OrgAuditController.GetAudit(search: "the needle", format: "csv"));

        Assert.Equal("true", b.OrgAuditController.Response.Headers[TruncatedHeader]);
    }

    [Fact]
    public async Task Audit_csv_export_within_the_search_window_is_not_flagged()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        await SeedAuditRowsAsync(b.Db, b.PrimaryOrgId, 10);

        var export = Assert.IsType<FileContentResult>(
            await b.OrgAuditController.GetAudit(search: "the needle", format: "csv"));

        // The needle is inside the window, so the export is complete and unflagged.
        Assert.Contains(
            "the needle",
            System.Text.Encoding.UTF8.GetString(export.FileContents),
            StringComparison.Ordinal);
        Assert.False(b.OrgAuditController.Response.Headers.ContainsKey(TruncatedHeader));
    }

    [Fact]
    public async Task Audit_csv_export_with_no_search_term_is_never_flagged()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        await SeedAuditRowsAsync(b.Db, b.PrimaryOrgId, AuditRepository.SearchScanCap + 10);

        Assert.IsType<FileContentResult>(await b.OrgAuditController.GetAudit(format: "csv"));

        Assert.False(b.OrgAuditController.Response.Headers.ContainsKey(TruncatedHeader));
    }

    // One old matching row under `filler` newer non-matching rows, so the match falls outside the
    // scan window once filler exceeds the cap.
    private static async Task SeedAuditRowsAsync(IMetadataStore db, string orgId, int filler)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, action, detail, created_at)
            VALUES ('aud-needle', 'tenant', @orgId, 'org_settings_updated', 'the needle',
                    strftime('%Y-%m-%dT%H:%M:%f', 1700000000, 'unixepoch') || 'Z')
            """,
            new { orgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, action, detail, created_at)
            WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < @filler)
            SELECT 'aud' || n, 'tenant', @orgId, 'org_settings_updated', 'filler row',
                   strftime('%Y-%m-%dT%H:%M:%f', 1700000000 + n, 'unixepoch') || 'Z'
            FROM seq
            """,
            new { orgId, filler });
    }
}
