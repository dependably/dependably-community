using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage for the apex fleet-usage surface: GET /api/v1/system/usage,
/// GET /api/v1/system/usage.csv, and GET /api/v1/system/tenants/{slug}/usage. Exercises the full
/// HTTP pipeline (route scoping, validation, projection) the same way the sibling SystemController
/// integration suites do — <see cref="Unit.Infrastructure.UsageReportRepositoryTests"/> covers the
/// SQL underneath this.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemUsageTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public SystemUsageTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(string OrgId, string Slug, string OwnerId, string OwnerJwt, string Host)> CreateTenantAsync()
    {
        string slug = "us-" + Guid.NewGuid().ToString("N")[..8];
        using var sysClient = await _factory.CreateSystemAdminClient();
        var createResp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, createResp.StatusCode);
        var createDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync());
        string orgId = createDoc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        string ownerId;
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId LIMIT 1", new { orgId })
                ?? throw new InvalidOperationException("owner user missing");
        }

        string ownerJwt = await _factory.CreateTenantJwt(userId: ownerId, tenantId: orgId, role: "owner");
        string host = $"{slug}.{DependablyMultiFactory.ApexHost}";
        return (orgId, slug, ownerId, ownerJwt, host);
    }

    private async Task SeedDailyAsync(
        string orgId, string meter, string day, long quantity, long redirect = 0, long requests = 0)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO usage_daily (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
            VALUES (@orgId, @meter, @day, @quantity, @redirect, @requests, @day || 'T00:00:00Z')
            ON CONFLICT (org_id, meter, bucket) DO UPDATE SET
                quantity = excluded.quantity, redirect_quantity = excluded.redirect_quantity,
                request_count = excluded.request_count
            """,
            new { orgId, meter, day, quantity, redirect, requests });
    }

    private async Task SeedSnapshotAsync(string orgId, string day)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO storage_snapshot
                (org_id, day_utc, hosted_bytes, oci_uploaded_bytes, cache_attributed_bytes, billable_bytes,
                 hosted_version_count, oci_manifest_count, oci_blob_count, cache_entry_count, db_row_count, captured_at)
            VALUES (@orgId, @day, 111, 222, 333, 444, 12, 3, 40, 56, 7890, @day || 'T00:00:00Z')
            """,
            new { orgId, day });
    }

    // ── Authorization ────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("/api/v1/system/usage")]
    [InlineData("/api/v1/system/usage.csv")]
    public async Task Unauthenticated_apex_request_is_refused(string path)
    {
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        var resp = await client.GetAsync(path);
        Assert.True(
            resp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Unauthorized,
            $"expected 401/404, got {(int)resp.StatusCode}");
    }

    [Theory]
    [InlineData("/api/v1/system/usage")]
    [InlineData("/api/v1/system/usage.csv")]
    public async Task Tenant_admin_token_on_apex_host_is_refused(string path)
    {
        var (_, _, _, ownerJwt, _) = await CreateTenantAsync();
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ownerJwt);

        var resp = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Theory]
    [InlineData("/api/v1/system/usage")]
    [InlineData("/api/v1/system/usage.csv")]
    public async Task Tenant_host_request_is_refused_even_with_a_tenant_admin_token(string path)
    {
        var (_, _, _, ownerJwt, host) = await CreateTenantAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ownerJwt);

        var resp = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Tenant_host_request_is_refused_even_with_a_system_admin_token()
    {
        var (_, _, _, _, host) = await CreateTenantAsync();
        string systemJwt = await _factory.CreateSystemAdminJwt();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", systemJwt);

        var resp = await client.GetAsync("/api/v1/system/usage");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task System_admin_on_apex_sees_every_tenant()
    {
        var (orgId1, slug1, _, _, _) = await CreateTenantAsync();
        var (orgId2, slug2, _, _, _) = await CreateTenantAsync();
        await SeedDailyAsync(orgId1, "egress_bytes", "2026-09-01", 100);
        await SeedDailyAsync(orgId2, "egress_bytes", "2026-09-01", 200);

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/usage?from=2026-09-01&to=2026-09-01&pageSize=200");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var slugs = doc.RootElement.GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("slug").GetString()).ToHashSet();
        Assert.Contains(slug1, slugs);
        Assert.Contains(slug2, slugs);
    }

    // ── Fleet query correctness ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Fleet_listing_sums_egress_redirect_and_metadata_for_the_requested_range()
    {
        var (orgId, slug, _, _, _) = await CreateTenantAsync();
        await SeedDailyAsync(orgId, "egress_bytes", "2026-09-01", 1000, redirect: 250);
        await SeedDailyAsync(orgId, "egress_bytes", "2026-09-02", 500);
        await SeedDailyAsync(orgId, "egress_metadata_bytes", "2026-09-01", 30);

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/usage?from=2026-09-01&to=2026-09-02&pageSize=200");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var row = doc.RootElement.GetProperty("items").EnumerateArray()
            .First(i => i.GetProperty("slug").GetString() == slug);
        Assert.Equal(1500L, row.GetProperty("egressBytes").GetInt64());
        Assert.Equal(250L, row.GetProperty("egressRedirectBytes").GetInt64());
        Assert.Equal(30L, row.GetProperty("egressMetadataBytes").GetInt64());
    }

    [Fact]
    public async Task Fleet_listing_reports_request_counts_and_snapshot_counts_as_signals()
    {
        var (orgId, slug, _, _, _) = await CreateTenantAsync();
        await SeedDailyAsync(orgId, "egress_bytes", "2026-09-01", 1000, requests: 8);
        await SeedDailyAsync(orgId, "egress_bytes", "2026-09-02", 500, requests: 2);
        await SeedDailyAsync(orgId, "egress_metadata_bytes", "2026-09-01", 30, requests: 90);
        await SeedSnapshotAsync(orgId, "2026-09-02");

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/usage?from=2026-09-01&to=2026-09-02&pageSize=200");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var row = doc.RootElement.GetProperty("items").EnumerateArray()
            .First(i => i.GetProperty("slug").GetString() == slug);
        Assert.Equal(10L, row.GetProperty("requestCount").GetInt64());
        Assert.Equal(90L, row.GetProperty("metadataRequestCount").GetInt64());
        var snapshot = row.GetProperty("snapshot");
        Assert.Equal(15L, snapshot.GetProperty("artifactCount").GetInt64());
        Assert.Equal(12L, snapshot.GetProperty("hostedVersionCount").GetInt64());
        Assert.Equal(3L, snapshot.GetProperty("ociManifestCount").GetInt64());
        Assert.Equal(40L, snapshot.GetProperty("ociBlobCount").GetInt64());
        Assert.Equal(56L, snapshot.GetProperty("cacheEntryCount").GetInt64());
        Assert.Equal(7890L, snapshot.GetProperty("dbRowCount").GetInt64());

        var totals = doc.RootElement.GetProperty("totals");
        Assert.True(totals.GetProperty("requestCount").GetInt64() >= 10);
        Assert.True(totals.GetProperty("metadataRequestCount").GetInt64() >= 90);
    }

    [Fact]
    public async Task Fleet_listing_sorts_by_database_footprint()
    {
        var (orgId, slug, _, _, _) = await CreateTenantAsync();
        await SeedSnapshotAsync(orgId, "2026-09-02");

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/usage?from=2026-09-01&to=2026-09-02&sort=dbRowCount&dir=desc&pageSize=200");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var footprints = doc.RootElement.GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("snapshot").ValueKind == JsonValueKind.Null
                ? 0L
                : i.GetProperty("snapshot").GetProperty("dbRowCount").GetInt64())
            .ToList();
        Assert.Equal(footprints.OrderByDescending(f => f), footprints);
        Assert.Contains(doc.RootElement.GetProperty("items").EnumerateArray(), i => i.GetProperty("slug").GetString() == slug);
    }

    [Fact]
    public async Task Fleet_listing_validates_the_date_range()
    {
        using var client = await _factory.CreateSystemAdminClient();

        var badDate = await client.GetAsync("/api/v1/system/usage?from=not-a-date");
        Assert.Equal(HttpStatusCode.UnprocessableEntity, badDate.StatusCode);

        var inverted = await client.GetAsync("/api/v1/system/usage?from=2026-09-10&to=2026-09-01");
        Assert.Equal(HttpStatusCode.UnprocessableEntity, inverted.StatusCode);

        var tooLarge = await client.GetAsync("/api/v1/system/usage?from=2020-01-01&to=2026-01-01");
        Assert.Equal(HttpStatusCode.UnprocessableEntity, tooLarge.StatusCode);
    }

    [Fact]
    public async Task Csv_export_returns_an_attachment_with_the_same_rows_as_the_json_listing()
    {
        var (orgId, slug, _, _, _) = await CreateTenantAsync();
        await SeedDailyAsync(orgId, "egress_bytes", "2026-09-01", 4242);

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/usage.csv?from=2026-09-01&to=2026-09-01");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("text/csv", resp.Content.Headers.ContentType?.MediaType);
        Assert.Equal("attachment", resp.Content.Headers.ContentDisposition?.DispositionType);

        string csv = await resp.Content.ReadAsStringAsync();
        Assert.Contains("org_id,slug,status,egress_bytes", csv.Split("\r\n")[0]);
        Assert.Contains($"{orgId},{slug},active,4242", csv);
    }

    [Fact]
    public async Task Csv_export_appends_the_signal_columns_after_the_existing_ones()
    {
        var (orgId, _, _, _, _) = await CreateTenantAsync();
        await SeedDailyAsync(orgId, "egress_bytes", "2026-09-01", 4242, requests: 17);
        await SeedDailyAsync(orgId, "egress_metadata_bytes", "2026-09-01", 1, requests: 23);
        await SeedSnapshotAsync(orgId, "2026-09-01");

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/usage.csv?from=2026-09-01&to=2026-09-01");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string[] lines = (await resp.Content.ReadAsStringAsync()).Split("\r\n");
        Assert.Equal(
            "org_id,slug,status,egress_bytes,egress_redirect_bytes,egress_metadata_bytes,billable_storage_bytes,"
            + "storage_mark_days,snapshot_billable_bytes,snapshot_hosted_bytes,snapshot_oci_uploaded_bytes,"
            + "snapshot_cache_attributed_bytes,snapshot_captured_at,last_computed_at,request_count,"
            + "metadata_request_count,snapshot_artifact_count,snapshot_hosted_version_count,"
            + "snapshot_oci_manifest_count,snapshot_oci_blob_count,snapshot_cache_entry_count,snapshot_db_row_count",
            lines[0]);
        string row = Assert.Single(lines, l => l.StartsWith(orgId + ",", StringComparison.Ordinal));
        Assert.EndsWith(",17,23,15,12,3,40,56,7890", row, StringComparison.Ordinal);
    }

    // ── Per-tenant series ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Per_tenant_snapshot_carries_the_captured_counts()
    {
        var (orgId, slug, _, _, _) = await CreateTenantAsync();
        await SeedSnapshotAsync(orgId, "2026-09-02");

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync($"/api/v1/system/tenants/{slug}/usage?from=2026-09-01&to=2026-09-02");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var snapshot = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.GetProperty("latestSnapshot");
        Assert.Equal(15L, snapshot.GetProperty("artifactCount").GetInt64());
        Assert.Equal(12L, snapshot.GetProperty("hostedVersionCount").GetInt64());
        Assert.Equal(3L, snapshot.GetProperty("ociManifestCount").GetInt64());
        Assert.Equal(40L, snapshot.GetProperty("ociBlobCount").GetInt64());
        Assert.Equal(56L, snapshot.GetProperty("cacheEntryCount").GetInt64());
        Assert.Equal(7890L, snapshot.GetProperty("dbRowCount").GetInt64());
    }

    [Fact]
    public async Task Unknown_slug_returns_404()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/tenants/does-not-exist/usage");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Per_tenant_daily_series_reports_one_bucket_per_day()
    {
        var (orgId, slug, _, _, _) = await CreateTenantAsync();
        await SeedDailyAsync(orgId, "egress_bytes", "2026-09-01", 100);
        await SeedDailyAsync(orgId, "egress_bytes", "2026-09-02", 200);

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync($"/api/v1/system/tenants/{slug}/usage?from=2026-09-01&to=2026-09-02");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("day", doc.RootElement.GetProperty("granularity").GetString());
        var series = doc.RootElement.GetProperty("series").EnumerateArray().ToList();
        Assert.Equal(2, series.Count);
        Assert.Equal(100L, series.First(b => b.GetProperty("bucket").GetString() == "2026-09-01")
            .GetProperty("egressBytes").GetInt64());
        Assert.Equal(200L, series.First(b => b.GetProperty("bucket").GetString() == "2026-09-02")
            .GetProperty("egressBytes").GetInt64());
    }

    [Fact]
    public async Task Per_tenant_series_and_month_to_date_carry_request_counts()
    {
        var (orgId, slug, _, _, _) = await CreateTenantAsync();
        await SeedDailyAsync(orgId, "egress_bytes", "2026-09-01", 100, requests: 4);
        await SeedDailyAsync(orgId, "egress_metadata_bytes", "2026-09-01", 10, requests: 9);

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync($"/api/v1/system/tenants/{slug}/usage?from=2026-09-01&to=2026-09-01");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var bucket = Assert.Single(doc.RootElement.GetProperty("series").EnumerateArray());
        Assert.Equal(4L, bucket.GetProperty("requestCount").GetInt64());
        Assert.Equal(9L, bucket.GetProperty("metadataRequestCount").GetInt64());
        var mtd = doc.RootElement.GetProperty("monthToDate");
        Assert.True(mtd.TryGetProperty("requestCount", out _));
        Assert.True(mtd.TryGetProperty("metadataRequestCount", out _));
    }

    [Fact]
    public async Task Per_tenant_hourly_series_carries_request_counts()
    {
        var (orgId, slug, _, _, _) = await CreateTenantAsync();
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO usage_hourly (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
                VALUES (@orgId, 'egress_bytes', '2026-09-01T10:00:00Z', 100, 0, 6, '2026-09-01T11:00:00Z')
                """,
                new { orgId });
        }

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync($"/api/v1/system/tenants/{slug}/usage?granularity=hour&from=2026-09-01&to=2026-09-01");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var bucket = Assert.Single(doc.RootElement.GetProperty("series").EnumerateArray());
        Assert.Equal(6L, bucket.GetProperty("requestCount").GetInt64());
        Assert.Equal(0L, bucket.GetProperty("metadataRequestCount").GetInt64());
    }

    [Fact]
    public async Task Per_tenant_hour_granularity_caps_the_requested_range()
    {
        var (_, slug, _, _, _) = await CreateTenantAsync();
        using var client = await _factory.CreateSystemAdminClient();

        var tooLong = await client.GetAsync(
            $"/api/v1/system/tenants/{slug}/usage?granularity=hour&from=2026-01-01&to=2026-09-01");
        Assert.Equal(HttpStatusCode.UnprocessableEntity, tooLong.StatusCode);

        var ok = await client.GetAsync(
            $"/api/v1/system/tenants/{slug}/usage?granularity=hour&from=2026-09-01&to=2026-09-05");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var doc = JsonDocument.Parse(await ok.Content.ReadAsStringAsync());
        Assert.Equal("hour", doc.RootElement.GetProperty("granularity").GetString());
    }

    [Fact]
    public async Task Per_tenant_response_includes_latest_snapshot_and_month_to_date_summary()
    {
        var (orgId, slug, _, _, _) = await CreateTenantAsync();
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO storage_snapshot (org_id, day_utc, hosted_bytes, oci_uploaded_bytes, cache_attributed_bytes, billable_bytes, captured_at)
                VALUES (@orgId, '2026-09-02', 111, 222, 333, 444, '2026-09-02T00:00:00Z')
                """,
                new { orgId });
        }

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync($"/api/v1/system/tenants/{slug}/usage?from=2026-09-01&to=2026-09-02");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var snapshot = doc.RootElement.GetProperty("latestSnapshot");
        Assert.Equal(444L, snapshot.GetProperty("billableBytes").GetInt64());
        // Written without the count columns, as the previous release's capture does: they read 0.
        Assert.Equal(0L, snapshot.GetProperty("dbRowCount").GetInt64());
        Assert.Equal(0L, snapshot.GetProperty("artifactCount").GetInt64());
        Assert.True(doc.RootElement.TryGetProperty("monthToDate", out var mtd));
        Assert.True(mtd.TryGetProperty("egressBytes", out _));
    }
}
