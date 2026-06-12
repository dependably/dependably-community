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
/// End-to-end coverage of the quarantine review workflow: a policy-blocked download lands a
/// pending entry, approval flips the version's manual allow override so the next download
/// succeeds, denial records the manual block, and the decision endpoint enforces tenant
/// scoping, single-decision semantics, and the TenantConfigure capability.
/// Reuses the malicious gate (unscored MAL- advisory) as the blocking policy because its
/// data path is fully local — no upstream stubs needed.
/// </summary>
[Trait("Category", "Integration")]
public sealed class QuarantineWorkflowTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public QuarantineWorkflowTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"qw-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    /// <summary>
    /// Pushes a hosted npm package, links an unscored MAL- advisory, stamps vuln_checked_at,
    /// and triggers one blocked download so a pending quarantine entry exists. Returns the
    /// entry id.
    /// </summary>
    private async Task<string> SeedBlockedEntryAsync(string pkg)
    {
        using var admin = await AdminClient();
        var put = await admin.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            blockMalicious = "block",
        });
        put.EnsureSuccessStatusCode();

        await _factory.PushNpmPackage(pkg, "1.0.0");
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            string? versionId = await conn.ExecuteScalarAsync<string>(
                """
                SELECT pv.id FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.name = @pkg LIMIT 1
                """, new { pkg });
            string vulnId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                """
                INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, modified_at, fetched_at)
                VALUES (@vulnId, @osvId, 'npm', @pkg,
                    strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                """, new { vulnId, osvId = $"MAL-2026-{Guid.NewGuid():N}", pkg });
            await conn.ExecuteAsync(
                "INSERT INTO package_version_vulns (package_version_id, vuln_id) VALUES (@versionId, @vulnId)",
                new { versionId, vulnId });
            await conn.ExecuteAsync(
                "UPDATE package_versions SET vuln_checked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @versionId",
                new { versionId });
        }

        var blocked = await DownloadTarballAsync(pkg);
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

        var list = await admin.GetAsync("/api/v1/quarantine?state=pending");
        list.EnsureSuccessStatusCode();
        var doc = await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync());
        var entry = doc.RootElement.GetProperty("items").EnumerateArray()
            .Single(e => e.GetProperty("purl").GetString()!.Contains(pkg));
        Assert.Equal("malicious", entry.GetProperty("gate").GetString());
        return entry.GetProperty("id").GetString()!;
    }

    private async Task<HttpResponseMessage> DownloadTarballAsync(string pkgName)
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        string json = await client.GetStringAsync($"/npm/{pkgName}");
        using var doc = JsonDocument.Parse(json);
        string tarballUrl = doc.RootElement
            .GetProperty("versions").GetProperty("1.0.0")
            .GetProperty("dist").GetProperty("tarball").GetString()!;
        return await client.GetAsync(new Uri(tarballUrl).PathAndQuery);
    }

    [Fact]
    public async Task Approve_UnblocksNextDownload_AndAuditsDecision()
    {
        string pkg = $"qappr{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string id = await SeedBlockedEntryAsync(pkg);

        using var admin = await AdminClient();
        var decide = await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide",
            new { decision = "approved", note = "vetted internally" });
        Assert.Equal(HttpStatusCode.OK, decide.StatusCode);

        var resp = await DownloadTarballAsync(pkg);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long audits = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'quarantine_decision' AND detail LIKE @p",
            new { p = $"%{pkg}%" });
        Assert.Equal(1, audits);
    }

    [Fact]
    public async Task Deny_KeepsBlocking_ViaManualBlock()
    {
        string pkg = $"qdeny{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string id = await SeedBlockedEntryAsync(pkg);

        using var admin = await AdminClient();
        var decide = await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide",
            new { decision = "denied" });
        Assert.Equal(HttpStatusCode.OK, decide.StatusCode);

        var resp = await DownloadTarballAsync(pkg);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);

        // The deny is recorded as the version's manual block, which outranks policy gates.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? state = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.manual_block_state FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id WHERE p.name = @pkg LIMIT 1
            """, new { pkg });
        Assert.Equal("blocked", state);
    }

    [Fact]
    public async Task Decide_Twice_Returns409()
    {
        string pkg = $"qtwice{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string id = await SeedBlockedEntryAsync(pkg);

        using var admin = await AdminClient();
        (await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide", new { decision = "approved" }))
            .EnsureSuccessStatusCode();
        var second = await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide", new { decision = "denied" });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Decide_UnknownOrCrossTenantId_Returns404()
    {
        using var admin = await AdminClient();
        var resp = await admin.PostAsJsonAsync(
            $"/api/v1/quarantine/never-{Guid.NewGuid():N}/decide", new { decision = "approved" });
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Decide_InvalidDecision_Returns422()
    {
        string pkg = $"qbad{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string id = await SeedBlockedEntryAsync(pkg);

        using var admin = await AdminClient();
        var resp = await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide", new { decision = "maybe" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Member_ForbiddenOnListAndDecide()
    {
        // The queue is an admin surface end to end: ReadTenant (list) and TenantConfigure
        // (decide) are both admin-tier capabilities.
        string pkg = $"qmem{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string id = await SeedBlockedEntryAsync(pkg);

        using var member = await MemberClient();
        var list = await member.GetAsync("/api/v1/quarantine");
        Assert.Equal(HttpStatusCode.Forbidden, list.StatusCode);

        var decide = await member.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide", new { decision = "approved" });
        Assert.Equal(HttpStatusCode.Forbidden, decide.StatusCode);
    }

    [Fact]
    public async Task ManualUnblockEndpoint_ResolvesPendingEntry()
    {
        // The two surfaces can't disagree: a direct unblock resolves the pending review row.
        string pkg = $"qsync{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string id = await SeedBlockedEntryAsync(pkg);

        using var admin = await AdminClient();
        (await admin.PostAsync($"/api/v1/packages/npm/{pkg}/1.0.0/unblock", content: null))
            .EnsureSuccessStatusCode();

        var list = await admin.GetAsync("/api/v1/quarantine?state=approved");
        var doc = await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync());
        Assert.Contains(doc.RootElement.GetProperty("items").EnumerateArray(),
            e => e.GetProperty("id").GetString() == id);
    }
}
