using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of the quarantine review workflow: a policy-blocked download lands a
/// pending entry, approval flips the version's manual allow override so the next download
/// succeeds, denial records the manual block, a decided entry can be re-decided or reset to
/// pending (the change-my-mind path), and the decision endpoint enforces tenant scoping and
/// the TenantConfigure capability.
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
            string pvvId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                "INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind) VALUES (@pvvId, @versionId, @vulnId, 'package_version')",
                new { pvvId, versionId, vulnId });
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

        // Construct the tarball URL directly — blocked versions are absent from the packument
        // after block-gate filtering, so reading tarball from the packument would fail.
        string tarballPath = $"/npm/tarballs/{pkgName}/{pkgName}-1.0.0.tgz";
        return await client.GetAsync(tarballPath);
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
    public async Task Redecide_ApprovedToDenied_FlipsManualBlock_AndReblocks()
    {
        // The change-my-mind path: an approved entry can be re-decided as denied, which flips
        // the version's manual override from allow to block and re-blocks the next download.
        string pkg = $"qflip{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string id = await SeedBlockedEntryAsync(pkg);

        using var admin = await AdminClient();
        (await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide", new { decision = "approved" }))
            .EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.OK, (await DownloadTarballAsync(pkg)).StatusCode);

        var flip = await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide", new { decision = "denied" });
        Assert.Equal(HttpStatusCode.OK, flip.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await DownloadTarballAsync(pkg)).StatusCode);

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
    public async Task Reset_ToPending_ClearsOverride_AndDecisionMetadata()
    {
        // Resetting a decided entry to pending clears the version override and wipes the row's
        // decision metadata so it re-enters the queue clean — and the gate blocks again.
        string pkg = $"qreset{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string id = await SeedBlockedEntryAsync(pkg);

        using var admin = await AdminClient();
        (await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide",
            new { decision = "approved", note = "vetted internally" })).EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.OK, (await DownloadTarballAsync(pkg)).StatusCode);

        var reset = await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide", new { decision = "pending" });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);

        // The override is cleared, so the malicious gate blocks the next download again.
        Assert.Equal(HttpStatusCode.Forbidden, (await DownloadTarballAsync(pkg)).StatusCode);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? manual = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.manual_block_state FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id WHERE p.name = @pkg LIMIT 1
            """, new { pkg });
        Assert.Null(manual);

        var row = await conn.QuerySingleAsync(
            "SELECT state, decided_by AS DecidedBy, decided_at AS DecidedAt, note FROM quarantine WHERE id = @id",
            new { id });
        Assert.Equal("pending", (string)row.state);
        Assert.Null(row.DecidedBy);
        Assert.Null(row.DecidedAt);
        Assert.Null(row.note);
    }

    [Fact]
    public async Task Redecide_SameState_IsNoOp_Returns200()
    {
        string pkg = $"qnoop{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string id = await SeedBlockedEntryAsync(pkg);

        using var admin = await AdminClient();
        (await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide", new { decision = "denied" }))
            .EnsureSuccessStatusCode();
        var again = await admin.PostAsJsonAsync($"/api/v1/quarantine/{id}/decide", new { decision = "denied" });
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
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

/// <summary>
/// Integration tests for the release-age auto-purge at list time. A separate fixture class
/// with a frozen host clock so the age arithmetic is deterministic.
/// </summary>
[Trait("Category", "Integration")]
public sealed class QuarantineReleaseAgePurgeTests : IAsyncLifetime
{
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    /// <summary>
    /// End-to-end proof that the LIST endpoint omits an aged-out release_age entry while
    /// keeping a still-young one. This is the mixed partial-failure scenario for the lazy
    /// purge: the GET /api/v1/quarantine call must delete the aged row before returning, so
    /// the response total and items count reflect the post-purge state.
    /// </summary>
    [Fact]
    public async Task List_AgedOutReleaseAge_IsOmitted_YoungEntryIsRetained()
    {
        using var admin = await AdminClient();

        // Enable release-age hold of 24 hours.
        (await admin.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            minReleaseAgeHours = 24,
        })).EnsureSuccessStatusCode();

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        string orgId = (await orgs.GetBySlugAsync("default"))!.Id;

        // Seed two npm packages and stamp their published_at values.
        // agedpkg: published 50 hours before frozen-now — aged out (past the 24h hold).
        // youngpkg: published 1 hour before frozen-now — still held.
        string agedPkg = $"qpurge-aged-{Guid.NewGuid():N}"[..28].ToLowerInvariant();
        string youngPkg = $"qpurge-young-{Guid.NewGuid():N}"[..28].ToLowerInvariant();

        await _factory.PushNpmPackage(agedPkg, "1.0.0");
        await _factory.PushNpmPackage(youngPkg, "1.0.0");

        string agedTs = TestTime.KnownNow.AddHours(-50).ToString("o");
        string youngTs = TestTime.KnownNow.AddHours(-1).ToString("o");

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                UPDATE package_versions SET published_at = @ts
                WHERE id = (
                    SELECT pv.id FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.name = @name LIMIT 1)
                """,
                new { ts = agedTs, name = agedPkg });
            await conn.ExecuteAsync(
                """
                UPDATE package_versions SET published_at = @ts
                WHERE id = (
                    SELECT pv.id FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.name = @name LIMIT 1)
                """,
                new { ts = youngTs, name = youngPkg });
        }

        // Directly seed pending release_age quarantine rows so we don't need to trigger an
        // actual blocked download (the release-age gate only fires on proxy-fetched versions).
        var quarantine = _factory.Services.GetRequiredService<QuarantineRepository>();
        string agedPurl = $"pkg:npm/{agedPkg}@1.0.0";
        string youngPurl = $"pkg:npm/{youngPkg}@1.0.0";

        string? agedVerId;
        string? youngVerId;
        await using (var conn = await store.OpenAsync())
        {
            agedVerId = await conn.ExecuteScalarAsync<string>(
                """
                SELECT pv.id FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.name = @name LIMIT 1
                """, new { name = agedPkg });
            youngVerId = await conn.ExecuteScalarAsync<string>(
                """
                SELECT pv.id FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.name = @name LIMIT 1
                """, new { name = youngPkg });
        }

        await quarantine.UpsertPendingAsync(orgId, "npm", agedPurl, "release_age", null, agedVerId);
        await quarantine.UpsertPendingAsync(orgId, "npm", youngPurl, "release_age", null, youngVerId);

        // GET /api/v1/quarantine?state=pending — the aged-out entry must be purged before the
        // response is built; the young entry must still be present.
        var resp = await admin.GetAsync("/api/v1/quarantine?state=pending");
        resp.EnsureSuccessStatusCode();
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var items = doc.RootElement.GetProperty("items").EnumerateArray().ToList();

        Assert.DoesNotContain(items, e => e.GetProperty("purl").GetString() == agedPurl);
        Assert.Contains(items, e => e.GetProperty("purl").GetString() == youngPurl);
    }
}
