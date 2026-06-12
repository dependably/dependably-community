using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class ClaimsControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public ClaimsControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    [Fact]
    public async Task Anonymous_Get_Returns401Or404()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/admin/claims");
        Assert.True(resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound);
    }

    /// <summary>
    /// Pins the access decision for the claims read endpoints: the whole claims admin
    /// surface (reads included) requires claim:manage. A member holds read:claims but not
    /// claim:manage, so List and Get are 403 — the [RequireCapability] attribute and the
    /// inner AuthorizeAsync check enforce the same requirement.
    /// </summary>
    [Fact]
    public async Task ListAndGet_MemberWithoutClaimManage_Returns403()
    {
        string userId = await _factory.CreateUser($"claims-member-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(userId, "member");
        using var c = _factory.CreateClientWithBearer(jwt);

        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/api/v1/admin/claims")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/api/v1/admin/claims/npm/some-package")).StatusCode);
    }

    [Fact]
    public async Task Create_LocalOnly_ReturnsCreatedWithPurgesProxy()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/admin/claims", new
        {
            ecosystem = "npm",
            name = "acme-claim-create",
            state = "local_only",
            reason = "internal"
        });
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(doc.GetProperty("purgesProxy").GetBoolean());
        Assert.Equal("local_only", doc.GetProperty("claim").GetProperty("state").GetString());
    }

    [Fact]
    public async Task Create_DuplicateName_409()
    {
        using var c = await AdminClient();
        var body = new { ecosystem = "npm", name = "acme-claim-dup", state = "local_only", reason = "init" };
        var first = await c.PostAsJsonAsync("/api/v1/admin/claims", body);
        first.EnsureSuccessStatusCode();

        var second = await c.PostAsJsonAsync("/api/v1/admin/claims", body);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Create_InvalidState_400()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/admin/claims", new
        {
            ecosystem = "npm",
            name = "acme-claim-bad",
            state = "unclaimed",
            reason = "x"
        });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Transition_LocalOnlyToMixed_Allows()
    {
        using var c = await AdminClient();
        var create = await c.PostAsJsonAsync("/api/v1/admin/claims", new
        {
            ecosystem = "npm",
            name = "acme-claim-transition",
            state = "local_only",
            reason = "init"
        });
        create.EnsureSuccessStatusCode();

        var resp = await c.PatchAsJsonAsync("/api/v1/admin/claims/npm/acme-claim-transition",
            new { state = "mixed", reason = "want fallback" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("mixed", doc.GetProperty("claim").GetProperty("state").GetString());
        Assert.False(doc.GetProperty("purgesProxy").GetBoolean());
    }

    [Fact]
    public async Task Transition_NonExistent_404()
    {
        using var c = await AdminClient();
        var resp = await c.PatchAsJsonAsync("/api/v1/admin/claims/npm/ghost-claim",
            new { state = "mixed", reason = "x" });
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Release_NoLocalVersions_NoContent()
    {
        using var c = await AdminClient();
        var create = await c.PostAsJsonAsync("/api/v1/admin/claims", new
        {
            ecosystem = "npm",
            name = "acme-claim-release",
            state = "local_only",
            reason = "init"
        });
        create.EnsureSuccessStatusCode();

        var resp = await c.DeleteAsync("/api/v1/admin/claims/npm/acme-claim-release?reason=cleanup");
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        // Subsequent GET resolves to implicit unclaimed (connected mode default).
        var get = await c.GetAsync("/api/v1/admin/claims/npm/acme-claim-release");
        get.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("unclaimed", doc.GetProperty("state").GetString());
        Assert.True(doc.GetProperty("isImplicit").GetBoolean());
    }

    [Fact]
    public async Task CreateClaim_EmitsTypedClaimCreateEventInAuditEventTable()
    {
        // claim.create lands in audit_event with typed shape, alongside the legacy
        // audit_log dual-write. The supply-chain reviewer queries the typed table directly —
        // we used to read it through /api/v1/admin/audit-events, but that endpoint was
        // unused-and-redundant with /api/v1/siem/events/auth and got removed.
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/admin/claims", new
        {
            ecosystem = "npm",
            name = "acme-claim-typed",
            state = "local_only",
            reason = "audit test"
        });
        resp.EnsureSuccessStatusCode();

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        string? payload = await conn.ExecuteScalarAsync<string?>(
            "SELECT payload FROM audit_event WHERE event_type = 'claim.create' " +
            "AND payload LIKE @needle ORDER BY occurred_at DESC LIMIT 1",
            new { needle = "%acme-claim-typed%" });
        Assert.NotNull(payload);

        var doc = JsonDocument.Parse(payload!).RootElement;
        Assert.Equal("npm", doc.GetProperty("ecosystem").GetString());
        Assert.Equal("local_only", doc.GetProperty("state").GetString());
        Assert.True(doc.GetProperty("purges_proxy").GetBoolean());   // local_only → purge
    }

    [Fact]
    public async Task List_FiltersByState()
    {
        using var c = await AdminClient();
        await c.PostAsJsonAsync("/api/v1/admin/claims", new
        {
            ecosystem = "npm",
            name = "acme-list-local",
            state = "local_only",
            reason = "x"
        });
        await c.PostAsJsonAsync("/api/v1/admin/claims", new
        {
            ecosystem = "npm",
            name = "acme-list-mixed",
            state = "mixed",
            reason = "x"
        });

        var resp = await c.GetAsync("/api/v1/admin/claims?ecosystem=npm&state=mixed");
        resp.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        var items = doc.GetProperty("items").EnumerateArray().ToList();
        Assert.Contains(items, x => x.GetProperty("name").GetString() == "acme-list-mixed");
        Assert.DoesNotContain(items, x => x.GetProperty("name").GetString() == "acme-list-local");
    }

    // ── local_only purge actually evicts proxy artefacts ─────────────────────
    // The state-machine flag has always reported purgesProxy=true; this test exists to
    // catch a regression where the side-effect path stops running. Imported / private
    // versions for an unrelated package are seeded so the purge is verifiably scoped.

    [Fact]
    public async Task CreateLocalOnly_PurgesProxyVersionsAndBlobsForName()
    {
        using var c = await AdminClient();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();

        // Seed: two proxy versions of acme-purge-target plus one private version of
        // acme-purge-bystander whose blobs must NOT be touched.
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = (await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
            await conn.ExecuteAsync("""
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, created_at)
                VALUES ('p-target', @orgId, 'npm', 'acme-purge-target', 'acme-purge-target', 1,
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, created_at)
                VALUES ('p-bystander', @orgId, 'npm', 'acme-purge-bystander', 'acme-purge-bystander', 0,
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                """, new { orgId });

            await conn.ExecuteAsync("""
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, first_fetch, origin)
                VALUES ('v-proxy-1', 'p-target', '1.0.0', 'pkg:npm/acme-purge-target@1.0.0',
                        'proxy/sha256/aaa', 100, 'aaa',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'proxy');
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, first_fetch, origin)
                VALUES ('v-proxy-2', 'p-target', '2.0.0', 'pkg:npm/acme-purge-target@2.0.0',
                        'proxy/sha256/bbb', 100, 'bbb',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'proxy');
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, first_fetch, origin)
                VALUES ('v-private', 'p-bystander', '1.0.0', 'pkg:npm/acme-purge-bystander@1.0.0',
                        'hosted/private/ccc', 100, 'ccc',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'uploaded');
                """);
        }

        await _factory.BlobStore.PutAsync("proxy/sha256/aaa", new MemoryStream([1, 2, 3]));
        await _factory.BlobStore.PutAsync("proxy/sha256/bbb", new MemoryStream([4, 5, 6]));
        await _factory.BlobStore.PutAsync("hosted/private/ccc", new MemoryStream([7, 8, 9]));

        // Act: create the local_only claim.
        var resp = await c.PostAsJsonAsync("/api/v1/admin/claims", new
        {
            ecosystem = "npm",
            name = "acme-purge-target",
            state = "local_only",
            reason = "purge test"
        });
        resp.EnsureSuccessStatusCode();
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(body.GetProperty("purgesProxy").GetBoolean());
        Assert.Equal(2, body.GetProperty("purgedCount").GetInt32());

        // Proxy rows are gone; private bystander is untouched.
        await using (var verify = await store.OpenAsync())
        {
            long remaining = await verify.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM package_versions WHERE package_id = 'p-target'");
            Assert.Equal(0, remaining);

            long bystander = await verify.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM package_versions WHERE id = 'v-private'");
            Assert.Equal(1, bystander);

            long historyPurged = await verify.ExecuteScalarAsync<long>(
                "SELECT purged_count FROM claim_history WHERE name = 'acme-purge-target' ORDER BY occurred_at DESC LIMIT 1");
            Assert.Equal(2, historyPurged);
        }

        // Proxy blobs gone; private blob retained.
        Assert.False(await _factory.BlobStore.ExistsAsync("proxy/sha256/aaa"));
        Assert.False(await _factory.BlobStore.ExistsAsync("proxy/sha256/bbb"));
        Assert.True(await _factory.BlobStore.ExistsAsync("hosted/private/ccc"));
    }

    [Fact]
    public async Task TransitionMixedToLocalOnly_PurgesProxyVersions()
    {
        using var c = await AdminClient();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();

        // Start in mixed (no purge on create); proxy version persists.
        var create = await c.PostAsJsonAsync("/api/v1/admin/claims", new
        {
            ecosystem = "npm",
            name = "acme-mixed-transition",
            state = "mixed",
            reason = "init"
        });
        create.EnsureSuccessStatusCode();

        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = (await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
            await conn.ExecuteAsync("""
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, created_at)
                VALUES ('p-mixed', @orgId, 'npm', 'acme-mixed-transition', 'acme-mixed-transition', 1,
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, first_fetch, origin)
                VALUES ('v-mixed', 'p-mixed', '1.0.0', 'pkg:npm/acme-mixed-transition@1.0.0',
                        'proxy/sha256/ddd', 100, 'ddd',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'proxy');
                """, new { orgId });
        }
        await _factory.BlobStore.PutAsync("proxy/sha256/ddd", new MemoryStream([1, 2, 3]));

        // Transition mixed → local_only. PurgesProxy=true on this edge.
        var resp = await c.PatchAsJsonAsync("/api/v1/admin/claims/npm/acme-mixed-transition",
            new { state = "local_only", reason = "lock down" });
        resp.EnsureSuccessStatusCode();
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(body.GetProperty("purgesProxy").GetBoolean());
        Assert.Equal(1, body.GetProperty("purgedCount").GetInt32());
        Assert.False(await _factory.BlobStore.ExistsAsync("proxy/sha256/ddd"));
    }
}
