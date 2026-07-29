using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// GDPR Art. 15 (access) / Art. 20 (portability) self-service export at
/// <c>GET /api/v1/users/me/export</c>.
///
/// <para>
/// The surface is BOLA-sensitive: it aggregates a subject's personal data from eleven tables, so
/// the tests pair every "the subject's own rows are present" probe with its adversarial twin —
/// a second subject in the same org, and a subject in another org, whose rows must appear nowhere
/// in the export. The scoping proof (see <see cref="Export_LeaksNoOtherSubjectsRows"/>) is what
/// fails if the per-user filter is removed from the aggregation queries.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class PersonalDataExportTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public PersonalDataExportTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Export_IncludesARowFromEveryCoveredTable_ForTheCallerOnly()
    {
        var subject = await SeedSubjectAsync("subject-a@example.com", "AAA");

        using var doc = await GetExportAsync(subject);
        var root = doc.RootElement;

        // Completeness (Art. 15): every covered table is present and carries the subject's row(s).
        Assert.Equal(subject.UserId, root.GetProperty("user").GetProperty("id").GetString());
        Assert.Equal("subject-a@example.com", root.GetProperty("user").GetProperty("email").GetString());

        AssertNonEmpty(root, "userTokens");
        AssertNonEmpty(root, "passwordResetTokens");
        AssertNonEmpty(root, "externalIdentities");
        AssertNonEmpty(root, "mfaTrustedDevices");
        AssertNonEmpty(root, "bannerDismissals");
        AssertNonEmpty(root, "invitesCreated");
        AssertNonEmpty(root, "invitesReceived");
        AssertNonEmpty(root, "auditLog");
        AssertNonEmpty(root, "activity");
        AssertNonEmpty(root, "auditEvents");
        Assert.Equal(JsonValueKind.Object, root.GetProperty("loginAttempts").ValueKind);

        // The subject's unique marker appears (proves the rows are really theirs, not a shell).
        string body = root.GetRawText();
        Assert.Contains(subject.Marker, body);

        // Secret material is never exported.
        Assert.DoesNotContain("password_hash", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("passwordHash", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tokenHash", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("securityStamp", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(subject.SecretTokenHash, body);
    }

    /// <summary>
    /// Adversarial twin: a second subject in the SAME org and a third subject in ANOTHER org each
    /// seed the full row set. Neither one's data may appear in the caller's export. If the per-user
    /// scoping is dropped from the aggregation queries, the same-org subject's rows leak here — that
    /// is the regression this test exists to catch.
    /// </summary>
    [Fact]
    public async Task Export_LeaksNoOtherSubjectsRows()
    {
        var caller = await SeedSubjectAsync("caller@example.com", "CALLER");
        var sameOrgOther = await SeedSubjectAsync("same-org-other@example.com", "SAMEORGOTHER");
        var otherOrg = await SeedSubjectInNewOrgAsync("other-org@example.com", "OTHERORG", "rival-org");

        using var doc = await GetExportAsync(caller);
        string body = doc.RootElement.GetRawText();

        Assert.Contains(caller.Marker, body);

        // Same-org second subject: user-scoping must exclude every one of their markers.
        Assert.DoesNotContain(sameOrgOther.Marker, body);
        Assert.DoesNotContain(sameOrgOther.UserId, body);
        Assert.DoesNotContain("same-org-other@example.com", body);

        // Cross-org subject: org-scoping must exclude them entirely.
        Assert.DoesNotContain(otherOrg.Marker, body);
        Assert.DoesNotContain(otherOrg.UserId, body);
        Assert.DoesNotContain("other-org@example.com", body);
    }

    [Fact]
    public async Task Export_Unauthenticated_Returns401()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/v1/users/me/export");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private async Task<JsonDocument> GetExportAsync(SeededSubject subject)
    {
        string jwt = await _factory.CreateUserJwt(subject.UserId, "member");
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/users/me/export");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
    }

    private static void AssertNonEmpty(JsonElement root, string property)
    {
        var el = root.GetProperty(property);
        Assert.Equal(JsonValueKind.Array, el.ValueKind);
        Assert.True(el.GetArrayLength() > 0, $"expected '{property}' to contain the subject's row(s).");
    }

    private sealed record SeededSubject(string UserId, string OrgId, string Email, string Marker, string SecretTokenHash);

    private async Task<SeededSubject> SeedSubjectAsync(string email, string marker)
    {
        string userId = await _factory.CreateUser(email, "Sup3r-Str0ng-Pw!");
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("default org missing");
        return await SeedRowsAsync(conn, userId, orgId, email, marker);
    }

    private async Task<SeededSubject> SeedSubjectInNewOrgAsync(string email, string marker, string slug)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string orgId = "org-" + marker.ToLowerInvariant();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@orgId, @slug)", new { orgId, slug });
        string userId = "user-" + marker.ToLowerInvariant();
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@userId, @orgId, @email, 'x', 'member')",
            new { userId, orgId, email });
        return await SeedRowsAsync(conn, userId, orgId, email, marker);
    }

    // Seeds one row into every table the export covers, all stamped with the subject's unique
    // marker so cross-subject leakage is detectable in the serialized body.
    private static async Task<SeededSubject> SeedRowsAsync(
        System.Data.Common.DbConnection conn, string userId, string orgId, string email, string marker)
    {
        string secretTokenHash = $"secret-token-hash-{marker}";

        await conn.ExecuteAsync(
            "INSERT INTO user_tokens (id, org_id, user_id, token_hash, description) VALUES (@id, @orgId, @userId, @hash, @desc)",
            new { id = $"tok-{marker}", orgId, userId, hash = secretTokenHash, desc = $"desc-{marker}" });

        await conn.ExecuteAsync(
            "INSERT INTO password_reset_tokens (id, user_id, org_id, token_hash, expires_at) VALUES (@id, @userId, @orgId, @hash, '2999-01-01T00:00:00Z')",
            new { id = $"prt-{marker}", userId, orgId, hash = $"prt-hash-{marker}" });

        await conn.ExecuteAsync(
            "INSERT INTO external_identities (id, org_id, user_id, idp_entity_id, nameid, email_snapshot) VALUES (@id, @orgId, @userId, @idp, @nameid, @snap)",
            new { id = $"ext-{marker}", orgId, userId, idp = $"idp-{marker}", nameid = $"nameid-{marker}", snap = email });

        await conn.ExecuteAsync(
            "INSERT INTO mfa_trusted_devices (id, user_id, realm, tenant_id, token_hash, user_agent, expires_at) VALUES (@id, @userId, 'tenant', @orgId, @hash, @ua, '2999-01-01T00:00:00Z')",
            new { id = $"mfa-{marker}", userId, orgId, hash = $"mfa-hash-{marker}", ua = $"agent-{marker}" });

        await conn.ExecuteAsync(
            "INSERT INTO banners (id, scope, org_id, body, starts_at, ends_at) VALUES (@id, 'tenant', @orgId, 'b', '2000-01-01T00:00:00Z', '2999-01-01T00:00:00Z')",
            new { id = $"banner-{marker}", orgId });
        await conn.ExecuteAsync(
            "INSERT INTO banner_dismissals (banner_id, user_id) VALUES (@bid, @userId)",
            new { bid = $"banner-{marker}", userId });

        // Invite the subject created (created_by = subject).
        await conn.ExecuteAsync(
            "INSERT INTO invites (id, org_id, email, token_hash, created_by, expires_at) VALUES (@id, @orgId, @invitee, @hash, @userId, '2999-01-01T00:00:00Z')",
            new { id = $"inv-created-{marker}", orgId, invitee = $"invitee-{marker}@example.com", hash = $"inv-created-hash-{marker}", userId });
        // Invite addressed to the subject (email = subject), created by someone else.
        await conn.ExecuteAsync(
            "INSERT INTO invites (id, org_id, email, token_hash, created_by, expires_at) VALUES (@id, @orgId, @email, @hash, @userId, '2999-01-01T00:00:00Z')",
            new { id = $"inv-recv-{marker}", orgId, email, hash = $"inv-recv-hash-{marker}", userId });

        await conn.ExecuteAsync(
            "INSERT INTO audit_log (id, scope, org_id, actor_id, actor_kind, action, source_ip) VALUES (@id, 'tenant', @orgId, @userId, 'user', @action, @ip)",
            new { id = $"aud-{marker}", orgId, userId, action = $"action.{marker}", ip = $"10.1.1.{marker.Length}" });

        await conn.ExecuteAsync(
            "INSERT INTO activity (id, org_id, ecosystem, event_type, actor_id, actor_kind, source_ip) VALUES (@id, @orgId, 'auth', 'login.success', @userId, 'user', @ip)",
            new { id = $"act-{marker}", orgId, userId, ip = $"10.2.2.{marker.Length}" });

        await conn.ExecuteAsync(
            "INSERT INTO audit_event (event_id, event_type, org_id, tenant_resolver, actor_type, actor_id, source_ip, user_agent, outcome, payload) " +
            "VALUES (@id, @etype, @orgId, 'single', 'user', @userId, @ip, @ua, 'accepted', @payload)",
            new { id = $"aev-{marker}", etype = $"event.{marker}", orgId, userId, ip = $"10.3.3.{marker.Length}", ua = $"aev-agent-{marker}", payload = $"{{\"m\":\"{marker}\"}}" });

        // login_attempts is keyed by the tenant-scoped lockout pseudonym, exactly as the export
        // recomputes it from the subject's realm/tenant/email.
        string loginKey = LoginService.HashLockoutKey("tenant", orgId, email);
        await conn.ExecuteAsync(
            "INSERT INTO login_attempts (email_hash, failed_count, last_attempt) VALUES (@hash, 3, '2024-01-01T00:00:00Z')",
            new { hash = loginKey });

        return new SeededSubject(userId, orgId, email, marker, secretTokenHash);
    }
}
