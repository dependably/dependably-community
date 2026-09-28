using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit;

/// <summary>
/// The startup convergence that backfills <c>upstream_credential_history</c> from the upstream
/// rows present at boot: credentialed upstreams written before the table existed, or by a
/// previous release during a blue-green cutover, are recorded, so deleting them afterwards does
/// not make the org's proxied objects edge-cacheable. Anonymous-only orgs get no row. Upstreams
/// that were added and deleted before the table existed are found through their
/// <c>upstream_registry_added</c> audit events.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamCredentialHistoryConvergenceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    private SchemaInitializer Initializer() => new(_db, time: _clock);

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private UpstreamRegistryRepository Repo() => new(_db, TimeProvider.System, TestEnvelope.Configured());

    /// <summary>An upstream row as a writer that records no history leaves it.</summary>
    private async Task InsertRawAsync(string orgId, string ecosystem, string url, string authType, string? username, string? secret)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, username, secret)
            VALUES (@id, @orgId, @ecosystem, @url, 9, @authType, @username, @secret)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, ecosystem, url, authType, username, secret });
    }

    /// <summary>An <c>upstream_registry_added</c> audit row, as the management API writes it.</summary>
    private async Task InsertAuditAddAsync(string orgId, string? detail, int daysAgo = 1)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, action, detail, created_at)
            VALUES (@id, 'tenant', @orgId, 'upstream_registry_added', @detail, @createdAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                detail,
                createdAt = _clock.GetUtcNow().AddDays(-daysAgo).ToUtcIso(),
            });
    }

    private async Task<List<(string OrgId, string Ecosystem)>> HistoryAsync()
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.QueryAsync<(string, string)>(
            "SELECT org_id, ecosystem FROM upstream_credential_history ORDER BY org_id, ecosystem")).ToList();
    }

    [Fact]
    public async Task Boot_RecordsPreExistingCredentialedUpstreams_AndNothingForAnonymousOnes()
    {
        await Initializer().InitializeAsync();
        string tainted = await OrgSeeder.InsertAsync(_db, "tainted");
        string clean = await OrgSeeder.InsertAsync(_db, "clean");
        await InsertRawAsync(tainted, "npm", "https://registry.npmjs.org", "anonymous", null, null);
        await InsertRawAsync(tainted, "npm", "https://npm.private.example", "bearer", null, "legacy-plaintext");
        await InsertRawAsync(tainted, "oci", "registry.private.example", "basic", "robot", "legacy-plaintext");
        await InsertRawAsync(tainted, "pypi", "https://pypi.org", "anonymous", null, null);
        await InsertRawAsync(clean, "npm", "https://registry.npmjs.org", "anonymous", null, null);
        await InsertRawAsync(clean, "oci", "registry-1.docker.io", "dockerhub_token_exchange", null, null);
        Assert.Empty(await HistoryAsync());

        await Initializer().InitializeAsync();

        Assert.Equal([(tainted, "npm"), (tainted, "oci")], await HistoryAsync());
    }

    [Fact]
    public async Task BackfilledUpstream_DeletedAfterBoot_KeepsTheOrgPrivate()
    {
        await Initializer().InitializeAsync();
        string org = await OrgSeeder.InsertAsync(_db, "org");
        await InsertRawAsync(org, "npm", "https://registry.npmjs.org", "anonymous", null, null);
        await InsertRawAsync(org, "npm", "https://npm.private.example", "bearer", null, "legacy-plaintext");

        await Initializer().InitializeAsync();
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM upstream_registry WHERE org_id = @org AND url = 'https://npm.private.example'", new { org });
        }

        Assert.False(await Repo().AllUpstreamsCredentialFreeAsync(org, "npm"));
    }

    [Fact]
    public async Task Boot_IsIdempotent_AndKeepsTheFirstSighting()
    {
        await Initializer().InitializeAsync();
        string org = await OrgSeeder.InsertAsync(_db, "org");
        await InsertRawAsync(org, "cargo", "https://crates.private.example", "basic", "u", "legacy-plaintext");
        await Initializer().InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE upstream_credential_history SET first_seen_at = '2026-01-02T03:04:05Z' WHERE org_id = @org", new { org });

        await Initializer().InitializeAsync();

        Assert.Equal(
            "2026-01-02T03:04:05Z",
            await conn.ExecuteScalarAsync<string>("SELECT first_seen_at FROM upstream_credential_history WHERE org_id = @org", new { org }));
        Assert.Single(await HistoryAsync());
    }

    // ── Audit trail: upstreams deleted before the history table existed ────────

    [Fact]
    public async Task Boot_RecordsACredentialedAddFromTheAuditLog_WithNoUpstreamRowLeft()
    {
        await Initializer().InitializeAsync();
        string org = await OrgSeeder.InsertAsync(_db, "org");
        await InsertRawAsync(org, "npm", "https://registry.npmjs.org", "anonymous", null, null);
        await InsertAuditAddAsync(org,
            """{"id":"x","ecosystem":"npm","url":"https://npm.private.example","name":null,"authType":"bearer","hasSecret":true,"protocol":null,"hasPublicKey":false}""");
        await InsertAuditAddAsync(org,
            """{"id":"y","ecosystem":"oci","host":"registry.private.example","authType":"basic","prefixes":["t/"],"hasSecret":true,"name":null}""");
        Assert.True(await Repo().AllUpstreamsCredentialFreeAsync(org, "npm"));

        await Initializer().InitializeAsync();

        Assert.Equal([(org, "npm"), (org, "oci")], await HistoryAsync());
        Assert.False(await Repo().AllUpstreamsCredentialFreeAsync(org, "npm"));
    }

    [Fact]
    public async Task Boot_IgnoresAnonymousAdds_ScrubbedDetail_AndDeletedOrgs()
    {
        await Initializer().InitializeAsync();
        string org = await OrgSeeder.InsertAsync(_db, "org");
        await InsertAuditAddAsync(org,
            """{"id":"a","ecosystem":"npm","url":"https://mirror.example/npm","name":null,"authType":"anonymous","hasSecret":false,"protocol":null,"hasPublicKey":false}""");
        await InsertAuditAddAsync(org,
            """{"id":"b","ecosystem":"oci","host":"registry-1.docker.io","authType":"dockerhub_token_exchange","prefixes":[""],"hasSecret":false,"name":null}""");
        await InsertAuditAddAsync(org, """{"id":"c","ecosystem":"pypi","url":"https://pypi.org","name":null}""");
        await InsertAuditAddAsync(org, detail: null);
        await InsertAuditAddAsync("org-that-was-deleted",
            """{"id":"d","ecosystem":"npm","url":"https://npm.private.example","authType":"bearer","hasSecret":true}""");

        await Initializer().InitializeAsync();

        Assert.Empty(await HistoryAsync());
    }

    [Fact]
    public async Task OldAuditEvents_AreReadByTheOneShotBackfill_NotByEveryBoot()
    {
        await Initializer().InitializeAsync();
        string org = await OrgSeeder.InsertAsync(_db, "org");
        await InsertAuditAddAsync(org,
            """{"id":"x","ecosystem":"cargo","url":"https://crates.private.example","authType":"basic","hasSecret":true}""",
            daysAgo: SchemaInitializer.UpstreamCredentialAuditLookbackDays + 30);

        await Initializer().InitializeAsync();
        Assert.Empty(await HistoryAsync());

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'backfill_upstream_credential_history_from_audit'");
        }

        await Initializer().InitializeAsync();

        Assert.Equal([(org, "cargo")], await HistoryAsync());
    }

    [Theory]
    [InlineData("""{"ecosystem":"npm","url":"https://x.example","authType":"bearer","hasSecret":true}""", null, "npm")]
    [InlineData("""{"ecosystem":"npm","url":"https://x.example","authType":"basic","hasSecret":false}""", null, "npm")]
    [InlineData("""{"ecosystem":"npm","url":"https://x.example","authType":"anonymous","hasSecret":false}""", null, null)]
    [InlineData("""{"ecosystem":"npm","url":"https://x.example","authType":"anonymous","hasSecret":true}""", null, "npm")]
    [InlineData("""{"ecosystem":"npm","url":"https://u:p@x.example","authType":"anonymous","hasSecret":false}""", null, "npm")]
    [InlineData("""{"ecosystem":"oci","host":"registry-1.docker.io","authType":"dockerhub_token_exchange","hasSecret":false}""", null, null)]
    [InlineData("""{"ecosystem":"oci","host":"registry-1.docker.io","authType":"dockerhub_token_exchange","hasSecret":true}""", null, "oci")]
    [InlineData("""{"ecosystem":"oci","host":"123.dkr.ecr.aws","authType":"aws_ecr","hasSecret":false}""", null, "oci")]
    [InlineData("""{"ecosystem":"npm","url":"https://x.example","authType":"anonymous"}""", null, "npm")]
    [InlineData("""{"ecosystem":"npm","url":"https://x.example","hasSecret":false}""", null, "npm")]
    [InlineData("""{"ecosystem":"npm","url":"https://x.example","authType":7,"hasSecret":false}""", null, "npm")]
    [InlineData("""{"ecosystem":"npm","url":"https://x.example","name":null}""", null, null)]
    [InlineData("""{"ecosystem":"npm","url":"https://u:p@x.example","name":null}""", null, "npm")]
    [InlineData("""{"ecosystem":"npm","name":null}""", null, "npm")]
    [InlineData("""{"url":"https://x.example","authType":"bearer","hasSecret":true}""", null, null)]
    [InlineData("""{"url":"https://x.example","authType":"bearer","hasSecret":true}""", "pypi", "pypi")]
    [InlineData("not json", "npm", "npm")]
    [InlineData("not json", null, null)]
    [InlineData("[1,2]", null, null)]
    [InlineData(null, "npm", null)]
    [InlineData("", "npm", null)]
    public void CredentialedEcosystemFromAuditedAdd_ReadsTheLoggedFacts(string? detail, string? fallback, string? expected)
        => Assert.Equal(expected, UpstreamRegistryRepository.CredentialedEcosystemFromAuditedAdd(detail, fallback));
}
