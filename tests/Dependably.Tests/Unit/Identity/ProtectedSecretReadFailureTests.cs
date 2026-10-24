using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Hex;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// What a reader does with one stored secret that does not decrypt. Readers that need a single
/// value, and the upstream lists whose order is a trust decision, fail closed with a
/// <see cref="ProtectedSecretUnreadableException"/> that names the row and never the value; the
/// same read for a sibling row (another org, or another ecosystem) keeps working.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProtectedSecretReadFailureTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _time = TestTime.Frozen();
    private readonly EnvelopeProtector _envelope = TestEnvelope.Configured();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-a', 'org-a')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-b', 'org-b')");
    }

    public async Task DisposeAsync()
    {
        _envelope.Dispose();
        await _db.DisposeAsync();
    }

    private static void AssertNamesRowNotValue(
        ProtectedSecretUnreadableException ex, string kind, string table, string rowId, string? orgId,
        params string[] sensitive)
    {
        Assert.Equal(kind, ex.Kind);
        Assert.Equal(table, ex.Table);
        Assert.Equal(rowId, ex.RowId);
        Assert.Equal(orgId, ex.OrgId);
        Assert.Equal(ProtectedSecretFailureReasons.AuthenticationFailed, ex.Reason);
        Assert.Contains(rowId, ex.Message);
        Assert.Contains(table, ex.Message);
        foreach (string s in sensitive)
        {
            Assert.DoesNotContain(s, ex.Message);
        }
    }

    // ── EnvelopeProtector.TryUnprotect ───────────────────────────────────────────

    [Fact]
    public void TryUnprotect_ReportsEachOutcomeWithoutThrowing()
    {
        Assert.True(_envelope.TryUnprotect(_envelope.Protect("s3cret"), out string? good, out _));
        Assert.Equal("s3cret", good);

        Assert.True(_envelope.TryUnprotect("legacy-plaintext", out string? legacy, out _));
        Assert.Equal("legacy-plaintext", legacy);

        Assert.False(_envelope.TryUnprotect(CorruptCiphertext.Envelope(_envelope, "s3cret"), out _, out string? reason));
        Assert.Equal(ProtectedSecretFailureReasons.AuthenticationFailed, reason);

        using var keyless = TestEnvelope.Unconfigured();
        Assert.False(keyless.TryUnprotect(_envelope.Protect("s3cret"), out _, out string? missing));
        Assert.Equal(ProtectedSecretFailureReasons.MasterKeyMissing, missing);
    }

    // ── Upstream credentials: the list fails closed, naming the row ──────────────

    private async Task InsertUpstreamAsync(string id, string orgId, string ecosystem, string url, string? secret)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, auth_type, secret, position)
            VALUES (@id, @orgId, @ecosystem, @url, @authType, @secret, 0)
            """,
            new { id, orgId, ecosystem, url, authType = secret is null ? "anonymous" : "bearer", secret });
    }

    [Fact]
    public async Task ListSourcesForEcosystemAsync_CorruptedCredential_FailsTheListNamingTheRow()
    {
        string corrupted = CorruptCiphertext.Envelope(_envelope, "npm-token-bad");
        await InsertUpstreamAsync("up-bad", "org-a", "npm", "https://private.example.com/", corrupted);
        await InsertUpstreamAsync("up-pypi", "org-a", "pypi", "https://pypi.example.com/", _envelope.Protect("pypi-token"));
        await InsertUpstreamAsync("up-b", "org-b", "npm", "https://b.example.com/", _envelope.Protect("b-token"));
        var repo = new UpstreamRegistryRepository(_db, _time, _envelope);

        var ex = await Assert.ThrowsAsync<ProtectedSecretUnreadableException>(
            () => repo.ListSourcesForEcosystemAsync("org-a", "npm"));
        AssertNamesRowNotValue(ex, ProtectedSecretKinds.UpstreamCredential, "upstream_registry", "up-bad", "org-a",
            "npm-token-bad", corrupted[EnvelopeProtector.EncryptedPrefix.Length..]);

        // The same org's other ecosystem, and another org's npm list, are unaffected.
        Assert.Single(await repo.ListSourcesForEcosystemAsync("org-a", "pypi"));
        Assert.Single(await repo.ListSourcesForEcosystemAsync("org-b", "npm"));
    }

    [Fact]
    public async Task BuildOciUpstreamsForOrgAsync_CorruptedCredential_FailsTheListNamingTheRow()
    {
        string corrupted = CorruptCiphertext.Envelope(_envelope, "oci-pass-bad");
        await InsertUpstreamAsync("oci-bad", "org-a", "oci", "registry.example.com", corrupted);
        await InsertUpstreamAsync("oci-b", "org-b", "oci", "registry.example.com", _envelope.Protect("oci-pass"));
        var repo = new UpstreamRegistryRepository(_db, _time, _envelope);

        var ex = await Assert.ThrowsAsync<ProtectedSecretUnreadableException>(
            () => repo.BuildOciUpstreamsForOrgAsync("org-a"));
        AssertNamesRowNotValue(ex, ProtectedSecretKinds.UpstreamCredential, "upstream_registry", "oci-bad", "org-a",
            "oci-pass-bad");

        var other = Assert.Single(await repo.BuildOciUpstreamsForOrgAsync("org-b"));
        Assert.Equal("oci-pass", other.Password);
    }

    // ── Single-value readers: fail closed, naming the row ────────────────────────

    [Fact]
    public async Task GetDecryptedSlackWebhookUrlAsync_Corrupted_ThrowsNamingTheOrg()
    {
        string corrupted = CorruptCiphertext.Envelope(_envelope, "https://hooks.slack.com/services/T0/B0/bad");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO alert_settings (org_id, slack_enabled, slack_webhook_url) VALUES ('org-a', 1, @url)",
                new { url = corrupted });
            await conn.ExecuteAsync(
                "INSERT INTO alert_settings (org_id, slack_enabled, slack_webhook_url) VALUES ('org-b', 1, @url)",
                new { url = _envelope.Protect("https://hooks.slack.com/services/T0/B0/good") });
        }

        var repo = new AlertSettingsRepository(_db, _envelope, _time);

        var ex = await Assert.ThrowsAsync<ProtectedSecretUnreadableException>(
            () => repo.GetDecryptedSlackWebhookUrlAsync("org-a"));
        AssertNamesRowNotValue(ex, ProtectedSecretKinds.AlertSlackWebhookUrl, "alert_settings", "org-a", "org-a",
            "hooks.slack.com");
        Assert.Equal("https://hooks.slack.com/services/T0/B0/good", await repo.GetDecryptedSlackWebhookUrlAsync("org-b"));
    }

    [Fact]
    public async Task HexSigningKey_Corrupted_ThrowsNamingTheOrg()
    {
        var repo = new HexSigningKeyRepository(_db, _envelope, _time, TestEdgeMode.Disabled());
        Assert.NotNull(await repo.GetOrCreateAsync("org-a"));
        Assert.NotNull(await repo.GetOrCreateAsync("org-b"));
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE hex_signing_key SET private_key = @k WHERE org_id = 'org-a'",
                new { k = CorruptCiphertext.Envelope(_envelope, "-----BEGIN PRIVATE KEY-----") });
        }

        var ex = await Assert.ThrowsAsync<ProtectedSecretUnreadableException>(() => repo.GetAsync("org-a"));
        AssertNamesRowNotValue(ex, ProtectedSecretKinds.HexSigningKey, "hex_signing_key", "org-a", "org-a",
            "PRIVATE KEY");
        Assert.NotNull(await repo.GetAsync("org-b"));
    }

    [Fact]
    public async Task SbomSigningKey_Corrupted_ThrowsNamingTheKeyRow()
    {
        var repo = new SbomSigningKeyRepository(_db, _envelope, _time, TestEdgeMode.Disabled());
        var created = await repo.GetOrCreateAsync("org-a");
        Assert.NotNull(created);
        Assert.NotNull(await repo.GetOrCreateAsync("org-b"));
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE sbom_signing_key SET private_key = @k WHERE org_id = 'org-a'",
                new { k = CorruptCiphertext.Envelope(_envelope, "-----BEGIN PRIVATE KEY-----") });
        }

        var ex = await Assert.ThrowsAsync<ProtectedSecretUnreadableException>(() => repo.GetActiveAsync("org-a"));
        AssertNamesRowNotValue(ex, ProtectedSecretKinds.SbomSigningKey, "sbom_signing_key", created!.Id, "org-a",
            "PRIVATE KEY");
        Assert.NotNull(await repo.GetActiveAsync("org-b"));
    }

    [Fact]
    public async Task GetInstanceSettingAsync_Corrupted_ThrowsNamingTheSettingKey()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO instance_settings (key, value) VALUES ('smtp_password', @v)",
                new { v = CorruptCiphertext.Envelope(_envelope, "relay-password") });
            await conn.ExecuteAsync(
                "INSERT INTO instance_settings (key, value) VALUES ('vuln_tracker_token', @v)",
                new { v = _envelope.Protect("tracker-token") });
        }

        var repo = new OrgRepository(_db, envelope: _envelope);

        var ex = await Assert.ThrowsAsync<ProtectedSecretUnreadableException>(
            () => repo.GetInstanceSettingAsync("smtp_password"));
        AssertNamesRowNotValue(ex, "smtp_password", "instance_settings", "smtp_password", null, "relay-password");
        Assert.Equal("tracker-token", await repo.GetInstanceSettingAsync("vuln_tracker_token"));
    }
}
