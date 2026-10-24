using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// <see cref="ProtectedSecretVerifier"/> against a real schema: one good and one corrupted value
/// of every protected kind, plus legacy-plaintext values. A corrupted value carries the
/// <c>enc:v1:</c> prefix and parses, which is exactly why the boot probe's prefix check never saw
/// it; only an authenticated decrypt does.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProtectedSecretVerifierTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 10, 7, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private readonly TestMetadataStore _db = new();
    private readonly byte[] _masterKey = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _mfaKey = RandomNumberGenerator.GetBytes(32);
    private EnvelopeProtector _envelope = null!;
    private MfaSecretProtector _totp = null!;

    // Every value written to the database, plaintext or stored form, so a test can assert that
    // none of them leaks into the report.
    private readonly List<string> _sensitive = [];

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _envelope = TestEnvelope.Configured(_masterKey);
        _totp = new MfaSecretProtector(_mfaKey);
    }

    public async Task DisposeAsync()
    {
        _envelope.Dispose();
        _totp.Dispose();
        await _db.DisposeAsync();
    }

    private ProtectedSecretVerifier Verifier(EnvelopeProtector? envelope = null, IDictionary<string, string?>? config = null) =>
        new(_db, envelope ?? _envelope,
            new ConfigurationBuilder().AddInMemoryCollection(config ?? new Dictionary<string, string?>()).Build(),
            TestTime.Frozen(Now));

    private string Good(string plaintext)
    {
        string stored = _envelope.Protect(plaintext);
        _sensitive.Add(plaintext);
        _sensitive.Add(stored[EnvelopeProtector.EncryptedPrefix.Length..]);
        return stored;
    }

    private string Bad(string plaintext)
    {
        string stored = CorruptCiphertext.Envelope(_envelope, plaintext);
        _sensitive.Add(plaintext);
        _sensitive.Add(stored[EnvelopeProtector.EncryptedPrefix.Length..]);
        return stored;
    }

    private string GoodTotp(string plaintext)
    {
        string stored = _totp.Protect(plaintext);
        _sensitive.Add(plaintext);
        _sensitive.Add(stored);
        return stored;
    }

    private string BadTotp(string plaintext)
    {
        string stored = CorruptCiphertext.Totp(_totp, plaintext);
        _sensitive.Add(plaintext);
        _sensitive.Add(stored);
        return stored;
    }

    private async Task ExecAsync(string sql, object? param = null)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(sql, param);
    }

    private Task SetInstanceAsync(string key, string value) =>
        ExecAsync("INSERT INTO instance_settings (key, value) VALUES (@key, @value)", new { key, value });

    private Task OrgAsync(string id) =>
        ExecAsync("INSERT INTO orgs (id, slug) VALUES (@id, @id)", new { id });

    private Task UserAsync(string id, string orgId, string? totp) =>
        ExecAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, mfa_authenticator_key) VALUES (@id, @orgId, @email, 'x', @totp)",
            new { id, orgId, email = id + "@example.com", totp });

    private Task SystemAdminAsync(string id, string? totp) =>
        ExecAsync(
            "INSERT INTO system_admins (id, email, password_hash, mfa_authenticator_key) VALUES (@id, @email, 'x', @totp)",
            new { id, email = id + "@example.com", totp });

    private Task WebhookAsync(string id, string orgId, string? secret) =>
        ExecAsync(
            "INSERT INTO webhook_subscription (id, org_id, url, secret) VALUES (@id, @orgId, 'https://hooks.example.com/x', @secret)",
            new { id, orgId, secret });

    private Task UpstreamAsync(string id, string orgId, string? secret) =>
        ExecAsync(
            "INSERT INTO upstream_registry (id, org_id, ecosystem, url, auth_type, secret) VALUES (@id, @orgId, 'npm', @url, 'bearer', @secret)",
            new { id, orgId, url = "https://registry.example.com/" + id, secret });

    private Task SlackAsync(string orgId, string url) =>
        ExecAsync(
            "INSERT INTO alert_settings (org_id, slack_enabled, slack_webhook_url) VALUES (@orgId, 1, @url)",
            new { orgId, url });

    private Task SbomKeyAsync(string id, string orgId, string privateKey, string? retiredAt = null) =>
        ExecAsync(
            "INSERT INTO sbom_signing_key (id, org_id, private_key, public_key_pem, retired_at) VALUES (@id, @orgId, @privateKey, 'pub', @retiredAt)",
            new { id, orgId, privateKey, retiredAt });

    private Task HexKeyAsync(string orgId, string privateKey) =>
        ExecAsync(
            "INSERT INTO hex_signing_key (org_id, private_key, public_key_pem, fingerprint) VALUES (@orgId, @privateKey, 'pub', 'fp')",
            new { orgId, privateKey });

    private Task KeyRingAsync(string name, string xml) =>
        ExecAsync("INSERT INTO data_protection_keys (friendly_name, xml) VALUES (@name, @xml)", new { name, xml });

    // One good and one corrupted value of every kind, two orgs, plus legacy plaintext rows.
    private async Task SeedEveryKindAsync()
    {
        await SetInstanceAsync("jwt_secret", Good("jwt-secret-value-0123456789"));
        await SetInstanceAsync("mfa_encryption_key", Good(Convert.ToBase64String(_mfaKey)));
        await SetInstanceAsync("smtp_password", Bad("smtp-relay-password"));
        await SetInstanceAsync("system_slack_webhook_url", "https://hooks.slack.com/services/T0/B0/plain");

        await OrgAsync("org-a");
        await OrgAsync("org-b");

        await SlackAsync("org-a", Good("https://hooks.slack.com/services/T1/B1/good"));
        await SlackAsync("org-b", Bad("https://hooks.slack.com/services/T2/B2/bad"));

        await WebhookAsync("wh-good", "org-a", Good("webhook-hmac-good"));
        await WebhookAsync("wh-bad", "org-b", Bad("webhook-hmac-bad"));
        await WebhookAsync("wh-plain", "org-a", "webhook-hmac-legacy");
        await WebhookAsync("wh-none", "org-a", null);

        await UpstreamAsync("up-good", "org-a", Good("upstream-token-good"));
        await UpstreamAsync("up-bad", "org-b", Bad("upstream-token-bad"));

        await SbomKeyAsync("sbom-good", "org-a", Good("-----BEGIN PRIVATE KEY-----good"));
        await SbomKeyAsync("sbom-bad", "org-b", Bad("-----BEGIN PRIVATE KEY-----bad"));
        await SbomKeyAsync("sbom-retired-bad", "org-b", Bad("-----BEGIN PRIVATE KEY-----retired"), "2026-01-01T00:00:00Z");

        await HexKeyAsync("org-a", Good("-----BEGIN PRIVATE KEY-----hex-good"));
        await HexKeyAsync("org-b", Bad("-----BEGIN PRIVATE KEY-----hex-bad"));

        await UserAsync("user-good", "org-a", GoodTotp("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
        await UserAsync("user-bad", "org-b", BadTotp("KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU"));
        // The stores only ever write ciphertext, so a bare Base32 key was planted from outside.
        _sensitive.Add("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        _sensitive.Add("GAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZ");
        await UserAsync("user-plain", "org-a", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        await UserAsync("user-no-mfa", "org-a", null);

        await SystemAdminAsync("admin-good", GoodTotp("MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK"));
        await SystemAdminAsync("admin-bad", BadTotp("NBSWY3DPNBSWY3DPNBSWY3DPNBSWY3DP"));
        await SystemAdminAsync("admin-plain", "GAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZ");

        await KeyRingAsync("dp-good", CorruptCiphertext.KeyRingElement(_masterKey));
        await KeyRingAsync("dp-bad", CorruptCiphertext.KeyRingElement(_masterKey, CorruptCiphertext.FlipTagBit));
        await KeyRingAsync("dp-plain", "<key id=\"1\"><descriptor><masterKey><value>cGxhaW4=</value></masterKey></descriptor></key>");
        await KeyRingAsync("dp-revocation", "<revocation version=\"1\"><revocationDate>2026-01-01T00:00:00Z</revocationDate></revocation>");
    }

    [Fact]
    public async Task CorruptedValueOfEveryKind_IsReportedWithIdentity()
    {
        await SeedEveryKindAsync();

        var report = await Verifier().VerifyAsync();

        var failures = report.Failures
            .Select(f => (f.Kind, f.Table, f.RowId, f.OrgId, f.Reason))
            .ToHashSet();
        const string Auth = ProtectedSecretFailureReasons.AuthenticationFailed;
        const string Plain = ProtectedSecretFailureReasons.UnexpectedPlaintext;
        Assert.Equal(
            new HashSet<(string, string, string, string?, string)>
            {
                ("smtp_password", "instance_settings", "smtp_password", null, Auth),
                (ProtectedSecretKinds.AlertSlackWebhookUrl, "alert_settings", "org-b", "org-b", Auth),
                (ProtectedSecretKinds.WebhookSecret, "webhook_subscription", "wh-bad", "org-b", Auth),
                (ProtectedSecretKinds.UpstreamCredential, "upstream_registry", "up-bad", "org-b", Auth),
                (ProtectedSecretKinds.SbomSigningKey, "sbom_signing_key", "sbom-bad", "org-b", Auth),
                (ProtectedSecretKinds.HexSigningKey, "hex_signing_key", "org-b", "org-b", Auth),
                (ProtectedSecretKinds.UserTotpKey, "users", "user-bad", "org-b", Auth),
                (ProtectedSecretKinds.UserTotpKey, "users", "user-plain", "org-a", Plain),
                (ProtectedSecretKinds.SystemAdminTotpKey, "system_admins", "admin-bad", null, Auth),
                (ProtectedSecretKinds.SystemAdminTotpKey, "system_admins", "admin-plain", null, Plain),
                (ProtectedSecretKinds.DataProtectionKey, "data_protection_keys", "dp-bad", null, Auth),
            },
            failures);
        Assert.Equal(11, report.Failed);
        Assert.False(report.FailuresTruncated);
        Assert.True(report.MasterKeyConfigured);
        Assert.Equal(Now, report.CheckedAt);
    }

    [Fact]
    public async Task GoodAndLegacyPlaintextValues_AreCountedButNotReported()
    {
        await SeedEveryKindAsync();

        var report = await Verifier().VerifyAsync();
        var kinds = report.Kinds.ToDictionary(k => k.Kind);

        // Good rows decrypt; legacy plaintext reads and is not a failure. TOTP keys have no
        // plaintext era, so a plaintext-shaped TOTP value is a failure, never legacy plaintext.
        Assert.Equal((3, 1, 1, 1), Counts(kinds[ProtectedSecretKinds.WebhookSecret]));
        Assert.Equal((3, 1, 0, 2), Counts(kinds[ProtectedSecretKinds.UserTotpKey]));
        Assert.Equal((3, 1, 0, 2), Counts(kinds[ProtectedSecretKinds.SystemAdminTotpKey]));
        Assert.Equal((3, 1, 1, 1), Counts(kinds[ProtectedSecretKinds.DataProtectionKey]));
        Assert.Equal(1, kinds["system_slack_webhook_url"].LegacyPlaintext);
        Assert.Equal(1, kinds["jwt_secret"].Ok);
        Assert.Equal(1, kinds["mfa_encryption_key"].Ok);
        Assert.Equal(0, kinds["vuln_tracker_token"].Checked);

        // A retired SBOM key is never decrypted again, so its state does not matter.
        string[] good = ["sbom-retired-bad", "wh-good", "wh-plain", "wh-none", "up-good", "sbom-good", "user-good", "admin-good", "dp-good", "dp-plain", "dp-revocation", "org-a", "jwt_secret", "mfa_encryption_key", "system_slack_webhook_url"];
        Assert.DoesNotContain(report.Failures, f => good.Contains(f.RowId));

        // Every kind is listed even when it has no rows, so the operator sees what was covered.
        Assert.Equal(
            ["jwt_secret", "mfa_encryption_key", "smtp_password", "system_slack_webhook_url", "vuln_tracker_token",
             ProtectedSecretKinds.AlertSlackWebhookUrl, ProtectedSecretKinds.WebhookSecret, ProtectedSecretKinds.UpstreamCredential,
             ProtectedSecretKinds.SbomSigningKey, ProtectedSecretKinds.HexSigningKey, ProtectedSecretKinds.UserTotpKey,
             ProtectedSecretKinds.SystemAdminTotpKey, ProtectedSecretKinds.DataProtectionKey],
            report.Kinds.Select(k => k.Kind));

        static (int Checked, int Ok, int Plain, int Failed) Counts(ProtectedSecretKindResult k) =>
            (k.Checked, k.Ok, k.LegacyPlaintext, k.Failed);
    }

    [Fact]
    public async Task Report_NeverContainsAValueOrCiphertext()
    {
        await SeedEveryKindAsync();

        var report = await Verifier().VerifyAsync();
        string json = JsonSerializer.Serialize(report, WebJson);

        Assert.NotEmpty(_sensitive);
        foreach (string value in _sensitive)
        {
            Assert.DoesNotContain(value, json, StringComparison.Ordinal);
            Assert.DoesNotContain(value[..Math.Min(12, value.Length)], json, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task CorruptedValue_PassesThePrefixOnlyBootProbe()
    {
        // The startup probe decides "encrypted" from the prefix alone, so a value the race wrote
        // looks healthy to it. This is the gap the verifier closes.
        string corrupted = CorruptCiphertext.Envelope(_envelope, "webhook-hmac");
        Assert.True(EnvelopeProtector.IsEncrypted(corrupted));
        Assert.Throws<MfaSecretProtectionException>(() => _envelope.Unprotect(corrupted));

        await OrgAsync("org-a");
        await WebhookAsync("wh-bad", "org-a", corrupted);

        var report = await Verifier().VerifyAsync();
        Assert.Contains(report.Failures, f => f.RowId == "wh-bad");
    }

    [Fact]
    public async Task EveryPageIsRead_AndTheFailureListIsCapped()
    {
        // More rows than one page and more failures than the list cap: the counts must cover
        // every row while the list stops at the cap.
        int total = ProtectedSecretVerifier.PageSize * 2 + 37;
        int corrupt = ProtectedSecretVerifier.MaxReportedFailures + 25;
        await OrgAsync("org-a");
        string good = _envelope.Protect("hmac");
        string bad = CorruptCiphertext.Envelope(_envelope, "hmac");
        await using (var conn = await _db.OpenAsync())
        {
            await using var tx = await conn.BeginTransactionAsync();
            for (int i = 0; i < total; i++)
            {
                await conn.ExecuteAsync(
                    "INSERT INTO webhook_subscription (id, org_id, url, secret) VALUES (@id, 'org-a', 'https://h.example.com', @secret)",
                    new { id = $"wh-{i:D5}", secret = i < corrupt ? bad : good }, tx);
            }

            await tx.CommitAsync();
        }

        var report = await Verifier().VerifyAsync();
        var webhooks = report.Kinds.Single(k => k.Kind == ProtectedSecretKinds.WebhookSecret);

        Assert.Equal(total, webhooks.Checked);
        Assert.Equal(corrupt, webhooks.Failed);
        Assert.Equal(total - corrupt, webhooks.Ok);
        Assert.Equal(ProtectedSecretVerifier.MaxReportedFailures, report.Failures.Count);
        Assert.True(report.FailuresTruncated);
        Assert.Equal(report.Failures.Count, report.Failures.Select(f => f.RowId).Distinct().Count());
    }

    [Fact]
    public async Task WithoutAMasterKey_EncryptedValuesAreUnverifiable_AndPlaintextIsNot()
    {
        await OrgAsync("org-a");
        await WebhookAsync("wh-enc", "org-a", _envelope.Protect("hmac"));
        await WebhookAsync("wh-plain", "org-a", "hmac-legacy");

        var report = await Verifier(TestEnvelope.Unconfigured()).VerifyAsync();

        var failure = Assert.Single(report.Failures);
        Assert.Equal(("wh-enc", ProtectedSecretFailureReasons.MasterKeyMissing), (failure.RowId, failure.Reason));
        Assert.Equal(1, report.Kinds.Single(k => k.Kind == ProtectedSecretKinds.WebhookSecret).LegacyPlaintext);
        Assert.False(report.MasterKeyConfigured);
    }

    [Fact]
    public async Task UnreadableMfaKey_IsReported_AndTotpKeysAreMarkedNotChecked()
    {
        await SetInstanceAsync("mfa_encryption_key", Bad(Convert.ToBase64String(_mfaKey)));
        await OrgAsync("org-a");
        await UserAsync("user-1", "org-a", GoodTotp("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));

        var report = await Verifier().VerifyAsync();

        Assert.Contains(report.Failures, f => f.Kind == "mfa_encryption_key");
        var users = report.Kinds.Single(k => k.Kind == ProtectedSecretKinds.UserTotpKey);
        Assert.Equal(ProtectedSecretSkipReasons.MfaEncryptionKeyUnavailable, users.SkippedReason);
        Assert.Equal(0, users.Checked);
        // No system admin has a TOTP key, so there is nothing that went unchecked there.
        Assert.Null(report.Kinds.Single(k => k.Kind == ProtectedSecretKinds.SystemAdminTotpKey).SkippedReason);
    }

    [Fact]
    public async Task KeyRingInRedis_IsMarkedNotChecked()
    {
        await KeyRingAsync("dp-bad", CorruptCiphertext.KeyRingElement(_masterKey, CorruptCiphertext.FlipTagBit));

        var report = await Verifier(config: new Dictionary<string, string?> { ["REDIS_CONNECTION_STRING"] = "localhost:6379" })
            .VerifyAsync();

        var ring = report.Kinds.Single(k => k.Kind == ProtectedSecretKinds.DataProtectionKey);
        Assert.Equal(ProtectedSecretSkipReasons.KeyRingInRedis, ring.SkippedReason);
        Assert.Empty(report.Failures);
    }

    [Fact]
    public async Task KeyRingWrittenByTheRealKeyManager_IsVerified()
    {
        // Let DataProtection itself generate and persist an encrypted key, so the check reads the
        // element shape the framework writes rather than one this test assumed.
        var kek = new EnvFileMasterKeyProvider(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(_masterKey) })
            .Build());
        var services = new ServiceCollection();
        services.AddSingleton<IMasterKeyProvider>(kek);
        services.AddTransient<EnvelopeXmlDecryptor>();
        services.AddDataProtection().AddKeyManagementOptions(opts =>
        {
            opts.XmlRepository = new DbXmlRepository(_db, NullLogger<DbXmlRepository>.Instance);
            opts.XmlEncryptor = new EnvelopeXmlEncryptor(kek);
        });
        await using (var sp = services.BuildServiceProvider())
        {
            _ = sp.GetRequiredService<IDataProtectionProvider>().CreateProtector("test").Protect("payload");
        }

        var clean = await Verifier().VerifyAsync();
        var ring = clean.Kinds.Single(k => k.Kind == ProtectedSecretKinds.DataProtectionKey);
        Assert.Equal((1, 1, 0), (ring.Checked, ring.Ok, ring.Failed));

        // Corrupt the stored ciphertext in place, as the race would have.
        await using (var conn = await _db.OpenAsync())
        {
            var (name, xml) = await conn.QuerySingleAsync<(string, string)>(
                "SELECT friendly_name, xml FROM data_protection_keys");
            var root = XElement.Parse(xml);
            var value = root.Descendants().Single(e => e.Name.LocalName == "value" && e.Parent!.Name.LocalName == "encryptedKey");
            value.Value = CorruptCiphertext.FlipTagBit(value.Value);
            await conn.ExecuteAsync(
                "UPDATE data_protection_keys SET xml = @xml WHERE friendly_name = @name",
                new { name, xml = root.ToString(SaveOptions.DisableFormatting) });
        }

        var corrupt = await Verifier().VerifyAsync();
        var failure = Assert.Single(corrupt.Failures);
        Assert.Equal(ProtectedSecretKinds.DataProtectionKey, failure.Kind);
    }

    [Fact]
    public async Task CleanStore_ReportsNoFailures()
    {
        await SetInstanceAsync("jwt_secret", Good("jwt"));
        await OrgAsync("org-a");
        await WebhookAsync("wh-1", "org-a", Good("hmac"));

        var report = await Verifier().VerifyAsync();

        Assert.Empty(report.Failures);
        Assert.Equal(0, report.Failed);
        Assert.Equal(2, report.Ok);
    }
}
