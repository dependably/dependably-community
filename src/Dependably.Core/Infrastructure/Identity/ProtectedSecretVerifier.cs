using System.Xml;
using System.Xml.Linq;
using Dapper;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Stable identifiers for each kind of stored secret <see cref="ProtectedSecretVerifier"/> checks.
/// They appear in the verification API response and the startup log, and OPERATIONS.md keys its
/// per-kind repair steps on them, so they are wire values: rename one and the runbook stops
/// matching.
/// </summary>
public static class ProtectedSecretKinds
{
    /// <summary><c>alert_settings.slack_webhook_url</c>: one org's Slack alert channel.</summary>
    public const string AlertSlackWebhookUrl = "alert_slack_webhook_url";

    /// <summary><c>webhook_subscription.secret</c>: the HMAC signing secret of one webhook.</summary>
    public const string WebhookSecret = "webhook_secret";

    /// <summary><c>upstream_registry.secret</c>: the credential for one private upstream.</summary>
    public const string UpstreamCredential = "upstream_credential";

    /// <summary><c>users.mfa_authenticator_key</c>: one tenant user's TOTP key.</summary>
    public const string UserTotpKey = "user_totp_key";

    /// <summary><c>system_admins.mfa_authenticator_key</c>: one system admin's TOTP key.</summary>
    public const string SystemAdminTotpKey = "system_admin_totp_key";

    /// <summary><c>sbom_signing_key.private_key</c>: one org's SBOM signing key.</summary>
    public const string SbomSigningKey = "sbom_signing_key";

    /// <summary><c>hex_signing_key.private_key</c>: one org's Hex registry signing key.</summary>
    public const string HexSigningKey = "hex_signing_key";

    /// <summary><c>data_protection_keys.xml</c>: one element of the DataProtection key ring.</summary>
    public const string DataProtectionKey = "data_protection_key";
}

/// <summary>
/// Why a stored secret failed verification. Wire values, like <see cref="ProtectedSecretKinds"/>.
/// </summary>
public static class ProtectedSecretFailureReasons
{
    /// <summary>
    /// The value carries the encryption envelope, but AES-GCM authentication rejects it (or its
    /// nonce/tag/ciphertext framing is broken). It can never be decrypted with this key and has
    /// to be re-entered.
    /// </summary>
    public const string AuthenticationFailed = "authentication_failed";

    /// <summary>
    /// The value carries the encryption envelope but this instance has no master key, so it
    /// cannot be decrypted here.
    /// </summary>
    public const string MasterKeyMissing = "master_key_missing";

    /// <summary>A DataProtection key element is not well-formed XML or lacks its ciphertext.</summary>
    public const string Malformed = "malformed";

    /// <summary>
    /// A TOTP key is stored as a bare Base32 key instead of ciphertext. The application never
    /// writes one, so it came from a write outside the application; it is rejected at sign-in
    /// and should be investigated as well as repaired.
    /// </summary>
    public const string UnexpectedPlaintext = "unexpected_plaintext";
}

/// <summary>
/// Why a whole kind was not checked. Wire values, like <see cref="ProtectedSecretKinds"/>.
/// </summary>
public static class ProtectedSecretSkipReasons
{
    /// <summary>
    /// TOTP keys are encrypted with <c>mfa_encryption_key</c>, and that key is absent or itself
    /// fails to decrypt, so no TOTP key can be checked. The key's own failure, if any, is reported.
    /// </summary>
    public const string MfaEncryptionKeyUnavailable = "mfa_encryption_key_unavailable";

    /// <summary>
    /// With <c>REDIS_CONNECTION_STRING</c> set the DataProtection key ring lives in Redis, not in
    /// the database this check reads.
    /// </summary>
    public const string KeyRingInRedis = "key_ring_in_redis";
}

/// <summary>One stored secret that does not decrypt. Carries its identity, never its value.</summary>
/// <param name="Kind">One of <see cref="ProtectedSecretKinds"/>, or an instance-secret key name.</param>
/// <param name="Table">The table holding the value.</param>
/// <param name="RowId">The row's primary key: an id, an org id, a setting key or a key-ring name.</param>
/// <param name="OrgId">The owning org, or null for an instance-level secret.</param>
/// <param name="Reason">One of <see cref="ProtectedSecretFailureReasons"/>.</param>
public sealed record ProtectedSecretFailure(string Kind, string Table, string RowId, string? OrgId, string Reason);

/// <summary>Per-kind counts from one verification run.</summary>
/// <param name="Kind">One of <see cref="ProtectedSecretKinds"/>, or an instance-secret key name.</param>
/// <param name="Table">The table holding values of this kind.</param>
/// <param name="Checked">Stored values examined (empty columns are not counted).</param>
/// <param name="Ok">Values that decrypt.</param>
/// <param name="LegacyPlaintext">Values stored without encryption. Readable, so not a failure.</param>
/// <param name="Failed">Values that cannot be decrypted.</param>
/// <param name="SkippedReason">Set when the kind could not be checked at all; see <see cref="ProtectedSecretSkipReasons"/>.</param>
public sealed record ProtectedSecretKindResult(
    string Kind, string Table, int Checked, int Ok, int LegacyPlaintext, int Failed, string? SkippedReason);

/// <summary>The outcome of one <see cref="ProtectedSecretVerifier.VerifyAsync"/> run.</summary>
/// <param name="CheckedAt">When the run started.</param>
/// <param name="MasterKeyConfigured">Whether <c>DEPENDABLY_MASTER_KEY</c> is set on this instance.</param>
/// <param name="Kinds">Counts for every kind, in a fixed order, including kinds with no rows.</param>
/// <param name="Failures">The failing rows, at most <see cref="ProtectedSecretVerifier.MaxReportedFailures"/>.</param>
/// <param name="FailuresTruncated">True when more rows failed than <paramref name="Failures"/> lists.</param>
public sealed record ProtectedSecretReport(
    DateTimeOffset CheckedAt,
    bool MasterKeyConfigured,
    IReadOnlyList<ProtectedSecretKindResult> Kinds,
    IReadOnlyList<ProtectedSecretFailure> Failures,
    bool FailuresTruncated)
{
    /// <summary>Stored values examined across every kind.</summary>
    public int Checked => Kinds.Sum(k => k.Checked);

    /// <summary>Values that decrypt, across every kind.</summary>
    public int Ok => Kinds.Sum(k => k.Ok);

    /// <summary>Values stored without encryption, across every kind.</summary>
    public int LegacyPlaintext => Kinds.Sum(k => k.LegacyPlaintext);

    /// <summary>Values that cannot be decrypted, across every kind. Counts past the list cap.</summary>
    public int Failed => Kinds.Sum(k => k.Failed);

    /// <summary>The most failing rows <see cref="Failures"/> ever lists.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static",
        Justification = "Instance member of a serialized report; a static property would drop it from the JSON payload.")]
    public int FailureLimit => ProtectedSecretVerifier.MaxReportedFailures;
}

/// <summary>
/// Tries to decrypt every stored secret the product protects at rest and reports the ones that
/// cannot be decrypted, by table, row and owning org, never by value.
///
/// <para>A secret encrypted while the shared AES-GCM instance was being used from two threads at
/// once on Linux could be stored with a nonce, tag and ciphertext that do not belong together.
/// Such a value is permanently undecryptable, and nothing notices until the feature that needs it
/// runs: an alert that is not delivered, a webhook that is skipped, an upstream fetch that fails
/// authentication, a TOTP code that is always "invalid". The write paths are serialized now, but
/// values written before that stay broken until someone re-enters them, and this is how an
/// operator finds them.</para>
///
/// <para>Coverage: the <see cref="OrgRepository.SecretKeys"/> instance secrets, the per-org
/// Slack webhook URL, webhook secrets, upstream credentials, active SBOM and Hex signing keys, tenant and
/// system-admin TOTP keys (under <c>mfa_encryption_key</c>, which is checked first), and the
/// DataProtection key ring when it is stored in the database. A value without the
/// <c>enc:v1:</c> envelope is counted as legacy plaintext, not as a failure: it still reads.</para>
///
/// <para>Bounded: each table is read in keyset-ordered pages of <see cref="PageSize"/> rows,
/// at most <see cref="MaxReportedFailures"/> failing rows are listed (the counts keep going), and
/// concurrent calls run one at a time. The sweep reads every org's rows, so it opens cross-tenant
/// connections itself rather than depending on its caller's scope.</para>
/// </summary>
public sealed class ProtectedSecretVerifier : IDisposable
{
    /// <summary>Rows read per query.</summary>
    internal const int PageSize = 500;

    /// <summary>Failing rows listed in one report; later failures are counted, not listed.</summary>
    public const int MaxReportedFailures = 500;

    private const string InstanceSettingsTable = "instance_settings";

    // The instance secret that encrypts TOTP keys, so it is checked before them.
    private const string MfaKeySetting = "mfa_encryption_key";

    // Instance secrets in a fixed order, so the report and the log read the same on every run.
    private static readonly string[] InstanceSecretKeys = [.. OrgRepository.SecretKeys.Order(StringComparer.Ordinal)];

    // Every query below reads one page of (RowId, OrgId, Value) after a keyset cursor. Each table's
    // primary key orders the pages, so the cursor is stable while rows are added or removed.

    // xtenant: instance-wide verification sweep over every org's Slack alert URL.
    private const string AlertSlackSql =
        """
        SELECT org_id AS RowId, org_id AS OrgId, slack_webhook_url AS Value
        FROM alert_settings
        WHERE slack_webhook_url IS NOT NULL AND org_id > @after
        ORDER BY org_id
        LIMIT @limit
        """;

    // xtenant: instance-wide verification sweep over every org's webhook signing secrets.
    private const string WebhookSql =
        """
        SELECT id AS RowId, org_id AS OrgId, secret AS Value
        FROM webhook_subscription
        WHERE secret IS NOT NULL AND id > @after
        ORDER BY id
        LIMIT @limit
        """;

    // xtenant: instance-wide verification sweep over every org's upstream credentials.
    private const string UpstreamSql =
        """
        SELECT id AS RowId, org_id AS OrgId, secret AS Value
        FROM upstream_registry
        WHERE secret IS NOT NULL AND id > @after
        ORDER BY id
        LIMIT @limit
        """;

    // Retired SBOM keys are skipped: only the public half of a retired key is ever read again,
    // so a corrupt one breaks nothing, and rotating (the repair) leaves the old row retired.
    // xtenant: instance-wide verification sweep over every org's active SBOM signing key.
    private const string SbomSigningKeySql =
        """
        SELECT id AS RowId, org_id AS OrgId, private_key AS Value
        FROM sbom_signing_key
        WHERE retired_at IS NULL AND id > @after
        ORDER BY id
        LIMIT @limit
        """;

    // xtenant: instance-wide verification sweep over every org's Hex signing key.
    private const string HexSigningKeySql =
        """
        SELECT org_id AS RowId, org_id AS OrgId, private_key AS Value
        FROM hex_signing_key
        WHERE org_id > @after
        ORDER BY org_id
        LIMIT @limit
        """;

    // xtenant: instance-wide verification sweep over every tenant user's TOTP key.
    private const string UserTotpSql =
        """
        SELECT id AS RowId, tenant_id AS OrgId, mfa_authenticator_key AS Value
        FROM users
        WHERE mfa_authenticator_key IS NOT NULL AND id > @after
        ORDER BY id
        LIMIT @limit
        """;

    private const string SystemAdminTotpSql =
        """
        SELECT id AS RowId, NULL AS OrgId, mfa_authenticator_key AS Value
        FROM system_admins
        WHERE mfa_authenticator_key IS NOT NULL AND id > @after
        ORDER BY id
        LIMIT @limit
        """;

    private const string DataProtectionSql =
        """
        SELECT friendly_name AS RowId, NULL AS OrgId, xml AS Value
        FROM data_protection_keys
        WHERE friendly_name > @after
        ORDER BY friendly_name
        LIMIT @limit
        """;

    private const string InstanceSecretSql =
        "SELECT key AS RowId, NULL AS OrgId, value AS Value FROM instance_settings WHERE key = @key";

    private static readonly SecretSource[] SecretSources =
    [
        new(ProtectedSecretKinds.AlertSlackWebhookUrl, "alert_settings", AlertSlackSql),
        new(ProtectedSecretKinds.WebhookSecret, "webhook_subscription", WebhookSql),
        new(ProtectedSecretKinds.UpstreamCredential, "upstream_registry", UpstreamSql),
        new(ProtectedSecretKinds.SbomSigningKey, "sbom_signing_key", SbomSigningKeySql),
        new(ProtectedSecretKinds.HexSigningKey, "hex_signing_key", HexSigningKeySql),
    ];

    private static readonly SecretSource[] TotpSources =
    [
        new(ProtectedSecretKinds.UserTotpKey, "users", UserTotpSql),
        new(ProtectedSecretKinds.SystemAdminTotpKey, "system_admins", SystemAdminTotpSql),
    ];

    private static readonly SecretSource DataProtectionSource =
        new(ProtectedSecretKinds.DataProtectionKey, "data_protection_keys", DataProtectionSql);

    private readonly IMetadataStore _db;
    private readonly EnvelopeProtector _envelope;
    private readonly IConfiguration _config;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public ProtectedSecretVerifier(IMetadataStore db, EnvelopeProtector envelope, IConfiguration config, TimeProvider time)
    {
        _db = db;
        _envelope = envelope;
        _config = config;
        _time = time;
    }

    /// <summary>
    /// Runs one full verification. A call made while another is running waits for it to finish
    /// and then runs its own, so two callers never sweep the database at the same time.
    /// </summary>
    public async Task<ProtectedSecretReport> VerifyAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            return await RunAsync(ct);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _gate.Dispose();

    private async Task<ProtectedSecretReport> RunAsync(CancellationToken ct)
    {
        var checkedAt = _time.GetUtcNow();
        var tally = new Tally();

        byte[]? mfaKey = await VerifyInstanceSecretsAsync(tally, ct);

        foreach (var source in SecretSources)
        {
            await VerifySourceAsync(source, tally, ClassifyEnvelope, ct);
        }

        await VerifyTotpKeysAsync(mfaKey, tally, ct);

        if (string.IsNullOrWhiteSpace(_config["REDIS_CONNECTION_STRING"]))
        {
            await VerifySourceAsync(DataProtectionSource, tally, ClassifyKeyRingElement, ct);
        }
        else
        {
            tally.Skip(DataProtectionSource.Kind, DataProtectionSource.Table, ProtectedSecretSkipReasons.KeyRingInRedis);
        }

        return tally.ToReport(checkedAt, _envelope.IsConfigured);
    }

    // Checks each instance secret and returns the usable MFA key, or null when it is absent or
    // does not decrypt (which leaves TOTP keys unverifiable).
    private async Task<byte[]?> VerifyInstanceSecretsAsync(Tally tally, CancellationToken ct)
    {
        byte[]? mfaKey = null;
        foreach (string key in InstanceSecretKeys)
        {
            tally.Declare(key, InstanceSettingsTable);
            var rows = await QueryAsync(InstanceSecretSql, new { key }, ct);
            foreach (var row in rows)
            {
                var outcome = tally.Record(key, InstanceSettingsTable, row, ClassifyEnvelope);
                if (key == MfaKeySetting && outcome is Outcome.Ok or Outcome.LegacyPlaintext)
                {
                    mfaKey = DecodeMfaKey(row.Value!);
                }
            }
        }

        return mfaKey;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null means no usable key was stored; an empty array would read as a zero-length key.")]
    private byte[]? DecodeMfaKey(string stored)
    {
        try
        {
            byte[] key = Convert.FromBase64String(_envelope.Unprotect(stored));
            return key.Length == 32 ? key : null;
        }
        catch (Exception ex) when (ex is FormatException or MfaSecretProtectionException or InvalidOperationException)
        {
            return null;
        }
    }

    private async Task VerifyTotpKeysAsync(byte[]? mfaKey, Tally tally, CancellationToken ct)
    {
        if (mfaKey is null)
        {
            foreach (var source in TotpSources)
            {
                // A store with no MFA key has never encrypted a TOTP key, so an empty table is
                // simply empty; skipped is reported only when there is something to check.
                bool any = (await QueryPageAsync(source, "", 1, ct)).Count > 0;
                if (any)
                {
                    tally.Skip(source.Kind, source.Table, ProtectedSecretSkipReasons.MfaEncryptionKeyUnavailable);
                }
                else
                {
                    tally.Declare(source.Kind, source.Table);
                }
            }

            return;
        }

        using var totp = new MfaSecretProtector(mfaKey);
        foreach (var source in TotpSources)
        {
            await VerifySourceAsync(source, tally, value => ClassifyTotp(totp, value), ct);
        }
    }

    private async Task VerifySourceAsync(
        SecretSource source, Tally tally, Func<string, Classification> classify, CancellationToken ct)
    {
        tally.Declare(source.Kind, source.Table);
        string after = "";
        while (true)
        {
            var page = await QueryPageAsync(source, after, PageSize, ct);
            foreach (var row in page)
            {
                tally.Record(source.Kind, source.Table, row, classify);
            }

            if (page.Count < PageSize)
            {
                return;
            }

            after = page[^1].RowId;
        }
    }

    private Task<IReadOnlyList<SecretRow>> QueryPageAsync(
        SecretSource source, string after, int limit, CancellationToken ct) =>
        QueryAsync(source.Sql, new { after, limit }, ct);

    private async Task<IReadOnlyList<SecretRow>> QueryAsync(string sql, object param, CancellationToken ct)
    {
        // xtenant: the verification sweep reads every org's stored secrets by design; a tenant
        // connection would see one org's rows and report the rest as absent.
        await using var conn = await _db.OpenCrossTenantAsync("protected-secret verification sweep", ct);
        var rows = await conn.QueryAsync<SecretRow>(new CommandDefinition(sql, param, cancellationToken: ct));
        return rows.AsList();
    }

    private Classification ClassifyEnvelope(string stored)
    {
        if (!EnvelopeProtector.IsEncrypted(stored))
        {
            return Classification.Plaintext;
        }

        if (!_envelope.IsConfigured)
        {
            return Classification.Fail(ProtectedSecretFailureReasons.MasterKeyMissing);
        }

        try
        {
            _ = _envelope.Unprotect(stored);
            return Classification.Decrypts;
        }
        catch (MfaSecretProtectionException)
        {
            return Classification.Fail(ProtectedSecretFailureReasons.AuthenticationFailed);
        }
    }

    // TOTP keys have no legacy-plaintext era: the user stores always wrote ciphertext and accept
    // nothing else, so a value that does not decrypt is a failure whatever its shape.
    // TotpKeyShape picks the reason the stores also log.
    private static Classification ClassifyTotp(MfaSecretProtector totp, string stored)
    {
        try
        {
            _ = totp.Unprotect(stored);
            return Classification.Decrypts;
        }
        catch (MfaSecretProtectionException)
        {
            return Classification.Fail(TotpKeyShape.FailureReason(stored));
        }
    }

    // A DataProtection key element is either plaintext XML (written before a master key was set)
    // or wraps its key material in an <encryptedSecret> naming EnvelopeXmlDecryptor, whose
    // <encryptedKey><value> holds the same base64(nonce||tag||ciphertext) framing as an envelope
    // value without the prefix. Elements that hold no key material (revocations) are not counted.
    private Classification ClassifyKeyRingElement(string xml)
    {
        XElement root;
        try
        {
            root = XElement.Parse(xml);
        }
        catch (XmlException)
        {
            return Classification.Fail(ProtectedSecretFailureReasons.Malformed);
        }

        var wrapped = root.DescendantsAndSelf()
            .Where(e => e.Name.LocalName == "encryptedSecret"
                && (e.Attribute("decryptorType")?.Value ?? "").Contains(nameof(EnvelopeXmlDecryptor), StringComparison.Ordinal))
            .ToList();
        if (wrapped.Count == 0)
        {
            return root.Name.LocalName == "key" ? Classification.Plaintext : Classification.NotASecret;
        }

        foreach (var element in wrapped)
        {
            string? cipher = element.Descendants()
                .FirstOrDefault(e => e.Name.LocalName == "value" && e.Parent?.Name.LocalName == "encryptedKey")?.Value;
            if (string.IsNullOrEmpty(cipher))
            {
                return Classification.Fail(ProtectedSecretFailureReasons.Malformed);
            }

            var outcome = ClassifyEnvelope(EnvelopeProtector.EncryptedPrefix + cipher);
            if (outcome.Outcome != Outcome.Ok)
            {
                return outcome;
            }
        }

        return Classification.Decrypts;
    }

    private enum Outcome
    {
        Ok,
        LegacyPlaintext,
        Failed,
        NotASecret,
    }

    private readonly record struct Classification(Outcome Outcome, string? Reason)
    {
        public static Classification Decrypts => new(Outcome.Ok, null);

        public static Classification Plaintext => new(Outcome.LegacyPlaintext, null);

        public static Classification NotASecret => new(Outcome.NotASecret, null);

        public static Classification Fail(string reason) => new(Outcome.Failed, reason);
    }

    private sealed record SecretSource(string Kind, string Table, string Sql);

    // String-only members, so Dapper binds it identically on SQLite and Postgres.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "Dapper sets these properties by reflection; a positional record cannot take an untyped NULL "
                        + "OrgId column, which SQLite reports as bytes.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed",
        Justification = "Dapper sets these properties by reflection; a positional record cannot take an untyped NULL "
                        + "OrgId column, which SQLite reports as bytes.")]
    private sealed class SecretRow
    {
        public string RowId { get; set; } = "";

        public string? OrgId { get; set; }

        public string? Value { get; set; }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3604:Member initializer values should not be redundant",
        Justification = "The members are initialized from primary-constructor parameters; the rule misreads that as a "
                        + "redundant initializer.")]
    private sealed class Counter(string table)
    {
        public string Table { get; } = table;

        public int Checked { get; set; }

        public int Ok { get; set; }

        public int LegacyPlaintext { get; set; }

        public int Failed { get; set; }

        public string? SkippedReason { get; set; }
    }

    // Accumulates counts per kind in first-declared order, and the failing rows up to the cap.
    private sealed class Tally
    {
        private readonly List<string> _order = [];
        private readonly Dictionary<string, Counter> _counters = new(StringComparer.Ordinal);
        private readonly List<ProtectedSecretFailure> _failures = [];
        private bool _truncated;

        public void Declare(string kind, string table)
        {
            if (!_counters.ContainsKey(kind))
            {
                _order.Add(kind);
                _counters[kind] = new Counter(table);
            }
        }

        public void Skip(string kind, string table, string reason)
        {
            Declare(kind, table);
            _counters[kind].SkippedReason = reason;
        }

        public Outcome Record(string kind, string table, SecretRow row, Func<string, Classification> classify)
        {
            if (string.IsNullOrEmpty(row.Value))
            {
                return Outcome.NotASecret;
            }

            var result = classify(row.Value);
            var counter = _counters[kind];
            switch (result.Outcome)
            {
                case Outcome.NotASecret:
                    return result.Outcome;
                case Outcome.Ok:
                    counter.Ok++;
                    break;
                case Outcome.LegacyPlaintext:
                    counter.LegacyPlaintext++;
                    break;
                default:
                    counter.Failed++;
                    if (_failures.Count < MaxReportedFailures)
                    {
                        _failures.Add(new ProtectedSecretFailure(kind, table, row.RowId, row.OrgId, result.Reason!));
                    }
                    else
                    {
                        _truncated = true;
                    }

                    break;
            }

            counter.Checked++;
            return result.Outcome;
        }

        public ProtectedSecretReport ToReport(DateTimeOffset checkedAt, bool masterKeyConfigured) =>
            new(
                checkedAt,
                masterKeyConfigured,
                [.. _order.Select(k =>
                {
                    var c = _counters[k];
                    return new ProtectedSecretKindResult(k, c.Table, c.Checked, c.Ok, c.LegacyPlaintext, c.Failed, c.SkippedReason);
                })],
                [.. _failures],
                _truncated);
    }
}
