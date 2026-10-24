namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Runs <see cref="ProtectedSecretVerifier"/> once per boot, in the background, after the host
/// has started listening, and logs a warning for each kind of stored secret that does not
/// decrypt, naming the failing rows but never their values.
///
/// <para>It never delays or fails startup: it waits for
/// <see cref="IHostApplicationLifetime.ApplicationStarted"/> before touching the database, and a
/// sweep that throws is logged and dropped. A corrupt secret breaks one feature for one org;
/// refusing to boot over it would take down every org to report it.</para>
///
/// <para>On by default because the failure it reports is otherwise silent until the feature
/// that needs the secret runs. <c>SECRETS_VERIFY_ON_STARTUP=false</c> turns it off, for a fleet
/// where every replica repeating the same read-only sweep on a rolling restart is unwanted; the
/// on-demand endpoints still run it.</para>
///
/// suspension-ok: not per-tenant. One instance-wide, read-only sweep that writes nothing and
/// delivers nothing to any org; a suspended org's undecryptable secret is still worth reporting.
/// </summary>
public sealed class ProtectedSecretBootCheck : BackgroundService
{
    internal const string EnabledSetting = "SECRETS_VERIFY_ON_STARTUP";

    // Row identities named per kind in one log event; the rest are counted, and the endpoint
    // lists them in full.
    internal const int LoggedRowsPerKind = 20;

    private readonly ProtectedSecretVerifier _verifier;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly IConfiguration _config;
    private readonly ILogger<ProtectedSecretBootCheck> _logger;

    public ProtectedSecretBootCheck(
        ProtectedSecretVerifier verifier,
        IHostApplicationLifetime lifetime,
        IConfiguration config,
        ILogger<ProtectedSecretBootCheck> logger)
    {
        _verifier = verifier;
        _lifetime = lifetime;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!IsEnabled())
        {
            _logger.LogInformation(
                "Stored-secret verification at startup is off ({Setting}=false).", EnabledSetting);
            return;
        }

        if (!await WaitForStartedAsync(stoppingToken))
        {
            return;
        }

        ProtectedSecretReport report;
        try
        {
            report = await _verifier.VerifyAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Stored-secret verification at startup could not complete. Run it on demand from "
                + "the secrets verification endpoint; see OPERATIONS.md, Verifying stored secrets.");
            return;
        }

        LogReport(report);
    }

    private bool IsEnabled()
    {
        string? raw = _config[EnabledSetting];
        if (string.IsNullOrWhiteSpace(raw))
        {
            return true;
        }

        if (bool.TryParse(raw.Trim(), out bool enabled))
        {
            return enabled;
        }

        // A value that is not a boolean keeps the check on: a diagnostic that reads nothing but
        // the database is the safer side of a typo.
        _logger.LogWarning(
            "{Setting} is not true or false; stored-secret verification at startup stays on.", EnabledSetting);
        return true;
    }

    private async Task<bool> WaitForStartedAsync(CancellationToken stoppingToken)
    {
        if (_lifetime.ApplicationStarted.IsCancellationRequested)
        {
            return true;
        }

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var onStarted = _lifetime.ApplicationStarted.Register(() => started.TrySetResult());
        using var onStopping = stoppingToken.Register(() => started.TrySetCanceled(stoppingToken));
        try
        {
            await started.Task;
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    internal void LogReport(ProtectedSecretReport report)
    {
        foreach (var kind in report.Kinds.Where(k => k.Failed > 0))
        {
            var rows = report.Failures.Where(f => f.Kind == kind.Kind).ToList();
            string named = string.Join(", ", rows.Take(LoggedRowsPerKind).Select(DescribeRow));
            int unnamed = kind.Failed - Math.Min(rows.Count, LoggedRowsPerKind);
            _logger.LogWarning(
                "Stored secret check: {Failed} {Kind} value(s) in {Table} cannot be decrypted and must be "
                + "re-entered. Rows: {Rows}{More}. See OPERATIONS.md, Verifying stored secrets.",
                kind.Failed, kind.Kind, kind.Table, named,
                unnamed > 0 ? $" and {unnamed} more" : "");
        }

        foreach (var kind in report.Kinds.Where(k => k.SkippedReason == ProtectedSecretSkipReasons.MfaEncryptionKeyUnavailable))
        {
            _logger.LogWarning(
                "Stored secret check: {Kind} values in {Table} were not checked ({Reason}).",
                kind.Kind, kind.Table, kind.SkippedReason);
        }

        if (report.Failed == 0)
        {
            _logger.LogInformation(
                "Stored secret check: {Checked} stored secret(s) checked, none fail to decrypt ({Plaintext} stored unencrypted).",
                report.Checked, report.LegacyPlaintext);
        }
    }

    private static string DescribeRow(ProtectedSecretFailure failure) =>
        failure.OrgId is null || failure.OrgId == failure.RowId
            ? failure.OrgId is null ? failure.RowId : $"org {failure.OrgId}"
            : $"{failure.RowId} (org {failure.OrgId})";
}
