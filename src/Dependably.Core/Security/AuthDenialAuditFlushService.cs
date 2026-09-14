using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;

namespace Dependably.Security;

/// <summary>
/// Closes <see cref="AuthDenialAuditCoalescer"/>'s accumulation window on a timer and writes one
/// audit row per key per window, carrying the count. Nothing else writes those rows: the denial
/// seams call <see cref="AuthDenialAuditCoalescer.Record"/> and return, so the audit write rate is
/// bounded by the window period and the live key count rather than by the request rate an
/// unauthenticated caller controls.
///
/// <para>
/// A tenant-scoped tally writes through <c>LogAsync</c> with its org; a tally with no resolved
/// tenant (apex/system-scope requests, and the saturation bucket, which drops the org to stay
/// bounded) writes through <c>LogSystemAsync</c>, because a tenant-scope row with a NULL org is
/// readable from neither the tenant audit page nor that tenant's SIEM feed. The row is actor-less
/// by construction — the partition dimension already carries whatever identity the denial had,
/// and folding two actors into one row would misattribute it.
/// </para>
///
/// <para>
/// <b>Shutdown and loss.</b> The loop drains one last time after its stopping token fires, so
/// counts accumulated between the final tick and SIGTERM still land. A SIGKILL, or a host that
/// exits before the drain completes, loses the open window — the counts live only in this
/// process's memory, and buying durability would mean a database write per denied request, which
/// is the amplification this whole mechanism exists to remove.
/// </para>
///
/// <para>
/// <b>Per-replica counts.</b> Each replica accumulates and flushes its own window, so a
/// multi-replica deployment emits one row per replica per window and the true count for a key is
/// the SUM of rows sharing <c>(org, partition, reason, window_start)</c>. The payload names the
/// replica so a reader can tell those rows apart. That grouping works only because
/// <c>window_start</c> is the wall-clock bucket of the counted denials
/// (<see cref="AuthDenialAuditCoalescer.FloorToWindow"/>) and not this replica's flush schedule —
/// so the label is read off each tally here, never off the drain instant.
/// </para>
///
/// <para>
/// suspension-ok: not a per-tenant scheduled job. It flushes counts of requests that were already
/// refused, for whatever tenants appear in the open window; a suspended org cannot generate new
/// denials (its planes are behind TenantStatusEnforcementMiddleware), and dropping a suspended
/// org's already-counted refusals would delete exactly the security record an operator wants after
/// suspending a tenant. Nothing here initiates work on a tenant's behalf.
/// </para>
/// </summary>
public sealed class AuthDenialAuditFlushService : BackgroundService
{
    /// <summary>
    /// Flush period. One minute keeps a burst's audit cost at one row per live key per minute per
    /// replica while staying short enough that a SOC rule on denial volume still sees the shape of
    /// a burst rather than a single daily total. It matches
    /// <see cref="AuthDenialAuditCoalescer.WindowAlignment"/>, which is what makes the default
    /// configuration close one wall-clock window into exactly one row per key per replica; a
    /// shorter period (the test seam) stays correct, it just splits a window across several rows
    /// that carry the same <c>window_start</c> and so sum back to the same total.
    /// </summary>
    internal static readonly TimeSpan DefaultWindow = AuthDenialAuditCoalescer.WindowAlignment;

    private readonly AuthDenialAuditCoalescer _coalescer;
    private readonly AuditRepository _audit;
    private readonly ILogger<AuthDenialAuditFlushService> _logger;
    private readonly TimeProvider _time;
    private readonly TimeSpan _window;

    // Hostname, which in a container deployment is the pod/container name — the identity an
    // operator already uses to tell replicas apart. Read once: it cannot change under a running
    // process, and every flushed row in the window carries it.
    private readonly string _replica = Environment.MachineName;

    public AuthDenialAuditFlushService(
        AuthDenialAuditCoalescer coalescer,
        AuditRepository audit,
        TimeProvider time,
        ILogger<AuthDenialAuditFlushService> logger)
        : this(coalescer, audit, time, logger, window: null)
    {
    }

    /// <summary>
    /// Test seam over the flush window. <paramref name="window"/> replaces
    /// <see cref="DefaultWindow"/>; null keeps it, which is what every production caller gets. It
    /// is not configuration — an operator has no way to reach it, so no deployment can shorten the
    /// interval denial counts are written on.
    ///
    /// <para>
    /// It exists for the same reason <c>SiemForwarderQueue</c>'s backoff seam does. A test that
    /// only needs the loop to reach its next flush, and asserts nothing about the period, would
    /// otherwise have to hand-drive a <c>FakeTimeProvider</c> from outside while the loop registers
    /// its timer from inside — and the two race: every advance the pump spends before the timer
    /// exists is wasted, so the test passes or fails on machine load. Tests that assert on the
    /// window instants keep the real period and drive the clock; tests that only need a flush call
    /// <see cref="FlushWindowAsync"/> directly, which is the same method the loop calls.
    /// </para>
    /// </summary>
    internal AuthDenialAuditFlushService(
        AuthDenialAuditCoalescer coalescer,
        AuditRepository audit,
        TimeProvider time,
        ILogger<AuthDenialAuditFlushService> logger,
        TimeSpan? window)
    {
        _coalescer = coalescer;
        _audit = audit;
        _time = time;
        _logger = logger;
        _window = window ?? DefaultWindow;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // The TimeProvider overload, so a test's fake clock drives the window rather than the
        // suite waiting on real minutes.
        using var timer = new PeriodicTimer(_window, _time);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await FlushWindowAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Falls through to the final drain — the counts buffered since the last tick are the
            // ones a shutdown would otherwise lose.
        }

        await FinalDrainAsync();
    }

    /// <summary>
    /// Test-only direct invocation of <see cref="ExecuteAsync"/>.
    /// <see cref="BackgroundService.StartAsync"/> short-circuits when handed an already-cancelled
    /// token and never enters <c>ExecuteAsync</c> at all, so it cannot exercise the shutdown drain.
    /// </summary>
    internal Task ExecuteAsyncForTests(CancellationToken stoppingToken) => ExecuteAsync(stoppingToken);

    /// <summary>
    /// Closes the window and writes its tallies. Public entry point for tests, which drive the
    /// flush directly rather than racing the loop's timer registration.
    /// </summary>
    internal async Task FlushWindowAsync(CancellationToken ct)
    {
        var window = _coalescer.DrainWindow();
        if (window.Entries.Count == 0)
        {
            return;
        }

        int written = 0;
        try
        {
            foreach (var tally in window.Entries)
            {
                await WriteAsync(tally, ct);
                written++;
            }
        }
        catch (Exception ex)
        {
            // Best-effort, the same posture the activity writer takes on a failed batch: the
            // window is already drained, so the unwritten tallies are gone rather than retried.
            // Retrying in place would hold the counts across an unbounded number of windows and
            // turn a database outage into unbounded process memory.
            _logger.LogWarning(
                ex,
                "Auth-denial audit flush failed: {ExceptionType} written={Written} dropped={Dropped}",
                ex.GetType().Name,
                written,
                window.Entries.Count - written);
        }
    }

    private async Task FinalDrainAsync()
    {
        try
        {
            await FlushWindowAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex, "Auth-denial audit shutdown drain failed: {ExceptionType}", ex.GetType().Name);
        }
    }

    private Task WriteAsync(AuthDenialTally tally, CancellationToken ct)
    {
        var key = tally.Key;
        string detail = JsonSerializer.Serialize(
            new
            {
                reason = key.Reason,
                partition = key.Partition,
                route = key.Route,
                policy = key.Policy,
                // Required-versus-granted, the pair that makes a capability denial actionable.
                // Null on the families that have no capability behind them, which keeps one
                // payload shape across the whole family rather than two a consumer must branch on.
                required = key.Required,
                granted = key.Granted,
                ecosystem = key.Ecosystem,
                count = tally.Count,
                window_start = tally.WindowStart.ToUtcIsoMillis(),
                window_end = tally.WindowEnd.ToUtcIsoMillis(),
                replica = _replica,
            },
            EventJsonOptions.Detail);

        // audit-action-ok: AuthDenialKey.Action carries one of the declared refusal names
        // (auth.token.rejected, auth.capability.denied, ratelimit.rejected) — AuthDenialAuditCoalescer.Record
        // refuses an undeclared one at the accumulation seam, before a row can reach this drain.
        return key.OrgId is { Length: > 0 } orgId
            ? _audit.LogAsync(
                key.Action,
                orgId: orgId,
                ecosystem: key.Ecosystem,
                detail: detail,
                sourceIp: tally.SourceIp,
                ct: ct)
            // audit-action-ok: the same declared refusal names as the tenant-scope arm above; a
            // denial with no resolvable tenant is written system-scope.
            : _audit.LogSystemAsync(
                key.Action,
                detail: detail,
                sourceIp: tally.SourceIp,
                ct: ct);
    }
}
