namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Shared retry/auto-disable arithmetic for the per-org alert delivery queues
/// (<see cref="AlertSlackQueue"/> and the email counterpart). Extracted so the two channels
/// can never drift on what "sustained failure" means.
/// </summary>
public static class AlertDeliveryPolicy
{
    /// <summary>Auto-disable a delivery channel for an org after this many consecutive terminal failures.</summary>
    public const int AutoDisableAfterFailures = 20;

    /// <summary>Auto-disable a delivery channel for an org failing continuously for this long.</summary>
    public static readonly TimeSpan AutoDisableAfterDuration = TimeSpan.FromHours(48);

    /// <summary>Retry backoff schedule shared by every delivery queue: 1 initial attempt + 3 retries.</summary>
    public static readonly TimeSpan[] BackoffSchedule =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(30)
    ];
}
