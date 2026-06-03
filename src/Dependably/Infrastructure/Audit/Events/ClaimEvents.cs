using System.Text.Json;

namespace Dependably.Infrastructure.Audit.Events;

/// <summary>
/// Typed payloads for claim lifecycle events. The claim audit trail is the
/// supply-chain-shaped surface that compliance reviewers query most often, so it gets
/// dedicated typed records — not freeform audit_log strings — for grep stability.
/// </summary>
public static class ClaimEvents
{
    public const string TypeCreate = "claim.create";
    public const string TypeTransition = "claim.transition";
    public const string TypeRelease = "claim.release";

    public sealed record Create(
        string Ecosystem,
        string Name,
        string State,
        string Reason,
        bool PurgesProxy)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record Transition(
        string Ecosystem,
        string Name,
        string PriorState,
        string NewState,
        string Reason,
        bool PurgesProxy)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record Release(
        string Ecosystem,
        string Name,
        string PriorState,
        string Reason,
        int LocalVersionCount)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }
}
