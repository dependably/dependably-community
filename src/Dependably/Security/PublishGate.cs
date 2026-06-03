using Dependably.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Security;

/// <summary>
/// Feature-flagged claim gate for publish/import paths. When
/// <c>CLAIM_ENFORCEMENT=on</c>, every publish handler consults this gate before accepting an
/// upload; unclaimed names are rejected with a structured 409 that includes the action the
/// caller should take. Default is <c>off</c> for backward-compatibility — existing
/// deployments and the compliance test suite continue working unchanged. Operators flip the
/// flag once they have established their initial set of claims.
///
/// In air-gap mode every name resolves to implicit <c>local_only</c>, so the gate
/// is effectively a no-op there even when the flag is on. The check still runs because an
/// operator might have created an explicit <c>unclaimed</c> claim row to deny publishing on
/// a specific name.
/// </summary>
public sealed class PublishGate
{
    private readonly bool _enforced;
    private readonly ClaimResolver _claims;

    public PublishGate(IConfiguration config, ClaimResolver claims)
    {
        _enforced = string.Equals(
            (config["CLAIM_ENFORCEMENT"] ?? "off").Trim(),
            "on",
            StringComparison.OrdinalIgnoreCase);
        _claims = claims;
    }

    public bool IsEnforced => _enforced;

    /// <summary>
    /// Returns null when publish is allowed (gate off, or claim is local_only/mixed).
    /// Returns a 409 <see cref="IActionResult"/> with a structured problem document when the
    /// gate rejects. Controllers should return the value directly.
    /// </summary>
    public async Task<IActionResult?> CheckAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        if (!_enforced) return null;
        if (await _claims.CanPublishAsync(orgId, ecosystem, name, ct)) return null;

        return new ObjectResult(new ProblemDetails
        {
            Type = "https://dependably.dev/problems/claim-required",
            Title = "Name not claimed",
            Status = StatusCodes.Status409Conflict,
            Detail = $"Publishing to '{name}' is not permitted because the name is unclaimed. " +
                     "Create a 'local_only' or 'mixed' claim for this name before uploading.",
            Extensions =
            {
                ["ecosystem"] = ecosystem,
                ["name"] = name
            }
        })
        {
            StatusCode = StatusCodes.Status409Conflict
        };
    }
}
