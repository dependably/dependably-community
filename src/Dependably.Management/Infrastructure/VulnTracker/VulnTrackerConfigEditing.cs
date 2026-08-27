using System.Globalization;

namespace Dependably.Infrastructure.VulnTracker;

/// <summary>
/// Request body shared by <c>PUT /api/v1/system/vuln-tracker-config</c> and
/// <c>PUT /api/v1/instance/vuln-tracker-config</c>. Mirrors <c>EmailConfigRequest</c>'s
/// write-only-secret convention: every field except <see cref="Token"/> is a full-form
/// replacement value the caller always supplies; <see cref="Token"/> is write-only —
/// null/empty on update means "leave the stored token unchanged", non-empty rotates it.
/// </summary>
public sealed class VulnTrackerConfigRequest
{
    public bool Enabled { get; set; }
    public string? BaseUrl { get; set; }
    public string? Token { get; set; }
    public int MaxStalenessHours { get; set; } = VulnTrackerSettings.DefaultMaxStalenessHours;
    public int BatchSize { get; set; } = VulnTrackerSettings.DefaultBatchSize;
}

/// <summary>
/// Shared editing helpers for the one instance-level vulnerability-tracker connection, used by
/// both the multi-mode apex surface (<c>SystemController.VulnTrackerConfig.cs</c>) and the
/// single-mode instance surface (<c>InstanceController</c>). Centralising validation, the
/// response projection, and the write keeps the two handlers behaviourally identical and unable
/// to drift — the same arrangement <c>EmailConfigEditing</c> makes for the SMTP transport.
/// </summary>
public static class VulnTrackerConfigEditing
{
    /// <summary>
    /// Validates the request's base URL, staleness horizon, and batch size. Returns the first
    /// invalid field name and its SharedResource key, or <c>(null, null)</c> when everything
    /// parses. The token is an opaque string with no format to check here.
    /// </summary>
    public static (string? Field, string? ResourceKey) Validate(VulnTrackerConfigRequest req)
        => VulnTrackerSettings.Validate(req.BaseUrl, req.MaxStalenessHours, req.BatchSize);

    /// <summary>
    /// Save-time SSRF screen on the base URL's host, shared by the apex and single-mode surfaces
    /// so the two cannot diverge on which hosts they accept. True when the URL parses and its
    /// host is an IP literal <paramref name="isBlocked"/> rejects.
    ///
    /// <para>
    /// Advisory only, deliberately: a hostname is not resolved here, because DNS can change
    /// between save time and request time and a save-time hostname check is therefore never
    /// authoritative. The authoritative, DNS-rebinding-aware gate is the connect-time guard the
    /// tracker client runs on every request. This exists to fail fast on an obviously-bad
    /// literal, not to be the boundary.
    /// </para>
    /// </summary>
    public static bool IsHostBlocked(string? baseUrl, Func<System.Net.IPAddress, bool> isBlocked)
        => VulnTrackerSettings.TryParseBaseUrl(baseUrl, out var uri)
           && uri is not null
           && Dependably.Security.HostSsrfValidator.IsHostBlocked(uri.Host, isBlocked);

    /// <summary>
    /// Builds the GET/PUT response object. <c>hasToken</c> reflects whether a credential is
    /// currently stored — the raw value is never included on any read or write response, so the
    /// only way a token leaves this deployment is the outbound request that uses it.
    /// <c>secretsAvailable</c> mirrors the email-config convention (=
    /// <c>EnvelopeProtector.IsConfigured</c>) so the UI can grey out the token field with an
    /// explanatory hint when no master key is set, rather than accepting a value the write path
    /// will refuse.
    /// </summary>
    public static object BuildView(
        InstanceVulnTrackerConfig.ResolvedVulnTrackerConfig resolved, bool secretsAvailable)
    {
        var c = resolved.Connection;
        return new
        {
            enabled = resolved.Enabled,
            baseUrl = c.BaseUrl,
            hasToken = !string.IsNullOrEmpty(c.Token),
            maxStalenessHours = c.MaxStalenessHours,
            batchSize = c.BatchSize,
            configured = resolved.Configured,
            active = resolved.IsActive,
            secretsAvailable,
        };
    }

    /// <summary>
    /// Projects a probe outcome for the wire. camelCase via the Web serializer defaults, because
    /// the Svelte frontend is the only consumer — the C# default would emit PascalCase, which it
    /// does not read and which surfaces as a runtime blank rather than a compile error.
    /// </summary>
    public static object BuildProbeView(VulnTrackerProbeResult probe)
        => new
        {
            reached = probe.Reached,
            reason = probe.Reason,
            latencyMs = probe.LatencyMs,
            freshness = probe.Freshness
                .Select(f => new { source = f.Source, asOf = f.AsOf })
                .ToList(),
        };

    /// <summary>
    /// Writes the request's fields to <c>instance_settings</c> via
    /// <c>OrgRepository.SetInstanceSettingAsync</c> (which envelope-encrypts
    /// <c>vuln_tracker_token</c> automatically once a master key is configured). The token is
    /// written only when the caller supplied a non-empty value — the caller is responsible for
    /// having already checked <c>EnvelopeProtector.IsConfigured</c> before calling this when
    /// <see cref="VulnTrackerConfigRequest.Token"/> is non-empty.
    ///
    /// <para>
    /// Clearing the base URL also clears the stored token. Pausing enrichment is what
    /// <see cref="VulnTrackerConfigRequest.Enabled"/> is for; clearing the URL is a teardown, and
    /// leaving a bearer credential at rest for a tracker this deployment no longer talks to is a
    /// secret with no remaining purpose. The two are kept distinct precisely so an operator never
    /// has to choose between pausing and discarding the credential.
    /// </para>
    /// </summary>
    public static async Task ApplyAsync(
        OrgRepository orgs, VulnTrackerConfigRequest req, CancellationToken ct)
    {
        string baseUrl = req.BaseUrl?.Trim() ?? "";

        await orgs.SetInstanceSettingAsync("vuln_tracker_enabled", req.Enabled ? "1" : "0", ct);
        await orgs.SetInstanceSettingAsync("vuln_tracker_base_url", baseUrl, ct);
        await orgs.SetInstanceSettingAsync(
            "vuln_tracker_max_staleness_hours",
            req.MaxStalenessHours.ToString(CultureInfo.InvariantCulture),
            ct);
        await orgs.SetInstanceSettingAsync(
            "vuln_tracker_batch_size",
            req.BatchSize.ToString(CultureInfo.InvariantCulture),
            ct);

        if (baseUrl.Length == 0)
        {
            await orgs.SetInstanceSettingAsync("vuln_tracker_token", "", ct);
        }
        else if (!string.IsNullOrEmpty(req.Token))
        {
            await orgs.SetInstanceSettingAsync("vuln_tracker_token", req.Token, ct);
        }
    }
}
