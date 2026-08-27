using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Audit.Events;

namespace Dependably.Protocol;

/// <summary>Outcome of one policy evaluation pass: the stamped rollup and how many findings it produced.</summary>
public readonly record struct SbomPolicyEvaluationResult(string PolicyStatus, int FindingCount);

/// <summary>
/// Orchestrates one project version's policy evaluation: loads the component/vuln/VEX facts,
/// runs <see cref="SbomPolicyEvaluator.Evaluate"/> plus the licence arm (which needs
/// <see cref="LicenseRepository.CheckPolicyAsync"/>'s database read, so it cannot live inside the
/// pure evaluator), replaces the version's <c>sbom_policy_findings</c> rows, stamps
/// <c>project_versions.policy_status</c>, and raises the alert on a fresh violation.
///
/// Called at scan completion, on a VEX/manual-triage change, and once per project version by the
/// nightly SBOM pass. The nightly call is what bounds feed-driven drift: an advisory joining KEV
/// or an EPSS score crossing a tenant's tolerance changes the verdict without touching a single
/// component row, so a version that nothing re-uploads would otherwise keep its last verdict
/// indefinitely. All three are event-driven or scheduled background paths with no HTTP request
/// behind them, which is why the activity write below carries a reasoned audit-attribution
/// opt-out rather than a source IP or actor.
/// </summary>
public sealed class SbomPolicyEvaluationService
{
    private readonly SbomPolicyRepository _repo;
    private readonly OrgRepository _orgs;
    private readonly LicenseRepository _licenses;
    private readonly AlertService _alerts;
    private readonly AuditRepository _audit;
    private readonly ILogger<SbomPolicyEvaluationService> _logger;

    public SbomPolicyEvaluationService(
        SbomPolicyRepository repo,
        OrgRepository orgs,
        LicenseRepository licenses,
        AlertService alerts,
        AuditRepository audit,
        ILogger<SbomPolicyEvaluationService> logger)
    {
        _repo = repo;
        _orgs = orgs;
        _licenses = licenses;
        _alerts = alerts;
        _audit = audit;
        _logger = logger;
    }

    public async Task<SbomPolicyEvaluationResult> EvaluateAndPersistAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        var settings = await _orgs.GetSettingsAsync(orgId, ct) ?? new OrgSettings { OrgId = orgId };
        var policy = new BlockPolicy(
            MinReleaseAgeHours: null,
            BlockDeprecatedMode: null,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance);

        var components = await _repo.LoadEvaluationContextAsync(orgId, projectVersionId, ct);

        var findings = new List<(string ComponentId, SbomPolicyFindingResult Finding)>();
        int unscannable = 0;
        int unscanned = 0;

        foreach (var component in components)
        {
            foreach (var finding in SbomPolicyEvaluator.Evaluate(component.Facts, policy))
            {
                findings.Add((component.ComponentId, finding));
            }

            CountCoverage(component, ref unscannable, ref unscanned);

            // The licence arm runs over every component, scannable or not: an unscannable row
            // still carries a declared licence, and licence enforcement is independent of
            // advisory coverage.
            if (settings.LicenseEnforcementMode == "block")
            {
                var licenseFinding = await EvaluateLicenseArmAsync(
                    orgId, component.Facts.Ecosystem, component.LicenseSpdx, ct);
                if (licenseFinding is not null)
                {
                    findings.Add((component.ComponentId, licenseFinding));
                }
            }
        }

        // A scannable component that was never successfully scanned is not evidence of a clean
        // bill of health — it is an open question. It must not read as 'pass' merely because
        // nothing scoreable produced a finding.
        string status = findings.Count > 0 ? "violation" : unscanned > 0 ? "warn" : "pass";

        await _repo.ReplaceFindingsAsync(orgId, projectVersionId, findings, ct);
        await _repo.SetPolicyStatusAsync(orgId, projectVersionId, status, ct);

        if (unscannable > 0)
        {
            _logger.LogInformation(
                "Project version {ProjectVersionId} (org {OrgId}) holds {Unscannable} unscannable "
                + "component(s) of {Total}; they are excluded from the unscanned arm and reported "
                + "in the analysis rollup.",
                projectVersionId, orgId, unscannable, components.Count);
        }

        if (findings.Count > 0)
        {
            await RaiseAlertAndActivityAsync(orgId, projectVersionId, findings.Count, ct);
        }

        return new SbomPolicyEvaluationResult(status, findings.Count);
    }

    /// <summary>
    /// Buckets one component's advisory coverage.
    ///
    /// <para>Unscannable and unscanned are different statements, and only one of them is an open
    /// question. 'warn' means a scan could still answer something: the source was unreachable, or
    /// the row is still queued. A component with no parseable purl, no ecosystem, or an ecosystem
    /// OSV publishes no feed for will never be answerable by any pass, so folding it into that
    /// bucket pins the version at 'warn' permanently — destroying the signal rather than preserving
    /// it, because an operator who can never reach 'pass' stops reading the field. Those rows are
    /// counted and surfaced instead. A scannable component that is genuinely still unstamped keeps
    /// forcing 'warn'.</para>
    /// </summary>
    private static void CountCoverage(
        SbomComponentEvaluationInput component, ref int unscannable, ref int unscanned)
    {
        if (!SbomScannableComponents.IsScannable(component.Facts.Ecosystem, component.Purl))
        {
            unscannable++;
        }
        else if (component.Facts.VulnCheckedAt is null)
        {
            unscanned++;
        }
    }

    private async Task RaiseAlertAndActivityAsync(
        string orgId, string projectVersionId, int findingCount, CancellationToken ct)
    {
        var label = await _repo.GetVersionLabelAsync(orgId, projectVersionId, ct);
        string projectName = label?.ProjectName ?? "unknown project";
        string versionLabel = label?.VersionLabel ?? "unknown version";

        await _alerts.RaiseSbomPolicyViolationAlertAsync(
            orgId, projectVersionId, projectName, versionLabel, findingCount, ct);

        string detail = JsonSerializer.Serialize(
            new { project_version_id = projectVersionId, finding_count = findingCount },
            EventJsonOptions.Detail);

        try
        {
            // Policy evaluation runs on the scan-completion / VEX-change background path — there
            // is no HTTP request and so no client IP, and no single actor to attribute a
            // scan-triggered re-evaluation to.
            // audit-attribution-ok: background scan/VEX evaluation pass, no per-request actor or source IP
            await _audit.LogActivityAsync(
                orgId, "system", null, "sbom_policy_violation", detail: detail, ct: ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Failed to write the sbom_policy_violation activity row for project version {ProjectVersionId} (org {OrgId}); findings and alert still persisted.",
                projectVersionId, orgId);
        }
    }

    // Licence arm: mirrors BlockGateService.EvaluateLicenseArmAsync's empty-entries posture
    // (DeclaredLicenseEcosystems blocks on absence, the rest pass through) over a component's
    // single SPDX expression rather than package_version_licenses's multi-row set.
    private async Task<SbomPolicyFindingResult?> EvaluateLicenseArmAsync(
        string orgId, string? ecosystem, string? licenseSpdx, CancellationToken ct)
    {
        List<string> entries = string.IsNullOrWhiteSpace(licenseSpdx) ? [] : [licenseSpdx];

        if (entries.Count == 0)
        {
            return ecosystem is not null && BlockGateService.DeclaredLicenseEcosystems.Contains(ecosystem)
                ? LicenseFinding(BlockGateService.NoLicenseAssertion)
                : null;
        }

        var verdict = await _licenses.CheckPolicyAsync(orgId, "block", entries, ct);
        return verdict.Allowed ? null : LicenseFinding(verdict.BlockedLicense);
    }

    private static SbomPolicyFindingResult LicenseFinding(string? offendingLicense) =>
        new("license", null, offendingLicense,
            JsonSerializer.Serialize(new { license = offendingLicense }, EventJsonOptions.Detail));
}
