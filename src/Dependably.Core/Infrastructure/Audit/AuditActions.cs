using System.Collections.Immutable;

namespace Dependably.Infrastructure.Audit;

/// <summary>
/// The declared vocabulary of <c>audit_log.action</c> values, and the matching rules the SIEM
/// auth feed's <c>action=</c> filter applies to them.
///
/// <para>
/// Action names used to be string literals at ~160 call sites with nothing declaring the set. Two
/// consequences shipped: the same event was written under two spellings
/// (<c>project.create</c>/<c>project.created</c>), and the reader side drifted away from the
/// writers entirely — the feed's default filter advertised <c>token.</c> and <c>rbac.</c> families
/// that no writer has ever emitted, so a collector trusting the default believed it had token and
/// RBAC coverage and had neither. A declared vocabulary is what lets a static gate
/// (<c>AuditActionVocabularyComplianceTests</c>) reject an undeclared literal, reject a name the
/// CEF table maps but nothing writes, and let <c>GET /api/v1/siem/actions</c> tell a collector
/// what it is not subscribed to — which no query over the rows can do, because a row only exists
/// after the event nobody was listening for.
/// </para>
///
/// <para>
/// Adding an action is two steps: write it, and declare it here in the right group. The gate
/// fails on step one without step two.
/// </para>
/// </summary>
public static class AuditActions
{
    /// <summary>
    /// The security feed: the events a SOC triages — authentication and session, credential
    /// lifecycle, privilege and membership change, identity-provider trust, supply-chain
    /// integrity failures and policy refusals, tenant lifecycle, and bulk personal-data egress.
    /// A collector that sends no <c>action=</c> parameter receives exactly this set.
    ///
    /// <para>
    /// The line against <see cref="OperationalActions"/> is triage value, not importance:
    /// changing an allowlist, a licence policy, a retention window or an upstream registry is
    /// compliance-audit material — reviewed after the fact, from the audit page or an export —
    /// while a refusal, a credential mint and a role change are things a SOC alerts on. A
    /// *refusal* produced by one of those policies (<c>allowlist_blocked</c>,
    /// <c>quarantine_decision</c>) is therefore in the security set even though the policy edit
    /// that armed it is not.
    /// </para>
    ///
    /// <para>
    /// Everything the previous prefix-shaped default matched (<c>login.</c>, <c>lockout.</c>,
    /// <c>auth.</c>, <c>ratelimit.</c>) is named here, so no collector loses an event family it
    /// receives today. The two dead prefixes it also carried are what this set replaces: the
    /// credential and RBAC events <c>token.</c>/<c>rbac.</c> promised are the flat
    /// <c>token_created</c>/<c>member_role_changed</c> names below.
    /// </para>
    /// </summary>
    private static readonly ImmutableArray<string> SecurityRelevantActions =
    [
        // Authentication, session and MFA.
        "login.success",
        "login.failure",
        "lockout.triggered",
        "auth.login.failure",
        "auth.saml.login.success",
        "auth.saml.login.failure",
        "auth.saml.test.success",
        "auth.saml.user_provisioned",
        "auth.saml.user_linked",
        "auth.saml.role_assigned",
        "auth.saml.role_changed",
        "auth.saml.role_change_refused",
        "auth.saml.role_mapping_blocked",
        "mfa.enrolled",
        "mfa.disabled",
        "mfa.recovery_codes_regenerated",
        "mfa.recovery_code_used",
        "mfa.trusted_device_added",
        "mfa.trusted_device_used",

        // Refusals: credential, capability, rate limit, scope.
        "auth.token.rejected",
        "auth.capability.denied",
        "ratelimit.rejected",
        "oci.scope_denied",
        "metrics.scrape_denied",

        // Credential lifecycle.
        "token_created",
        "token_revoked",
        "service_token_created",
        "service_token_revoked",
        "hex_signing_key_rotated",
        "sbom_signing_key_rotated",
        "system_admin.jwt_secret_rotated",
        "user.password_changed",
        "user.password_reset",
        "user.password_reset_requested",
        "user.email_change_requested",
        "user.email_changed",
        "system_admin.password_changed",
        "system_admin.password_reset",
        "system_admin.admin_password_reset",

        // Privilege and membership.
        "member_role_changed",
        "member_removed",
        "invite_created",
        "invite_deleted",
        "invite_accept_blocked",
        "name_grant_added",
        "name_grant_revoked",
        "system_admin.admin_created",
        "system_admin.admin_deleted",
        "system_admin.account_status_changed",
        "system_admin.admin_account_status_changed",
        "system_admin.user_lookup",

        // Identity-provider trust.
        "saml.config_updated",
        "saml.config_deleted",
        "saml.metadata_uploaded",
        "saml.signing_cert_set",
        "saml.signing_cert_cleared",
        "saml.signing_cert_expiring",
        "saml.signing_cert_expired",

        // Supply-chain integrity and policy refusals.
        "checksum_failure",
        "ssrf_blocked",
        "provenance_verification_failed",
        "sbom_signature_blocked",
        "upstream_source_pin_violation",
        "upstream_response_too_large",
        "proxy_serve_facts_unreadable",
        "allowlist_blocked",
        "conflict_resolved",
        "quarantine_decision",
        "package_version_blocked",
        "package_version_unblocked",
        "package.override.set",
        "trust_anchor_added",
        "trust_anchor_removed",

        // Tenant lifecycle.
        "tenant.created",
        "tenant.deleted",
        "tenant.hard_deleted",
        "tenant.restored",
        "tenant.status_changed",

        // Bulk personal-data egress.
        "user.data_exported",
    ];

    /// <summary>
    /// The rest of the vocabulary: configuration, content and package-lifecycle events. Reachable
    /// by naming them (or their family) in <c>action=</c>, and listed by
    /// <c>GET /api/v1/siem/actions</c> with <c>security_relevant: false</c>, but not served to a
    /// collector that sends no filter.
    /// </summary>
    private static readonly ImmutableArray<string> OperationalActions =
    [
        // Package and project lifecycle.
        "push",
        "project.created",
        "project.updated",
        "project.deleted",
        "project.version_promoted",
        "project.version_retired",
        "project.version_reinstated",
        "project.version_deleted",
        "sbom.analysis.triage",
        // Recorded under 'warn' — the verdict this policy would have refused under 'block',
        // logged without refusing the upload. The 'block' refusal itself is
        // sbom_signature_blocked, in the security set above.
        "sbom_signature_warn",
        "claim.create",
        "claim.transition",
        "claim.release",

        // Tenant configuration.
        "tenant.quota_changed",
        "tenant.setting.change",
        "org_settings_updated",
        "proxy_settings_updated",
        "retention_updated",
        "alert_settings_updated",
        "alert_dismissed",
        "alert_dismissed_all",
        "banner.created",
        "banner.updated",
        "banner.deleted",

        // Policy configuration. The refusals these arm are in the security set above.
        "allowlist_added",
        "allowlist_removed",
        "blocklist_added",
        "blocklist_removed",
        "license_allowlist_added",
        "license_allowlist_removed",
        "license_allowlist_updated",
        "license_blocklist_added",
        "license_blocklist_removed",
        "license_blocklist_updated",
        "license_policy_mode_changed",
        "install_script_allowlist_added",
        "install_script_allowlist_removed",
        "reserved_namespace_added",
        "reserved_namespace_removed",

        // Proxy and integration configuration.
        "upstream_registry_added",
        "upstream_registry_removed",
        "upstream_registry_reordered",
        "upstream_registry_symbol_server_set",
        "webhook_subscription_added",
        "webhook_subscription_updated",
        "webhook_subscription_deleted",
        "webhook_test_sent",

        // Instance configuration. The two spellings are two writers, not a rename: the
        // `instance_*` rows come from the org-scoped settings surface and the `system_admin.*`
        // rows from the operator dashboard.
        "instance_email_config_updated",
        "instance_metrics_access_updated",
        "instance_settings_updated",
        "instance_vuln_tracker_config_tested",
        "instance_vuln_tracker_config_updated",
        "system_admin.email_config_updated",
        "system_admin.instance_settings_updated",
        "system_admin.metrics_access_updated",
        "system_admin.slack_config_updated",
        "system_admin.vuln_tracker_config_tested",
        "system_admin.vuln_tracker_config_updated",

        // User and operator preferences.
        "system_admin.language_changed",
        "system_admin.timezone_changed",
        "user.language_changed",
        "user.timezone_changed",
    ];

    /// <summary>Every declared <c>audit_log.action</c> value, security set first.</summary>
    public static readonly ImmutableArray<string> All =
        [.. SecurityRelevantActions, .. OperationalActions];

    /// <summary>
    /// The filter set applied when a caller sends no <c>action=</c> parameter. Exact names, never
    /// family prefixes — a family prefix silently enrolls every future member of that family into
    /// the default feed, which is how <c>system_admin.</c>-style families mix a timezone change in
    /// with a JWT-secret rotation.
    /// </summary>
    public static readonly ImmutableArray<string> DefaultFilters = SecurityRelevantActions;

    private static readonly ImmutableHashSet<string> AllSet =
        [.. All];

    /// <summary>
    /// Declared actions that are a strict dotted-prefix ancestor of another declared action —
    /// empty today, because the vocabulary is deliberately all leaves. It is computed rather than
    /// asserted so <see cref="IsDeclaredLeaf"/> stays correct on the day someone declares both
    /// <c>saml.config</c> and <c>saml.config.updated</c>, instead of silently starting to elide a
    /// family term that would then have had something to match.
    /// </summary>
    private static readonly ImmutableHashSet<string> DeclaredAncestors =
        [.. All.Where(a => All.Any(b => b.StartsWith(a + FamilySeparator, StringComparison.Ordinal)))];

    /// <summary>
    /// Every distinct dotted-family prefix the declared vocabulary implies but does not itself
    /// declare — <c>auth</c>, <c>auth.saml.login</c>, <c>system_admin</c>, <c>package.override</c>
    /// and the rest. These are exactly the filter values that are meaningful as families and
    /// nothing else: a caller naming one is asking for a group, and only such a filter needs the
    /// <c>LIKE</c> term that <c>AuditRepository.BuildActionPredicate</c> emits.
    /// <para>
    /// Its length is what bounds the family half of the auth feed's filter list
    /// (<c>AuditRepository.MaxAuthEventFamilyFilters</c>), so the bound tracks the vocabulary
    /// instead of being a number someone chose.
    /// </para>
    /// </summary>
    public static readonly ImmutableArray<string> ImpliedFamilyPrefixes =
    [
        .. All
            .SelectMany(DottedAncestorsOf)
            .Where(p => !AllSet.Contains(p))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
    ];

    private const string FamilySeparator = ".";

    private static IEnumerable<string> DottedAncestorsOf(string action)
    {
        for (int i = action.IndexOf('.'); i >= 0; i = action.IndexOf('.', i + 1))
        {
            yield return action[..i];
        }
    }

    /// <summary>
    /// True when <paramref name="filter"/> names a declared action that no other declared action
    /// sits under. Such a filter's dotted family is empty by construction, so the <c>LIKE</c> half
    /// of the feed's match rule can only match an action outside the declared vocabulary — which
    /// is why <c>AuditRepository.BuildActionPredicate</c> omits the term entirely for these. It is
    /// the same reasoning the no-filter default rests on, applied per filter rather than to the
    /// whole request, so caller-supplied and default filters cost the same.
    /// <para>
    /// That no declared action sits under another is a property of the vocabulary rather than a
    /// rule of the language, so it is a tripwire rather than an assumption:
    /// <c>AuditActionVocabularyComplianceTests</c> fails the day one does, and until someone has
    /// had that conversation this method keeps answering correctly either way.
    /// </para>
    /// </summary>
    public static bool IsDeclaredLeaf(string filter) =>
        AllSet.Contains(filter) && !DeclaredAncestors.Contains(filter);

    private static readonly ImmutableHashSet<string> SecuritySet =
        [.. SecurityRelevantActions];

    /// <summary>True when <paramref name="action"/> is part of the declared vocabulary.</summary>
    public static bool IsDeclared(string action) => AllSet.Contains(action);

    /// <summary>True when <paramref name="action"/> is served by the no-filter default feed.</summary>
    public static bool IsSecurityRelevant(string action) => SecuritySet.Contains(action);

    /// <summary>
    /// Canonical form of one caller-supplied <c>action=</c> value: a trailing family separator is
    /// dropped, so <c>login.</c> and <c>login</c> are the same filter. Callers wrote the trailing
    /// dot for years because it was the only form that matched anything, and both spellings keep
    /// working.
    /// </summary>
    public static string NormalizeFilter(string filter) => filter.TrimEnd('.');

    /// <summary>
    /// The feed's match rule, in the form the SQL implements: a filter matches the action of
    /// exactly that name, and every action in its dotted family.
    ///
    /// <para>
    /// The family half is the pre-existing prefix behaviour (<c>action=login.</c> → the
    /// <c>login.*</c> family) and collectors depend on it. The exact half is what made the flat
    /// names reachable at all: the filter used to append the family separator unconditionally, so
    /// every pattern was <c>&lt;value&gt;.%</c> and an action with no dot in it — 57 of them,
    /// <c>checksum_failure</c> and <c>token_created</c> among them — could not be matched by any
    /// value a caller was able to send.
    /// </para>
    ///
    /// <para>
    /// The family half is skipped for a filter naming a declared leaf (<see cref="IsDeclaredLeaf"/>):
    /// nothing declared sits under such a name, so the only rows the family half could add are ones
    /// outside the vocabulary, and <c>AuditRepository.BuildActionPredicate</c> omits the <c>LIKE</c>
    /// term for them rather than evaluating it against every row of the window. The rule is stated
    /// here the way the SQL implements it, because a reader reaching for one of the two has to be
    /// able to trust it describes the other.
    /// </para>
    ///
    /// <para>This is the C# statement of the rule; <c>AuditRepository.ListAuthEventsAsync</c>
    /// builds the equivalent bound predicate, and <c>AuditActionFilterParityTests</c> drives both
    /// over the same vocabulary so they cannot diverge.</para>
    /// </summary>
    public static bool Matches(string filter, string action)
    {
        string normalized = NormalizeFilter(filter);
        return string.Equals(action, normalized, StringComparison.Ordinal)
            || (!IsDeclaredLeaf(normalized)
                && action.StartsWith(normalized + FamilySeparator, StringComparison.Ordinal));
    }
}
