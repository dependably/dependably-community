namespace Dependably.Security;

/// <summary>
/// Capability strings and role mappings per the RBAC matrix. Capabilities are
/// fine-grained permission strings; tokens carry an explicit subset and roles map to a
/// fixed set. Capabilities are the single source of truth for permission checks — the
/// legacy <c>scope</c> column was retired in PR-7 / followup.
///
/// 1:1 tenancy stance (overrides the multi-tenant user model): every user belongs to
/// exactly one tenant. Cross-tenant work happens only via the system_admin operator
/// dashboard with an audited assume-tenant flow. The roles defined here therefore apply
/// within a tenant only; the platform-admin level is represented by the
/// <c>system_admin</c> role on the JWT (resolved via <see cref="ForPlatformAdmin"/> to
/// grant <c>platform:*</c>).
///
/// Naming convention: every capability is <c>&lt;domain&gt;:&lt;action_or_target&gt;</c>
/// — two segments, lower-case. The only sanctioned wildcards are <c>platform:*</c>
/// (operator override) and the global <c>*</c> (currently unused). Family wildcards
/// like <c>publish:*</c> remain in the vocabulary as role-level shorthand (the admin
/// role grants <c>publish:*</c> rather than enumerating leaves); callers may request
/// either the wildcard or per-ecosystem leaves (<c>publish:npm</c>, <c>publish:pypi</c>,
/// <c>publish:nuget</c>).
/// </summary>
public static class Capabilities
{
    // ── Read ────────────────────────────────────────────────────────────────────
    public const string ReadMetadata = "read:metadata";
    public const string ReadArtifact = "read:artifact";
    public const string ReadPackages = "read:packages";
    public const string ReadClaims   = "read:claims";
    public const string ReadAudit    = "read:audit";
    public const string ReadTenant   = "read:tenant";

    // ── Publish (per-ecosystem and wildcard) ────────────────────────────────────
    public const string PublishNpm   = "publish:npm";
    public const string PublishPypi  = "publish:pypi";
    public const string PublishNuget = "publish:nuget";
    public const string PublishMaven = "publish:maven";
    public const string PublishRpm   = "publish:rpm";
    public const string PublishOci   = "publish:oci";
    public const string PublishAll   = "publish:*";

    // ── Import (per-ecosystem and wildcard) ─────────────────────────────────────
    public const string ImportNpm    = "import:npm";
    public const string ImportPypi   = "import:pypi";
    public const string ImportNuget  = "import:nuget";
    public const string ImportMaven  = "import:maven";
    public const string ImportRpm    = "import:rpm";
    public const string ImportOci    = "import:oci";
    public const string ImportAll    = "import:*";

    // OCI also needs a "pull" capability for the proxy path — pure read of a public-repo
    // image doesn't need publish. read:artifact already covers this for other ecosystems.
    public const string PullOci      = "pull:oci";

    // ── Yank (per-ecosystem and wildcard) ───────────────────────────────────────
    public const string YankNpm   = "yank:npm";
    public const string YankPypi  = "yank:pypi";
    public const string YankNuget = "yank:nuget";
    public const string YankMaven = "yank:maven";
    public const string YankRpm   = "yank:rpm";
    public const string YankOci   = "yank:oci";
    public const string YankAll   = "yank:*";

    // ── Manage ─────────────────────────────────────────────────────────────────
    public const string ClaimManage     = "claim:manage";
    public const string TenantConfigure = "tenant:configure";
    public const string TenantAdmin     = "tenant:admin";
    public const string ManageOwnTokens = "tokens:manage_own";

    // ── Platform (system_admin operator role) ───────────────────────────────────
    public const string PlatformAll = "platform:*";

    // ── Wildcards ──────────────────────────────────────────────────────────────
    public const string EverythingTheUserCanDo = "*";

    private static readonly IReadOnlySet<string> ReaderCaps = new HashSet<string>
    {
        ReadMetadata, ReadArtifact, ReadPackages, ReadClaims, ManageOwnTokens
    };

    private static readonly IReadOnlySet<string> PublisherCaps = new HashSet<string>(ReaderCaps)
    {
        PublishAll, ImportAll, YankAll
    };

    private static readonly IReadOnlySet<string> ClaimManagerCaps = new HashSet<string>(ReaderCaps)
    {
        ClaimManage
    };

    private static readonly IReadOnlySet<string> AuditorCaps = new HashSet<string>
    {
        ReadAudit, ManageOwnTokens
    };

    // admin = publisher + claim-manager + read:tenant + read:audit + tenant:configure.
    // The owner-only privilege is tenant:admin (added below) — the only capability that
    // distinguishes owner from admin within the tenant.
    private static readonly IReadOnlySet<string> AdminCaps =
        new HashSet<string>(PublisherCaps.Concat(ClaimManagerCaps))
        {
            ReadTenant, ReadAudit, TenantConfigure
        };

    private static readonly IReadOnlySet<string> TenantAdminCaps = new HashSet<string>(AdminCaps)
    {
        TenantAdmin
    };

    private static readonly IReadOnlySet<string> PlatformAdminCaps = new HashSet<string>
    {
        PlatformAll, ReadMetadata, ReadArtifact, ReadPackages, ReadClaims, ReadAudit, ReadTenant,
        ManageOwnTokens
    };

    /// <summary>
    /// Returns the capability set granted by the user's tenant role. Existing roles map as:
    /// <c>member</c> → reader caps,
    /// <c>admin</c> → publisher + claim-manager + read:tenant + read:audit + tenant:configure,
    /// <c>owner</c> → admin caps + tenant:admin (everything within the tenant),
    /// <c>auditor</c> → audit-read + manage-own-tokens.
    /// Unknown roles get the empty set.
    /// </summary>
    public static IReadOnlySet<string> ForRole(string role) => role switch
    {
        "member"   => ReaderCaps,
        "admin"    => AdminCaps,
        "owner"    => TenantAdminCaps,
        "auditor"  => AuditorCaps,
        _ => new HashSet<string>()
    };

    /// <summary>
    /// Capability set for the operator (<c>system_admin</c> role on the JWT). Platform
    /// admins read everything but to write to tenant-scoped data they assume a tenant role
    /// temporarily — see <c>system.assume_tenant_role</c> audit event.
    /// </summary>
    public static IReadOnlySet<string> ForPlatformAdmin() => PlatformAdminCaps;

    /// <summary>
    /// Returns true if the requested capability is satisfied by any of the granted
    /// capabilities. Honors wildcards: <c>publish:*</c> grants <c>publish:npm</c>;
    /// <c>platform:*</c> grants any platform capability; <c>*</c> grants anything.
    /// </summary>
    public static bool Grants(IReadOnlySet<string> granted, string requested)
    {
        if (granted.Contains(EverythingTheUserCanDo)) return true;
        if (granted.Contains(requested)) return true;

        var colon = requested.IndexOf(':');
        if (colon < 0) return false;
        var family = string.Concat(requested.AsSpan(0, colon + 1), "*");
        return granted.Contains(family);
    }

    /// <summary>
    /// The closed vocabulary of capability strings a client may request when minting a
    /// token. Excludes the global and platform wildcards (system-internal only). Family
    /// wildcards <c>publish:*</c> / <c>import:*</c> / <c>yank:*</c> are allowed so admin
    /// callers can mint broad publisher tokens without enumerating every ecosystem.
    /// </summary>
    public static readonly IReadOnlySet<string> Requestable = new HashSet<string>(StringComparer.Ordinal)
    {
        ReadMetadata, ReadArtifact, ReadPackages, ReadClaims, ReadAudit, ReadTenant,
        PublishNpm, PublishPypi, PublishNuget, PublishMaven, PublishRpm, PublishOci, PublishAll,
        ImportNpm, ImportPypi, ImportNuget, ImportMaven, ImportRpm, ImportOci, ImportAll,
        YankNpm, YankPypi, YankNuget, YankMaven, YankRpm, YankOci, YankAll,
        PullOci,
        ClaimManage, TenantConfigure, TenantAdmin, ManageOwnTokens,
    };

    /// <summary>
    /// The trust-boundary pipeline for token issuance. Parses, validates, and authorizes a
    /// requested capability list in one step. Returns canonical JSON (sorted, deduped) on
    /// success; on failure populates <paramref name="error"/> and <paramref name="field"/>
    /// with a single offending field name so the controller can return a 400 with the same
    /// shape every time.
    ///
    /// Rules, in order:
    /// <list type="number">
    ///   <item>Non-null and non-empty.</item>
    ///   <item>Every entry is a known capability from <see cref="Requestable"/>.</item>
    ///   <item>No duplicates (case-sensitive; vocabulary is lower-case).</item>
    ///   <item>Every entry is satisfied by <paramref name="callerGrants"/> via
    ///         <see cref="Grants"/> — no privilege escalation.</item>
    /// </list>
    /// </summary>
    public static bool TryNormalizeAndAuthorize(
        IReadOnlyList<string>? requested,
        IReadOnlySet<string> callerGrants,
        out string canonicalJson,
        out string[] capabilities,
        out string? error,
        out string? field)
    {
        canonicalJson = "";
        capabilities = Array.Empty<string>();
        error = null;
        field = null;

        if (requested is null || requested.Count == 0)
        {
            field = "capabilities";
            error = "At least one capability is required.";
            return false;
        }

        var entries = new List<string>(requested.Count);
        foreach (var c in requested)
        {
            if (string.IsNullOrWhiteSpace(c))
            {
                field = "capabilities";
                error = "Capability entries must be non-empty strings.";
                return false;
            }
            entries.Add(c.Trim());
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var dups = entries.Where(c => !seen.Add(c)).Distinct(StringComparer.Ordinal).ToList();
        if (dups.Count > 0)
        {
            field = "capabilities";
            error = $"Duplicate capabilities: {string.Join(", ", dups)}.";
            return false;
        }

        var unknown = entries.Where(c => !Requestable.Contains(c)).ToList();
        if (unknown.Count > 0)
        {
            field = "capabilities";
            error = $"Unknown capabilities: {string.Join(", ", unknown)}.";
            return false;
        }

        var ungranted = entries.Where(c => !Grants(callerGrants, c)).ToList();
        if (ungranted.Count > 0)
        {
            field = "capabilities";
            error = $"Requested capabilities exceed your role: {string.Join(", ", ungranted)}.";
            return false;
        }

        capabilities = entries.OrderBy(c => c, StringComparer.Ordinal).ToArray();
        canonicalJson = System.Text.Json.JsonSerializer.Serialize(capabilities);
        return true;
    }
}
