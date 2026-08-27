namespace Dependably.Infrastructure;

/// <summary>
/// The triage bucket an advisory lands in for one project version, derived at READ time from every
/// exploitation/decision-support signal the platform already stores against it: the advisory's own
/// CVSS score with an NVD-overlay fallback, the CISA KEV flag and its ransomware-campaign
/// assertion, EPSS probability and percentile, CISA Vulnrichment SSVC exploitation state, the VEX
/// analysis state, SARIF-reported reachability, and — on the projects plane only — the
/// dependency-graph position (kind/scope) and install-script presence.
///
/// <para><b>Never materialized.</b> KEV, EPSS, NVD, and SSVC are refreshed on the shared
/// <c>vulnerabilities</c> row by the threat-feed and enrichment passes, and VEX/reachability land
/// on a per-(component, advisory) row. A stored bucket would keep serving the verdict that was true
/// when the SBOM was scanned; deriving on the read path means a KEV catalog addition, an EPSS jump,
/// or a fresh enrichment pass changes what an operator sees on the very next request, with no
/// re-stamp pass and no window in which the stored answer and the stored inputs disagree.</para>
///
/// <para>The rules, top-down. Rule 1 (suppression) and rule 2 (top-tier exploitation evidence) are
/// each final — the first that fires decides the verdict outright. Rules 3–4 compose in order over
/// everything that falls through both.</para>
/// <list type="number">
///   <item>A VEX state saying the product is not exploitable — <c>not_affected</c>,
///   <c>false_positive</c>, <c>resolved</c> — is <see cref="Suppressed"/>.</item>
///   <item><b>Top-tier evidence of exploitation, any one of which is <see cref="Act"/> outright,
///   whatever the score:</b> the advisory is CISA-KEV-listed; CISA explicitly marks the KEV entry
///   as ransomware-campaign use; CISA Vulnrichment SSVC exploitation is <c>active</c> (an
///   <em>observation</em>, strictly better evidence than EPSS, which is a predicted probability);
///   the EPSS percentile is in the top decile
///   (&gt;= <see cref="EpssPercentileActThreshold"/>, an axis independent of the raw probability —
///   the same reasoning the block gate's separate EPSS-percentile arm already applies, per
///   <c>ARCH-block-gate</c>); the EPSS probability and the effective CVSS both cross their own
///   thresholds; or <see cref="VulnFacts.IsMalicious"/> is true — an advisory recorded under the
///   <c>MAL-</c> OSV prefix names a package that is itself the attack, not a vulnerable dependency
///   with a score to weigh, so it forces <see cref="Act"/> the same way KEV listing does rather
///   than entering the base-bucket/adjustment arithmetic in rule 3. <see cref="VulnFacts.IsKevRansomware"/>
///   is written only when <see cref="VulnFacts.IsKev"/> is already true (<c>SetKevAsync</c> only
///   ever populates ransomware context alongside KEV membership), so in practice this arm never
///   fires independently of the KEV arm today — it is still evaluated as its own condition,
///   defense-in-depth, and to keep the rule composable if a future feed ever separates the two
///   facts.</item>
///   <item><b>Base bucket, then a single accumulated adjustment.</b> The base bucket comes from
///   <see cref="VulnFacts.EffectiveCvss"/> (the advisory's own CVSS score, or the NVD overlay's
///   when OSV carries none): 7.0 and above starts at <see cref="Attend"/>, everything else —
///   including unscored — starts at <see cref="Track"/>. Every adjustment below is collected as a
///   signed delta and applied <em>once</em>, after summing, against the ladder's clamp — never as
///   separate sequential clamps per step, which would make the result depend on the order the
///   deltas happen to be listed in:
///   <list type="bullet">
///     <item><c>DependencyKind == "transitive"</c> demotes by one. Every other value — including
///     <c>"graph-unknown"</c>, an explicit statement of not knowing rather than of position, and a
///     null value — leaves this term at zero. Absence is unknown, never benign, so only the
///     unambiguous "transitive" value may demote.</item>
///     <item><c>DependencyScope == "dev"</c> demotes by one. Every other value — including
///     <c>"unknown"</c> and null — leaves this term at zero.</item>
///     <item>Reachability <c>"reachable"</c> promotes by one. Reachability <c>"not-observed"</c>
///     demotes by one, <b>unless <see cref="PriorityFacts.HasInstallScript"/> is true, in which
///     case this term contributes zero instead</b> — a package whose code is never imported but
///     whose install script runs on every install executes regardless of what a static
///     reachability scan observed, so "not observed" must not read as "safe" for it. Every other
///     reachability value — <c>"imported-not-called"</c>, <c>"unknown"</c>, null — leaves this term
///     at zero.</item>
///     <item><see cref="PriorityFacts.HasInstallScript"/> promotes by one, independent of and
///     additive with the reachability term above — a component can gain both this promotion and
///     have its would-be reachability demotion suppressed to zero, netting a promotion of one
///     rather than a wash.</item>
///   </list>
///   The final rank is the base bucket's rank plus the summed delta, clamped once to the
///   <see cref="Track"/>–<see cref="Act"/> range.</item>
///   <item><b>Floors, applied last, after the clamp above.</b> A VEX state of <c>exploitable</c>
///   floors the result at <see cref="Attend"/> (existing). CISA Vulnrichment SSVC exploitation of
///   <c>poc</c> also floors at <see cref="Attend"/> (new) — weaker evidence than <c>active</c>,
///   which already forces <see cref="Act"/> in rule 2, but a proof-of-concept existing without
///   confirmed active exploitation is stronger than nothing and still earns a floor rather than
///   being left to the base/adjustment arithmetic alone.</item>
/// </list>
///
/// <para><b><c>KevDueDate</c> is deliberately NOT consumed by this rule set.</b> Rule 2 already
/// floors any KEV-listed advisory at <see cref="Act"/> unconditionally, so a due date has no
/// remaining bucket left to move an advisory to — it could only matter for ordering <em>within</em>
/// <see cref="Act"/>, which <see cref="PriorityVerdict"/>'s two-field shape (bucket, unscored) has
/// no room to express. Making <see cref="Derive"/> compare the due date against the current time
/// would also require injecting a clock into a function this codebase documents and tests as pure
/// and time-independent, for a signal that provably cannot change the bucket it returns.
/// <c>KevDueDate</c> stays available on <see cref="VulnFacts"/> for a future consumer — export or
/// UI surfacing, not ranking — to read directly.</para>
///
/// <para><see cref="PriorityVerdict.Unscored"/> reports that no CVSS score exists for the advisory
/// from either source — neither the advisory's own nor the NVD overlay's — independently of which
/// rule decided the bucket. It is not "low severity": a KEV advisory nobody scored is both
/// <see cref="Act"/> and unscored, and the reader is entitled to know the score is missing rather
/// than seeing a blank cell that reads as "fine".</para>
///
/// <para><c>resolved_with_pedigree</c> is deliberately NOT a suppressing state here. It asserts a
/// fix carried with provenance the platform does not yet verify, so the advisory keeps its derived
/// bucket and stays visible; the state itself is still rendered beside the row.</para>
///
/// <para><b>Absent is unknown, never benign.</b> Every new signal's absent value (null SSVC
/// exploitation, null EPSS percentile, a null tri-state ransomware flag, a false
/// <see cref="VulnFacts.IsMalicious"/> flag, null dependency kind/scope, a false install-script
/// flag) leaves its own term at zero rather than demoting — verified by
/// <c>EffectivePriorityTests</c>' upgrade-safety property, which pins that a
/// <see cref="PriorityFacts"/> built with every new field at its absent default reproduces the
/// exact verdict this method returned before these fields existed. An unconfigured optional
/// tracker connection (SSVC/NVD both null for every advisory) therefore changes no existing
/// deployment's ranking on upgrade, and a caller that has not yet populated
/// <see cref="VulnFacts.IsMalicious"/> gets the pre-existing verdict rather than a spurious
/// <see cref="Act"/>.</para>
/// </summary>
public static class EffectivePriority
{
    /// <summary>Recorded and watched, not scheduled.</summary>
    public const string Track = "track";

    /// <summary>Needs a decision this cycle.</summary>
    public const string Attend = "attend";

    /// <summary>Needs a decision now.</summary>
    public const string Act = "act";

    /// <summary>A VEX statement says this advisory does not apply to this product.</summary>
    public const string Suppressed = "suppressed";

    /// <summary>CVSS at or above which an advisory starts at <see cref="Attend"/>.</summary>
    public const double HighCvssThreshold = 7.0;

    /// <summary>EPSS probability at or above which a high-CVSS advisory jumps straight to <see cref="Act"/>.</summary>
    public const double EpssActThreshold = 0.10;

    /// <summary>
    /// EPSS percentile at or above which an advisory jumps straight to <see cref="Act"/>, whatever
    /// its score. Top-decile — a commonly used EPSS operational threshold for "highly likely to be
    /// exploited relative to every other scored vulnerability" — and deliberately independent of
    /// the raw probability threshold above: <see cref="EpssActThreshold"/> and this constant answer
    /// different questions (how likely, versus how likely relative to everything else), the same
    /// distinction the block gate's separate EPSS-percentile arm already draws.
    /// </summary>
    public const double EpssPercentileActThreshold = 0.90;

    /// <summary>The VEX states that mean "this advisory does not apply to this product".</summary>
    public static readonly IReadOnlySet<string> SuppressingVexStates =
        new HashSet<string>(StringComparer.Ordinal) { "not_affected", "false_positive", "resolved" };

    /// <summary>The VEX state that floors an advisory at <see cref="Attend"/>.</summary>
    public const string ExploitableVexState = "exploitable";

    /// <summary>Reachability value that promotes the base bucket one step.</summary>
    public const string ReachableValue = "reachable";

    /// <summary>
    /// Reachability value that demotes the base bucket one step, unless
    /// <see cref="PriorityFacts.HasInstallScript"/> suppresses the demotion.
    /// </summary>
    public const string NotObservedValue = "not-observed";

    /// <summary>SSVC exploitation state that forces <see cref="Act"/> in rule 2.</summary>
    public const string ActiveSsvcExploitation = "active";

    /// <summary>SSVC exploitation state that floors an advisory at <see cref="Attend"/> in rule 4.</summary>
    public const string PocSsvcExploitation = "poc";

    /// <summary>Dependency kind that demotes the base bucket one step.</summary>
    public const string TransitiveDependencyKind = "transitive";

    /// <summary>Dependency scope that demotes the base bucket one step.</summary>
    public const string DevDependencyScope = "dev";

    // Ordinal ladder the adjustment and the floors move along. Suppressed is deliberately absent
    // from it: rule 1 is final, so nothing ever steps into or out of that bucket.
    private const int TrackRank = 1;
    private const int AttendRank = 2;
    private const int ActRank = 3;

    /// <summary>
    /// Derives the bucket for one advisory. Pure: the same inputs always produce the same verdict,
    /// which is what makes the whole surface assertable against frozen fixtures.
    /// </summary>
    public static PriorityVerdict Derive(PriorityFacts facts)
    {
        var vuln = facts.Vulnerability;
        double? effectiveCvss = vuln.EffectiveCvss;
        bool unscored = effectiveCvss is null;
        string? state = NormalizeState(facts.VexState);

        if (state is not null && SuppressingVexStates.Contains(state))
        {
            return new PriorityVerdict(Suppressed, unscored);
        }

        if (HasTopTierExploitationEvidence(vuln, effectiveCvss))
        {
            return new PriorityVerdict(Act, unscored);
        }

        int baseRank = effectiveCvss >= HighCvssThreshold ? AttendRank : TrackRank;
        int rank = Math.Clamp(baseRank + AdjustmentFor(facts), TrackRank, ActRank);

        if (rank < AttendRank && (state == ExploitableVexState || vuln.SsvcExploitation == PocSsvcExploitation))
        {
            rank = AttendRank;
        }

        return new PriorityVerdict(BucketFor(rank), unscored);
    }

    /// <summary>
    /// Rule 2: evidence-of-exploitation signals evaluated together, any one of which is decisive.
    /// Order among the arms does not matter — they all produce the same outcome.
    /// </summary>
    private static bool HasTopTierExploitationEvidence(VulnFacts vuln, double? effectiveCvss) =>
        vuln.IsKev
        || vuln.IsKevRansomware == true
        || vuln.SsvcExploitation == ActiveSsvcExploitation
        || vuln.EpssPercentile >= EpssPercentileActThreshold
        || (vuln.Epss >= EpssActThreshold && effectiveCvss >= HighCvssThreshold)
        || vuln.IsMalicious;

    /// <summary>
    /// Rule 3's adjustment: every delta summed before the ladder is clamped once, so the result
    /// never depends on the order the individual terms happen to be evaluated in.
    /// </summary>
    private static int AdjustmentFor(PriorityFacts facts)
    {
        int delta = 0;

        if (facts.DependencyKind == TransitiveDependencyKind)
        {
            delta -= 1;
        }

        if (facts.DependencyScope == DevDependencyScope)
        {
            delta -= 1;
        }

        string? reachability = NormalizeReachability(facts.Reachability);
        if (reachability == ReachableValue)
        {
            delta += 1;
        }
        else if (reachability == NotObservedValue && !facts.HasInstallScript)
        {
            delta -= 1;
        }

        if (facts.HasInstallScript)
        {
            delta += 1;
        }

        return delta;
    }

    /// <summary>
    /// Sort weight for a bucket: higher is more urgent. <see cref="Suppressed"/> ranks below
    /// <see cref="Track"/> so a suppressed advisory never outranks one still in play, and an
    /// unrecognised value ranks below everything rather than being silently promoted.
    /// </summary>
    public static int RankOf(string? bucket) => bucket switch
    {
        Act => 4,
        Attend => 3,
        Track => 2,
        Suppressed => 1,
        _ => 0,
    };

    /// <summary>
    /// Canonical spelling of a reachability value: lowercase, with spaces and underscores folded to
    /// the hyphenated form the schema stores. A producer that wrote <c>not_observed</c> then lands
    /// on the arm its author meant instead of silently taking the no-change branch.
    /// </summary>
    public static string? NormalizeReachability(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : value.Trim().ToLowerInvariant().Replace(' ', '-').Replace('_', '-');

    private static string BucketFor(int rank) => rank switch
    {
        ActRank => Act,
        AttendRank => Attend,
        _ => Track,
    };

    // VEX states are an underscore vocabulary, so only case and surrounding whitespace are folded
    // here — replacing underscores the way reachability does would turn not_affected into a value
    // no arm recognises.
    private static string? NormalizeState(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToLowerInvariant();
}

/// <summary>
/// One advisory's derived triage bucket plus the uncertainty flag that travels with it.
/// <see cref="Unscored"/> ships beside <see cref="Bucket"/> rather than folded into it, so the UI
/// can render "UNSCORED"/"NO CVSS" instead of a blank score cell.
/// </summary>
public readonly record struct PriorityVerdict(string Bucket, bool Unscored);

/// <summary>
/// Everything <see cref="EffectivePriority.Derive(PriorityFacts)"/> needs to decide one advisory's
/// triage bucket: the vulnerability's own exploitation/decision-support signals plus the facts that
/// live on the (component, advisory) pair or the component itself rather than the vulnerability —
/// VEX disposition, SARIF-reported reachability, dependency-graph position, and install-script
/// presence. Built by a factory rather than field-by-field, mirroring <c>BlockGateRequest</c>'s own
/// construction discipline: a field a call site forgets to set silently defaults to null/false,
/// which every arm above reads as "signal absent" rather than failing loudly.
/// </summary>
public readonly record struct PriorityFacts(
    VulnFacts Vulnerability,
    string? VexState,
    string? Reachability,
    string? DependencyKind,
    string? DependencyScope,
    bool HasInstallScript)
{
    /// <summary>
    /// The registry plane has no VEX statements, reachability data, or dependency-graph position —
    /// those are projects-plane concepts — and no install-script signal wired into priority either,
    /// so a registry-plane caller building <see cref="PriorityFacts"/> supplies none of them.
    /// </summary>
    public static PriorityFacts ForRegistryPlane(VulnFacts vulnerability) =>
        new(vulnerability, VexState: null, Reachability: null,
            DependencyKind: null, DependencyScope: null, HasInstallScript: false);

    /// <summary>
    /// The projects plane supplies every signal: a linked VEX statement, SARIF-reported
    /// reachability, the component's dependency-graph position, and whether this coordinate's
    /// artefact is known (via a best-effort registry cross-link — <c>sbom_components</c> itself
    /// carries no install-script column) to ship an install/lifecycle script.
    /// </summary>
    public static PriorityFacts ForProjectsPlane(
        VulnFacts vulnerability,
        string? vexState,
        string? reachability,
        string? dependencyKind,
        string? dependencyScope,
        bool hasInstallScript) =>
        new(vulnerability, vexState, reachability, dependencyKind, dependencyScope, hasInstallScript);
}
