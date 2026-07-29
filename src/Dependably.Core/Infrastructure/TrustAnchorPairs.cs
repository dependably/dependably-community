namespace Dependably.Infrastructure;

/// <summary>
/// The canonical set of <c>(ecosystem, anchor_kind)</c> pairs a signature trust anchor may be
/// stored under. A pair outside this set has no material validator behind it, so the bytes in
/// <c>signature_trust_anchor.material</c> were never parsed, never checked for minimum key
/// strength, and can never produce a <c>verified</c> provenance verdict.
///
/// This set is the single source of truth for three consumers that must not drift apart:
/// <list type="bullet">
///   <item>the insert-time gate on <c>POST /api/v1/trust-anchors</c>, which refuses an
///   unregistered pair rather than storing arbitrary bytes as a trust root;</item>
///   <item><see cref="TrustAnchorRepository.ListSuspectAsync"/>, the cross-org audit read that
///   surfaces rows stored under an unregistered pair;</item>
///   <item><see cref="TrustAnchorEntry.IsRegisteredPair"/>, the per-row flag the settings UI
///   renders as a warning badge.</item>
/// </list>
///
/// A row stored under an unregistered pair is <em>not</em> automatically inert, and is never
/// removed automatically. Two consequences make deletion an operator decision:
/// <list type="number">
///   <item>For rpm, maven, npm, nuget and apk,
///   <see cref="IPerOrgTrustAnchorStore.IsConfiguredForAsync"/> tests only for the presence of a
///   row in the ecosystem, so such a row makes <c>verify_*_signatures = 'block'</c> read as
///   backed while no artifact can actually verify. Removing the row flips the same ecosystem to
///   denying every artifact, with no intermediate state.</item>
///   <item>The npm, nuget and apk material builders do not filter on <c>anchor_kind</c>, so a
///   row carrying the wrong kind label but well-formed material for that ecosystem is a real,
///   currently-verifying trust anchor.</item>
/// </list>
/// </summary>
public static class TrustAnchorPairs
{
    /// <summary>
    /// Every accepted <c>(ecosystem, anchor_kind)</c> pair, in the order the settings UI groups
    /// ecosystems. Each pair has a registered material validator on the add path.
    /// </summary>
    public static readonly IReadOnlyList<(string Ecosystem, string AnchorKind)> Registered =
    [
        ("rpm", "pgp"),
        ("maven", "pgp"),
        ("npm", "spki"),
        ("nuget", "x509"),
        ("pypi", "sigstore_root"),
        ("pypi", "trusted_publisher"),
        ("pypi", "rekor_key"),
        ("apk", "rsa"),
    ];

    private static readonly HashSet<(string Ecosystem, string AnchorKind)> Lookup = [.. Registered];

    /// <summary>
    /// True when the pair has a registered material validator. Ordinal comparison: both values
    /// are lowercased at the API boundary and stored verbatim.
    /// </summary>
    public static bool IsRegistered(string? ecosystem, string? anchorKind) =>
        ecosystem is not null && anchorKind is not null && Lookup.Contains((ecosystem, anchorKind));

    /// <summary>
    /// The anchor kinds registered for one ecosystem, for the validation error that names what
    /// the caller could have sent instead. Empty for an unknown ecosystem.
    /// </summary>
    public static IReadOnlyList<string> AnchorKindsFor(string? ecosystem) =>
        ecosystem is null
            ? []
            : [.. Registered.Where(p => string.Equals(p.Ecosystem, ecosystem, StringComparison.Ordinal))
                            .Select(p => p.AnchorKind)];
}
