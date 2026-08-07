using NuGet.Versioning;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolves "the latest version" of a package by version precedence rather than recency.
/// Mirrors the shape npm's dist-tag lazy-latest computation already established
/// (<c>NpmSharedHelpers.ComputeLazyLatest</c>): SemVer-primary, with <see cref="PackageVersion.CreatedAt"/>
/// used only to break a tie between versions of equal precedence. <c>CreatedAt</c> alone is the
/// wrong signal for "latest" — publishing a hotfix after a later major release must not make the
/// hotfix report as newest — and for a global-plane proxy entry it is doubly wrong, since
/// <c>cache_artifact.first_cached_at</c> is deduped across every tenant and, for any tenant after
/// the first, reflects another tenant's fetch time rather than this one's.
///
/// Parsing uses <c>NuGet.Versioning</c> — the repo-wide precedent for version comparison across
/// ecosystems (also used by npm's <c>ComputeLazyLatest</c> and NuGet's own
/// <c>NuGetRegistrationHelpers.ComputeRange</c>). A version that fails to parse never throws and is
/// never dropped from consideration: it sorts behind every version that does parse, so one
/// malformed version cannot hide every other version of the same package.
///
/// This resolver has no opinion on prerelease eligibility — a caller that needs to exclude
/// prereleases (or exclude a package whose only versions are prerelease) filters its candidate
/// list before calling <see cref="ResolveLatest"/>, the way <c>NuGetSearchHandler</c> does for
/// both <c>SearchAsync</c> and <c>AutocompleteAsync</c>. Baking a "prefer stable, fall back to
/// prerelease when none exists" rule in here previously made a package with only prerelease
/// versions still resolve to one — plausible-sounding, but wrong: the NuGet Search Query Service
/// (like nuget.org) omits such a package entirely when the caller does not opt into prereleases.
/// </summary>
public static class VersionPrecedenceResolver
{
    /// <summary>
    /// Picks the highest-precedence version out of <paramref name="candidates"/>, or null when
    /// the list is empty. Tie-break order for equal precedence: newest
    /// <see cref="PackageVersion.CreatedAt"/> first, then <c>uploaded</c> origin over
    /// <c>proxy</c> — never the reverse, because a proxy <c>CreatedAt</c> is a global-plane
    /// timestamp that can predate this tenant's own fetch.
    /// </summary>
    public static PackageVersion? ResolveLatest(IReadOnlyList<PackageVersion> candidates) =>
        candidates.Count == 0
            ? null
            : candidates
                .Select(v => (Version: v, Parsed: NuGetVersion.TryParse(v.Version, out var sv) ? sv : null))
                .OrderByDescending(x => x.Parsed, Comparer<NuGetVersion?>.Create(CompareParsedVersions))
                .ThenByDescending(x => x.Version.CreatedAt)
                .ThenByDescending(x => x.Version.Origin == "uploaded")
                .First().Version;

    // A version that fails to parse sorts behind every version that does (never null-reference,
    // never dropped from consideration) — see the class doc for why one malformed version must
    // not hide every other version of the same package.
    private static int CompareParsedVersions(NuGetVersion? a, NuGetVersion? b) =>
        a is null && b is null ? 0
        : a is null ? -1
        : b is null ? 1
        : a.CompareTo(b);
}
