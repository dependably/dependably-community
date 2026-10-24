using Dependably.Protocol;

namespace Dependably.Infrastructure.OciScan;

/// <summary>
/// An OCI image's scan state as the UI reads it, independent of the display status (which
/// blocked, allowed and deprecated can mask). <c>State</c> is <c>scanned</c> when the org has a
/// stored result, else <c>unscanned</c> while its scanner is live, else <c>no_feed</c>. On a
/// package rollup, <c>GapCount</c> sums the held images' gaps, <c>FindingCount</c> is the largest
/// per-image advisory count (a lower bound on the distinct advisories across images, never an
/// overcount) and <c>MaxScore</c> the highest score across images.
/// </summary>
public sealed record OciScanView(string State, int GapCount, int FindingCount, double? MaxScore);

/// <summary>
/// The one place an org's OCI scan facts become a scan state, for a single image (version page)
/// and for a package's images (package list), so the two surfaces cannot disagree.
/// </summary>
public static class OciScanProjection
{
    public const string Scanned = "scanned";
    public const string Unscanned = "unscanned";
    public const string NoFeed = OsvFeedCoverage.NoFeedStatus;

    /// <summary>
    /// The scan state every OCI surface reports (version row, package rollup, and the expanded
    /// row's scan detail): <c>scanned</c> with a stored result, else <c>unscanned</c> while the
    /// org's scanner is live, else <c>no_feed</c>.
    /// </summary>
    public static string State(bool hasResult, bool covered)
        => hasResult ? Scanned : covered ? Unscanned : NoFeed;

    /// <summary>
    /// One image's scan state from the org's own facts (<paramref name="facts"/> is null when the
    /// org has no result for it) and whether its scanner is live.
    /// </summary>
    public static OciScanView Project(OciScanFacts? facts, bool covered)
        => new(State(facts is not null, covered), facts?.GapCount ?? 0, facts?.AdvisoryCount ?? 0, facts?.MaxScore);

    /// <summary>
    /// The worst state across a package's held images, in the order the UI ranks them:
    /// vulnerable, partial, unscanned, no_feed, clean. Only a package whose every image is scanned
    /// clean rolls up clean. A package holding no image has no scan evidence and reads as the
    /// org's coverage state, never clean.
    /// </summary>
    public static OciScanView RollUp(IReadOnlyCollection<OciScanFacts?> images, bool covered)
    {
        if (images.Count == 0)
        {
            return Project(null, covered);
        }

        var views = images.Select(f => Project(f, covered)).ToList();
        int rank = views.Min(Rank);
        var worst = views.Where(v => Rank(v) == rank).ToList();
        return rank switch
        {
            0 => new OciScanView(Scanned, views.Sum(v => v.GapCount),
                worst.Max(v => v.FindingCount), views.Max(v => v.MaxScore)),
            1 => new OciScanView(Scanned, views.Sum(v => v.GapCount), 0, null),
            2 or 3 => worst[0],
            _ => new OciScanView(Scanned, 0, 0, null),
        };
    }

    // 0 vulnerable, 1 partial, 2 unscanned, 3 no_feed, 4 clean. Mirrors web/src/lib/ociScan.js.
    private static int Rank(OciScanView v) => v.State switch
    {
        Scanned when v.FindingCount > 0 => 0,
        Scanned when v.GapCount > 0 => 1,
        Scanned => 4,
        Unscanned => 2,
        _ => 3,
    };
}
