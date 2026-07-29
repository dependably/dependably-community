using Dependably.Protocol;
using NSubstitute;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Factory for <see cref="IOsvSource"/> test doubles that configures ALL FOUR members —
/// <c>QueryAsync</c>, <c>QueryBatchAsync</c>, and the reachability-reporting
/// <c>TryQueryAsync</c>/<c>TryQueryBatchAsync</c> pair — from one advisory selector.
///
/// Configuring only the non-<c>Try</c> pair is a silent trap: <see cref="IOsvSource"/> declares
/// the <c>Try</c> variants as default interface implementations, NSubstitute intercepts them like
/// any other virtual member, and an unconfigured call answers a null
/// <see cref="OsvQueryResult"/> — which <see cref="Dependably.Infrastructure.VulnerabilityScanService"/>
/// correctly treats as "source not reached" and refuses to record as a scan. Every double goes
/// through here so the reachability signal is always explicit.
/// </summary>
public static class TestOsvSource
{
    /// <summary>
    /// A double answering <paramref name="selector"/> for each queried PURL (default: no
    /// advisories, i.e. a genuinely clean answer).
    /// </summary>
    /// <param name="reached">
    /// The reachability signal the <c>Try</c> variants report. <see langword="false"/> models an
    /// unreachable advisory source — the all-empty answer every failure mode produces, which the
    /// scan service must never persist as "scanned, 0 advisories".
    /// </param>
    public static IOsvSource Create(Func<string, List<OsvAdvisory>>? selector = null, bool reached = true)
    {
        var select = selector ?? (_ => []);
        var osv = Substitute.For<IOsvSource>();

        osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult(select(call.ArgAt<string>(0))));
        osv.TryQueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult(new OsvQueryResult(select(call.ArgAt<string>(0)), reached)));

        osv.QueryBatchAsync(Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult(Batch(call.ArgAt<IReadOnlyList<string>>(0), select)));
        osv.TryQueryBatchAsync(Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult(
                new OsvBatchQueryResult(Batch(call.ArgAt<IReadOnlyList<string>>(0), select), reached)));

        return osv;
    }

    /// <summary>
    /// A double that answers every PURL with one advisory carrying <paramref name="cvssScore"/>,
    /// for the score-ceiling arms.
    /// </summary>
    public static IOsvSource WithAdvisory(
        double cvssScore, string osvId = "GHSA-test-0001", string severity = "CRITICAL") =>
        Create(_ =>
        [
            new(osvId, [], "test advisory", severity,
                CvssScore: cvssScore, AffectedPackages: [], Published: null, Modified: null,
                IsHydrated: true),
        ]);

    private static List<List<OsvAdvisory>> Batch(
        IReadOnlyList<string> purls, Func<string, List<OsvAdvisory>> select)
        => purls.Select(select).ToList();
}
