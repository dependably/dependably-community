using Dependably.Protocol;
using NSubstitute;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Factory for <see cref="IOsvSource"/> test doubles that configures ALL FIVE members —
/// <c>QueryAsync</c>, <c>QueryBatchAsync</c>, the reachability-reporting
/// <c>TryQueryAsync</c>/<c>TryQueryBatchAsync</c> pair, and <c>HasCoverageFor</c> — from one
/// advisory selector.
///
/// Configuring only a subset is a silent trap: <see cref="IOsvSource"/> declares
/// <c>TryQueryAsync</c>/<c>TryQueryBatchAsync</c>/<c>HasCoverageFor</c> as default interface
/// implementations, NSubstitute intercepts them like any other virtual member, and an
/// unconfigured call does **not** fall through to the interface's own default body — it answers
/// NSubstitute's auto-value for the return type instead (<see langword="null"/> for a reference
/// type, <see langword="false"/> for <c>Task&lt;bool&gt;</c>'s inner value). Left unconfigured,
/// <c>HasCoverageFor</c> would silently answer <see langword="false"/> for every ecosystem on
/// every test double built here — <see cref="Dependably.Infrastructure.VulnerabilityScanService"/>
/// reads that as "no dynamic coverage" and skips persistence entirely, which is indistinguishable
/// from a real regression until a scan-pass assertion mysteriously finds nothing written. Every
/// double goes through here so the reachability signal — and now the coverage signal — is always
/// explicit.
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

        // Mirrors OsvClient's real behaviour (defer entirely to the static gate) rather than
        // LocalOsvSource's RPM-specific dynamic narrowing — this double models a generic working
        // source, and a test that needs to pin the dynamic no-coverage case exercises a real
        // LocalOsvSource against a temp dump directory instead (see
        // VulnerabilityScanRpmLocalCoverageTests), where the behaviour actually lives.
        osv.HasCoverageFor(Arg.Any<string?>())
            .Returns(call => Task.FromResult(OsvFeedCoverage.HasAdvisoryFeed(call.ArgAt<string?>(0))));

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
