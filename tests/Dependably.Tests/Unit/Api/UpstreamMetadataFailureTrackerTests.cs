using Dependably.Api.NuGetProtocol;
using Dependably.Protocol;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Pins <see cref="UpstreamMetadataFailureTracker"/>'s Refused/Transient classification
/// directly, with no HTTP anywhere in the test. The classification is a pure function of the
/// recorded per-upstream outcomes, and asserting it through a live stub server made the
/// assertion depend on that server answering inside the handler's 10-second per-upstream
/// deadline: a loaded runner turns the stubbed 401 into a timeout, the timeout is recorded
/// through <see cref="UpstreamMetadataFailureTracker.RecordFailure"/> (always a non-refusal),
/// and the accumulator latches <c>Refused</c> to false. The exception is still thrown, so only
/// the classification assertion fails — a red pipeline on a test whose subject never broke.
///
/// The accumulator is <c>&amp;=</c>, so these cases are the whole contract: every recorded
/// failure must be an authenticated 401/403 for the aggregate to be a refusal, and a single
/// non-refusal event of any kind must demote it to transient.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamMetadataFailureTrackerTests
{
    private const string Url = "https://upstream.test/registration5-semver1/pkg/index.json";
    private const string Auth = "Bearer test-token";

    [Fact]
    public void NoFailuresRecorded_DoesNotThrow()
    {
        var tracker = new UpstreamMetadataFailureTracker();

        tracker.ThrowIfFailed();
    }

    [Theory]
    [InlineData(404)]
    [InlineData(410)]
    public void ConfirmedAbsence_IsACleanAnswer_NotAFailure(int statusCode)
    {
        var tracker = new UpstreamMetadataFailureTracker();

        tracker.RecordHttpStatus(Url, statusCode, authorizationHeader: null);

        tracker.ThrowIfFailed();
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    public void AuthenticatedRefusal_IsRefusedAndNonTransient(int statusCode)
    {
        var tracker = new UpstreamMetadataFailureTracker();

        tracker.RecordHttpStatus(Url, statusCode, Auth);

        var ex = Assert.Throws<UpstreamFetchFailedException>(tracker.ThrowIfFailed);
        Assert.True(ex.Refused);
        Assert.False(ex.Transient);
        Assert.Null(ex.RetryAfter);
        Assert.Equal(statusCode, ex.StatusCode);
        Assert.Equal(Url, ex.Url);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    public void AnonymousRefusalStatus_IsNotARefusal(int statusCode)
    {
        // No credential was presented, so there is nothing for the upstream to have refused —
        // public registry CDNs emit genuinely transient 401/403s (bot mitigation, edge
        // throttling). Classifying these as refusals would turn a retryable 503 into a
        // permanent 502 for every anonymous upstream having a bad minute.
        var tracker = new UpstreamMetadataFailureTracker();

        tracker.RecordHttpStatus(Url, statusCode, authorizationHeader: null);

        var ex = Assert.Throws<UpstreamFetchFailedException>(tracker.ThrowIfFailed);
        Assert.False(ex.Refused);
        Assert.True(ex.Transient);
    }

    /// <summary>
    /// The adversarial twin of <see cref="AuthenticatedRefusal_IsRefusedAndNonTransient"/>: the
    /// deterministic assertion must not pass when the classification is genuinely wrong. A
    /// <see cref="UpstreamMetadataFailureTracker.RecordFailure"/> alongside the authenticated 401
    /// — a timeout, a connection-level exception, an unparseable 2xx body — is exactly the event
    /// the flaky CI run injected by accident, and it must still demote the aggregate to
    /// transient. Both orderings are covered because the accumulator is order-independent by
    /// construction and a rewrite that made it order-dependent would be a regression.
    /// </summary>
    [Fact]
    public void AuthenticatedRefusalPlusANonRefusalFailure_IsTransientNotRefused()
    {
        var refusalFirst = new UpstreamMetadataFailureTracker();
        refusalFirst.RecordHttpStatus(Url, 401, Auth);
        refusalFirst.RecordFailure("https://upstream-b.test/index.json");

        var ex = Assert.Throws<UpstreamFetchFailedException>(refusalFirst.ThrowIfFailed);
        Assert.False(ex.Refused);
        Assert.True(ex.Transient);

        var failureFirst = new UpstreamMetadataFailureTracker();
        failureFirst.RecordFailure("https://upstream-b.test/index.json");
        failureFirst.RecordHttpStatus(Url, 401, Auth);

        var ex2 = Assert.Throws<UpstreamFetchFailedException>(failureFirst.ThrowIfFailed);
        Assert.False(ex2.Refused);
        Assert.True(ex2.Transient);
    }

    [Fact]
    public void AuthenticatedRefusalPlusAServerError_IsTransientNotRefused()
    {
        var tracker = new UpstreamMetadataFailureTracker();

        tracker.RecordHttpStatus(Url, 401, Auth);
        tracker.RecordHttpStatus("https://upstream-b.test/index.json", 500, Auth);

        var ex = Assert.Throws<UpstreamFetchFailedException>(tracker.ThrowIfFailed);
        Assert.False(ex.Refused);
        Assert.True(ex.Transient);
    }

    [Fact]
    public void ConfirmedAbsenceAlongsideAnAuthenticatedRefusal_StaysARefusal()
    {
        // A 404 from one upstream is a clean answer, not a failure, so it must not demote the
        // refusal recorded by another upstream.
        var tracker = new UpstreamMetadataFailureTracker();

        tracker.RecordHttpStatus("https://upstream-a.test/index.json", 404, authorizationHeader: null);
        tracker.RecordHttpStatus(Url, 401, Auth);

        var ex = Assert.Throws<UpstreamFetchFailedException>(tracker.ThrowIfFailed);
        Assert.True(ex.Refused);
        Assert.False(ex.Transient);
    }

    [Fact]
    public void RecordFailureAlone_IsTransientWithNoStatusCode()
    {
        var tracker = new UpstreamMetadataFailureTracker();

        tracker.RecordFailure(Url);

        var ex = Assert.Throws<UpstreamFetchFailedException>(tracker.ThrowIfFailed);
        Assert.False(ex.Refused);
        Assert.True(ex.Transient);
        Assert.Equal(0, ex.StatusCode);
    }
}
