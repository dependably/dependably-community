using Dependably.Api;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Unit coverage for <see cref="SamlController.ResolveAssertionExpiry"/> — the fallback/normalisation
/// logic that turns a validated assertion's NotOnOrAfter into the replay-cache expiry. The assertion
/// ID and NotOnOrAfter themselves now come straight from the ITfoxtec-validated security token, so the
/// only branch worth pinning here is the missing-value fallback and UTC normalisation.
/// </summary>
public sealed class SamlReplayExpiryTests
{
    // Fixed clock instant: the resolver takes `now` as a parameter, so the fallback
    // branch asserts exactly instead of tolerating wall-clock movement mid-test.
    private static readonly DateTimeOffset Now = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Fact]
    public void ResolveAssertionExpiry_Default_FallsBackToGenerousTtl()
    {
        var result = SamlController.ResolveAssertionExpiry(default, Now);

        Assert.Equal(Now.AddHours(24), result);
    }

    [Fact]
    public void ResolveAssertionExpiry_ConcreteValue_ReturnedInUtc()
    {
        var notOnOrAfter = new DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero);

        var result = SamlController.ResolveAssertionExpiry(notOnOrAfter, Now);

        Assert.Equal(notOnOrAfter, result);
        Assert.Equal(TimeSpan.Zero, result.Offset);
    }

    [Fact]
    public void ResolveAssertionExpiry_NonUtcOffset_NormalisedToSameInstantUtc()
    {
        // An IdP that emits a non-Z offset must still land on the same absolute instant in UTC.
        var withOffset = new DateTimeOffset(2030, 1, 2, 8, 4, 5, TimeSpan.FromHours(5));

        var result = SamlController.ResolveAssertionExpiry(withOffset, Now);

        Assert.Equal(TimeSpan.Zero, result.Offset);
        Assert.Equal(withOffset.UtcDateTime, result.UtcDateTime);
    }
}
