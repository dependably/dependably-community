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
    [Fact]
    public void ResolveAssertionExpiry_Default_FallsBackToGenerousTtl()
    {
        var before = DateTimeOffset.UtcNow;
        var result = SamlController.ResolveAssertionExpiry(default);
        var after = DateTimeOffset.UtcNow;

        // Fallback is now + 24h; allow a small window for clock movement during the call.
        Assert.InRange(result, before.AddHours(24).AddSeconds(-5), after.AddHours(24).AddSeconds(5));
    }

    [Fact]
    public void ResolveAssertionExpiry_ConcreteValue_ReturnedInUtc()
    {
        var notOnOrAfter = new DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero);

        var result = SamlController.ResolveAssertionExpiry(notOnOrAfter);

        Assert.Equal(notOnOrAfter, result);
        Assert.Equal(TimeSpan.Zero, result.Offset);
    }

    [Fact]
    public void ResolveAssertionExpiry_NonUtcOffset_NormalisedToSameInstantUtc()
    {
        // An IdP that emits a non-Z offset must still land on the same absolute instant in UTC.
        var withOffset = new DateTimeOffset(2030, 1, 2, 8, 4, 5, TimeSpan.FromHours(5));

        var result = SamlController.ResolveAssertionExpiry(withOffset);

        Assert.Equal(TimeSpan.Zero, result.Offset);
        Assert.Equal(withOffset.UtcDateTime, result.UtcDateTime);
    }
}
