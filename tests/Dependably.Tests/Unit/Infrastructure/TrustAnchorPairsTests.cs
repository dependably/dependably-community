using Dependably.Api;
using Dependably.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins <see cref="TrustAnchorPairs.Registered"/> as the single definition shared by the
/// insert-time gate on <c>POST /api/v1/trust-anchors</c> and the audit surfaces that report rows
/// stored outside it.
///
/// The set-equality assertion is the load-bearing one. If a pair were registered here without a
/// material validator behind it, the add path would accept material nothing parses — the exact
/// hole the pair gate closes. If a validator existed for a pair not in the set, the add path
/// would reject material it can in fact validate, and every already-stored row of that shape
/// would be misreported as suspect.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TrustAnchorPairsTests
{
    [Fact]
    public void RegisteredSet_MatchesTheControllerValidatorSet_Exactly()
    {
        var declared = TrustAnchorPairs.Registered.ToHashSet();
        var validators = TrustAnchorController.EcosystemValidators.Keys.ToHashSet();

        Assert.Equal(validators, declared);
    }

    [Fact]
    public void RegisteredSet_IsTheNineKnownPairs()
    {
        // Spelled out rather than derived, so widening the accepted surface is a deliberate edit
        // to a test that names every pair, not a silently-passing list length.
        Assert.Equal(
            new HashSet<(string, string)>
            {
                ("rpm", "pgp"),
                ("maven", "pgp"),
                ("terraform", "pgp"),
                ("npm", "spki"),
                ("nuget", "x509"),
                ("pypi", "sigstore_root"),
                ("pypi", "trusted_publisher"),
                ("pypi", "rekor_key"),
                ("apk", "rsa"),
            },
            TrustAnchorPairs.Registered.ToHashSet());
    }

    [Fact]
    public void EverySupportedEcosystem_HasAtLeastOneRegisteredKind()
    {
        // The add path's validation error names the kinds allowed for the requested ecosystem;
        // an ecosystem with none would render an empty allowed-list.
        foreach (string ecosystem in TrustAnchorRepository.SupportedEcosystems)
        {
            Assert.NotEmpty(TrustAnchorPairs.AnchorKindsFor(ecosystem));
        }
    }

    [Fact]
    public void EveryRegisteredPair_UsesAKnownEcosystemAndKind()
    {
        foreach (var (ecosystem, anchorKind) in TrustAnchorPairs.Registered)
        {
            Assert.True(TrustAnchorRepository.IsSupportedEcosystem(ecosystem), ecosystem);
            Assert.True(TrustAnchorRepository.IsAllowedAnchorKind(anchorKind), anchorKind);
        }
    }

    [Theory]
    [InlineData("npm", "pgp")]
    [InlineData("rpm", "spki")]
    [InlineData("nuget", "rsa")]
    [InlineData("apk", "pgp")]
    [InlineData("pypi", "spki")]
    [InlineData("maven", "x509")]
    [InlineData("terraform", "x509")]
    public void IsRegistered_RejectsAValidEcosystemPairedWithTheWrongKind(string eco, string kind)
        => Assert.False(TrustAnchorPairs.IsRegistered(eco, kind));

    [Theory]
    [InlineData(null, "pgp")]
    [InlineData("rpm", null)]
    [InlineData("", "")]
    [InlineData("RPM", "pgp")]
    public void IsRegistered_RejectsNullEmptyAndNonCanonicalCasing(string? eco, string? kind)
        => Assert.False(TrustAnchorPairs.IsRegistered(eco, kind));

    [Fact]
    public void AnchorKindsFor_ReturnsTheThreePyPiKinds_AndNothingForAnUnknownEcosystem()
    {
        Assert.Equal(
            new[] { "sigstore_root", "trusted_publisher", "rekor_key" },
            TrustAnchorPairs.AnchorKindsFor("pypi"));
        Assert.Empty(TrustAnchorPairs.AnchorKindsFor("cargo"));
        Assert.Empty(TrustAnchorPairs.AnchorKindsFor(null));
    }
}
