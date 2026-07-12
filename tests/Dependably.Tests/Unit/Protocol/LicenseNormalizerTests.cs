using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// LicenseNormalizer resolves a raw license leaf to its canonical SPDX identifier using the
/// real seeded <c>spdx_license</c> reference table (via <see cref="InMemoryDbFixture"/>, which
/// runs the production <c>SchemaInitializer</c> — including <c>SpdxLicenseSeeder</c> — exactly
/// like <c>SpdxLicenseSeederTests</c>/<c>LicenseReviewQueueTests</c> do).
/// </summary>
[Trait("Category", "Unit")]
public sealed class LicenseNormalizerTests : IAsyncLifetime
{
    private readonly InMemoryDbFixture _fixture = new();

    public Task InitializeAsync() => _fixture.InitializeAsync();

    public Task DisposeAsync() => _fixture.DisposeAsync();

    private LicenseNormalizer NewSut() =>
        new(_fixture.Store, NullLogger<LicenseNormalizer>.Instance);

    [Theory]
    [InlineData("apache-2.0", "Apache-2.0")]
    [InlineData("APACHE-2.0", "Apache-2.0")]
    [InlineData("Apache-2.0", "Apache-2.0")]
    [InlineData("mit", "MIT")]
    [InlineData("MIT", "MIT")]
    public void Normalize_ExactIdentifierHit_ReturnsCanonicalCasing(string input, string expected)
    {
        var sut = NewSut();
        Assert.Equal(expected, sut.Normalize(input));
    }

    [Fact]
    public void Normalize_SpdxNameMatch_ReturnsIdentifier()
    {
        var sut = NewSut();
        Assert.Equal("Apache-2.0", sut.Normalize("Apache License 2.0"));
    }

    [Fact]
    public void Normalize_NameMatch_IsCaseInsensitive()
    {
        var sut = NewSut();
        Assert.Equal("Apache-2.0", sut.Normalize("apache license 2.0"));
        Assert.Equal("Apache-2.0", sut.Normalize("APACHE LICENSE 2.0"));
    }

    [Fact]
    public void Normalize_AliasOverlayVariant_ReturnsIdentifier()
    {
        var sut = NewSut();
        Assert.Equal("Apache-2.0", sut.Normalize("apache 2.0"));
        Assert.Equal("MIT", sut.Normalize("the mit license"));
    }

    [Fact]
    public void Normalize_UnknownCustomString_PassesThroughUnchanged()
    {
        var sut = NewSut();
        Assert.Equal("MyCompany-Internal-License-v3", sut.Normalize("MyCompany-Internal-License-v3"));
    }

    [Fact]
    public void Normalize_UnknownCustomString_TrimsWhitespace()
    {
        var sut = NewSut();
        Assert.Equal("Some Custom License", sut.Normalize("  Some Custom License  "));
    }

    [Fact]
    public void Normalize_WithException_NormalizesBaseOnly_PreservesException()
    {
        var sut = NewSut();
        Assert.Equal(
            "GPL-2.0-only WITH Classpath-exception-2.0",
            sut.Normalize("gpl-2.0-only WITH Classpath-exception-2.0"));
    }

    [Fact]
    public void Normalize_WithException_UnknownException_PreservedVerbatim()
    {
        var sut = NewSut();
        // The exception side is never looked up against spdx_license — only the base id is.
        Assert.Equal(
            "Apache-2.0 WITH Some-Custom-Exception",
            sut.Normalize("apache-2.0 WITH Some-Custom-Exception"));
    }

    [Fact]
    public void Normalize_DeprecatedIdentifier_ReturnsItselfUnchanged()
    {
        var sut = NewSut();
        // GPL-3.0 is a deprecated SPDX id, but an exact-identifier hit is never remapped to
        // a current replacement — the review/enforcement surfaces must see the id actually
        // observed on the package.
        Assert.Equal("GPL-3.0", sut.Normalize("GPL-3.0"));
        Assert.Equal("GPL-3.0", sut.Normalize("gpl-3.0"));
    }

    [Fact]
    public void Normalize_NameCollision_ResolvesToNonDeprecatedIdentifier()
    {
        var sut = NewSut();
        // "GNU General Public License v3.0 only" is the shared name of both the deprecated
        // GPL-3.0 and the current GPL-3.0-only. A name-based (not exact-id) lookup must
        // prefer the non-deprecated identifier.
        Assert.Equal("GPL-3.0-only", sut.Normalize("GNU General Public License v3.0 only"));
    }

    [Fact]
    public void Normalize_EmptyOrWhitespace_ReturnsEmpty()
    {
        var sut = NewSut();
        Assert.Equal(string.Empty, sut.Normalize(string.Empty));
        Assert.Equal(string.Empty, sut.Normalize("   "));
    }

    [Fact]
    public void Normalize_MapsAreCachedAcrossCalls_NotRebuiltPerCall()
    {
        // Not a direct probe of query counts (Normalize's public contract), but pins the
        // observable behavior: repeated calls against the same instance keep resolving
        // correctly, which would break if the lazily-built cache were torn down or partially
        // reused incorrectly between calls.
        var sut = NewSut();
        for (int i = 0; i < 5; i++)
        {
            Assert.Equal("Apache-2.0", sut.Normalize("apache-2.0"));
            Assert.Equal("MIT", sut.Normalize("mit license"));
        }
    }
}
