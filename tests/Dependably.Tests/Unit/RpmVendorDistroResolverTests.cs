using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Coverage for <see cref="RpmVendorDistroResolver"/>: tolerant, real-world-shaped Vendor strings
/// mapping to the eight OSV.dev RPM distro namespaces, plus the deliberate non-matches (Fedora,
/// Photon OS, and anything else OSV registers no RPM feed for).
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmVendorDistroResolverTests
{
    [Theory]
    [InlineData("AlmaLinux OS Foundation", "almalinux")]
    [InlineData("AlmaLinux", "almalinux")]
    [InlineData("Rocky Enterprise Software Foundation", "rocky-linux")]
    [InlineData("Rocky Linux", "rocky-linux")]
    [InlineData("Red Hat, Inc.", "redhat")]
    [InlineData("Red Hat", "redhat")]
    [InlineData("openEuler", "openeuler")]
    [InlineData("openEuler Community", "openeuler")]
    [InlineData("openSUSE", "opensuse")]
    [InlineData("openSUSE Leap 15.5", "opensuse")]
    [InlineData("SUSE LLC", "suse")]
    [InlineData("SUSE Linux Enterprise Server 15", "suse")]
    [InlineData("Microsoft Corporation", "azure-linux")]
    [InlineData("Mageia.Org", "mageia")]
    [InlineData("Mageia", "mageia")]
    public void Resolve_KnownVendorVariant_ReturnsExpectedNamespace(string vendor, string expected)
    {
        Assert.Equal(expected, RpmVendorDistroResolver.Resolve(vendor));
    }

    [Fact]
    public void Resolve_OpenSuseVendor_NeverMatchesBareSuse()
    {
        // "openSUSE" contains the substring "suse" — this pins that the narrower namespace wins,
        // not the broader one that would otherwise swallow it.
        Assert.Equal("opensuse", RpmVendorDistroResolver.Resolve("openSUSE"));
        Assert.NotEqual("suse", RpmVendorDistroResolver.Resolve("openSUSE"));
    }

    [Theory]
    [InlineData("Fedora Project")]
    [InlineData("Fedora")]
    [InlineData("VMware, Inc.")]
    [InlineData("Photon OS")]
    [InlineData("Canonical Ltd.")]
    [InlineData("Some Third-Party Vendor")]
    public void Resolve_UnrecognizedVendor_ReturnsNull(string vendor)
    {
        // Fedora and Photon OS are deliberately absent from both of OSV.dev's own registration
        // tables — resolving them to null is correct, not a resolver gap.
        Assert.Null(RpmVendorDistroResolver.Resolve(vendor));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Resolve_EmptyOrWhitespaceVendor_ReturnsNull(string? vendor)
    {
        Assert.Null(RpmVendorDistroResolver.Resolve(vendor));
    }

    [Fact]
    public void KnownNamespaces_MatchesOsvDevRegisteredSet()
    {
        // Cross-checked directly against osv/purl_helpers.py's ECOSYSTEM_PURL_DATA and
        // go/purl/ecosystems_simple.go's registerSimple calls — both register exactly these eight
        // rpm/{namespace} keys and no bare "rpm" key.
        Assert.Equal(
            new[] { "almalinux", "azure-linux", "mageia", "openeuler", "opensuse", "redhat", "rocky-linux", "suse" },
            RpmVendorDistroResolver.KnownNamespaces.OrderBy(n => n, StringComparer.Ordinal));
    }
}
