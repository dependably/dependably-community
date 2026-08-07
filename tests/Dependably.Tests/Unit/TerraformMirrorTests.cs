using Dependably.Api;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Tests.Unit;

/// <summary>
/// Path parsing and identity for the Terraform provider network mirror.
///
/// The parsing tests matter more than their size suggests: every segment they accept flows into a
/// blob key and an upstream URL, so a traversal sequence that survives parsing is a path-escape in
/// the blob store.
/// </summary>
[Trait("Category", "Unit")]
public class TerraformMirrorTests
{
    // ── Provider source address ──────────────────────────────────────────────

    [Theory]
    [InlineData("registry.terraform.io/hashicorp/random", "registry.terraform.io", "hashicorp", "random")]
    // Provider type names legitimately contain underscores and hyphens.
    [InlineData("registry.terraform.io/hashicorp/aws_cloud-control", "registry.terraform.io", "hashicorp", "aws_cloud-control")]
    // A private registry is as valid a source address as the public one.
    [InlineData("tf.example.com/acme/internal", "tf.example.com", "acme", "internal")]
    // Terraform matches source addresses case-insensitively, so parsing canonicalizes to lowercase
    // — every downstream identity (blob key, cache coordinate, source pin, PURL) derives from here.
    [InlineData("Registry.Terraform.IO/HashiCorp/Random", "registry.terraform.io", "hashicorp", "random")]
    public void TryParseProvider_AcceptsWellFormedSourceAddress(
        string input, string hostname, string ns, string type)
    {
        Assert.True(TerraformController.TryParseProvider(input, out var provider));
        Assert.Equal(hostname, provider.Hostname);
        Assert.Equal(ns, provider.Namespace);
        Assert.Equal(type, provider.Type);
    }

    [Theory]
    // Wrong arity: a source address is exactly three segments.
    [InlineData("hashicorp/random")]
    [InlineData("registry.terraform.io/hashicorp/random/extra")]
    [InlineData("")]
    // Traversal in any position must not survive parsing — these reach blob keys.
    [InlineData("../../etc/passwd")]
    [InlineData("registry.terraform.io/../random")]
    [InlineData("registry.terraform.io/hashicorp/..")]
    // An empty segment would collapse a blob key path.
    [InlineData("registry.terraform.io//random")]
    public void TryParseProvider_RejectsMalformedOrUnsafe(string input)
        => Assert.False(TerraformController.TryParseProvider(input, out _));

    // ── Archive path ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData("registry.terraform.io/hashicorp/random/3.9.0/linux_amd64.zip", "3.9.0", "linux_amd64")]
    [InlineData("registry.terraform.io/hashicorp/random/1.0.0-beta.1/darwin_arm64.zip", "1.0.0-beta.1", "darwin_arm64")]
    public void TryParseArchive_AcceptsVersionAndPlatform(
        string path, string expectedVersion, string expectedPlatform)
    {
        Assert.True(TerraformController.TryParseArchive(
            path, out var provider, out string version, out string platform));
        Assert.Equal("registry.terraform.io", provider.Hostname);
        Assert.Equal(expectedVersion, version);
        Assert.Equal(expectedPlatform, platform);
    }

    [Theory]
    // Platform must carry the os_arch separator — this is why the platform gets its own path
    // segment rather than being suffixed onto a filename that may itself contain underscores.
    [InlineData("registry.terraform.io/hashicorp/random/3.9.0/linux.zip")]
    // Wrong arity.
    [InlineData("registry.terraform.io/hashicorp/random/linux_amd64.zip")]
    [InlineData("registry.terraform.io/hashicorp/random/3.9.0/sub/linux_amd64.zip")]
    // Traversal in the version position.
    [InlineData("registry.terraform.io/hashicorp/random/../linux_amd64.zip")]
    public void TryParseArchive_RejectsMalformedOrUnsafe(string path)
        => Assert.False(TerraformController.TryParseArchive(path, out _, out _, out _));

    // ── Identity ─────────────────────────────────────────────────────────────

    [Fact]
    public void ProviderName_IsTheFullSourceAddress()
    {
        Assert.True(TerraformController.TryParseProvider(
            "registry.terraform.io/hashicorp/random", out var provider));
        Assert.Equal("registry.terraform.io/hashicorp/random", TerraformController.ProviderName(provider));
    }

    // The canonical name is what the cache coordinate, the source pin and the reserved-namespace
    // lookup are all keyed on, so two spellings of one provider must produce one name. Two rows
    // would mean a block recorded against one spelling not applying to the other, and a duplicated
    // cache entry per spelling.
    [Fact]
    public void ProviderName_IsIdenticalForEverySpellingOfOneAddress()
    {
        Assert.True(TerraformController.TryParseProvider(
            "registry.terraform.io/hashicorp/random", out var canonical));
        Assert.True(TerraformController.TryParseProvider(
            "Registry.Terraform.IO/HashiCorp/Random", out var mixedCase));

        Assert.Equal(
            TerraformController.ProviderName(canonical), TerraformController.ProviderName(mixedCase));
    }

    // The parsed address feeds BlobKeys.Terraform directly, so canonicalization has to reach the
    // key too — otherwise one provider occupies two cache entries in the blob store.
    [Fact]
    public void BlobKey_IsIdenticalForEverySpellingOfOneAddress()
    {
        Assert.True(TerraformController.TryParseProvider(
            "registry.terraform.io/hashicorp/random", out var canonical));
        Assert.True(TerraformController.TryParseProvider(
            "REGISTRY.TERRAFORM.IO/HASHICORP/RANDOM", out var mixedCase));

        Assert.Equal(
            BlobKeys.Terraform("org1", canonical.Hostname, canonical.Namespace, canonical.Type, "3.9.0", "linux_amd64"),
            BlobKeys.Terraform("org1", mixedCase.Hostname, mixedCase.Namespace, mixedCase.Type, "3.9.0", "linux_amd64"));
    }

    [Fact]
    public void Purl_CarriesRegistryAsQualifier()
        => Assert.Equal(
            "pkg:terraform/hashicorp/random@3.9.0?registry=registry.terraform.io",
            PurlNormalizer.Terraform("registry.terraform.io", "hashicorp", "random", "3.9.0"));

    // Terraform matches source addresses case-insensitively, so two spellings must not become two
    // identities — a block recorded against one would otherwise not apply to the other.
    [Fact]
    public void Purl_LowercasesSourceAddress()
        => Assert.Equal(
            PurlNormalizer.Terraform("registry.terraform.io", "hashicorp", "random", "3.9.0"),
            PurlNormalizer.Terraform("Registry.Terraform.IO", "HashiCorp", "Random", "3.9.0"));

    [Fact]
    public void CanonicalName_LowercasesTerraformNames()
        => Assert.Equal(
            "registry.terraform.io/hashicorp/random",
            PurlNormalizer.CanonicalName("terraform", "Registry.Terraform.IO/HashiCorp/Random"));

    // ── Blob key ─────────────────────────────────────────────────────────────

    [Fact]
    public void BlobKey_IsOrgScopedAndPlatformQualified()
        => Assert.Equal(
            "terraform/org1/registry.terraform.io/hashicorp/random/3.9.0/linux_amd64.zip",
            BlobKeys.Terraform("org1", "registry.terraform.io", "hashicorp", "random", "3.9.0", "linux_amd64"));

    // Two registries publishing the same namespace/type are different providers and must not
    // share a cache entry.
    [Fact]
    public void BlobKey_SeparatesProvidersFromDifferentRegistries()
        => Assert.NotEqual(
            BlobKeys.Terraform("org1", "registry.terraform.io", "acme", "internal", "1.0.0", "linux_amd64"),
            BlobKeys.Terraform("org1", "tf.example.com", "acme", "internal", "1.0.0", "linux_amd64"));

    // ── Registry page link ───────────────────────────────────────────────────

    [Fact]
    public void RegistryPage_DerivesFromSourceAddressNotDownloadHost()
        => Assert.Equal(
            "https://registry.terraform.io/providers/hashicorp/random/3.9.0",
            RegistryPageUrl.ForVersion(
                "terraform",
                "pkg:terraform/hashicorp/random@3.9.0?registry=registry.terraform.io",
                "registry.terraform.io/hashicorp/random",
                "3.9.0",
                "https://releases.hashicorp.com/terraform-provider-random/3.9.0/terraform-provider-random_3.9.0_linux_amd64.zip"));

    // A third-party registry links to itself, not to HashiCorp's.
    [Fact]
    public void RegistryPage_FollowsAThirdPartyRegistry()
        => Assert.Equal(
            "https://tf.example.com/providers/acme/internal/1.0.0",
            RegistryPageUrl.ForVersion(
                "terraform",
                "pkg:terraform/acme/internal@1.0.0?registry=tf.example.com",
                "tf.example.com/acme/internal",
                "1.0.0",
                "https://tf.example.com/downloads/internal-1.0.0.zip"));

    // A name that is not a full source address yields no link rather than a guessed one.
    [Fact]
    public void RegistryPage_ReturnsNullForNonSourceAddressName()
        => Assert.Null(RegistryPageUrl.ForVersion(
            "terraform", "pkg:terraform/acme/internal@1.0.0", "internal", "1.0.0",
            "https://tf.example.com/downloads/internal-1.0.0.zip"));

    // ── Version ordering ─────────────────────────────────────────────────────

    // Provider versions are SemVer 2.0, so they order under the same comparer npm uses.
    [Fact]
    public void VersionOrdering_UsesSemver()
        => Assert.Equal(
            new[] { "10.0.0", "9.1.0", "9.0.1" },
            EcosystemVersionOrdering.OrderStableDescending(
                "terraform", new[] { "9.0.1", "10.0.0", "9.1.0" }));

    [Fact]
    public void VersionOrdering_ComparesSemverNotLexically()
        => Assert.True(EcosystemVersionOrdering.Compare("terraform", "10.0.0", "9.0.0") > 0);
}
