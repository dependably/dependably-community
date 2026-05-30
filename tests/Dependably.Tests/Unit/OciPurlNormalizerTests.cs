using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class OciPurlNormalizerTests
{
    [Fact]
    public void Oci_TagPull_EncodesDigestAndCapturesTag()
    {
        // Name is the repo basename; the digest colon is percent-encoded; repository_url keeps
        // the full path; tag is captured as a qualifier.
        Assert.Equal(
            "pkg:oci/ubuntu@sha256%3Aabc123?repository_url=library/ubuntu&tag=22.04",
            PurlNormalizer.Oci("library/ubuntu", "sha256:abc123", "22.04"));
    }

    [Fact]
    public void Oci_DigestPull_OmitsTagQualifier()
    {
        Assert.Equal(
            "pkg:oci/alpine@sha256%3Adeadbeef?repository_url=alpine",
            PurlNormalizer.Oci("alpine", "sha256:deadbeef"));
    }

    [Fact]
    public void Oci_MixedCaseRepository_LowercasesName()
    {
        // The purl name is lowercased; repository_url preserves the original path verbatim.
        Assert.StartsWith(
            "pkg:oci/myimage@",
            PurlNormalizer.Oci("MyOrg/MyImage", "sha256:00", "latest"));
        Assert.Contains(
            "repository_url=MyOrg/MyImage",
            PurlNormalizer.Oci("MyOrg/MyImage", "sha256:00", "latest"));
    }
}
