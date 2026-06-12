using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the static factory members on the OCI result records returned by
/// <c>OciUploadService</c> — the sentinel results and digest-carrying constructors.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciResultRecordsTests
{
    [Fact]
    public void BlobFinalizeResult_Sentinels_CarryExpectedStatus()
    {
        Assert.Equal(OciFinalizeStatus.BadDigest, OciBlobFinalizeResult.BadDigest.Status);
        Assert.Equal(OciFinalizeStatus.DigestMismatch, OciBlobFinalizeResult.DigestMismatch.Status);

        var ok = OciBlobFinalizeResult.Ok("sha256:abc", 42);
        Assert.Equal(OciFinalizeStatus.Ok, ok.Status);
        Assert.Equal("sha256:abc", ok.Digest);
        Assert.Equal(42, ok.SizeBytes);
    }

    [Fact]
    public void ManifestStoreResult_FactoriesCarryDigestAndStatus()
    {
        Assert.Equal(OciManifestStatus.Invalid, OciManifestStoreResult.Invalid.Status);

        var missing = OciManifestStoreResult.MissingBlob("sha256:deadbeef");
        Assert.Equal(OciManifestStatus.MissingBlob, missing.Status);
        Assert.Equal("sha256:deadbeef", missing.MissingDigest);

        var ok = OciManifestStoreResult.Ok("sha256:cafe");
        Assert.Equal(OciManifestStatus.Ok, ok.Status);
        Assert.Equal("sha256:cafe", ok.Digest);
    }
}
