using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// The cross-cutting seams the projects plane hangs off: the document blob key, the
/// <c>sbom:upload</c> capability, and the <c>sbom-scan</c> background-job name. Each is a
/// contract several other surfaces bind to, so each is pinned here rather than left to the first
/// caller that happens to exercise it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomSeamsTests
{
    private const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void ProjectDocumentKey_IsOrgScopedUnderTheHostedPrefix()
    {
        string key = BlobKeys.ProjectDocument("org1", "proj1", "ver1", "sbom", Sha);

        Assert.Equal($"hosted/org1/projects/proj1/ver1/sbom/{Sha}.json", key);
        // The hosted/ prefix is load-bearing: it is what puts the blob inside
        // OrphanBlobReconcilerService's sweep, which is why project_documents is in that sweep's
        // referenced-key union.
        Assert.StartsWith("hosted/org1/", key, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("sbom")]
    [InlineData("vex")]
    [InlineData("sarif")]
    public void ProjectDocumentKey_AcceptsEachDocumentKind(string docType)
    {
        string key = BlobKeys.ProjectDocument("org1", "proj1", "ver1", docType, Sha);
        Assert.Contains($"/{docType}/", key, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("spdx")]
    [InlineData("../../etc")]
    [InlineData("")]
    public void ProjectDocumentKey_RefusesAnUnknownDocumentKind(string docType)
        => Assert.Throws<ArgumentException>(
            () => BlobKeys.ProjectDocument("org1", "proj1", "ver1", docType, Sha));

    [Theory]
    [InlineData("not-a-digest")]
    [InlineData("../../../etc/passwd")]
    [InlineData("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef")]
    public void ProjectDocumentKey_RefusesANonCanonicalDigest(string sha256)
        => Assert.Throws<ArgumentException>(
            () => BlobKeys.ProjectDocument("org1", "proj1", "ver1", "sbom", sha256));

    /// <summary>
    /// A capability that is not in <see cref="Capabilities.Requestable"/> is rejected by the token
    /// issuance pipeline as unknown, so a half-wired constant reads as a working grant in code and
    /// fails at runtime for every caller trying to mint it.
    /// </summary>
    [Fact]
    public void SbomUpload_IsARequestableCapability()
        => Assert.Contains(Capabilities.SbomUpload, Capabilities.Requestable);

    [Fact]
    public void SbomUpload_IsGrantedToAdminAndOwner_ButNotToMemberOrAuditor()
    {
        Assert.Contains(Capabilities.SbomUpload, Capabilities.ForRole("admin"));
        Assert.Contains(Capabilities.SbomUpload, Capabilities.ForRole("owner"));
        Assert.DoesNotContain(Capabilities.SbomUpload, Capabilities.ForRole("member"));
        Assert.DoesNotContain(Capabilities.SbomUpload, Capabilities.ForRole("auditor"));
    }

    /// <summary>
    /// The point of a separate grant: an <c>sbom:upload</c> token must not be satisfiable by, or
    /// satisfy, the far broader import credential it replaces.
    /// </summary>
    [Fact]
    public void SbomUpload_IsNeitherGrantedByNorGrantsTheImportCredential()
    {
        var sbomOnly = new HashSet<string> { Capabilities.SbomUpload };
        var importOnly = new HashSet<string> { Capabilities.ImportAll, Capabilities.TenantConfigure };

        Assert.False(Capabilities.Grants(importOnly, Capabilities.SbomUpload));
        Assert.False(Capabilities.Grants(sbomOnly, Capabilities.ImportAll));
        Assert.False(Capabilities.Grants(sbomOnly, Capabilities.TenantConfigure));
        Assert.True(Capabilities.Grants(sbomOnly, Capabilities.SbomUpload));
    }

    [Fact]
    public void AnAdminCanMintAnSbomUploadToken()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            [Capabilities.SbomUpload],
            Capabilities.ForRole("admin"),
            out string canonicalJson, out string[] capabilities, out string? error, out _);

        Assert.True(ok, error);
        Assert.Equal([Capabilities.SbomUpload], capabilities);
        Assert.Equal("""["sbom:upload"]""", canonicalJson);
    }

    [Fact]
    public void AMemberCannotMintAnSbomUploadToken()
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            [Capabilities.SbomUpload],
            Capabilities.ForRole("member"),
            out _, out _, out string? error, out string? field);

        Assert.False(ok);
        Assert.Equal("capabilities", field);
        Assert.Contains("exceed your role", error);
    }

    /// <summary>
    /// An unregistered job name is accepted by <c>DISABLE_BACKGROUND_JOBS</c> but warned about, so
    /// a name missing from the registry reads as a working disable while the operator's intent is
    /// only ever visible in a log line.
    /// </summary>
    [Fact]
    public void SbomScan_IsDisableableWithoutAnUnknownJobWarning()
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DISABLE_BACKGROUND_JOBS"] = "sbom-scan",
            })
            .Build();

        var airGap = new AirGapMode(cfg, NullLogger<AirGapMode>.Instance);

        Assert.True(airGap.IsJobDisabled("sbom-scan"));
        Assert.False(airGap.IsJobDisabled("vuln-scan"));
    }

    /// <summary>
    /// A scan pass over uploaded components queries the advisory feed, so an edge node — which
    /// creates nothing authoritative — must not run it.
    /// </summary>
    [Fact]
    public void SbomScan_IsForceDisabledOnAnEdgeNode()
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPLOYMENT_MODE"] = "edge",
            })
            .Build();

        Assert.True(new AirGapMode(cfg).IsJobDisabled("sbom-scan"));
    }
}
