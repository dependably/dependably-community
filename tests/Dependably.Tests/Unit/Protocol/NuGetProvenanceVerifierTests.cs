using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Exercises <see cref="NuGetProvenanceVerifier"/> end to end with a self-generated CA → leaf
/// certificate chain (never a real nuget.org key) and a test-signed <c>.nupkg</c> built in
/// memory. A signed package carries a <c>.signature.p7s</c> CMS at the ZIP root; the verifier must
/// accept a valid signature whose signer chains to a pinned anchor and reject everything else
/// without throwing — tampered signatures, untrusted chains, unsigned packages, and malformed
/// archives.
///
/// Fixed certificate validity dates keep the test deterministic (no wall-clock read); the verifier
/// builds its chain with <c>IgnoreNotTimeValid</c>, so the pin — not the clock — is the trust
/// decision either way.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetProvenanceVerifierTests
{
    private static readonly DateTimeOffset NotBefore = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private const long Cap = 64 * 1024 * 1024;
    private const string OrgA = "org-a";
    private const string OrgB = "org-b";

    // ── happy path ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ValidSignature_ChainingToPinnedRoot_Verifies()
    {
        var (root, leaf) = BuildChain();
        byte[] nupkg = SignedNupkg(leaf);
        var verifier = VerifierForOrg(OrgA, root);

        var result = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), Cap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(leaf.Subject, result.Signer);
    }

    // ── per-org isolation ──────────────────────────────────────────────────

    [Fact]
    public async Task DifferentOrg_WithoutAnchor_NotApplicable()
    {
        // Org A has a pinned anchor; org B has none. The same signed package must return
        // NotApplicable for org B (no anchors → cannot verify → not blocked).
        var (root, leaf) = BuildChain();
        byte[] nupkg = SignedNupkg(leaf);
        var verifier = VerifierForOrg(OrgA, root);

        var result = await verifier.VerifyForOrgAsync(OrgB, new MemoryStream(nupkg), Cap);

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
    }

    [Fact]
    public async Task OrgA_Anchor_DoesNotSatisfy_OrgB_Verify()
    {
        // Org A and org B each have different pinned roots. Org B's anchor must not satisfy
        // a package signed under org A's root — fail closed, not cross-contaminated.
        var (rootA, leafA) = BuildChain();
        var (rootB, _) = BuildChain();
        byte[] nupkg = SignedNupkg(leafA);

        var stub = new StubPerOrgTrustAnchorStore();
        stub.AddAnchor(OrgA, "nuget", AnchorMaterial(rootA));
        stub.AddAnchor(OrgB, "nuget", AnchorMaterial(rootB));
        var trustStore = new NuGetSignatureTrustStore(stub);
        var verifier = new NuGetProvenanceVerifier(trustStore, NullLogger<NuGetProvenanceVerifier>.Instance);

        // Org A: package was signed by leafA which chains to rootA → Verified.
        var resultA = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), Cap);
        // Org B: package was signed by leafA which chains to rootA, but org B pinned rootB → Failed.
        var resultB = await verifier.VerifyForOrgAsync(OrgB, new MemoryStream(nupkg), Cap);

        Assert.Equal(ProvenanceStatus.Verified, resultA.Status);
        Assert.Equal(ProvenanceStatus.Failed, resultB.Status);
        Assert.Null(resultB.Signer);
    }

    // ── failure paths ────────────────────────────────────────────────────────

    [Fact]
    public async Task UntrustedChain_Fails()
    {
        var (_, leaf) = BuildChain();
        byte[] nupkg = SignedNupkg(leaf);
        // Pin a DIFFERENT root: the signature is valid but chains to an anchor we did not pin.
        var (otherRoot, _) = BuildChain();
        var verifier = VerifierForOrg(OrgA, otherRoot);

        var result = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task TamperedSignatureBytes_Fails()
    {
        var (root, leaf) = BuildChain();
        byte[] nupkg = SignedNupkgWithTamperedSignature(leaf);
        var verifier = VerifierForOrg(OrgA, root);

        var result = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task TamperedPackageContent_BreaksSignature_Fails()
    {
        // Re-write the .signature.p7s entry's CMS so its embedded signed content no longer matches
        // the signature: a package whose signed bytes were altered after signing. CheckSignature
        // must reject it.
        var (root, leaf) = BuildChain();
        byte[] nupkg = SignedNupkgWithMismatchedContent(leaf);
        var verifier = VerifierForOrg(OrgA, root);

        var result = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── unsigned ───────────────────────────────────────────────────────────

    [Fact]
    public async Task NoSignatureEntry_Unsigned()
    {
        byte[] nupkg = UnsignedNupkg();
        var (root, _) = BuildChain();
        var verifier = VerifierForOrg(OrgA, root);

        var result = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), Cap);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
        Assert.Null(result.Signer);
    }

    // ── malformed → Failed, never throws ──────────────────────────────────────

    [Fact]
    public async Task NotAZipArchive_Fails_DoesNotThrow()
    {
        var verifier = VerifierForOrg(OrgA, BuildChain().Root);

        var result = await verifier.VerifyForOrgAsync(
            OrgA, new MemoryStream(Encoding.UTF8.GetBytes("this is not a zip file")), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task SignatureEntryNotValidCms_Fails_DoesNotThrow()
    {
        byte[] nupkg = NupkgWithSignatureBytes(Encoding.UTF8.GetBytes("not a CMS blob"));
        var verifier = VerifierForOrg(OrgA, BuildChain().Root);

        var result = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task PackageOverSizeCap_Fails_DoesNotThrow()
    {
        var (root, leaf) = BuildChain();
        byte[] nupkg = SignedNupkg(leaf);
        var verifier = VerifierForOrg(OrgA, root);

        // A cap below the package size must fail closed rather than buffer without bound.
        var result = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), maxBytes: 8);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── configuration ─────────────────────────────────────────────────────────

    [Fact]
    public async Task NoAnchor_OrgHasNone_NotApplicable()
    {
        // An org with no configured anchors cannot verify; returns NotApplicable not Failed.
        var stub = new StubPerOrgTrustAnchorStore();
        var trustStore = new NuGetSignatureTrustStore(stub);
        var verifier = new NuGetProvenanceVerifier(trustStore, NullLogger<NuGetProvenanceVerifier>.Instance);

        var (_, leaf) = BuildChain();
        byte[] nupkg = SignedNupkg(leaf);
        var result = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), Cap);

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void NoPinnedCerts_VerifierNotConfigured()
    {
        var stub = new StubPerOrgTrustAnchorStore();
        var trustStore = new NuGetSignatureTrustStore(stub);
        var verifier = new NuGetProvenanceVerifier(trustStore, NullLogger<NuGetProvenanceVerifier>.Instance);

        Assert.False(verifier.IsConfigured);
    }

    [Fact]
    public async Task IsConfiguredForAsync_WithAnchor_True()
    {
        var (root, _) = BuildChain();
        var verifier = VerifierForOrg(OrgA, root);

        Assert.True(await verifier.IsConfiguredForAsync(OrgA));
        Assert.False(await verifier.IsConfiguredForAsync(OrgB));
    }

    [Fact]
    public async Task MetadataDrivenVerify_IsNotApplicableForNuGet()
    {
        var verifier = VerifierForOrg(OrgA, BuildChain().Root);

        // NuGet signatures live in the package bytes, not the metadata; the ProvenanceInput entry
        // point must report NotApplicable (the ingest path calls VerifyForOrgAsync instead).
        var result = await verifier.VerifyAsync(
            new ProvenanceInput("nuget", "lib", "1.0.0", null, []));

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
    }

    // ── mixed partial-failure: one bad anchor + one good anchor ────────────

    [Fact]
    public async Task MixedAnchors_OneGarbageOneGood_GoodAnchorVerifies()
    {
        // Seed one unparseable anchor and one valid cert for the same org. The parseable
        // cert must still verify; the garbage entry is skipped (fail-closed for that entry
        // only, not for the whole org).
        var (root, leaf) = BuildChain();
        byte[] nupkg = SignedNupkg(leaf);

        var stub = new StubPerOrgTrustAnchorStore();
        stub.AddAnchor(OrgA, "nuget", new TrustAnchorMaterial
        { Id = "bad", AnchorKind = "x509", Material = "this-is-not-a-certificate", Label = "bad entry" });
        stub.AddAnchor(OrgA, "nuget", AnchorMaterial(root));

        var trustStore = new NuGetSignatureTrustStore(stub);
        var verifier = new NuGetProvenanceVerifier(trustStore, NullLogger<NuGetProvenanceVerifier>.Instance);

        var result = await verifier.VerifyForOrgAsync(OrgA, new MemoryStream(nupkg), Cap);

        // The good anchor should have verified the package even though the other entry failed parse.
        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(leaf.Subject, result.Signer);
    }

    // ── fixture helpers ────────────────────────────────────────────────────────

    // Builds a self-signed CA root and a leaf certificate signed by it. The leaf carries the
    // signing private key; the root is the pinned trust anchor.
    private static (X509Certificate2 Root, X509Certificate2 Leaf) BuildChain()
    {
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Dependably Test Root", rootKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));
        var root = rootReq.CreateSelfSigned(NotBefore, NotAfter);

        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Dependably Test Signer", leafKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, true));
        byte[] serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        var leafPublic = leafReq.Create(root, NotBefore, NotAfter, serial);
        var leaf = leafPublic.CopyWithPrivateKey(leafKey);

        return (root, leaf);
    }

    // Builds a TrustAnchorMaterial row for a given X.509 cert (base64 DER).
    private static TrustAnchorMaterial AnchorMaterial(X509Certificate2 cert) => new()
    {
        Id = "test-" + cert.Thumbprint,
        AnchorKind = "x509",
        KeyId = cert.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant(),
        Material = Convert.ToBase64String(cert.Export(X509ContentType.Cert)),
    };

    // Creates a NuGetProvenanceVerifier with a single per-org X.509 anchor seeded for OrgA.
    private static NuGetProvenanceVerifier VerifierForOrg(string orgId, X509Certificate2 root)
    {
        var stub = new StubPerOrgTrustAnchorStore();
        stub.AddAnchor(orgId, "nuget", AnchorMaterial(root));
        var trustStore = new NuGetSignatureTrustStore(stub);
        return new NuGetProvenanceVerifier(trustStore, NullLogger<NuGetProvenanceVerifier>.Instance);
    }

    // A minimal NuGet "signature content" document — the bytes the .signature.p7s CMS signs over.
    private static byte[] SignatureContent() => Encoding.UTF8.GetBytes(
        "Version:1\n\n2.16.840.1.101.3.4.2.1-Hash:" + Convert.ToBase64String(SHA256.HashData([1, 2, 3])) + "\n");

    private static byte[] BuildSignatureCms(X509Certificate2 leaf)
    {
        var content = new ContentInfo(SignatureContent());
        var cms = new SignedCms(content, detached: false);
        var signer = new CmsSigner(leaf) { IncludeOption = X509IncludeOption.EndCertOnly };
        cms.ComputeSignature(signer);
        return cms.Encode();
    }

    private static byte[] SignedNupkg(X509Certificate2 leaf)
        => NupkgWithSignatureBytes(BuildSignatureCms(leaf));

    private static byte[] SignedNupkgWithTamperedSignature(X509Certificate2 leaf)
    {
        byte[] cms = BuildSignatureCms(leaf);
        // Flip a byte in the encoded signature so the CMS no longer validates over its content.
        cms[cms.Length / 2] ^= 0xFF;
        return NupkgWithSignatureBytes(cms);
    }

    private static byte[] SignedNupkgWithMismatchedContent(X509Certificate2 leaf)
    {
        // Sign one content document, then swap the embedded content for a different one by
        // re-encoding a detached CMS over altered bytes — CheckSignature then fails.
        var content = new ContentInfo(SignatureContent());
        var cms = new SignedCms(content, detached: false);
        var signer = new CmsSigner(leaf) { IncludeOption = X509IncludeOption.EndCertOnly };
        cms.ComputeSignature(signer);
        byte[] encoded = cms.Encode();

        // Decode, then re-decode with a tampered copy of the encoded content octet by flipping a
        // byte in the embedded EncapsulatedContentInfo region (after the signature was computed).
        // Locate the original content bytes and corrupt the first occurrence.
        byte[] marker = SignatureContent();
        int idx = IndexOf(encoded, marker);
        if (idx >= 0)
        {
            encoded[idx] ^= 0xFF;
        }

        return NupkgWithSignatureBytes(encoded);
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }

            if (match) { return i; }
        }

        return -1;
    }

    private static byte[] UnsignedNupkg()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var nuspec = zip.CreateEntry("lib.nuspec");
            using var w = new StreamWriter(nuspec.Open());
            w.Write("<package><metadata><id>lib</id></metadata></package>");
        }

        return ms.ToArray();
    }

    // Builds a nupkg ZIP carrying the given bytes at the root-level .signature.p7s entry.
    private static byte[] NupkgWithSignatureBytes(byte[] signatureBytes)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using (var nuspec = new StreamWriter(zip.CreateEntry("lib.nuspec").Open()))
            {
                nuspec.Write("<package><metadata><id>lib</id></metadata></package>");
            }

            using var sig = zip.CreateEntry(".signature.p7s").Open();
            sig.Write(signatureBytes, 0, signatureBytes.Length);
        }

        return ms.ToArray();
    }
}
