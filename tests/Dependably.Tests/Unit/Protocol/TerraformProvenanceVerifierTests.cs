using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Exercises <see cref="TerraformProvenanceVerifier"/> end-to-end with a self-generated RSA-2048
/// keypair (never a real HashiCorp key). A Terraform provider registry publishes a SHASUMS file
/// listing every platform's SHA-256 alongside a detached OpenPGP signature over it
/// (SHASUMS.sig); the verifier must accept a valid signature from a per-org pinned key AND
/// confirm the archive's own SHA-256 appears against its filename inside the now-trusted SHASUMS
/// text — rejecting a validly-signed file that simply omits or mismatches this platform's entry,
/// tampered SHASUMS, wrong keys, unpinned keys, missing sidecars, and malformed input, all
/// without throwing. Per-org isolation is enforced: org A with an anchor verifies; org B with no
/// anchor gets NotApplicable without requiring a restart.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TerraformProvenanceVerifierTests
{
    private const string Filename = "terraform-provider-random_3.6.0_linux_amd64.zip";
    private const string ArchiveSha256 =
        "b5b2b8ae6aade095e7dde6e218993b256794a7fea65fd26a40db1ccf97647729";
    private const string OtherFilename = "terraform-provider-random_3.6.0_darwin_arm64.zip";
    private const string OtherSha256 =
        "c6c3c9bf7bbf1a06f8eef7f329aa4367905b8b1fb76f37b51ee2ddf08758838a";
    private const string OrgA = "org-a";
    private const string OrgB = "org-b";

    // ── happy path ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ValidSignature_ShasumsListsTheArchive_Verifies()
    {
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename), (OtherSha256, OtherFilename));
        byte[] sig = SignDetached(shasums, secretKey);
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArchiveAsync(OrgA, Filename, ArchiveSha256, shasums, sig);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.NotNull(result.Signer);
        // Signer is a lowercase hex fingerprint.
        Assert.Matches("^[0-9a-f]+$", result.Signer);
    }

    // ── per-org isolation ────────────────────────────────────────────────────────

    [Fact]
    public async Task OrgA_WithAnchor_Verifies_OrgB_WithNoAnchor_IsNotApplicable()
    {
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        byte[] sig = SignDetached(shasums, secretKey);

        var store = new StubPerOrgTrustAnchorStore();
        SeedPgpAnchor(store, OrgA, publicKey);
        var verifier = new TerraformProvenanceVerifier(store, NullLogger<TerraformProvenanceVerifier>.Instance);

        var resultA = await verifier.VerifyArchiveAsync(OrgA, Filename, ArchiveSha256, shasums, sig);
        var resultB = await verifier.VerifyArchiveAsync(OrgB, Filename, ArchiveSha256, shasums, sig);

        Assert.Equal(ProvenanceStatus.Verified, resultA.Status);
        Assert.NotNull(resultA.Signer);
        Assert.Equal(ProvenanceStatus.NotApplicable, resultB.Status);
    }

    // ── failure paths ───────────────────────────────────────────────────────────

    [Fact]
    public async Task TamperedShasums_Fails()
    {
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        byte[] sig = SignDetached(shasums, secretKey);
        var verifier = VerifierWithKey(OrgA, publicKey);

        // Flip one byte in the SHASUMS body after signing — the signature no longer verifies.
        byte[] tampered = (byte[])shasums.Clone();
        tampered[0] ^= 0xFF;

        var result = await verifier.VerifyArchiveAsync(OrgA, Filename, ArchiveSha256, tampered, sig);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task ValidlySignedShasums_ButArchiveHashMismatches_Fails()
    {
        // The SHASUMS file itself verifies (a real signature over real bytes), but the fetched
        // archive's own SHA-256 does not match what the trusted document declares for its
        // filename — the tampering happened at the archive-host leg, not the SHASUMS leg. This is
        // the case the checksum-only shasum field in the download response cannot catch, and the
        // exact gap this verifier closes.
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        byte[] sig = SignDetached(shasums, secretKey);
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArchiveAsync(OrgA, Filename, OtherSha256, shasums, sig);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task ValidlySignedShasums_ButFilenameAbsent_Fails()
    {
        // Signature verifies, but the SHASUMS document simply never lists this platform's file —
        // a different filename's entry must not stand in for it.
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((OtherSha256, OtherFilename));
        byte[] sig = SignDetached(shasums, secretKey);
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArchiveAsync(OrgA, Filename, ArchiveSha256, shasums, sig);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task WrongKey_SignatureValidButKeyNotPinned_Fails()
    {
        var (secretKey, _) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        byte[] sig = SignDetached(shasums, secretKey);
        // Pin a DIFFERENT key: signature is cryptographically valid but the signing key is not trusted.
        var (_, differentPublicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(OrgA, differentPublicKey);

        var result = await verifier.VerifyArchiveAsync(OrgA, Filename, ArchiveSha256, shasums, sig);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task MissingShasumsSidecar_NullBytes_IsUnsigned()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArchiveAsync(
            OrgA, Filename, ArchiveSha256, shasumsBytes: null, shasumsSigBytes: null);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task MissingSignatureOnly_ShasumsPresent_IsUnsigned()
    {
        // SHASUMS fetched successfully but the signature sidecar could not be fetched (or was
        // empty) — the whole chain is unverifiable, not "half verified".
        var (_, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArchiveAsync(
            OrgA, Filename, ArchiveSha256, shasums, shasumsSigBytes: null);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    [Fact]
    public async Task MalformedSignature_NotPgpData_Fails()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArchiveAsync(
            OrgA, Filename, ArchiveSha256, shasums,
            shasumsSigBytes: Encoding.UTF8.GetBytes("this is not a pgp signature"));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task NotConfigured_OrgWithNoAnchors_ReturnsNotApplicable()
    {
        // Empty store → no anchors for OrgA → NotApplicable.
        var store = new StubPerOrgTrustAnchorStore();
        var verifier = new TerraformProvenanceVerifier(store, NullLogger<TerraformProvenanceVerifier>.Instance);

        var (secretKey, _) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        byte[] sig = SignDetached(shasums, secretKey);

        var result = await verifier.VerifyArchiveAsync(OrgA, Filename, ArchiveSha256, shasums, sig);

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
        Assert.Null(result.Signer);
    }

    // ── IsConfiguredForAsync gate ────────────────────────────────────────────────

    [Fact]
    public async Task IsConfiguredForAsync_OrgWithAnchor_ReturnsTrue()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(OrgA, publicKey);

        Assert.True(await verifier.IsConfiguredForAsync(OrgA));
    }

    [Fact]
    public async Task IsConfiguredForAsync_OrgWithNoAnchor_ReturnsFalse()
    {
        var store = new StubPerOrgTrustAnchorStore();
        var verifier = new TerraformProvenanceVerifier(store, NullLogger<TerraformProvenanceVerifier>.Instance);

        Assert.False(await verifier.IsConfiguredForAsync(OrgA));
    }

    // ── mixed / partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task Mixed_OnePlatformVerified_AnotherHashMismatched_IndependentOutcomes()
    {
        // One SHASUMS document, signed once, listing two platforms. One platform's fetched
        // archive matches its declared hash; the other's does not (a corrupted or substituted
        // archive-host download). The verifier must return Verified and Failed independently for
        // the same signed document.
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename), (OtherSha256, OtherFilename));
        byte[] sig = SignDetached(shasums, secretKey);
        var verifier = VerifierWithKey(OrgA, publicKey);

        var goodResult = await verifier.VerifyArchiveAsync(OrgA, Filename, ArchiveSha256, shasums, sig);
        // Corrupted download: the bytes hashed to something other than what SHASUMS declares.
        var badResult = await verifier.VerifyArchiveAsync(
            OrgA, OtherFilename, "0000000000000000000000000000000000000000000000000000000000000000", shasums, sig);

        Assert.Equal(ProvenanceStatus.Verified, goodResult.Status);
        Assert.NotNull(goodResult.Signer);
        Assert.Equal(ProvenanceStatus.Failed, badResult.Status);
    }

    [Fact]
    public async Task Mixed_OneValidOneUnparseableAnchor_RingBuiltFromGoodOne()
    {
        // Two anchors: one valid PGP key, one garbage. The ring should be built from the
        // good one (per-entry isolation in PgpKeyRingBuilder); the garbage is logged and skipped.
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        byte[] sig = SignDetached(shasums, secretKey);

        string armoredKey = ToArmoredPublicKey(publicKey);
        string garbage = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot-valid-base64!!!\n-----END PGP PUBLIC KEY BLOCK-----\n";

        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(OrgA, "terraform", new TrustAnchorMaterial { Id = "id-good", AnchorKind = "pgp", Material = armoredKey, KeyId = "key-1" });
        store.AddAnchor(OrgA, "terraform", new TrustAnchorMaterial { Id = "id-bad", AnchorKind = "pgp", Material = garbage, KeyId = "key-2" });
        var verifier = new TerraformProvenanceVerifier(store, NullLogger<TerraformProvenanceVerifier>.Instance);

        var result = await verifier.VerifyArchiveAsync(OrgA, Filename, ArchiveSha256, shasums, sig);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.NotNull(result.Signer);
    }

    // ── internal static method parity (VerifyShasums) ────────────────────────────

    [Fact]
    public void VerifyShasums_ValidSignatureAndMatchingHash_ReturnsVerified()
    {
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        byte[] sig = SignDetached(shasums, secretKey);
        var keyRing = KeyRingFor(publicKey);

        var result = TerraformProvenanceVerifier.VerifyShasums(Filename, ArchiveSha256, shasums, sig, keyRing);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public void VerifyShasums_GarbageSignature_ReturnsFailed()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        byte[] shasums = Shasums((ArchiveSha256, Filename));
        var keyRing = KeyRingFor(publicKey);

        byte[] garbage = Encoding.UTF8.GetBytes(
            "-----BEGIN PGP SIGNATURE-----\nVersion: Test\n\nnot+valid+pgp+data=\n-----END PGP SIGNATURE-----\n");

        var result = TerraformProvenanceVerifier.VerifyShasums(Filename, ArchiveSha256, shasums, garbage, keyRing);

        Assert.True(result.Status is ProvenanceStatus.Failed or ProvenanceStatus.Unsigned);
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

    // Builds a sha256sum(1)-style SHASUMS text: "<64-hex hash>  <filename>" per line.
    private static byte[] Shasums(params (string Sha256, string Filename)[] entries)
    {
        var sb = new StringBuilder();
        foreach (var (sha256, filename) in entries)
        {
            sb.Append(sha256).Append("  ").Append(filename).Append('\n');
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    // Generates an RSA-2048 keypair as a BouncyCastle PGP key pair.
    private static (PgpSecretKey SecretKey, PgpPublicKey PublicKey) GenerateRsaKeyPair()
    {
        var gen = GeneratorUtilities.GetKeyPairGenerator("RSA");
        gen.Init(new RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001),
            new SecureRandom(), 2048, 12));
        var kp = gen.GenerateKeyPair();

        var pgpPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp,
            new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var secretKey = new PgpSecretKey(
            PgpSignature.DefaultCertification,
            pgpPair,
            "test-terraform-signer@example.com",
            SymmetricKeyAlgorithmTag.Null,
            passPhrase: null,
            useSha1: true,
            null, null,
            new SecureRandom());

        return (secretKey, secretKey.PublicKey);
    }

    // Produces a detached, non-armored (binary) OpenPGP signature over the given bytes — the
    // shape HashiCorp's own SHASUMS.sig files ship in.
    private static byte[] SignDetached(byte[] data, PgpSecretKey secretKey)
    {
        var privateKey = secretKey.ExtractPrivateKey(passPhrase: null);
        var sigGen = new PgpSignatureGenerator(
            secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
        sigGen.InitSign(PgpSignature.BinaryDocument, privateKey);
        sigGen.Update(data);

        using var ms = new MemoryStream();
        var sig = sigGen.Generate();
        sig.Encode(ms);
        return ms.ToArray();
    }

    // Builds a key-ring bundle containing the given public key.
    private static PgpPublicKeyRingBundle KeyRingFor(PgpPublicKey publicKey)
        => new([new PgpPublicKeyRing(publicKey.GetEncoded())]);

    // Exports a PGP public key as an ASCII-armored string.
    private static string ToArmoredPublicKey(PgpPublicKey publicKey)
    {
        using var ms = new MemoryStream();
        using (var armoredOut = new ArmoredOutputStream(ms))
        {
            publicKey.Encode(armoredOut);
        }
        return Encoding.ASCII.GetString(ms.ToArray());
    }

    // Seeds a single PGP anchor for (orgId, "terraform") in the stub store.
    private static void SeedPgpAnchor(StubPerOrgTrustAnchorStore store, string orgId, PgpPublicKey publicKey)
    {
        string material = ToArmoredPublicKey(publicKey);
        string fingerprint = Convert.ToHexString(publicKey.GetFingerprint()).ToLowerInvariant();
        store.AddAnchor(orgId, "terraform", new TrustAnchorMaterial
        {
            Id = Guid.NewGuid().ToString("N"),
            AnchorKind = "pgp",
            Material = material,
            KeyId = fingerprint,
        });
    }

    // Constructs a TerraformProvenanceVerifier with a single pinned key for the given org.
    private static TerraformProvenanceVerifier VerifierWithKey(string orgId, PgpPublicKey publicKey)
    {
        var store = new StubPerOrgTrustAnchorStore();
        SeedPgpAnchor(store, orgId, publicKey);
        return new TerraformProvenanceVerifier(store, NullLogger<TerraformProvenanceVerifier>.Instance);
    }
}
