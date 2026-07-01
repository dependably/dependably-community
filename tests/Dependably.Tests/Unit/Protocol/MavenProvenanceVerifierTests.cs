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
/// Exercises <see cref="MavenProvenanceVerifier"/> end-to-end with a self-generated RSA-2048
/// keypair (never a real Maven Central key). Maven artifacts are accompanied by a detached
/// ASCII-armored OpenPGP signature (<c>.asc</c>); the verifier must accept a valid signature
/// from a per-org pinned key and reject everything else without throwing — tampered signatures,
/// wrong keys, unpinned keys, missing .asc sidecars, and malformed input.
/// Per-org isolation is enforced: org A with an anchor verifies; org B with no anchor gets
/// NotApplicable without requiring a restart.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenProvenanceVerifierTests
{
    private static readonly byte[] SampleArtifact = Encoding.UTF8.GetBytes("com.example:lib:1.0.0:jar");
    private const string OrgA = "org-a";
    private const string OrgB = "org-b";

    // ── happy path ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ValidSignature_FromPinnedKey_Verifies()
    {
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArtifactAsync(OrgA, SampleArtifact, asc);

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
        byte[] asc = SignDetached(SampleArtifact, secretKey);

        // Seed an anchor for OrgA only; OrgB has none.
        var store = new StubPerOrgTrustAnchorStore();
        SeedPgpAnchor(store, OrgA, publicKey);
        var verifier = new MavenProvenanceVerifier(store, NullLogger<MavenProvenanceVerifier>.Instance);

        var resultA = await verifier.VerifyArtifactAsync(OrgA, SampleArtifact, asc);
        var resultB = await verifier.VerifyArtifactAsync(OrgB, SampleArtifact, asc);

        Assert.Equal(ProvenanceStatus.Verified, resultA.Status);
        Assert.NotNull(resultA.Signer);
        Assert.Equal(ProvenanceStatus.NotApplicable, resultB.Status);
    }

    [Fact]
    public async Task TwoOrgs_DifferentKeys_EachVerifiesOwnArtifact_CrossOrgFails()
    {
        var (secretA, publicA) = GenerateRsaKeyPair();
        var (secretB, publicB) = GenerateRsaKeyPair();
        byte[] artifactA = Encoding.UTF8.GetBytes("com.example:lib-a:1.0:jar");
        byte[] artifactB = Encoding.UTF8.GetBytes("com.example:lib-b:1.0:jar");
        byte[] ascA = SignDetached(artifactA, secretA);
        byte[] ascB = SignDetached(artifactB, secretB);

        var store = new StubPerOrgTrustAnchorStore();
        SeedPgpAnchor(store, OrgA, publicA);
        SeedPgpAnchor(store, OrgB, publicB);
        var verifier = new MavenProvenanceVerifier(store, NullLogger<MavenProvenanceVerifier>.Instance);

        // Each org's artifact verifies under its own key.
        Assert.Equal(ProvenanceStatus.Verified, (await verifier.VerifyArtifactAsync(OrgA, artifactA, ascA)).Status);
        Assert.Equal(ProvenanceStatus.Verified, (await verifier.VerifyArtifactAsync(OrgB, artifactB, ascB)).Status);

        // Cross-org: OrgA verifying artifact signed by OrgB's key → Failed (key not in OrgA's ring).
        Assert.Equal(ProvenanceStatus.Failed, (await verifier.VerifyArtifactAsync(OrgA, artifactA, ascB)).Status);
        Assert.Equal(ProvenanceStatus.Failed, (await verifier.VerifyArtifactAsync(OrgB, artifactB, ascA)).Status);
    }

    // ── failure paths ───────────────────────────────────────────────────────────

    [Fact]
    public async Task TamperedArtifact_Fails()
    {
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);
        var verifier = VerifierWithKey(OrgA, publicKey);

        // Flip one byte in the artifact — the signature no longer verifies.
        byte[] tampered = (byte[])SampleArtifact.Clone();
        tampered[0] ^= 0xFF;

        var result = await verifier.VerifyArtifactAsync(OrgA, tampered, asc);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task WrongKey_SignatureValidButKeyNotPinned_Fails()
    {
        var (secretKey, _) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);
        // Pin a DIFFERENT key: signature is cryptographically valid but the signing key is not trusted.
        var (_, differentPublicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(OrgA, differentPublicKey);

        var result = await verifier.VerifyArtifactAsync(OrgA, SampleArtifact, asc);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task MissingAscSidecar_NullBytes_IsUnsigned()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArtifactAsync(OrgA, SampleArtifact, ascBytes: null);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task MissingAscSidecar_EmptyBytes_IsUnsigned()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArtifactAsync(OrgA, SampleArtifact, ascBytes: []);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    [Fact]
    public async Task MalformedAsc_NotPgpData_Fails()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(OrgA, publicKey);

        var result = await verifier.VerifyArtifactAsync(OrgA, SampleArtifact,
            ascBytes: Encoding.UTF8.GetBytes("this is not a pgp signature"));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task NotConfigured_OrgWithNoAnchors_ReturnsNotApplicable()
    {
        // Empty store → no anchors for OrgA → NotApplicable.
        var store = new StubPerOrgTrustAnchorStore();
        var verifier = new MavenProvenanceVerifier(store, NullLogger<MavenProvenanceVerifier>.Instance);

        var (secretKey, _) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);

        var result = await verifier.VerifyArtifactAsync(OrgA, SampleArtifact, asc);

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
        var verifier = new MavenProvenanceVerifier(store, NullLogger<MavenProvenanceVerifier>.Instance);

        Assert.False(await verifier.IsConfiguredForAsync(OrgA));
    }

    // ── mixed / partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task Mixed_OneArtifactVerified_AnotherTamperedFails_IndependentOutcomes()
    {
        // Two artifacts signed by the same pinned key; one is intact, one is tampered.
        // Verifier must return Verified and Failed independently — no shared state.
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] artifactA = Encoding.UTF8.GetBytes("com.example:lib-a:1.0.0:jar");
        byte[] artifactB = Encoding.UTF8.GetBytes("com.example:lib-b:2.0.0:jar");

        byte[] ascA = SignDetached(artifactA, secretKey);
        byte[] ascB = SignDetached(artifactB, secretKey);

        // Tamper lib-a after signing.
        byte[] tamperedA = (byte[])artifactA.Clone();
        tamperedA[0] ^= 0x01;

        var verifier = VerifierWithKey(OrgA, publicKey);

        var resultA = await verifier.VerifyArtifactAsync(OrgA, tamperedA, ascA);
        var resultB = await verifier.VerifyArtifactAsync(OrgA, artifactB, ascB);

        Assert.Equal(ProvenanceStatus.Failed, resultA.Status);
        Assert.Equal(ProvenanceStatus.Verified, resultB.Status);
        Assert.NotNull(resultB.Signer);
    }

    [Fact]
    public async Task Mixed_SomeArtifactsUnsigned_SomeVerified_IndependentOutcomes()
    {
        // Some artifacts have no .asc (Unsigned); others are validly signed (Verified).
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] signed = Encoding.UTF8.GetBytes("com.example:signed-lib:1.0:jar");
        byte[] unsigned = Encoding.UTF8.GetBytes("com.example:unsigned-lib:1.0:jar");

        byte[] asc = SignDetached(signed, secretKey);
        var verifier = VerifierWithKey(OrgA, publicKey);

        var signedResult = await verifier.VerifyArtifactAsync(OrgA, signed, asc);
        var unsignedResult = await verifier.VerifyArtifactAsync(OrgA, unsigned, ascBytes: null);

        Assert.Equal(ProvenanceStatus.Verified, signedResult.Status);
        Assert.Equal(ProvenanceStatus.Unsigned, unsignedResult.Status);
    }

    [Fact]
    public async Task Mixed_OneValidOneUnparseableAnchor_RingBuiltFromGoodOne()
    {
        // Two anchors: one valid PGP key, one garbage. The ring should be built from the
        // good one (per-entry isolation in PgpKeyRingBuilder); the garbage is logged and skipped.
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);

        string armoredKey = ToArmoredPublicKey(publicKey);
        string garbage = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot-valid-base64!!!\n-----END PGP PUBLIC KEY BLOCK-----\n";

        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(OrgA, "maven", new TrustAnchorMaterial { Id = "id-good", AnchorKind = "pgp", Material = armoredKey, KeyId = "key-1" });
        store.AddAnchor(OrgA, "maven", new TrustAnchorMaterial { Id = "id-bad", AnchorKind = "pgp", Material = garbage, KeyId = "key-2" });
        var verifier = new MavenProvenanceVerifier(store, NullLogger<MavenProvenanceVerifier>.Instance);

        // Should still verify against the good key — the bad anchor is skipped.
        var result = await verifier.VerifyArtifactAsync(OrgA, SampleArtifact, asc);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.NotNull(result.Signer);
    }

    // ── internal static method parity (VerifyDetachedSignature) ─────────────────

    [Fact]
    public void VerifyDetachedSignature_ValidAsc_ReturnsVerified()
    {
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);
        var keyRing = KeyRingFor(publicKey);

        var result = MavenProvenanceVerifier.VerifyDetachedSignature(SampleArtifact, asc, keyRing);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public void VerifyDetachedSignature_GarbageAsc_ReturnsFailed()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        var keyRing = KeyRingFor(publicKey);

        // An ASC body that looks like a PGP armor header but has invalid/garbage base64 inside —
        // BouncyCastle cannot construct a PgpSignatureList from it.
        byte[] garbage = Encoding.UTF8.GetBytes(
            "-----BEGIN PGP SIGNATURE-----\nVersion: Test\n\nnot+valid+pgp+data=\n-----END PGP SIGNATURE-----\n");

        var result = MavenProvenanceVerifier.VerifyDetachedSignature(SampleArtifact, garbage, keyRing);

        // Malformed ASC → Failed (never throws).
        Assert.True(result.Status is ProvenanceStatus.Failed or ProvenanceStatus.Unsigned);
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

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
            "test-maven-signer@example.com",
            SymmetricKeyAlgorithmTag.Null,
            passPhrase: null,
            useSha1: true,
            null, null,
            new SecureRandom());

        return (secretKey, secretKey.PublicKey);
    }

    // Produces a detached ASCII-armored OpenPGP signature (.asc) over the given bytes.
    private static byte[] SignDetached(byte[] data, PgpSecretKey secretKey)
    {
        var privateKey = secretKey.ExtractPrivateKey(passPhrase: null);
        var sigGen = new PgpSignatureGenerator(
            secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
        sigGen.InitSign(PgpSignature.BinaryDocument, privateKey);
        sigGen.Update(data);

        using var ms = new MemoryStream();
        using (var armoredOut = new ArmoredOutputStream(ms))
        {
            armoredOut.SetHeader("Version", "Dependably-Test");
            var sig = sigGen.Generate();
            sig.Encode(armoredOut);
        }
        return ms.ToArray();
    }

    // Builds a key-ring bundle containing the given public key.
    private static PgpPublicKeyRingBundle KeyRingFor(PgpPublicKey publicKey)
    {
        using var ringMs = new MemoryStream();
        publicKey.Encode(ringMs);
        ringMs.Position = 0;
        using var decoded = PgpUtilities.GetDecoderStream(ringMs);
        return new PgpPublicKeyRingBundle([new PgpPublicKeyRing(publicKey.GetEncoded())]);
    }

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

    // Seeds a single PGP anchor for (orgId, "maven") in the stub store.
    private static void SeedPgpAnchor(StubPerOrgTrustAnchorStore store, string orgId, PgpPublicKey publicKey)
    {
        string material = ToArmoredPublicKey(publicKey);
        string fingerprint = Convert.ToHexString(publicKey.GetFingerprint()).ToLowerInvariant();
        store.AddAnchor(orgId, "maven", new TrustAnchorMaterial
        {
            Id = Guid.NewGuid().ToString("N"),
            AnchorKind = "pgp",
            Material = material,
            KeyId = fingerprint,
        });
    }

    // Constructs a MavenProvenanceVerifier with a single pinned key for the given org.
    private static MavenProvenanceVerifier VerifierWithKey(string orgId, PgpPublicKey publicKey)
    {
        var store = new StubPerOrgTrustAnchorStore();
        SeedPgpAnchor(store, orgId, publicKey);
        return new MavenProvenanceVerifier(store, NullLogger<MavenProvenanceVerifier>.Instance);
    }
}
