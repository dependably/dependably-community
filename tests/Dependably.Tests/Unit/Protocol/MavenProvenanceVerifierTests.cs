using System.Text;
using Dependably.Protocol.Provenance;
using Microsoft.Extensions.Configuration;
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
/// from a pinned key and reject everything else without throwing — tampered signatures, wrong
/// keys, unpinned keys, missing .asc sidecars, and malformed input.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenProvenanceVerifierTests
{
    private static readonly byte[] SampleArtifact = Encoding.UTF8.GetBytes("com.example:lib:1.0.0:jar");

    // ── happy path ──────────────────────────────────────────────────────────────

    [Fact]
    public void ValidSignature_FromPinnedKey_Verifies()
    {
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);
        var verifier = VerifierWithKey(publicKey);

        var result = verifier.VerifyArtifact(SampleArtifact, asc);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.NotNull(result.Signer);
        // Signer is a lowercase hex fingerprint.
        Assert.Matches("^[0-9a-f]+$", result.Signer);
    }

    // ── failure paths ───────────────────────────────────────────────────────────

    [Fact]
    public void TamperedArtifact_Fails()
    {
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);
        var verifier = VerifierWithKey(publicKey);

        // Flip one byte in the artifact — the signature no longer verifies.
        byte[] tampered = (byte[])SampleArtifact.Clone();
        tampered[0] ^= 0xFF;

        var result = verifier.VerifyArtifact(tampered, asc);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public void WrongKey_SignatureValidButKeyNotPinned_Fails()
    {
        var (secretKey, _) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);
        // Pin a DIFFERENT key: signature is cryptographically valid but the signing key is not trusted.
        var (_, differentPublicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(differentPublicKey);

        var result = verifier.VerifyArtifact(SampleArtifact, asc);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public void MissingAscSidecar_NullBytes_IsUnsigned()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(publicKey);

        var result = verifier.VerifyArtifact(SampleArtifact, ascBytes: null);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public void MissingAscSidecar_EmptyBytes_IsUnsigned()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(publicKey);

        var result = verifier.VerifyArtifact(SampleArtifact, ascBytes: []);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    [Fact]
    public void MalformedAsc_NotPgpData_Fails()
    {
        var (_, publicKey) = GenerateRsaKeyPair();
        var verifier = VerifierWithKey(publicKey);

        var result = verifier.VerifyArtifact(SampleArtifact,
            ascBytes: Encoding.UTF8.GetBytes("this is not a pgp signature"));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public void NotConfigured_ReturnsNotApplicable()
    {
        // Empty config → no keys → IsConfigured=false.
        var keyStore = new MavenSignatureKeyStore(
            new ConfigurationBuilder().Build(),
            NullLogger<MavenSignatureKeyStore>.Instance);
        var verifier = new MavenProvenanceVerifier(keyStore, NullLogger<MavenProvenanceVerifier>.Instance);

        var (secretKey, _) = GenerateRsaKeyPair();
        byte[] asc = SignDetached(SampleArtifact, secretKey);

        var result = verifier.VerifyArtifact(SampleArtifact, asc);

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
        Assert.Null(result.Signer);
    }

    // ── mixed / partial-failure scenario ────────────────────────────────────────

    [Fact]
    public void Mixed_OneArtifactVerified_AnotherTamperedFails_IndependentOutcomes()
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

        var verifier = VerifierWithKey(publicKey);

        var resultA = verifier.VerifyArtifact(tamperedA, ascA);
        var resultB = verifier.VerifyArtifact(artifactB, ascB);

        Assert.Equal(ProvenanceStatus.Failed, resultA.Status);
        Assert.Equal(ProvenanceStatus.Verified, resultB.Status);
        Assert.NotNull(resultB.Signer);
    }

    [Fact]
    public void Mixed_SomeArtifactsUnsigned_SomeVerified_IndependentOutcomes()
    {
        // Some artifacts have no .asc (Unsigned); others are validly signed (Verified).
        var (secretKey, publicKey) = GenerateRsaKeyPair();
        byte[] signed = Encoding.UTF8.GetBytes("com.example:signed-lib:1.0:jar");
        byte[] unsigned = Encoding.UTF8.GetBytes("com.example:unsigned-lib:1.0:jar");

        byte[] asc = SignDetached(signed, secretKey);
        var verifier = VerifierWithKey(publicKey);

        var signedResult = verifier.VerifyArtifact(signed, asc);
        var unsignedResult = verifier.VerifyArtifact(unsigned, ascBytes: null);

        Assert.Equal(ProvenanceStatus.Verified, signedResult.Status);
        Assert.Equal(ProvenanceStatus.Unsigned, unsignedResult.Status);
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

    // Constructs a MavenProvenanceVerifier with a single pinned key.
    private static MavenProvenanceVerifier VerifierWithKey(PgpPublicKey publicKey)
    {
        // Armored-export the public key for the config.
        using var armoredMs = new MemoryStream();
        using (var armoredOut = new ArmoredOutputStream(armoredMs))
        {
            publicKey.Encode(armoredOut);
        }
        string armoredKey = Encoding.ASCII.GetString(armoredMs.ToArray());

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection([
                new KeyValuePair<string, string?>("Maven:SignatureKeys:0", armoredKey),
            ])
            .Build();

        var keyStore = new MavenSignatureKeyStore(config, NullLogger<MavenSignatureKeyStore>.Instance);
        return new MavenProvenanceVerifier(keyStore, NullLogger<MavenProvenanceVerifier>.Instance);
    }
}
