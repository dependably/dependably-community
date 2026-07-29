using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dependably.Security;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Pins the minimum-strength floor applied to operator-pinned trust anchors at import time,
/// across every <c>anchor_kind</c> the schema declares. Each "below the floor is refused"
/// assertion is paired with a "comfortably above the floor still imports" twin, so a change
/// that simply rejected every anchor could not pass.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TrustAnchorKeyStrengthTests
{
    // ── The floor itself ────────────────────────────────────────────────────────

    /// <summary>
    /// The boundary the floor draws, asserted directly. Curves below P-256 cannot be generated
    /// on every platform .NET runs on (macOS refuses P-224 outright), so the below-floor curve
    /// case is pinned here rather than through generated key material.
    /// </summary>
    [Theory]
    [InlineData(160, true, true)]
    [InlineData(192, true, true)]
    [InlineData(224, true, true)]
    [InlineData(254, true, true)]
    [InlineData(255, true, false)]   // Ed25519/X25519 — a 255-bit field at 128-bit security
    [InlineData(256, true, false)]   // P-256
    [InlineData(384, true, false)]
    [InlineData(512, false, true)]
    [InlineData(1024, false, true)]
    [InlineData(2047, false, true)]
    [InlineData(2048, false, false)]
    [InlineData(4096, false, false)]
    public void KeySizeFloor_DrawsTheLineAt2048BitsAnd255BitCurves(
        int bits, bool ellipticCurve, bool expectRefused)
    {
        string? error = TrustAnchorKeyStrength.ValidateKeySize(bits, ellipticCurve);

        Assert.Equal(expectRefused, error is not null);
    }

    // ── apk: anchor_kind='rsa' (PEM RSA public key) ──────────────────────────────

    [Fact]
    public void Rsa1024PemAnchor_IsRefused()
    {
        using var rsa = RSA.Create(1024);
        string pem = rsa.ExportSubjectPublicKeyInfoPem();

        string? error = TrustAnchorKeyStrength.Validate("rsa", pem);

        Assert.NotNull(error);
        Assert.Contains("1024-bit RSA", error);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public void RsaPemAnchorAtOrAboveTheFloor_IsAccepted(int bits)
    {
        using var rsa = RSA.Create(bits);

        Assert.Null(TrustAnchorKeyStrength.Validate("rsa", rsa.ExportSubjectPublicKeyInfoPem()));
    }

    /// <summary>
    /// Material that does not parse at all is the per-ecosystem validator's error to report,
    /// not the strength floor's — the floor must not turn a paste typo into a key-size
    /// complaint, and must not throw on it either.
    /// </summary>
    [Fact]
    public void UnparseableMaterial_IsNotTheStrengthFloorsError()
    {
        Assert.Null(TrustAnchorKeyStrength.Validate("rsa", "not a pem block"));
        Assert.Null(TrustAnchorKeyStrength.Validate("spki", "&&&not-base64&&&"));
        Assert.Null(TrustAnchorKeyStrength.Validate("x509", "garbage"));
        Assert.Null(TrustAnchorKeyStrength.Validate("pgp", "garbage"));
    }

    /// <summary>An anchor kind that carries no key at all is out of scope for the floor.</summary>
    [Fact]
    public void TrustedPublisherAnchor_CarriesNoKeyAndIsAccepted()
    {
        Assert.Null(TrustAnchorKeyStrength.Validate(
            "trusted_publisher", """{"issuer":"https://token.actions.githubusercontent.com","subject":"x"}"""));
    }

    // ── npm: anchor_kind='spki' / PyPI: 'rekor_key' (base64 ECDSA SPKI) ──────────

    [Theory]
    [InlineData("spki")]
    [InlineData("rekor_key")]
    public void EcdsaP256SpkiAnchor_IsAccepted(string anchorKind)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        Assert.Null(TrustAnchorKeyStrength.Validate(
            anchorKind, Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo())));
    }

    [Fact]
    public void EcdsaP384SpkiAnchor_IsAccepted()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        Assert.Null(TrustAnchorKeyStrength.Validate(
            "spki", Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo())));
    }

    // ── NuGet: anchor_kind='x509' / PyPI: 'sigstore_root' (X.509 certificate) ────

    [Theory]
    [InlineData("x509")]
    [InlineData("sigstore_root")]
    public void Rsa1024CertificateAnchor_IsRefused(string anchorKind)
    {
        string pem = SelfSignedRsaCertificatePem(1024);

        string? error = TrustAnchorKeyStrength.Validate(anchorKind, pem);

        Assert.NotNull(error);
        Assert.Contains("1024-bit RSA", error);
    }

    [Theory]
    [InlineData("x509")]
    [InlineData("sigstore_root")]
    public void Rsa2048CertificateAnchor_IsAccepted(string anchorKind)
    {
        Assert.Null(TrustAnchorKeyStrength.Validate(anchorKind, SelfSignedRsaCertificatePem(2048)));
    }

    [Fact]
    public void EcdsaP256CertificateAnchor_IsAccepted()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=dependably-test", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(
            new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Null(TrustAnchorKeyStrength.Validate(
            "x509", Convert.ToBase64String(cert.Export(X509ContentType.Cert))));
    }

    // ── RPM / Maven: anchor_kind='pgp' (OpenPGP public key ring) ─────────────────

    [Fact]
    public void Pgp1024RsaAnchor_IsRefused()
    {
        string armored = ArmoredPgpPublicKey(1024);

        string? error = TrustAnchorKeyStrength.Validate("pgp", armored);

        Assert.NotNull(error);
        Assert.Contains("1024-bit RSA", error);
    }

    [Fact]
    public void Pgp2048RsaAnchor_IsAccepted()
    {
        Assert.Null(TrustAnchorKeyStrength.Validate("pgp", ArmoredPgpPublicKey(2048)));
    }

    /// <summary>
    /// A well-formed OpenPGP stream whose first packet is not a public key ring (here, a
    /// literal-data packet) previously escaped as an unhandled
    /// <see cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException"/> ("PgpLiteralData found where
    /// PgpPublicKeyRing expected" — the same shape as the reported "PgpCompressedData found
    /// where PgpPublicKeyRing expected" crash, thrown by the same
    /// <see cref="PgpPublicKeyRingBundle"/> object-type check for any non-key-ring packet)
    /// instead of the documented null-on-unparseable contract. Pins that <c>ValidatePgp</c> now
    /// fails closed like every other malformed-input case.
    /// </summary>
    [Fact]
    public void PgpLiteralDataPacket_IsWellFormedOpenPgpButNotAKeyRing_ReturnsNullInsteadOfThrowing()
    {
        string material = Convert.ToBase64String(BuildPgpLiteralDataPacket());

        string? error = TrustAnchorKeyStrength.Validate("pgp", material);

        Assert.Null(error);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    // Builds a single, well-formed OpenPGP literal-data packet — valid OpenPGP framing, but
    // not a PgpPublicKeyRingBundle, which is the exact shape that previously reached
    // BouncyCastle's public-key-ring object-type check and threw PgpException rather than
    // failing closed.
    private static byte[] BuildPgpLiteralDataPacket()
    {
        using var ms = new MemoryStream();
        var litGen = new PgpLiteralDataGenerator();
        using (var os = litGen.Open(
            ms, PgpLiteralData.Binary, "x", new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc), new byte[1024]))
        {
            os.Write(System.Text.Encoding.ASCII.GetBytes("not a public key ring"));
        }

        return ms.ToArray();
    }

    private static string SelfSignedRsaCertificatePem(int bits)
    {
        using var rsa = RSA.Create(bits);
        var req = new CertificateRequest(
            "CN=dependably-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(
            new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
        return cert.ExportCertificatePem();
    }

    // Generates a real ASCII-armored OpenPGP public key of the requested modulus size, mirroring
    // the generator in PgpKeyRingBuilderTests: no PGP fixture files are committed.
    private static string ArmoredPgpPublicKey(int bits)
    {
        var gen = GeneratorUtilities.GetKeyPairGenerator("RSA");
        gen.Init(new RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001), new SecureRandom(), bits, 12));
        var kp = gen.GenerateKeyPair();

        var pgpPair = new PgpKeyPair(
            PublicKeyAlgorithmTag.RsaGeneral, kp, new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var secretKey = new PgpSecretKey(
            PgpSignature.DefaultCertification, pgpPair,
            "test@example.com", SymmetricKeyAlgorithmTag.Null,
            passPhrase: null, useSha1: true, null, null, new SecureRandom());

        using var ms = new MemoryStream();
        using (var armor = new ArmoredOutputStream(ms))
        {
            secretKey.PublicKey.Encode(armor);
        }

        return System.Text.Encoding.ASCII.GetString(ms.ToArray());
    }
}
