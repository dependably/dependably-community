using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Dependably.Security;

/// <summary>
/// Minimum-strength floor applied to operator-pinned signature trust anchors at import time.
///
/// <para>An anchor is the trust root every per-ecosystem verifier resolves to, so its key
/// strength bounds the strength of every verdict derived from it. The floor is a <b>hard</b>
/// one rather than an opt-in: unlike the digest algorithms an upstream ecosystem forces on us,
/// the anchor key is chosen by the operator, and no ecosystem requires a key below the
/// NIST SP 800-57 / BSI TR-02102 floor that has stood since 2010.</para>
///
/// <para>Enforcement is at <b>import</b> only (<c>POST /api/v1/trust-anchors</c>), where the
/// operator is present and gets an immediate, actionable rejection. Anchors already stored
/// keep verifying: a floor applied at verification time would turn an upgrade into a silent
/// registry-wide outage for anyone holding a legacy key, with the failure surfacing as a
/// signature mismatch rather than as "your anchor is too weak".</para>
/// </summary>
public static class TrustAnchorKeyStrength
{
    /// <summary>Minimum modulus size for finite-field keys (RSA, DSA, ElGamal), in bits.</summary>
    public const int MinimumRsaBits = 2048;

    /// <summary>
    /// Minimum field size for elliptic-curve keys, in bits. 255 rather than 256 so Ed25519 and
    /// X25519 (a 255-bit field at the 128-bit security level) pass, while P-224 and every
    /// smaller curve are refused.
    /// </summary>
    public const int MinimumEllipticCurveBits = 255;

    /// <summary>
    /// Validates the key strength of trust-anchor <paramref name="material"/> for the given
    /// <paramref name="anchorKind"/>. Returns null when the material meets the floor, when the
    /// kind carries no key (<c>trusted_publisher</c>), or when the material does not parse —
    /// an unparseable paste is the per-ecosystem validator's error to report, not this one's.
    /// Returns an operator-facing error string when the key parses and is below the floor.
    /// </summary>
    public static string? Validate(string anchorKind, string material) => anchorKind switch
    {
        "rsa" => ValidateRsaPem(material),
        "spki" or "rekor_key" => ValidateEcdsaSpki(material),
        "x509" or "sigstore_root" => ValidateCertificate(material),
        "pgp" => ValidatePgp(material),
        _ => null,
    };

    // apk anchors: a PEM-encoded RSA public key (SPKI or PKCS#1).
    private static string? ValidateRsaPem(string material)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(material);
            return BelowRsaFloor(rsa.KeySize, "RSA");
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return null;
        }
    }

    // npm anchors and PyPI Rekor keys: a base64 (optionally PEM-armoured) ECDSA SPKI DER blob.
    private static string? ValidateEcdsaSpki(string material)
    {
        try
        {
            byte[] der = Convert.FromBase64String(StripPemArmour(material));
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(der, out _);
            return BelowCurveFloor(ecdsa.KeySize);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return null;
        }
    }

    // NuGet anchors and PyPI Sigstore roots: a PEM or raw base64 DER X.509 certificate. The
    // floor applies to whichever public key the certificate carries.
    private static string? ValidateCertificate(string material)
    {
        try
        {
            byte[] der = Convert.FromBase64String(StripPemArmour(material));
            using var cert = X509CertificateLoader.LoadCertificate(der);

            using var certRsa = cert.GetRSAPublicKey();
            if (certRsa is not null)
            {
                return BelowRsaFloor(certRsa.KeySize, "RSA");
            }

            using var certEcdsa = cert.GetECDsaPublicKey();
            return certEcdsa is not null ? BelowCurveFloor(certEcdsa.KeySize) : null;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return null;
        }
    }

    // RPM and Maven anchors: an ASCII-armored (or base64) OpenPGP public key ring. Every key in
    // the ring must clear the floor — a ring is imported whole, and the verifiers accept a
    // signature from any key it contains, so the weakest key sets the anchor's real strength.
    private static string? ValidatePgp(string material)
    {
        PgpPublicKeyRingBundle bundle;
        try
        {
            byte[] armoured = material.Contains("-----BEGIN PGP", StringComparison.Ordinal)
                ? System.Text.Encoding.UTF8.GetBytes(material)
                : Convert.FromBase64String(material.Trim());
            using var keyIn = PgpUtilities.GetDecoderStream(new MemoryStream(armoured));
            bundle = new PgpPublicKeyRingBundle(keyIn);
        }
        catch (Exception ex) when (ex is IOException or FormatException or ArgumentException
                                       or PgpException
                                       or Org.BouncyCastle.Security.SecurityUtilityException)
        {
            return null;
        }

        foreach (var ring in bundle.GetKeyRings())
        {
            foreach (var key in ring.GetPublicKeys())
            {
                string? error = IsFiniteFieldAlgorithm(key.Algorithm)
                    ? BelowRsaFloor(key.BitStrength, NameOf(key.Algorithm))
                    : BelowCurveFloor(key.BitStrength);
                if (error is not null)
                {
                    return error;
                }
            }
        }

        return null;
    }

    private static bool IsFiniteFieldAlgorithm(PublicKeyAlgorithmTag algorithm) => algorithm
        is PublicKeyAlgorithmTag.RsaGeneral
        or PublicKeyAlgorithmTag.RsaEncrypt
        or PublicKeyAlgorithmTag.RsaSign
        or PublicKeyAlgorithmTag.Dsa
        or PublicKeyAlgorithmTag.ElGamalGeneral
        or PublicKeyAlgorithmTag.ElGamalEncrypt;

    private static string NameOf(PublicKeyAlgorithmTag algorithm) => algorithm switch
    {
        PublicKeyAlgorithmTag.Dsa => "DSA",
        PublicKeyAlgorithmTag.ElGamalGeneral or PublicKeyAlgorithmTag.ElGamalEncrypt => "ElGamal",
        _ => "RSA",
    };

    /// <summary>
    /// Applies the floor to an already-parsed key of <paramref name="bits"/> bits. Returns null
    /// when the key clears its floor, an operator-facing error otherwise.
    /// <paramref name="ellipticCurve"/> selects which floor applies: the elliptic-curve field
    /// size or the finite-field modulus size.
    /// </summary>
    public static string? ValidateKeySize(int bits, bool ellipticCurve) =>
        ellipticCurve ? BelowCurveFloor(bits) : BelowRsaFloor(bits, "RSA");

    private static string? BelowRsaFloor(int bits, string algorithmName) =>
        bits >= MinimumRsaBits
            ? null
            : $"the key is {bits}-bit {algorithmName}, below the {MinimumRsaBits}-bit minimum for a "
              + "trust anchor. A trust anchor bounds the strength of every signature verdict derived "
              + "from it, and keys below 2048 bits are under the NIST SP 800-57 / BSI TR-02102 floor. "
              + "Rotate to a key of at least 2048 bits and pin that instead.";

    private static string? BelowCurveFloor(int bits) =>
        bits >= MinimumEllipticCurveBits
            ? null
            : $"the key is on a {bits}-bit elliptic curve, below the {MinimumEllipticCurveBits}-bit "
              + "minimum for a trust anchor. A trust anchor bounds the strength of every signature "
              + "verdict derived from it. Rotate to P-256 or stronger and pin that instead.";

    // Strips PEM armour and whitespace to leave the base64 body; a raw base64 string passes
    // through unchanged after whitespace removal.
    private static string StripPemArmour(string value)
    {
        string trimmed = value.Trim();
        if (!trimmed.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            return string.Concat(trimmed.Where(c => !char.IsWhiteSpace(c)));
        }

        var sb = new System.Text.StringBuilder();
        bool inBody = false;
        foreach (string line in trimmed.Split('\n'))
        {
            string l = line.Trim();
            if (l.StartsWith("-----BEGIN", StringComparison.Ordinal)) { inBody = true; continue; }
            if (l.StartsWith("-----END", StringComparison.Ordinal)) { break; }
            if (inBody) { sb.Append(l); }
        }

        return sb.ToString();
    }
}
