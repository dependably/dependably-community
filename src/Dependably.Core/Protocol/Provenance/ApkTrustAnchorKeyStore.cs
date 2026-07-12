using System.Security.Cryptography;
using Dependably.Infrastructure;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Per-org trust anchor store for Alpine apk <c>APKINDEX.tar.gz</c> signatures. Trust anchors
/// are stored as per-org rows in <c>signature_trust_anchor</c> (<c>ecosystem='apk'</c>,
/// <c>anchor_kind='rsa'</c>). Each row carries a PEM-encoded RSA public key (SPKI or PKCS#1
/// <c>-----BEGIN PUBLIC KEY-----</c> / <c>-----BEGIN RSA PUBLIC KEY-----</c> block); the
/// verifier resolves all rows at request time from <see cref="IPerOrgTrustAnchorStore"/> and
/// accepts any signature that verifies against a pinned key.
///
/// The trust root is always configured out of band by the operator — never the key embedded
/// in the upstream-fetched index itself (fetching the verifier's own trust root from the thing
/// it is verifying would defeat the check).
///
/// Unparseable entries are logged and skipped; an org with zero usable keys reports
/// <see cref="IsConfiguredForAsync"/> = false.
/// </summary>
public static class ApkTrustAnchorKeyStore
{
    /// <summary>
    /// Returns true when at least one apk RSA trust anchor is configured for <paramref name="orgId"/>.
    /// Fail-closed: an org with no anchors cannot enable signature verification.
    /// </summary>
    public static Task<bool> IsConfiguredForAsync(
        IPerOrgTrustAnchorStore store, string orgId, CancellationToken ct = default)
        => store.IsConfiguredForAsync(orgId, "apk", ct);

    // Parses a list of TrustAnchorMaterial rows into RSA public keys. Skips entries with
    // missing material or an unparseable PEM block (logged + fail-closed so a paste typo
    // surfaces as a missing anchor rather than a per-request crypto throw).
    internal static IReadOnlyList<RSA> BuildRsaKeys(IReadOnlyList<TrustAnchorMaterial> anchors, ILogger logger)
    {
        var result = new List<RSA>();
        foreach (var anchor in anchors)
        {
            string material = anchor.Material?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(material))
            {
                continue;
            }

            if (TryParseRsaPublicKey(material, out var rsa, logger))
            {
                result.Add(rsa!);
            }
        }

        return result;
    }

    /// <summary>
    /// Parses a PEM-encoded RSA public key (SPKI <c>PUBLIC KEY</c> or PKCS#1
    /// <c>RSA PUBLIC KEY</c> block). Returns false and logs a warning on failure — malformed
    /// material, a non-RSA key, or an empty/non-PEM string.
    /// </summary>
    internal static bool TryParseRsaPublicKey(string pem, out RSA? rsa, ILogger logger)
    {
        rsa = null;
        RSA? candidate = null;
        try
        {
            candidate = RSA.Create();
            candidate.ImportFromPem(pem);
            rsa = candidate;
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            candidate?.Dispose();
            logger.LogWarning(
                "apk trust anchor material could not be parsed as a PEM RSA public key "
                + "({ExceptionType}); signatures cannot be checked against this anchor.",
                ex.GetType().Name);
            return false;
        }
    }

    /// <summary>
    /// Derives the display <c>key_id</c> for an apk RSA trust anchor: <c>SHA256:</c> followed
    /// by the base64 SHA-256 digest of the key's SubjectPublicKeyInfo DER, the same convention
    /// npm registry keyids use. Returns null when the material does not parse as an RSA public key.
    /// </summary>
    public static string? DeriveKeyId(string material, ILogger logger)
    {
        if (!TryParseRsaPublicKey(material, out var rsa, logger) || rsa is null)
        {
            return null;
        }

        using (rsa)
        {
            byte[] spki = rsa.ExportSubjectPublicKeyInfo();
            byte[] hash = SHA256.HashData(spki);
            return "SHA256:" + Convert.ToBase64String(hash);
        }
    }
}
