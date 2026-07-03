using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Dependably.Infrastructure;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Per-org trust anchor store for NuGet package signatures. Trust anchors are stored as
/// per-org rows in <c>signature_trust_anchor</c> (<c>ecosystem='nuget'</c>,
/// <c>anchor_kind='x509'</c>). Each row carries a PEM block or raw base64-DER X.509
/// certificate; the verifier resolves all rows at request time from
/// <see cref="IPerOrgTrustAnchorStore"/> and accepts any signature whose signer chain
/// terminates in one of the pinned anchors.
///
/// The trust root is always configured out of band by the operator — never the upstream-fetched
/// key (fetching the verifier's own trust root from the thing it is verifying defeats the check).
///
/// Unparseable entries are logged and skipped (fail-closed: that org's anchors exclude the
/// entry, so a signature chaining only to it fails); an org with zero usable certificates
/// reports <see cref="IsConfiguredForAsync"/> = false.
/// </summary>
public sealed class NuGetSignatureTrustStore
{
    private readonly IPerOrgTrustAnchorStore _store;

    public NuGetSignatureTrustStore(IPerOrgTrustAnchorStore store)
    {
        _store = store;
    }

    /// <summary>
    /// Always false at the instance level — NuGet trust anchors are per-org, not instance-wide.
    /// Use <see cref="IsConfiguredForAsync"/> to test whether a specific org has anchors.
    /// This property exists only to satisfy callers that depend on the instance-level gate;
    /// code that needs the per-org gate must call <see cref="IsConfiguredForAsync"/>.
    /// </summary>
    public bool IsConfigured => false;

    /// <summary>
    /// Returns true when at least one NuGet X.509 trust anchor is configured for
    /// <paramref name="orgId"/>. Fail-closed: an org with no anchors cannot enable
    /// signature verification.
    /// </summary>
    public Task<bool> IsConfiguredForAsync(string orgId, CancellationToken ct = default)
        => _store.IsConfiguredForAsync(orgId, "nuget", ct);

    /// <summary>
    /// Resolves the per-org anchor collection for <paramref name="orgId"/>. Entries that
    /// fail to parse as a certificate are logged and omitted. Returns an empty collection
    /// when no anchors are configured.
    /// </summary>
    public Task<X509Certificate2Collection> GetNuGetAnchorsAsync(
        string orgId, CancellationToken ct = default)
        => _store.GetNuGetAnchorsAsync(orgId, ct);

    // Parses a list of TrustAnchorMaterial rows into an X509Certificate2Collection.
    // Skips unparseable entries (logged + fail-closed so a paste typo surfaces as a missing
    // anchor rather than a per-request crypto throw). The loop is necessary for per-entry
    // try/catch with logging side effects; a LINQ rewrite would lose per-entry error isolation.
    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "Loop has per-entry try/catch with logging side effects; LINQ cannot express the per-entry error isolation.")]
    internal static X509Certificate2Collection ParseAnchors(
        IReadOnlyList<TrustAnchorMaterial> anchors, ILogger logger)
    {
        var result = new X509Certificate2Collection();
        foreach (var anchor in anchors)
        {
            string? value = anchor.Material;
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            try
            {
                // X509CertificateLoader handles raw DER bytes; for PEM we strip the armour and
                // decode the base64 body so a copied-and-pasted PEM block loads unchanged.
                byte[] der = Convert.FromBase64String(ExtractBase64(value));
                result.Add(X509CertificateLoader.LoadCertificate(der));
            }
            catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException)
            {
                logger.LogWarning(
                    "NuGet trust anchor could not be parsed as an X.509 certificate "
                    + "({ExceptionType}); it is skipped and signatures chaining only to it fail closed.",
                    ex.GetType().Name);
            }
        }

        return result;
    }

    // Derives the key_id for a trust anchor entry from the certificate's SHA-256 thumbprint.
    // The thumbprint is a stable, human-readable identifier for the cert independent of the
    // label the operator assigns.
    internal static string? DeriveKeyId(string material, ILogger logger)
    {
        string? value = material?.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            byte[] der = Convert.FromBase64String(ExtractBase64(value));
            using var cert = X509CertificateLoader.LoadCertificate(der);
            return cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256)
                       .ToLowerInvariant();
        }
        catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException)
        {
            logger.LogWarning(
                "NuGet trust anchor material could not be parsed for key_id derivation ({ExceptionType}).",
                ex.GetType().Name);
            return null;
        }
    }

    // Strips PEM armour and whitespace to leave the base64 DER body. A raw base64 string (no
    // armour) passes through unchanged after whitespace removal.
    internal static string ExtractBase64(string value)
    {
        string trimmed = value.Trim();
        if (trimmed.Contains("-----BEGIN", StringComparison.Ordinal))
        {
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

        return trimmed.Replace("\r", "").Replace("\n", "").Replace(" ", "");
    }
}
