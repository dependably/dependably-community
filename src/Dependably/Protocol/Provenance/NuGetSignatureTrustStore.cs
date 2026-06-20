using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Operator-pinned trust anchors for NuGet package signatures. Mirrors the npm
/// <see cref="NpmSignatureKeyStore"/> / RPM <c>Rpm:GpgKey</c> posture: the trust root is always
/// configured out of band by the operator, never derived from the upstream-fetched package or
/// the system/OS certificate stores (trusting the OS roots would let any publicly-chaining
/// certificate masquerade as the registry's repository-signing identity).
///
/// Configuration: <c>NuGet:SignatureCertificates</c> is a string array of pinned anchors. Each
/// entry is either a PEM block (<c>-----BEGIN CERTIFICATE-----</c> …) or raw base64 DER of an
/// X.509 certificate — the nuget.org repository-signing root and/or intermediate(s) the operator
/// copies in after verifying them out of band. Entries that don't parse as a certificate are
/// logged and skipped (so a typo surfaces as a missing anchor → fail closed, not a per-request
/// crypto throw); a store with zero usable anchors reports <see cref="IsConfigured"/> = false.
/// </summary>
public sealed class NuGetSignatureTrustStore
{
    private readonly X509Certificate2Collection _anchors;
    private readonly ILogger<NuGetSignatureTrustStore> _logger;

    public NuGetSignatureTrustStore(IConfiguration configuration, ILogger<NuGetSignatureTrustStore> logger)
    {
        _logger = logger;
        _anchors = LoadAnchors(configuration.GetSection("NuGet:SignatureCertificates"));
    }

    /// <summary>True when at least one pinned certificate parsed into a usable trust anchor.</summary>
    public bool IsConfigured => _anchors.Count > 0;

    /// <summary>
    /// The pinned anchors as a fresh collection. Returned as a copy so callers can hand it to a
    /// per-verification <see cref="X509Chain"/> without sharing mutable state across requests.
    /// </summary>
    public X509Certificate2Collection GetAnchors() => new(_anchors);

    // The loop issues per-entry log warnings and adds to an X509Certificate2Collection, which has
    // no LINQ-compatible initialisation path; a LINQ rewrite would lose per-entry error isolation.
    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "Loop has per-entry try/catch with logging side effects; LINQ cannot express the per-entry error isolation.")]
    private X509Certificate2Collection LoadAnchors(IConfigurationSection section)
    {
        var result = new X509Certificate2Collection();
        foreach (var entry in section.GetChildren())
        {
            string? value = entry.Value;
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
                _logger.LogWarning(
                    "NuGet:SignatureCertificates entry could not be parsed as an X.509 certificate "
                    + "({ExceptionType}); it is skipped and signatures chaining only to it fail closed.",
                    ex.GetType().Name);
            }
        }

        return result;
    }

    // Strips PEM armour and whitespace to leave the base64 DER body. A raw base64 string (no
    // armour) passes through unchanged after whitespace removal.
    private static string ExtractBase64(string value)
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
