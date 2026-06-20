using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Operator-pinned trust material for PyPI PEP 740 attestations: the Sigstore/Fulcio root
/// anchors, the expected Trusted Publisher allowlist, and optional Rekor transparency-log public
/// keys. Mirrors the npm <see cref="NpmSignatureKeyStore"/> / NuGet
/// <see cref="NuGetSignatureTrustStore"/> / RPM <c>Rpm:GpgKey</c> posture — the trust root is
/// always configured out of band by the operator, never the material the upstream bundle ships (a
/// bundle that carried its own trust root would defeat the check).
///
/// Configuration:
/// <list type="bullet">
///   <item><c>PyPI:SigstoreRoots</c> — a string array of pinned Fulcio/Sigstore CA anchors. Each
///         entry is a PEM block or raw base64 DER X.509 certificate (a root or intermediate the
///         operator copies in after verifying it out of band against the Sigstore TUF root).
///         Entries that don't parse are logged and skipped (a typo surfaces as a missing anchor →
///         fail closed, not a per-request crypto throw).</item>
///   <item><c>PyPI:TrustedPublishers</c> — an array of <c>{ "issuer": "&lt;OIDC issuer URL&gt;",
///         "subject": "&lt;SAN identity or prefix&gt;" }</c> objects. A Fulcio leaf is accepted
///         only when its OIDC-issuer extension and SAN identity match one of these entries (the
///         subject matches exactly or as a prefix, so a workflow-ref suffix the publisher rotates
///         does not have to be re-pinned).</item>
///   <item><c>PyPI:RekorPublicKeys</c> — an optional array of Rekor transparency-log public keys:
///         <c>{ "keyId": "&lt;base64 of the SHA-256 of the key SPKI DER&gt;", "key":
///         "&lt;PEM or base64 DER SubjectPublicKeyInfo of the ECDSA P-256 log key&gt;" }</c>.
///         When this section is present and at least one entry parses, <see cref="HasRekorKeys"/>
///         is true and every attestation's transparency-log entry is verified (inclusion proof +
///         SET + valid-at-signing window). Entries that don't parse are logged and skipped (fail
///         closed posture). When the section is absent or empty, Rekor verification is skipped and
///         the verifier behaves as before.</item>
/// </list>
///
/// A store with zero usable anchors OR zero trusted publishers reports
/// <see cref="IsConfigured"/> = false: PEP 740 verification needs both a root to chain to and an
/// identity to match, so neither alone is enough to enable enforcement.
/// </summary>
public sealed class PyPiSigstoreTrustStore
{
    private readonly X509Certificate2Collection _roots;
    private readonly List<RekorLogKey> _rekorKeys;
    private readonly ILogger<PyPiSigstoreTrustStore> _logger;

    public PyPiSigstoreTrustStore(IConfiguration configuration, ILogger<PyPiSigstoreTrustStore> logger)
    {
        _logger = logger;
        _roots = LoadRoots(configuration.GetSection("PyPI:SigstoreRoots"));
        Publishers = LoadPublishers(configuration.GetSection("PyPI:TrustedPublishers"));
        _rekorKeys = LoadRekorKeys(configuration.GetSection("PyPI:RekorPublicKeys"));
    }

    /// <summary>
    /// True when at least one pinned Fulcio root AND at least one Trusted Publisher parsed. Both
    /// halves are required: a root with no publisher allowlist would accept any Sigstore-issued
    /// identity, and a publisher allowlist with no root has nothing to chain to.
    /// </summary>
    public bool IsConfigured => _roots.Count > 0 && Publishers.Count > 0;

    /// <summary>
    /// True when at least one Rekor transparency-log public key parsed from
    /// <c>PyPI:RekorPublicKeys</c>. When true, the verifier enforces the full inclusion-proof +
    /// SET + valid-at-signing check on every bundle; when false, that check is skipped.
    /// </summary>
    public bool HasRekorKeys => _rekorKeys.Count > 0;

    /// <summary>
    /// The pinned roots as a fresh collection. Returned as a copy so callers can hand it to a
    /// per-verification <see cref="X509Chain"/> without sharing mutable state across requests.
    /// </summary>
    public X509Certificate2Collection GetRoots() => new(_roots);

    /// <summary>The configured Trusted Publisher allowlist (issuer + subject identity).</summary>
    public IReadOnlyList<TrustedPublisher> Publishers { get; }

    /// <summary>
    /// Looks up the Rekor log key by its log-id bytes (the raw SHA-256 of the key's SPKI DER, as
    /// carried in the bundle's <c>logId.keyId</c> field). Returns the ECDSA key whose computed
    /// SHA-256(SPKI) matches <paramref name="logIdBytes"/>, or null when no configured key matches.
    /// The comparison is performed against the precomputed key-id stored alongside each configured
    /// key; if the configured <c>keyId</c> entry already carries the hex or base64 of the SHA-256,
    /// the match is done by comparing those bytes directly.
    /// </summary>
    // ReadOnlySpan<byte> is a ref struct and cannot be captured in a LINQ lambda; the loop form
    // is required to perform the span equality comparison safely without boxing or copying.
    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "ReadOnlySpan<byte> cannot be captured in a LINQ lambda (ref struct restriction); the foreach is required.")]
    public ECDsa? GetRekorKey(ReadOnlySpan<byte> logIdBytes)
    {
        foreach (var entry in _rekorKeys)
        {
            if (entry.LogId.AsSpan().SequenceEqual(logIdBytes))
            {
                return entry.Key;
            }
        }

        return null;
    }

    // The loop issues per-entry log warnings and adds to an X509Certificate2Collection; a LINQ
    // rewrite would lose per-entry error isolation (try/catch per entry is intentional).
    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "Loop has per-entry try/catch with logging side effects; LINQ cannot express the per-entry error isolation.")]
    private X509Certificate2Collection LoadRoots(IConfigurationSection section)
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
                byte[] der = Convert.FromBase64String(ExtractBase64(value));
                result.Add(X509CertificateLoader.LoadCertificate(der));
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                _logger.LogWarning(
                    "PyPI:SigstoreRoots entry could not be parsed as an X.509 certificate "
                    + "({ExceptionType}); it is skipped and bundles chaining only to it fail closed.",
                    ex.GetType().Name);
            }
        }

        return result;
    }

    private List<TrustedPublisher> LoadPublishers(IConfigurationSection section)
    {
        var result = new List<TrustedPublisher>();
        foreach (var entry in section.GetChildren())
        {
            string? issuer = entry["issuer"];
            string? subject = entry["subject"];
            if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
            {
                _logger.LogWarning(
                    "PyPI:TrustedPublishers entry is missing 'issuer' or 'subject'; it is skipped "
                    + "and no leaf identity can match it.");
                continue;
            }

            result.Add(new TrustedPublisher(issuer.Trim(), subject.Trim()));
        }

        return result;
    }

    private List<RekorLogKey> LoadRekorKeys(IConfigurationSection section)
    {
        var result = new List<RekorLogKey>();
        foreach (var entry in section.GetChildren())
        {
            string? keyIdB64 = entry["keyId"];
            string? keyPemOrDer = entry["key"];
            if (string.IsNullOrWhiteSpace(keyIdB64) || string.IsNullOrWhiteSpace(keyPemOrDer))
            {
                _logger.LogWarning(
                    "PyPI:RekorPublicKeys entry is missing 'keyId' or 'key'; it is skipped "
                    + "and bundles referencing that log id fail closed.");
                continue;
            }

            try
            {
                // Parse the public key from PEM or raw base64 DER SPKI.
                byte[] spkiDer = Convert.FromBase64String(ExtractBase64(keyPemOrDer));
                var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(spkiDer, out _);

                // The log id in the bundle is SHA-256(SPKI DER). Compute it from the key material
                // so we can match without trusting the configured keyId alone.
                byte[] computedLogId = SHA256.HashData(spkiDer);

                // Also decode the operator-supplied keyId for cross-validation. The configured
                // keyId may be the base64 of the raw SHA-256 bytes (Sigstore's canonical form).
                byte[] configuredLogId = Convert.FromBase64String(keyIdB64.Trim());

                // If the configured keyId doesn't match the key's own SHA-256(SPKI), log the
                // mismatch and use the computed value (the key material is the ground truth).
                if (!configuredLogId.AsSpan().SequenceEqual(computedLogId.AsSpan()))
                {
                    _logger.LogWarning(
                        "PyPI:RekorPublicKeys entry: configured keyId does not match SHA-256(SPKI) "
                        + "of the supplied key; using the computed SHA-256(SPKI) as the log id.");
                }

                result.Add(new RekorLogKey(computedLogId, ecdsa));
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                _logger.LogWarning(
                    "PyPI:RekorPublicKeys entry could not be parsed ({ExceptionType}); it is "
                    + "skipped and bundles referencing that log id fail closed.",
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

// A parsed Rekor transparency-log public key entry. The LogId is the SHA-256 of the key's
// SPKI DER, matching the bundle's logId.keyId field. Key is the ECDSA P-256 public key used
// to verify the Signed Entry Timestamp.
internal sealed record RekorLogKey(byte[] LogId, ECDsa Key);

/// <summary>
/// An expected PyPI Trusted Publisher: the OIDC issuer that minted the Fulcio cert and the SAN
/// identity (or prefix) of the publishing workflow. A leaf matches when its issuer equals
/// <see cref="Issuer"/> and its SAN identity starts with <see cref="Subject"/> — prefix-matching
/// lets a publisher pin <c>https://github.com/org/repo/</c> without re-pinning every workflow ref.
/// </summary>
public sealed record TrustedPublisher(string Issuer, string Subject)
{
    /// <summary>True when the leaf's OIDC issuer and SAN identity match this publisher.</summary>
    public bool Matches(string leafIssuer, string leafIdentity) =>
        string.Equals(leafIssuer, Issuer, StringComparison.Ordinal)
        && leafIdentity.StartsWith(Subject, StringComparison.Ordinal);
}
