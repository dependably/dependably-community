using System.Diagnostics.CodeAnalysis;
using System.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Operator-pinned trust anchors for Maven detached <c>.asc</c> OpenPGP signature
/// verification. Mirrors the RPM <c>Rpm:GpgKey</c> posture: the trust root is always
/// configured out of band by the operator — never a key fetched from Maven Central or any
/// upstream registry, which would be circular against a MITM.
///
/// Configuration: <c>Maven:SignatureKeys</c> is a JSON array of armored or base64-encoded
/// OpenPGP public key blocks (one key or key-ring per entry). An array (rather than a single
/// value) lets operators pin multiple publisher keys (e.g. one per project group). Unparseable
/// entries are logged and skipped; a store with zero usable keys reports
/// <see cref="IsConfigured"/> = false and causes a caller with 'warn'/'block' policy to
/// produce <see cref="ProvenanceStatus.NotApplicable"/>.
/// </summary>
public sealed class MavenSignatureKeyStore
{
    private readonly PgpPublicKeyRingBundle? _keyRing;
    private readonly ILogger<MavenSignatureKeyStore> _logger;

    public MavenSignatureKeyStore(IConfiguration configuration, ILogger<MavenSignatureKeyStore> logger)
    {
        _logger = logger;
        _keyRing = LoadKeyRingOrNull(configuration.GetSection("Maven:SignatureKeys"));
    }

    /// <summary>True when at least one pinned key parsed successfully into a usable key ring.</summary>
    public bool IsConfigured => _keyRing is not null;

    /// <summary>
    /// Returns the loaded key-ring bundle, or null when no keys are configured.
    /// Callers treat a null return as not-configured (fail-closed under any enforce policy).
    /// </summary>
    public PgpPublicKeyRingBundle? GetKeyRing() => _keyRing;

    // The loop accumulates key bytes from multiple entries and tracks a loaded count for
    // error handling; side effects (logging, AddRange) make a LINQ rewrite unsafe here.
    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "Loop has logging side effects and an AddRange accumulation that LINQ Select cannot express without losing error isolation per entry.")]
    private PgpPublicKeyRingBundle? LoadKeyRingOrNull(IConfigurationSection section)
    {
        var entries = section.GetChildren().ToList();
        if (entries.Count == 0)
        {
            return null;
        }

        var allKeys = new List<byte>();
        int loaded = 0;

        foreach (var entry in entries)
        {
            string? value = entry.Value;
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            try
            {
                byte[] keyBytes = ParseKeyEntry(value);
                allKeys.AddRange(keyBytes);
                loaded++;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    "Maven:SignatureKeys entry could not be parsed as an OpenPGP public key " +
                    "({ExceptionType}); signatures from that key fail closed.",
                    ex.GetType().Name);
            }
        }

        if (loaded == 0)
        {
            return null;
        }

        try
        {
            using var combined = PgpUtilities.GetDecoderStream(new MemoryStream(allKeys.ToArray()));
            return new PgpPublicKeyRingBundle(combined);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                "Maven:SignatureKeys could not be assembled into a key-ring bundle " +
                "({ExceptionType}); Maven signature verification is disabled.",
                ex.GetType().Name);
            return null;
        }
    }

    // Accepts either ASCII-armored PGP block or base64-encoded raw bytes.
    private static byte[] ParseKeyEntry(string value)
    {
        string trimmed = value.Trim();
        if (trimmed.Contains("-----BEGIN PGP", StringComparison.Ordinal))
        {
            return Encoding.UTF8.GetBytes(trimmed);
        }

        // Try base64: strip whitespace so multi-line PEM-alike values work.
        string b64 = trimmed.Replace("\n", "").Replace("\r", "").Replace(" ", "");
        return Convert.FromBase64String(b64);
    }
}
