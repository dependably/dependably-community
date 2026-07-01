using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Immutable per-org PyPI PEP 740 trust material: the Sigstore/Fulcio root anchors, the Trusted
/// Publisher allowlist, and optional Rekor transparency-log public keys. Built per-org from
/// <c>signature_trust_anchor</c> rows by <see cref="Dependably.Infrastructure.IPerOrgTrustAnchorStore"/>
/// and cached through the shared org-scoped hot cache. All three anchor kinds are public trust
/// material and are stored plaintext — no envelope encryption applies.
///
/// <c>IsConfigured</c> requires at least one <c>sigstore_root</c> AND at least one
/// <c>trusted_publisher</c>: a root with no publisher allowlist would accept any Sigstore identity,
/// and a publisher allowlist with no root has nothing to chain to. Rekor keys are optional.
/// </summary>
public sealed class PyPiTrustMaterial
{
    private readonly X509Certificate2Collection _roots;
    private readonly List<RekorLogKey> _rekorKeys;

    internal PyPiTrustMaterial(
        X509Certificate2Collection roots,
        IReadOnlyList<TrustedPublisher> publishers,
        List<RekorLogKey> rekorKeys)
    {
        _roots = roots;
        Publishers = publishers;
        _rekorKeys = rekorKeys;
    }

    /// <summary>Empty material — no anchors configured. IsConfigured is false.</summary>
    public static readonly PyPiTrustMaterial Empty = new(
        new X509Certificate2Collection(),
        Array.Empty<TrustedPublisher>(),
        new List<RekorLogKey>());

    /// <summary>
    /// True when at least one pinned Fulcio root AND at least one Trusted Publisher are present.
    /// Both halves are required: a root with no publisher allowlist would accept any
    /// Sigstore-issued identity, and a publisher allowlist with no root has nothing to chain to.
    /// </summary>
    public bool IsConfigured => _roots.Count > 0 && Publishers.Count > 0;

    /// <summary>
    /// True when at least one Rekor transparency-log public key is present. When true, the
    /// verifier enforces the full inclusion-proof + SET + valid-at-signing check on every
    /// bundle; when false, that check is skipped.
    /// </summary>
    public bool HasRekorKeys => _rekorKeys.Count > 0;

    /// <summary>
    /// The pinned roots as a fresh collection. Returned as a copy so callers can hand it to a
    /// per-verification <see cref="X509Chain"/> without sharing mutable state across requests.
    /// </summary>
    public X509Certificate2Collection GetRoots() => new(_roots);

    /// <summary>The configured Trusted Publisher allowlist (issuer + subject identity + match mode).</summary>
    public IReadOnlyList<TrustedPublisher> Publishers { get; }

    /// <summary>
    /// Looks up the Rekor log key by its log-id bytes (the raw SHA-256 of the key's SPKI DER, as
    /// carried in the bundle's <c>logId.keyId</c> field). Returns the ECDSA key whose computed
    /// SHA-256(SPKI) matches <paramref name="logIdBytes"/>, or null when no configured key matches.
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
}

/// <summary>
/// Loads per-org PyPI trust material from <c>signature_trust_anchor</c> rows. Handles three
/// anchor kinds — <c>sigstore_root</c>, <c>trusted_publisher</c>, and <c>rekor_key</c> — and
/// returns an immutable <see cref="PyPiTrustMaterial"/> used by <see cref="PyPiProvenanceVerifier"/>
/// at request time. Parsing errors are logged and skipped so a single bad row fails closed
/// rather than crashing the entire anchor set.
/// </summary>
public static class PyPiSigstoreTrustStore
{
    /// <summary>
    /// Builds a <see cref="PyPiTrustMaterial"/> from the per-org anchor rows returned by
    /// <see cref="Dependably.Infrastructure.IPerOrgTrustAnchorStore.ListAsync"/>. Returns
    /// <see cref="PyPiTrustMaterial.Empty"/> when no rows are present or all fail to parse.
    /// </summary>
    public static PyPiTrustMaterial BuildFromAnchors(
        IReadOnlyList<Dependably.Infrastructure.TrustAnchorMaterial> anchors,
        ILogger logger)
    {
        var roots = new X509Certificate2Collection();
        var publishers = new List<TrustedPublisher>();
        var rekorKeys = new List<RekorLogKey>();

        foreach (var row in anchors)
        {
            switch (row.AnchorKind)
            {
                case "sigstore_root":
                    ParseSigstoreRoot(row, roots, logger);
                    break;
                case "trusted_publisher":
                    ParseTrustedPublisher(row, publishers, logger);
                    break;
                case "rekor_key":
                    ParseRekorKey(row, rekorKeys, logger);
                    break;
            }
        }

        return new PyPiTrustMaterial(roots, publishers, rekorKeys);
    }

    // Parses a sigstore_root anchor row (PEM or base64 DER X.509). Logs and skips on failure.
    private static void ParseSigstoreRoot(
        Dependably.Infrastructure.TrustAnchorMaterial row,
        X509Certificate2Collection roots,
        ILogger logger)
    {
        try
        {
            byte[] der = Convert.FromBase64String(ExtractBase64(row.Material));
            roots.Add(X509CertificateLoader.LoadCertificate(der));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            logger.LogWarning(
                "PyPI sigstore_root anchor (id={AnchorId}) could not be parsed as X.509 ({ExceptionType}); "
                + "it is skipped and bundles chaining only to it fail closed.",
                row.Id, ex.GetType().Name);
        }
    }

    // Parses a trusted_publisher anchor row (JSON with issuer, subject, and match fields).
    private static void ParseTrustedPublisher(
        Dependably.Infrastructure.TrustAnchorMaterial row,
        List<TrustedPublisher> publishers,
        ILogger logger)
    {
        try
        {
            using var doc = JsonDocument.Parse(row.Material);
            var root = doc.RootElement;
            string? issuer = root.TryGetProperty("issuer", out var iss) ? iss.GetString() : null;
            string? subject = root.TryGetProperty("subject", out var sub) ? sub.GetString() : null;
            string? matchStr = root.TryGetProperty("match", out var m) ? m.GetString() : null;

            if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
            {
                logger.LogWarning(
                    "PyPI trusted_publisher anchor (id={AnchorId}) is missing 'issuer' or 'subject'; skipped.",
                    row.Id);
                return;
            }

            var matchMode = matchStr == "exact" ? TrustedPublisherMatchMode.Exact : TrustedPublisherMatchMode.Prefix;
            publishers.Add(new TrustedPublisher(issuer.Trim(), subject.Trim(), matchMode));
        }
        catch (JsonException ex)
        {
            logger.LogWarning(
                "PyPI trusted_publisher anchor (id={AnchorId}) could not be parsed as JSON ({ExceptionType}); skipped.",
                row.Id, ex.GetType().Name);
        }
    }

    // Parses a rekor_key anchor row (PEM or base64 DER SPKI). Recomputes SHA-256(SPKI) and warns
    // if the stored key_id doesn't match, using the computed value as ground truth.
    private static void ParseRekorKey(
        Dependably.Infrastructure.TrustAnchorMaterial row,
        List<RekorLogKey> rekorKeys,
        ILogger logger)
    {
        try
        {
            byte[] spkiDer = Convert.FromBase64String(ExtractBase64(row.Material));
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spkiDer, out _);

            byte[] computedLogId = SHA256.HashData(spkiDer);
            WarnIfKeyIdMismatch(row, computedLogId, logger);

            rekorKeys.Add(new RekorLogKey(computedLogId, ecdsa));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            logger.LogWarning(
                "PyPI rekor_key anchor (id={AnchorId}) could not be parsed as ECDSA SPKI ({ExceptionType}); "
                + "it is skipped and bundles referencing that log id fail closed.",
                row.Id, ex.GetType().Name);
        }
    }

    // When a key_id is stored, cross-validates it against the computed SHA-256(SPKI) and warns
    // on mismatch or invalid base64. The computed value is always used as the log id regardless
    // of the outcome.
    private static void WarnIfKeyIdMismatch(
        Dependably.Infrastructure.TrustAnchorMaterial row, byte[] computedLogId, ILogger logger)
    {
        if (row.KeyId is null)
        {
            return;
        }

        try
        {
            byte[] configuredLogId = Convert.FromBase64String(row.KeyId.Trim());
            if (!configuredLogId.AsSpan().SequenceEqual(computedLogId.AsSpan()))
            {
                logger.LogWarning(
                    "PyPI rekor_key anchor (id={AnchorId}): stored key_id does not match SHA-256(SPKI) "
                    + "of the key; using the computed SHA-256(SPKI) as the log id.",
                    row.Id);
            }
        }
        catch (FormatException)
        {
            logger.LogWarning(
                "PyPI rekor_key anchor (id={AnchorId}): stored key_id is not valid base64; "
                + "using the computed SHA-256(SPKI) as the log id.",
                row.Id);
        }
    }

    /// <summary>
    /// Strips PEM armour and whitespace to leave the base64 DER body. A raw base64 string (no
    /// armour) passes through unchanged after whitespace removal.
    /// </summary>
    public static string ExtractBase64(string value)
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

    /// <summary>
    /// Parses a PEM or base64 DER X.509 certificate and returns its SHA-256 thumbprint as a
    /// lowercase hex string, or null when the material does not parse. Used by the
    /// <see cref="Dependably.Api.TrustAnchorController"/> sigstore_root validator.
    /// </summary>
    public static string? DeriveRootKeyId(string material, ILogger logger)
    {
        try
        {
            byte[] der = Convert.FromBase64String(ExtractBase64(material));
            using var cert = X509CertificateLoader.LoadCertificate(der);
            byte[] thumb = cert.GetCertHash(HashAlgorithmName.SHA256);
            return Convert.ToHexString(thumb).ToLowerInvariant();
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            logger.LogWarning(
                "PyPI sigstore_root material could not be parsed as X.509 ({ExceptionType}).",
                ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// Parses a PEM or base64 DER ECDSA SPKI blob and returns the base64 SHA-256(SPKI) as the
    /// computed log id, or null when the material does not parse. Used by the
    /// <see cref="Dependably.Api.TrustAnchorController"/> rekor_key validator.
    /// </summary>
    public static string? DeriveRekorKeyId(string material, ILogger logger)
    {
        try
        {
            byte[] spkiDer = Convert.FromBase64String(ExtractBase64(material));
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spkiDer, out _);
            byte[] logId = SHA256.HashData(spkiDer);
            return Convert.ToBase64String(logId);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            logger.LogWarning(
                "PyPI rekor_key material could not be parsed as ECDSA SPKI ({ExceptionType}).",
                ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// Validates a trusted_publisher material JSON string and normalizes it, applying the smart
    /// match-mode default when the caller omits the <c>match</c> field. Returns the normalized
    /// material (with <c>match</c> always present and explicit) and null error on success, or
    /// null material and an error string on failure.
    /// </summary>
    public static (string? NormalizedMaterial, string? Error) ValidateTrustedPublisherMaterial(
        string rawMaterial)
    {
        try
        {
            using var doc = JsonDocument.Parse(rawMaterial);
            var root = doc.RootElement;
            string? issuer = root.TryGetProperty("issuer", out var iss) ? iss.GetString() : null;
            string? subject = root.TryGetProperty("subject", out var sub) ? sub.GetString() : null;
            string? matchStr = root.TryGetProperty("match", out var m) ? m.GetString() : null;

            if (string.IsNullOrWhiteSpace(issuer))
            {
                return (null, "trusted_publisher material must include a non-empty 'issuer' field.");
            }

            if (string.IsNullOrWhiteSpace(subject))
            {
                return (null, "trusted_publisher material must include a non-empty 'subject' field.");
            }

            // Validate match mode when present; otherwise apply the smart default.
            TrustedPublisherMatchMode mode;
            if (matchStr is not null)
            {
                if (matchStr is not ("prefix" or "exact"))
                {
                    return (null, "trusted_publisher 'match' must be 'prefix' or 'exact'.");
                }

                mode = matchStr == "exact"
                    ? TrustedPublisherMatchMode.Exact
                    : TrustedPublisherMatchMode.Prefix;
            }
            else
            {
                // Smart default: Exact when the subject looks like a complete workflow identity
                // (contains a .yml/.yaml workflow path AND an @ref), Prefix for truncated identities.
                mode = TrustedPublisher.InferMatchMode(subject.Trim());
            }

            // Always serialize with the match field explicit so it is stored and visible.
            string normalized = System.Text.Json.JsonSerializer.Serialize(new
            {
                issuer = issuer.Trim(),
                subject = subject.Trim(),
                match = mode == TrustedPublisherMatchMode.Exact ? "exact" : "prefix",
            });
            return (normalized, null);
        }
        catch (JsonException)
        {
            return (null,
                "trusted_publisher material must be valid JSON with 'issuer' and 'subject' fields, "
                + "and an optional 'match' field ('prefix' or 'exact').");
        }
    }
}

// A parsed Rekor transparency-log public key entry. The LogId is the SHA-256 of the key's
// SPKI DER, matching the bundle's logId.keyId field. Key is the ECDSA P-256 public key used
// to verify the Signed Entry Timestamp.
internal sealed record RekorLogKey(byte[] LogId, ECDsa Key);

/// <summary>
/// The match mode for a <see cref="TrustedPublisher"/> subject identity. Controls whether the
/// bundle leaf's SAN identity must equal the subject exactly or merely start with it.
/// <list type="bullet">
///   <item><b>Prefix</b> — the leaf identity starts with the configured subject. Use for
///         truncated identities such as <c>https://github.com/org/repo/</c> that cover any
///         workflow or ref in that repo.</item>
///   <item><b>Exact</b> — the leaf identity equals the configured subject. Use for fully-
///         qualified workflow+ref identities such as
///         <c>https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main</c>
///         that must match the specific workflow and ref.</item>
/// </list>
/// The mode is stored explicitly in the anchor material JSON so it is always visible and
/// editable; it is never silently inferred at match time from the stored text.
/// </summary>
public enum TrustedPublisherMatchMode
{
    /// <summary>Leaf identity must start with the configured subject (prefix match).</summary>
    Prefix,

    /// <summary>Leaf identity must equal the configured subject (exact match).</summary>
    Exact,
}

/// <summary>
/// An expected PyPI Trusted Publisher: the OIDC issuer that minted the Fulcio cert, the SAN
/// identity (or prefix) of the publishing workflow, and the match mode. A leaf matches when its
/// issuer equals <see cref="Issuer"/> and its SAN identity satisfies the match mode:
/// <see cref="TrustedPublisherMatchMode.Prefix"/> uses <c>StartsWith</c> (an org-level identity
/// such as <c>https://github.com/org/repo/</c> does not require re-pinning every workflow ref);
/// <see cref="TrustedPublisherMatchMode.Exact"/> requires full identity equality (a specific
/// workflow + ref such as <c>…/release.yml@refs/heads/main</c> must match exactly).
/// </summary>
public sealed record TrustedPublisher(
    string Issuer,
    string Subject,
    TrustedPublisherMatchMode MatchMode = TrustedPublisherMatchMode.Prefix)
{
    /// <summary>True when the leaf's OIDC issuer and SAN identity satisfy this publisher's match rule.</summary>
    public bool Matches(string leafIssuer, string leafIdentity) =>
        string.Equals(leafIssuer, Issuer, StringComparison.Ordinal)
        && (MatchMode == TrustedPublisherMatchMode.Exact
            ? string.Equals(leafIdentity, Subject, StringComparison.Ordinal)
            : leafIdentity.StartsWith(Subject, StringComparison.Ordinal));

    /// <summary>
    /// Infers the match mode from the subject string when the caller does not supply one
    /// explicitly. Returns <see cref="TrustedPublisherMatchMode.Exact"/> when the subject
    /// looks like a complete workflow identity (contains a workflow <c>.yml</c> or <c>.yaml</c>
    /// path segment immediately before an <c>@ref</c> suffix), otherwise returns
    /// <see cref="TrustedPublisherMatchMode.Prefix"/> for truncated/org-level identities.
    /// The inferred mode is always stored explicitly in the anchor material and surfaced in the
    /// UI — this heuristic runs only at insert time, never at match time.
    /// </summary>
    public static TrustedPublisherMatchMode InferMatchMode(string subject)
    {
        // A complete workflow identity looks like:
        //   https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main
        // It has both a workflow file extension (.yml or .yaml) AND an @ref marker.
        bool hasWorkflowExtension =
            subject.Contains(".yml@", StringComparison.OrdinalIgnoreCase)
            || subject.Contains(".yaml@", StringComparison.OrdinalIgnoreCase);

        return hasWorkflowExtension
            ? TrustedPublisherMatchMode.Exact
            : TrustedPublisherMatchMode.Prefix;
    }
}
