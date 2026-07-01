using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Dependably.Infrastructure.Observability;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Verifies a PyPI PEP 740 digital attestation for a proxied distribution file, offline, using
/// only <see cref="System.Security.Cryptography"/> and JSON parsing. Stateless: trust material
/// (<see cref="PyPiTrustMaterial"/>) is resolved per-org by the caller and passed in, keeping
/// the verifier free of any repository dependency.
///
/// PEP 740 publishes <b>attestations</b> for files: the PEP 691 JSON Simple index exposes
/// <c>files[].provenance</c> (a URL to a provenance file) and/or inline <c>files[].attestations</c>.
/// A provenance file is <c>{ attestation_bundles: [{ attestations: [&lt;attestation&gt;] }] }</c>;
/// each attestation is a Sigstore bundle:
/// <list type="number">
///   <item>an <b>in-toto statement</b> whose <c>subject</c> binds the file name + sha256 digest and
///         whose <c>predicateType</c> is a PyPI publish attestation;</item>
///   <item>wrapped in a <b>DSSE envelope</b> (payload + payloadType + a signature over the DSSE
///         pre-authentication encoding);</item>
///   <item>signed by an ephemeral key whose <b>Fulcio-issued X.509 leaf certificate</b> carries the
///         publisher OIDC identity (a PyPI Trusted Publisher) in its SAN + OIDC-issuer extension,
///         with a Rekor transparency-log entry.</item>
/// </list>
///
/// This verifier enforces, fully offline:
/// <list type="number">
///   <item><b>Digest binding</b> — the statement subject's sha256 digest equals the file's sha256
///         (the bytes dependably just checksum-verified). Mismatch → <see cref="ProvenanceStatus.Failed"/>.</item>
///   <item><b>DSSE signature</b> — the envelope signature verifies over the DSSE PAE using the
///         ECDSA P-256 public key extracted from the bundle's Fulcio leaf certificate.</item>
///   <item><b>Certificate chain</b> — the leaf chains to an operator-pinned Sigstore/Fulcio root
///         (<see cref="PyPiTrustMaterial"/>, <see cref="X509ChainTrustMode.CustomRootTrust"/>,
///         never OS roots). Revocation is not checked and time validity is ignored for the chain build
///         because Fulcio certificates are deliberately short-lived. When Rekor keys are configured,
///         the <c>integratedTime</c> from the tlog entry is the authoritative signing-time bound.</item>
///   <item><b>Identity</b> — the leaf SAN identity + OIDC-issuer extension match an expected
///         Trusted Publisher (<see cref="PyPiTrustMaterial.Publishers"/>). No match →
///         <see cref="ProvenanceStatus.Failed"/>.</item>
///   <item><b>Rekor inclusion proof + SET + valid-at-signing</b> — enforced when the trust material
///         has Rekor keys (<see cref="PyPiTrustMaterial.HasRekorKeys"/> is true). The tlog entry must
///         carry a valid RFC 6962 Merkle inclusion proof, a Signed Entry Timestamp (ECDSA over the
///         canonical entry JSON) that verifies against the configured log key, and an
///         <c>integratedTime</c> that falls within the Fulcio leaf's validity window. When this
///         check is active, a bundle without a valid tlog entry is rejected. When no Rekor keys are
///         configured, this check is skipped.</item>
/// </list>
///
/// Result mapping: all checks pass → <see cref="ProvenanceStatus.Verified"/> (signer = the SAN
/// identity); no attestation present → <see cref="ProvenanceStatus.Unsigned"/>; any check fails or
/// the bundle is malformed → <see cref="ProvenanceStatus.Failed"/>. Never throws on bad input — a
/// parse/crypto failure maps to <see cref="ProvenanceStatus.Failed"/> so the proxy ingest path can
/// fail closed.
/// </summary>
public sealed class PyPiProvenanceVerifier : IArtifactProvenanceVerifier
{
    // Fulcio OIDC-issuer certificate extensions. 57264.1.1 is the v1 issuer (raw UTF-8 string);
    // 57264.1.8 is the v2 issuer (DER-encoded UTF8String). PyPI publishers use the v2 form, but
    // both are honoured so an older bundle still matches.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out",
        Justification = "Prose comment describing Sigstore OID assignments; not commented-out code.")]
    private const string FulcioIssuerV1Oid = "1.3.6.1.4.1.57264.1.1";
    private const string FulcioIssuerV2Oid = "1.3.6.1.4.1.57264.1.8";

    // The DSSE payloadType PyPI attestations carry. The PAE binds the type, so a mismatched type
    // would not verify; we additionally reject anything else up front for a clearer Failed reason.
    private const string InTotoPayloadType = "application/vnd.in-toto+json";

    // PyPI publish-attestation predicate types (v1). Accept either form; the digest binding is the
    // load-bearing check, the predicate type is a sanity gate.
    private static readonly string[] AcceptedPredicateTypes =
    {
        "https://docs.pypi.org/attestations/publish/v1",
    };

    private readonly Dependably.Infrastructure.IPerOrgTrustAnchorStore _trustStore;
    private readonly ILogger<PyPiProvenanceVerifier> _logger;

    public PyPiProvenanceVerifier(
        Dependably.Infrastructure.IPerOrgTrustAnchorStore trustStore,
        ILogger<PyPiProvenanceVerifier> logger)
    {
        _trustStore = trustStore;
        _logger = logger;
    }

    public string Ecosystem => "pypi";

    /// <summary>
    /// Always false at the instance level — PyPI trust is per-org. Use
    /// <see cref="IsConfiguredForAsync"/> to test whether a specific org has both a
    /// sigstore_root and a trusted_publisher anchor configured. This property satisfies the
    /// <see cref="IArtifactProvenanceVerifier"/> contract; code that needs the per-org gate must
    /// call <see cref="IsConfiguredForAsync"/>.
    /// </summary>
    public bool IsConfigured => false;

    /// <summary>
    /// Returns true when the org has at least one <c>sigstore_root</c> anchor AND at least one
    /// <c>trusted_publisher</c> anchor. Rekor keys are optional. The built-in
    /// <see cref="IsConfigured"/> property always returns false; this is the correct per-org gate.
    /// </summary>
    public async Task<bool> IsConfiguredForAsync(string orgId, CancellationToken ct = default)
    {
        var material = await _trustStore.GetPyPiTrustAsync(orgId, ct);
        return material.IsConfigured;
    }

    /// <summary>
    /// Resolves the per-org <see cref="PyPiTrustMaterial"/> for the given org. Used by the proxy
    /// fetch path to check configuration and pass material to <see cref="VerifyAttestation"/>
    /// in a single call without needing a direct reference to the underlying trust anchor store.
    /// </summary>
    public Task<PyPiTrustMaterial> GetTrustMaterialAsync(string orgId, CancellationToken ct = default)
        => _trustStore.GetPyPiTrustAsync(orgId, ct);

    /// <summary>
    /// Metadata-driven verification does not apply to PyPI through the generic
    /// <see cref="ProvenanceInput"/> shape: the attestation is fetched as a separate provenance
    /// document, not carried in the registry metadata signature list. The PyPI ingest path calls
    /// <see cref="VerifyAttestation"/> with the downloaded file's name + sha256, the provenance
    /// JSON, and the resolved per-org trust material. Returning
    /// <see cref="ProvenanceResult.NotApplicable"/> keeps the uniform interface usable for generic
    /// resolution without implying an unsigned/failed verdict.
    /// </summary>
    public Task<ProvenanceResult> VerifyAsync(ProvenanceInput input, CancellationToken ct = default)
        => Task.FromResult(ProvenanceResult.NotApplicable);

    /// <summary>
    /// Verifies the PEP 740 provenance/attestation JSON for a distribution file using the
    /// caller-supplied per-org trust material. The file's sha256 is the value dependably already
    /// verified the downloaded bytes against. Never throws.
    /// </summary>
    /// <param name="fileName">The distribution filename (the in-toto subject name must match it).</param>
    /// <param name="fileSha256Hex">The lowercase hex sha256 of the downloaded bytes.</param>
    /// <param name="provenanceJson">
    /// The PEP 740 provenance document, or a single inline attestation object. Null/empty when the
    /// file carries no attestation → <see cref="ProvenanceStatus.Unsigned"/>.
    /// </param>
    /// <param name="trust">The per-org trust material resolved by the caller.</param>
    public ProvenanceResult VerifyAttestation(
        string fileName, string fileSha256Hex, string? provenanceJson, PyPiTrustMaterial trust)
    {
        if (string.IsNullOrWhiteSpace(provenanceJson))
        {
            return Record(ProvenanceResult.Unsigned);
        }

        List<JsonElement> attestations;
        try
        {
            attestations = ExtractAttestations(provenanceJson);
        }
        catch (JsonException)
        {
            return Record(ProvenanceResult.Failed);
        }

        if (attestations.Count == 0)
        {
            // A well-formed provenance document that lists no attestations is treated as unsigned —
            // there is nothing to verify, same as a missing document.
            return Record(ProvenanceResult.Unsigned);
        }

        // Any single attestation that passes every check establishes provenance. A bundle carrying
        // multiple attestations (multiple publishers) verifies on the first that holds.
        foreach (var attestation in attestations)
        {
            var result = VerifyOne(attestation, fileName, fileSha256Hex, trust);
            if (result.Status == ProvenanceStatus.Verified)
            {
                return Record(result);
            }
        }

        // At least one attestation was present but none verified end to end — fail closed.
        return Record(ProvenanceResult.Failed);
    }

    // Pulls the flat list of attestation objects from either a full PEP 740 provenance document
    // ({ attestation_bundles: [{ attestations: [...] }] }) or a single inline attestation object.
    private static List<JsonElement> ExtractAttestations(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement.Clone();
        var result = new List<JsonElement>();

        if (root.ValueKind == JsonValueKind.Object
            && root.TryGetProperty("attestation_bundles", out var bundles)
            && bundles.ValueKind == JsonValueKind.Array)
        {
            foreach (var bundle in bundles.EnumerateArray())
            {
                if (bundle.TryGetProperty("attestations", out var atts) && atts.ValueKind == JsonValueKind.Array)
                {
                    result.AddRange(atts.EnumerateArray());
                }
            }

            return result;
        }

        // A bare array of attestations (the PEP 691 inline files[].attestations form).
        if (root.ValueKind == JsonValueKind.Array)
        {
            result.AddRange(root.EnumerateArray());
            return result;
        }

        // A single inline attestation object (carries an "envelope").
        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("envelope", out _))
        {
            result.Add(root);
        }

        return result;
    }

    // Runs the offline checks on one attestation using the supplied per-org trust material.
    // Returns Verified only when all hold; any structural or crypto failure returns Failed (never throws).
    private ProvenanceResult VerifyOne(
        JsonElement attestation, string fileName, string fileSha256Hex, PyPiTrustMaterial trust)
    {
        try
        {
            // ── parse the bundle ────────────────────────────────────────────────────
            if (!attestation.TryGetProperty("envelope", out var envelope)
                || !envelope.TryGetProperty("statement", out var statementEl)
                || !envelope.TryGetProperty("signature", out var signatureEl))
            {
                return ProvenanceResult.Failed;
            }

            byte[] payload = Convert.FromBase64String(statementEl.GetString() ?? "");
            byte[] signature = Convert.FromBase64String(signatureEl.GetString() ?? "");

            var leaf = ExtractLeafCertificate(attestation);
            if (leaf is null)
            {
                return ProvenanceResult.Failed;
            }

            using (leaf)
            {
                // ── check 1: digest binding (subject sha256 == file sha256) ──────────
                if (!StatementBindsFile(payload, fileName, fileSha256Hex))
                {
                    return ProvenanceResult.Failed;
                }

                // ── check 2: DSSE signature over the PAE using the leaf public key ───
                if (!VerifyDsseSignature(leaf, payload, signature))
                {
                    return ProvenanceResult.Failed;
                }

                // ── check 3: leaf chains to a pinned Sigstore/Fulcio root ────────────
                if (!ChainsToPinnedRoot(leaf, trust))
                {
                    return ProvenanceResult.Failed;
                }

                // ── check 4: SAN identity + OIDC issuer match a Trusted Publisher ────
                string? identity = MatchTrustedPublisher(leaf, trust);
                if (identity is null)
                {
                    return ProvenanceResult.Failed;
                }

                // ── check 5: Rekor inclusion proof + SET + valid-at-signing ──────────
                // Enforced only when the org has configured Rekor log public keys.
                // When no keys are configured the check is skipped (opt-in, fail-closed
                // when enabled — same pattern as the other anchors).
                return trust.HasRekorKeys && !VerifyRekorEntry(attestation, leaf, trust)
                    ? ProvenanceResult.Failed
                    : ProvenanceResult.Verified(identity);
            }
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or JsonException or AsnContentException)
        {
            // Malformed base64, DER, JSON, or crypto material — fail closed.
            _logger.LogWarning(
                "PyPI attestation verification failed ({ExceptionType}); treating the file as unverifiable.",
                ex.GetType().Name);
            return ProvenanceResult.Failed;
        }
    }

    // Check 5: Rekor transparency-log entry verification.
    // Parses tlog_entries[0] from verification_material, verifies the RFC 6962 inclusion proof,
    // verifies the Signed Entry Timestamp, and checks that integratedTime is within the leaf's
    // validity window. Returns false on any parse or crypto failure.
    private bool VerifyRekorEntry(JsonElement attestation, X509Certificate2 leaf, PyPiTrustMaterial trust)
    {
        if (!TryLocateTlogEntry(attestation, out var entry))
        {
            return false;
        }

        if (!TryParseTlogEntryFields(entry, out string? bodyB64, out byte[] canonicalizedBody,
                out long integratedTime, out long logIndex, out byte[]? logIdBytes))
        {
            return false;
        }

        var rekorKey = trust.GetRekorKey(logIdBytes!);
        if (rekorKey is null)
        {
            // No configured key for this log id — fail closed when Rekor enforcement is active.
            _logger.LogWarning(
                "PyPI attestation references a Rekor log id not in the org's rekor_key anchors; "
                + "treating the file as unverifiable.");
            return false;
        }

        var inclusionProofData = ParseInclusionProof(entry);
        if (inclusionProofData is null)
        {
            return false;
        }

        // ── check 5a: RFC 6962 inclusion proof ──────────────────────────────────
        byte[] leafHash = RekorMerkle.LeafHash(canonicalizedBody);
        if (!RekorMerkle.VerifyInclusion(
                inclusionProofData.LeafIndex, inclusionProofData.TreeSize,
                leafHash, inclusionProofData.ProofHashes, inclusionProofData.RootHash))
        {
            _logger.LogWarning(
                "PyPI attestation Rekor inclusion proof did not verify; treating the file as unverifiable.");
            return false;
        }

        // ── check 5b: Signed Entry Timestamp ────────────────────────────────────
        if (!VerifySignedEntryTimestamp(entry, rekorKey, bodyB64!, integratedTime, logIdBytes!, logIndex))
        {
            return false;
        }

        // ── check 5c: leaf was valid at the proven signing time ──────────────────
        var signingTime = DateTimeOffset.FromUnixTimeSeconds(integratedTime);
        if (signingTime < leaf.NotBefore || signingTime > leaf.NotAfter)
        {
            _logger.LogWarning(
                "PyPI attestation Rekor integratedTime {IntegratedTime} is outside the Fulcio "
                + "leaf validity window; treating the file as unverifiable.",
                integratedTime);
            return false;
        }

        return true;
    }

    // Locates the first tlog entry from the attestation's verification_material.
    private static bool TryLocateTlogEntry(JsonElement attestation, out JsonElement entry)
    {
        entry = default;
        if (!attestation.TryGetProperty("verification_material", out var vm)
            && !attestation.TryGetProperty("verificationMaterial", out vm))
        {
            return false;
        }

        if (!vm.TryGetProperty("tlog_entries", out var tlogEntries)
            && !vm.TryGetProperty("tlogEntries", out tlogEntries))
        {
            return false;
        }

        if (tlogEntries.ValueKind != JsonValueKind.Array || tlogEntries.GetArrayLength() == 0)
        {
            return false;
        }

        entry = tlogEntries[0];
        return true;
    }

    // Parses the core scalar fields from a single tlog entry (body, integratedTime, logIndex, logId).
    private static bool TryParseTlogEntryFields(
        JsonElement entry,
        out string? bodyB64,
        out byte[] canonicalizedBody,
        out long integratedTime,
        out long logIndex,
        out byte[]? logIdBytes)
    {
        canonicalizedBody = Array.Empty<byte>();
        integratedTime = 0;
        logIndex = 0;
        logIdBytes = null;

        bodyB64 = TryGetString(entry, "canonicalized_body", "canonicalizedBody");
        if (string.IsNullOrWhiteSpace(bodyB64))
        {
            return false;
        }

        canonicalizedBody = Convert.FromBase64String(bodyB64);

        integratedTime = TryGetInt64(entry, "integrated_time", "integratedTime");
        if (integratedTime <= 0)
        {
            return false;
        }

        logIndex = TryGetInt64(entry, "log_index", "logIndex");

        if (entry.TryGetProperty("log_id", out var logIdEl) || entry.TryGetProperty("logId", out logIdEl))
        {
            string? keyIdB64 = TryGetString(logIdEl, "key_id", "keyId");
            if (!string.IsNullOrWhiteSpace(keyIdB64))
            {
                logIdBytes = Convert.FromBase64String(keyIdB64);
            }
        }

        return logIdBytes is not null;
    }

    // Parses the inclusion_proof object and its hashes array from the tlog entry.
    // Returns a parsed record on success, or null when any required field is absent or malformed.
    private static InclusionProofData? ParseInclusionProof(JsonElement entry)
    {
        if (!entry.TryGetProperty("inclusion_proof", out var inclusionProof)
            && !entry.TryGetProperty("inclusionProof", out inclusionProof))
        {
            return null;
        }

        long leafIndex = TryGetInt64(inclusionProof, "log_index", "logIndex");
        long treeSize = TryGetInt64(inclusionProof, "tree_size", "treeSize");

        string? rootHashStr = TryGetString(inclusionProof, "root_hash", "rootHash");
        if (string.IsNullOrWhiteSpace(rootHashStr))
        {
            return null;
        }

        byte[] rootHash = ParseHashBytes(rootHashStr);

        if (!inclusionProof.TryGetProperty("hashes", out var hashesEl)
            || hashesEl.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var proofHashes = new List<byte[]>();
        foreach (var h in hashesEl.EnumerateArray())
        {
            string? hs = h.GetString();
            if (string.IsNullOrWhiteSpace(hs))
            {
                return null;
            }

            proofHashes.Add(ParseHashBytes(hs));
        }

        return new InclusionProofData(leafIndex, treeSize, rootHash, proofHashes);
    }

    // Parsed Rekor inclusion-proof fields: Merkle tree position, root hash, and the sibling hashes.
    private sealed record InclusionProofData(long LeafIndex, long TreeSize, byte[] RootHash, List<byte[]> ProofHashes);

    // Check 5b: verifies the Signed Entry Timestamp (ECDSA over the canonical SET JSON) against
    // the configured Rekor log key. The SET canonical JSON binds body, integratedTime, logID, and
    // logIndex so a replayed or tampered SET cannot match.
    private bool VerifySignedEntryTimestamp(
        JsonElement entry, ECDsa rekorKey, string bodyB64, long integratedTime, byte[] logIdBytes, long logIndex)
    {
        string logIdHex = Convert.ToHexString(logIdBytes).ToLowerInvariant();
        string setJson = BuildSetCanonicalJson(bodyB64, integratedTime, logIdHex, logIndex);
        byte[] setJsonBytes = Encoding.UTF8.GetBytes(setJson);

        byte[]? setSignature = null;
        if (entry.TryGetProperty("inclusion_promise", out var inclusionPromise)
            || entry.TryGetProperty("inclusionPromise", out inclusionPromise))
        {
            string? setB64 = TryGetString(inclusionPromise, "signed_entry_timestamp", "signedEntryTimestamp");
            if (!string.IsNullOrWhiteSpace(setB64))
            {
                setSignature = Convert.FromBase64String(setB64);
            }
        }

        if (setSignature is null)
        {
            return false;
        }

        if (!rekorKey.VerifyData(setJsonBytes, setSignature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
        {
            _logger.LogWarning(
                "PyPI attestation Rekor SET signature did not verify; treating the file as unverifiable.");
            return false;
        }

        return true;
    }

    // Reads a string value from the first property name that is present on the element.
    private static string? TryGetString(JsonElement el, string snakeCase, string camelCase)
        => (el.TryGetProperty(snakeCase, out var v) || el.TryGetProperty(camelCase, out v))
            ? (v.ValueKind == JsonValueKind.String ? v.GetString() : null)
            : null;

    // Reads a 64-bit integer from a property that may be a number or a quoted number string.
    private static long TryGetInt64(JsonElement el, string snakeCase, string camelCase)
        => (el.TryGetProperty(snakeCase, out var v) || el.TryGetProperty(camelCase, out v))
            ? (v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out long n)
                ? n
                : v.ValueKind == JsonValueKind.String && long.TryParse(v.GetString(), out long ns)
                    ? ns
                    : 0)
            : 0;

    // SHA-256 as a lowercase hex string is always 64 characters (32 bytes × 2 hex digits).
    private const int Sha256HexLength = 64;

    // Decodes a hash string that may be base64 or lowercase hex. A 64-character string of hex
    // digits is treated as a hex-encoded SHA-256; anything else is treated as base64.
    private static byte[] ParseHashBytes(string value)
        => value.Length == Sha256HexLength && IsHexString(value)
            ? Convert.FromHexString(value)
            : Convert.FromBase64String(value);

    // Returns true when every character in the string is a valid hexadecimal digit.
    private static bool IsHexString(string s)
        => s.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F'));

    // Builds the Rekor SET canonical JSON. Keys are sorted alphabetically; values are unquoted
    // numbers for integratedTime and logIndex, and quoted strings for body and logID.
    // Canonical form: {"body":"<b64>","integratedTime":<int>,"logID":"<hex>","logIndex":<int>}
    private static string BuildSetCanonicalJson(string bodyB64, long integratedTime, string logIdHex, long logIndex)
    {
        // Key order is alphabetical: body < integratedTime < logID < logIndex.
        var sb = new StringBuilder();
        sb.Append("{\"body\":\"");
        sb.Append(bodyB64);
        sb.Append("\",\"integratedTime\":");
        sb.Append(integratedTime);
        sb.Append(",\"logID\":\"");
        sb.Append(logIdHex);
        sb.Append("\",\"logIndex\":");
        sb.Append(logIndex);
        sb.Append('}');
        return sb.ToString();
    }

    // Reads the Fulcio leaf certificate from the bundle's verification_material. Sigstore bundles
    // place it either as a single x509CertificateChain[0] / certificate, or directly as
    // "certificate"/"rawBytes". Returns null when no parseable leaf is present.
    private static X509Certificate2? ExtractLeafCertificate(JsonElement attestation)
    {
        if (!attestation.TryGetProperty("verification_material", out var vm)
            && !attestation.TryGetProperty("verificationMaterial", out vm))
        {
            return null;
        }

        // Newer Sigstore bundle: verification_material.certificate.raw_bytes (base64 DER).
        if (vm.TryGetProperty("certificate", out var certEl))
        {
            byte[]? der = ReadCertDer(certEl);
            if (der is not null)
            {
                return X509CertificateLoader.LoadCertificate(der);
            }
        }

        // Older bundle: verification_material.x509_certificate_chain.certificates[0].raw_bytes.
        if ((vm.TryGetProperty("x509_certificate_chain", out var chain)
                || vm.TryGetProperty("x509CertificateChain", out chain))
            && chain.TryGetProperty("certificates", out var certs)
            && certs.ValueKind == JsonValueKind.Array)
        {
            foreach (var c in certs.EnumerateArray())
            {
                byte[]? der = ReadCertDer(c);
                if (der is not null)
                {
                    return X509CertificateLoader.LoadCertificate(der);
                }
            }
        }

        return null;
    }

    // Reads a base64 DER certificate from a JSON node that is either a base64 string, or an object
    // carrying raw_bytes / rawBytes. Returns null when no base64 body is present.
    [SuppressMessage("Major Bug", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null signals 'no certificate data present'; an empty byte array is not a valid absent-certificate sentinel.")]
    private static byte[]? ReadCertDer(JsonElement node)
    {
        string? b64 = node.ValueKind switch
        {
            JsonValueKind.String => node.GetString(),
            JsonValueKind.Object when node.TryGetProperty("raw_bytes", out var rb) => rb.GetString(),
            JsonValueKind.Object when node.TryGetProperty("rawBytes", out var rb) => rb.GetString(),
            _ => null,
        };
        return string.IsNullOrWhiteSpace(b64) ? null : Convert.FromBase64String(b64);
    }

    // Check 1: the in-toto statement's subject must name this file and carry its sha256 digest.
    // The digest is the file dependably already checksum-verified, so this binds the attestation
    // to the exact bytes served.
    private static bool StatementBindsFile(byte[] payload, string fileName, string fileSha256Hex)
    {
        using var statement = JsonDocument.Parse(payload);
        var root = statement.RootElement;

        // Predicate-type sanity gate (the PAE-bound payloadType already constrains the envelope).
        if (root.TryGetProperty("predicateType", out var pt)
            && pt.GetString() is { } predicateType
            && Array.IndexOf(AcceptedPredicateTypes, predicateType) < 0)
        {
            return false;
        }

        if (!root.TryGetProperty("subject", out var subjects) || subjects.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var subject in subjects.EnumerateArray())
        {
            // The subject name must match the distribution filename — a digest match on a
            // different-named subject must not authorise this file.
            if (!subject.TryGetProperty("name", out var nameEl)
                || !string.Equals(nameEl.GetString(), fileName, StringComparison.Ordinal))
            {
                continue;
            }

            if (subject.TryGetProperty("digest", out var digest)
                && digest.TryGetProperty("sha256", out var sha)
                && sha.GetString() is { } subjectSha
                && string.Equals(subjectSha, fileSha256Hex, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    // Check 2: verify the DSSE envelope signature over the pre-authentication encoding (PAE).
    // DSSEv1 PAE = "DSSEv1" SP len(type) SP type SP len(body) SP body, all ASCII lengths. The
    // signature is ECDSA P-256 / SHA-256 in IEEE-P1363 fixed-size form (Sigstore's encoding).
    private static bool VerifyDsseSignature(X509Certificate2 leaf, byte[] payload, byte[] signature)
    {
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);

        using var ecdsa = leaf.GetECDsaPublicKey();
        if (ecdsa is null)
        {
            // PyPI/Fulcio leaves are ECDSA P-256; a non-EC key is not a valid Sigstore leaf.
            return false;
        }

        // Sigstore DSSE signatures are DER (Rfc3279DerSequence). Try DER first, then the fixed-size
        // P1363 form so a bundle produced by either encoder verifies.
        return ecdsa.VerifyData(pae, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
            || ecdsa.VerifyData(pae, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    // Builds the DSSEv1 pre-authentication encoding for the given payload type and body.
    private static byte[] BuildDssePae(string payloadType, byte[] payload)
    {
        // "DSSEv1 " + ASCII(len(type)) + " " + type + " " + ASCII(len(payload)) + " " + payload
        byte[] typeBytes = Encoding.ASCII.GetBytes(payloadType);
        var prefix = new StringBuilder()
            .Append("DSSEv1 ")
            .Append(typeBytes.Length).Append(' ')
            .Append(payloadType).Append(' ')
            .Append(payload.Length).Append(' ');
        byte[] prefixBytes = Encoding.ASCII.GetBytes(prefix.ToString());

        byte[] pae = new byte[prefixBytes.Length + payload.Length];
        Buffer.BlockCopy(prefixBytes, 0, pae, 0, prefixBytes.Length);
        Buffer.BlockCopy(payload, 0, pae, prefixBytes.Length, payload.Length);
        return pae;
    }

    // Check 3: the Fulcio leaf must chain to an operator-pinned Sigstore root. CustomRootTrust so
    // the OS/system roots are never implicitly trusted. Revocation NoCheck and IgnoreNotTimeValid:
    // Fulcio certs are deliberately short-lived and offline deployments must not fail-open or hang
    // on an unreachable OCSP/CRL endpoint. When Rekor keys are configured, the proven
    // integratedTime (check 5c) is the authoritative signing-time bound; the chain build keeps
    // IgnoreNotTimeValid regardless so expired short-lived leaves still chain.
    private static bool ChainsToPinnedRoot(X509Certificate2 leaf, PyPiTrustMaterial trust)
    {
        var roots = trust.GetRoots();
        using var chain = new X509Chain
        {
            ChainPolicy =
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid
                    | X509VerificationFlags.IgnoreCtlNotTimeValid,
            },
        };
        foreach (var root in roots)
        {
            chain.ChainPolicy.CustomTrustStore.Add(root);
        }

        return chain.Build(leaf);
    }

    // Check 4: the leaf's SAN identity and OIDC-issuer extension must match a configured Trusted
    // Publisher. Returns the matched SAN identity (the persisted signer) or null when no publisher
    // matches.
    private static string? MatchTrustedPublisher(X509Certificate2 leaf, PyPiTrustMaterial trust)
    {
        string? issuer = ReadFulcioIssuer(leaf);
        string? identity = ReadSanIdentity(leaf);
        return issuer is not null && identity is not null
            && trust.Publishers.Any(p => p.Matches(issuer, identity))
            ? identity
            : null;
    }

    // Reads the Fulcio OIDC-issuer extension. The v2 extension (57264.1.8) is a DER-encoded
    // UTF8String; the v1 extension (57264.1.1) is a raw UTF-8 string. Returns null when neither is
    // present or decodable.
    private static string? ReadFulcioIssuer(X509Certificate2 leaf)
    {
        foreach (var ext in leaf.Extensions)
        {
            if (ext.Oid?.Value == FulcioIssuerV2Oid)
            {
                try
                {
                    var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER);
                    return reader.ReadCharacterString(UniversalTagNumber.UTF8String);
                }
                catch (AsnContentException)
                {
                    // Fall through to try the v1 interpretation of the same bytes.
                }
            }

            if (ext.Oid?.Value == FulcioIssuerV1Oid)
            {
                return Encoding.UTF8.GetString(ext.RawData);
            }
        }

        return null;
    }

    // Subject Alternative Name extension OID.
    private const string SanOid = "2.5.29.17";

    // GeneralName context tags (RFC 5280): [6] uniformResourceIdentifier (IA5String),
    // [2] dNSName (IA5String). Fulcio places the OIDC identity (e.g. a GitHub Actions workflow
    // ref URL) in a SAN URI; we surface the first URI, falling back to the first DNS name.
    private static readonly Asn1Tag UriTag = new(TagClass.ContextSpecific, 6);
    private static readonly Asn1Tag DnsTag = new(TagClass.ContextSpecific, 2);

    // Reads the publisher identity from the leaf's SAN by parsing the GeneralNames ASN.1 directly:
    // the BCL X509SubjectAlternativeNameExtension surfaces DNS/IP but not URI GeneralNames, and the
    // Fulcio publisher identity is a URI. Returns the first URI, else the first DNS name, else null.
    private static string? ReadSanIdentity(X509Certificate2 leaf)
    {
        foreach (var ext in leaf.Extensions)
        {
            if (ext.Oid?.Value != SanOid)
            {
                continue;
            }

            try
            {
                return ParseSanGeneralNames(ext.RawData);
            }
            catch (AsnContentException)
            {
                // Malformed SAN — no identity to match; fail closed by returning null.
                return null;
            }
        }

        return null;
    }

    // Parses the GeneralNames sequence from a SAN extension's raw DER bytes. Returns the first URI
    // GeneralName (the Fulcio OIDC identity), or the first DNS name when no URI is present, or null.
    private static string? ParseSanGeneralNames(byte[] rawData)
    {
        var outer = new AsnReader(rawData, AsnEncodingRules.DER);
        var names = outer.ReadSequence();
        string? firstDns = null;
        while (names.HasData)
        {
            var tag = names.PeekTag();
            if (tag.HasSameClassAndValue(UriTag))
            {
                return names.ReadCharacterString(UniversalTagNumber.IA5String, UriTag);
            }

            if (tag.HasSameClassAndValue(DnsTag) && firstDns is null)
            {
                firstDns = names.ReadCharacterString(UniversalTagNumber.IA5String, DnsTag);
                continue;
            }

            // Skip any GeneralName form we don't surface (otherName, directoryName, …).
            names.ReadEncodedValue();
        }

        return firstDns;
    }

    // Emits the OTel result counter (ecosystem + result only — no per-file labels, to stay inside
    // the cardinality budget).
    private static ProvenanceResult Record(ProvenanceResult result)
    {
        DependablyMeter.ProvenanceVerified.Add(1,
            new KeyValuePair<string, object?>("ecosystem", "pypi"),
            new KeyValuePair<string, object?>("result", ResultLabel(result.Status)));
        return result;
    }

    private static string ResultLabel(ProvenanceStatus status) => status switch
    {
        ProvenanceStatus.Verified => "verified",
        ProvenanceStatus.Failed => "failed",
        ProvenanceStatus.Unsigned => "unsigned",
        _ => "not_applicable",
    };
}
