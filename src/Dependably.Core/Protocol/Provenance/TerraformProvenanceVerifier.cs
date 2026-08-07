using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Verifies the publisher-signed SHASUMS chain for a proxied Terraform provider archive against
/// per-org trust anchors stored in <c>signature_trust_anchor</c>.
///
/// A Terraform provider registry's download response for one platform carries a <c>shasum</c>
/// field, but that value is self-certified by the same authority that named the archive host — it
/// is not signed by anyone. The registry separately publishes <c>shasums_url</c> (a
/// <c>terraform-provider-{type}_{version}_SHA256SUMS</c> file listing every platform's SHA-256)
/// and <c>shasums_signature_url</c> (a detached OpenPGP signature over that file). This verifier
/// fetches both, checks the detached signature against the per-org key ring resolved from
/// <see cref="IPerOrgTrustAnchorStore"/>, and — only once the signature verifies — confirms the
/// archive's own SHA-256 appears against its filename inside the verified SHASUMS text.
///
/// The trust root is always the per-org operator-pinned ring, never the <c>signing_keys</c> the
/// download response itself supplies — fetching the verifier's own trust root from the thing it
/// is verifying would defeat the check, the same posture <see cref="RpmProvenanceVerifier"/> and
/// <see cref="MavenProvenanceVerifier"/> already take.
///
/// Result mapping: a valid detached signature whose keyid is in the pinned ring, over a SHASUMS
/// file that lists the archive's own filename with its own SHA-256 →
/// <see cref="ProvenanceStatus.Verified"/> (signer = key fingerprint); a signature present but
/// invalid, signed by an unpinned key, or a verified SHASUMS whose entry for this filename does
/// not match the archive's SHA-256 → <see cref="ProvenanceStatus.Failed"/>; SHASUMS or its
/// signature absent → <see cref="ProvenanceStatus.Unsigned"/>; no per-org anchor configured →
/// <see cref="ProvenanceStatus.NotApplicable"/>. Never throws on bad input.
/// </summary>
public sealed class TerraformProvenanceVerifier : IArtifactProvenanceVerifier
{
    private readonly IPerOrgTrustAnchorStore _trustStore;
    private readonly ILogger<TerraformProvenanceVerifier> _logger;

    public TerraformProvenanceVerifier(IPerOrgTrustAnchorStore trustStore, ILogger<TerraformProvenanceVerifier> logger)
    {
        _trustStore = trustStore;
        _logger = logger;
    }

    public string Ecosystem => "terraform";

    /// <summary>
    /// Always false at the instance level — Terraform trust anchors are per-org, not
    /// instance-wide. Use <see cref="IsConfiguredForAsync"/> to test whether a specific org has
    /// anchors. This property exists only to satisfy the <see cref="IArtifactProvenanceVerifier"/>
    /// interface contract; code that needs the per-org gate must call
    /// <see cref="IsConfiguredForAsync"/>.
    /// </summary>
    public bool IsConfigured => false;

    /// <summary>
    /// Returns true when at least one Terraform PGP trust anchor is configured for
    /// <paramref name="orgId"/>. Fail-closed: an org with no anchors cannot enable signature
    /// verification.
    /// </summary>
    public Task<bool> IsConfiguredForAsync(string orgId, CancellationToken ct = default)
        => _trustStore.IsConfiguredForAsync(orgId, "terraform", ct);

    /// <summary>
    /// Metadata-driven verification does not apply to Terraform: the signature chain is a pair of
    /// sidecar documents (SHASUMS + SHASUMS.sig), not registration metadata. The Terraform proxy
    /// path calls <see cref="VerifyArchiveAsync"/> with the fetched documents instead. Returning
    /// <see cref="ProvenanceResult.NotApplicable"/> keeps the uniform interface usable for generic
    /// resolution without implying an unsigned/failed verdict.
    /// </summary>
    public Task<ProvenanceResult> VerifyAsync(ProvenanceInput input, CancellationToken ct = default)
        => Task.FromResult(ProvenanceResult.NotApplicable);

    /// <summary>
    /// Verifies the detached OpenPGP signature in <paramref name="shasumsSigBytes"/> over
    /// <paramref name="shasumsBytes"/> against the per-org trust anchor ring for
    /// <paramref name="orgId"/>, then confirms <paramref name="filename"/>'s entry inside the
    /// verified SHASUMS text matches <paramref name="archiveSha256Hex"/>.
    ///
    /// Either sidecar null or empty maps to <see cref="ProvenanceStatus.Unsigned"/>. No per-org
    /// anchor configured maps to <see cref="ProvenanceStatus.NotApplicable"/>. Never throws.
    /// </summary>
    public async Task<ProvenanceResult> VerifyArchiveAsync(
        string orgId, string filename, string archiveSha256Hex,
        byte[]? shasumsBytes, byte[]? shasumsSigBytes, CancellationToken ct = default)
    {
        var keyRing = await _trustStore.GetTerraformKeyRingAsync(orgId, ct);
        if (keyRing is null)
        {
            return Record(ProvenanceResult.NotApplicable);
        }

        if (shasumsBytes is null || shasumsBytes.Length == 0
            || shasumsSigBytes is null || shasumsSigBytes.Length == 0)
        {
            return Record(ProvenanceResult.Unsigned);
        }

        try
        {
            return Record(VerifyShasums(filename, archiveSha256Hex, shasumsBytes, shasumsSigBytes, keyRing));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "Terraform SHASUMS signature verification threw unexpectedly ({ExceptionType}); " +
                "treating as unverifiable.",
                ex.GetType().Name);
            return Record(ProvenanceResult.Failed);
        }
    }

    // Decodes the detached OpenPGP signature over the SHASUMS bytes, resolves the signing key in
    // the operator ring, and — only once the signature verifies — checks the archive's own entry
    // inside the (now-trusted) SHASUMS text. Returns Failed (never throws) on any parse/crypto
    // failure or a mismatched/missing entry.
    internal static ProvenanceResult VerifyShasums(
        string filename, string archiveSha256Hex, byte[] shasumsBytes, byte[] shasumsSigBytes,
        PgpPublicKeyRingBundle keyRing)
    {
        var sig = ParseDetachedSignature(shasumsSigBytes);
        if (sig is null)
        {
            return ProvenanceResult.Failed;
        }

        // The key-id inside the packet is unauthenticated: it only names which pinned key to test.
        var publicKey = keyRing.GetPublicKey(sig.KeyId);
        if (publicKey is null)
        {
            return ProvenanceResult.Failed;
        }

        sig.InitVerify(publicKey);
        sig.Update(shasumsBytes);

        if (!sig.Verify())
        {
            return ProvenanceResult.Failed;
        }

        // The signature verifies, so the SHASUMS text is now a trusted document — but the check
        // is only complete once THIS archive's own filename/hash pair is found inside it. A
        // validly-signed file that simply omits (or mismatches) this platform's entry must not
        // read as verified for it.
        string? expected = FindShasumEntry(shasumsBytes, filename);
        return expected is not null
            && string.Equals(expected, archiveSha256Hex, StringComparison.OrdinalIgnoreCase)
            ? ProvenanceResult.Verified(ToHexFingerprint(publicKey.GetFingerprint()))
            : ProvenanceResult.Failed;
    }

    // Decodes a detached OpenPGP signature — ASCII-armored (.asc-style) or raw binary (the shape
    // HashiCorp's own SHASUMS.sig files ship in). GetDecoderStream inspects the leading bytes and
    // transparently dearmors when needed, so both forms parse through the same path. Returns null
    // when the bytes are not a well-formed OpenPGP signature.
    private static PgpSignature? ParseDetachedSignature(byte[] sigBytes)
    {
        try
        {
            using var decoderStream = PgpUtilities.GetDecoderStream(new MemoryStream(sigBytes, writable: false));
            var factory = new PgpObjectFactory(decoderStream);
            var obj = factory.NextPgpObject();

            if (obj is PgpCompressedData compressed)
            {
                obj = new PgpObjectFactory(compressed.GetDataStream()).NextPgpObject();
            }

            return obj is PgpSignatureList { Count: > 0 } sigList ? sigList[0] : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    // Locates `filename`'s entry in a sha256sum(1)-style SHASUMS text ("<64-hex hash>  <filename>"
    // per line, tolerating the single-space and binary-mode "*filename" forms) and returns its
    // hash, or null when no line names the filename or the hash is not 64 hex characters.
    private static string? FindShasumEntry(byte[] shasumsBytes, string filename)
    {
        string text = System.Text.Encoding.UTF8.GetString(shasumsBytes);
        foreach (string rawLine in text.Split('\n'))
        {
            string line = rawLine.TrimEnd('\r').Trim();
            if (line.Length == 0)
            {
                continue;
            }

            int sep = line.IndexOfAny([' ', '\t']);
            if (sep <= 0)
            {
                continue;
            }

            string hash = line[..sep];
            string name = line[(sep + 1)..].TrimStart(' ', '\t', '*');
            if (hash.Length == 64 && string.Equals(name, filename, StringComparison.Ordinal))
            {
                return hash;
            }
        }

        return null;
    }

    // Returns the 40-char lowercase hex fingerprint of the signing key.
    private static string ToHexFingerprint(byte[] fingerprint)
        => Convert.ToHexString(fingerprint).ToLowerInvariant();

    // Emits the OTel result counter (ecosystem + result only — no per-package labels).
    private static ProvenanceResult Record(ProvenanceResult result)
    {
        DependablyMeter.ProvenanceVerified.Add(1,
            new KeyValuePair<string, object?>("ecosystem", "terraform"),
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
