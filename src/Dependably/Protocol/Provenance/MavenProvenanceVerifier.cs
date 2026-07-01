using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Verifies a detached OpenPGP <c>.asc</c> signature over a proxied Maven artefact against
/// per-org trust anchors stored in <c>signature_trust_anchor</c>.
///
/// A Maven artefact on Central and most hosted repos is accompanied by a detached ASCII-armored
/// OpenPGP signature (<c>{artifact}.asc</c>). When the Maven proxy path fetches the artefact it
/// also fetches the <c>.asc</c> sidecar; this verifier checks the sidecar over the artefact bytes
/// against the per-org key ring resolved from <see cref="IPerOrgTrustAnchorStore"/>.
///
/// The trust root is always the per-org operator-pinned ring, never the upstream-served key —
/// fetching the verifier's own trust root from the thing it is verifying would defeat the check.
///
/// Result mapping: a valid detached signature whose keyid is in the pinned ring →
/// <see cref="ProvenanceStatus.Verified"/> (signer = key fingerprint); present-but-invalid
/// signature, wrong key, or malformed signature → <see cref="ProvenanceStatus.Failed"/>; absent
/// <c>.asc</c> → <see cref="ProvenanceStatus.Unsigned"/>; no per-org anchor configured →
/// <see cref="ProvenanceStatus.NotApplicable"/>. Never throws on bad input.
/// </summary>
public sealed class MavenProvenanceVerifier : IArtifactProvenanceVerifier
{
    private readonly IPerOrgTrustAnchorStore _trustStore;
    private readonly ILogger<MavenProvenanceVerifier> _logger;

    public MavenProvenanceVerifier(IPerOrgTrustAnchorStore trustStore, ILogger<MavenProvenanceVerifier> logger)
    {
        _trustStore = trustStore;
        _logger = logger;
    }

    public string Ecosystem => "maven";

    /// <summary>
    /// Always false at the instance level — Maven trust anchors are per-org, not instance-wide.
    /// Use <see cref="IsConfiguredForAsync"/> to test whether a specific org has anchors.
    /// This property exists only to satisfy the <see cref="IArtifactProvenanceVerifier"/> interface
    /// contract; code that needs the per-org gate must call <see cref="IsConfiguredForAsync"/>.
    /// </summary>
    public bool IsConfigured => false;

    /// <summary>
    /// Returns true when at least one Maven PGP trust anchor is configured for <paramref name="orgId"/>.
    /// Fail-closed: an org with no anchors cannot enable signature verification.
    /// </summary>
    public Task<bool> IsConfiguredForAsync(string orgId, CancellationToken ct = default)
        => _trustStore.IsConfiguredForAsync(orgId, "maven", ct);

    /// <summary>
    /// Metadata-driven verification does not apply to Maven: the signature is a detached file
    /// (<c>.asc</c>), not carried in the registration metadata. The Maven ingest path calls
    /// <see cref="VerifyArtifactAsync"/> with both streams instead. Returning
    /// <see cref="ProvenanceResult.NotApplicable"/> keeps the uniform interface usable for
    /// generic resolution without implying an unsigned/failed verdict.
    /// </summary>
    public Task<ProvenanceResult> VerifyAsync(ProvenanceInput input, CancellationToken ct = default)
        => Task.FromResult(ProvenanceResult.NotApplicable);

    /// <summary>
    /// Verifies the detached <c>.asc</c> OpenPGP signature in <paramref name="ascBytes"/>
    /// over <paramref name="artifactBytes"/> against the per-org trust anchor ring for
    /// <paramref name="orgId"/>.
    ///
    /// <paramref name="ascBytes"/> null or empty maps to <see cref="ProvenanceStatus.Unsigned"/>.
    /// No per-org anchor configured maps to <see cref="ProvenanceStatus.NotApplicable"/>. Never throws.
    /// </summary>
    public async Task<ProvenanceResult> VerifyArtifactAsync(
        string orgId, byte[] artifactBytes, byte[]? ascBytes, CancellationToken ct = default)
    {
        var keyRing = await _trustStore.GetMavenKeyRingAsync(orgId, ct);
        if (keyRing is null)
        {
            return Record(ProvenanceResult.NotApplicable);
        }

        if (ascBytes is null || ascBytes.Length == 0)
        {
            return Record(ProvenanceResult.Unsigned);
        }

        try
        {
            return Record(VerifyDetachedSignature(artifactBytes, ascBytes, keyRing));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "Maven .asc signature verification threw unexpectedly ({ExceptionType}); " +
                "treating as unverifiable.",
                ex.GetType().Name);
            return Record(ProvenanceResult.Failed);
        }
    }

    // Decodes the detached ASCII-armored OpenPGP signature, finds the signing key in the
    // operator ring, initialises the verifier, feeds the artefact bytes, and returns the verdict.
    // Returns Failed (never throws) on any parse/crypto failure.
    internal static ProvenanceResult VerifyDetachedSignature(
        byte[] artifactBytes, byte[] ascBytes, PgpPublicKeyRingBundle keyRing)
    {
        try
        {
            using var sigStream = PgpUtilities.GetDecoderStream(new MemoryStream(ascBytes));
            var factory = new PgpObjectFactory(sigStream);
            var obj = factory.NextPgpObject();

            if (obj is PgpCompressedData compressed)
            {
                obj = new PgpObjectFactory(compressed.GetDataStream()).NextPgpObject();
            }

            if (obj is not PgpSignatureList { Count: > 0 } sigList)
            {
                return ProvenanceResult.Failed;
            }

            var sig = sigList[0];

            // Resolve the signing key from the operator-pinned ring — a key not in the ring
            // is untrusted, same as no key configured.
            var publicKey = keyRing.GetPublicKey(sig.KeyId);
            if (publicKey is null)
            {
                return ProvenanceResult.Failed;
            }

            sig.InitVerify(publicKey);
            sig.Update(artifactBytes);

            if (!sig.Verify())
            {
                return ProvenanceResult.Failed;
            }

            string fingerprint = ToHexFingerprint(publicKey.GetFingerprint());
            return ProvenanceResult.Verified(fingerprint);
        }
        catch
        {
            // Malformed ASC, unsupported algorithm, corrupt artefact, etc. — fail closed.
            return ProvenanceResult.Failed;
        }
    }

    // Returns the 40-char lowercase hex fingerprint of the signing key.
    private static string ToHexFingerprint(byte[] fingerprint)
        => Convert.ToHexString(fingerprint).ToLowerInvariant();

    // Emits the OTel result counter (ecosystem + result only — no per-package labels).
    private static ProvenanceResult Record(ProvenanceResult result)
    {
        DependablyMeter.ProvenanceVerified.Add(1,
            new KeyValuePair<string, object?>("ecosystem", "maven"),
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
