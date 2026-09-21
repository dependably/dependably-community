using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Dependably.Infrastructure.Canonicalization;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// Signs an exported CycloneDX document with the org's SBOM signing key
/// (ADR-sbom-author-signature). Two-step by design: <see cref="ResolveAsync"/> answers whether
/// signing is possible and what <c>dependably:signature-state</c> the document must therefore
/// declare — needed BEFORE the document's <c>metadata.properties</c> are finalized — and
/// <see cref="Attach"/> signs the fully-built document — which must run LAST, after every other
/// field (including that property) is in place, since anything added afterward would not be
/// covered by the signature.
/// </summary>
public sealed class SbomAuthorSigner
{
    /// <summary>The document was signed with the org's active key.</summary>
    public const string SignedState = "signed";

    /// <summary>
    /// No key exists for this org anywhere in the fleet — <c>DEPENDABLY_MASTER_KEY</c> has never
    /// been configured for this install. The export still succeeds; this is what makes the gap
    /// visible to a consumer rather than silent (ADR-sbom-author-signature, "An export without a
    /// key is unsigned, not refused").
    /// </summary>
    public const string UnsignedNoMasterKeyState = "unsigned-no-master-key";

    /// <summary>
    /// The org DOES have an active signing key, but this replica cannot read it right now (its
    /// own <c>DEPENDABLY_MASTER_KEY</c> is unset, or this node is edge) — the mixed-fleet/rolling-
    /// rollout case <see cref="UnsignedNoMasterKeyState"/> must never claim, because "no key
    /// exists for this org" is false here. This is a DEGRADED-RENDER marker: it never enters the
    /// content fingerprint (<see cref="ResolveAsync"/>'s own doc comment), because which replica
    /// answers a request is not a fact about the org. See <c>SbomExportService.Revision.cs</c>'s
    /// class doc comment, "the fingerprint covers the org's signing POSTURE".
    /// </summary>
    public const string UnsignedKeyUnavailableState = "unsigned-key-unavailable";

    private readonly SbomSigningKeyRepository _keys;

    public SbomAuthorSigner(SbomSigningKeyRepository keys) => _keys = keys;

    /// <summary>
    /// Resolves the org's active signing key, minting one on first use. Returns the key (null
    /// when THIS replica cannot sign), the signature-state string the caller must place in
    /// <c>metadata.properties</c> before building the rest of the document, and
    /// <c>OrgHasActiveKey</c> — the org-scoped signing posture a caller folds into a content
    /// fingerprint (see <c>SbomExportService.Revision.cs</c>'s class doc comment). The RENDERED
    /// state can differ by which replica answered (<see cref="SignedState"/> vs
    /// <see cref="UnsignedKeyUnavailableState"/> for the SAME org, on the SAME data, depending on
    /// which node has <c>DEPENDABLY_MASTER_KEY</c>); <c>OrgHasActiveKey</c> does not — it is true
    /// whenever the org has an active key ANYWHERE in the fleet, false only when it has none at
    /// all, so it is safe to fingerprint where the rendered string is not. The caller owns the
    /// returned key and must dispose it.
    /// </summary>
    public async Task<(SbomSigningKey? Key, string State, bool OrgHasActiveKey)> ResolveAsync(string orgId, CancellationToken ct)
    {
        var key = await _keys.GetOrCreateAsync(orgId, ct);
        if (key is not null)
        {
            return (key, SignedState, true);
        }

        bool orgHasActiveKey = await _keys.HasActiveKeyAsync(orgId, ct);
        return (null, orgHasActiveKey ? UnsignedKeyUnavailableState : UnsignedNoMasterKeyState, orgHasActiveKey);
    }

    /// <summary>
    /// Attaches the enveloped JSF <c>signature</c> member to <paramref name="document"/>, signed
    /// with <paramref name="key"/>. Call this LAST: the canonicalization it signs over is a
    /// snapshot of <paramref name="document"/> at the moment of the call (minus the signature's
    /// own <c>value</c>), so a field added afterward is not covered and a field the caller
    /// intends to sign must already be present.
    /// </summary>
    public static void Attach(JsonObject document, SbomSigningKey key)
    {
        var envelope = JsfEnvelope.AttachUnsignedEnvelope(document, key.Id);
        byte[] canonical = JsfEnvelope.CanonicalBytesWithoutValue(document);
        byte[] raw = key.PrivateKey.SignData(
            canonical, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        JsfEnvelope.SetValue(envelope, raw);
    }
}
