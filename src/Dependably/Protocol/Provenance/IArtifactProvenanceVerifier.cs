namespace Dependably.Protocol.Provenance;

/// <summary>
/// Outcome of an artefact-provenance check. Ordered so the persisted string and the block-gate
/// arm read consistently across ecosystems:
/// <list type="bullet">
///   <item><see cref="Verified"/> — a pinned trust anchor produced a valid signature over the
///         artefact's canonical signing payload.</item>
///   <item><see cref="Failed"/> — a signature was present but did not verify (tampered bytes,
///         wrong key, malformed signature, or unknown keyid). Always fail-closed under a
///         require policy.</item>
///   <item><see cref="Unsigned"/> — the upstream metadata carried no signature for this version
///         (older packages predate registry signing). Behaviour governed by the org mode.</item>
///   <item><see cref="NotApplicable"/> — verification was not attempted (policy off, ecosystem
///         without a verifier, or a non-proxy origin). Never blocks.</item>
/// </list>
/// </summary>
public enum ProvenanceStatus
{
    NotApplicable,
    Unsigned,
    Verified,
    Failed,
}

/// <summary>
/// Per-ecosystem inputs to a provenance check. Generic over ecosystems so Phases 2/3 (NuGet
/// author/repo signatures, PyPI attestations) reuse the same shape: the canonical identity, the
/// integrity string the registry signs over, and the registry-supplied signature list.
/// </summary>
/// <param name="Ecosystem">Ecosystem tag (<c>npm</c>, …) — used for the OTel result counter.</param>
/// <param name="PackageName">Canonical package name (npm: full name incl. scope).</param>
/// <param name="Version">Exact version string.</param>
/// <param name="Integrity">
/// Integrity reference the registry signs over. For npm this is the <c>dist.integrity</c> SRI
/// (e.g. <c>sha512-…</c>); the signed payload is <c>"{name}@{version}:{integrity}"</c>.
/// </param>
/// <param name="Signatures">
/// Registry-supplied signatures (keyid + base64 signature). Empty when upstream published none.
/// </param>
public sealed record ProvenanceInput(
    string Ecosystem,
    string PackageName,
    string Version,
    string? Integrity,
    IReadOnlyList<ProvenanceSignature> Signatures);

/// <summary>A single registry signature entry: the trust-anchor key id and the base64 signature.</summary>
public sealed record ProvenanceSignature(string KeyId, string Signature);

/// <summary>
/// Result of a provenance check: the status plus the identity of the signer (the trust-anchor
/// keyid) when a signature verified. <see cref="Signer"/> is null for every non-<see cref="ProvenanceStatus.Verified"/>
/// status.
/// </summary>
public sealed record ProvenanceResult(ProvenanceStatus Status, string? Signer)
{
    public static readonly ProvenanceResult NotApplicable = new(ProvenanceStatus.NotApplicable, null);
    public static readonly ProvenanceResult Unsigned = new(ProvenanceStatus.Unsigned, null);
    public static readonly ProvenanceResult Failed = new(ProvenanceStatus.Failed, null);

    public static ProvenanceResult Verified(string signer) => new(ProvenanceStatus.Verified, signer);
}

/// <summary>
/// Verifies that a proxied artefact's upstream-published signature chains to an operator-pinned
/// trust anchor. Resolved per-ecosystem; the trust root is always operator-configured (never the
/// upstream-fetched key), mirroring the RPM GPG-key posture. A verifier whose ecosystem has no
/// pinned keys reports <see cref="ProvenanceStatus.NotApplicable"/> — enabling enforcement without
/// pinned keys is a startup/validation error, not a silent allow.
/// </summary>
public interface IArtifactProvenanceVerifier
{
    /// <summary>Ecosystem this verifier handles (<c>npm</c>, …).</summary>
    string Ecosystem { get; }

    /// <summary>
    /// True when this verifier has the pinned material it needs to produce a
    /// <see cref="ProvenanceStatus.Verified"/> verdict (i.e. at least one trust anchor is
    /// configured). When false, enabling the per-org verify policy must fail closed.
    /// </summary>
    bool IsConfigured { get; }

    /// <summary>
    /// Verifies the signatures in <paramref name="input"/>. Never throws on malformed input —
    /// a parse/crypto failure maps to <see cref="ProvenanceStatus.Failed"/> so the caller can
    /// fail closed. No signatures present maps to <see cref="ProvenanceStatus.Unsigned"/>.
    /// </summary>
    Task<ProvenanceResult> VerifyAsync(ProvenanceInput input, CancellationToken ct = default);
}

/// <summary>
/// Stable string forms of <see cref="ProvenanceStatus"/> persisted in
/// <c>package_versions.provenance_status</c> and read by the block gate. Lowercase to match the
/// other status columns and the external wire conventions.
/// </summary>
public static class ProvenanceStatuses
{
    public const string Verified = "verified";
    public const string Failed = "failed";
    public const string Unsigned = "unsigned";

    public static string? ToColumn(ProvenanceStatus status) => status switch
    {
        ProvenanceStatus.Verified => Verified,
        ProvenanceStatus.Failed => Failed,
        ProvenanceStatus.Unsigned => Unsigned,
        // NotApplicable is not persisted — the column stays NULL.
        _ => null,
    };
}
