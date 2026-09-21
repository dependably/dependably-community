namespace Dependably.Protocol;

/// <summary>
/// Raised when the blob proxy declines to serve a blob that upstream <b>does</b> have.
///
/// <para>
/// The distinction this type exists to preserve is refusal versus absence. Both used to leave the
/// fetch path as a null result, and a null became <c>404 BLOB_UNKNOWN</c> — "this content does not
/// exist" — which is a false statement about content the upstream was in the middle of handing
/// over. A client believes it and stops; an operator reads it and goes looking for a corrupt
/// cache. Modelling the refusals as exceptions rather than as another null is what lets the
/// controller answer 5xx for them while a genuine miss keeps its 404.
/// </para>
///
/// <para>
/// <see cref="Fault"/> and <see cref="OperatorMessage"/> are the disclosure-gated half:
/// <c>/v2/</c> blob reads are anonymously reachable under <c>anonymous_pull</c>, so a subclass
/// puts the upstream host and the specific fault here, for the controller to add only for a
/// caller holding a token for the org.
/// </para>
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization (SerializationInfo/StreamingContext) is obsolete in .NET 8+ and disabled by default; this exception is never serialized across processes.")]
public abstract class OciBlobRefusedException : Exception
{
    protected OciBlobRefusedException(string digest, string upstreamHost, string message)
        : base(message)
    {
        Digest = digest;
        UpstreamHost = upstreamHost;
    }

    /// <summary>The blob digest that was refused.</summary>
    public string Digest { get; }

    /// <summary>The upstream the blob was being fetched from. Topology — authenticated callers only.</summary>
    public string UpstreamHost { get; }

    /// <summary>
    /// Stable machine-readable discriminator for the <c>detail.fault</c> field, matching the
    /// vocabulary the manifest plane uses. Authenticated callers only: the shape of the response
    /// would otherwise separate faults that the prose deliberately does not.
    /// </summary>
    public abstract string Fault { get; }

    /// <summary>
    /// The sentence added for a caller holding a token for this org — what actually happened and
    /// what the operator can do about it. Never sent to an anonymous caller.
    /// </summary>
    public abstract string OperatorMessage { get; }
}

/// <summary>
/// The blob is larger than <c>Oci:MaxBlobProxyBytes</c> allows this registry to proxy.
///
/// <para>
/// A configuration decision, not an integrity event and not an absence: the bytes exist and
/// verify, this instance has simply been told not to carry that many of them. The remedy is an
/// operator's, which is why <see cref="OperatorMessage"/> names the setting rather than just the
/// number.
/// </para>
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization (SerializationInfo/StreamingContext) is obsolete in .NET 8+ and disabled by default; this exception is never serialized across processes.")]
public sealed class OciBlobTooLargeException : OciBlobRefusedException
{
    public OciBlobTooLargeException(string digest, string upstreamHost, long capBytes, long? declaredBytes)
        : base(digest, upstreamHost,
            $"OCI blob {digest} from {upstreamHost} exceeds the {capBytes}-byte proxy cap "
            + $"(declared: {declaredBytes?.ToString() ?? "unknown"}).")
    {
        CapBytes = capBytes;
        DeclaredBytes = declaredBytes;
    }

    /// <summary>The configured ceiling that was exceeded.</summary>
    public long CapBytes { get; }

    /// <summary>Upstream's declared Content-Length, or null when the transfer was chunked.</summary>
    public long? DeclaredBytes { get; }

    public override string Fault => "blob_too_large";

    public override string OperatorMessage =>
        $"Upstream '{UpstreamHost}' has this blob, but it exceeds this registry's "
        + $"{CapBytes}-byte per-blob proxy limit"
        + (DeclaredBytes is { } declared ? $" (upstream declared {declared} bytes)" : " (chunked transfer)")
        + ". Raise Oci__MaxBlobProxyBytes to proxy it, and confirm the cache tier has room for it.";
}

/// <summary>
/// The bytes upstream delivered do not hash to the digest they were requested under.
///
/// <para>
/// Kept separate from <see cref="OciBlobTooLargeException"/> because the two have opposite
/// owners and opposite urgency. An over-cap refusal is a number an operator chose; a digest
/// mismatch means something between this registry and the upstream served wrong bytes for a
/// content address — a truncated transfer at best, tampering at worst — and it is worth alerting
/// on. Folding both into one status and one message, as the old shared null did, is what made
/// that indistinguishable.
/// </para>
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization (SerializationInfo/StreamingContext) is obsolete in .NET 8+ and disabled by default; this exception is never serialized across processes.")]
public sealed class OciBlobDigestMismatchException : OciBlobRefusedException
{
    public OciBlobDigestMismatchException(string digest, string upstreamHost, string computedDigest)
        : base(digest, upstreamHost,
            $"OCI blob digest mismatch from {upstreamHost}: requested {digest}, computed {computedDigest}.")
        => ComputedDigest = computedDigest;

    /// <summary>What the delivered bytes actually hashed to.</summary>
    public string ComputedDigest { get; }

    public override string Fault => "blob_digest_mismatch";

    public override string OperatorMessage =>
        $"Upstream '{UpstreamHost}' returned content that does not match the requested digest, "
        + "so it was discarded rather than cached. The bytes were truncated or altered in transit; "
        + "nothing was written to the cache.";
}
