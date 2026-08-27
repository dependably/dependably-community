namespace Dependably.Security;

/// <summary>
/// The connect-time SSRF gate for endpoints the <em>deployment operator</em> declares — today,
/// the instance-level vulnerability-tracker connection.
///
/// <para>
/// A distinct DI type rather than a second registration of <see cref="SsrfConnectCallback"/>,
/// for two reasons. The two postures are genuinely different — the app-wide gate refuses
/// loopback and RFC 1918 because it guards tenant-supplied and artifact-named URLs, while this
/// one permits them because a self-hosted sidecar is the normal shape for an operator-declared
/// endpoint — and a single registration would make "which posture did this client get?" depend
/// on registration order rather than on the type asked for.
/// </para>
///
/// <para>
/// It also keeps the seam testable: a test can substitute this type to assert that a client's
/// connect really is gated, without touching the gate every other client shares.
/// </para>
/// </summary>
public sealed class OperatorEndpointConnectGate
{
    public OperatorEndpointConnectGate(SsrfConnectCallback callback) => Callback = callback;

    /// <summary>Default production posture: only the instance-metadata range is refused.</summary>
    public OperatorEndpointConnectGate()
        : this(new SsrfConnectCallback(SsrfGuard.IsBlockedIpForOperatorEndpoint)) { }

    public SsrfConnectCallback Callback { get; }
}
