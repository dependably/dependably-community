namespace Dependably.Infrastructure.Siem;

/// <summary>
/// Outbound SIEM forwarder. Implementations are responsible for one transport (webhook,
/// syslog/TCP, syslog/UDP, syslog/TLS). The hosted <see cref="SiemForwarderQueue"/> drives
/// delivery from a bounded channel; forwarders are stateless w.r.t. the queue and may be
/// retried by the queue on failure.
/// </summary>
public interface ISiemForwarder
{
    Task SendAsync(SiemEvent ev, CancellationToken ct = default);

    /// <summary>Diagnostic name for logs / metrics.</summary>
    string Name { get; }
}
