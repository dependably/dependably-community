namespace Dependably.Security;

/// <summary>
/// Result of an upstream URL validation check. Distinguishes the blocked reason so
/// callers can emit the correct <c>reason</c> attribute on the
/// <c>dependably.security.upstream_url_blocks</c> counter.
/// </summary>
public enum UpstreamUrlBlock
{
    /// <summary>URL is allowed — no block.</summary>
    None,

    /// <summary>
    /// Resolved IP address falls inside a blocked range (loopback, RFC1918, link-local,
    /// or cloud-metadata prefix). The audit event has already been written by
    /// <see cref="UpstreamUrlValidator.CheckAsync"/>.
    /// </summary>
    BlockedRange,

    /// <summary>
    /// DNS resolution failed — treated as fail-closed (the URL is not allowed).
    /// </summary>
    DnsFailure,
}

public interface IUpstreamUrlValidator
{
    /// <summary>
    /// Resolves <paramref name="url"/> via DNS and checks the resulting addresses against
    /// the SSRF block list. Returns the block reason so the caller can emit the correct
    /// metric attribute; returns <see cref="UpstreamUrlBlock.None"/> when the URL is
    /// allowed.
    /// </summary>
    Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default);
}
