using Dependably.Security;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test-only validator that allows every upstream URL. Wired up in <see cref="DependablyFactory"/>
/// so tests can point <c>NuGet:Upstream</c>/<c>Npm:Upstream</c>/<c>PyPI:Upstream</c> at the
/// WireMock server on localhost without being blocked by the production SSRF guard
/// (<c>UpstreamUrlValidator</c>, which blocks 127.0.0.0/8 and other private ranges).
/// </summary>
public sealed class PermissiveUpstreamUrlValidator : IUpstreamUrlValidator
{
    public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
        => Task.FromResult(true);
}
