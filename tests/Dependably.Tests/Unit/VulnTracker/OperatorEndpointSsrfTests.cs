using System.Net;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;
using Dependably.Security;
using Xunit;

namespace Dependably.Tests.Unit.VulnTracker;

/// <summary>
/// The SSRF posture for an endpoint the <em>deployment operator</em> declares, as opposed to one
/// a tenant supplies or an artifact names.
///
/// <para>
/// The vulnerability-tracker connection shipped using the tenant-facing predicate, which blocks
/// loopback and RFC 1918. That made the feature unusable in the shape it is designed for — a
/// self-hosted sidecar — with <b>no</b> configuration that lifted it: <c>WEBHOOK_ALLOW_PRIVATE</c>
/// reached only the save-time check, and loopback is blocked even by the relaxed predicate, while
/// the connect-time guard had no escape hatch at all. Loopback, RFC 1918 and a compose service
/// name all failed.
/// </para>
///
/// <para>
/// These tests pin the narrower posture and, just as importantly, pin what it still refuses.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class OperatorEndpointSsrfTests
{
    // ── what an operator may now name ────────────────────────────────────────

    [Theory]
    [InlineData("127.0.0.1")]        // the reported case: a sidecar on the same host
    [InlineData("127.0.0.53")]
    [InlineData("::1")]
    [InlineData("10.1.2.3")]         // compose / private network
    [InlineData("172.16.4.5")]
    [InlineData("192.168.1.50")]
    [InlineData("203.0.113.10")]     // a public address is fine too
    public void OperatorEndpoint_PermitsSelfHostedAddresses(string ip)
    {
        Assert.False(SsrfGuard.IsBlockedIpForOperatorEndpoint(IPAddress.Parse(ip)));
    }

    [Fact]
    public void TheTenantFacingPredicates_StillRefuseLoopback()
    {
        // The twin that shows why a separate predicate was needed rather than reusing either
        // existing one: both of them refuse the address an operator legitimately configures.
        Assert.True(SsrfGuard.IsBlockedIp(IPAddress.Parse("127.0.0.1")));
        Assert.True(SsrfGuard.IsBlockedIpExcludingPrivate(IPAddress.Parse("127.0.0.1")));
    }

    // ── what it still refuses ────────────────────────────────────────────────

    [Theory]
    [InlineData("169.254.169.254")]  // cloud instance metadata — the escalation case
    [InlineData("169.254.0.1")]
    [InlineData("fe80::1")]          // IPv6 link-local
    public void OperatorEndpoint_StillRefusesInstanceMetadata(string ip)
    {
        Assert.True(SsrfGuard.IsBlockedIpForOperatorEndpoint(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("::ffff:169.254.169.254")]         // IPv4-mapped
    [InlineData("2002:a9fe:a9fe::")]               // 6to4-embedded 169.254.169.254
    [InlineData("64:ff9b::a9fe:a9fe")]             // NAT64 well-known prefix
    public void OperatorEndpoint_RefusesMetadataSmuggledThroughIPv6Encodings(string ip)
    {
        // The relaxation must not have dropped the transitional-encoding decoding: metadata
        // reached through a 6to4/NAT64 wrapper is the same target by a different spelling.
        Assert.True(SsrfGuard.IsBlockedIpForOperatorEndpoint(IPAddress.Parse(ip)));
    }

    // ── the connect-time layer, which had no escape hatch at all ─────────────

    [Fact]
    public async Task ConnectTime_DoesNotBlockLoopback_ForAnOperatorEndpoint()
    {
        // The layer that mattered most: even a successful save left every request refused,
        // because the tracker shared the app-wide guard and nothing lifted it. A connect to a
        // closed loopback port must now fail at the SOCKET, not at the SSRF gate.
        var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIpForOperatorEndpoint);

        var ex = await Record.ExceptionAsync(async () =>
            await cb.ConnectAsync("127.0.0.1", 65001,
                new CancellationTokenSource(TimeSpan.FromSeconds(2)).Token));

        Assert.NotNull(ex);
        Assert.IsNotType<SsrfBlockedException>(ex);
    }

    [Fact]
    public async Task ConnectTime_StillBlocksMetadata_ForAnOperatorEndpoint()
    {
        // The twin: the relaxation must not have opened the one range that matters.
        var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIpForOperatorEndpoint);

        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectAsync("169.254.169.254", 80, CancellationToken.None));

        Assert.Contains("169.254.169.254", ex.Message);
    }

    [Fact]
    public async Task ConnectTime_TheSharedGuard_StillBlocksLoopback()
    {
        // Proves the fix is scoped to the tracker's own client and did not weaken the guard the
        // osv/threatfeed/webhook paths use.
        var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIp);

        await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectAsync("127.0.0.1", 65001, CancellationToken.None));
    }

    // ── the save-time check that produced the reported error ─────────────────

    [Fact]
    public void SaveTime_AcceptsALoopbackTrackerUrl()
    {
        // Reproduces the reported configuration exactly.
        Assert.False(VulnTrackerConfigEditing.IsHostBlocked(
            "http://127.0.0.1:8090/", SsrfGuard.IsBlockedIpForOperatorEndpoint));
    }

    [Fact]
    public void SaveTime_StillRejectsAMetadataTrackerUrl()
    {
        Assert.True(VulnTrackerConfigEditing.IsHostBlocked(
            "http://169.254.169.254/latest/meta-data/", SsrfGuard.IsBlockedIpForOperatorEndpoint));
    }

    [Fact]
    public void SaveTime_LeavesAHostnameToTheConnectTimeGuard()
    {
        // Unchanged behaviour, restated because it is load-bearing for the fix: a hostname is
        // not resolved at save time, so a compose service name passes here and is judged when it
        // is actually dialled.
        Assert.False(VulnTrackerConfigEditing.IsHostBlocked(
            "http://tracker-api:8000/", SsrfGuard.IsBlockedIpForOperatorEndpoint));
    }
}
