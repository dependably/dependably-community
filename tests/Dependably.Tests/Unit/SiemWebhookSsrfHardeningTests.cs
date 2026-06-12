using System.Net;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Siem;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Unit;

/// <summary>
/// Startup-validation and SSRF-predicate coverage for the SIEM webhook forwarder.
/// The <c>ValidateSiemWebhookUrl</c> helper gates <c>SIEM_WEBHOOK_URL</c> at startup,
/// and <c>SsrfGuard.IsBlockedIpExcludingPrivate</c> drives the connect-time callback
/// when <c>SIEM_WEBHOOK_ALLOW_PRIVATE=true</c>.
/// </summary>
[Trait("Category", "Security")]
public sealed class SiemWebhookSsrfHardeningTests
{
    private static IConfiguration BuildConfig(params (string Key, string? Value)[] pairs)
    {
        var dict = new Dictionary<string, string?>();
        foreach (var (k, v) in pairs)
        {
            dict[k] = v;
        }
        return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
    }

    // ── ValidateSiemWebhookUrl — disallowed schemes ──────────────────────────

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://collector.example.com/events")]
    [InlineData("javascript://evil")]
    [InlineData("data:text/html,<script>alert(1)</script>")]
    public void ValidateSiemWebhookUrl_DisallowedScheme_ReturnsError(string url)
    {
        string? error = ServiceCollectionExtensions.ValidateSiemWebhookUrl(url, allowPrivate: false);

        Assert.NotNull(error);
        Assert.Contains("scheme", error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://collector.example.com/events")]
    public void ValidateSiemWebhookUrl_DisallowedScheme_StillRejectedWhenAllowPrivate(string url)
    {
        // Scheme check must fire even when RFC 1918 addresses are allowed.
        string? error = ServiceCollectionExtensions.ValidateSiemWebhookUrl(url, allowPrivate: true);

        Assert.NotNull(error);
        Assert.Contains("scheme", error, StringComparison.OrdinalIgnoreCase);
    }

    // ── ValidateSiemWebhookUrl — loopback / link-local / metadata ───────────

    [Theory]
    [InlineData("http://127.0.0.1/collect")]
    [InlineData("https://169.254.169.254/latest/meta-data/")]  // cloud metadata endpoint
    [InlineData("http://169.254.1.1/collect")]
    public void ValidateSiemWebhookUrl_LoopbackOrMetadata_RejectedRegardlessOfAllowPrivate(string url)
    {
        // Loopback and link-local are always blocked — the ALLOW_PRIVATE flag must not
        // open them up.
        string? errorFull = ServiceCollectionExtensions.ValidateSiemWebhookUrl(url, allowPrivate: false);
        string? errorAllowPrivate = ServiceCollectionExtensions.ValidateSiemWebhookUrl(url, allowPrivate: true);

        Assert.NotNull(errorFull);
        Assert.NotNull(errorAllowPrivate);
    }

    // ── ValidateSiemWebhookUrl — RFC 1918 with ALLOW_PRIVATE=false ───────────

    [Theory]
    [InlineData("http://192.168.1.1/collect")]
    [InlineData("http://10.0.0.1/collect")]
    [InlineData("http://172.16.5.10/collect")]
    public void ValidateSiemWebhookUrl_PrivateIp_RejectedWhenAllowPrivateFalse(string url)
    {
        string? error = ServiceCollectionExtensions.ValidateSiemWebhookUrl(url, allowPrivate: false);

        Assert.NotNull(error);
    }

    // ── ValidateSiemWebhookUrl — RFC 1918 with ALLOW_PRIVATE=true ────────────

    [Theory]
    [InlineData("http://192.168.1.1/collect")]
    [InlineData("https://192.168.100.200/siem")]
    [InlineData("http://10.0.0.1/collect")]
    [InlineData("http://172.16.5.10/collect")]
    [InlineData("http://172.31.255.255/collect")]
    public void ValidateSiemWebhookUrl_PrivateIp_AllowedWhenAllowPrivateTrue(string url)
    {
        // Self-hosted SIEM on a private network is a legitimate deployment.
        string? error = ServiceCollectionExtensions.ValidateSiemWebhookUrl(url, allowPrivate: true);

        Assert.Null(error);
    }

    // ── ValidateSiemWebhookUrl — public and hostname URLs ────────────────────

    [Theory]
    [InlineData("https://siem.example.com/ingest")]
    [InlineData("http://collector.corp.internal/events")]   // hostname — not blocked at URL-check time
    [InlineData("https://8.8.8.8/collect")]
    public void ValidateSiemWebhookUrl_PublicOrHostname_ReturnsNull(string url)
    {
        string? error = ServiceCollectionExtensions.ValidateSiemWebhookUrl(url, allowPrivate: false);

        Assert.Null(error);
    }

    [Fact]
    public void ValidateSiemWebhookUrl_InvalidFormat_ReturnsError()
    {
        string? error = ServiceCollectionExtensions.ValidateSiemWebhookUrl("not-a-url", allowPrivate: false);

        Assert.NotNull(error);
    }

    // ── AddDependablySiemForwarding — startup throws on bad URL ─────────────

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://siem.example.com")]
    public void AddDependablySiemForwarding_InvalidScheme_ThrowsOnStartup(string badUrl)
    {
        var services = new ServiceCollection();
        var config = BuildConfig(("SIEM_WEBHOOK_URL", badUrl));

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddDependablySiemForwarding(config));

        Assert.Contains("SIEM_WEBHOOK_URL", ex.Message);
    }

    [Fact]
    public void AddDependablySiemForwarding_MetadataIp_ThrowsOnStartup()
    {
        var services = new ServiceCollection();
        var config = BuildConfig(("SIEM_WEBHOOK_URL", "http://169.254.169.254/collect"));

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddDependablySiemForwarding(config));

        Assert.Contains("SIEM_WEBHOOK_URL", ex.Message);
    }

    [Fact]
    public void AddDependablySiemForwarding_LoopbackIp_ThrowsOnStartup()
    {
        var services = new ServiceCollection();
        var config = BuildConfig(("SIEM_WEBHOOK_URL", "http://127.0.0.1/collect"));

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddDependablySiemForwarding(config));

        Assert.Contains("SIEM_WEBHOOK_URL", ex.Message);
    }

    [Fact]
    public void AddDependablySiemForwarding_PrivateIpWithAllowPrivateFalse_ThrowsOnStartup()
    {
        var services = new ServiceCollection();
        var config = BuildConfig(
            ("SIEM_WEBHOOK_URL", "http://192.168.1.1/collect"),
            ("SIEM_WEBHOOK_ALLOW_PRIVATE", "false"));

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddDependablySiemForwarding(config));

        Assert.Contains("SIEM_WEBHOOK_URL", ex.Message);
    }

    [Fact]
    public void AddDependablySiemForwarding_PrivateIpWithAllowPrivateTrue_RegistersSuccessfully()
    {
        // RFC 1918 address is permitted when SIEM_WEBHOOK_ALLOW_PRIVATE=true (the default).
        var services = new ServiceCollection();
        var config = BuildConfig(
            ("SIEM_WEBHOOK_URL", "http://192.168.1.1/collect"),
            ("SIEM_WEBHOOK_ALLOW_PRIVATE", "true"));

        // Must not throw.
        services.AddDependablySiemForwarding(config);

        Assert.Contains(services, d =>
            d.ServiceType == typeof(Dependably.Infrastructure.Siem.WebhookSiemForwarder));
    }

    [Fact]
    public void AddDependablySiemForwarding_PrivateIpWithDefaultAllowPrivate_RegistersSuccessfully()
    {
        // SIEM_WEBHOOK_ALLOW_PRIVATE defaults to true when not set.
        var services = new ServiceCollection();
        var config = BuildConfig(("SIEM_WEBHOOK_URL", "http://10.10.0.5/collect"));

        // Must not throw.
        services.AddDependablySiemForwarding(config);

        Assert.Contains(services, d =>
            d.ServiceType == typeof(Dependably.Infrastructure.Siem.WebhookSiemForwarder));
    }

    [Fact]
    public void AddDependablySiemForwarding_PublicUrl_RegistersSuccessfully()
    {
        var services = new ServiceCollection();
        var config = BuildConfig(("SIEM_WEBHOOK_URL", "https://siem.example.com/ingest"));

        services.AddDependablySiemForwarding(config);

        Assert.Contains(services, d =>
            d.ServiceType == typeof(Dependably.Infrastructure.Siem.WebhookSiemForwarder));
    }

    // ── SsrfGuard.IsBlockedIpExcludingPrivate ────────────────────────────────

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.100")]
    [InlineData("169.254.169.254")]  // cloud metadata endpoint
    [InlineData("169.254.1.1")]
    [InlineData("100.64.0.1")]      // CGNAT
    [InlineData("::1")]             // IPv6 loopback
    [InlineData("fc00::1")]         // IPv6 unique-local
    [InlineData("fe80::1")]         // IPv6 link-local
    public void IsBlockedIpExcludingPrivate_AlwaysBlocked_ReturnsTrue(string ip)
    {
        // Loopback, link-local, cloud-metadata, and IPv6 special ranges are blocked
        // regardless of private-IP opt-in.
        Assert.True(SsrfGuard.IsBlockedIpExcludingPrivate(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.255")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.0.1")]
    [InlineData("192.168.255.255")]
    public void IsBlockedIpExcludingPrivate_Rfc1918_ReturnsFalse(string ip)
    {
        // RFC 1918 addresses must pass through when private is permitted.
        Assert.False(SsrfGuard.IsBlockedIpExcludingPrivate(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("140.82.121.4")]
    public void IsBlockedIpExcludingPrivate_PublicIp_ReturnsFalse(string ip)
    {
        Assert.False(SsrfGuard.IsBlockedIpExcludingPrivate(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("::ffff:127.0.0.1")]       // IPv4-mapped loopback
    [InlineData("::ffff:169.254.169.254")] // IPv4-mapped metadata endpoint
    public void IsBlockedIpExcludingPrivate_Ipv4MappedAlwaysBlocked_ReturnsTrue(string ip)
    {
        // IPv4-mapped loopback and metadata addresses must still be blocked.
        Assert.True(SsrfGuard.IsBlockedIpExcludingPrivate(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("::ffff:10.0.0.1")]       // IPv4-mapped RFC1918
    [InlineData("::ffff:192.168.1.1")]    // IPv4-mapped RFC1918
    public void IsBlockedIpExcludingPrivate_Ipv4MappedPrivate_ReturnsFalse(string ip)
    {
        // IPv4-mapped RFC 1918 addresses must be allowed when private-IP is permitted.
        Assert.False(SsrfGuard.IsBlockedIpExcludingPrivate(IPAddress.Parse(ip)));
    }

    // ── Handler-chain wiring — predicate is captured per-client, not resolved from DI ─

    /// <summary>
    /// Verifies that the SIEM webhook handler uses the permissive predicate when
    /// <c>SIEM_WEBHOOK_ALLOW_PRIVATE=true</c>, even when a competing full-block
    /// <c>SsrfConnectCallback</c> singleton is present in the container. This is the
    /// regression guard for the bug where <c>GetRequiredService&lt;SsrfConnectCallback&gt;</c>
    /// resolved the last-registered descriptor (the full-block one) rather than the
    /// predicate captured at registration time.
    /// </summary>
    [Fact]
    public async Task WebhookHandler_AllowPrivateTrue_PrivateIpPassesSsrfGuard()
    {
        // Arrange: register SIEM forwarding with ALLOW_PRIVATE=true, then add a competing
        // full-block SsrfConnectCallback as AddSingleton (the Program.cs pattern).
        var services = new ServiceCollection();
        services.AddLogging();
        var config = BuildConfig(
            ("SIEM_WEBHOOK_URL", "http://192.168.1.1/collect"),
            ("SIEM_WEBHOOK_ALLOW_PRIVATE", "true"));

        services.AddDependablySiemForwarding(config);

        // Competing full-block registration — simulates the app-level AddSingleton in
        // Program.cs. With the old code (TryAdd + GetRequiredService), this was the
        // registration that AddSingleton appended last and GetRequiredService resolved.
        services.AddSingleton(new SsrfConnectCallback(SsrfGuard.IsBlockedIp));

        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var httpClient = factory.CreateClient(nameof(WebhookSiemForwarder));

        // Act: drive a request to a private IP literal. With the permissive predicate wired,
        // the SSRF callback passes the IP and the connection attempt fails at the TCP layer
        // (SocketException or OperationCanceledException), never at the SSRF guard. With the
        // full-block predicate, the callback throws SsrfBlockedException immediately.
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        Exception? caughtEx = null;
        try
        {
            await httpClient.GetAsync("http://192.168.1.1/collect", cts.Token);
        }
        catch (Exception ex)
        {
            caughtEx = ex;
        }

        // Assert: the exception must NOT be (or wrap) SsrfBlockedException — the SSRF gate
        // passed and the failure is a TCP-layer or cancellation error.
        Assert.NotNull(caughtEx);
        var inner = caughtEx is HttpRequestException hre ? hre.InnerException : caughtEx;
        Assert.IsNotType<SsrfBlockedException>(inner);
    }

    /// <summary>
    /// Verifies that the SIEM webhook handler uses the full-block predicate when
    /// <c>SIEM_WEBHOOK_ALLOW_PRIVATE=false</c>, blocking even RFC 1918 addresses at
    /// connect time.
    /// </summary>
    [Fact]
    public async Task WebhookHandler_AllowPrivateFalse_PrivateIpBlockedBySsrfGuard()
    {
        // Arrange: register with ALLOW_PRIVATE=false and a public URL that passes startup
        // validation, then add the same competing AddSingleton (permissive predicate this
        // time, to confirm the SIEM handler does NOT inherit it).
        var services = new ServiceCollection();
        services.AddLogging();
        var config = BuildConfig(
            ("SIEM_WEBHOOK_URL", "https://siem.example.com/ingest"),
            ("SIEM_WEBHOOK_ALLOW_PRIVATE", "false"));

        services.AddDependablySiemForwarding(config);

        // Competing permissive registration — if the handler resolved this from DI instead
        // of using its captured predicate, a private-IP request would NOT throw SsrfBlockedException.
        services.AddSingleton(new SsrfConnectCallback(_ => false));

        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var httpClient = factory.CreateClient(nameof(WebhookSiemForwarder));

        // Act: request to a private IP literal — must be blocked by the full-block predicate
        // captured at registration time, regardless of the permissive competing singleton.
        Exception? caughtEx = null;
        try
        {
            await httpClient.GetAsync("http://192.168.1.1/collect");
        }
        catch (Exception ex)
        {
            caughtEx = ex;
        }

        // Assert: the exception must be (or wrap) SsrfBlockedException — the SSRF gate
        // fired at connect time before any TCP dial.
        Assert.NotNull(caughtEx);
        var inner = caughtEx is HttpRequestException hre ? hre.InnerException : caughtEx;
        Assert.IsType<SsrfBlockedException>(inner);
    }
}
