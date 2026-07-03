using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Isolated (non-parallel) coverage for the D278-1 anonymous-mode startup warning. The assertion
/// reads a Serilog capture sink wired through the host's <c>ReadFrom.Services</c>; Serilog's
/// static <c>Log.Logger</c> is process-global, so this class runs in a serialized collection to
/// avoid a parallel host overwriting the logger between emit and assert.
/// </summary>
[Trait("Category", "Integration")]
[Collection("EdgeLogCapture")]
public sealed class EdgeAnonymousWarningTests
{
    [Fact]
    public async Task Edge_NoAccessToken_LogsAnonymousClientsWarning()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            DeploymentMode = "edge",
            EdgeAccessToken = null,
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        // anonymous_pull enabled and the D278-1 warning fired verbatim at Warning level.
        var db = f.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
                "SELECT anonymous_pull FROM org_settings LIMIT 1"));
        }

        Assert.True(
            sink.Contains("edge node accepting anonymous clients — intended for trusted networks only",
                Serilog.Events.LogEventLevel.Warning),
            "expected the anonymous-mode startup warning to be logged at Warning level");
    }

    [Fact]
    public async Task Edge_WithAccessToken_DoesNotLogAnonymousWarning()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            DeploymentMode = "edge",
            EdgeAccessToken = "inbound-secret",
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        Assert.False(
            sink.Contains("edge node accepting anonymous clients",
                Serilog.Events.LogEventLevel.Warning),
            "tokened edge must NOT log the anonymous-clients warning");
    }

    // With no master key, the edge host warns that the master enrollment token is stored
    // unencrypted — the edge-accurate wording, which must NOT enumerate jwt_secret/mfa_encryption_key
    // (the edge has no login or MFA layer).
    [Fact]
    public async Task Edge_NoMasterKey_LogsEdgeMasterTokenAtRestWarning()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            DeploymentMode = "edge",
            MasterKey = null,
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        Assert.True(
            sink.Contains("The edge master enrollment token (EDGE_MASTER_TOKEN)",
                Serilog.Events.LogEventLevel.Warning),
            "expected the edge-accurate master-key-at-rest warning naming EDGE_MASTER_TOKEN");
        Assert.False(
            sink.Contains("jwt_secret, mfa_encryption_key", Serilog.Events.LogEventLevel.Warning),
            "edge must NOT enumerate the full host's jwt_secret/mfa_encryption_key");
    }

    // The edge host issues no session cookies, so the BASE_URL session-cookie warning must not
    // fire there — its advice ("cookies will not be marked Secure") is impossible on edge.
    [Fact]
    public async Task Edge_NoBaseUrl_DoesNotLogSessionCookieWarning()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            DeploymentMode = "edge",
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        Assert.False(
            sink.Contains("Session cookies will not be marked Secure",
                Serilog.Events.LogEventLevel.Warning),
            "edge issues no session cookies, so the BASE_URL cookie warning must not fire");
    }
}

/// <summary>
/// Isolated (non-parallel) coverage that the FULL host keeps the original warning wording — the
/// edge-accuracy change must not regress the full-host messages. Shares the serialized log-capture
/// collection because Serilog's static <c>Log.Logger</c> is process-global.
/// </summary>
[Trait("Category", "Integration")]
[Collection("EdgeLogCapture")]
public sealed class FullHostStartupWarningTests
{
    // The full host stores a JWT signing secret and an MFA encryption key; its master-key-at-rest
    // warning enumerates them verbatim and must not adopt the edge wording.
    [Fact]
    public async Task FullHost_NoMasterKey_LogsInstanceSecretsAtRestWarning()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            MasterKey = null,
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        Assert.True(
            sink.Contains("Instance secrets (jwt_secret, mfa_encryption_key)",
                Serilog.Events.LogEventLevel.Warning),
            "expected the full-host master-key-at-rest warning enumerating jwt_secret/mfa_encryption_key");
        Assert.False(
            sink.Contains("The edge master enrollment token", Serilog.Events.LogEventLevel.Warning),
            "full host must NOT adopt the edge master-enrollment-token wording");
    }

    // The full host does issue session cookies, so with no BASE_URL its session-cookie warning
    // fires verbatim.
    [Fact]
    public async Task FullHost_NoBaseUrl_LogsSessionCookieWarning()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        Assert.True(
            sink.Contains("Session cookies will not be marked Secure",
                Serilog.Events.LogEventLevel.Warning),
            "full host issues session cookies, so the BASE_URL cookie warning must fire");
    }
}

/// <summary>Serializes the log-capture edge tests — Serilog's static logger is process-global.</summary>
[CollectionDefinition("EdgeLogCapture", DisableParallelization = true)]
public sealed class EdgeLogCaptureCollection
{
}
