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
}

/// <summary>Serializes the log-capture edge tests — Serilog's static logger is process-global.</summary>
[CollectionDefinition("EdgeLogCapture", DisableParallelization = true)]
public sealed class EdgeLogCaptureCollection
{
}
