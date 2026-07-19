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

/// <summary>
/// Isolated (non-parallel) coverage for the legacy <c>SMTP_*</c> present-but-ignored startup
/// warning. Email configuration is DB-backed with no environment-to-database seed, so a
/// deployment carrying the old variables loses invite email silently — this warning is the only
/// signal the operator gets. Shares the serialized log-capture collection because Serilog's
/// static <c>Log.Logger</c> is process-global.
/// </summary>
[Trait("Category", "Integration")]
[Collection("EdgeLogCapture")]
public sealed class LegacySmtpEnvWarningTests
{
    private const string WarningPrefix = "Legacy SMTP environment variables are set but ignored";

    [Fact]
    public async Task FullHost_LegacySmtpHostPresent_LogsIgnoredWarningNamingTheVariable()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            LegacySmtpVars = new Dictionary<string, string?>
            {
                ["SMTP_HOST"] = "smtp.example.com",
            },
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        Assert.True(
            sink.Contains(WarningPrefix, Serilog.Events.LogEventLevel.Warning),
            "a present-but-ignored SMTP_* variable must warn at Warning level");
        Assert.True(
            sink.Contains("SMTP_HOST", Serilog.Events.LogEventLevel.Warning),
            "the warning must name the variable that is being ignored");
        Assert.True(
            sink.Contains("Settings -> Instance settings -> Instance email (SMTP)",
                Serilog.Events.LogEventLevel.Warning),
            "the warning must point at where invite SMTP is now configured");
    }

    // Mixed state: some legacy variables set, others absent. The warning must enumerate exactly
    // the ones present — naming an unset variable would send the operator hunting for config
    // they never had.
    [Fact]
    public async Task FullHost_SubsetOfLegacySmtpVarsPresent_NamesOnlyThePresentOnes()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            LegacySmtpVars = new Dictionary<string, string?>
            {
                ["SMTP_HOST"] = "smtp.example.com",
                ["SMTP_FROM"] = "invites@example.com",
                // SMTP_PORT / SMTP_USERNAME / SMTP_STARTTLS deliberately absent.
                ["SMTP_PASSWORD"] = "  ",
            },
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        Assert.True(
            sink.Contains("SMTP_HOST, SMTP_FROM", Serilog.Events.LogEventLevel.Warning),
            "the warning must enumerate the present variables in declaration order");
        Assert.False(
            sink.Contains("SMTP_PORT", Serilog.Events.LogEventLevel.Warning),
            "an absent variable must not be named");
        // A whitespace-only value is not a configured relay; treating it as present would warn
        // an operator who has nothing to migrate.
        Assert.False(
            sink.Contains("SMTP_PASSWORD", Serilog.Events.LogEventLevel.Warning),
            "a whitespace-only value must count as absent");
    }

    [Fact]
    public async Task FullHost_NoLegacySmtpVars_StaysSilent()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        Assert.False(
            sink.Contains(WarningPrefix, Serilog.Events.LogEventLevel.Warning),
            "a host with no legacy SMTP_* variables must not warn");
    }

    // The edge host has no management plane, so it has no invite mailer and no Settings UI to
    // point at — the warning's advice would be impossible there.
    [Fact]
    public async Task Edge_LegacySmtpHostPresent_DoesNotWarn()
    {
        var sink = new CapturingLogSink();
        await using var f = new DependablyFactory
        {
            DeploymentMode = "edge",
            LegacySmtpVars = new Dictionary<string, string?>
            {
                ["SMTP_HOST"] = "smtp.example.com",
            },
            LogSink = sink,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        Assert.False(
            sink.Contains(WarningPrefix, Serilog.Events.LogEventLevel.Warning),
            "edge carries no invite mailer, so the legacy SMTP warning must not fire");
    }
}

/// <summary>Serializes the log-capture edge tests — Serilog's static logger is process-global.</summary>
[CollectionDefinition("EdgeLogCapture", DisableParallelization = true)]
public sealed class EdgeLogCaptureCollection
{
}
