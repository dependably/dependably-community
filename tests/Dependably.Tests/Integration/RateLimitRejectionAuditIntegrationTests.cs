using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Drives a real 429 through the full pipeline (real routing, the real <c>metadata</c>
/// <c>[EnableRateLimiting]</c> policy, the real global <c>OnRejected</c> callback) rather than a
/// hand-built <see cref="Microsoft.AspNetCore.Http.DefaultHttpContext"/>, so it pins the actual
/// wiring line in <c>AuthStartupExtensions.AddDependablyRateLimiter</c> — deleting the
/// <c>RateLimitDenialAuditRecorder.Record(...)</c> call turns this test red, which no
/// hand-built-context unit test can do, because such a test only ever calls the recorder
/// directly and so cannot observe whether production code still calls it at all.
/// </summary>
[Trait("Category", "Integration")]
public sealed class RateLimitRejectionAuditIntegrationTests
{
    [Fact]
    public async Task MetadataLimiterRejection_IsAuditedWithCountRouteOrgAndRealPartition()
    {
        await using var factory = new DependablyFactory
        {
            ExtraSettings = new Dictionary<string, string?>
            {
                ["METADATA_RATE_LIMIT_PERMITS"] = "2",
                ["METADATA_RATE_LIMIT_QUEUE"] = "0",
            },
        };
        await factory.InitializeAsync();
        await factory.PushNpmPackage("ratelimit-audit-npm", "1.0.0");

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);

        // DependablyFactory pins Connection.RemoteIpAddress to loopback for every request, so all
        // five share one partition and the metadata limiter's tight budget (2/s, no queue) rejects
        // everything past the first two.
        int rejected = 0;
        for (int i = 0; i < 5; i++)
        {
            var resp = await client.GetAsync("/npm/ratelimit-audit-npm");
            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
            {
                rejected++;
            }
        }

        Assert.True(rejected > 0, "expected at least one 429 from the tightened metadata limiter");

        // Close the accumulator's window directly rather than waiting on the real one-minute
        // PeriodicTimer — the same seam AuthDenialAuditFlushServiceTests uses.
        var flusher = factory.Services.GetRequiredService<AuthDenialAuditFlushService>();
        await flusher.FlushWindowAsync(CancellationToken.None);

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var rows = (await conn.QueryAsync<AuditRow>(
            """
            SELECT scope AS Scope, org_id AS OrgId, action AS Action, ecosystem AS Ecosystem,
                   detail AS Detail, source_ip AS SourceIp
            FROM audit_log WHERE action = 'ratelimit.rejected'
            """)).ToList();

        var row = Assert.Single(rows);
        Assert.Equal("tenant", row.Scope);
        Assert.NotNull(row.OrgId);
        Assert.Equal("npm", row.Ecosystem);
        Assert.Equal("127.0.0.1", row.SourceIp);

        var detail = JsonDocument.Parse(row.Detail ?? "{}").RootElement;
        Assert.Equal(rejected, detail.GetProperty("count").GetInt64());
        Assert.Equal("metadata", detail.GetProperty("policy").GetString());
        Assert.Equal("rate_limited", detail.GetProperty("reason").GetString());
        // Slash-normalised. The npm metadata action declares its route without a leading slash,
        // so the raw RoutePattern.RawText is "npm/{package}" — and the credential/capability
        // denial seams, which write the same column, normalise. Two spellings of one route are two
        // accumulator keys and two rows a SOC rule has to know to union, so every denial writer
        // goes through AuthDenialRecorder.RouteTemplate. This assertion is what makes that hold on
        // a real pipeline run rather than only on a hand-built HttpContext.
        Assert.Equal("/npm/{package}", detail.GetProperty("route").GetString());

        // The metadata limiter buckets on the bare source IP with no "ip:" prefix
        // (AddMetadataLimiter calls GetRateLimitPartitionIp directly) — a fact only a real
        // pipeline run can pin, since a hand-built HttpContext test can only compare the
        // recorder's output to the same function the recorder itself calls.
        Assert.Equal("127.0.0.1", detail.GetProperty("partition").GetString());
    }

    private sealed record AuditRow(
        string Scope, string? OrgId, string Action, string? Ecosystem, string? Detail, string? SourceIp);
}
