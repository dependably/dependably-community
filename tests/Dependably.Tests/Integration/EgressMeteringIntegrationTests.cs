using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Egress fidelity through the real pipeline: each ecosystem's artifact download records exactly
/// the bytes it served as <c>egress_bytes</c>, metadata records under its own meter, and HEAD and
/// error responses record nothing.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EgressMeteringIntegrationTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task Npm_tarball_bills_its_exact_size_and_the_packument_bills_as_metadata()
    {
        string pkg = $"metered{Guid.NewGuid():N}"[..16];
        await _factory.PushNpmPackage(pkg, "1.0.0");
        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));
        await ResetEventsAsync();

        var tarball = await client.GetAsync($"/npm/tarballs/{pkg}/{pkg}-1.0.0.tgz");
        Assert.Equal(HttpStatusCode.OK, tarball.StatusCode);
        long tarballBytes = (await tarball.Content.ReadAsByteArrayAsync()).LongLength;

        var packument = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, packument.StatusCode);
        long packumentBytes = (await packument.Content.ReadAsByteArrayAsync()).LongLength;

        var events = await DrainEventsAsync();
        Assert.Equal(2, events.Count);
        Assert.Contains(events, e => e.Meter == UsageMeters.EgressBytes && e.Quantity == tarballBytes
                                     && e.Source == "npm" && e.Delivery == UsageDelivery.Streamed);
        Assert.Contains(events, e => e.Meter == UsageMeters.EgressMetadataBytes && e.Quantity == packumentBytes);
    }

    [Fact]
    public async Task PyPi_download_bills_its_exact_size()
    {
        string pkg = $"metered{Guid.NewGuid():N}"[..16];
        await _factory.PushPyPiPackage(pkg, "1.0.0");
        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));

        string index = await client.GetStringAsync($"/simple/{pkg}/");
        string href = index.Split("href=\"")[1].Split('"')[0].Split('#')[0];
        await ResetEventsAsync();

        var file = await client.GetAsync(href);
        Assert.Equal(HttpStatusCode.OK, file.StatusCode);
        long bytes = (await file.Content.ReadAsByteArrayAsync()).LongLength;

        var e = Assert.Single(await DrainEventsAsync());
        Assert.Equal(UsageMeters.EgressBytes, e.Meter);
        Assert.Equal(bytes, e.Quantity);
        Assert.Equal("pypi", e.Source);
    }

    [Fact]
    public async Task Head_and_missing_artifacts_bill_nothing()
    {
        string pkg = $"metered{Guid.NewGuid():N}"[..16];
        await _factory.PushNpmPackage(pkg, "1.0.0");
        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));
        await ResetEventsAsync();

        var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/npm/tarballs/{pkg}/{pkg}-1.0.0.tgz"));
        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        var missing = await client.GetAsync($"/npm/tarballs/{pkg}/{pkg}-9.9.9.tgz");
        Assert.NotEqual(HttpStatusCode.OK, missing.StatusCode);

        Assert.Empty(await DrainEventsAsync());
    }

    [Fact]
    public async Task Unmetered_protocol_routes_record_nothing()
    {
        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));
        await ResetEventsAsync();

        var ping = await client.GetAsync("/npm/-/ping");
        Assert.Equal(HttpStatusCode.OK, ping.StatusCode);

        Assert.Empty(await DrainEventsAsync());
    }

    private async Task ResetEventsAsync()
    {
        await _factory.Services.GetRequiredService<UsageEventWriterHostedService>().WaitForIdleAsync(TimeSpan.FromSeconds(10));
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync("DELETE FROM usage_events WHERE 1 = 1");
    }

    private async Task<List<UsageEvent>> DrainEventsAsync()
    {
        await _factory.Services.GetRequiredService<UsageEventWriterHostedService>().WaitForIdleAsync(TimeSpan.FromSeconds(10));
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        var rows = await conn.QueryAsync<UsageEvent>(
            """
            SELECT event_id AS EventId, org_id AS OrgId, meter AS Meter, delivery AS Delivery,
                   quantity AS Quantity, source AS Source, object_ref AS ObjectRef, occurred_at AS OccurredAt
            FROM usage_events
            """);
        return rows.ToList();
    }
}
