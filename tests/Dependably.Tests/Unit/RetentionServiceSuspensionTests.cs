using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// A suspended/archived/deleting org is excluded from <see cref="RetentionService.RunGcPassAsync"/>'s
/// per-org enumeration (see TenantLifecycle), so none of its opt-in policies (keep_versions here)
/// advance while it stays non-active — the accepted trade-off documented on TenantLifecycle.
///
/// Every mixed-pass assertion below pairs the negative probe (the non-active org's excess
/// versions survive) with its adversarial twin (an active org in the SAME pass still gets
/// pruned) — a sweep that skips one non-active org must not abort the whole pass.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RetentionServiceSuspensionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private RetentionService Build()
    {
        var cfg = new ConfigurationBuilder().Build();
        return new RetentionService(new RetentionService.Dependencies(
            _db, _blobs, new JwtRevocationRepository(_db, time: _clock),
            new InviteRepository(_db, _clock), new SamlConfigRepository(_db, _clock), new TrustedDeviceService(_db, _clock, cfg),
            cfg, new AirGapMode(cfg), NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new Dependably.Storage.TieredBlobStorage(_blobs, _blobs),
                new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg),
            new OrgStatsHistoryRepository(_db)));
    }

    private async Task SeedOrgAsync(string orgId, string status, int keepVersions)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES (@orgId, @orgId, @status)",
            new { orgId, status });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id, keep_versions) VALUES (@orgId, @keepVersions)",
            new { orgId, keepVersions });
    }

    // Seeds TWO uploaded versions of the same package for the org, so a keep_versions=1 pass has
    // exactly one to prune.
    private async Task SeedTwoUploadedVersionsAsync(string orgId)
    {
        var t = _clock.GetUtcNow();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES (@pkg, @orgId, 'npm', 'left-pad', 'left-pad')",
            new { pkg = orgId + "-pkg", orgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, created_at)
            VALUES
              (@v1, @pkg, '1.0.0', 'pkg:npm/left-pad@1.0.0', @blob1, 'uploaded', @t1),
              (@v2, @pkg, '1.0.1', 'pkg:npm/left-pad@1.0.1', @blob2, 'uploaded', @t2)
            """,
            new
            {
                v1 = orgId + "-v1",
                v2 = orgId + "-v2",
                pkg = orgId + "-pkg",
                blob1 = "registry/" + orgId + "/left-pad-1.0.0.tgz",
                blob2 = "registry/" + orgId + "/left-pad-1.0.1.tgz",
                t1 = t.AddDays(-2).ToUtcIso(),
                t2 = t.AddDays(-1).ToUtcIso(),
            });
    }

    private async Task<long> VersionCountAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE package_id = @pkg",
            new { pkg = orgId + "-pkg" });
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task RunGcPass_SkipsVersionLimitEnforcement_ForANonActiveOrg_ButStillPrunesAnActiveOrgInTheSamePass(
        string nonActiveStatus)
    {
        await SeedOrgAsync("locked", nonActiveStatus, keepVersions: 1);
        await SeedTwoUploadedVersionsAsync("locked");

        await SeedOrgAsync("live", "active", keepVersions: 1);
        await SeedTwoUploadedVersionsAsync("live");

        await Build().RunGcPassAsync(default);

        // Negative probe: the non-active org's excess version is frozen in place, not pruned.
        Assert.Equal(2, await VersionCountAsync("locked"));

        // Adversarial twin, same pass: the active org's excess version IS pruned. Proves the
        // non-active org was skipped, not that the whole pass silently did nothing.
        Assert.Equal(1, await VersionCountAsync("live"));
    }

    [Fact]
    public async Task RunGcPass_ResumesVersionLimitEnforcement_OnceTheOrgIsReinstated()
    {
        await SeedOrgAsync("reinstated", "suspended", keepVersions: 1);
        await SeedTwoUploadedVersionsAsync("reinstated");

        var svc = Build();
        await svc.RunGcPassAsync(default);
        Assert.Equal(2, await VersionCountAsync("reinstated"));

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET status = 'active' WHERE id = 'reinstated'");
        }

        await svc.RunGcPassAsync(default);
        Assert.Equal(1, await VersionCountAsync("reinstated"));
    }
}
