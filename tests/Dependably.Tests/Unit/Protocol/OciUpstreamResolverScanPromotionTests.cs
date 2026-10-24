using System.Net;
using Dapper;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Moving-tag promotion under scan enforcement: with the org's <c>oci_scan_enforcement</c> at
/// <c>block</c>, a tag is repointed only to a digest the pull gate would serve, so a repoint to an
/// image the org has not scanned keeps serving the last accepted digest while the new digest is
/// held pending and fetched for scanning. A gate read that fails holds the tag (allowing on
/// evidence the gate could not read would be allowing by default); a held or promoted digest the
/// upstream no longer serves never makes the tag unavailable.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciUpstreamResolverScanPromotionTests : IAsyncLifetime
{
    private const string Tag = "1.27";
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private OciResolverHarness _h = null!;
    private string? _hiddenDigest;
    private string? _faultingDigest;
    private bool _hideTagBody;
    private bool _stripHeadDigest;

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        if (_h is not null)
        {
            await _h.DisposeAsync();
        }
    }

    private async Task BuildAsync(OciResolverHarness.PullGate gate)
    {
        _h = await OciResolverHarness.CreateAsync(
            intercept: req =>
            {
                string path = req.RequestUri!.AbsolutePath;
                if (req.Method == HttpMethod.Get && _hiddenDigest is not null
                    && path.EndsWith($"/manifests/{_hiddenDigest}", StringComparison.Ordinal))
                {
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                }

                if (req.Method == HttpMethod.Get && _faultingDigest is not null
                    && path.EndsWith($"/manifests/{_faultingDigest}", StringComparison.Ordinal))
                {
                    throw new HttpRequestException("connection reset by peer");
                }

                if (req.Method == HttpMethod.Get && _hideTagBody && path.EndsWith($"/manifests/{Tag}", StringComparison.Ordinal))
                {
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                }

                if (req.Method == HttpMethod.Head && _stripHeadDigest)
                {
                    var resp = _h.Upstream.Respond(req);
                    resp.Headers.Remove("Docker-Content-Digest");
                    return resp;
                }

                return null;
            },
            pullGate: gate);
    }

    private record TagRow(string? Digest, string? PendingDigest);

    private async Task<TagRow> RowAsync()
    {
        await using var conn = await _h.Db.OpenAsync();
        return await conn.QuerySingleAsync<TagRow>(
            "SELECT digest AS Digest, pending_digest AS PendingDigest FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId = _h.OrgId, repo = OciResolverHarness.Repository, tag = Tag });
    }

    private async Task<bool> IsCachedAsync(string digest)
    {
        await using var conn = await _h.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<bool>(
            "SELECT EXISTS(SELECT 1 FROM oci_blobs WHERE org_id = @orgId AND digest = @digest)",
            new { orgId = _h.OrgId, digest });
    }

    private async Task<string?> PullAsync()
    {
        var result = await _h.Resolver.FetchManifestAsync(
            _h.OrgId, OciResolverHarness.Repository, Tag, isDigest: false, default);
        if (result is null)
        {
            return null;
        }

        await result.Content.DisposeAsync();
        return result.Digest;
    }

    private async Task<(FakeOciRegistry.Image Old, FakeOciRegistry.Image Moved)> AcceptOldThenRepointAsync()
    {
        var old = _h.Upstream.AddImage("1.27.0");
        var moved = _h.Upstream.AddImage("1.27.1");
        _h.Upstream.Tag(Tag, old.Digest);
        Assert.Equal(old.Digest, await PullAsync());
        _h.Upstream.Tag(Tag, moved.Digest);
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        return (old, moved);
    }

    [Fact]
    public async Task UnderBlock_ARepointToAnUnscannedDigest_IsHeld_AndTheHeldDigestIsFetchedForScanning()
    {
        await BuildAsync(OciResolverHarness.PullGate.Covered);
        await _h.SetScanEnforcementAsync("block");
        var (old, moved) = await AcceptOldThenRepointAsync();

        Assert.Equal(old.Digest, await PullAsync());

        var row = await RowAsync();
        Assert.Equal(old.Digest, row.Digest);
        Assert.Equal(moved.Digest, row.PendingDigest);
        Assert.True(await IsCachedAsync(moved.Digest));
    }

    [Fact]
    public async Task UnderWarn_TheSameRepoint_IsPromoted_BecauseOnlyBlockGatesPromotion()
    {
        await BuildAsync(OciResolverHarness.PullGate.Covered);
        await _h.SetScanEnforcementAsync("warn");
        var (_, moved) = await AcceptOldThenRepointAsync();

        Assert.Equal(moved.Digest, await PullAsync());

        Assert.Equal(moved.Digest, (await RowAsync()).Digest);
    }

    [Fact]
    public async Task WithNoGateWired_PromotionIsAgeOnly_EvenUnderBlock()
    {
        await BuildAsync(OciResolverHarness.PullGate.NotWired);
        await _h.SetScanEnforcementAsync("block");
        var (_, moved) = await AcceptOldThenRepointAsync();

        Assert.Equal(moved.Digest, await PullAsync());
    }

    [Fact]
    public async Task AGateReadThatFails_HoldsTheTag_NeverPromotesOnEvidenceItCouldNotRead()
    {
        await BuildAsync(OciResolverHarness.PullGate.CoverageFails);
        await _h.SetScanEnforcementAsync("block");
        var (old, moved) = await AcceptOldThenRepointAsync();

        Assert.Equal(old.Digest, await PullAsync());

        var row = await RowAsync();
        Assert.Equal(old.Digest, row.Digest);
        Assert.Equal(moved.Digest, row.PendingDigest);
    }

    [Fact]
    public async Task UnderBlock_ADigestApprovedPastTheUnscannedGate_IsPromoted()
    {
        await BuildAsync(OciResolverHarness.PullGate.Covered);
        await _h.SetScanEnforcementAsync("block");
        var (_, moved) = await AcceptOldThenRepointAsync();
        await using (var conn = await _h.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO quarantine (id, org_id, ecosystem, purl, gate, state, updated_at)
                VALUES (@id, @orgId, 'oci', @purl, 'unscanned', 'approved', '2026-06-15T12:00:00Z')
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId = _h.OrgId,
                    purl = PurlNormalizer.Oci(OciResolverHarness.Repository, moved.Digest),
                });
        }

        Assert.Equal(moved.Digest, await PullAsync());

        Assert.Equal(moved.Digest, (await RowAsync()).Digest);
    }

    [Fact]
    public async Task UnderBlock_AnApprovalForADifferentGate_DoesNotWaiveTheUnscannedArm()
    {
        await BuildAsync(OciResolverHarness.PullGate.Covered);
        await _h.SetScanEnforcementAsync("block");
        var (old, moved) = await AcceptOldThenRepointAsync();
        await using (var conn = await _h.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO quarantine (id, org_id, ecosystem, purl, gate, state, updated_at)
                VALUES (@id, @orgId, 'oci', @purl, 'release_age', 'approved', '2026-06-15T12:00:00Z')
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId = _h.OrgId,
                    purl = PurlNormalizer.Oci(OciResolverHarness.Repository, moved.Digest),
                });
        }

        Assert.Equal(old.Digest, await PullAsync());

        Assert.Equal(moved.Digest, (await RowAsync()).PendingDigest);
    }

    [Fact]
    public async Task ATooYoungDigest_WithScanEnforcementOff_IsHeld_WithoutBeingFetchedForScanning()
    {
        await BuildAsync(OciResolverHarness.PullGate.Covered);
        await _h.SetMinReleaseAgeHoursAsync(24);
        var (old, moved) = await AcceptOldThenRepointAsync();

        Assert.Equal(old.Digest, await PullAsync());

        Assert.Equal(moved.Digest, (await RowAsync()).PendingDigest);
        Assert.False(await IsCachedAsync(moved.Digest));
    }

    [Fact]
    public async Task AFaultWhileFetchingTheHeldDigest_IsContained_AndTheAcceptedDigestStillServes()
    {
        await BuildAsync(OciResolverHarness.PullGate.Covered);
        await _h.SetScanEnforcementAsync("block");
        var (old, moved) = await AcceptOldThenRepointAsync();
        _faultingDigest = moved.Digest;

        Assert.Equal(old.Digest, await PullAsync());

        var row = await RowAsync();
        Assert.Equal(old.Digest, row.Digest);
        Assert.Equal(moved.Digest, row.PendingDigest);
    }

    [Fact]
    public async Task AHeldDigestTheUpstreamNoLongerServes_IsNotCached_AndTheAcceptedDigestStillServes()
    {
        await BuildAsync(OciResolverHarness.PullGate.Covered);
        await _h.SetScanEnforcementAsync("block");
        var (old, moved) = await AcceptOldThenRepointAsync();
        _hiddenDigest = moved.Digest;

        Assert.Equal(old.Digest, await PullAsync());

        Assert.Equal(moved.Digest, (await RowAsync()).PendingDigest);
        Assert.False(await IsCachedAsync(moved.Digest));
    }

    [Fact]
    public async Task APromotableDigestThatVanishedBetweenHeadAndFetch_LeavesTheAcceptedMappingServing()
    {
        await BuildAsync(OciResolverHarness.PullGate.NotWired);
        var (old, moved) = await AcceptOldThenRepointAsync();
        _hiddenDigest = moved.Digest;

        Assert.Equal(old.Digest, await PullAsync());

        var row = await RowAsync();
        Assert.Equal(old.Digest, row.Digest);
        Assert.Null(row.PendingDigest);
    }

    [Fact]
    public async Task AFirstPullWhoseObservedDigestVanished_FallsBackToFetchingByTag()
    {
        await BuildAsync(OciResolverHarness.PullGate.NotWired);
        var old = _h.Upstream.AddImage("1.27.0");
        _h.Upstream.Tag(Tag, old.Digest);
        var meta = await _h.Resolver.FetchManifestMetadataAsync(
            _h.OrgId, OciResolverHarness.Repository, Tag, isDigest: false, default);
        Assert.Equal(old.Digest, meta!.Digest);
        _hiddenDigest = old.Digest;

        Assert.Equal(old.Digest, await PullAsync());

        Assert.Equal(old.Digest, (await RowAsync()).Digest);
    }

    [Fact]
    public async Task ADigestlessHead_WhoseTagBodyThenCannotBeFetched_IsAMiss()
    {
        await BuildAsync(OciResolverHarness.PullGate.NotWired);
        await AcceptOldThenRepointAsync();
        _stripHeadDigest = true;
        _hideTagBody = true;

        Assert.Null(await PullAsync());
    }
}
