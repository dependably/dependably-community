using Dapper;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The moving-tag state machine of the OCI proxy: a tag the org has accepted keeps serving its
/// accepted digest until upstream moves it AND the promotion gate allows the move; a too-young
/// digest is held pending (and keeps aging) rather than served; a registry that answers HEAD
/// without a digest is revalidated by body; an upstream failure is never cached as an answer and
/// an upstream that no longer has the tag is a definitive miss.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciUpstreamResolverTagRevalidationTests : IAsyncLifetime
{
    private const string Tag = "1.27";
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private OciResolverHarness _h = null!;
    private bool _stripHeadDigest;

    public async Task InitializeAsync()
    {
        _h = await OciResolverHarness.CreateAsync(intercept: req =>
        {
            if (!_stripHeadDigest || req.Method != HttpMethod.Head)
            {
                return null;
            }

            var resp = _h.Upstream.Respond(req);
            resp.Headers.Remove("Docker-Content-Digest");
            return resp;
        });
    }

    public async Task DisposeAsync() => await _h.DisposeAsync();

    private record TagRow(string? Digest, string? LastRevalidated, string? PendingDigest, string? PendingFirstSeenAt);

    private async Task<TagRow?> RowAsync()
    {
        await using var conn = await _h.Db.OpenAsync();
        return await conn.QuerySingleOrDefaultAsync<TagRow>(
            """
            SELECT digest AS Digest, last_revalidated AS LastRevalidated,
                   pending_digest AS PendingDigest, pending_first_seen_at AS PendingFirstSeenAt
            FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag
            """,
            new { orgId = _h.OrgId, repo = OciResolverHarness.Repository, tag = Tag });
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

    private (FakeOciRegistry.Image Old, FakeOciRegistry.Image Moved) SeedTwoReleases()
    {
        var old = _h.Upstream.AddImage("1.27.0");
        var moved = _h.Upstream.AddImage("1.27.1");
        _h.Upstream.Tag(Tag, old.Digest);
        return (old, moved);
    }

    [Fact]
    public async Task APullWithinTheTtl_IsServedFromTheAcceptedMapping_WithoutAnUpstreamAsk()
    {
        var (old, _) = SeedTwoReleases();

        Assert.Equal(old.Digest, await PullAsync());
        int firstPullRequests = _h.Requests.Count;
        _h.Clock.Advance(Ttl - TimeSpan.FromSeconds(1));

        Assert.Equal(old.Digest, await PullAsync());
        Assert.Equal(firstPullRequests, _h.Requests.Count);
    }

    [Fact]
    public async Task AnUnchangedTag_IsConfirmedWithAHeadOnly_AndThePendingMarkerStaysClear()
    {
        var (old, _) = SeedTwoReleases();
        await PullAsync();
        _h.Requests.Clear();
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.Equal(old.Digest, await PullAsync());

        Assert.Single(_h.Requests, r => r.StartsWith("HEAD ", StringComparison.Ordinal));
        Assert.DoesNotContain(_h.Requests, r => r.StartsWith("GET ", StringComparison.Ordinal));
        var row = await RowAsync();
        Assert.Equal(old.Digest, row!.Digest);
        Assert.Null(row.PendingDigest);
    }

    [Fact]
    public async Task ARepeatedRevalidation_AfterTheObservationWentStale_AsksUpstreamAgain()
    {
        var (old, _) = SeedTwoReleases();
        await PullAsync();
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        await PullAsync();
        _h.Requests.Clear();
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.Equal(old.Digest, await PullAsync());

        Assert.Single(_h.Requests, r => r.StartsWith("HEAD ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ARepointedTag_WithNoReleaseAgePolicy_IsPromotedImmediately()
    {
        var (old, moved) = SeedTwoReleases();
        await PullAsync();
        _h.Upstream.Tag(Tag, moved.Digest);
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.Equal(moved.Digest, await PullAsync());

        var row = await RowAsync();
        Assert.Equal(moved.Digest, row!.Digest);
        Assert.NotEqual(old.Digest, row.Digest);
        Assert.Null(row.PendingDigest);
    }

    [Fact]
    public async Task ATooYoungRepoint_IsHeldPending_KeepsServingTheAcceptedDigest_AndPromotesOnceItHasAged()
    {
        var (old, moved) = SeedTwoReleases();
        await _h.SetMinReleaseAgeHoursAsync(24);
        await PullAsync();
        _h.Upstream.Tag(Tag, moved.Digest);

        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        Assert.Equal(old.Digest, await PullAsync());
        var held = await RowAsync();
        Assert.Equal(old.Digest, held!.Digest);
        Assert.Equal(moved.Digest, held.PendingDigest);
        string firstSeen = held.PendingFirstSeenAt!;

        _h.Clock.Advance(TimeSpan.FromHours(1));
        Assert.Equal(old.Digest, await PullAsync());
        var stillHeld = await RowAsync();
        Assert.Equal(firstSeen, stillHeld!.PendingFirstSeenAt);

        _h.Clock.Advance(TimeSpan.FromHours(24));
        Assert.Equal(moved.Digest, await PullAsync());
        var promoted = await RowAsync();
        Assert.Equal(moved.Digest, promoted!.Digest);
        Assert.Null(promoted.PendingDigest);
    }

    [Fact]
    public async Task AFurtherRepointWhileHeld_RestartsTheAgeOfTheNewPendingDigest()
    {
        var (old, moved) = SeedTwoReleases();
        var newest = _h.Upstream.AddImage("1.27.2");
        await _h.SetMinReleaseAgeHoursAsync(24);
        await PullAsync();
        _h.Upstream.Tag(Tag, moved.Digest);
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        await PullAsync();
        var first = await RowAsync();

        _h.Upstream.Tag(Tag, newest.Digest);
        _h.Clock.Advance(TimeSpan.FromHours(20));
        Assert.Equal(old.Digest, await PullAsync());

        var second = await RowAsync();
        Assert.Equal(newest.Digest, second!.PendingDigest);
        Assert.NotEqual(first!.PendingFirstSeenAt, second.PendingFirstSeenAt);
        Assert.Equal(old.Digest, second.Digest);
    }

    [Fact]
    public async Task ATagTheUpstreamNoLongerHas_IsADefinitiveMiss_ForAnAcceptedTag()
    {
        SeedTwoReleases();
        await PullAsync();
        _h.Upstream.Tag(Tag, FakeOciRegistry.Digest("not a manifest"u8.ToArray()));
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.Null(await PullAsync());
    }

    [Fact]
    public async Task AnUpstreamFailureOnRevalidation_Propagates_AndIsNeverCachedAsAnAnswer()
    {
        var (old, _) = SeedTwoReleases();
        await PullAsync();
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        _h.Upstream.Down = true;

        await Assert.ThrowsAsync<OciUpstreamUnavailableException>(PullAsync);

        _h.Upstream.Down = false;
        Assert.Equal(old.Digest, await PullAsync());
    }

    [Fact]
    public async Task ARegistryAnsweringHeadWithoutADigest_IsRevalidatedByBody_AndRepointsWhenAllowed()
    {
        var (old, moved) = SeedTwoReleases();
        await PullAsync();
        _stripHeadDigest = true;
        _h.Upstream.Tag(Tag, moved.Digest);
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        _h.Requests.Clear();

        Assert.Equal(moved.Digest, await PullAsync());

        Assert.Contains(_h.Requests, r => r.StartsWith("GET ", StringComparison.Ordinal) && r.EndsWith($"/manifests/{Tag}", StringComparison.Ordinal));
        Assert.Equal(moved.Digest, (await RowAsync())!.Digest);
        Assert.NotEqual(old.Digest, moved.Digest);
    }

    [Fact]
    public async Task ARegistryAnsweringHeadWithoutADigest_HoldsATooYoungRepointPending()
    {
        var (old, moved) = SeedTwoReleases();
        await _h.SetMinReleaseAgeHoursAsync(24);
        await PullAsync();
        _stripHeadDigest = true;
        _h.Upstream.Tag(Tag, moved.Digest);
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.Equal(old.Digest, await PullAsync());

        var row = await RowAsync();
        Assert.Equal(old.Digest, row!.Digest);
        Assert.Equal(moved.Digest, row.PendingDigest);
    }

    [Fact]
    public async Task ARegistryAnsweringHeadWithoutADigest_ConfirmsAnUnchangedTagByBody()
    {
        var (old, _) = SeedTwoReleases();
        await PullAsync();
        _stripHeadDigest = true;
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.Equal(old.Digest, await PullAsync());
        Assert.Equal(old.Digest, (await RowAsync())!.Digest);
    }

    [Fact]
    public async Task ARegistryAnsweringHeadWithoutADigest_WhoseTagIsGone_IsAMiss()
    {
        SeedTwoReleases();
        await PullAsync();
        _stripHeadDigest = true;
        _h.Upstream.Tag(Tag, FakeOciRegistry.Digest("gone"u8.ToArray()));
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.Null(await PullAsync());
    }

    [Fact]
    public async Task AFreshHeadObservation_LetsAFirstPullPromoteByDigest_WithoutAGetByTag()
    {
        var (old, _) = SeedTwoReleases();
        var meta = await _h.Resolver.FetchManifestMetadataAsync(
            _h.OrgId, OciResolverHarness.Repository, Tag, isDigest: false, default);
        Assert.Equal(old.Digest, meta!.Digest);
        _h.Requests.Clear();
        _h.Clock.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal(old.Digest, await PullAsync());

        Assert.DoesNotContain(_h.Requests, r => r.EndsWith($"/manifests/{Tag}", StringComparison.Ordinal) && r.StartsWith("GET ", StringComparison.Ordinal));
        Assert.Contains(_h.Requests, r => r.StartsWith("GET ", StringComparison.Ordinal) && r.EndsWith($"/manifests/{old.Digest}", StringComparison.Ordinal));
        Assert.Equal(old.Digest, (await RowAsync())!.Digest);
    }

    // ── HEAD-side revalidation ──────────────────────────────────────────────────

    private async Task<OciManifestMetadata?> HeadAsync()
        => await _h.Resolver.FetchManifestMetadataAsync(
            _h.OrgId, OciResolverHarness.Repository, Tag, isDigest: false, default);

    [Fact]
    public async Task AHeadOnAnUnchangedTag_RefreshesTheFreshnessStamp_AndAnswersFromTheCachedManifest()
    {
        var (old, _) = SeedTwoReleases();
        await PullAsync();
        var before = await RowAsync();
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        var meta = await HeadAsync();

        Assert.Equal(old.Digest, meta!.Digest);
        Assert.Equal(old.Manifest.Length, meta.SizeBytes);
        Assert.NotEqual(before!.LastRevalidated, (await RowAsync())!.LastRevalidated);
    }

    [Fact]
    public async Task AHeadOnARepointedTag_WithNoPolicy_AnswersWithTheNewDigest_ButNeverRepointsFromAHead()
    {
        var (old, moved) = SeedTwoReleases();
        await PullAsync();
        _h.Upstream.Tag(Tag, moved.Digest);
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        var meta = await HeadAsync();

        Assert.Equal(moved.Digest, meta!.Digest);
        var row = await RowAsync();
        Assert.Equal(old.Digest, row!.Digest);
        Assert.Equal(moved.Digest, row.PendingDigest);
    }

    [Fact]
    public async Task AHeadOnATooYoungRepoint_StillAnswersWithTheAcceptedDigest()
    {
        var (old, moved) = SeedTwoReleases();
        await _h.SetMinReleaseAgeHoursAsync(24);
        await PullAsync();
        _h.Upstream.Tag(Tag, moved.Digest);
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        var meta = await HeadAsync();

        Assert.Equal(old.Digest, meta!.Digest);
        Assert.Equal(moved.Digest, (await RowAsync())!.PendingDigest);
    }

    [Fact]
    public async Task AHeadOnATagTheUpstreamNoLongerHas_IsNull()
    {
        SeedTwoReleases();
        await PullAsync();
        _h.Upstream.Tag(Tag, FakeOciRegistry.Digest("gone"u8.ToArray()));
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.Null(await HeadAsync());
    }

    [Fact]
    public async Task AHeadAnsweredWithoutADigest_IsNull_NotAGuess()
    {
        SeedTwoReleases();
        await PullAsync();
        _stripHeadDigest = true;
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.Null(await HeadAsync());
    }

    [Fact]
    public async Task AFirstPullOfATagTheUpstreamDoesNotHave_IsNull_AndRecordsNothing()
    {
        Assert.Null(await PullAsync());

        Assert.Null(await RowAsync());
    }
}
