using Dapper;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// An org with upstream fetching off — proxy passthrough disabled, or the org air-gapped — sends
/// nothing to an upstream registry from any public fetch of the resolver: no token exchange, no
/// HEAD, no GET. The same fetches with passthrough on reach the upstream, and an org with no
/// settings row keeps the default, passthrough on.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciUpstreamResolverPassthroughOffTests : IAsyncLifetime
{
    private OciResolverHarness _h = null!;
    private FakeOciRegistry.Image _image = null!;

    public async Task InitializeAsync()
    {
        _h = await OciResolverHarness.CreateAsync();
        _image = _h.Upstream.AddImage("passthrough");
        _h.Upstream.Tag("1.0", _image.Digest);
    }

    public async Task DisposeAsync() => await _h.DisposeAsync();

    public static TheoryData<string> Fetches() =>
        ["manifest-by-tag", "manifest-by-digest", "manifest-metadata", "blob", "blob-metadata", "tags"];

    private async Task FetchAsync(string fetch)
    {
        string org = _h.OrgId;
        const string repo = OciResolverHarness.Repository;
        switch (fetch)
        {
            case "manifest-by-tag":
                await DisposeAsync(await _h.Resolver.FetchManifestAsync(org, repo, "1.0", isDigest: false, default));
                break;
            case "manifest-by-digest":
                await DisposeAsync(await _h.Resolver.FetchManifestAsync(org, repo, _image.Digest, isDigest: true, default));
                break;
            case "manifest-metadata":
                await _h.Resolver.FetchManifestMetadataAsync(org, repo, "1.0", isDigest: false, default);
                break;
            case "blob":
                var blob = await _h.Resolver.FetchBlobAsync(org, repo, _image.LayerDigest, default);
                if (blob?.Blob is { } served)
                {
                    await served.Content.DisposeAsync();
                }

                break;
            case "blob-metadata":
                await _h.Resolver.FetchBlobMetadataAsync(org, repo, _image.LayerDigest, default);
                break;
            case "tags":
                await _h.Resolver.FetchTagsAsync(org, repo, default);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(fetch), fetch, null);
        }
    }

    private static async Task DisposeAsync(OciManifestResult? result)
    {
        if (result is not null)
        {
            await result.Content.DisposeAsync();
        }
    }

    [Theory]
    [MemberData(nameof(Fetches))]
    public async Task WithPassthroughOff_EveryFetchIsRefused_BeforeAnyUpstreamRequest(string fetch)
    {
        await _h.SetUpstreamPostureAsync(passthrough: false, airGapped: false);

        await Assert.ThrowsAsync<OciPassthroughOffException>(() => FetchAsync(fetch));

        Assert.Empty(_h.Requests);
    }

    [Theory]
    [MemberData(nameof(Fetches))]
    public async Task WithTheOrgAirGapped_EveryFetchIsRefused_BeforeAnyUpstreamRequest(string fetch)
    {
        await _h.SetUpstreamPostureAsync(passthrough: true, airGapped: true);

        await Assert.ThrowsAsync<OciPassthroughOffException>(() => FetchAsync(fetch));

        Assert.Empty(_h.Requests);
    }

    [Theory]
    [MemberData(nameof(Fetches))]
    public async Task WithPassthroughOn_EveryFetchReachesTheUpstream(string fetch)
    {
        await _h.SetUpstreamPostureAsync(passthrough: true, airGapped: false);

        await FetchAsync(fetch);

        Assert.NotEmpty(_h.Requests);
    }

    [Theory]
    [MemberData(nameof(Fetches))]
    public async Task WithNoSettingsRow_EveryFetchReachesTheUpstream(string fetch)
    {
        await using (var conn = await _h.Db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM org_settings WHERE org_id = @orgId", new { orgId = _h.OrgId });
        }

        await FetchAsync(fetch);

        Assert.NotEmpty(_h.Requests);
    }

    /// <summary>
    /// A tag held past <c>Oci:ManifestTagTtl</c> is the revalidation case: with passthrough off
    /// the resolver refuses it like any other fetch rather than asking the upstream whether the
    /// tag moved.
    /// </summary>
    [Fact]
    public async Task ADueTagRevalidation_WithPassthroughOff_SendsNothingUpstream()
    {
        await DisposeAsync(await _h.Resolver.FetchManifestAsync(
            _h.OrgId, OciResolverHarness.Repository, "1.0", isDigest: false, default));
        _h.Requests.Clear();
        _h.Clock.Advance(TimeSpan.FromMinutes(10));
        await _h.SetUpstreamPostureAsync(passthrough: false, airGapped: false);

        await Assert.ThrowsAsync<OciPassthroughOffException>(() => FetchAsync("manifest-by-tag"));

        Assert.Empty(_h.Requests);
    }
}
