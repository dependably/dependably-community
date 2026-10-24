using System.Collections;
using System.Reflection;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The tag-observation cache is keyed on a client-controlled repository and tag, so it must stay
/// bounded under enumeration: at the cap, stale and non-Found entries are dropped first and then
/// the oldest completed ones, whether the new entry arrives from a HEAD observation or from a
/// body-verified revalidation.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciUpstreamResolverTagObservationBoundTests : IAsyncLifetime
{
    private const int Cap = 1024;
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private OciResolverHarness _h = null!;
    private FakeOciRegistry.Image _image = null!;
    private bool _stripHeadDigest;

    public async Task InitializeAsync()
    {
        _h = await OciResolverHarness.CreateAsync(intercept: req =>
        {
            if (req.Method != HttpMethod.Head || !_stripHeadDigest)
            {
                return null;
            }

            var resp = _h.Upstream.Respond(req);
            resp.Headers.Remove("Docker-Content-Digest");
            return resp;
        });
        _image = _h.Upstream.AddImage("nginx-1.27");
    }

    public async Task DisposeAsync() => await _h.DisposeAsync();

    private int ObservationCount()
    {
        var field = typeof(OciUpstreamResolver).GetField("_tagObservations", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return ((ICollection)field.GetValue(_h.Resolver)!).Count;
    }

    private async Task ObserveAsync(string prefix, int count)
    {
        for (int i = 0; i < count; i++)
        {
            string tag = $"{prefix}-{i}";
            _h.Upstream.Tag(tag, _image.Digest);
            var meta = await _h.Resolver.FetchManifestMetadataAsync(
                _h.OrgId, OciResolverHarness.Repository, tag, isDigest: false, default);
            Assert.Equal(_image.Digest, meta!.Digest);
        }
    }

    [Fact]
    public async Task AtTheCap_StaleObservationsAreDropped_BeforeTheNewOneIsAdded()
    {
        await ObserveAsync("stale", 600);
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        await ObserveAsync("fresh", Cap - 600);
        Assert.Equal(Cap, ObservationCount());

        await ObserveAsync("one-more", 1);

        Assert.True(ObservationCount() <= Cap - 600 + 1);
        Assert.True(ObservationCount() >= 1);
    }

    [Fact]
    public async Task AtTheCap_WithEverythingFresh_TheOldestObservationIsEvicted_SoTheCacheNeverGrowsPastIt()
    {
        await ObserveAsync("tag", Cap);
        Assert.Equal(Cap, ObservationCount());

        await ObserveAsync("overflow", 3);

        Assert.Equal(Cap, ObservationCount());
    }

    [Fact]
    public async Task ABodyVerifiedRevalidation_AtTheCap_PrunesBeforeRecordingItsObservation()
    {
        string tag = "1.27";
        _h.Upstream.Tag(tag, _image.Digest);
        var first = await _h.Resolver.FetchManifestAsync(_h.OrgId, OciResolverHarness.Repository, tag, isDigest: false, default);
        await first!.Content.DisposeAsync();
        await ObserveAsync("filler", Cap);
        _stripHeadDigest = true;
        _h.Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        var again = await _h.Resolver.FetchManifestAsync(_h.OrgId, OciResolverHarness.Repository, tag, isDigest: false, default);
        await again!.Content.DisposeAsync();

        Assert.Equal(_image.Digest, again.Digest);
        Assert.True(ObservationCount() <= Cap);
    }
}
