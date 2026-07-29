using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// <see cref="BlobPresignService"/> is the single decision point for "redirect or stream". Every
/// case here asserts the same posture from a different angle: anything short of a fully working
/// signing path returns null, which the serve paths read as "stream the bytes". The service never
/// fails a read it could have served.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlobPresignServiceTests
{
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    private BlobPresignService Sut(bool enabled, int ttlSeconds = PresignedReadOptions.DefaultTtlSeconds)
        => new(
            new PresignedReadOptions { Enabled = enabled, Ttl = TimeSpan.FromSeconds(ttlSeconds) },
            _clock,
            NullLogger<BlobPresignService>.Instance);

    [Fact]
    public async Task Disabled_NeverAsksTheStoreToSign()
    {
        var store = new CapableStore();
        Assert.Null(await Sut(enabled: false).TryCreateAsync(store, "k"));
        Assert.Equal(0, store.SignCalls);
    }

    [Fact]
    public async Task Enabled_StoreWithoutTheCapability_ReturnsNull()
    {
        // The local backend's shape: it does not implement IPresignedReadBlobStore at all.
        Assert.Null(await Sut(enabled: true).TryCreateAsync(new InMemoryBlobStore(_clock), "k"));
    }

    [Fact]
    public async Task Enabled_StoreThatCannotSignRightNow_ReturnsNull()
    {
        var store = new CapableStore { CanSign = false };
        Assert.Null(await Sut(enabled: true).TryCreateAsync(store, "k"));
        Assert.Equal(0, store.SignCalls);
    }

    [Fact]
    public async Task Enabled_MintsAUrlExpiringExactlyOneTtlFromTheInjectedClock()
    {
        var store = new CapableStore();

        var result = await Sut(enabled: true, ttlSeconds: 45).TryCreateAsync(store, "oci/sha256/abc");

        Assert.NotNull(result);
        Assert.Equal(_clock.GetUtcNow().AddSeconds(45), result!.Value.ExpiresAt);
        Assert.Equal(result.Value.ExpiresAt, store.LastExpiry);
        Assert.Equal("https://signed.test/oci/sha256/abc", result.Value.Url.ToString());
    }

    [Fact]
    public async Task Enabled_StoreReturnsNullForAMissingBlob_ReturnsNull()
    {
        var store = new CapableStore { ReturnUrl = false };
        Assert.Null(await Sut(enabled: true).TryCreateAsync(store, "gone"));
    }

    [Fact]
    public async Task Enabled_StoreThrows_FallsBackToStreamingRatherThanFailingTheRead()
    {
        // A signing outage must degrade to "serve it yourself", never to a failed pull — the
        // redirect is a throughput optimisation on a read that is already authorized.
        var store = new CapableStore { Throw = true };
        Assert.Null(await Sut(enabled: true).TryCreateAsync(store, "k"));
    }

    [Fact]
    public async Task Enabled_CancellationIsNotSwallowedAsAFallback()
    {
        var store = new CapableStore { Throw = true, ThrowCancellation = true };
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Sut(enabled: true).TryCreateAsync(store, "k", cts.Token));
    }

    // ── Options binding ───────────────────────────────────────────────────────

    [Fact]
    public void Options_DefaultOff_WithASixtySecondTtl()
    {
        var opts = PresignedReadOptions.FromConfiguration(Config());
        Assert.False(opts.Enabled);
        Assert.Equal(TimeSpan.FromSeconds(PresignedReadOptions.DefaultTtlSeconds), opts.Ttl);
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("TRUE", true)]
    [InlineData("false", false)]
    [InlineData("yes", false)]
    [InlineData("", false)]
    public void Options_EnableFlagIsStrictBoolean_AnythingElseLeavesItOff(string raw, bool expected)
    {
        var opts = PresignedReadOptions.FromConfiguration(
            Config((PresignedReadOptions.EnabledKey, raw)));
        Assert.Equal(expected, opts.Enabled);
    }

    [Theory]
    [InlineData("1", PresignedReadOptions.MinTtlSeconds)]
    [InlineData("100000", PresignedReadOptions.MaxTtlSeconds)]
    [InlineData("-5", PresignedReadOptions.MinTtlSeconds)]
    [InlineData("120", 120)]
    [InlineData("banana", PresignedReadOptions.DefaultTtlSeconds)]
    public void Options_TtlIsClampedRatherThanRejected(string raw, int expectedSeconds)
    {
        var opts = PresignedReadOptions.FromConfiguration(
            Config((PresignedReadOptions.TtlSecondsKey, raw)));
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), opts.Ttl);
    }

    private static IConfiguration Config(params (string Key, string Value)[] values)
        => new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    /// <summary>A blob store that advertises the presign capability, with each failure mode dialled in.</summary>
    private sealed class CapableStore : IBlobStore, IPresignedReadBlobStore
    {
        public bool CanSign { get; init; } = true;
        public bool ReturnUrl { get; init; } = true;
        public bool Throw { get; init; }
        public bool ThrowCancellation { get; init; }
        public int SignCalls { get; private set; }
        public DateTimeOffset? LastExpiry { get; private set; }

        public bool SupportsPresignedReads => CanSign;

        public Task<Uri?> TryCreatePresignedReadUrlAsync(
            string key, DateTimeOffset expiresAt, CancellationToken ct = default)
        {
            SignCalls++;
            LastExpiry = expiresAt;
            return ThrowCancellation
                ? throw new OperationCanceledException(ct)
                : Throw
                ? throw new InvalidOperationException("signing credential unavailable")
                : Task.FromResult(ReturnUrl ? new Uri($"https://signed.test/{key}") : null);
        }

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => Task.CompletedTask;
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => Task.FromResult<Stream?>(null);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => Task.FromResult(true);
        public Task DeleteAsync(string key, CancellationToken ct = default) => Task.CompletedTask;
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => Task.FromResult(0L);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => Task.FromResult<RangedStream?>(null);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => AsyncEnumerable.Empty<BlobInfo>();
    }
}
