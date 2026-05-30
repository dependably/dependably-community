using Dependably.Storage;
using NSubstitute;
using Xunit;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// Behavioral tests for the Azure blob adapter. The smoke tests cover Put + GetTotalSize
/// happy paths; this file fills the remaining methods + pagination edge cases.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AzureBlobStoreTests
{
    private readonly IAzureBlobContainer _container = Substitute.For<IAzureBlobContainer>();
    private AzureBlobStore Sut => new(_container);

    [Fact]
    public async Task GetAsync_Existing_DelegatesToContainer()
    {
        var stream = new MemoryStream([1, 2]);
        _container.DownloadOrNullAsync("k", Arg.Any<CancellationToken>()).Returns(stream);

        var result = await Sut.GetAsync("k");
        Assert.Same(stream, result);
    }

    [Fact]
    public async Task GetAsync_Missing_PassesThroughNull()
    {
        _container.DownloadOrNullAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((Stream?)null);

        Assert.Null(await Sut.GetAsync("missing"));
    }

    [Fact]
    public async Task ExistsAsync_DelegatesToContainerExists()
    {
        _container.ExistsAsync("k", Arg.Any<CancellationToken>()).Returns(true);
        Assert.True(await Sut.ExistsAsync("k"));
    }

    [Fact]
    public async Task DeleteAsync_DelegatesToDeleteIfExists()
    {
        await Sut.DeleteAsync("k");
        await _container.Received(1).DeleteIfExistsAsync("k", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetTotalSizeAsync_SumsAllEnumeratedSizes()
    {
        _container.EnumerateSizesAsync(Arg.Any<CancellationToken>())
            .Returns(AsyncEnum(10, 20, 30));
        Assert.Equal(60, await Sut.GetTotalSizeAsync());
    }

    [Fact]
    public async Task GetTotalSizeAsync_EmptyContainer_ReturnsZero()
    {
        _container.EnumerateSizesAsync(Arg.Any<CancellationToken>())
            .Returns(AsyncEnum());
        Assert.Equal(0, await Sut.GetTotalSizeAsync());
    }

    [Fact]
    public async Task PutAsync_DelegatesToContainerWithCorrectKeyAndStream()
    {
        using var stream = new MemoryStream([42, 43]);
        await Sut.PutAsync("the-key", stream);
        await _container.Received(1).UploadAsync("the-key", stream, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ExistsAsync_BlobMissing_ReturnsFalse()
    {
        _container.ExistsAsync("missing", Arg.Any<CancellationToken>()).Returns(false);
        Assert.False(await Sut.ExistsAsync("missing"));
    }

    [Fact]
    public async Task ListAsync_DelegatesToContainerWithPrefixAndPagesResults()
    {
        var entries = new[]
        {
            new BlobInfo("prefix/a", 11, DateTimeOffset.UnixEpoch),
            new BlobInfo("prefix/b", 22, DateTimeOffset.UnixEpoch.AddMinutes(1)),
            new BlobInfo("prefix/c", 33, DateTimeOffset.UnixEpoch.AddMinutes(2)),
        };
        _container.EnumerateBlobsAsync("prefix/", Arg.Any<CancellationToken>())
            .Returns(AsyncBlobs(entries));

        var collected = new List<BlobInfo>();
        await foreach (var b in Sut.ListAsync("prefix/"))
            collected.Add(b);

        Assert.Equal(entries, collected);
        _container.Received(1).EnumerateBlobsAsync("prefix/", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ListAsync_EmptyPrefix_YieldsNothing()
    {
        _container.EnumerateBlobsAsync("empty/", Arg.Any<CancellationToken>())
            .Returns(AsyncBlobs());

        var any = false;
        await foreach (var _ in Sut.ListAsync("empty/")) any = true;
        Assert.False(any);
    }

    [Fact]
    public async Task PutAsync_PropagatesCancellationToken()
    {
        using var stream = new MemoryStream([1]);
        using var cts = new CancellationTokenSource();
        await Sut.PutAsync("k", stream, cts.Token);
        await _container.Received(1).UploadAsync("k", stream, cts.Token);
    }

    [Fact]
    public async Task GetAsync_PropagatesCancellationToken()
    {
        using var cts = new CancellationTokenSource();
        _container.DownloadOrNullAsync("k", cts.Token).Returns((Stream?)null);
        await Sut.GetAsync("k", cts.Token);
        await _container.Received(1).DownloadOrNullAsync("k", cts.Token);
    }

    [Fact]
    public async Task ExistsAsync_PropagatesCancellationToken()
    {
        using var cts = new CancellationTokenSource();
        _container.ExistsAsync("k", cts.Token).Returns(true);
        await Sut.ExistsAsync("k", cts.Token);
        await _container.Received(1).ExistsAsync("k", cts.Token);
    }

    [Fact]
    public async Task DeleteAsync_PropagatesCancellationToken()
    {
        using var cts = new CancellationTokenSource();
        await Sut.DeleteAsync("k", cts.Token);
        await _container.Received(1).DeleteIfExistsAsync("k", cts.Token);
    }

    [Fact]
    public async Task PutAsync_ContainerThrows_ExceptionPassesThrough()
    {
        using var stream = new MemoryStream([1]);
        _container.UploadAsync(Arg.Any<string>(), Arg.Any<Stream>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException(new InvalidOperationException("boom")));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Sut.PutAsync("k", stream));
        Assert.Equal("boom", ex.Message);
    }

    [Fact]
    public async Task GetTotalSizeAsync_PropagatesCancellationToken()
    {
        using var cts = new CancellationTokenSource();
        _container.EnumerateSizesAsync(cts.Token).Returns(AsyncEnum(5, 7));
        Assert.Equal(12, await Sut.GetTotalSizeAsync(cts.Token));
        _container.Received(1).EnumerateSizesAsync(cts.Token);
    }

    // ── Production constructor: argument validation ─────────────────────────
    // The real-Azure constructor path (BlobContainerClient + CreateIfNotExists) is
    // exercised in compose-tests against Azurite — see compose/azurite/. These unit
    // tests cover the constructor's argument-validation surface only.

    [Fact]
    public void ProductionCtor_NullConnectionString_Throws()
    {
        // BlobContainerClient validates the connection string in its ctor; surfacing the
        // exception unwrapped is the documented behaviour — verify we don't accidentally
        // swallow it inside AzureBlobStore.
        Assert.ThrowsAny<ArgumentException>(
            () => new AzureBlobStore(connectionString: null!, containerName: "c"));
    }

    [Fact]
    public void ProductionCtor_NullContainerName_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(
            () => new AzureBlobStore(connectionString: "UseDevelopmentStorage=true", containerName: null!));
    }

    [Fact]
    public void ProductionCtor_MalformedConnectionString_Throws()
    {
        // A connection string that doesn't even tokenize — Azure SDK throws FormatException
        // (derived from SystemException). Verify the failure surfaces; covers the
        // BlobContainerClient construction line on the production constructor.
        Assert.ThrowsAny<Exception>(
            () => new AzureBlobStore(connectionString: "not-a-real-connection-string", containerName: "c"));
    }

    private static async IAsyncEnumerable<long> AsyncEnum(params long[] values)
    {
        foreach (var v in values) { await Task.Yield(); yield return v; }
    }

    private static async IAsyncEnumerable<BlobInfo> AsyncBlobs(params BlobInfo[] values)
    {
        foreach (var v in values) { await Task.Yield(); yield return v; }
    }
}
