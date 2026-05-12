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

    private static async IAsyncEnumerable<long> AsyncEnum(params long[] values)
    {
        foreach (var v in values) { await Task.Yield(); yield return v; }
    }
}
