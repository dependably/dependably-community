using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Reading a blob to learn whether it is a manifest stops as soon as the leading bytes or the
/// size say it is not, so a layer is not pulled into memory just to be discarded.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciManifestCandidateReadTests
{
    [Fact]
    public async Task ANonJsonBlob_IsAbandonedAfterItsFirstChunk()
    {
        await using var layer = new CountingStream(new byte[3 * 1024 * 1024]);

        var candidate = await OciManifestParser.ReadManifestCandidateAsync(layer, default);

        Assert.Null(candidate);
        Assert.True(layer.BytesRead <= 81920, $"read {layer.BytesRead} bytes of a blob that cannot be a manifest");
    }

    [Fact]
    public async Task AnOversizedBlob_IsAbandonedOnceItPassesTheCap()
    {
        byte[] bytes = new byte[(int)OciManifestParser.ManifestSniffMaxBytes + 4096];
        bytes[0] = (byte)'{';
        await using var big = new CountingStream(bytes);

        var candidate = await OciManifestParser.ReadManifestCandidateAsync(big, default);

        Assert.Null(candidate);
        Assert.True(big.BytesRead <= OciManifestParser.ManifestSniffMaxBytes + 81920);
    }

    [Theory]
    [InlineData("{\"schemaVersion\":2}")]
    [InlineData("  \r\n\t{\"schemaVersion\":2}")]
    public async Task ABlobOpeningAnObject_IsReturnedWhole(string json)
    {
        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));

        using var candidate = await OciManifestParser.ReadManifestCandidateAsync(stream, default);

        Assert.NotNull(candidate);
        Assert.Equal(json, Encoding.UTF8.GetString(candidate.ToArray()));
        Assert.Equal(0, candidate.Position);
    }

    [Fact]
    public async Task ABlobOpeningAnObjectAfterABom_IsReturnedWhole()
    {
        byte[] bytes = [0xEF, 0xBB, 0xBF, (byte)'{', (byte)'}'];
        await using var stream = new MemoryStream(bytes);

        using var candidate = await OciManifestParser.ReadManifestCandidateAsync(stream, default);

        Assert.NotNull(candidate);
    }

    [Theory]
    [InlineData("[1,2]")]
    [InlineData("  \"text\"")]
    [InlineData("PK\u0003\u0004")]
    public async Task ABlobNotOpeningAnObject_IsNotACandidate(string text)
    {
        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes(text));

        Assert.Null(await OciManifestParser.ReadManifestCandidateAsync(stream, default));
    }

    private sealed class CountingStream(byte[] bytes) : MemoryStream(bytes)
    {
        public long BytesRead { get; private set; }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int read = await base.ReadAsync(buffer, cancellationToken);
            BytesRead += read;
            return read;
        }
    }
}
