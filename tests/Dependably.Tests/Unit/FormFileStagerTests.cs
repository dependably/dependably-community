using Dependably.Api;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit;

/// <summary>
/// <see cref="FormFileStager"/> is the shared cap-enforcement seam PyPI and NuGet publish now
/// route their multipart file through (mirroring <c>RequestBodyStager</c> for the raw-body
/// ecosystems and <c>NpmPublishBodyParser</c> for npm). These tests pin the core security
/// property the API4:2023 fix depends on: the source is read under a
/// <see cref="LimitedReadStream"/> cap that aborts the copy mid-stream — the write itself is
/// bounded — rather than staging the full artifact and only checking its size afterward.
///
/// <see cref="CountingFormFile"/> tracks exactly how many bytes were pulled from the source
/// stream so the oversize case can assert the read stopped far short of the full body, not just
/// that the response eventually mapped to a 413.
/// </summary>
[Trait("Category", "Unit")]
public sealed class FormFileStagerTests : IDisposable
{
    private readonly string _staging = Path.Combine(Path.GetTempPath(), $"dependably-formfilestage-{Guid.NewGuid():N}");

    public FormFileStagerTests() => Directory.CreateDirectory(_staging);

    public void Dispose()
    {
        try { Directory.Delete(_staging, recursive: true); } catch { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task StageAsync_UnderCap_WritesFullFileAndReturnsExactSize()
    {
        byte[] content = new byte[50_000];
        Random.Shared.NextBytes(content);
        var file = new CountingFormFile(content);

        var staged = await FormFileStager.StageAsync(file, _staging, cap: 500_000, CancellationToken.None);

        Assert.Equal(content.LongLength, staged.Size);
        Assert.Equal(content, await File.ReadAllBytesAsync(staged.Path));
        Assert.Equal(content.LongLength, file.BytesRead);
        File.Delete(staged.Path);
    }

    /// <summary>
    /// The regression case for the API4:2023 unbounded-resource-consumption fix: with a cap far
    /// below the file size, the copy must throw before the source is fully drained. Before the
    /// fix, PyPI/NuGet staging had no cap parameter at all — the source was always read to
    /// completion (<c>BytesRead == content.Length</c>) and the size limit was only checked after
    /// the full artifact was already on disk. Asserting <c>BytesRead</c> is bounded to a small
    /// multiple of the copy buffer size — not the full 2 MiB body — is what a reverted (uncapped)
    /// copy cannot satisfy: an unbounded <c>CopyToAsync</c> always drains the entire source.
    /// </summary>
    [Fact]
    public async Task StageAsync_OverCap_ThrowsBeforeDrainingSource_AndLeavesNoStagingFile()
    {
        byte[] content = new byte[2 * 1024 * 1024]; // 2 MiB — far larger than the cap below.
        Random.Shared.NextBytes(content);
        var file = new CountingFormFile(content);

        const long cap = 1024;
        await Assert.ThrowsAsync<InvalidDataException>(
            () => FormFileStager.StageAsync(file, _staging, cap, CancellationToken.None));

        // The copy aborts within (at most) a couple of internal buffer chunks past the cap —
        // nowhere near the full 2 MiB body the old, uncapped copy always fully drained.
        Assert.True(file.BytesRead < 200_000,
            $"Expected the capped copy to abort after a small multiple of the cap; " +
            $"actually read {file.BytesRead} of {content.Length} bytes from the source.");

        // The partial temp file is cleaned up by FormFileStager itself on failure.
        Assert.Empty(Directory.GetFiles(_staging, "publish-stage-*.tmp"));
    }

    [Fact]
    public async Task StageAsync_ExactlyAtCap_Succeeds()
    {
        byte[] content = new byte[4096];
        Random.Shared.NextBytes(content);
        var file = new CountingFormFile(content);

        var staged = await FormFileStager.StageAsync(file, _staging, cap: 4096, CancellationToken.None);

        Assert.Equal(4096, staged.Size);
        File.Delete(staged.Path);
    }

    /// <summary>
    /// Mixed partial-failure (house rule): sequential stages of the same underlying method —
    /// under cap (succeeds), over cap (413-mapped exception, no leak), under cap again (succeeds)
    /// — proving the cap failure on one call never corrupts staging for the next.
    /// </summary>
    [Fact]
    public async Task StageAsync_MixedPartialFailure_EachCallIndependentlyCleansUp()
    {
        byte[] small = new byte[1000];
        Random.Shared.NextBytes(small);

        var staged1 = await FormFileStager.StageAsync(new CountingFormFile(small), _staging, cap: 500_000, CancellationToken.None);
        Assert.Equal(1000, staged1.Size);
        File.Delete(staged1.Path);
        Assert.Empty(Directory.GetFiles(_staging, "publish-stage-*.tmp"));

        byte[] big = new byte[500_000];
        Random.Shared.NextBytes(big);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => FormFileStager.StageAsync(new CountingFormFile(big), _staging, cap: 1000, CancellationToken.None));
        Assert.Empty(Directory.GetFiles(_staging, "publish-stage-*.tmp"));

        var staged3 = await FormFileStager.StageAsync(new CountingFormFile(small), _staging, cap: 500_000, CancellationToken.None);
        Assert.Equal(1000, staged3.Size);
        File.Delete(staged3.Path);
        Assert.Empty(Directory.GetFiles(_staging, "publish-stage-*.tmp"));
    }

    /// <summary>
    /// Minimal <see cref="IFormFile"/> test double over an in-memory byte array. Only
    /// <see cref="OpenReadStream"/> is exercised by <see cref="FormFileStager"/>; the returned
    /// stream tracks every byte actually pulled from the source so tests can assert a capped copy
    /// stopped reading early instead of draining the whole backing array.
    /// </summary>
    private sealed class CountingFormFile(byte[] content) : IFormFile
    {
        public long BytesRead { get; private set; }

        public string ContentType { get; set; } = "application/octet-stream";
        public string ContentDisposition { get; set; } = string.Empty;
        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();
        public long Length => content.Length;
        public string Name => "content";
        public string FileName => "test.bin";

        public void CopyTo(Stream target) => throw new NotSupportedException();
        public Task CopyToAsync(Stream target, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Stream OpenReadStream() => new CountingStream(new MemoryStream(content), this);

        private sealed class CountingStream(Stream inner, CountingFormFile owner) : Stream
        {
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush()
            {
                // Read-only stream: nothing to flush.
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                int n = inner.Read(buffer, offset, count);
                owner.BytesRead += n;
                return n;
            }

            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                int n = await inner.ReadAsync(buffer, cancellationToken);
                owner.BytesRead += n;
                return n;
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    inner.Dispose();
                }
                base.Dispose(disposing);
            }
        }
    }
}
