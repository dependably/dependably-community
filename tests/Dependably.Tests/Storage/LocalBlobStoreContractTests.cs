using Dependably.Storage;

namespace Dependably.Tests.Storage;

public sealed class LocalBlobStoreContractTests : BlobStoreContractTests
{
    protected override IBlobStore CreateStore()
    {
        string path = Path.Combine(Path.GetTempPath(), "dependably-test-blobs", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return new LocalBlobStore(path);
    }
}
