namespace Dependably.Storage;

public static class BlobStoreSizeExtensions
{
    /// <summary>
    /// The byte length of a just-staged blob, for a serve path that must record it on the cache
    /// plane. A seekable stream (a local file) reports its own length; an object-store response
    /// stream does not, so the store is asked for one listing of the exact key. Returns 0 when the
    /// store does not list the key, which the recorder treats as "not measured".
    /// </summary>
    public static async Task<long> GetStagedSizeAsync(
        this IBlobStore store, Stream staged, string storeKey, CancellationToken ct = default)
        => staged.CanSeek ? staged.Length : await store.GetStoredSizeAsync(storeKey, ct);

    /// <summary>
    /// The byte length of the object stored at exactly <paramref name="storeKey"/>, from one
    /// listing of that key as a prefix; 0 when the store does not list it.
    /// </summary>
    public static async Task<long> GetStoredSizeAsync(this IBlobStore store, string storeKey, CancellationToken ct = default)
    {
        await foreach (var blob in store.ListAsync(storeKey, ct))
        {
            if (blob.Key == storeKey)
            {
                return blob.SizeBytes;
            }
        }

        return 0;
    }
}
