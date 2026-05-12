namespace Dependably.Storage;

public interface IBlobStore
{
    Task PutAsync(string key, Stream data, CancellationToken ct = default);
    Task<Stream?> GetAsync(string key, CancellationToken ct = default);
    Task<bool> ExistsAsync(string key, CancellationToken ct = default);
    Task DeleteAsync(string key, CancellationToken ct = default);
    Task<long> GetTotalSizeAsync(CancellationToken ct = default);
}
