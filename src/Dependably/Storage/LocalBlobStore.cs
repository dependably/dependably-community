namespace Dependably.Storage;

public sealed class LocalBlobStore : IBlobStore
{
    private readonly string _root;

    public LocalBlobStore(string root)
    {
        _root = root;
        Directory.CreateDirectory(root);
    }

    private string FullPath(string key) => Path.Combine(_root, key.Replace('/', Path.DirectorySeparatorChar));

    public async Task PutAsync(string key, Stream data, CancellationToken ct = default)
    {
        var path = FullPath(key);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await using var file = File.Create(path);
        await data.CopyToAsync(file, ct);
    }

    public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
    {
        var path = FullPath(key);
        if (!File.Exists(path))
            return Task.FromResult<Stream?>(null);
        return Task.FromResult<Stream?>(File.OpenRead(path));
    }

    public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        => Task.FromResult(File.Exists(FullPath(key)));

    public Task DeleteAsync(string key, CancellationToken ct = default)
    {
        var path = FullPath(key);
        if (File.Exists(path))
            File.Delete(path);
        return Task.CompletedTask;
    }

    public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
    {
        if (!Directory.Exists(_root))
            return Task.FromResult(0L);
        var total = new DirectoryInfo(_root)
            .EnumerateFiles("*", SearchOption.AllDirectories)
            .Sum(f => f.Length);
        return Task.FromResult(total);
    }
}
