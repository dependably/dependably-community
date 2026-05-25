using System.Runtime.CompilerServices;

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

    public async IAsyncEnumerable<BlobInfo> ListAsync(
        string prefix, [EnumeratorCancellation] CancellationToken ct = default)
    {
        // Resolve the prefix to its on-disk equivalent so a `hosted/` prefix scans only
        // the hosted subtree rather than walking the whole root and filtering after.
        var prefixPath = Path.Combine(_root, prefix.Replace('/', Path.DirectorySeparatorChar));
        if (!Directory.Exists(prefixPath))
            yield break;

        // Use enumerate-options to avoid materializing the full list before the first yield —
        // a hosted tier with millions of files would otherwise hold the whole listing in RAM.
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
        };
        foreach (var path in Directory.EnumerateFiles(prefixPath, "*", options))
        {
            if (ct.IsCancellationRequested) yield break;
            FileInfo info;
            try { info = new FileInfo(path); }
            catch { continue; }  // race: file deleted between enumerate and stat
            if (!info.Exists) continue;

            // Reconstruct the logical key (forward slashes, relative to root).
            var rel = Path.GetRelativePath(_root, path)
                .Replace(Path.DirectorySeparatorChar, '/');
            yield return new BlobInfo(rel, info.Length, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero));
            await Task.Yield();
        }
    }
}
