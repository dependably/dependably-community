using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;

namespace Dependably.Infrastructure;

/// <summary>
/// Wraps an <see cref="IFileProvider"/> and re-roots all lookups under a fixed sub-path.
/// Used by the Swagger UI mount so we can serve <c>wwwroot/swagger/*</c> from
/// <c>WebRootFileProvider</c> (which already understands both dev StaticWebAssets and the
/// published manifest) at request path <c>/api/v1/docs</c> without duplicating files.
/// </summary>
internal sealed class SubPathFileProvider : IFileProvider
{
    private readonly IFileProvider _inner;
    private readonly string _root;

    public SubPathFileProvider(IFileProvider inner, string subPath)
    {
        _inner = inner;
        _root = "/" + subPath.Trim('/');
    }

    public IDirectoryContents GetDirectoryContents(string subpath)
        => _inner.GetDirectoryContents(Combine(subpath));

    public IFileInfo GetFileInfo(string subpath)
        => _inner.GetFileInfo(Combine(subpath));

    public IChangeToken Watch(string filter)
        => _inner.Watch(Combine(filter));

    private string Combine(string subpath)
    {
        return string.IsNullOrEmpty(subpath) || subpath == "/" ? _root : _root + "/" + subpath.TrimStart('/');
    }
}
