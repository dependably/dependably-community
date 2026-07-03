using Microsoft.AspNetCore.Http;

namespace Dependably.Security;

/// <summary>
/// Shared <c>If-None-Match</c> check for the artifact-blob serve paths (npm tarball, PyPI
/// package, Maven artifact, RPM package). Mirrors the strong-ETag exact-match comparison
/// already used by the metadata handlers (npm packument, Maven metadata, PyPI simple index,
/// NuGet registration, Cargo index) — a plain quoted-string equality against the single
/// <c>If-None-Match</c> value every client here sends. No weak-tag (<c>W/</c>) or
/// comma-separated multi-value parsing: none of these protocol clients (npm, pip, Maven,
/// dnf/yum) send either form.
/// </summary>
public static class ConditionalRequestHelper
{
    /// <summary>
    /// True when the request's <c>If-None-Match</c> header value exactly matches
    /// <paramref name="etag"/> (a quoted strong ETag, e.g. <c>"sha256:&lt;hex&gt;"</c>).
    /// Callers check this before opening the blob stream, so a client that already has the
    /// current bytes gets a <c>304</c> without a store read.
    /// </summary>
    public static bool IfNoneMatchHits(IHeaderDictionary requestHeaders, string etag)
        => requestHeaders.IfNoneMatch.FirstOrDefault() == etag;
}
