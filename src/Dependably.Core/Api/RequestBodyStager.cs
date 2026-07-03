using Dependably.Protocol;

namespace Dependably.Api;

// Staging file names are "publish-stage-{server-GUID}.tmp" under the operator-configured staging
// root; the request-body stream reaches the file CONTENT, never the file NAME. SCS's
// interprocedural taint from Request.Body into the constructed path is a false positive.
#pragma warning disable SCS0018

/// <summary>
/// Streams a raw request body to a staging temp file under the operator-configured staging
/// root, computing digests inline, and enforces a byte cap DURING the read so an oversize body
/// is rejected before any blob is written. Used by the RPM and Maven hosted-publish paths,
/// which take the artifact as the raw <c>Request.Body</c> (not a multipart form), mirroring the
/// memory-bounded pattern the PyPI/npm/NuGet publish handlers already use.
/// </summary>
internal static class RequestBodyStager
{
    /// <summary>Result of staging a request body to disk: the temp path, byte count, and digests.
    /// <see cref="Sha1"/> / <see cref="Md5"/> are populated only when the caller requested the
    /// Maven sidecar digests.</summary>
    internal sealed record StagedBody(string Path, long Size, string Sha256, string? Sha1, string? Md5);

    /// <summary>
    /// Streams <paramref name="source"/> to a fresh staging file, computing SHA-256 inline
    /// (plus SHA-1/MD5 when <paramref name="withMavenDigests"/> is set). The read is wrapped in a
    /// <see cref="LimitedReadStream"/> at <paramref name="cap"/> so a body larger than the cap
    /// throws <see cref="InvalidDataException"/> before the file is fully written and before any
    /// blob store call — the caller maps that to a 413. The partial temp file is deleted on any
    /// failure; on success the caller owns deletion via <see cref="TryDelete"/>.
    /// </summary>
    internal static async Task<StagedBody> StageAsync(
        Stream source, string stagingRoot, long cap, bool withMavenDigests, CancellationToken ct)
    {
        // deepcode ignore PT: staging file name is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        string tempPath = Path.Combine(stagingRoot, $"publish-stage-{Guid.NewGuid():N}.tmp");
        bool ok = false;
        try
        {
            long size;
            string sha256;
            string? sha1;
            string? md5;
            var fileStream = new FileStream(
                tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 81920, useAsync: true);
            await using (var staging = new HashingFileStream(fileStream, long.MaxValue, withMavenDigests))
            await using (var limited = new LimitedReadStream(source, cap, "upload body"))
            {
                await limited.CopyToAsync(staging, ct);
                size = staging.BytesWritten;
                sha256 = staging.GetSha256Hex();
                sha1 = withMavenDigests ? staging.GetSha1Hex() : null;
                md5 = withMavenDigests ? staging.GetMd5Hex() : null;
            }
            ok = true;
            return new StagedBody(tempPath, size, sha256, sha1, md5);
        }
        finally
        {
            if (!ok)
            {
                TryDelete(tempPath);
            }
        }
    }

    /// <summary>Best-effort deletion of a staging temp file; a leaked file under the staging root
    /// is operator-visible and swept on restart.</summary>
    internal static void TryDelete(string? path)
    {
        if (path is null)
        {
            return;
        }
        try
        {
            if (File.Exists(path))
            {
                // deepcode ignore PT: path is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
                File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup only.
        }
    }
}
