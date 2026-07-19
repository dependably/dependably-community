using Dependably.Protocol;
using Microsoft.AspNetCore.Http;

namespace Dependably.Api;

// Staging file names are "publish-stage-{server-GUID}.tmp" under the operator-configured staging
// root; the source stream reaches the file CONTENT, never the file NAME. SCS's interprocedural
// taint from the form-file source into the constructed path is a false positive.
#pragma warning disable SCS0018

/// <summary>
/// Streams an <see cref="IFormFile"/> (the shape twine/nuget.exe post as a multipart section) to
/// a staging temp file under the operator-configured staging root, computing SHA-256 inline via
/// <see cref="HashingFileStream"/>, and enforces a byte cap DURING the copy via
/// <see cref="LimitedReadStream"/> so an oversize file is rejected with
/// <see cref="InvalidDataException"/> before it is ever fully written to disk. Mirrors
/// <see cref="RequestBodyStager"/> (used by the RPM/Maven raw-body publish paths) for the two
/// hosted-publish ecosystems (PyPI, NuGet) whose upload arrives as a multipart form file instead
/// of a raw request body.
/// </summary>
internal static class FormFileStager
{
    /// <summary>Result of staging a form file to disk: the temp path and byte count.</summary>
    internal sealed record StagedFile(string Path, long Size);

    /// <summary>
    /// Streams <paramref name="file"/> to a fresh staging file under <paramref name="stagingRoot"/>.
    /// The read is wrapped in a <see cref="LimitedReadStream"/> at <paramref name="cap"/> so a file
    /// larger than the cap throws <see cref="InvalidDataException"/> before the file is fully
    /// written — the caller maps that to a 413. The partial temp file is deleted on any failure;
    /// on success the caller owns deletion via <see cref="RequestBodyStager.TryDelete"/>.
    /// </summary>
    internal static async Task<StagedFile> StageAsync(
        IFormFile file, string stagingRoot, long cap, CancellationToken ct)
    {
        // staging file name is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        string tempPath = Path.Combine(stagingRoot, $"publish-stage-{Guid.NewGuid():N}.tmp");
        bool ok = false;
        try
        {
            var fileStream = new FileStream(
                tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 81920, useAsync: true);
            await using (var staging = new HashingFileStream(fileStream, long.MaxValue))
            await using (var limited = new LimitedReadStream(file.OpenReadStream(), cap, "upload body"))
            {
                await limited.CopyToAsync(staging, ct);
            }
            long size = new FileInfo(tempPath).Length;
            ok = true;
            return new StagedFile(tempPath, size);
        }
        finally
        {
            if (!ok)
            {
                RequestBodyStager.TryDelete(tempPath);
            }
        }
    }
}
