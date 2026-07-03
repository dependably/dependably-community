using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test helper for asserting on Maven serve results. The Maven proxy-MISS serve path streams the
/// cached blob straight to the response (<see cref="FileStreamResult"/>) rather than buffering it
/// into a <see cref="FileContentResult"/>, so tests read the served bytes through this shim which
/// accepts either shape and exposes the same field names the tests previously used.
/// </summary>
public static class MavenServe
{
    public readonly record struct FileFacts(byte[] FileContents, string ContentType, string? FileDownloadName);

    public static FileFacts File(IActionResult result) => result switch
    {
        FileContentResult fc => new(fc.FileContents, fc.ContentType, fc.FileDownloadName),
        FileStreamResult fs => new(ReadAll(fs.FileStream), fs.ContentType, fs.FileDownloadName),
        _ => throw new Xunit.Sdk.XunitException(
            $"Expected a file result, got {result?.GetType().Name ?? "null"}."),
    };

    private static byte[] ReadAll(Stream s)
    {
        using (s)
        {
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return ms.ToArray();
        }
    }
}
