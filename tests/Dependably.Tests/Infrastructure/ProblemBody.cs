using System.Net;
using System.Text.Json;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Reads and asserts the RFC 9457 problem body the management API returns for a refusal, so a
/// test pins the status code and the offending field together instead of the status alone.
/// </summary>
internal static class ProblemBody
{
    public static async Task<JsonElement> ReadAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    /// <summary>Asserts a 422 validation problem that names <paramref name="field"/>.</summary>
    public static async Task AssertValidationAsync(HttpResponseMessage response, string field)
    {
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        var body = await ReadAsync(response);
        Assert.Equal(field, body.GetProperty("field").GetString());
    }

    /// <summary>Asserts a 403 problem (capability denial) with a JSON problem body.</summary>
    public static async Task AssertForbiddenAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await ReadAsync(response);
        Assert.Equal(403, body.GetProperty("status").GetInt32());
    }
}
