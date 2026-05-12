using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Compliance;

/// <summary>
/// OpenAPI contract gate. Fetches /api/v1/openapi.json from an in-memory host,
/// projects it into a normalized contract model, and compares it to
/// tests/Contracts/openapi.contract.json.
///
/// Any change to the API surface (added, removed, or modified routes/params/responses)
/// requires a conscious update to openapi.contract.json. If the test fails, paste
/// the JSON from the failure message into that file.
/// </summary>
[Trait("Category", "ApiContract")]
public sealed class ApiContractTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public ApiContractTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task OpenApi_Loads()
    {
        using var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/v1/openapi.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(content);
        Assert.True(doc.RootElement.TryGetProperty("paths", out var paths));
        Assert.True(paths.EnumerateObject().Any(), "OpenAPI paths must not be empty");
    }

    [Fact]
    public async Task OpenApi_MatchesContract()
    {
        using var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/v1/openapi.json");
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        var current = ContractProjector.Project(json);
        var currentJson = ContractProjector.Serialize(current);

        var contractPath = LocateContract();

        if (!File.Exists(contractPath))
            Assert.Fail(
                $"tests/Contracts/openapi.contract.json not found. Create it with:\n\n{currentJson}\n");

        var committed = File.ReadAllText(contractPath).ReplaceLineEndings("\n").TrimEnd();
        var normalized = currentJson.ReplaceLineEndings("\n").TrimEnd();

        Assert.True(normalized == committed,
            $"API contract is out of date. Replace tests/Contracts/openapi.contract.json with:\n\n{currentJson}\n");
    }

    private static string LocateContract()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Dependably.sln")))
            dir = dir.Parent;
        if (dir is null)
            throw new InvalidOperationException("Could not locate Dependably.sln from test base directory.");
        return Path.Combine(dir.FullName, "tests", "Contracts", "openapi.contract.json");
    }
}

internal sealed record ContractOperation(List<string> RequiredParams, List<string> ResponseCodes);
internal sealed record ContractPath(SortedDictionary<string, ContractOperation> Operations);
internal sealed record ApiContract(string Version, SortedDictionary<string, ContractPath> Paths);

internal static class ContractProjector
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    internal static string Serialize(ApiContract contract) =>
        JsonSerializer.Serialize(contract, SerializerOptions);

    internal static ApiContract Project(string openApiJson)
    {
        var paths = new SortedDictionary<string, ContractPath>(StringComparer.Ordinal);

        using var doc = JsonDocument.Parse(openApiJson);
        if (!doc.RootElement.TryGetProperty("paths", out var pathsEl))
            return new ApiContract("1", paths);

        foreach (var pathProp in pathsEl.EnumerateObject())
        {
            var operations = new SortedDictionary<string, ContractOperation>(StringComparer.Ordinal);

            foreach (var opProp in pathProp.Value.EnumerateObject())
            {
                // Skip non-operation keys like "parameters" or "summary" at path level
                var httpMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "get", "post", "put", "delete", "patch", "head", "options", "trace" };
                if (!httpMethods.Contains(opProp.Name))
                    continue;

                var requiredParams = new List<string>();
                if (opProp.Value.TryGetProperty("parameters", out var paramsEl))
                {
                    foreach (var param in paramsEl.EnumerateArray())
                    {
                        var isRequired = param.TryGetProperty("required", out var req) && req.GetBoolean();
                        if (isRequired && param.TryGetProperty("name", out var name))
                            requiredParams.Add(name.GetString() ?? "");
                    }
                    requiredParams.Sort(StringComparer.Ordinal);
                }

                var responseCodes = new List<string>();
                if (opProp.Value.TryGetProperty("responses", out var responsesEl))
                {
                    responseCodes = responsesEl.EnumerateObject()
                        .Select(r => r.Name)
                        .OrderBy(k => k, StringComparer.Ordinal)
                        .ToList();
                }

                operations[opProp.Name.ToLowerInvariant()] =
                    new ContractOperation(requiredParams, responseCodes);
            }

            if (operations.Count > 0)
                paths[pathProp.Name] = new ContractPath(operations);
        }

        return new ApiContract("1", paths);
    }
}
