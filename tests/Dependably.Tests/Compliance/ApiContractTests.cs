using System.Linq;
using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Compliance;

/// <summary>
/// OpenAPI contract gate. Fetches both /openapi/management.json and
/// /openapi/protocol.json from an in-memory host, merges them, projects the
/// union into a normalized contract model, and compares it to
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
    public async Task OpenApi_OptionalProxySettingsFields_RenderAsPlainNullableScalars()
    {
        // UpdateProxySettingsRequest.MinReleaseAgeHours/MaxEpssTolerance are Optional<T> (see
        // Optional<T> and OptionalSchemaTransformer). The exporter can't reflect through the
        // type's JsonConverterFactory, so without OptionalSchemaTransformer these would render
        // as an opaque/empty schema rather than as "an integer or number, possibly null" the way
        // every other optional field in this document does — a real regression for anyone
        // generating a client from this document, not just a cosmetic one.
        string token = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync("/openapi/management.json");
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStreamAsync());
        var schemas = doc.RootElement.GetProperty("components").GetProperty("schemas");

        AssertPlainNullableScalar(schemas, "OptionalOfint", "integer");
        AssertPlainNullableScalar(schemas, "OptionalOfdouble", "number");

        static void AssertPlainNullableScalar(JsonElement schemas, string schemaName, string expectedType)
        {
            Assert.True(schemas.TryGetProperty(schemaName, out var schema),
                $"Expected a component schema named '{schemaName}' for Optional<T>'s rewritten shape.");
            Assert.False(schema.TryGetProperty("properties", out _),
                $"'{schemaName}' must not expose Optional<T>'s IsPresent/Value struct shape.");
            Assert.True(schema.TryGetProperty("type", out var type));
            string?[] types = type.EnumerateArray().Select(t => t.GetString()).ToArray();
            Assert.Contains(expectedType, types);
            Assert.Contains("null", types);
        }
    }

    [Fact]
    public async Task OpenApi_Loads()
    {
        // The management document requires an authenticated management session in addition to
        // the metrics IP allowlist (loopback, which the in-memory TestServer satisfies).
        string token = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(token);

        var managementResp = await client.GetAsync("/openapi/management.json");
        Assert.Equal(HttpStatusCode.OK, managementResp.StatusCode);
        var managementDoc = JsonDocument.Parse(await managementResp.Content.ReadAsStringAsync());
        Assert.True(managementDoc.RootElement.TryGetProperty("paths", out var managementPaths));
        Assert.True(managementPaths.EnumerateObject().Any(),
            "Management OpenAPI paths must not be empty");

        var protocolResp = await client.GetAsync("/openapi/protocol.json");
        Assert.Equal(HttpStatusCode.OK, protocolResp.StatusCode);
        var protocolDoc = JsonDocument.Parse(await protocolResp.Content.ReadAsStringAsync());
        Assert.True(protocolDoc.RootElement.TryGetProperty("paths", out var protocolPaths));
        Assert.True(protocolPaths.EnumerateObject().Any(),
            "Protocol OpenAPI paths must not be empty");
    }

    [Fact]
    public async Task OpenApi_MatchesContract()
    {
        // The management document requires an authenticated management session in addition to
        // the metrics IP allowlist (loopback, which the in-memory TestServer satisfies).
        string token = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(token);

        var managementResp = await client.GetAsync("/openapi/management.json");
        managementResp.EnsureSuccessStatusCode();
        string managementJson = await managementResp.Content.ReadAsStringAsync();

        var protocolResp = await client.GetAsync("/openapi/protocol.json");
        protocolResp.EnsureSuccessStatusCode();
        string protocolJson = await protocolResp.Content.ReadAsStringAsync();

        var current = ContractProjector.ProjectMerged(managementJson, protocolJson);
        string currentJson = ContractProjector.Serialize(current);

        string contractPath = LocateContract();

        // Escape hatch: set UPDATE_API_CONTRACT=1 to overwrite the
        // committed contract instead of asserting. Use sparingly — the
        // assert path is what catches accidental surface changes in CI.
        if (Environment.GetEnvironmentVariable("UPDATE_API_CONTRACT") == "1")
        {
            File.WriteAllText(contractPath, currentJson);
            return;
        }

        if (!File.Exists(contractPath))
        {
            Assert.Fail(
                $"tests/Contracts/openapi.contract.json not found. Create it with:\n\n{currentJson}\n");
        }

        string committed = File.ReadAllText(contractPath).ReplaceLineEndings("\n").TrimEnd();
        string normalized = currentJson.ReplaceLineEndings("\n").TrimEnd();

        Assert.True(normalized == committed,
            $"API contract is out of date. Replace tests/Contracts/openapi.contract.json with:\n\n{currentJson}\n");
    }

    private static string LocateContract()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Dependably.sln")))
        {
            dir = dir.Parent;
        }

        return dir is null
            ? throw new InvalidOperationException("Could not locate Dependably.sln from test base directory.")
            : Path.Combine(dir.FullName, "tests", "Contracts", "openapi.contract.json");
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

    /// <summary>
    /// Projects both OpenAPI documents and merges them into a single contract.
    /// The named-document split (management vs protocol) is an UI/spec presentation
    /// concern; the contract gate cares about the union of the published surface.
    /// </summary>
    internal static ApiContract ProjectMerged(string managementJson, string protocolJson)
    {
        var management = Project(managementJson);
        var protocol = Project(protocolJson);

        var merged = new SortedDictionary<string, ContractPath>(StringComparer.Ordinal);
        foreach (var (k, v) in management.Paths)
        {
            merged[k] = v;
        }

        foreach (var (k, v) in protocol.Paths)
        {
            // The two documents must be path-disjoint by construction (see
            // OpenApiSplitTests.ManagementAndProtocol_AreSetDisjoint). Detect a regression
            // here loudly rather than silently letting one document overwrite the other.
            if (merged.ContainsKey(k))
            {
                throw new InvalidOperationException(
                    $"OpenAPI split regression: path '{k}' present in both management and protocol documents.");
            }

            merged[k] = v;
        }

        return new ApiContract(management.Version, merged);
    }

    internal static ApiContract Project(string openApiJson)
    {
        var paths = new SortedDictionary<string, ContractPath>(StringComparer.Ordinal);

        using var doc = JsonDocument.Parse(openApiJson);
        if (!doc.RootElement.TryGetProperty("paths", out var pathsEl))
        {
            return new ApiContract("1", paths);
        }

        foreach (var pathProp in pathsEl.EnumerateObject())
        {
            var operations = new SortedDictionary<string, ContractOperation>(StringComparer.Ordinal);

            foreach (var opProp in pathProp.Value.EnumerateObject())
            {
                // Skip non-operation keys like "parameters" or "summary" at path level
                var httpMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "get", "post", "put", "delete", "patch", "head", "options", "trace" };
                if (!httpMethods.Contains(opProp.Name))
                {
                    continue;
                }

                var requiredParams = new List<string>();
                if (opProp.Value.TryGetProperty("parameters", out var paramsEl))
                {
                    foreach (var param in paramsEl.EnumerateArray())
                    {
                        bool isRequired = param.TryGetProperty("required", out var req) && req.GetBoolean();
                        if (isRequired && param.TryGetProperty("name", out var name))
                        {
                            requiredParams.Add(name.GetString() ?? "");
                        }
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
            {
                paths[pathProp.Name] = new ContractPath(operations);
            }
        }

        return new ApiContract("1", paths);
    }
}
