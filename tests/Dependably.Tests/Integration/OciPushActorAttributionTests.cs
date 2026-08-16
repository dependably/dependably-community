using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end proof that an OCI push made with a live, unexpired service token names its actor
/// in the audit feed.
///
/// <para>OCI push does not route through <c>PublishAuditor</c> — <c>OciController.Manifests</c>
/// writes its own <c>"push"</c> activity row — so the publish-path fix did not reach it. Every
/// such site paired <c>token.UserId</c> (always NULL for a service token, because
/// <c>TokenRepository.ResolveAsync</c> selects <c>NULL AS user_id</c> for that branch) with
/// <c>token.ActorKind</c> of <c>'service'</c>. The list query resolves a service actor through
/// <c>LEFT JOIN service_tokens ON st.id = a.actor_id</c>, which cannot match a NULL, so the row
/// rendered as anonymous.</para>
///
/// <para>This drives the real HTTP push path rather than calling the audit writer directly,
/// because the defect lived in what the controller <em>passed</em>, not in what the repository
/// did with it — a test that supplies <c>actor_id</c> itself reproduces nothing. The token here
/// is created and never revoked: this is the active-token case, not the revoked-token one.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciPushActorAttributionTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Repo = "team/attribution";
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private readonly DependablyFactory _factory;

    public OciPushActorAttributionTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Push_WithActiveServiceToken_NamesTheTokenAsTheActor()
    {
        string raw = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(raw);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        // The token is live: CreateToken inserts it and nothing revokes it here.
        var (tokenId, tokenName) = await conn.QuerySingleAsync<(string Id, string Name)>(
            "SELECT id, name FROM service_tokens ORDER BY created_at DESC LIMIT 1");

        string digest = await PushImageAsync(client, "1.0.0");

        // Activity rows go through the async batching writer — drain before asserting.
        await _factory.Services.GetRequiredService<ActivityWriterHostedService>().WaitForIdleAsync();

        var audit = _factory.Services.GetRequiredService<AuditRepository>();
        string orgId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;

        var (items, _, _) = await audit.ListActivityAsync(orgId, limit: 50, offset: 0, eventType: "push");
        var row = Assert.Single(items, i => i.Purl == $"pkg:oci/{Repo}@{digest}");

        Assert.Equal(tokenId, row.ActorId);
        Assert.Equal(ActorKinds.Service, await ActorKindOfAsync(conn, row.Id));
        // What the audit UI actually renders. Before the fix this was NULL and the page showed
        // "anonymous"; the assertion is on the resolved label, not merely on a non-null id.
        Assert.Equal($"service:{tokenName}", row.ActorEmail);
    }

    /// <summary>
    /// The adversarial twin. A push must never acquire an actor it did not have — if this ever
    /// passes for an anonymous request, the fix has started fabricating attribution, which is
    /// worse than the bug it replaced.
    /// </summary>
    [Fact]
    public async Task AnonymousActivityRow_DoesNotAcquireAFabricatedActor()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;

        var audit = _factory.Services.GetRequiredService<AuditRepository>();
        await audit.LogActivityAsync(orgId, "oci", "pkg:oci/anon@sha256:deadbeef", "anon_probe",
            actorId: null, actorKind: null);
        await _factory.Services.GetRequiredService<ActivityWriterHostedService>().WaitForIdleAsync();

        var (items, _, _) = await audit.ListActivityAsync(orgId, limit: 50, offset: 0, eventType: "anon_probe");
        var row = Assert.Single(items);
        Assert.Null(row.ActorId);
        Assert.Null(row.ActorEmail);
    }


    /// <summary>
    /// The denormalized label is what keeps a forensic row readable once the row it would
    /// otherwise join to is gone. service_tokens is hard-deleted on revocation
    /// (<c>TokenRepository.RevokeServiceTokenAsync</c> — <c>DELETE FROM service_tokens</c>), and
    /// audit rows carry no FK, so without the stored name the join silently stops resolving and
    /// the push reverts to reading as anonymous — at exactly the moment an operator is asking who
    /// used the credential.
    /// </summary>
    [Fact]
    public async Task PushedRow_StillNamesTheTokenAfterItIsRevoked()
    {
        string raw = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(raw);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var (tokenId, tokenName) = await conn.QuerySingleAsync<(string Id, string Name)>(
            "SELECT id, name FROM service_tokens ORDER BY created_at DESC LIMIT 1");

        string digest = await PushImageAsync(client, "2.0.0");
        await _factory.Services.GetRequiredService<ActivityWriterHostedService>().WaitForIdleAsync();

        // Hard-delete the token, exactly as revocation does.
        await conn.ExecuteAsync("DELETE FROM service_tokens WHERE id = @tokenId", new { tokenId });

        string orgId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
        var audit = _factory.Services.GetRequiredService<AuditRepository>();
        var (items, _, _) = await audit.ListActivityAsync(orgId, limit: 50, offset: 0, eventType: "push");
        var row = Assert.Single(items, i => i.Purl == $"pkg:oci/{Repo}@{digest}");

        // The join can no longer resolve anything; the stored label is the only remaining source.
        Assert.Equal($"service:{tokenName}", row.ActorEmail);
    }

    private static async Task<string?> ActorKindOfAsync(System.Data.Common.DbConnection conn, string activityId)
        => await conn.ExecuteScalarAsync<string?>(
            "SELECT actor_kind FROM activity WHERE id = @activityId", new { activityId });

    private static async Task<string> PushImageAsync(HttpClient client, string tag)
    {
        byte[] config = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        byte[] layer = RandomBytes(1024);
        string configDigest = Digest(config);
        string layerDigest = Digest(layer);

        await PushBlobAsync(client, config, configDigest);
        await PushBlobAsync(client, layer, layerDigest);

        byte[] manifest = Encoding.UTF8.GetBytes(
            $$"""
            {"schemaVersion":2,"mediaType":"{{ManifestMediaType}}",
             "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{{configDigest}}","size":{{config.Length}}},
             "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{{layerDigest}}","size":{{layer.Length}}}]}
            """);

        using var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(ManifestMediaType);
        using var response = await client.PutAsync($"/v2/{Repo}/manifests/{tag}", content);
        response.EnsureSuccessStatusCode();
        return Assert.Single(response.Headers.GetValues("Docker-Content-Digest"));
    }

    private static async Task PushBlobAsync(HttpClient client, byte[] bytes, string digest)
    {
        using var start = await client.PostAsync($"/v2/{Repo}/blobs/uploads/", null);
        start.EnsureSuccessStatusCode();
        string location = start.Headers.Location!.ToString();
        string sep = location.Contains('?', StringComparison.Ordinal) ? "&" : "?";

        using var body = new ByteArrayContent(bytes);
        body.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var done = await client.PutAsync($"{location}{sep}digest={digest}", body);
        done.EnsureSuccessStatusCode();
    }

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}
