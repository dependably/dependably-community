using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// A hermetic, protocol-correct OCI upstream for integration tests, answered through
/// <see cref="DependablyFactory.OciUpstreamHandler"/>: any number of images and image indexes in
/// one repository, mutable tags, and a switch that makes every request fail as an outage.
/// </summary>
public sealed class FakeOciRegistry
{
    public const string ImageManifestType = "application/vnd.oci.image.manifest.v1+json";
    public const string ImageIndexType = "application/vnd.oci.image.index.v1+json";

    private readonly string _repo;
    private readonly Dictionary<string, (byte[] Bytes, string MediaType)> _manifests = new(StringComparer.Ordinal);
    private readonly Dictionary<string, byte[]> _blobs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _blobTypes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _tags = new(StringComparer.Ordinal);
    private int _calls;

    public FakeOciRegistry(string repo) => _repo = repo;

    /// <summary>True makes every request answer 503, as an upstream outage.</summary>
    public bool Down { get; set; }

    /// <summary>When true, manifests are also answered on the blob route (some registries do).</summary>
    public bool ServeManifestsAsBlobs { get; set; }

    /// <summary>
    /// The media type a manifest is labelled with on the blob route; null keeps its manifest type.
    /// Docker distribution answers <c>application/octet-stream</c> there.
    /// </summary>
    public string? BlobRouteManifestType { get; set; }

    public int CallCount => Volatile.Read(ref _calls);

    public sealed record Image(string Digest, byte[] Manifest, string ConfigDigest, string LayerDigest);

    /// <summary>Adds one single-platform image (config + one layer + manifest).</summary>
    public Image AddImage(string seed)
    {
        byte[] config = Encoding.UTF8.GetBytes(
            """{"architecture":"amd64","os":"linux","config":{"Labels":{"seed":""" + "\"" + seed + "\"}}}");
        byte[] layer = Encoding.UTF8.GetBytes($"layer-bytes-{seed}");
        string configDigest = Digest(config);
        string layerDigest = Digest(layer);
        byte[] manifest = Encoding.UTF8.GetBytes(
            $$"""{"schemaVersion":2,"mediaType":"{{ImageManifestType}}","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{{configDigest}}","size":{{config.Length}}},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{{layerDigest}}","size":{{layer.Length}}}]}""");
        lock (_manifests)
        {
            _blobs[configDigest] = config;
            _blobs[layerDigest] = layer;
            _manifests[Digest(manifest)] = (manifest, ImageManifestType);
        }

        return new Image(Digest(manifest), manifest, configDigest, layerDigest);
    }

    /// <summary>Adds a blob served on the blob route under <paramref name="mediaType"/>; returns its digest.</summary>
    public string AddBlob(byte[] bytes, string mediaType)
    {
        lock (_manifests)
        {
            _blobs[Digest(bytes)] = bytes;
            _blobTypes[Digest(bytes)] = mediaType;
        }

        return Digest(bytes);
    }

    /// <summary>
    /// Adds a manifest padded with an annotation to <paramref name="padBytes"/> extra bytes, so a
    /// test can size a manifest against the registry's limits; returns its digest.
    /// </summary>
    public string AddPaddedImage(string seed, int padBytes)
    {
        var image = AddImage(seed);
        string json = Encoding.UTF8.GetString(image.Manifest);
        byte[] padded = Encoding.UTF8.GetBytes(
            json[..^1] + ",\"annotations\":{\"pad\":\"" + new string('x', padBytes) + "\"}}");
        lock (_manifests)
        {
            _manifests[Digest(padded)] = (padded, ImageManifestType);
        }

        return Digest(padded);
    }

    /// <summary>Adds an index listing the given platform images; returns the index digest and bytes.</summary>
    public (string Digest, byte[] Bytes) AddIndex(params Image[] platforms)
    {
        string entries = string.Join(",", platforms.Select((p, i) =>
            $$$"""{"mediaType":"{{{ImageManifestType}}}","digest":"{{{p.Digest}}}","size":{{{p.Manifest.Length}}},"platform":{"architecture":"{{{(i == 0 ? "amd64" : "arm64")}}}","os":"linux"}}"""));
        byte[] index = Encoding.UTF8.GetBytes(
            $$"""{"schemaVersion":2,"mediaType":"{{ImageIndexType}}","manifests":[{{entries}}]}""");
        lock (_manifests)
        {
            _manifests[Digest(index)] = (index, ImageIndexType);
        }

        return (Digest(index), index);
    }

    /// <summary>Points <paramref name="tag"/> at <paramref name="digest"/>.</summary>
    public void Tag(string tag, string digest)
    {
        lock (_manifests)
        {
            _tags[tag] = digest;
        }
    }

    /// <summary>
    /// True when the upstream URL addresses a manifest: its final two path segments are
    /// <c>manifests/&lt;reference&gt;</c>. Classified from the end of the path because a repository
    /// name may itself contain a <c>manifests</c> or <c>blobs</c> segment.
    /// </summary>
    public static bool IsManifestUrl(string url)
    {
        int cut = url.IndexOfAny(['?', '#']);
        string path = cut >= 0 ? url[..cut] : url;
        int v2 = path.IndexOf("/v2/", StringComparison.Ordinal);
        if (v2 < 0)
        {
            return false;
        }

        string[] segments = path[(v2 + 4)..].Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length >= 3 && segments[^2] == "manifests";
    }

    public static string Digest(byte[] bytes) => "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    public HttpResponseMessage Respond(HttpRequestMessage req)
    {
        Interlocked.Increment(ref _calls);
        if (Down)
        {
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        }

        string path = req.RequestUri!.AbsolutePath;
        string manifestsPrefix = $"/v2/{_repo}/manifests/";
        string blobsPrefix = $"/v2/{_repo}/blobs/";
        lock (_manifests)
        {
            if (path.StartsWith(manifestsPrefix, StringComparison.Ordinal))
            {
                string reference = path[manifestsPrefix.Length..];
                string digest = _tags.TryGetValue(reference, out string? tagged) ? tagged : reference;
                return _manifests.TryGetValue(digest, out var m)
                    ? Manifest(req, m.Bytes, m.MediaType, digest)
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            if (path.StartsWith(blobsPrefix, StringComparison.Ordinal))
            {
                string digest = path[blobsPrefix.Length..];
                if (_blobs.TryGetValue(digest, out byte[]? blob))
                {
                    return Blob(req, blob, _blobTypes.GetValueOrDefault(digest, "application/octet-stream"));
                }

                if (ServeManifestsAsBlobs && _manifests.TryGetValue(digest, out var m))
                {
                    return Blob(req, m.Bytes, BlobRouteManifestType ?? m.MediaType);
                }
            }
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Manifest(HttpRequestMessage req, byte[] bytes, string mediaType, string digest)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(req.Method == HttpMethod.Head ? [] : bytes),
        };
        resp.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        resp.Content.Headers.ContentLength = bytes.Length;
        resp.Headers.TryAddWithoutValidation("Docker-Content-Digest", digest);
        return resp;
    }

    private static HttpResponseMessage Blob(HttpRequestMessage req, byte[] bytes, string mediaType)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(req.Method == HttpMethod.Head ? [] : bytes),
        };
        resp.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        resp.Content.Headers.ContentLength = bytes.Length;
        return resp;
    }
}
