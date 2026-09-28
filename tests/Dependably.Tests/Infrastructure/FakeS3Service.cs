using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Amazon;
using Amazon.Runtime;
using Amazon.S3;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// An in-process S3 service behind a <b>real</b> <see cref="AmazonS3Client"/>: the SDK marshals,
/// signs and validates every request exactly as it does in production, and only the HTTP exchange
/// is answered here instead of by AWS. That is the point of it over a mocked <see cref="IAmazonS3"/>
/// — client-side preconditions the SDK enforces before sending anything (a request body whose
/// length it cannot determine, for one) fail here the same way they fail against AWS, where a
/// substitute would accept any request object it is handed.
///
/// <para>
/// Implements the object and multipart-upload operations <c>S3BlobStore</c> uses, over one bucket.
/// Uploaded bodies are decoded from the SDK's <c>aws-chunked</c> framing when it is used. The
/// multipart rules S3 enforces are enforced here too, because an upload that only a lenient fake
/// accepts is the failure these tests exist to catch: a part's checksum algorithm must match the
/// one the upload was created with, a CRC32 checksum must match the part's bytes, a completion
/// for a CRC32 upload must list every part's <c>ChecksumCRC32</c>, each listed part's ETag must
/// match, and every part but the last must reach <see cref="MinPartSizeBytes"/>.
/// </para>
/// </summary>
public sealed class FakeS3Service
{
    private const string Crc32Algorithm = "CRC32";

    private readonly ConcurrentDictionary<string, byte[]> _objects = new();
    private readonly ConcurrentDictionary<string, Upload> _uploads = new();
    private readonly ConcurrentQueue<string> _operations = new();
    private readonly ConcurrentQueue<IReadOnlyList<int>> _completedPartSizes = new();
    private int _uploadSeq;
    private int _failPartNumber;
    private int _failNextAbort;

    public FakeS3Service(string bucket = "test-bucket") => Bucket = bucket;

    public string Bucket { get; }

    /// <summary>
    /// Smallest size S3 accepts for any part but the last (5 MiB on AWS). Tests that drive the
    /// multipart path with small parts lower it to their own part size.
    /// </summary>
    public int MinPartSizeBytes { get; set; } = 5 * 1024 * 1024;

    /// <summary>Operation names in the order they reached the service (e.g. <c>PutObject</c>, <c>UploadPart</c>).</summary>
    public IReadOnlyList<string> Operations => _operations.ToArray();

    /// <summary>Multipart uploads initiated but neither completed nor aborted.</summary>
    public int OpenMultipartUploads => _uploads.Count;

    /// <summary>For each completed multipart upload, the byte length of every part, in part order.</summary>
    public IReadOnlyList<IReadOnlyList<int>> CompletedPartSizes => _completedPartSizes.ToArray();

    public IReadOnlyCollection<string> Keys => _objects.Keys.ToArray();

    public byte[]? GetObject(string key) => _objects.TryGetValue(key, out byte[]? b) ? b : null;

    /// <summary>Makes the next <c>UploadPart</c> carrying <paramref name="partNumber"/> fail with a 500, once.</summary>
    public void FailNextUploadPart(int partNumber) => Volatile.Write(ref _failPartNumber, partNumber);

    /// <summary>
    /// Makes the next <c>AbortMultipartUpload</c> fail client-side with an
    /// <see cref="AmazonClientException"/> (the SDK's own failure type for signing, credential and
    /// checksum errors), once.
    /// </summary>
    public void FailNextAbortClientSide() => Volatile.Write(ref _failNextAbort, 1);

    /// <summary>
    /// A real SDK client wired to this service, configured like the production AWS client (a
    /// regional endpoint, default checksum and signing behaviour). Retries are off so an injected
    /// failure surfaces on the first attempt.
    /// </summary>
    public AmazonS3Client CreateClient()
        => new(new BasicAWSCredentials("AKIDFAKEFAKEFAKE", "fake-secret"), new AmazonS3Config
        {
            RegionEndpoint = RegionEndpoint.USEast1,
            HttpClientFactory = new HandlerFactory(new Handler(this)),
            MaxErrorRetry = 0,
        });

    private sealed record Part(byte[] Body, string ETag, string? Crc32);

    private sealed class Upload(string? checksumAlgorithm)
    {
        public string? ChecksumAlgorithm { get; } = checksumAlgorithm;
        public ConcurrentDictionary<int, Part> Parts { get; } = new();
    }

    private sealed class HandlerFactory(HttpMessageHandler handler) : HttpClientFactory
    {
        public override HttpClient CreateHttpClient(IClientConfig clientConfig)
            => new(handler, disposeHandler: false);

        public override bool UseSDKHttpClientCaching(IClientConfig clientConfig) => false;

        public override bool DisposeHttpClientsAfterUse(IClientConfig clientConfig) => true;
    }

    private sealed class Handler(FakeS3Service s3) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string key = s3.KeyOf(request.RequestUri!);
            var query = ParseQuery(request.RequestUri!.Query);
            var body = request.Content is null
                ? new RequestBody([], new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase))
                : await ReadBodyAsync(request.Content, ct);

            if (request.Method == HttpMethod.Post && query.ContainsKey("uploads"))
            {
                s3._operations.Enqueue("CreateMultipartUpload");
                string uploadId = "upload-" + Interlocked.Increment(ref s3._uploadSeq);
                s3._uploads[uploadId] = new Upload(HeaderValue(request, "x-amz-checksum-algorithm")?.ToUpperInvariant());
                return Xml(HttpStatusCode.OK,
                    $"<InitiateMultipartUploadResult><Bucket>{s3.Bucket}</Bucket><Key>{key}</Key><UploadId>{uploadId}</UploadId></InitiateMultipartUploadResult>");
            }

            if (request.Method == HttpMethod.Put && query.TryGetValue("uploadId", out string? partUpload))
            {
                return s3.UploadPart(partUpload, query["partNumber"], request, body);
            }

            if (request.Method == HttpMethod.Post && query.TryGetValue("uploadId", out string? completeUpload))
            {
                return s3.Complete(key, completeUpload, body.Bytes);
            }

            if (request.Method == HttpMethod.Delete && query.TryGetValue("uploadId", out string? abortUpload))
            {
                s3._operations.Enqueue("AbortMultipartUpload");
                if (Interlocked.Exchange(ref s3._failNextAbort, 0) == 1)
                {
                    throw new AmazonClientException("Injected client-side failure aborting the upload.");
                }
                s3._uploads.TryRemove(abortUpload, out _);
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }

            if (request.Method == HttpMethod.Put)
            {
                s3._operations.Enqueue("PutObject");
                if (PartCrc32(request, body) is { } crc && crc != Crc32(body.Bytes))
                {
                    return Error(HttpStatusCode.BadRequest, "BadDigest");
                }
                s3._objects[key] = body.Bytes;
                var ok = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([]) };
                ok.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue($"\"{ETag(body.Bytes)}\"");
                return ok;
            }

            if (request.Method == HttpMethod.Delete)
            {
                s3._operations.Enqueue("DeleteObject");
                s3._objects.TryRemove(key, out _);
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }

            if (request.Method == HttpMethod.Get || request.Method == HttpMethod.Head)
            {
                s3._operations.Enqueue(request.Method == HttpMethod.Get ? "GetObject" : "HeadObject");
                if (!s3._objects.TryGetValue(key, out byte[]? obj))
                {
                    return request.Method == HttpMethod.Head
                        ? new HttpResponseMessage(HttpStatusCode.NotFound)
                        : Error(HttpStatusCode.NotFound, "NoSuchKey");
                }
                var ok = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(request.Method == HttpMethod.Get ? obj : []),
                };
                ok.Content.Headers.ContentLength = obj.Length;
                ok.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue($"\"{ETag(obj)}\"");
                return ok;
            }

            return Error(HttpStatusCode.NotImplemented, "NotImplemented");
        }
    }

    private HttpResponseMessage UploadPart(string uploadId, string partNumberText, HttpRequestMessage request, RequestBody body)
    {
        _operations.Enqueue("UploadPart");
        int partNumber = int.Parse(partNumberText, System.Globalization.CultureInfo.InvariantCulture);
        if (Interlocked.CompareExchange(ref _failPartNumber, 0, partNumber) == partNumber)
        {
            return Error(HttpStatusCode.InternalServerError, "InternalError");
        }
        if (!_uploads.TryGetValue(uploadId, out var upload))
        {
            return Error(HttpStatusCode.NotFound, "NoSuchUpload");
        }

        string? crc = PartCrc32(request, body);
        string? partAlgorithm = crc is null ? null : Crc32Algorithm;
        if (!string.Equals(partAlgorithm, upload.ChecksumAlgorithm, StringComparison.Ordinal))
        {
            // S3 refuses a part whose checksum type differs from the one the upload was created with.
            return Error(HttpStatusCode.BadRequest, "InvalidRequest");
        }
        if (crc is not null && crc != Crc32(body.Bytes))
        {
            return Error(HttpStatusCode.BadRequest, "BadDigest");
        }

        string etag = ETag(body.Bytes);
        upload.Parts[partNumber] = new Part(body.Bytes, etag, crc);
        var ok = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([]) };
        ok.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue($"\"{etag}\"");
        if (crc is not null)
        {
            ok.Headers.Add("x-amz-checksum-crc32", crc);
        }
        return ok;
    }

    private HttpResponseMessage Complete(string key, string uploadId, byte[] requestXml)
    {
        _operations.Enqueue("CompleteMultipartUpload");
        if (!_uploads.TryGetValue(uploadId, out var upload))
        {
            return Error(HttpStatusCode.NotFound, "NoSuchUpload");
        }

        var listed = XDocument.Parse(Encoding.UTF8.GetString(requestXml)).Descendants()
            .Where(e => e.Name.LocalName == "Part")
            .Select(e => (
                Number: int.Parse(Child(e, "PartNumber") ?? "0", System.Globalization.CultureInfo.InvariantCulture),
                ETag: Child(e, "ETag")?.Trim('"'),
                Crc32: Child(e, "ChecksumCRC32")))
            .ToList();
        if (listed.Count == 0)
        {
            return Error(HttpStatusCode.BadRequest, "MalformedXML");
        }

        var parts = new List<Part>();
        foreach (var entry in listed)
        {
            if (!upload.Parts.TryGetValue(entry.Number, out var part) || part.ETag != entry.ETag)
            {
                return Error(HttpStatusCode.BadRequest, "InvalidPart");
            }
            if (upload.ChecksumAlgorithm == Crc32Algorithm && entry.Crc32 != part.Crc32)
            {
                // An upload created with a checksum algorithm must be completed with every part's checksum.
                return Error(HttpStatusCode.BadRequest, "InvalidRequest");
            }
            parts.Add(part);
        }
        if (listed.Select(p => p.Number).Zip(listed.Skip(1).Select(p => p.Number)).Any(p => p.First >= p.Second))
        {
            return Error(HttpStatusCode.BadRequest, "InvalidPartOrder");
        }
        if (parts.SkipLast(1).Any(p => p.Body.Length < MinPartSizeBytes))
        {
            return Error(HttpStatusCode.BadRequest, "EntityTooSmall");
        }

        _uploads.TryRemove(uploadId, out _);
        _objects[key] = parts.SelectMany(p => p.Body).ToArray();
        _completedPartSizes.Enqueue(parts.Select(p => p.Body.Length).ToArray());
        return Xml(HttpStatusCode.OK,
            $"<CompleteMultipartUploadResult><Bucket>{Bucket}</Bucket><Key>{key}</Key><ETag>\"{ETag(_objects[key])}-{parts.Count}\"</ETag></CompleteMultipartUploadResult>");
    }

    private static string? Child(XElement parent, string localName)
        => parent.Elements().FirstOrDefault(e => e.Name.LocalName == localName)?.Value;

    private static string? HeaderValue(HttpRequestMessage request, string name)
        => request.Headers.TryGetValues(name, out var values) ? values.FirstOrDefault()
            : request.Content?.Headers.TryGetValues(name, out values) == true ? values!.FirstOrDefault()
            : null;

    // The CRC32 a request carries, either as a header or as an aws-chunked trailer.
    private static string? PartCrc32(HttpRequestMessage request, RequestBody body)
        => HeaderValue(request, "x-amz-checksum-crc32")
            ?? (body.Trailers.TryGetValue("x-amz-checksum-crc32", out string? trailer) ? trailer : null);

    // S3's CRC32 checksum encoding: the big-endian CRC32 of the bytes, base64-encoded.
    private static string Crc32(byte[] data)
    {
        Span<byte> bigEndian = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bigEndian, System.IO.Hashing.Crc32.HashToUInt32(data));
        return Convert.ToBase64String(bigEndian);
    }

    private sealed record RequestBody(byte[] Bytes, Dictionary<string, string> Trailers);

    private string KeyOf(Uri uri)
    {
        string path = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
        bool pathStyle = !uri.Host.StartsWith(Bucket + ".", StringComparison.Ordinal)
            && path.StartsWith(Bucket + "/", StringComparison.Ordinal);
        return pathStyle ? path[(Bucket.Length + 1)..] : path;
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            string name = Uri.UnescapeDataString(eq < 0 ? pair : pair[..eq]);
            result[name] = eq < 0 ? "" : Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return result;
    }

    // Reads the request body, undoing aws-chunked framing ("<hex>[;ext]\r\n<data>\r\n" … a
    // zero-length chunk, then "name:value" trailer lines) when the SDK streamed it that way.
    private static async Task<RequestBody> ReadBodyAsync(HttpContent content, CancellationToken ct)
    {
        byte[] raw = await content.ReadAsByteArrayAsync(ct);
        var trailers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        bool chunked = content.Headers.ContentEncoding.Contains("aws-chunked")
            || content.Headers.Contains("x-amz-decoded-content-length");
        if (!chunked)
        {
            return new RequestBody(raw, trailers);
        }

        var decoded = new MemoryStream();
        int pos = 0;
        while (pos < raw.Length)
        {
            int lineEnd = IndexOfCrlf(raw, pos);
            string header = Encoding.ASCII.GetString(raw, pos, lineEnd - pos);
            int semi = header.IndexOf(';');
            int size = Convert.ToInt32(semi < 0 ? header : header[..semi], 16);
            pos = lineEnd + 2;
            if (size == 0)
            {
                break;
            }
            decoded.Write(raw, pos, size);
            pos += size + 2;
        }

        foreach (string line in Encoding.ASCII.GetString(raw, pos, raw.Length - pos).Split("\r\n"))
        {
            int colon = line.IndexOf(':');
            if (colon > 0)
            {
                trailers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
            }
        }
        return new RequestBody(decoded.ToArray(), trailers);
    }

    private static int IndexOfCrlf(byte[] data, int from)
    {
        for (int i = from; i < data.Length - 1; i++)
        {
            if (data[i] == '\r' && data[i + 1] == '\n')
            {
                return i;
            }
        }
        throw new InvalidDataException("Malformed aws-chunked body.");
    }

    // S3 defines a single-part object's ETag as the MD5 of its body, and the SDK checks a
    // downloaded body against it, so the fake has to produce the same value to be believed.
    private static string ETag(byte[] body) => Convert.ToHexString(MD5.HashData(body)).ToLowerInvariant();

    private static HttpResponseMessage Xml(HttpStatusCode status, string xml)
        => new(status)
        {
            Content = new StringContent("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + xml, Encoding.UTF8, "application/xml"),
        };

    private static HttpResponseMessage Error(HttpStatusCode status, string code)
        => Xml(status, $"<Error><Code>{code}</Code><Message>{code}</Message><RequestId>fake</RequestId></Error>");
}
