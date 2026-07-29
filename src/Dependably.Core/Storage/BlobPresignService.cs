namespace Dependably.Storage;

/// <summary>
/// The single place a serve path asks "may I answer this read with a redirect, and if so what
/// URL?". It owns the three conditions that must all hold — the feature is enabled, the tier
/// backing this blob advertises <see cref="IPresignedReadBlobStore"/> and can sign right now, and
/// the blob is actually there — and the one clock read that fixes the expiry.
///
/// <para>
/// Every failure mode falls back to streaming rather than failing the request. A presigned
/// redirect is a throughput optimisation layered on top of a read the caller has already
/// authorized; a store that cannot sign, or throws while signing, must not turn an authorized
/// pull into an error. The inverse — falling back to a redirect when something is wrong — is
/// what this type never does.
/// </para>
///
/// <para>
/// This service makes no authorization, tenancy, or policy decision of its own and deliberately
/// cannot: it is handed a blob key that a caller has already resolved and gated. Callers invoke
/// it as the last step before writing the response, so there is no path on which a URL is minted
/// ahead of the checks that authorize the read.
/// </para>
/// </summary>
public sealed class BlobPresignService
{
    private readonly PresignedReadOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<BlobPresignService> _logger;

    public BlobPresignService(PresignedReadOptions options, TimeProvider time, ILogger<BlobPresignService> logger)
    {
        _options = options;
        _time = time;
        _logger = logger;
    }

    /// <summary>True when the operator has opted this instance into presigned reads.</summary>
    public bool Enabled => _options.Enabled;

    /// <summary>The lifetime minted URLs carry.</summary>
    public TimeSpan Ttl => _options.Ttl;

    /// <summary>
    /// Mints a presigned read URL for <paramref name="key"/> in <paramref name="store"/>, or
    /// returns <c>null</c> when the caller should stream the blob instead.
    /// </summary>
    public async Task<PresignedReadUrl?> TryCreateAsync(IBlobStore store, string key, CancellationToken ct = default)
    {
        if (!_options.Enabled || store is not IPresignedReadBlobStore presigner || !presigner.SupportsPresignedReads)
        {
            return null;
        }

        var expiresAt = _time.GetUtcNow().Add(_options.Ttl);
        try
        {
            var url = await presigner.TryCreatePresignedReadUrlAsync(key, expiresAt, ct);
            return url is null ? null : new PresignedReadUrl(url, expiresAt);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "{ExceptionType} minting a presigned read URL for a blob; the read falls back to streaming through this instance. TraceId={TraceId}",
                ex.GetType().Name, System.Diagnostics.Activity.Current?.TraceId.ToString());
            return null;
        }
    }
}
