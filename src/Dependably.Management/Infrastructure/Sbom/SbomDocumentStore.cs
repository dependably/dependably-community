using Dependably.Storage;

namespace Dependably.Infrastructure.Sbom;

// The staged file name is "publish-stage-{server-GUID}.tmp" under the operator-configured staging
// root, built by RequestBodyStager; the request body reaches the file CONTENT, never the file
// NAME. The interprocedural taint the analyzer traces from the controller action into this
// constructed path is a false positive, the same one RequestBodyStager itself suppresses.
#pragma warning disable SCS0018

/// <summary>One document to persist: the staged bytes plus what the metadata row records.</summary>
/// <param name="Lifecycles">
/// metadata.lifecycles as a JSON array, when the caller parsed one — an SBOM upload's own
/// document. Null for VEX/SARIF uploads, which carry no lifecycle claim of their own.
/// </param>
/// <param name="SignatureStatus">
/// CISA D2's verdict, from <see cref="SbomSignatureVerifier"/>. Null when this upload's
/// doc_type/format is outside that policy's scope, or verification was off.
/// </param>
/// <param name="SignatureKeyId">The signing key's fingerprint, set only when <paramref name="SignatureStatus"/> is <c>verified</c>.</param>
/// <param name="ToolVersionExplicitlyUnknown">
/// X4/D8b read back: true when the parsed document's named tool entry explicitly carried
/// dependably's own <c>dependably:tool-version-status</c> property. False for VEX/SARIF uploads
/// and every document that never demonstrated the vocabulary.
/// </param>
public sealed record SbomDocumentWrite(
    string OrgId,
    string ProjectId,
    string ProjectVersionId,
    string DocType,
    string Format,
    string? SpecVersion,
    string? ToolName,
    string? ToolVersion,
    string Sha256,
    long SizeBytes,
    string TempPath,
    string? UploadedBy,
    DateTimeOffset UploadedAt,
    string? Lifecycles = null,
    string? SignatureStatus = null,
    string? SignatureKeyId = null,
    bool ToolVersionExplicitlyUnknown = false);

/// <summary>
/// Puts an uploaded document's bytes in the registry blob tier and its metadata in
/// <c>project_documents</c>.
///
/// <para>The order is the whole design, and it is deliberately a two-step one the caller drives:
/// <see cref="StageBlobAsync"/>, then the caller's own merge, then <see cref="CommitRowAsync"/>.
/// Blob first means the metadata row never names bytes that are not there yet. What is left over
/// in the worst case — a blob written for an upload whose merge or metadata write then failed —
/// is an unreferenced blob, which the orphan reconciler reclaims from the same prefix.</para>
///
/// <para><b>Why the row is not written before the merge.</b> The row is what the upload path's
/// deduplication reads: a byte-identical re-upload whose digest matches the stored row is an
/// idempotent 200 no-op. That answer is only true if the row means "this exact document has been
/// fully applied". Committing it before the merge makes it mean "these bytes were received",
/// which is a different and weaker claim — a merge that then throws (a client disconnect
/// cancelling mid-transaction, a transient database error) leaves the row recording a document
/// whose components were never merged, and every retry of the same bytes short-circuits to a
/// success that reports <c>added: 0</c> over the previous document's inventory, permanently.
/// Committing the row last makes a failed apply indistinguishable from an upload that never
/// happened, which is the state a retry can actually repair.</para>
///
/// <para><b>Nothing here deletes a blob.</b> A document a re-upload supersedes stops being
/// referenced the moment the row is rewritten, and
/// <see cref="OrphanBlobReconcilerService"/> reclaims it on its next pass — <c>project_documents</c>
/// is in that sweep's referenced-key union and <see cref="Storage.BlobKeys.ProjectDocument"/>
/// keys under the same <c>hosted/</c> prefix it walks. Reclaiming inline instead cannot be made
/// safe from here, because the blob store and the database commit independently: an upload stages
/// bytes X, a concurrent upload of different bytes commits its own row, reads X as superseded and
/// deletes it, and only afterwards does the first upload commit a row naming X. The sweep has no
/// such window for the case that matters — its grace window skips any blob written more recently
/// than <c>ORPHAN_RECONCILE_GRACE_MINUTES</c>, so a blob staged by an upload that has not
/// committed yet is left alone however the row commit interleaves. One narrower window does
/// remain, and it is the sweep's rather than this path's: the freshness test reads the
/// last-modified stamp the listing captured, so re-putting an already-unreferenced key in the
/// gap between that entry being listed and the delete landing is not covered. The consequence is
/// a 404 that the next upload repairs, not a lost row. The cost of all this is that superseded
/// document bytes linger until the next pass.</para>
/// </summary>
public sealed class SbomDocumentStore
{
    private readonly ITenantStorageResolver _storage;
    private readonly ProjectDocumentRepository _documents;

    public SbomDocumentStore(ITenantStorageResolver storage, ProjectDocumentRepository documents)
    {
        _storage = storage;
        _documents = documents;
    }

    /// <summary>
    /// Writes the staged bytes to the registry tier and returns the content-addressed key they
    /// landed on. Writes no metadata row — the caller applies the document first and calls
    /// <see cref="CommitRowAsync"/> only once that has succeeded.
    ///
    /// <para>The put is unconditional, even when the key is already present: it is what stamps
    /// the blob's last-modified instant, and the orphan reconciler's grace window is measured
    /// from that instant. A re-upload of bytes some other in-flight upload is also carrying
    /// therefore re-arms the window for both.</para>
    /// </summary>
    public async Task<string> StageBlobAsync(SbomDocumentWrite write, CancellationToken ct = default)
    {
        var store = await _storage.GetRegistryAsync(write.OrgId, ct);
        string blobKey = Storage.BlobKeys.ProjectDocument(
            write.OrgId, write.ProjectId, write.ProjectVersionId, write.DocType, write.Sha256);

        await using var staged = new FileStream(
            write.TempPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 81920, useAsync: true);
        await store.PutAsync(blobKey, staged, ct);
        return blobKey;
    }

    /// <summary>
    /// Records the document as the current one of its kind and returns its stable row id. Called
    /// only after the document has been applied, so the row's existence certifies a completed
    /// apply rather than a received upload.
    /// </summary>
    public Task<string> CommitRowAsync(
        SbomDocumentWrite write, string blobKey, CancellationToken ct = default)
    {
        return _documents.UpsertAsync(
            new ProjectDocument
            {
                OrgId = write.OrgId,
                ProjectVersionId = write.ProjectVersionId,
                DocType = write.DocType,
                Format = write.Format,
                SpecVersion = write.SpecVersion,
                ToolName = write.ToolName,
                ToolVersion = write.ToolVersion,
                Sha256 = write.Sha256,
                SizeBytes = write.SizeBytes,
                BlobKey = blobKey,
                UploadedBy = write.UploadedBy,
                // Stamped by the build that actually applied the document, so the dedup arm can
                // tell rows written by this projection from rows written by an older one.
                IngestVersion = SbomIngestVersion.Current,
                Lifecycles = write.Lifecycles,
                SignatureStatus = write.SignatureStatus,
                SignatureKeyId = write.SignatureKeyId,
                ToolVersionExplicitlyUnknown = write.ToolVersionExplicitlyUnknown,
                UploadedAt = write.UploadedAt,
            },
            ct);
    }

    /// <summary>Opens a stored document's bytes, or null when the blob is gone.</summary>
    public async Task<Stream?> OpenAsync(string orgId, string blobKey, CancellationToken ct = default)
    {
        var store = await _storage.GetRegistryAsync(orgId, ct);
        return await store.GetAsync(blobKey, ct);
    }
}

#pragma warning restore SCS0018
