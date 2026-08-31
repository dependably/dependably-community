using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Latest-wins storage for the one SBOM, one VEX and one SARIF a project version may carry.
///
/// <para>The uniqueness is <c>(project_version_id, doc_type)</c>, so a re-upload rewrites the
/// row in place and the document id a reader has already seen keeps resolving. History is
/// deliberately not kept: the derived rows are a merge of the latest of each kind, so a second
/// stored SBOM for one version would be a document nothing reads.</para>
///
/// <para>This repository writes metadata only. Rewriting a row leaves whatever blob it used to
/// name unreferenced, and reclaiming that blob belongs to
/// <see cref="OrphanBlobReconcilerService"/> rather than to the caller — the blob store and the
/// database commit independently, so a caller handed a superseded key can delete bytes an upload
/// that is still in flight is about to commit a row for. The sweep's grace window is what makes
/// that interleaving harmless, so nothing here returns a key to delete.</para>
/// </summary>
public sealed class ProjectDocumentRepository
{
    private readonly IMetadataStore _db;

    public ProjectDocumentRepository(IMetadataStore db)
    {
        _db = db;
    }

    /// <summary>The current document of one kind for one version, or null.</summary>
    public async Task<ProjectDocument?> GetAsync(
        string orgId, string projectVersionId, string docType, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<ProjectDocument>(new CommandDefinition(
            """
            SELECT id AS Id, org_id AS OrgId, project_version_id AS ProjectVersionId,
                   doc_type AS DocType, format AS Format, spec_version AS SpecVersion,
                   tool_name AS ToolName, tool_version AS ToolVersion, sha256 AS Sha256,
                   size_bytes AS SizeBytes, blob_key AS BlobKey, uploaded_by AS UploadedBy,
                   ingest_version AS IngestVersion, uploaded_at AS UploadedAt
            FROM project_documents
            WHERE org_id = @orgId AND project_version_id = @projectVersionId AND doc_type = @docType
            """,
            new { orgId, projectVersionId, docType },
            cancellationToken: ct));
    }

    /// <summary>Every document held for one version, newest kind ordering left to the caller.</summary>
    public async Task<IReadOnlyList<ProjectDocument>> ListAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<ProjectDocument>(new CommandDefinition(
            """
            SELECT id AS Id, org_id AS OrgId, project_version_id AS ProjectVersionId,
                   doc_type AS DocType, format AS Format, spec_version AS SpecVersion,
                   tool_name AS ToolName, tool_version AS ToolVersion, sha256 AS Sha256,
                   size_bytes AS SizeBytes, blob_key AS BlobKey, uploaded_by AS UploadedBy,
                   ingest_version AS IngestVersion, uploaded_at AS UploadedAt
            FROM project_documents
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
            ORDER BY doc_type
            """,
            new { orgId, projectVersionId },
            cancellationToken: ct));
        return rows.ToList();
    }

    /// <summary>
    /// Writes <paramref name="document"/> as the current document of its kind, replacing any row
    /// already held for that <c>(version, kind)</c> pair, and returns the row's stable id.
    ///
    /// <para>The read of the existing row and the write that replaces it are one transaction, so
    /// the returned id is the id the committed row actually carries. Outside one they diverge:
    /// two concurrent first uploads of the same <c>(version, kind)</c> both read no row and both
    /// mint an id, one inserts, the other's <c>ON CONFLICT DO UPDATE</c> leaves that inserted id
    /// in place — and the second caller returns an id no row has, which the response hands to a
    /// client as a document reference that resolves to nothing.</para>
    ///
    /// <para><b>What the transaction buys differs by provider, and neither outcome is the
    /// hazard.</b> SQLite is a single writer, so the second caller's write cannot land inside
    /// the first's open transaction at all — it is refused (<c>SQLITE_BUSY</c>) and the upload
    /// fails, loudly and repeatably. Postgres under Npgsql's default READ COMMITTED does not
    /// refuse it: the second <c>ON CONFLICT DO UPDATE</c> waits out the row lock and then applies
    /// over the row the first caller committed. What both providers guarantee is that the row is
    /// never left half-written between the read and the upsert.</para>
    /// </summary>
    public async Task<string> UpsertAsync(
        ProjectDocument document, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            string id = await UpsertWithinTransactionAsync(conn, dbTx, document, ct);
            await dbTx.CommitAsync(ct);
            return id;
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }
    }

    private static async Task<string> UpsertWithinTransactionAsync(
        DbConnection conn, DbTransaction dbTx, ProjectDocument document, CancellationToken ct)
    {
        string? existingId = await conn.QuerySingleOrDefaultAsync<string?>(
            new CommandDefinition(
                """
                SELECT id FROM project_documents
                WHERE org_id = @orgId AND project_version_id = @projectVersionId AND doc_type = @docType
                """,
                new
                {
                    orgId = document.OrgId,
                    projectVersionId = document.ProjectVersionId,
                    docType = document.DocType,
                },
                dbTx,
                cancellationToken: ct));

        string id = existingId ?? Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO project_documents (
                id, org_id, project_version_id, doc_type, format, spec_version,
                tool_name, tool_version, sha256, size_bytes, blob_key, uploaded_by,
                ingest_version, uploaded_at)
            VALUES (
                @id, @orgId, @projectVersionId, @docType, @format, @specVersion,
                @toolName, @toolVersion, @sha256, @sizeBytes, @blobKey, @uploadedBy,
                @ingestVersion, @uploadedAt)
            ON CONFLICT (project_version_id, doc_type) DO UPDATE SET
                format = excluded.format,
                spec_version = excluded.spec_version,
                tool_name = excluded.tool_name,
                tool_version = excluded.tool_version,
                sha256 = excluded.sha256,
                size_bytes = excluded.size_bytes,
                blob_key = excluded.blob_key,
                uploaded_by = excluded.uploaded_by,
                ingest_version = excluded.ingest_version,
                uploaded_at = excluded.uploaded_at
            """,
            new
            {
                id,
                orgId = document.OrgId,
                projectVersionId = document.ProjectVersionId,
                docType = document.DocType,
                format = document.Format,
                specVersion = document.SpecVersion,
                toolName = document.ToolName,
                toolVersion = document.ToolVersion,
                sha256 = document.Sha256,
                sizeBytes = document.SizeBytes,
                blobKey = document.BlobKey,
                uploadedBy = document.UploadedBy,
                ingestVersion = document.IngestVersion,
                uploadedAt = document.UploadedAt.ToUtcIso(),
            },
            dbTx,
            cancellationToken: ct));

        return id;
    }
}
