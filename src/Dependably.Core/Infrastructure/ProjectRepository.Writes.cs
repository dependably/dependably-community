using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>
/// The write half of the projects plane: create, update, delete, promote, and the
/// resolve-or-create path an SBOM upload takes. Every multi-row invariant the schema cannot
/// express — a parent must be a collection, a collection holds no versions, exactly one version
/// is latest — is enforced inside one transaction here, and a loser retries against the
/// committed state rather than reporting a conflict.
/// </summary>
public sealed partial class ProjectRepository
{
    // ── Writes ───────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a project or collection. <paramref name="parentId"/>, when supplied, must name a
    /// <c>kind='collection'</c> row in the same org.
    /// </summary>
    /// <exception cref="ProjectResolutionException">
    /// <see cref="ProjectResolutionReason.ParentNotFound"/> when the parent does not exist in this
    /// org, or <see cref="ProjectResolutionReason.ParentNotACollection"/> when it is not a
    /// collection.
    /// </exception>
    public async Task<Project> CreateAsync(
        string orgId,
        NewProject project,
        string? actorId,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        if (project.ParentId is not null)
        {
            await RequireCollectionParentAsync(conn, null, orgId, project.ParentId);
        }

        return await InsertProjectAsync(conn, null, orgId, project, actorId);
    }

    /// <summary>
    /// Renames, re-describes, re-classifies, retires-or-reinstates and/or relocates one project.
    /// Every field is a resolved final value — the caller has already folded "leave unchanged" into
    /// the row's current value — so this method always writes all five columns.
    ///
    /// Relocation is why the whole thing runs inside one transaction. The three cross-row facts a
    /// move has to respect (the target is a collection, the target is not the project itself, the
    /// target is not one of the project's own descendants) are read here and the UPDATE lands
    /// against the same snapshot, so two concurrent moves cannot each observe a legal tree and
    /// commit into a cycle — which no CHECK or index can express, and which would detach the whole
    /// subtree from the root permanently.
    ///
    /// Returns null when the project does not exist in this org, which the API renders as 404.
    /// </summary>
    /// <exception cref="ProjectResolutionException">
    /// <see cref="ProjectResolutionReason.ParentNotFound"/> / <see cref="ProjectResolutionReason.ParentNotACollection"/>
    /// / <see cref="ProjectResolutionReason.ParentIsSelf"/> / <see cref="ProjectResolutionReason.ParentIsDescendant"/>
    /// for an illegal move, and <see cref="ProjectResolutionReason.NameTaken"/> when the target
    /// scope already holds a different project of this name.
    /// </exception>
    public async Task<Project?> UpdateAsync(
        string orgId,
        string projectId,
        string name,
        string classifier,
        string? description,
        string? parentId,
        bool isActive,
        CancellationToken ct = default)
    {
        int attempt = 0;
        while (true)
        {
            attempt++;
            await using var conn = await _db.OpenAsync(ct);

            var current = await GetAsync(conn, null, orgId, projectId);
            if (current is null)
            {
                return null;
            }

            await using var tx = await conn.BeginTransactionAsync(ct);
            try
            {
                await RequireLegalMoveAsync(conn, tx, orgId, current, name, parentId, ct);

                int affected = await conn.ExecuteAsync(new CommandDefinition(
                    """
                    UPDATE projects
                       SET name = @name, classifier = @classifier,
                           description = @description, parent_id = @parentId,
                           is_active = @isActive
                     WHERE org_id = @orgId AND id = @projectId
                    """,
                    new { orgId, projectId, name, classifier, description, parentId, isActive },
                    tx, cancellationToken: ct));

                if (affected == 0)
                {
                    await tx.RollbackAsync(ct);
                    return null;
                }

                await tx.CommitAsync(ct);

                return new Project
                {
                    Id = current.Id,
                    OrgId = current.OrgId,
                    ParentId = parentId,
                    Kind = current.Kind,
                    Name = name,
                    Classifier = classifier,
                    Description = description,
                    IsActive = isActive,
                    CreatedBy = current.CreatedBy,
                    CreatedAt = current.CreatedAt,
                };
            }
            catch (ProjectResolutionException)
            {
                await SafeRollbackAsync(tx, ct);
                throw;
            }
            catch (Exception ex) when (IsRetryableWriteConflict(ex) && attempt < MaxPromotionAttempts)
            {
                await SafeRollbackAsync(tx, ct);
            }
        }
    }

    /// <summary>
    /// Everything a rename-or-move has to be true for, read inside the caller's transaction so the
    /// UPDATE lands against the same snapshot: the target is not the project itself, the target is
    /// a collection, the target is not one of the project's own descendants, and the target scope
    /// does not already hold a different project of this name. Throws
    /// <see cref="ProjectResolutionException"/> naming which one failed.
    ///
    /// The descendant and collection checks run only for an actual relocation — re-describing a
    /// project in place re-reads nothing about the tree.
    /// </summary>
    private static async Task RequireLegalMoveAsync(
        DbConnection conn, DbTransaction tx, string orgId, Project current, string name,
        string? targetParentId, CancellationToken ct)
    {
        bool relocating = !string.Equals(current.ParentId, targetParentId, StringComparison.Ordinal);
        if (relocating && targetParentId is not null)
        {
            if (string.Equals(targetParentId, current.Id, StringComparison.Ordinal))
            {
                throw new ProjectResolutionException(
                    ProjectResolutionReason.ParentIsSelf,
                    "A project cannot be its own parent.");
            }

            await RequireCollectionParentAsync(conn, tx, orgId, targetParentId);
            await RequireNotDescendantAsync(conn, tx, orgId, current.Id, targetParentId, ct);
        }

        var clash = await GetByNameAsync(conn, tx, orgId, targetParentId, name);
        if (clash is not null && !string.Equals(clash.Id, current.Id, StringComparison.Ordinal))
        {
            throw new ProjectResolutionException(
                ProjectResolutionReason.NameTaken,
                "The target scope already holds a project of this name.");
        }
    }

    /// <summary>
    /// Deletes a project and, by FK cascade, its subtree, versions, documents and derived rows.
    /// Returns false when nothing matched, which the API renders as a 404 rather than a 204.
    /// </summary>
    public async Task<bool> DeleteAsync(string orgId, string projectId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int affected = await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM projects WHERE org_id = @orgId AND id = @projectId",
            new { orgId, projectId }, cancellationToken: ct));
        return affected > 0;
    }

    /// <summary>
    /// Deletes one version and, by FK cascade, its documents and derived rows. Returns false when
    /// nothing matched.
    ///
    /// <para>Deleting the <c>is_latest</c> version promotes the newest survivor in the same
    /// transaction. A bare delete leaves the project permanently latest-less, which is not a
    /// cosmetic gap: every <c>latest</c> route 404s, the project list renders a null version label,
    /// and the rollup counts the project as unevaluated — degrading its whole ancestor chain to
    /// "Not scanned". The nightly policy sweep is bounded to in-service rows, so such a
    /// project also stops being re-evaluated entirely, and on an air-gapped instance it has no
    /// evaluation path left at all. This mirrors the first-version auto-latest rule in
    /// <see cref="ResolveOrCreateAsync"/>, from the same premise: a project holding versions always
    /// has one that <c>latest</c> resolves to.</para>
    ///
    /// <para>Deleting the last version correctly leaves none — latest-less is the right state for a
    /// project with nothing to be latest.</para>
    ///
    /// <para>The flag is read by <c>DELETE … RETURNING</c> rather than by a SELECT ahead of the
    /// DELETE, so the value the promotion branches on is the one the delete actually removed. A
    /// separate read is not safe on Postgres READ COMMITTED even inside this transaction: a
    /// concurrent promotion of the target row can commit while the DELETE waits on its row lock,
    /// and the DELETE — whose predicate is id-only — then removes the newly-latest row while the
    /// stale read still says <c>is_latest = 0</c>, leaving the project with no latest at all.
    /// SQLite serializes writers and so never exhibits it, which is exactly why the two-statement
    /// form passes every test on a community deployment and fails on a Postgres replica set.
    /// RETURNING is supported by both providers (SQLite since 3.35; the pinned native library is
    /// well past it), so the two stay on one code path.</para>
    /// </summary>
    public async Task<bool> DeleteVersionAsync(
        string orgId, string projectId, string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            // NULL means no row matched; otherwise this is the deleted row's own flag, read
            // atomically with its removal.
            int? wasLatest = await conn.ExecuteScalarAsync<int?>(new CommandDefinition(
                """
                DELETE FROM project_versions
                WHERE org_id = @orgId AND project_id = @projectId AND id = @versionId
                RETURNING is_latest
                """,
                new { orgId, projectId, versionId }, tx, cancellationToken: ct));

            if (wasLatest is null)
            {
                await tx.RollbackAsync(ct);
                return false;
            }

            if (wasLatest == 1)
            {
                // Newest survivor by created_at, id as the deterministic tiebreak — the same
                // ordering the retention sweep ranks on, so the version a cap would keep longest is
                // the one promoted here. No survivor means no promotion, which is correct.
                await conn.ExecuteAsync(new CommandDefinition(
                    """
                    UPDATE project_versions SET is_latest = 1
                    WHERE id = (
                        SELECT pv.id FROM project_versions pv
                        WHERE pv.org_id = @orgId AND pv.project_id = @projectId
                        ORDER BY pv.created_at DESC, pv.id DESC
                        LIMIT 1
                    )
                    """,
                    new { orgId, projectId }, tx, cancellationToken: ct));
            }

            await tx.CommitAsync(ct);
            return true;
        }
        catch
        {
            await SafeRollbackAsync(tx, ct);
            throw;
        }
    }

    /// <summary>
    /// Retires or reinstates one release. Returns the updated row, or null when the version does
    /// not exist in this org and project.
    ///
    /// <para>Deliberately a plain single-row UPDATE with none of the promotion machinery around it.
    /// <c>is_active</c> has no cross-row invariant to protect — any number of a project's releases
    /// may be active at once, and none need be — so there is no clear-then-set, no partial unique
    /// index to contend on, and nothing for a concurrent writer to lose a race to. Two operators
    /// retiring two different releases both succeed; two retiring the same one converge on the
    /// same value.</para>
    ///
    /// <para><b>Retiring the latest release is allowed and changes nothing about what is counted.</b>
    /// <see cref="ProjectLifecycle.InServiceFilter"/> treats latest as a floor, so the current build
    /// stays in the blast radius whatever this flag says. The flag is still stored and still shown,
    /// because "we have cut this release but nothing runs it yet" is a true statement an operator
    /// may want recorded — it just is not one that removes the release from a security count.</para>
    /// </summary>
    public async Task<ProjectVersion?> SetVersionActiveAsync(
        string orgId, string projectId, string versionId, bool isActive, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        int affected = await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE project_versions SET is_active = @isActive
            WHERE org_id = @orgId AND project_id = @projectId AND id = @versionId
            """,
            new { orgId, projectId, versionId, isActive }, cancellationToken: ct));

        return affected == 0 ? null : await GetVersionAsync(conn, null, orgId, projectId, versionId);
    }

    /// <summary>
    /// Makes <paramref name="versionId"/> the project's latest: clear-then-set inside one
    /// transaction. Returns false when the version does not exist in this org and project.
    ///
    /// The existence check runs before the transaction on purpose — it makes the transaction
    /// write-first, so a contending promoter blocks acquiring the write lock instead of holding a
    /// read lock and deadlocking on the upgrade. A promoter that still loses (the partial unique
    /// index on Postgres, the write lock on SQLite) re-reads and retries.
    /// </summary>
    public async Task<bool> PromoteLatestAsync(
        string orgId, string projectId, string versionId, CancellationToken ct = default)
    {
        int attempt = 0;
        while (true)
        {
            attempt++;
            await using var conn = await _db.OpenAsync(ct);

            var existing = await GetVersionAsync(conn, null, orgId, projectId, versionId);
            if (existing is null)
            {
                return false;
            }

            await using var tx = await conn.BeginTransactionAsync(ct);
            try
            {
                await conn.ExecuteAsync(new CommandDefinition(
                    """
                    UPDATE project_versions SET is_latest = 0
                    WHERE org_id = @orgId AND project_id = @projectId
                      AND is_latest = 1 AND id <> @versionId
                    """,
                    new { orgId, projectId, versionId }, tx, cancellationToken: ct));

                int promoted = await conn.ExecuteAsync(new CommandDefinition(
                    """
                    UPDATE project_versions SET is_latest = 1
                    WHERE org_id = @orgId AND project_id = @projectId AND id = @versionId
                    """,
                    new { orgId, projectId, versionId }, tx, cancellationToken: ct));

                if (promoted == 0)
                {
                    await tx.RollbackAsync(ct);
                    return false;
                }

                await tx.CommitAsync(ct);
                return true;
            }
            catch (Exception ex) when (IsRetryableWriteConflict(ex) && attempt < MaxPromotionAttempts)
            {
                await SafeRollbackAsync(tx, ct);
            }
        }
    }

    /// <summary>
    /// Resolves an existing (project, version) pair by name, or creates it when
    /// <paramref name="autoCreate"/> is set. Promotion of <paramref name="isLatest"/> happens inside
    /// the same transaction as the create, so an upload never observes a project version that is
    /// neither latest nor superseded.
    ///
    /// A project's first version is always latest: without that, a project whose uploads never ask
    /// for promotion would have no <c>latest</c> to resolve and every <c>latest</c> route would 404
    /// forever.
    ///
    /// <paramref name="parentVersion"/> is accepted for Dependency-Track client compatibility and
    /// takes no part in the lookup: a parent is a collection, and a collection has no versions.
    /// </summary>
    /// <exception cref="ProjectResolutionException">
    /// <see cref="ProjectResolutionReason.CollectionTarget"/> when the resolved project is a
    /// collection (the caller maps that to 409);
    /// <see cref="ProjectResolutionReason.NotFound"/> when the project or version does not exist and
    /// <paramref name="autoCreate"/> is false (404);
    /// <see cref="ProjectResolutionReason.ParentNotFound"/> when a named parent does not exist and
    /// <paramref name="autoCreate"/> is false;
    /// <see cref="ProjectResolutionReason.ParentNotACollection"/> when the named parent is a
    /// project rather than a collection.
    /// </exception>
    public async Task<ProjectResolution> ResolveOrCreateAsync(
        string orgId,
        ProjectVersionRequest request,
        string? actorId,
        CancellationToken ct)
    {
        _ = request.ParentVersion;

        if (string.IsNullOrWhiteSpace(request.ProjectName))
        {
            throw new ProjectResolutionException(
                ProjectResolutionReason.NotFound, "projectName is required.");
        }

        if (string.IsNullOrWhiteSpace(request.ProjectVersion))
        {
            throw new ProjectResolutionException(
                ProjectResolutionReason.NotFound, "projectVersion is required.");
        }

        // Trimmed once, here, so every retry below resolves against the same coordinate.
        var trimmed = request with
        {
            ProjectName = request.ProjectName.Trim(),
            ProjectVersion = request.ProjectVersion.Trim(),
            ParentName = string.IsNullOrWhiteSpace(request.ParentName) ? null : request.ParentName.Trim(),
        };

        int attempt = 0;
        while (true)
        {
            attempt++;
            try
            {
                return await ResolveOrCreateOnceAsync(orgId, trimmed, actorId, ct);
            }
            catch (Exception ex) when (IsRetryableWriteConflict(ex) && attempt < MaxResolveAttempts)
            {
                // A concurrent uploader created the same project, version, or latest promotion
                // first. The next pass reads its committed row instead of inserting a duplicate.
            }
        }
    }

    private async Task<ProjectResolution> ResolveOrCreateOnceAsync(
        string orgId,
        ProjectVersionRequest request,
        string? actorId,
        CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            string? parentScope = await ResolveParentScopeAsync(conn, tx, orgId, request, actorId);
            var (project, projectCreated) =
                await ResolveOrCreateProjectAsync(conn, tx, orgId, request, parentScope, actorId);
            var (version, versionCreated) =
                await ResolveOrCreateVersionAsync(conn, tx, orgId, request, project.Id, actorId, ct);

            await tx.CommitAsync(ct);

            return new ProjectResolution
            {
                ProjectId = project.Id,
                ProjectVersionId = version.Id,
                ProjectName = project.Name,
                VersionLabel = version.Version,
                ProjectCreated = projectCreated,
                VersionCreated = versionCreated,
            };
        }
        catch
        {
            await SafeRollbackAsync(tx, ct);
            throw;
        }
    }

    /// <summary>
    /// The scope every project lookup is keyed on: the supplied id, the id the name resolved to,
    /// or null for the root.
    ///
    /// <para>An id names exactly one row at any depth, so it is resolved first and never
    /// auto-created: an id the caller supplied and this org does not hold is a mistake to report,
    /// not a folder to invent. <c>parentName</c> cannot express depth at all — it is looked up in
    /// the ROOT scope only, so a name shared by a root folder and a nested one silently resolves
    /// to the root, which is why every caller that knows the id sends it.</para>
    /// </summary>
    private async Task<string?> ResolveParentScopeAsync(
        DbConnection conn, DbTransaction tx, string orgId, ProjectVersionRequest request, string? actorId)
    {
        if (request.ParentId is not null)
        {
            await RequireCollectionParentAsync(conn, tx, orgId, request.ParentId);
            return request.ParentId;
        }

        if (request.ParentName is null)
        {
            return null;
        }

        var parent = await GetByNameAsync(conn, tx, orgId, null, request.ParentName);
        if (parent is null)
        {
            if (!request.AutoCreate)
            {
                throw new ProjectResolutionException(
                    ProjectResolutionReason.ParentNotFound,
                    "The named parent collection does not exist.");
            }

            parent = await InsertProjectAsync(
                conn, tx, orgId,
                new NewProject(request.ParentName, ProjectKinds.Collection, ProjectClassifiers.Default),
                actorId);
        }
        else if (!string.Equals(parent.Kind, ProjectKinds.Collection, StringComparison.Ordinal))
        {
            throw new ProjectResolutionException(
                ProjectResolutionReason.ParentNotACollection,
                "The named parent is a project, not a collection.");
        }

        return parent.Id;
    }

    /// <summary>The named project within <paramref name="parentScope"/>, created when allowed.</summary>
    private async Task<(Project Project, bool Created)> ResolveOrCreateProjectAsync(
        DbConnection conn, DbTransaction tx, string orgId, ProjectVersionRequest request,
        string? parentScope, string? actorId)
    {
        var project = await GetByNameAsync(conn, tx, orgId, parentScope, request.ProjectName);
        if (project is not null)
        {
            return string.Equals(project.Kind, ProjectKinds.Collection, StringComparison.Ordinal)
                ? throw new ProjectResolutionException(
                    ProjectResolutionReason.CollectionTarget,
                    "The named project is a collection; collections hold no versions.")
                : (project, false);
        }

        if (!request.AutoCreate)
        {
            throw new ProjectResolutionException(
                ProjectResolutionReason.NotFound, "The named project does not exist.");
        }

        var created = await InsertProjectAsync(
            conn, tx, orgId,
            new NewProject(request.ProjectName, ProjectKinds.Project, request.Classifier, ParentId: parentScope),
            actorId);
        return (created, true);
    }

    /// <summary>
    /// The named version of <paramref name="projectId"/>, created when allowed. A first version is
    /// always latest whatever the request asked for — a project whose only version is not latest
    /// would render as having none.
    /// </summary>
    private async Task<(ProjectVersion Version, bool Created)> ResolveOrCreateVersionAsync(
        DbConnection conn, DbTransaction tx, string orgId, ProjectVersionRequest request,
        string projectId, string? actorId, CancellationToken ct)
    {
        var version = await conn.QuerySingleOrDefaultAsync<ProjectVersion>(new CommandDefinition(
            """
            SELECT v.id AS Id, v.org_id AS OrgId, v.project_id AS ProjectId, v.version AS Version,
                   v.is_latest AS IsLatest, v.is_active AS IsActive, v.policy_status AS PolicyStatus,
                   v.created_by AS CreatedBy, v.created_at AS CreatedAt
            FROM project_versions v
            WHERE v.org_id = @orgId AND v.project_id = @projectId AND v.version = @version
            """,
            new { orgId, projectId, version = request.ProjectVersion },
            tx, cancellationToken: ct));

        if (version is null)
        {
            if (!request.AutoCreate)
            {
                throw new ProjectResolutionException(
                    ProjectResolutionReason.NotFound, "The named project version does not exist.");
            }

            bool hasAnyVersion = await conn.ExecuteScalarAsync<int>(new CommandDefinition(
                """
                SELECT COUNT(*) FROM project_versions v
                WHERE v.org_id = @orgId AND v.project_id = @projectId
                """,
                new { orgId, projectId }, tx, cancellationToken: ct)) > 0;

            version = await InsertVersionAsync(
                conn, tx, orgId,
                new NewProjectVersion(projectId, request.ProjectVersion, request.IsLatest || !hasAnyVersion),
                actorId, ct);
            return (version, true);
        }

        if (request.IsLatest && !version.IsLatest)
        {
            await PromoteWithinTransactionAsync(conn, tx, orgId, projectId, version.Id, ct);
            version.IsLatest = true;
        }

        return (version, false);
    }

    private static async Task PromoteWithinTransactionAsync(
        DbConnection conn, DbTransaction tx, string orgId, string projectId, string versionId,
        CancellationToken ct)
    {
        await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE project_versions SET is_latest = 0
            WHERE org_id = @orgId AND project_id = @projectId AND is_latest = 1 AND id <> @versionId
            """,
            new { orgId, projectId, versionId }, tx, cancellationToken: ct));

        await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE project_versions SET is_latest = 1
            WHERE org_id = @orgId AND project_id = @projectId AND id = @versionId
            """,
            new { orgId, projectId, versionId }, tx, cancellationToken: ct));
    }

    private static async Task RequireCollectionParentAsync(
        DbConnection conn, DbTransaction? tx, string orgId, string parentId)
    {
        var parent = await GetAsync(conn, tx, orgId, parentId)
            ?? throw new ProjectResolutionException(
                ProjectResolutionReason.ParentNotFound, "The named parent collection does not exist.");

        if (!string.Equals(parent.Kind, ProjectKinds.Collection, StringComparison.Ordinal))
        {
            throw new ProjectResolutionException(
                ProjectResolutionReason.ParentNotACollection,
                "The named parent is a project, not a collection.");
        }
    }

    // Walks up from the proposed parent looking for the project being moved. Finding it means the
    // "parent" sits inside the subtree that is moving, so the move would cut that subtree loose
    // from the root — every row still reachable from itself and from nothing else.
    private static async Task RequireNotDescendantAsync(
        DbConnection conn, DbTransaction? tx, string orgId, string projectId, string parentId,
        CancellationToken ct)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? cursor = parentId;

        for (int depth = 0; cursor is not null && depth < MaxTreeDepth && seen.Add(cursor); depth++)
        {
            ct.ThrowIfCancellationRequested();
            if (string.Equals(cursor, projectId, StringComparison.Ordinal))
            {
                throw new ProjectResolutionException(
                    ProjectResolutionReason.ParentIsDescendant,
                    "The named parent is inside the subtree being moved.");
            }

            cursor = (await GetAsync(conn, tx, orgId, cursor))?.ParentId;
        }
    }

    private async Task<Project> InsertProjectAsync(
        DbConnection conn, DbTransaction? tx, string orgId, NewProject project, string? actorId)
    {
        var (name, kind, classifier, description, parentId) = project;
        var row = new Project
        {
            Id = Guid.NewGuid().ToString("N"),
            OrgId = orgId,
            ParentId = parentId,
            Kind = kind,
            Name = name,
            Classifier = ProjectClassifiers.Coerce(classifier),
            Description = description,
            CreatedBy = actorId,
            CreatedAt = _time.GetUtcNow(),
        };

        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, parent_id, kind, name, classifier, description,
                                  created_by, created_at)
            VALUES (@id, @orgId, @parentId, @kind, @name, @classifier, @description,
                    @createdBy, @createdAt)
            """,
            new
            {
                id = row.Id,
                orgId = row.OrgId,
                parentId = row.ParentId,
                kind = row.Kind,
                name = row.Name,
                classifier = row.Classifier,
                description = row.Description,
                createdBy = row.CreatedBy,
                createdAt = row.CreatedAt.ToUtcIso(),
            },
            tx);

        return row;
    }

    private async Task<ProjectVersion> InsertVersionAsync(
        DbConnection conn, DbTransaction? tx, string orgId, NewProjectVersion newVersion,
        string? actorId, CancellationToken ct)
    {
        var (projectId, version, isLatest) = newVersion;

        // Resolved before the clear below, because that clear is what makes the predecessor stop
        // being is_latest. Preference order is the project's current latest, then its most recently
        // created version — a project that has never had a latest row still has a predecessor worth
        // inheriting from, and a project with no versions at all yields none.
        string? predecessorId = await conn.QuerySingleOrDefaultAsync<string?>(new CommandDefinition(
            """
            SELECT pv.id FROM project_versions pv
            WHERE pv.org_id = @orgId AND pv.project_id = @projectId
            ORDER BY pv.is_latest DESC, pv.created_at DESC, pv.id DESC
            LIMIT 1
            """,
            new { orgId, projectId }, tx, cancellationToken: ct));

        if (isLatest)
        {
            await conn.ExecuteAsync(new CommandDefinition(
                """
                UPDATE project_versions SET is_latest = 0
                WHERE org_id = @orgId AND project_id = @projectId AND is_latest = 1
                """,
                new { orgId, projectId }, tx, cancellationToken: ct));
        }

        var row = new ProjectVersion
        {
            Id = Guid.NewGuid().ToString("N"),
            OrgId = orgId,
            ProjectId = projectId,
            Version = version,
            IsLatest = isLatest,
            PolicyStatus = null,
            CreatedBy = actorId,
            CreatedAt = _time.GetUtcNow(),
        };

        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, policy_status,
                                          created_by, created_at)
            VALUES (@id, @orgId, @projectId, @version, @isLatest, NULL, @createdBy, @createdAt)
            """,
            new
            {
                id = row.Id,
                orgId = row.OrgId,
                projectId = row.ProjectId,
                version = row.Version,
                isLatest = row.IsLatest ? 1 : 0,
                createdBy = row.CreatedBy,
                createdAt = row.CreatedAt.ToUtcIso(),
            },
            tx, cancellationToken: ct));

        if (predecessorId is not null)
        {
            await CarryForwardManualTriageAsync(conn, tx, orgId, predecessorId, row.Id, ct);
        }

        return row;
    }

    /// <summary>
    /// Seeds a freshly created version's <c>project_vuln_analysis</c> rows from its predecessor's
    /// <c>vex_source='manual'</c> rows, inside the version-insert transaction.
    ///
    /// <para>A manual triage decision is about <i>(product, package, advisory)</i>, not about a
    /// version label. <c>project_vuln_analysis</c> is keyed on the version-less <c>purl_key</c>, so
    /// the decision already survives a component bump and an SBOM re-upload within one version row;
    /// without this it does not survive the release that follows. A team that triaged forty
    /// <c>not_affected</c> statements on 2.3.0 would watch all forty return as open findings on
    /// 2.4.0 and re-fire the violation alert.</para>
    ///
    /// <para>Only the manual VEX arm is carried. An <c>upload</c> row is an assertion the
    /// predecessor's own VEX document made, and the SARIF reachability columns are an assertion the
    /// predecessor's own SARIF made; both are re-asserted by whatever documents the new version
    /// carries. Copying either would defeat retraction-by-omission — a producer that withdraws a
    /// statement expects it gone, and an inherited copy would keep answering in its place.</para>
    ///
    /// <para><c>updated_by</c> and <c>updated_at</c> are carried verbatim rather than restamped with
    /// the uploader who created the new version. The decision is inherited, not newly made: stamping
    /// the uploader would attribute a judgement to somebody who never made it, and would reset the
    /// age an operator reads to decide whether a triage is still current.</para>
    /// </summary>
    private static async Task CarryForwardManualTriageAsync(
        DbConnection conn, DbTransaction? tx, string orgId, string predecessorId, string newVersionId,
        CancellationToken ct)
    {
        var inherited = (await conn.QueryAsync<InheritedTriage>(new CommandDefinition(
            """
            SELECT a.purl_key AS PurlKey, a.vuln_key AS VulnKey, a.vex_state AS VexState,
                   a.vex_justification AS VexJustification, a.vex_response AS VexResponse,
                   a.vex_detail AS VexDetail, a.updated_by AS UpdatedBy, a.updated_at AS UpdatedAt
            FROM project_vuln_analysis a
            WHERE a.org_id = @orgId AND a.project_version_id = @predecessorId
              AND a.vex_source = 'manual'
            """,
            new { orgId, predecessorId }, tx, cancellationToken: ct))).AsList();

        foreach (var t in inherited)
        {
            await conn.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO project_vuln_analysis
                    (id, org_id, project_version_id, purl_key, vuln_key, vex_state,
                     vex_justification, vex_response, vex_detail, vex_source, updated_by, updated_at)
                VALUES
                    (@id, @orgId, @newVersionId, @purlKey, @vulnKey, @vexState,
                     @vexJustification, @vexResponse, @vexDetail, 'manual', @updatedBy, @updatedAt)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    newVersionId,
                    purlKey = t.PurlKey,
                    vulnKey = t.VulnKey,
                    vexState = t.VexState,
                    vexJustification = t.VexJustification,
                    vexResponse = t.VexResponse,
                    vexDetail = t.VexDetail,
                    updatedBy = t.UpdatedBy,
                    updatedAt = t.UpdatedAt,
                },
                tx, cancellationToken: ct));
        }
    }

    /// <summary>One predecessor manual-triage row, carried onto a newly created version.</summary>
    private sealed record InheritedTriage(
        string PurlKey, string VulnKey, string? VexState, string? VexJustification,
        string? VexResponse, string? VexDetail, string? UpdatedBy, string UpdatedAt);

    // A promoter or creator that lost a race sees a uniqueness violation on the provider that
    // detects it at commit, and a write-lock conflict on the provider that serialises writers
    // instead. Both mean the same thing here — somebody else got there first — and both are
    // resolved by re-reading the committed state.
    private static bool IsRetryableWriteConflict(Exception ex) =>
        ex is Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: 19 or 5 or 6 }
            or DbException { SqlState: "23505" or "40001" or "40P01" };

    private static async Task SafeRollbackAsync(DbTransaction tx, CancellationToken ct)
    {
        try
        {
            await tx.RollbackAsync(ct);
        }
        catch (DbException)
        {
            // The provider already resolved the transaction (a failed commit rolls back on its
            // own); there is nothing left to undo.
        }
        catch (InvalidOperationException)
        {
            // Same, for the providers that report an already-completed transaction this way.
        }
    }
}
