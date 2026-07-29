# Schema Migration Rules

Dependably applies its schema on startup via `SchemaInitializer` (`src/Dependably/Infrastructure/SchemaInitializer.cs`), in three layers:

1. **Base schema** — the embedded `Schema.sql` / `Schema.pg.sql` is applied with `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`, so re-running is a safe no-op.
2. **Additive columns** — `ALTER TABLE ... ADD COLUMN` statements in `RunAdditiveMigrationsAsync`. SQLite has no `IF NOT EXISTS` for column adds, so `MigrateSqliteAsync` swallows only the "duplicate column" error (code 1); Postgres rewrites to `ADD COLUMN IF NOT EXISTS`.
3. **One-time migrations** — destructive DDL (`DROP COLUMN`, table rebuilds) and data backfills that are **not** idempotent on their own. These run through `RunOnceAsync`, which records each by name in the `_applied_migrations` ledger table so it runs exactly once per database.

So there *is* a migration history table (`_applied_migrations`) — it exists precisely because the layer-3 migrations are not idempotent.

Because blue-green deploys run both the old (blue) and new (green) version against the same database during the cutover window, schema changes must be backward-compatible with the previous release.

## Rules

### Schema.sql is the authoritative complete schema

`Schema.sql` (and `Schema.pg.sql`) must always reflect the full current database structure. When adding a new column via `ALTER TABLE` in `SchemaInitializer`, also add it to the corresponding `CREATE TABLE` block in the schema file. The `ALTER TABLE` handles existing installs; the `CREATE TABLE` block makes the schema self-documenting for fresh installs and for anyone reading the file.

### New columns

New columns on existing tables **must** either have a `DEFAULT` value or allow `NULL`:

```sql
-- OK: nullable column, old code ignores it
ALTER TABLE packages ADD COLUMN description TEXT;

-- OK: column with default, old code sees the default
ALTER TABLE packages ADD COLUMN is_featured INTEGER NOT NULL DEFAULT 0;

-- NEVER: non-null column without default — old rows have no value
ALTER TABLE packages ADD COLUMN required_field TEXT NOT NULL;  -- breaks old code
```

Adding a column requires **two** edits, both enforced by `SchemaSyncComplianceTests`:

1. Append an `ALTER TABLE ... ADD COLUMN` to the `migrations` array in `SchemaInitializer.RunAdditiveMigrationsAsync`. This upgrades existing databases; re-runs are made safe by `MigrateSqliteAsync` (swallows the "duplicate column" error on SQLite) and by the `ADD COLUMN IF NOT EXISTS` rewrite on Postgres.
2. Add the same column to the `CREATE TABLE` block in **both** `Schema.sql` and `Schema.pg.sql`. This is what fresh installs get, and keeps the two providers in parity.

Do not skip (2): a column that lives only in the `ALTER` array means a fresh install gets it solely from the upgrade path, and the two provider schemas can silently drift. `SchemaSyncComplianceTests` fails the build if an additive column is absent from either `CREATE TABLE` block.

### Renaming columns or tables

Rename = three separate releases:

1. **Release N**: Add the new column/table. Backfill existing rows.
2. **Release N+1**: Write to both old and new. Read from new.
3. **Release N+2**: Drop the old column/table.

Never rename in a single release — the old slot still reads the old name during cutover.

The **contract step** of this sequence is enforced: `SchemaBackwardCompatibilityComplianceTests` compares the working tree's schema against the previous release tag and fails on a removed table or column, so a one-step rename is caught as the removal it contains. A deliberate contract step declares itself with a `backcompat-ok:` marker (see [Waiving a deliberate contract step](#waiving-a-deliberate-contract-step)). What stays reviewer-enforced is the *timing*: the gate knows the object disappeared, not whether release N+1 really stopped reading it.

### Dropping columns or tables

Only drop in a release where no application code reads or writes that column/table. Ensure the previous release removed all references first.

The drop needs a `backcompat-ok:` marker naming the object — without one the backward-compatibility gate fails, because from the schema alone a legitimate contract step and an accidental one-step drop look identical.

Destructive drops live in `SchemaInitializer` as a `RunOnceAsync(...)` call so the migration ledger guarantees they run exactly once per database. SQLite ≥ 3.35 and Postgres both support `ALTER TABLE ... DROP COLUMN` natively. Examples: `drop_legacy_token_scope_column` retires the `user_tokens.scope` / `service_tokens.scope` columns now that capabilities is the single source of truth; `drop_package_versions_sbom_column` retires the orphaned per-version SBOM blob (the only producer wrapped coordinate fields in CycloneDX JSON; the read endpoint was removed in the API cleanup pass). The `RunOnceAsync` helper emits an info-level log on apply and on skip so operators can confirm the migration state from startup logs.

### Widening a CHECK constraint (enum-style columns)

Several columns constrain their values with `CHECK (col IN (...))` (e.g. `users.role`,
`org_settings.block_deprecated`). Adding a new allowed value needs work on **both** the fresh-install
and the upgrade path, because the two paths produce different on-disk shapes:

- **Fresh installs** get the constraint from the `CREATE TABLE` block — so widen the `IN (...)` list
  in both `Schema.sql` and `Schema.pg.sql`.
- **Existing databases** need the stored constraint rewritten via a `RunOnceAsync(..., transactional: false)`
  one-shot. Postgres drops + re-adds the auto-named `<table>_<col>_check` constraint (`IF EXISTS` covers
  installs that never had one); SQLite rewrites the stored `CREATE TABLE` text through the
  `PRAGMA writable_schema` pattern, then bumps `PRAGMA schema_version` and runs `integrity_check`.
  Both branches are idempotent, which is why they opt out of the enclosing transaction.
- **Columns added by a later `ALTER ADD COLUMN`** (rather than the original `CREATE TABLE`) carry **no**
  CHECK on upgraded databases, so those installs rely on controller-side validation — the rewrite simply
  no-ops on them.

Precedents: `expand_role_check_with_auditor` (adds `'auditor'` to `users.role` / `invites.role`) and
`expand_block_deprecated_check` (widens `org_settings.block_deprecated` to `'block_new'`/`'block_all'`).
When the new value also supersedes an old one, follow the CHECK widen with a normal transactional data
migration to rewrite legacy rows — e.g. `migrate_block_deprecated_to_block_all` rewrites the retired
`'block'` value to `'block_all'`, ordered *after* the CHECK widen so the new value is permitted.

### Index changes

Adding or removing indexes is always safe — they don't affect data visible to running code.

### Destructive DDL

Never pair a destructive statement (`DROP COLUMN`, `DROP TABLE`) with a statement that depends on the new structure in the same release.

## Schema.sql conventions

- All tables use `CREATE TABLE IF NOT EXISTS` — idempotent, never fails on re-run.
- All indexes use `CREATE INDEX IF NOT EXISTS`.
- Columns added to existing tables go in the `RunAdditiveMigrationsAsync` array in `SchemaInitializer.cs` (duplicate-column-safe) **and** in the `CREATE TABLE` block of both schema files — see "New columns" above.
- Foreign key constraints use `ON DELETE CASCADE` so parent deletes propagate cleanly.
- All timestamps are ISO 8601 UTC strings (`TEXT`), defaulting to `strftime('%Y-%m-%dT%H:%M:%SZ','now')`.

## Existing schema review

There is no hand-maintained per-table compatibility snapshot — it would drift from `Schema.sql` immediately. The previous release's schema is read straight out of git at its release tag instead, and compared against the working tree by `SchemaBackwardCompatibilityComplianceTests`; `Schema.sql` / `Schema.pg.sql` are the authoritative listing of what exists.

### Backward compatibility with the previous release

Blue (the previous release) and green (this build) share one database for the whole cutover window, so the gate fails on the five changes green can make that blue cannot survive:

| Change | Why it breaks the cutover |
|---|---|
| table removed | blue still queries it |
| column removed (including a one-step rename, which is a removal plus an add) | blue still reads/writes it |
| `CHECK (col IN (...))` value set shrinks | green rejects values blue still writes |
| any other `CHECK` clause on a surviving column is added or changed | blue's writers were never validated against it |
| column stops being omittable from an `INSERT` — becomes `NOT NULL` with no `DEFAULT`, or was already `NOT NULL` and loses its `DEFAULT` | blue's inserts omit it |

Everything additive — new tables, new columns, a *widened* value set, dropping a `CHECK` outright, relaxing `NOT NULL`, a nullable column losing a `DEFAULT` — is invisible to blue and passes.

The fourth row is a text comparison, not a semantic one. Only two `CHECK` shapes pass without a marker: a clause set that shrinks or stays identical, and a literal `IN (...)` list that provably widens — so the routine "widen a CHECK enum" workflow stays waiver-free. Every other shape (a `GLOB` pattern, a Postgres `~` regex, an arbitrary boolean expression) is reported whenever its text changes, including the first time it appears. Two reasons it is not smarter than that: regex and `GLOB` containment is intractable in general, and a first-ever constraint on a previously bare column is a narrowing of an unbounded domain — "no constraint before" is not "nothing newly rejected". A clause naming several columns is attributed to each of them, so waiving it takes one marker per column; the waiver vocabulary is `table.column`, and over-requiring a marker is the safe direction.

The baseline is the newest `vX.Y.Z` tag reachable from `HEAD`. The tag's objects are fetched explicitly, so the gate works under CI's shallow checkout; the `--depth=1` on that fetch is applied only when the repository is already shallow, because on a complete repository the flag writes a `.git/shallow` boundary and truncates the history other jobs (Sonar's SCM blame) depend on. The schema files are located inside the tag's tree rather than by a fixed path, so a release predating a source move still resolves. Without `SCHEMA_BACKCOMPAT_REQUIRE_BASELINE`, any failure to resolve a baseline is tolerated — a developer checkout offline, or a source export with no git, should not fail a build over a comparison it cannot run. With `SCHEMA_BACKCOMPAT_REQUIRE_BASELINE=true` (set on the `schema-integrity` job) the operator is asserting a baseline exists, and then **the only tolerable absence is "the tag list was established and this repository has never had a release"**. Everything else fails: a tag whose objects or schema files cannot be read, a `git ls-remote` that fails (a shallow checkout discovers tag names by asking the remote, so an unreachable origin leaves the tag list *unknown*, which is not the same as *empty* — conflating the two is how one name-resolution blip would silently turn the gate into a no-op), no `origin` to ask at all, and a directory that is not a git checkout. None of those may be reachable by *removing* something, or "delete it and the gate goes green" becomes the easiest way past the gate.

#### What the gate does not see

The comparison is between the two **declarative** schema files at the previous tag and in the working tree. It never reads `SchemaInitializer`, and it does not compare views. So these remain reviewer-enforced:

- **Migration-applied DDL.** A `RunOnceAsync` `DROP COLUMN` / `DROP TABLE` whose object is still declared in `Schema.sql` is invisible — the gate sees the declaration, the database sees the drop. Likewise the `ADD CONSTRAINT … CHECK` narrowings in `SchemaInitializer.OwnerPlane.cs` and the table rebuilds in `SchemaInitializer.Reshapes.cs`: those change the on-disk shape without touching either schema file. Keeping the schema files authoritative (the rule at the top of this document) is what keeps this blind spot empty.
- **Views.** `artifact_inventory`, `artifact_license`, and `org_storage_bytes` are created imperatively in `SchemaInitializer.Views.cs`, so no schema-file diff describes them. Their shape is under the same blue-green rule as a table's — a view may gain columns, but dropping, renaming, or retyping one is an expand/migrate/contract sequence, because blue reads the view while green replaces it. Postgres enforces that mechanically (`CREATE OR REPLACE VIEW` refuses all three), and the guarded drop+create fallback is the deliberate contract step; on SQLite the rule is reviewer-enforced. A boot that changes no view definition performs no view DDL at all, so replica starts, scale-out, and rolling restarts leave concurrent readers untouched.
- **Multi-list `CHECK` columns.** A column constrained by more than one `IN (...)` list contributes the union of those lists, so a value is reported only when it disappears from every list. The alternative (intersection) would produce false narrowing reports on correct schemas. Unreachable today — of the `IN` lists in the two files, no column carries more than one.
- **Baseline selection on an unrebased branch.** When ancestry is unknowable (shallow history), the fallback picks the globally highest tag rather than the highest tag reachable from `HEAD`. A branch cut before a release landed, then built after it, is compared against a schema it never contained and can report spurious removals. Rebase on `main` — the same rule that already governs branching here.

### Waiving a deliberate contract step

Release N+2 legitimately drops what release N+1 stopped reading. Say so at the drop, naming the object and the reason, in the same style as the `// xtenant:` / `// rawsql:` / `// blobkey-ok:` opt-outs:

```csharp
// backcompat-ok: user_tokens.scope — capabilities is the single source of truth; no release
// still reads or writes the column.
```

- Form: `backcompat-ok: <table>[.<column>] — <reason>`. A table-level marker waives only that table's removal; each column needs its own marker.
- Location: any comment in `Schema.sql`, `Schema.pg.sql`, or a `SchemaInitializer*.cs` — put it next to the `RunOnceAsync` drop it authorises. One marker covers both provider files.
- A marker with no reason is rejected, not honoured: the reason is what makes the drop reviewable.
- Once the previous release also no longer declares the object, the marker is dead weight and can be deleted.

#### Waiving a new or changed `CHECK`

A drop is waived by asserting nobody reads the object any more. A **new or changed** constraint is the opposite claim — the object stays, and the assertion is that the constraint cannot reject anything the previous release writes. The gate cannot check that: the comparison is declarative, and the constraint's real reach depends on how it is applied and on what is already in the table. So the reason must state both halves:

1. **Where the constraint lands.** Declared only in the `CREATE TABLE` blocks, it reaches fresh installs and nothing else — the previous release's slot keeps writing to a table that carries no such constraint, and the cutover is unaffected. If a `RunOnceAsync` in the *same release* retrofits it onto existing databases (`ADD CONSTRAINT … CHECK` on Postgres, a table rebuild on SQLite), say so: the constraint is then live under the previous release's writers on the very first boot of the new slot.
2. **Whether every writer already complies — as of the previous release, not this one.** Only needed when (1) says the constraint is retrofitted. Name the audit: the single writer the values flow through, or the test that proves the property across the schema. "The new code writes compliant values" is not the claim; blue is the code that matters.

This is the same reviewer-enforced territory as the `ADD CONSTRAINT … CHECK` narrowings in `SchemaInitializer.OwnerPlane.cs` called out above — the gate reads the declarative files, the database sees the migration, and only the reason text connects the two.

## CI check

The `schema-integrity` CI job (xUnit tests tagged `Category=Schema`) enforces these rules on every pipeline:

- **`SchemaSyncComplianceTests`** — fails if an additive `ALTER TABLE ... ADD COLUMN` adds a `NOT NULL` column without a `DEFAULT`; if an additive column is missing from the `CREATE TABLE` block of either `Schema.sql` or `Schema.pg.sql` (the "authoritative complete schema" rule above); or if an object name is declared twice in a file.
- **`SchemaParityComplianceTests`** — fails if `Schema.sql` and `Schema.pg.sql` declare different tables, or different column names for the same table.
- **`SchemaIntegrityTests`** — applies the full schema to a fresh SQLite database and asserts structural soundness (no duplicate columns, every table has a primary key, foreign keys resolve, `PRAGMA integrity_check` is `ok`) and that re-running `SchemaInitializer` is a stable no-op.
- **`SchemaBackwardCompatibilityComplianceTests`** — fails if this build's schema removes a table or column, shrinks a `CHECK` value set, adds or changes any other `CHECK` clause on a surviving column, or makes a column `NOT NULL` without a `DEFAULT`, relative to the previous release tag — unless a `backcompat-ok:` marker waives that object. `SchemaBackwardCompatibilityAnalyzerTests` pins the diff semantics themselves against hand-written before/after DDL pairs, and runs the same engine against the real previous release both with and without the declared waivers.

This prevents incompatible migrations from reaching main.
