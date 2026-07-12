---
name: fix-path-traversal
description: Remediate path/directory traversal and symlink-following findings (CWE-22/23/36/59/61/65/73 — OWASP A01:2025 Broken Access Control) by canonicalizing paths and validating they stay inside an allowed base directory.
category: remediation
cwe:
  - CWE-22
  - CWE-23
  - CWE-36
  - CWE-59
  - CWE-61
  - CWE-65
  - CWE-73
inputs:
  - OSV_ID
  - PACKAGE_PURL
  - FIXED_VERSION
---

## When to use this

A user-controlled value (a filename, an id, a URL path segment) reaches a filesystem API, and an
attacker can supply `../` sequences, an absolute path, or a symlink to make the resolved path
point outside the directory the application intended to serve from — reading, writing, or
overwriting a file it shouldn't.

If the finding is in a third-party dependency and `FIXED_VERSION` is set, apply the
`fix-vulnerable-dependency` skill first. Use this skill when the traversal is in your own
file-serving or file-upload code, or when the fixed dependency version still needs the calling
code's path handling reviewed.

## Core principle

Never trust a resolved path just because it was built from a "safe-looking" input. Canonicalize
first (resolve `.`, `..`, and symlinks to the real absolute path), then verify the *canonical*
result is still inside the allowed base directory. Checking the raw, unresolved string for `../`
substrings is not sufficient — encoded variants (`%2e%2e%2f`), mixed separators, and symlinks all
bypass a naive string check.

## Canonicalize, then verify containment

```csharp
// C# — GetFullPath resolves .. and symlinks; then confirm it's still under the base dir.
string baseDir = Path.GetFullPath(allowedRoot);
string resolved = Path.GetFullPath(Path.Combine(baseDir, userSuppliedName));
if (!resolved.StartsWith(baseDir + Path.DirectorySeparatorChar, StringComparison.Ordinal))
{
    throw new UnauthorizedAccessException("Path escapes the allowed directory.");
}
```

```python
# Python — os.path.realpath resolves symlinks too, not just os.path.abspath.
base_dir = os.path.realpath(allowed_root)
resolved = os.path.realpath(os.path.join(base_dir, user_supplied_name))
if os.path.commonpath([base_dir, resolved]) != base_dir:
    raise PermissionError("Path escapes the allowed directory.")
```

```javascript
// Node — path.resolve normalizes .. segments; check containment against the resolved base.
const baseDir = path.resolve(allowedRoot);
const resolved = path.resolve(baseDir, userSuppliedName);
if (!resolved.startsWith(baseDir + path.sep)) {
  throw new Error("Path escapes the allowed directory.");
}
```

The trailing separator in the `startsWith`/prefix check matters: without it, `/allowed-evil`
would incorrectly pass a containment check against base dir `/allowed`.

## Prefer an identifier over a raw path

Where the use case allows it, don't accept a filesystem path from the client at all — accept an
opaque id (a database key, a content hash) and look up the real path server-side from a table you
control. This removes the traversal surface entirely rather than defending against it. This is the
same pattern dependably's own blob storage uses: keys are always constructed from validated
components (ecosystem, package name, version, hash), never from a raw client-supplied path.

## Symlink following (CWE-59/61/65)

Canonicalizing with `realpath`/`GetFullPath` (which follow symlinks to their target) before the
containment check also closes the symlink-following variant: an attacker who can place a symlink
inside the allowed directory pointing outside it is caught by the same check, because the
canonical resolved path — not the symlink's location — is what gets validated.

## Reject dangerous inputs outright

Beyond the canonicalize-and-verify check, reject upload/access requests where the supplied name:

- Contains a null byte (`\0`) — historically used to truncate a validated extension check.
- Is an absolute path when a relative one was expected.
- Resolves to a special file (device file, named pipe) rather than a regular file, if your
  platform's file APIs distinguish these.

## Verify

1. Reproduce the original payload (`../../../etc/passwd`, an absolute path, an encoded
   `%2e%2e%2f` variant, or a symlink pointing outside the base dir) against the fixed code path
   and confirm it is rejected rather than resolved.
2. Add a regression test asserting the containment check specifically — not just that "normal"
   filenames still work, but that a `../`-bearing name is rejected with the expected error, not a
   500 or a silent pass-through.
3. Run the project's test suite.
4. Re-run whatever SAST/DAST tool originally flagged the finding, or re-scan the dependency
   through dependably if the traversal was in a third-party package (`OSV_ID`, `PACKAGE_PURL`).
