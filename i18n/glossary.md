# Translator Glossary

This glossary defines approved terminology for Dependably translations. Translators must follow these conventions to ensure consistency across the UI and documentation. Where a French term is listed, use it — do not improvise alternatives.

## Do not translate

The following terms must appear unchanged in all locales. They are either proper nouns, technical identifiers, or protocol-level terms that have no meaningful translation.

### Product and ecosystem names

| Term | Notes |
|------|-------|
| Dependably | Product name |
| npm | JavaScript package manager and registry |
| NuGet | .NET package manager and registry |
| PyPI | Python Package Index |
| OCI | Open Container Initiative |
| Docker | Container platform name |

### Package format and protocol terms

| Term | Notes |
|------|-------|
| tarball | A `.tar.gz` archive; used as-is in package contexts |
| manifest | OCI/Docker image manifest document |
| lockfile | Dependency lockfile (e.g. `package-lock.json`, `Pipfile.lock`) |
| wheel | Python `.whl` binary distribution format |
| sdist | Python source distribution format |
| nupkg | NuGet package file format |
| PURL | Package URL identifier (e.g. `pkg:pypi/requests@2.31.0`) |
| SBOM | Software Bill of Materials |

### API and HTTP terms (machine-readable contexts)

These terms must not be translated when they appear as literal values that a machine or developer reads — for example, in code snippets, configuration examples, or error messages that quote an HTTP header name.

| Term | Notes |
|------|-------|
| Bearer | HTTP Authorization scheme |
| Authorization | HTTP header name |
| Content-Type | HTTP header name |
| HTTP status codes | 404, 429, 413, etc. — always numeric |
| SHA-256 | Hash algorithm name |
| JWT | JSON Web Token |
| OSV | Open Source Vulnerabilities database identifier format |

### Identifiers

| Term | Notes |
|------|-------|
| org slug | The URL-safe identifier of an organization (e.g. `acme-corp`). The word "slug" may be left in English or replaced with a parenthetical in surrounding prose, but the concept name `org slug` should not be translated in UI labels. |
| scope | npm package scope (`@scope/package`). Do not translate the word "scope" when it refers to the `@org/` prefix in npm package names. |
| OSV ID | Open Source Vulnerabilities identifier (e.g. `GHSA-xxxx-xxxx-xxxx`). Always displayed verbatim. |

---

## French preferred terms

Use the following French terms consistently. When a term is listed here, it supersedes any alternative a CAT tool might suggest.

| English | French | Notes |
|---------|--------|-------|
| package | paquet | Use throughout. Do not use "paquetage". |
| registry | registre | "registre de paquets" for the full phrase. |
| upstream | source amont | Use the full phrase "source amont" in prose. In tight UI contexts (table headers, badges) "amont" alone is acceptable. |
| token | jeton | Authentication or API token. |
| audit log | journal d'audit | Always use both words; do not shorten to "journal" alone when the audit meaning is important. |
| organization | organisation | Note the French spelling (no 'z'). |
| permission | autorisation | |
| role | rôle | Note the circumflex. |
| owner | propriétaire | |
| admin | administrateur | In full prose. In UI labels where space is constrained, "admin" (unchanged) is acceptable. |
| member | membre | |
| vulnerability | vulnérabilité | |
| severity | gravité | |
| allowlist | liste d'autorisation | |
| blocklist | liste de blocage | |
| activity | activité | |
| settings | paramètres | |
| sign out | se déconnecter | Button label and link text. |
| sign in | se connecter | |
| version | version | Same in both languages. |
| download | télécharger (verb), téléchargement (noun) | |
| upload | téléverser (verb), téléversement (noun) | |
| checksum | somme de contrôle | |
| retention | rétention | As in "retention policy". |
| invite | invitation | Noun. Verb: "inviter". |
| push | publier | In the context of pushing a package to the registry. |
| pull | récupérer | In the context of pulling/downloading a package. |
| scan | analyser (verb), analyse (noun) | Vulnerability scan. |
| report | rapport | Vulnerability report or scan result. |

---

## Usage notes

**Gendered nouns:** French nouns have grammatical gender. Use consistent gender for compound phrases. Example: "un jeton d'accès" (masculine), "une liste d'autorisation" (feminine).

**Formal register:** Use the formal "vous" form for all UI text that addresses the user directly. Never use "tu".

**Placeholders:** String placeholders such as `{user}`, `{org}`, `{count}` must be preserved exactly as-is in translated strings. Do not translate placeholder names.

**Punctuation:** French typography uses a non-breaking space before double punctuation marks (`:`, `;`, `!`, `?`). CAT tools that handle French correctly will insert these automatically. If inserting manually, use the Unicode non-breaking space character (U+00A0), not a regular space.

**Capitalization:** French uses significantly less title-case than English. Page titles and navigation items should use sentence case in French. Example: "Paramètres de l'organisation" not "Paramètres De L'Organisation".
