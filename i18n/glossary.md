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

## English source conventions

The English source is **Canadian English** (`en-CA`). It is the authoritative copy every other
locale is translated from, so its variant is a project decision rather than an author's habit.

There is one English string store, so `en-CA` is the spelling every English reader sees regardless
of their region — `en-GB` and `en-US` readers get Canadian spelling with their own date, time and
number formatting (see [README.md](README.md) → Locale tags). Splitting the copy per region would
mean maintaining parallel English catalogues for a handful of words, which is not worth it; the
formatting is where the regional difference actually matters.

| Rule | Use | Not |
|------|-----|-----|
| `-re` endings | centre, metre | center, meter |
| `-our` endings | behaviour, colour, favour | behavior, color, favor |
| `-ment` after a doubled-L verb | enrolment, instalment | enrollment, installment |
| Latin `-fact` | artefact | artifact |
| `-ize` / `-yze` (Canadian, not British `-ise`/`-yse`) | organization, analyze, authorize | organisation, analyse, authorise |
| `licence` (noun) / `license` (verb) | licence policy, blocked licences | license policy, blocked licenses |

The `-ize` row is where Canadian and British English part company, and it is deliberate: `-ize`
matches the API and database field names (`organization`, `license_*`), so prose and payload stay
spelled the same way.

The `licence` row is the one place prose deliberately departs from the payload: SPDX, the API,
and the schema all spell the field `license`, but in en-CA prose the noun is `licence` — the UI
writes "licence policy" over an API that says `license_policy_mode_changed`. Machine-readable
contexts are exempt: an SPDX field name, a `license_*` column, an API enum value, or a code
snippet quoting one is a literal and keeps `license` exactly as the machine spells it.

Three categories deliberately keep their non-Canadian spelling, because they are names rather
than prose:

- **`license`** in machine-readable contexts — the SPDX field name and the API/DB column name,
  whenever the string quotes the literal rather than writing prose.
- **"CISA Known Exploited Vulnerabilities Catalog"** — the proper name of the CISA catalog.
- **"analyzer"** in SARIF contexts — SARIF's own term for the tool that produced a result.

**Apostrophes** are the ASCII `'` (U+0027), in every locale. Both stores settled on it, and a mix
means the same word renders two ways on adjacent screens. Enforced by `i18n-validate.js`.

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

**Punctuation:** The French locale targets Canadian French (OQLF conventions): a non-breaking space (U+00A0, never a regular space) before `:` and inside guillemets (`« … »`), and **no** space before `;`, `!`, or `?`. This differs from France-French typography, which spaces all four marks — configure CAT tools for fr-CA accordingly. `i18n-validate.js` enforces all three rules: a NBSP and a plain space are indistinguishable in a diff, so this is not a rule review can be expected to catch.

**Capitalization:** French uses significantly less title-case than English. Page titles and navigation items should use sentence case in French. Example: "Paramètres de l'organisation" not "Paramètres De L'Organisation".
