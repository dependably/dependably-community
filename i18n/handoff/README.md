# Translation Handoff Package

This package contains all translatable strings from the Dependably application, prepared for professional translation into French (`fr`).

## Contents

| File | Description |
|------|-------------|
| `frontend.en.xlf` | UI strings exported from `web/src/locales/en.json` |
| `backend.en.xlf` | Backend/server strings exported from `src/Dependably/Resources/SharedResource.resx` |
| `glossary.md` | Approved term list — must be followed (see below) |

## Target locale

**French** (`fr`). The XLIFF files have `srcLang="en"` and `trgLang="fr"`. Do not translate regional variants (`fr-CA`, `fr-BE`); deliver standard French suitable for a global audience.

## Tools

Use any CAT (Computer-Assisted Translation) tool that supports **XLIFF 2.0**, for example:

- [OmegaT](https://omegat.org/) (free, open source)
- [memoQ](https://memoq.com/)
- [Phrase](https://phrase.com/) (formerly Memsource)
- [Crowdin](https://crowdin.com/)
- [Lokalize](https://userbase.kde.org/Lokalize) (free, open source)

XLIFF 1.2 tools will not parse these files correctly. Verify your tool supports XLIFF 2.0 before starting.

## How to translate

Each string is a `<unit>` element with a `<source>` (the English original) and an empty `<target/>`. Fill in the `<target>` element with the French translation:

**Before:**
```xml
<unit id="packages.list.empty.title">
  <segment>
    <source>No packages found</source>
    <target/>
  </segment>
</unit>
```

**After:**
```xml
<unit id="packages.list.empty.title">
  <segment>
    <source>No packages found</source>
    <target>Aucun paquet trouvé</target>
  </segment>
</unit>
```

Translate the content of `<source>` into `<target>`. Do not modify:

- The `<unit id="...">` attribute values (these are key identifiers).
- The `<source>` elements themselves.
- The XLIFF file structure or namespace declarations.
- Placeholder tokens in curly braces, e.g. `{user}`, `{org}`, `{count}`. These must appear verbatim in the translated string.

## Glossary

The file `glossary.md` in this package defines:

- **Do-not-translate terms** — product names, protocol terms, and technical identifiers that must appear unchanged in the French output (e.g. "Dependably", "npm", "PURL", "SBOM").
- **Preferred French terms** — for concepts like "package → paquet", "token → jeton", "audit log → journal d'audit". Use these consistently throughout both files.

Following the glossary is mandatory. Reviewers will flag any deviation.

## Return format

Return the completed XLIFF files with all `<target>` elements filled in. File names should be:

- `frontend.fr.xlf`
- `backend.fr.xlf`

If your CAT tool produces a single merged file, that is also acceptable — include it alongside the split files or in place of them with a note.

Deliver as a `.zip` archive containing the translated files and any translation memory (`.tmx`) or termbase (`.tbx`) produced during translation. These artefacts help future update rounds.

## Import process

Once translated files are received, a developer imports them with:

```bash
i18n/scripts/i18n-import.sh path/to/frontend.fr.xlf
i18n/scripts/i18n-import.sh path/to/backend.fr.xlf
```

The import script extracts `<target>` values and writes them into the appropriate source files (`web/src/locales/fr.json` and `src/Dependably/Resources/SharedResource.fr.resx`). CI validation then runs to confirm no keys are missing.

## Scope and context

Dependably is a self-hosted private artifact repository. It lets development teams host their own npm, PyPI, and NuGet packages, control access via tokens and roles, and monitor package vulnerabilities. The intended users are software engineers and DevOps practitioners.

**Tone:** Professional and direct. Avoid overly formal legal language. The UI is a developer tool; users are technically literate.

**String types you will encounter:**
- Navigation labels and button text (short, imperative)
- Form field labels and placeholder hints
- Empty state messages (explanatory, slightly longer)
- Error messages (clear, actionable)
- Success confirmations
- Table column headers (very short, often a single noun)

## Questions

If a string is ambiguous or context is unclear, flag it with a comment in the XLIFF `<note>` element rather than guessing:

```xml
<unit id="packages.detail.yanked">
  <notes>
    <note category="translator">Does "yanked" mean the package was deleted or just unpublished?</note>
  </notes>
  <segment>
    <source>This version has been yanked.</source>
    <target/>
  </segment>
</unit>
```

Developer review will resolve any flagged items before the translation is merged.
