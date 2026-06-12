# Adding a New Locale

This guide walks through every step required to add a new language to Dependably. Complete each step in order — later steps depend on earlier ones.

Cross-references: [i18n/README.md](README.md) · [glossary.md](glossary.md) · [handoff/README.md](handoff/README.md) · [i18n/scripts/i18n-validate.js](scripts/i18n-validate.js)

---

## Step 1 — Choose a locale code

Pick a [BCP 47](https://www.rfc-editor.org/rfc/rfc5646) language tag. Use the base language tag unless there is a compelling reason for a regional variant.

- **Prefer:** `de`, `ja`, `pt`, `es`
- **Avoid unless necessary:** `de-AT`, `pt-BR` (regional variants)

Regional variants are supported by the fallback chain (`pt-BR` → `pt` → `en`), but maintaining separate variant files doubles translation work. Discuss with stakeholders before committing to a variant.

Consult [i18n/README.md](README.md#locale-codes) for the full locale policy.

Throughout this guide, replace `xx` with your chosen locale code.

---

## Step 2 — Register the locale in the backend

Open `src/Dependably/Program.cs` and add your locale to the `RequestLocalizationOptions` configuration. Find the block that reads:

```csharp
builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    var supported = new[] { "en", "fr" };
    options.DefaultRequestCulture = new RequestCulture("en");
    options.SupportedCultures = supported.Select(c => new CultureInfo(c)).ToList();
    options.SupportedUICultures = options.SupportedCultures;
});
```

Add your locale tag to the `supported` array:

```csharp
var supported = new[] { "en", "fr", "xx" };
```

---

## Step 3 — Register the locale in the frontend

### 3a. Register in i18n initializer

Open `web/src/i18n/index.js` and add a `register` call for the new locale:

```js
register('xx', () => import('../locales/xx.json'));
```

Place it alongside the existing `register('en', ...)` and `register('fr', ...)` lines.

### 3b. Add to the locale switcher

Open `web/src/lib/locale.js`. Find the exported `locales` array and add an entry:

```js
export const locales = [
  { code: 'en', label: 'English' },
  { code: 'fr', label: 'Français' },
  { code: 'xx', label: 'Your Language Name' }  // add this
]
```

Use the native name of the language (e.g. `Deutsch` for German, `日本語` for Japanese), not the English name.

---

## Step 4 — Scaffold placeholder translation files

Create placeholder files by copying the English source. Prefix every string value with `[XX]` so that untranslated strings are immediately visible during QA.

### Frontend

```bash
node - web/src/locales/en.json web/src/locales/xx.json <<'EOF'
const fs = require('fs');
const [,, src, dst] = process.argv;
const obj = JSON.parse(fs.readFileSync(src, 'utf8'));
function prefix(o) {
  if (typeof o === 'string') return '[XX] ' + o;
  const r = {};
  for (const [k, v] of Object.entries(o)) r[k] = prefix(v);
  return r;
}
fs.writeFileSync(dst, JSON.stringify(prefix(obj), null, 2) + '\n', 'utf8');
EOF
```

### Backend

```bash
cp src/Dependably/Resources/SharedResource.resx src/Dependably/Resources/SharedResource.xx.resx
```

Then open `SharedResource.xx.resx` in an editor and add `[XX] ` as a prefix to every `<value>` element. For example:

```xml
<!-- Before -->
<data name="packages.list.empty.title" xml:space="preserve">
  <value>No packages found</value>
</data>

<!-- After -->
<data name="packages.list.empty.title" xml:space="preserve">
  <value>[XX] No packages found</value>
</data>
```

The `[XX]` prefix makes untranslated strings visually obvious in the UI during development and QA.

---

## Step 5 — Validate the scaffold

Run the validation script to confirm the scaffold has all required keys and no missing entries:

```bash
node i18n/scripts/i18n-validate.js
```

Expected output for a complete scaffold:

```
Validating frontend locales (source: web/src/locales/en.json)
────────────────────────────────────────────────────────────
  Source key count: N
  xx: OK (N keys)

Validating backend resources (source: src/Dependably/Resources/SharedResource.resx)
────────────────────────────────────────────────────────────
  Source key count: N
  xx: OK (N keys)

────────────────────────────────────────────────────────────
All locale files are complete.
```

If you see any `ERROR: Missing key` lines, the scaffold is incomplete — re-run the scaffolding commands above.

---

## Step 6 — Generate the handoff bundle

Export the English source strings to XLIFF 2.0 for translator delivery:

```bash
i18n/scripts/i18n-export.sh
```

This writes two files to `i18n/handoff/`:

- `frontend.en.xlf` — UI strings
- `backend.en.xlf` — backend strings

Package these two files together with `i18n/glossary.md` and send to the translation team. The translator README at [i18n/handoff/README.md](handoff/README.md) explains the handoff format and glossary requirements — include it in the delivery package.

The export is idempotent — re-running produces the same output.

---

## Step 7 — Import delivered translations

Once the translator returns completed XLIFF files (`frontend.xx.xlf` and `backend.xx.xlf`), import them:

```bash
i18n/scripts/i18n-import.sh path/to/frontend.xx.xlf
i18n/scripts/i18n-import.sh path/to/backend.xx.xlf
```

The import script:
1. Parses the `<target>` elements from the XLIFF file.
2. Writes the translated values into `web/src/locales/xx.json` (replacing `[XX]` placeholder values) and `src/Dependably/Resources/SharedResource.xx.resx`.

After import, run the validator again to confirm no keys are missing:

```bash
node i18n/scripts/i18n-validate.js
```

Remove any remaining `[XX]` prefixes that the translator may have left if they were unable to translate a string — leave those strings in English for the fallback chain to handle.

---

## Step 8 — QA walkthrough

Before shipping, perform a full walkthrough of the UI in the new locale:

- [ ] Set browser language to `xx` and verify the UI renders in the new locale throughout (not just the landing page).
- [ ] Switch locale via the locale switcher — confirm the selection persists across page reloads.
- [ ] Check every page listed in `web/src/pages/` for untranslated strings (no `[XX]` prefixes remaining).
- [ ] Verify all number, date, and relative-time formats render correctly using locale-appropriate conventions (decimal separators, date order, etc.).
- [ ] Test all error messages — submit invalid forms, trigger upload size limit errors, attempt unauthorized actions.
- [ ] Confirm do-not-translate terms (Dependably, npm, NuGet, PyPI, PURL, etc.) appear unchanged.
- [ ] Spot-check the glossary: "token", "registry", "audit log", etc. use the approved translations.
- [ ] Test the backend locale selection: send a request with `?ui-culture=xx` and confirm server-rendered error responses use the new locale.
- [ ] Run the full test suite to confirm nothing is broken: `dotnet test --filter "Category!=Integration"`

---

## Step 9 — Ship

Once QA is complete:

1. Open a merge request with all changed files:
   - `src/Dependably/Program.cs` (locale registration)
   - `src/Dependably/Resources/SharedResource.xx.resx` (backend translations)
   - `web/src/locales/xx.json` (frontend translations)
   - `web/src/i18n/index.js` (locale registration)
   - `web/src/lib/locale.js` (switcher entry)

2. The CI pipeline runs `node i18n/scripts/i18n-validate.js` automatically. The MR cannot merge if there are missing keys.

3. After merge, update [i18n/README.md](README.md#locale-codes) to list the new locale in the supported locales table.

---

## Maintaining the locale going forward

When new source strings are added to `en.json` or `SharedResource.resx`, run `node i18n/scripts/i18n-validate.js` to detect gaps. New keys that appear in `en` but not in `xx` will be reported as errors. Use `i18n/scripts/i18n-export.sh` to generate a delta handoff if a full re-translation is not practical — most CAT tools support incremental XLIFF updates.
