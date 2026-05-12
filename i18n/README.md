# Internationalization Architecture

This document describes how Dependably handles locale selection, string storage, translation handoff, and runtime formatting across its backend (.NET) and frontend (Svelte) layers.

## Locale codes

Dependably uses [BCP 47](https://www.rfc-editor.org/rfc/rfc5646) locale tags throughout.

| Tag | Language | Status |
|-----|----------|--------|
| `en` | English | Source language — authoritative |
| `fr` | French | Supported |

**Regional variants** (e.g. `en-US`, `fr-CA`) are not modeled separately. If a request arrives with a regional tag, it is resolved to the base language. `fr-CA` → `fr`, `en-GB` → `en`. Applications should not emit region-specific strings unless the region genuinely requires different wording.

Adding a new locale requires updating both backend and frontend registration. See [adding-a-locale.md](adding-a-locale.md) for the full checklist.

## File formats

### Backend — .NET ResX

Backend-facing strings (validation messages, server-rendered error text, log-facing labels) live in `.resx` XML resource files under `src/Dependably/Resources/`.

```
src/Dependably/Resources/
  SharedResource.resx          # English source (authoritative)
  SharedResource.fr.resx       # French translation
```

The `.resx` format is standard .NET XML. Each string is a `<data>` element:

```xml
<data name="packages.list.empty.title" xml:space="preserve">
  <value>No packages found</value>
</data>
```

Access via `IStringLocalizer<SharedResource>` injected into controllers or services. The localizer selects the `.resx` file for the current request culture automatically.

### Frontend — JSON

UI strings live in locale JSON files under `web/src/locales/`:

```
web/src/locales/
  en.json    # English source (authoritative)
  fr.json    # French translation
```

Keys are hierarchical dot-separated paths represented as nested JSON objects:

```json
{
  "packages": {
    "list": {
      "empty": {
        "title": "No packages found",
        "hint": "Push your first package to get started."
      }
    }
  }
}
```

The svelte-i18n library flattens nested keys to dotted paths at runtime, so `$t('packages.list.empty.title')` works regardless of nesting depth.

### Handoff format — XLIFF 2.0

Translation handoff to external translators uses [XLIFF 2.0](https://docs.oasis-open.org/xliff/xliff-core/v2.0/xliff-core-v2.0.html). XLIFF is widely supported by CAT tools (OmegaT, memoQ, Phrase, Crowdin, etc.).

Export files are placed in `i18n/handoff/`:

```
docs/i18n/handoff/
  frontend.en.xlf     # Exported from web/src/locales/en.json
  backend.en.xlf      # Exported from src/Dependably/Resources/SharedResource.resx
  README.md           # Instructions for translators
```

Generate the handoff bundle:

```bash
i18n/scripts/i18n-export.sh
```

Import a completed translation:

```bash
i18n/scripts/i18n-import.sh path/to/delivered.xlf
```

## Source of truth

`en` is the authoritative source language. Every other locale file is derived from it. The CI validation script (`i18n/scripts/i18n-validate.js`) enforces this: any key present in `en` but absent in a translated locale is a build error. Keys present in a translated locale but absent in `en` are warnings (orphaned keys to be cleaned up).

Never add a key to a locale file without first adding it to `en`. Never remove a key from `en` without also removing it from all locale files.

## Key naming convention

Keys use **hierarchical dot-separated semantic identifiers**. The hierarchy should reflect the location and purpose of the string, not the component tree.

```
<domain>.<context>.<element>.<property>
```

Examples:

| Key | String |
|-----|--------|
| `common.actions.save` | Save |
| `common.actions.cancel` | Cancel |
| `packages.list.empty.title` | No packages found |
| `packages.list.empty.hint` | Push your first package to get started. |
| `packages.detail.version.yanked` | This version has been yanked. |
| `auth.login.error.invalid_credentials` | Invalid username or password. |
| `settings.tokens.create.label` | Token name |
| `org.members.role.owner` | Owner |
| `errors.upload.too_large` | File exceeds the maximum upload size. |

Rules:

- All lowercase, words separated by underscores within a segment, segments separated by dots.
- Keep keys stable. Renaming a key is a breaking change that requires updating all locale files, XLIFF exports, and any code references.
- Prefer semantic names that describe intent, not content. Use `auth.login.error.invalid_credentials` not `auth.login.error.wrong_password_message`.
- Do not encode formatting in keys (no `_html`, `_bold` suffixes). Use svelte-i18n message parameters for interpolation.

## Fallback chain

Runtime locale resolution follows this chain:

```
Requested locale → Base language → en
```

Examples:

- Request with `fr-CA` → try `fr-CA` resources → fall back to `fr` → fall back to `en`
- Request with `de` (unsupported) → fall back to `en` immediately
- Request with `fr` → serve `fr` (no fallback needed)

The fallback ensures the UI is never blank even when a translation is incomplete. During active translation work, it is acceptable for a locale to render some strings in English.

## Backend locale selection

The backend uses ASP.NET Core's `RequestLocalizationMiddleware`. Configuration lives in `Program.cs`:

```csharp
builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    var supported = new[] { "en", "fr" };
    options.DefaultRequestCulture = new RequestCulture("en");
    options.SupportedCultures = supported.Select(c => new CultureInfo(c)).ToList();
    options.SupportedUICultures = options.SupportedCultures;
});
```

Culture providers are evaluated in this order (first match wins):

1. **Query string** — `?ui-culture=fr` (useful for testing without changing browser settings)
2. **Cookie** — `.AspNetCore.Culture` cookie value, e.g. `c=fr|uic=fr`
3. **Accept-Language header** — standard browser locale negotiation

The cookie format is the same as the frontend locale switcher writes, so changing the locale in the UI propagates to server-rendered responses automatically.

## Frontend locale selection

The frontend uses the [svelte-i18n](https://github.com/kaisermann/svelte-i18n) library.

### Setup

Locale registration and initialization live in `web/src/i18n/index.js`:

```js
import { register, init, getLocaleFromCookie } from 'svelte-i18n';

register('en', () => import('../locales/en.json'));
register('fr', () => import('../locales/fr.json'));

init({
  fallbackLocale: 'en',
  initialLocale: getLocaleFromCookie('locale') ?? 'en',
});
```

Locale files are loaded lazily — only the active locale is fetched on page load.

### Usage in components

```svelte
<script>
  import { t } from 'svelte-i18n';
</script>

<h1>{$t('packages.list.empty.title')}</h1>
<p>{$t('packages.list.empty.hint')}</p>
```

With interpolation:

```svelte
<p>{$t('packages.detail.uploaded_by', { values: { user: pkg.pushedBy } })}</p>
```

The corresponding source string uses `{user}` as a placeholder:

```json
{ "packages": { "detail": { "uploaded_by": "Uploaded by {user}" } } }
```

### Locale switcher

The locale switcher (`web/src/lib/LocaleSwitcher.svelte`) writes the selected locale to a `locale` cookie and reloads the page so both the frontend and the `.AspNetCore.Culture` cookie (set server-side) stay in sync. The switcher exposes all registered locales:

```js
const locales = [
  { code: 'en', label: 'English' },
  { code: 'fr', label: 'Français' },
];
```

## Format helpers

Date, number, and relative-time formatting lives in `web/src/lib/format.js`. All helpers accept a locale parameter defaulting to the current svelte-i18n locale.

```js
// Dates
formatDate(date, locale)           // "28 April 2026" / "28 avril 2026"
formatDateTime(date, locale)       // "28 April 2026, 14:32" / ...

// Numbers and sizes
formatNumber(n, locale)            // "1,234" / "1 234"
formatBytes(bytes, locale)         // "4.2 MB" / "4,2 Mo"

// Relative time
formatRelative(date, locale)       // "3 days ago" / "il y a 3 jours"
```

Internally these use `Intl.DateTimeFormat`, `Intl.NumberFormat`, and `Intl.RelativeTimeFormat` — all built into modern browsers, no extra dependencies required. Locales are passed explicitly rather than read from a global so helpers remain testable in isolation.

## CI validation

The `i18n/scripts/i18n-validate.js` script runs as part of the CI pipeline. It:

- Flattens all keys from `en.json` and compares against each translated locale file.
- Reports missing keys as `ERROR` (exits 1).
- Reports orphaned keys as `WARNING` (exits 0).
- Checks backend `.resx` files for the same conditions.

```bash
node i18n/scripts/i18n-validate.js
```

## Updating translations

### Adding a new string

1. Add the key and English value to `web/src/locales/en.json` (frontend) or `src/Dependably/Resources/SharedResource.resx` (backend).
2. Add the translated value to every locale file (`fr.json`, `SharedResource.fr.resx`, etc.).
3. Run `node i18n/scripts/i18n-validate.js` — the script exits non-zero if any locale is missing the new key.

If you don't have a translation ready, copy the English value as a temporary placeholder. The fallback chain will serve English anyway, but having an explicit entry prevents validation errors.

### Changing an existing string

Update the English source first (`en.json` or `SharedResource.resx`), then update all locale files to match the new meaning. If the meaning change is significant enough to invalidate the existing translation, prefix the locale values with `[XX]` so they are visually flagged until a proper translation is in place.

### Removing a string

Remove the key from `en.json` / `SharedResource.resx` and from all locale files. `i18n-validate.js` reports orphaned keys (present in a locale but absent from `en`) as warnings — clean these up to keep the locale files tidy.

### Regenerating XLIFF handoff files

After adding or changing source strings, regenerate the handoff bundle for translators:

```bash
i18n/scripts/i18n-export.sh
```

The export is idempotent. Commit the updated `.xlf` files alongside the source changes.

### Importing a completed translation

When a translator returns a completed XLIFF file, import it with:

```bash
i18n/scripts/i18n-import.sh path/to/frontend.fr.xlf
i18n/scripts/i18n-import.sh path/to/backend.fr.xlf
```

Then run the validator to confirm completeness:

```bash
node i18n/scripts/i18n-validate.js
```

## Related documents

- [glossary.md](glossary.md) — Approved term list for translators
- [handoff/README.md](handoff/README.md) — Translator handoff package instructions
- [adding-a-locale.md](adding-a-locale.md) — Step-by-step guide to add a new locale
