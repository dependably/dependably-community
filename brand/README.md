# Dependably — Brand Handoff

A drop-in icon kit for the Dependably private package repository.
Mark direction: **Graph Node** — a verified hub linked to three satellite
nodes, reading as both a dependency graph and a "trusted source of truth".

---

## Files

```
brand/
├── dependably-mark.svg            ← primary (ink + teal hub)
├── dependably-mark-mono.svg       ← single-color, uses currentColor
├── dependably-mark-inverse.svg    ← for dark backgrounds
├── dependably-lockup.svg          ← horizontal mark + wordmark
├── favicon.ico                    ← 16/32/48 multi-size
└── png/
    ├── dependably-mark-16.png … 512.png
    ├── dependably-mark-inverse-180.png, 512.png
    └── apple-touch-icon.png       ← 180×180, ink bg, ready for iOS
```

## Color tokens

| Token        | Hex / value             | Use                                |
| ------------ | ----------------------- | ---------------------------------- |
| `--ink`      | `#0e1a17`               | Primary foreground / dark surfaces |
| `--paper`    | `#faf8f3`               | Primary background                 |
| `--accent`   | `#1f6f5c` (oklch .55 .10 165) | Verified hub, primary action |
| `--accent-2` | `#3aa88f`               | Accent on dark backgrounds         |

## Typography

- **Wordmark / UI:** Inter (700 for the wordmark, 400/500/600 elsewhere).
  Tracking `-0.02em` on the wordmark.
- **Monospace:** JetBrains Mono — package names, versions, hashes, audit
  log lines.

---

## Drop-in HTML for the `<head>`

```html
<link rel="icon" href="/brand/favicon.ico" sizes="any" />
<link rel="icon" type="image/svg+xml" href="/brand/dependably-mark.svg" />
<link rel="apple-touch-icon" href="/brand/png/apple-touch-icon.png" />
<link rel="manifest" href="/site.webmanifest" />
<meta name="theme-color" content="#0e1a17" />
```

## `site.webmanifest`

```json
{
  "name": "Dependably",
  "short_name": "Dependably",
  "icons": [
    { "src": "/brand/png/dependably-mark-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/brand/png/dependably-mark-512.png", "sizes": "512x512", "type": "image/png" }
  ],
  "theme_color": "#0e1a17",
  "background_color": "#faf8f3",
  "display": "standalone"
}
```

---

## Svelte component (drop-in)

For sharp rendering at any size, use an inline SVG component instead of
an `<img>` tag. The Dependably frontend is Svelte; in-app usages follow
the `.brand` pattern in `DESIGN.md` §5.1 and use the theme variables from
`web/src/app.css` (`currentColor` + `var(--accent)`) so the mark follows
light/dark mode automatically:

```svelte
<!-- DependablyMark.svelte -->
<script>
  export let size = 32
  /** When true, renders paper-on-ink with the brighter accent (for
      fixed-dark surfaces outside the theming system). */
  export let inverse = false
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 64 64"
  fill="none"
  role="img"
  aria-label="Dependably"
  style={inverse ? 'color:#faf8f3; --accent:#3aa88f' : undefined}
>
  <path
    d="M32 32 L14 14 M32 32 L50 14 M32 32 L32 54"
    stroke="currentColor"
    stroke-width="4"
    stroke-linecap="round"
  />
  <circle cx="14" cy="14" r="5" fill="currentColor" />
  <circle cx="50" cy="14" r="5" fill="currentColor" />
  <circle cx="32" cy="54" r="5" fill="currentColor" />
  <circle cx="32" cy="32" r="9" fill="var(--accent, #1f6f5c)" />
  <path
    d="M28 32 L31 35 L37 28"
    stroke="var(--bg, #faf8f3)"
    stroke-width="2.5"
    stroke-linecap="round"
    stroke-linejoin="round"
  />
</svg>
```

```svelte
<!-- DependablyLockup.svelte -->
<script>
  import DependablyMark from './DependablyMark.svelte'
  export let size = 28
  export let inverse = false
</script>

<span class="lockup" style={inverse ? 'color:#faf8f3' : undefined}>
  <DependablyMark {size} {inverse} />
  <span class="wordmark" style="font-size: {Math.round(size * 0.78)}px">Dependably</span>
</span>

<style>
  .lockup   { display: inline-flex; align-items: center; gap: 10px; }
  .wordmark {
    font-family: Inter, -apple-system, system-ui, sans-serif;
    font-weight: 700;
    letter-spacing: -0.02em;
  }
</style>
```

### Usage

```svelte
<!-- Navbar brand -->
<DependablyLockup size={26} />

<!-- Login page hero -->
<DependablyMark size={120} inverse />

<!-- Favicon fallback / small UI chip -->
<DependablyMark size={16} />
```

---

## CSS tokens (for non-Svelte consumers)

The app's full token set lives in `web/src/app.css`. For embedding the
brand elsewhere, the four brand tokens are:

```css
:root {
  --ink:      #0e1a17;
  --paper:    #faf8f3;
  --accent:   #1f6f5c;  /* oklch(0.55 0.10 165) */
  --accent-2: #3aa88f;  /* accent on dark backgrounds */
}
```

---

## Construction notes (so future edits stay on-system)

- All marks live on a **64-unit viewBox** with a **4-unit stroke** for the
  edges. Satellite node radius = 5; verified hub radius = 9.
- Stroke endpoints use `linecap="round"` so the mark stays crisp at 16px.
- The check inside the hub uses a **2.5-unit stroke** — do not reduce it
  further; it disappears at 16px.
- For favicons, the SVG is rasterized into a multi-size `.ico`
  (16/32/48) via the build step. Re-run that step if you change the SVG.

## Prompt for Claude Code

> Re-brand the app to "Dependably". Use `/brand/` as the source of truth
> for the icon and color tokens. Wire up the favicon and apple-touch-icon
> in the document head per the snippet in `brand/README.md`. Replace
> existing logo usages with the `DependablyMark` (small) and
> `DependablyLockup` (top-bar / footer / login) Svelte components from
> `brand/README.md`. Do not introduce new colors — only `--ink`,
> `--paper`, `--accent`, `--accent-2`.
