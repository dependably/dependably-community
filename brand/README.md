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

## React component (drop-in)

For sharp rendering at any size, use the inline SVG component instead of
an `<img>` tag:

```tsx
// components/Logo.tsx
type LogoProps = {
  size?: number;
  /** When true, renders white-on-dark with a brighter accent. */
  inverse?: boolean;
  className?: string;
};

export function DependablyMark({ size = 32, inverse = false, className }: LogoProps) {
  const fg = inverse ? '#faf8f3' : '#0e1a17';
  const accent = inverse ? '#3aa88f' : '#1f6f5c';
  const check = inverse ? '#0e1a17' : '#faf8f3';
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      role="img"
      aria-label="Dependably"
      className={className}
    >
      <path
        d="M32 32 L14 14 M32 32 L50 14 M32 32 L32 54"
        stroke={fg}
        strokeWidth={4}
        strokeLinecap="round"
      />
      <circle cx="14" cy="14" r="5" fill={fg} />
      <circle cx="50" cy="14" r="5" fill={fg} />
      <circle cx="32" cy="54" r="5" fill={fg} />
      <circle cx="32" cy="32" r="9" fill={accent} />
      <path
        d="M28 32 L31 35 L37 28"
        stroke={check}
        strokeWidth={2.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function DependablyLockup({ size = 28, inverse = false }: LogoProps) {
  const fg = inverse ? '#faf8f3' : '#0e1a17';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
      <DependablyMark size={size} inverse={inverse} />
      <span
        style={{
          fontFamily: 'Inter, -apple-system, system-ui, sans-serif',
          fontWeight: 700,
          fontSize: Math.round(size * 0.78),
          letterSpacing: '-0.02em',
          color: fg,
        }}
      >
        Dependably
      </span>
    </span>
  );
}
```

### Usage

```tsx
// Top-right corner of site chrome
<DependablyLockup size={26} />

// Login page hero
<DependablyMark size={120} inverse />

// Favicon fallback / small UI chip
<DependablyMark size={16} />
```

---

## Tailwind tokens (optional)

```js
// tailwind.config.js — extend.colors
colors: {
  ink: '#0e1a17',
  paper: '#faf8f3',
  accent: {
    DEFAULT: '#1f6f5c',
    bright: '#3aa88f',
    soft: '#e7f1ee',
  },
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
> existing logo usages with `<DependablyMark />` (small) and
> `<DependablyLockup />` (top-bar / footer / login). Do not introduce new
> colors — only `--ink`, `--paper`, `--accent`, `--accent-2`.
