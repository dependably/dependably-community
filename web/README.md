# Dependably web frontend (Svelte + Vite)

## Development

```bash
npm install

# Dev server (Vite, hot reload)
npm run dev

# Production build — outputs into ../src/Dependably/wwwroot
npm run build
```

> **Build gotcha:** `npm run build` empties **all** of `src/Dependably/wwwroot`,
> including the tracked `wwwroot/swagger/` assets. Restore them after building:
> `git checkout -- src/Dependably/wwwroot/swagger`

## Quality checks

```bash
npm run lint        # ESLint over src
npm run lint:css    # stylelint (enforces no-hex-in-components, see DESIGN.md)
npm run check       # svelte-check
npm run format      # prettier --write src
```

## Unit tests (Vitest)

```bash
npm test                 # vitest run
npm run test:coverage    # with coverage
```

## E2E tests (Playwright)

```bash
# Install Playwright browsers (first time)
npx playwright install chromium

# Run E2E suite (starts the app automatically)
npm run e2e

# Interactive UI mode
npm run e2e:ui

# Debug a specific spec
npm run e2e:debug -- specs/auth.spec.ts

# Show the HTML report from the last run
npm run e2e:report
```

The suite boots the app with an ephemeral SQLite database and blob store in a temp directory. No cleanup needed — the OS recycles the temp dir on reboot.

Set `E2E_ADMIN_PASSWORD` env var to override the admin password used for seeding (default: `E2eTestPassword123!`).

## SBOM

```bash
npm run sbom        # CycloneDX → sbom-frontend.json (gitignored)
```
