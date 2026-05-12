# Svelte + Vite

## E2E Tests

```bash
# Install Playwright browsers (first time)
npx playwright install chromium

# Run E2E suite (starts the app automatically)
npm run e2e

# Interactive UI mode
npm run e2e:ui

# Debug a specific spec
npm run e2e:debug -- specs/auth.spec.ts
```

The suite boots the app with an ephemeral SQLite database and blob store in a temp directory. No cleanup needed — the OS recycles the temp dir on reboot.

Set `E2E_ADMIN_PASSWORD` env var to override the admin password used for seeding (default: `E2eTestPassword123!`).
