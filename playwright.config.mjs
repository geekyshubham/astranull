import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.BASE_URL ?? 'http://127.0.0.1:0';

export default defineConfig({
  testDir: '.',
  testMatch: [
    'tests/e2e/journeys/**/*.spec.mjs',
    'tests/e2e/provenance/**/*.spec.mjs',
    'tests/e2e/state/**/*.spec.mjs',
    'tests/a11y/**/*.spec.mjs',
  ],
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [['list']],
  use: {
    ...devices['Desktop Chrome'],
    baseURL,
    headless: true,
    launchOptions: {
      channel: undefined,
    },
    trace: 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        browserName: 'chromium',
        headless: true,
      },
    },
  ],
});