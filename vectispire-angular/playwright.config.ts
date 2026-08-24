import { defineConfig, devices } from '@playwright/test';

// Ensure proxy is bypassed for local test server requests
process.env['NO_PROXY'] = 'localhost,127.0.0.1,::1,*';
process.env['HTTP_PROXY'] = '';
process.env['HTTPS_PROXY'] = '';
process.env['http_proxy'] = '';
process.env['https_proxy'] = '';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 2 : 0,
  workers: process.env['CI'] ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:4280',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure'
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    }
  ],
  webServer: {
    command: 'npm run start --workspace @vectispire/frontend',
    url: 'http://localhost:4280',
    reuseExistingServer: true,
    timeout: 120 * 1000
  }
});
