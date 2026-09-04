import { defineConfig, devices } from '@playwright/test';

// Ensure proxy is bypassed for local test server requests
process.env['NO_PROXY'] = 'localhost,127.0.0.1,::1,*';
process.env['HTTP_PROXY'] = '';
process.env['HTTPS_PROXY'] = '';
process.env['http_proxy'] = '';
process.env['https_proxy'] = '';

export default defineConfig({
  testDir: './e2e',
  // **These suites are not independent, and running them as if they were is what made them
  // flaky.** They share one account and one client address, so they share both of the server's
  // anti-brute-force counters: the address bucket in `LoginRateLimitFilter` and the per-account
  // window in `LoginThrottle`. Eleven browser sign-ins inside a minute is a burst by the only
  // definition the server has.
  //
  // Established by running, not by reading — three runs against one control plane:
  // parallel with a raised address limit still failed eight; serial with the shipped limit of ten
  // failed four, every one of them on a 429; serial with the limit raised passed all eleven. Both
  // variables are real, so both are set here and in the nightly job.
  //
  // The cost is wall-clock: the whole set takes about seven seconds serially, which is not a
  // trade worth thinking about.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 2 : 0,
  reporter: 'html',
  // **Deux minutes, et non trente secondes.** Ces suites parlent au vrai serveur : un cas
  // commence par une connexion complète — chargement du bundle, page de connexion, éventuel
  // changement de mot de passe imposé, puis navigation — et le serveur de développement compile
  // les chunks paresseux à la première visite de chaque page. Le défaut coupait au milieu, et
  // l'échec se lisait « page fermée » à l'intérieur du helper de connexion, ce qui n'apprend rien
  // sur la cause. Un délai trop court ne rend pas la suite plus rapide, il la rend menteuse.
  timeout: 120_000,

  use: {
    // **Every request in the suites is relative to this**, including `page.request` calls to the
    // API. They used to name `http://127.0.0.1:3180` outright, which tied the suites to one port
    // and to one machine: a run against a second instance — or on a developer box already serving
    // on 3180 — sent fifteen failed logins at whatever happened to be listening.
    //
    // Relative paths go through the dev server's proxy (`proxy.conf.json`), so the API's address
    // is configured in exactly one place.
    baseURL: 'http://localhost:4280',

    // **La langue est fixée, parce qu'elle décidait des assertions sans le dire.** Le service
    // i18n lit `localStorage`, puis retombe sur `navigator.language` : dans un contexte neuf il
    // n'y a rien en réserve, donc c'est la locale du navigateur qui choisit. Les suites cherchent
    // « Issues », « Settings », « Audit log » — elles ne passaient que parce que la locale par
    // défaut de Playwright est anglaise, et une machine réglée en français les aurait toutes
    // fait échouer sur des libellés introuvables, sans que rien ne nomme la cause.
    locale: 'en-US',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure'
  },
  projects: [
    {
      name: 'chromium',
      // **Deux minutes, et non trente secondes.** Ces suites parlent au vrai serveur : un cas
  // commence par une connexion complète — chargement du bundle, page de connexion, éventuel
  // changement de mot de passe imposé, puis navigation — et le serveur de développement compile
  // les chunks paresseux à la première visite de chaque page. Le défaut coupait au milieu, et
  // l'échec se lisait « page fermée » à l'intérieur du helper de connexion, ce qui n'apprend rien
  // sur la cause. Un délai trop court ne rend pas la suite plus rapide, il la rend menteuse.
  timeout: 120_000,

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
