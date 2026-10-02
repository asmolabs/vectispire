import { test, expect } from '@playwright/test';
import { signIn } from './support/session';
import { resetLoginThrottle, seedOneIssue } from './support/fixture';

/**
 * The weekly OWASP view against the real server: a count clicked in the heatmap opens a backlog
 * that says what it was asked and holds as many issues as the count said.
 *
 * <p><b>The agreement is the server's, so only a running server can show it.</b> The unit specs
 * prove the link carries the figure's own definition — its Sunday, `unsettled` on a recorded week
 * only, no `state` — and that the backlog sends what it read; whether the backlog's filter and the
 * weekly figure then count the same issues is decided by two queries in the control plane, and the
 * figure clicked is compared here with the total the list reports, whatever the week turns out to
 * be (recorded once the capture has run, reconstructed before).
 */
test.describe.configure({ mode: 'serial' });

test.describe('the weekly OWASP view', () => {
    test.beforeEach(() => resetLoginThrottle());

    // A critical vulnerability first seen now: A06, open in the current week.
    test.beforeAll(() => seedOneIssue());

    test('a count clicked opens the filtered backlog, with its banner and the same count', async ({ page }) => {
        await signIn(page);
        // Inside the application, never `page.goto`: the session lives in memory (see `goTo`).
        await page.getByRole('link', { name: 'OWASP report' }).first().click();
        await expect(page).toHaveURL(/\/owasp(\?|$)/, { timeout: 15_000 });
        await page.getByTestId('view-weekly').click();
        await expect(page).toHaveURL(/\/owasp\?view=weekly/);

        const heatmap = page.getByTestId('owasp-heatmap');
        await expect(heatmap).toBeVisible({ timeout: 15_000 });
        // The current week is the last column; A06 is the sixth row.
        const square = heatmap.locator('tbody tr').nth(5).locator('td').last();
        const count = square.getByTestId('heat-open');
        await expect(count).toBeVisible();
        const figure = Number((await count.textContent())?.trim());
        expect(figure).toBeGreaterThan(0);

        await count.click();

        await expect(page).toHaveURL(/\/issues\?.*owasp_category=A06/);
        await expect(page).toHaveURL(/open_at=\d{4}-\d{2}-\d{2}/);
        const banner = page.getByTestId('weekly-banner');
        await expect(banner).toBeVisible({ timeout: 15_000 });
        await expect(page.getByTestId('weekly-banner-text')).toContainText(/Issues A06 open on \d{4}-\d{2}-\d{2}/);
        await expect(page.getByTestId('weekly-banner-text')).toContainText('from the weekly OWASP view');
        // The list's own count, against the figure clicked.
        await expect(banner).toContainText(new RegExp(`of ${figure}\\b`));

        // And back to the weekly view, on the week it came from.
        await page.getByTestId('weekly-back').click();
        await expect(page).toHaveURL(/\/owasp\?.*view=weekly.*week=\d{4}-\d{2}-\d{2}/);
        await expect(page.getByTestId('owasp-heatmap')).toBeVisible({ timeout: 15_000 });
    });
});
