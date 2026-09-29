import { test, expect } from '@playwright/test';
import { resetLoginThrottle } from './support/fixture';
import { goTo, signInAs } from './support/session';
import { checklistWorkbook } from './support/workbook';

/**
 * The checklist templates screen (decision 0032 §8), against the real server.
 *
 * <p>The unit specs pin the draft, the layout, the pairing and the refusals against fixtures read
 * from the contract; this pins the roles against the routes. The entry is in the sidebar for
 * governance readers only — a link leading to a refusal is the defect the menu suite watches for —
 * the auditor reads and is offered no import, and a security lead is refused a workbook past the
 * route's ceiling before a byte leaves the browser.
 */
test.describe('Checklist templates', () => {
    test.beforeEach(() => resetLoginThrottle());

    test('an ordinary account is not offered the checklist templates', async ({ page }) => {
        await signInAs(page, 'USER');

        await expect(page.getByRole('link', { name: 'Checklist templates' })).toHaveCount(0);
    });

    test('an auditor reads the checklist templates and is offered no import', async ({ page }) => {
        await signInAs(page, 'AUDITOR');
        await goTo(page, '/checklist-templates');

        await expect(page.getByRole('heading', { name: 'Checklist templates', level: 1 })).toBeVisible({
            timeout: 15_000
        });
        await expect(page.getByRole('button', { name: 'Import as a draft' })).toHaveCount(0);
        await expect(page.locator('#checklist-file')).toHaveCount(0);
    });

    test('a CISO is refused a workbook past ten megabytes before it is sent', async ({ page }) => {
        await signInAs(page, 'CISO');
        await goTo(page, '/checklist-templates');

        let posted = false;
        page.on('request', (request) => {
            if (request.method() === 'POST' && request.url().includes('/api/v1/checklist-templates/')) posted = true;
        });
        await page.locator('#checklist-slug').fill('e2e-oversized');
        await page.locator('#checklist-file').setInputFiles({
            name: 'oversized.xlsx',
            mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            buffer: Buffer.alloc(10 * 1024 * 1024 + 1)
        });

        await expect(page.getByTestId('upload-error')).toContainText(
            'The request body is larger than the 10485760 bytes this route accepts.'
        );
        await expect(page.getByRole('button', { name: 'Import as a draft' })).toBeDisabled();
        expect(posted).toBe(false);
    });

    /**
     * The whole flow against the server's own reader and its four-eyes rule, which ships switched
     * on and which no suite here switches off: the CISO who imported and confirmed the draft is not
     * offered its publication and is told why, and an administrator who wrote none of it publishes
     * the revision on screen.
     */
    test('a CISO imports and confirms a workbook, is told a second person must publish it, and an administrator does', async ({
        page
    }) => {
        // A slug per run: a template's versions are never deleted, and the campaign's file is disposable.
        const slug = `e2e-${Date.now().toString(36)}`;
        await signInAs(page, 'CISO');
        await goTo(page, '/checklist-templates');

        await page.locator('#checklist-slug').fill(slug);
        await page.locator('#checklist-name').fill('E2E release checklist');
        await page.locator('#checklist-file').setInputFiles({
            name: 'checklist.xlsx',
            mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            buffer: checklistWorkbook()
        });
        await page.getByRole('button', { name: 'Import as a draft' }).click();
        await expect(page.getByTestId('notice')).toContainText(`Version 1 of "${slug}" imported as a draft`);

        // The sheet's own cells, as the server read them from the raw body.
        await expect(page.getByTestId('sheet-grid')).toContainText('Shared accounts are disabled.');

        // Every field stated, whatever the reader proposed: this pins the body the server reads.
        for (const [column, letters] of Object.entries({
            id: '',
            domain: 'A',
            objective: '',
            control: 'B',
            contact: '',
            kpi: '',
            answer: 'C',
            comment: 'D'
        })) {
            await page.locator(`#layout-column-${column}`).fill(letters);
        }
        await page.locator('#layout-first-row').fill('4');
        await page.locator('#layout-last-row').fill('6');
        for (const field of ['date', 'product', 'author']) {
            await page.locator(`#layout-header-${field}-label`).fill(field === 'product' ? 'A1' : '');
            await page.locator(`#layout-header-${field}-value`).fill(field === 'product' ? 'B1' : '');
        }
        await page.locator('#layout-word-yes').fill('Done');
        await page.locator('#layout-word-no').fill('Not done');
        await page.getByRole('button', { name: 'Confirm the layout' }).click();

        await expect(page.getByTestId('notice')).toHaveText('Layout confirmed: 3 items read.');
        // The domain filled down onto row 5, as the sheet means it.
        await expect(page.getByTestId('items')).toContainText('Identity');
        await expect(page.getByTestId('no-previous')).toBeVisible();

        const shown = (await page.getByTestId('shown-revision').textContent())?.trim();
        // The author is not offered a publication the server would refuse, and is told who may publish.
        await expect(page.getByRole('button', { name: `Publish revision ${shown}` })).toBeDisabled();
        await expect(page.getByTestId('publish-four-eyes')).toContainText('a security lead');

        await signInAs(page, 'ADMIN');
        await goTo(page, '/checklist-templates');
        await page.getByRole('button', { name: `Open version 1 of ${slug}` }).click();
        await expect(page.getByTestId('shown-revision')).toHaveText(shown ?? '');
        await page.getByRole('button', { name: `Publish revision ${shown}` }).click();
        await page.locator('#confirm-act button').click();

        await expect(page.getByTestId('notice')).toHaveText('Version 1 published.');
        await expect(page.getByTestId(`version-${slug}-1`)).toContainText('Published');
        await expect(page.getByTestId(`version-${slug}-1`)).toContainText('e2e-admin');
    });
});
