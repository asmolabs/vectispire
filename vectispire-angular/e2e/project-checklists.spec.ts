import { test, expect, type Page } from '@playwright/test';
import { resetLoginThrottle } from './support/fixture';
import { goTo, ROLE_PASSWORD, ROLE_PASSWORD_ROTATED, signInAs } from './support/session';
import { checklistWorkbook } from './support/workbook';

/**
 * A project's security checklist (decision 0032 §5, §8), against the real server.
 *
 * <p>The unit specs pin every refusal, every body and every role against fixtures read from the
 * contract; this pins the main flow against the routes and the four-eyes rule, which ships switched
 * on and which no suite here switches off. The template and the project are made through the API —
 * the checklist templates suite already walks that screen — and the checklist itself through the
 * screen: a CISO opens it on the published version, answers every line, a "no" with its comment,
 * and submits; the sign-off is greyed out for them with the reason, the server refuses it to them by
 * its problem type, and an administrator who wrote none of it signs it off.
 */
test.describe('Project checklists', () => {
    test.beforeEach(() => resetLoginThrottle());

    /** A bearer token for `page.request`: the session lives in memory, where no request can read it. */
    async function tokenOf(page: Page, username: string): Promise<string> {
        for (const password of [ROLE_PASSWORD_ROTATED, ROLE_PASSWORD]) {
            const response = await page.request.post('/api/v1/auth/login', { data: { username, password } });
            if (response.ok()) {
                const token = (await response.json())['token'];
                if (token) return token as string;
            }
        }
        throw new Error(`no token for ${username}`);
    }

    const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });

    /** Version 1 of a fresh template, imported and laid out by the CISO, published by the administrator. */
    async function publishedTemplate(page: Page, slug: string, ciso: string, admin: string): Promise<void> {
        const imported = await page.request.post(`/api/v1/checklist-templates/${slug}/versions?name=E2E%20checklist`, {
            headers: {
                ...bearer(ciso),
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            },
            data: checklistWorkbook()
        });
        expect(imported.status(), await imported.text()).toBe(201);
        const draft = (await imported.json()) as { version: { revision: number } };

        const laidOut = await page.request.put(
            `/api/v1/checklist-templates/${slug}/versions/1/layout?revision=${draft.version.revision}`,
            {
                headers: bearer(ciso),
                data: {
                    sheet: 'Checklist',
                    columns: { domain: 'A', control: 'B', answer: 'C', comment: 'D' },
                    firstItemRow: 4,
                    lastItemRow: 6,
                    header: { product: { label: 'A1', value: 'B1' } },
                    answers: { yes: 'Done', no: 'Not done', notApplicable: null }
                }
            }
        );
        expect(laidOut.status(), await laidOut.text()).toBe(200);
        const confirmed = (await laidOut.json()) as { version: { revision: number } };

        const published = await page.request.post(`/api/v1/checklist-templates/${slug}/versions/1/publish`, {
            headers: bearer(admin),
            data: { revision: confirmed.version.revision }
        });
        expect(published.status(), await published.text()).toBe(200);
    }

    /** A solution holding one project, named for this run: names are unique and the file survives. */
    async function project(page: Page, name: string, admin: string): Promise<number> {
        const solution = await page.request.post('/api/v1/solutions', {
            headers: bearer(admin),
            data: { name: `${name} solution` }
        });
        expect(solution.ok(), await solution.text()).toBe(true);
        const solutionId = ((await solution.json()) as { id: number }).id;
        const created = await page.request.post(`/api/v1/solutions/${solutionId}/projects`, {
            headers: bearer(admin),
            data: { name }
        });
        expect(created.ok(), await created.text()).toBe(true);
        return ((await created.json()) as { id: number }).id;
    }

    async function openFromSolutions(page: Page, name: string): Promise<void> {
        await goTo(page, '/solutions');
        await page.getByRole('link', { name: `Security checklist of ${name}` }).click();
        await expect(page.getByRole('heading', { name: /Security checklist/, level: 1 })).toBeVisible({
            timeout: 15_000
        });
    }

    async function answer(page: Page, position: number, value: RegExp, comment?: string): Promise<void> {
        const line = page.getByTestId(`line-${position}`);
        await line.getByRole('button', { name: `Answer line ${position}` }).click();
        await line.getByRole('radio', { name: value }).check();
        if (comment) await line.getByLabel('Comment:').fill(comment);
        await line.getByRole('button', { name: 'Save the answer' }).click();
        await expect(line.getByTestId('problems')).toHaveText('Ready');
    }

    test('a CISO opens, answers and submits a checklist; four-eyes refuses them its sign-off; an administrator gives it', async ({
        page
    }) => {
        const run = Date.now().toString(36);
        const slug = `e2e-project-${run}`;
        const name = `E2E checklist ${run}`;

        const cisoName = await signInAs(page, 'CISO');
        const adminName = await signInAs(page, 'ADMIN');
        const ciso = await tokenOf(page, cisoName);
        const admin = await tokenOf(page, adminName);
        await publishedTemplate(page, slug, ciso, admin);
        const projectId = await project(page, name, admin);

        await signInAs(page, 'CISO');
        await openFromSolutions(page, name);
        await expect(page.getByTestId('no-checklist')).toContainText('This project has no security checklist yet.');
        await page.locator('#open-version').selectOption({ label: 'E2E checklist — version 1' });
        await page.getByRole('button', { name: 'Open the checklist' }).click();
        await expect(page.getByTestId('notice')).toHaveText('The checklist is open: revision 1.');
        await expect(page.getByTestId('status')).toHaveText('Draft');

        // Grouped as the sheet groups them: the domain filled down onto row 5.
        await expect(page.getByTestId('domain-0')).toContainText('Identity');
        await expect(page.getByTestId('domain-1')).toContainText('Supply chain');
        await expect(page.getByTestId('submit-blocked')).toHaveText(
            'Not ready to submit: lines 1, 2, 3 still need attention.'
        );

        await answer(page, 1, /^Yes/);
        await answer(page, 2, /^No/, 'Two shared accounts remain, removal planned for October.');
        await answer(page, 3, /^Yes/);
        await expect(page.getByTestId('line-2').getByTestId('answer-comment')).toContainText('removal planned');

        await page.getByRole('button', { name: 'Submit for sign-off' }).click();
        await expect(page.getByTestId('notice')).toHaveText('Revision 1 submitted for sign-off.');
        await expect(page.getByTestId('status')).toHaveText('Submitted');

        // The screen says it before the click; the server says it whatever the screen shows.
        await expect(page.getByRole('button', { name: 'Sign off' })).toBeDisabled();
        await expect(page.getByTestId('sign-off-blocked')).toHaveText(
            'Four-eyes approval is on and you wrote part of this revision: a second person must sign it off.'
        );
        const revision = (await (
            await page.request.get(`/api/v1/projects/${projectId}/checklists/1`, { headers: bearer(ciso) })
        ).json()) as { checklist: { edition: number } };
        const refused = await page.request.post(`/api/v1/projects/${projectId}/checklists/1/sign-off`, {
            headers: bearer(ciso),
            data: { edition: revision.checklist.edition }
        });
        expect(refused.status()).toBe(409);
        expect(((await refused.json()) as { type: string }).type).toBe('urn:vectispire:problem:checklist-four-eyes');

        await signInAs(page, 'ADMIN');
        await openFromSolutions(page, name);
        await expect(page.getByTestId('status')).toHaveText('Submitted');
        await expect(page.getByTestId('sign-off-blocked')).toHaveCount(0);
        await page.getByRole('button', { name: 'Sign off' }).click();

        await expect(page.getByTestId('notice')).toHaveText('Revision 1 signed off.');
        await expect(page.getByTestId('status')).toHaveText('Signed off');
        await expect(page.getByTestId('signed-off')).toContainText(adminName);
        await expect(page.getByTestId('four-eyes')).toHaveText('Applied: whoever signed it off wrote none of it.');
        await expect(page.getByRole('button', { name: 'Reopen as a new revision' })).toBeEnabled();
    });

    test('an auditor reads a project checklist and is offered no write', async ({ page }) => {
        const run = Date.now().toString(36);
        const adminName = await signInAs(page, 'ADMIN');
        const admin = await tokenOf(page, adminName);
        const name = `E2E read-only ${run}`;
        await project(page, name, admin);

        await signInAs(page, 'AUDITOR');
        await openFromSolutions(page, name);
        await expect(page.getByTestId('no-checklist')).toContainText('Somebody with write access opens one');
        await expect(page.locator('#open-version')).toHaveCount(0);
    });
});
