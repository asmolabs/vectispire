import { readFileSync } from 'node:fs';
import { test, expect, type Page } from '@playwright/test';
import { resetLoginThrottle } from './support/fixture';
import {
    BOOTSTRAP_PASSWORD,
    E2E_PASSWORD,
    goTo,
    ROLE_PASSWORD,
    ROLE_PASSWORD_ROTATED,
    signInAs
} from './support/session';
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
    async function tokenOf(
        page: Page,
        username: string,
        passwords: string[] = [ROLE_PASSWORD_ROTATED, ROLE_PASSWORD]
    ): Promise<string> {
        for (const password of passwords) {
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
        await publish(page, slug, admin, await draftTemplate(page, slug, ciso));
    }

    /** Version 1 of a fresh template, imported and laid out by the CISO: a draft, at the revision answered. */
    async function draftTemplate(page: Page, slug: string, ciso: string, name = 'E2E checklist'): Promise<number> {
        const imported = await page.request.post(`/api/v1/checklist-templates/${slug}/versions`, {
            params: { name },
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
        return ((await laidOut.json()) as { version: { revision: number } }).version.revision;
    }

    /** Version 1 published by somebody who wrote none of it, at the revision named. */
    async function publish(page: Page, slug: string, admin: string, revision: number): Promise<void> {
        const published = await page.request.post(`/api/v1/checklist-templates/${slug}/versions/1/publish`, {
            headers: bearer(admin),
            data: { revision }
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

    // `ready: false` for a line the read still holds back once saved — a yes on a measured line with no
    // data asks for a comment and a proof straight away, since the read counts the measurements.
    async function answer(page: Page, position: number, value: RegExp, comment?: string, ready = true): Promise<void> {
        const line = page.getByTestId(`line-${position}`);
        await line.getByRole('button', { name: `Answer line ${position}` }).click();
        await line.getByRole('radio', { name: value }).check();
        if (comment) await line.getByLabel('Comment:').fill(comment);
        await line.getByRole('button', { name: 'Save the answer' }).click();
        // **The save has landed once its form has closed**, and not before. `not Ready` is already
        // true while the request is in flight, so the next line's form could open first and be
        // closed by this save's answer — invisible on SQLite, deterministic on MySQL, a few
        // milliseconds slower to answer.
        await expect(page.getByTestId(`answer-form-${position}`)).toHaveCount(0);
        if (ready) await expect(line.getByTestId('problems')).toHaveText('Ready');
        else await expect(line.getByTestId('problems')).not.toHaveText('Ready');
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
        // Submitted is not signed: its document is a rendering, and nothing offers to verify it.
        // By its id: the icon's glyph opens the button's accessible name, and a name matched as a
        // substring would also find each listed revision's own download.
        await expect(page.locator('#download-document')).toHaveText('Download an unsigned rendering');
        await expect(page.getByTestId('verification')).toHaveCount(0);
        await page.getByRole('button', { name: 'Sign off' }).click();

        await expect(page.getByTestId('notice')).toHaveText('Revision 1 signed off.');
        await expect(page.getByTestId('status')).toHaveText('Signed off');
        await expect(page.getByTestId('signed-off')).toContainText(adminName);
        await expect(page.getByTestId('four-eyes')).toHaveText('Applied: whoever signed it off wrote none of it.');
        await expect(page.getByRole('button', { name: 'Reopen as a new revision' })).toBeEnabled();

        // The package the sign-off stored, fetched by the page with its token: the zip carries both
        // signatures, and the page gives the commands that check them against the published key.
        const saved = page.waitForEvent('download');
        await expect(page.locator('#download-document')).toHaveText('Download the signed package');
        await page.locator('#download-document button').click();
        const download = await saved;
        expect(download.suggestedFilename()).toBe(`checklist-project-${projectId}-revision-1.zip`);
        const zip = readFileSync(await download.path());
        for (const entry of ['checklist.xlsx', 'checklist.json', 'checklist.xlsx.sig', 'checklist.json.sig']) {
            expect(zip.includes(entry), entry).toBe(true);
        }
        await expect(page.getByTestId('verification-commands')).toContainText(
            'cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature checklist.json.sig checklist.json'
        );
        // Saved under the name the commands give it — the one the key route's header sends as well.
        const keySaved = page.waitForEvent('download');
        await page.getByTestId('public-key-link').click();
        const key = await keySaved;
        expect(key.suggestedFilename()).toBe('vectispire-signing-key.pub');
        expect(readFileSync(await key.path(), 'utf8')).toContain('PUBLIC KEY');
    });

    /**
     * The requirement set where a security lead sets it — the draft's screen — and met where a team
     * meets it: the line asks for a file, a yes alone does not make it ready, the server refuses the
     * submission naming the line as data, and the file attached through the screen lets it through.
     */
    test('a line set to ask for a file on the draft keeps the checklist from submission until a file is attached', async ({
        page
    }) => {
        const run = Date.now().toString(36);
        const slug = `e2e-proof-${run}`;
        const name = `E2E proof ${run}`;

        const cisoName = await signInAs(page, 'CISO');
        const adminName = await signInAs(page, 'ADMIN');
        const ciso = await tokenOf(page, cisoName);
        const admin = await tokenOf(page, adminName);
        // A name of its own: the version is chosen by its label, and every run's templates stay offered.
        const templateName = `E2E proof checklist ${run}`;
        await draftTemplate(page, slug, ciso, templateName);

        // Through the screen: row 6, "Every build publishes an SBOM.", asks for a file.
        await signInAs(page, 'CISO');
        await goTo(page, '/checklist-templates');
        await page.getByRole('button', { name: `Open version 1 of ${slug}` }).click();
        const kind = page.getByLabel('Proof asked by the item of row 6');
        await expect(kind.locator('option:checked')).toHaveText('None', { timeout: 15_000 });
        await kind.selectOption({ label: 'File' });
        await page.getByRole('button', { name: 'Save the proof asked (1 changed)' }).click();
        await expect(page.getByTestId('notice')).toHaveText('Proof asked set on 1 item(s).');
        await expect(kind.locator('option:checked')).toHaveText('File');
        await expect(page.getByRole('button', { name: 'Save the proof asked (0 changed)' })).toBeDisabled();

        const version = (await (
            await page.request.get(`/api/v1/checklist-templates/${slug}/versions/1`, { headers: bearer(admin) })
        ).json()) as {
            version: { revision: number; draftAuthors: string[] };
            items: { sheetRow: number; evidenceKind: string }[];
        };
        expect(version.items.find((item) => item.sheetRow === 6)?.evidenceKind).toBe('file');
        expect(version.version.draftAuthors).toContain(cisoName);
        await publish(page, slug, admin, version.version.revision);
        const projectId = await project(page, name, admin);

        await openFromSolutions(page, name);
        // Named before a checklist exists, from the project's context.
        await expect(page.getByTestId('project-name')).toHaveText(`— ${name}`);
        await page.locator('#open-version').selectOption({ label: `${templateName} — version 1` });
        await page.getByRole('button', { name: 'Open the checklist' }).click();
        await expect(page.getByTestId('notice')).toHaveText('The checklist is open: revision 1.');
        await expect(page.getByTestId('line-3')).toContainText('A yes needs a file as evidence');

        await answer(page, 1, /^Yes/);
        await answer(page, 2, /^Yes/);
        const line = page.getByTestId('line-3');
        await line.getByRole('button', { name: 'Answer line 3' }).click();
        await line.getByRole('radio', { name: /^Yes/ }).check();
        await line.getByRole('button', { name: 'Save the answer' }).click();
        await expect(line.getByTestId('problems')).toHaveText('Evidence required');
        await expect(page.getByRole('button', { name: 'Submit for sign-off' })).toBeDisabled();
        await expect(page.getByTestId('submit-blocked')).toHaveText(
            'Not ready to submit: lines 3 still need attention.'
        );

        // The server says it whatever the screen shows, and names the line as data.
        const draft = (await (
            await page.request.get(`/api/v1/projects/${projectId}/checklists/1`, { headers: bearer(ciso) })
        ).json()) as { checklist: { edition: number } };
        const refused = await page.request.post(`/api/v1/projects/${projectId}/checklists/1/submission`, {
            headers: bearer(ciso),
            data: { edition: draft.checklist.edition }
        });
        expect(refused.status()).toBe(409);
        const problem = (await refused.json()) as { type: string; lines: { position: number; problems: string[] }[] };
        expect(problem.type).toBe('urn:vectispire:problem:checklist-incomplete');
        expect(problem.lines.map(({ position, problems }) => ({ position, problems }))).toEqual([
            { position: 3, problems: ['evidence_required'] }
        ]);

        await line.getByRole('button', { name: 'Add evidence to line 3' }).click();
        await line.getByRole('radio', { name: 'A file' }).check();
        await line.locator('input[type="file"]').setInputFiles({
            name: 'sbom-2026.json',
            mimeType: 'application/json',
            buffer: Buffer.from('{"bomFormat":"CycloneDX"}')
        });
        await line.getByRole('button', { name: 'Attach' }).click();
        await expect(line.getByTestId('problems')).toHaveText('Ready');
        await expect(line.getByTestId('evidence')).toContainText('sbom-2026.json');

        await page.getByRole('button', { name: 'Submit for sign-off' }).click();
        await expect(page.getByTestId('notice')).toHaveText('Revision 1 submitted for sign-off.');
        await expect(page.getByTestId('status')).toHaveText('Submitted');
    });

    /**
     * A measured line, end to end (decision 0032 §6): the CISO binds "secrets at zero" to row 4 on the
     * draft's screen, an administrator publishes it, and on a fresh project the line's measurement is
     * no data — the project has no repository, so nothing looked, and the screen says so rather than
     * passing it. A yes against it is not ready until it carries a comment and a proof (question 4): the
     * view's line problems and readyToSubmit count what the submission's measurement would refuse.
     */
    test('a line bound to a rule on the draft is measured on the project, and a yes without data needs a comment and a proof', async ({
        page
    }) => {
        const run = Date.now().toString(36);
        const slug = `e2e-measured-${run}`;
        const name = `E2E measured ${run}`;
        const templateName = `E2E measured checklist ${run}`;

        const cisoName = await signInAs(page, 'CISO');
        const adminName = await signInAs(page, 'ADMIN');
        const ciso = await tokenOf(page, cisoName);
        const admin = await tokenOf(page, adminName);
        await draftTemplate(page, slug, ciso, templateName);

        await signInAs(page, 'CISO');
        await goTo(page, '/checklist-templates');
        await page.getByRole('button', { name: `Open version 1 of ${slug}` }).click();
        await expect(page.getByTestId('item-4').getByTestId('item-rule')).toContainText('No rule', { timeout: 15_000 });
        await page.getByRole('button', { name: 'Rule of row 4' }).click();
        const editor = page.getByTestId('rule-editor');
        await editor.getByRole('button', { name: 'Preset: secrets at zero' }).click();
        await expect(editor.getByTestId('rule-described')).toContainText('Critical — at most 0 open');
        await expect(editor.getByTestId('rule-described')).toContainText('Evidence at most 7 days old');
        await editor.getByRole('button', { name: 'Keep this rule' }).click();
        await page.getByRole('button', { name: 'Save the rules (1)' }).click();
        await expect(page.getByTestId('notice')).toHaveText('Rules saved on 1 line(s).');
        await expect(page.getByTestId('item-4').getByTestId('item-rule-kind')).toHaveText('Findings within thresholds');

        const version = (await (
            await page.request.get(`/api/v1/checklist-templates/${slug}/versions/1`, { headers: bearer(admin) })
        ).json()) as { version: { revision: number }; items: { sheetRow: number; boundRule: unknown }[] };
        expect(version.items.find((item) => item.sheetRow === 4)?.boundRule).toMatchObject({
            kind: 'findings_threshold',
            maxAgeDays: 7,
            scopes: ['builtin:secret'],
            thresholds: { critical: { maxOpen: 0 }, high: { maxOpen: 0 } }
        });
        await publish(page, slug, admin, version.version.revision);
        await project(page, name, admin);

        await openFromSolutions(page, name);
        await page.locator('#open-version').selectOption({ label: `${templateName} — version 1` });
        await page.getByRole('button', { name: 'Open the checklist' }).click();
        await expect(page.getByTestId('notice')).toHaveText('The checklist is open: revision 1.');

        const measured = page.getByTestId('measurement-1');
        await expect(measured.getByTestId('outcome')).toHaveText('No data');
        await expect(measured.getByTestId('reason')).toHaveText(
            'The project has no repository: there is nothing to measure, and nothing passes by default.'
        );
        await expect(page.getByTestId('measurements-mode')).toContainText('Measurements computed now');
        await expect(page.getByTestId('measurement-2')).toHaveCount(0);
        // No data offers nothing to rest an answer on.
        await expect(page.getByRole('button', { name: 'Answer line 1 as measured' })).toHaveCount(0);

        await answer(page, 1, /^Yes/, undefined, false);
        await answer(page, 2, /^Yes/);
        await answer(page, 3, /^Yes/);
        const line = page.getByTestId('line-1');
        const problems = line.getByTestId('problems');
        await expect(measured.getByTestId('reconciliation')).toHaveText('Declared, not measured');
        // Said once, by the line: the measurement's badges do not repeat what the view already counts.
        await expect(problems).toContainText('Comment required');
        await expect(problems).toContainText('Evidence required');
        await expect(measured.getByTestId('measured-problem')).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Submit for sign-off' })).toBeDisabled();
        await expect(page.getByTestId('submit-blocked')).toHaveText(
            'Not ready to submit: lines 1 still need attention.'
        );

        await answer(page, 1, /^Yes/, 'No repository filed yet: the secrets review was done by hand.', false);
        await expect(problems).not.toContainText('Comment required');
        await expect(problems).toContainText('Evidence required');
        await line.getByRole('button', { name: 'Add evidence to line 1' }).click();
        await line.getByLabel('Link (https: or http:)').fill('https://wiki.example.invalid/secrets-review');
        await line.getByRole('button', { name: 'Attach' }).click();
        await expect(line.getByTestId('evidence')).toContainText('secrets-review');
        await expect(problems).toHaveText('Ready');

        await page.getByRole('button', { name: 'Submit for sign-off' }).click();
        await expect(page.getByTestId('notice')).toHaveText('Revision 1 submitted for sign-off.');
        await expect(page.getByTestId('status')).toHaveText('Submitted');
    });

    /**
     * A published template whose rows 4 and 5 are measured by coverage, at least half and at least nine
     * tenths, and a project whose one repository imported three lines covered of four — line 1 met,
     * line 2 not met — with the platform governor's token, which decides whether Vectispire answers them.
     *
     * The coverage comes the way a pipeline sends it — a key holding `report_import`, declared for the
     * project by the platform's governor — because no scan runs here: the worker is off.
     */
    async function measuredByCoverage(
        page: Page,
        prefix: string
    ): Promise<{ name: string; templateName: string; governor: string }> {
        const run = Date.now().toString(36);
        const slug = `e2e-${prefix}-${run}`;
        const name = `E2E ${prefix} ${run}`;
        const templateName = `E2E ${prefix} checklist ${run}`;

        const cisoName = await signInAs(page, 'CISO');
        const adminName = await signInAs(page, 'ADMIN');
        const ciso = await tokenOf(page, cisoName);
        const admin = await tokenOf(page, adminName);
        const governor = await tokenOf(page, 'admin', [E2E_PASSWORD, BOOTSTRAP_PASSWORD]);
        const revision = await draftTemplate(page, slug, ciso, templateName);

        const draft = (await (
            await page.request.get(`/api/v1/checklist-templates/${slug}/versions/1`, { headers: bearer(ciso) })
        ).json()) as { items: { sheetRow: number; itemKey: string }[] };
        const keyOf = (row: number) => draft.items.find((item) => item.sheetRow === row)!.itemKey;
        const coverage = (minimumRatio: number) => ({
            kind: 'coverage_threshold',
            maxAgeDays: 7,
            metric: 'line',
            minimumRatio,
            aggregation: 'per_repository'
        });
        const bound = await page.request.put(`/api/v1/checklist-templates/${slug}/versions/1/rules`, {
            params: { revision },
            headers: bearer(ciso),
            data: {
                items: [
                    { itemKey: keyOf(4), rule: coverage(0.5) },
                    { itemKey: keyOf(5), rule: coverage(0.9) }
                ]
            }
        });
        expect(bound.status(), await bound.text()).toBe(200);
        await publish(page, slug, admin, ((await bound.json()) as { version: { revision: number } }).version.revision);
        const projectId = await project(page, name, admin);

        const repository = await page.request.post('/api/v1/repositories', {
            headers: bearer(admin),
            data: { name: `e2e-${prefix}-${run}`, url: `https://example.invalid/e2e-${run}.git`, branch: 'main' }
        });
        expect(repository.ok(), await repository.text()).toBe(true);
        const repositoryId = ((await repository.json()) as { id: number }).id;
        const attached = await page.request.put(`/api/v1/projects/${projectId}/repositories/${repositoryId}`, {
            headers: bearer(admin)
        });
        expect(attached.status(), await attached.text()).toBe(204);
        const key = await page.request.post('/api/v1/api-keys', {
            headers: bearer(admin),
            data: { name: `e2e-coverage-${run}`, scopes: ['report_import'] }
        });
        expect(key.ok(), await key.text()).toBe(true);
        const issued = (await key.json()) as { key: { id: string }; secret: string };
        const declared = await page.request.post('/api/v1/sarif-sources', {
            headers: bearer(governor),
            data: {
                slug: `e2e-ci-${run}`,
                name: `E2E CI ${run}`,
                api_key_id: issued.key.id,
                project_id: projectId,
                kinds: ['coverage']
            }
        });
        expect(declared.ok(), await declared.text()).toBe(true);
        const imported = await page.request.post(`/api/v1/repositories/${repositoryId}/coverage-imports`, {
            params: { format: 'lcov' },
            headers: { ...bearer(issued.secret), 'Content-Type': 'text/plain' },
            data: 'SF:a.ts\nDA:1,1\nDA:2,1\nDA:3,1\nDA:4,0\nend_of_record\n'
        });
        expect(imported.status(), await imported.text()).toBe(201);

        return { name, templateName, governor };
    }

    /** `checklist_auto_answer`, the platform governor's: on by default, and put back on by whoever turns it off. */
    async function autoAnswer(page: Page, governor: string, on: boolean): Promise<void> {
        const saved = await page.request.put('/api/v1/settings', {
            headers: bearer(governor),
            data: { checklist_auto_answer: String(on) }
        });
        expect(saved.ok(), await saved.text()).toBe(true);
    }

    async function openMeasured(page: Page, name: string, templateName: string): Promise<void> {
        await signInAs(page, 'CISO');
        await openFromSolutions(page, name);
        await page.locator('#open-version').selectOption({ label: `${templateName} — version 1` });
        await page.getByRole('button', { name: 'Open the checklist' }).click();
        await expect(page.getByTestId('notice')).toHaveText('The checklist is open: revision 1.');
        await expect(page.getByTestId('measurement-1').getByTestId('outcome')).toHaveText('Met');
        await expect(page.getByTestId('measurement-2').getByTestId('outcome')).toHaveText('Not met');
    }

    /**
     * Every measured line answered in one click (decision 0032 §6). The act answers line 1, met, yes;
     * line 2, not met, is left for the person's no with its comment, and the summary opens its form on no.
     *
     * The automatic answers are switched off for this one: they would answer both lines on opening, and
     * the act this pins — a person's, still offered when the setting is off — would never be offered.
     * They are switched back on whatever happens, since the setting is the platform's and ships on.
     */
    test('every measured line is answered as measured in one click, and a line not met is left for its no', async ({
        page
    }) => {
        const { name, templateName, governor } = await measuredByCoverage(page, 'as-measured');
        await autoAnswer(page, governor, false);
        try {
            await openMeasured(page, name, templateName);
            await expect(page.getByTestId('automatic-count')).toHaveCount(0);

            await page.getByRole('button', { name: 'Answer every measured line as measured' }).click();
            await expect(page.getByTestId('as-measured-answered')).toHaveText('1 line(s) answered yes as measured.');
            await expect(page.getByTestId('line-1').getByTestId('answer-value')).toHaveText('Yes');
            await expect(page.getByTestId('measurement-1').getByTestId('reconciliation')).toHaveText('Consistent');
            await expect(page.getByTestId('as-measured-needs_comment')).toContainText(
                'Lines 2, measured as not met, need your “no” with a comment:'
            );
            await expect(page.getByTestId('line-2').getByTestId('answer-value')).toHaveCount(0);

            await page.getByRole('button', { name: 'Line 2: answer no' }).click();
            const line = page.getByTestId('line-2');
            await expect(line.getByRole('radio', { name: /^No/ })).toBeChecked();
            await expect(line.getByLabel('Comment:')).toBeFocused();
            await line.getByLabel('Comment:').fill('Coverage below target on the ledger: tests planned this sprint.');
            await line.getByRole('button', { name: 'Save the answer' }).click();
            await expect(line.getByTestId('answer-value')).toHaveText('No');
            await expect(page.getByTestId('as-measured-needs_comment')).toHaveCount(0);
            // Nothing left that the one click offers on an unanswered line: the act is no longer offered.
            await expect(page.getByRole('button', { name: 'Answer every measured line as measured' })).toHaveCount(0);
        } finally {
            await autoAnswer(page, governor, true);
        }
    });

    /**
     * Vectispire's own answers (decision 0032, amendment of 2026-09-29), with the setting as it ships:
     * opening the checklist answers the met line yes and the unmet one no with the measurement for its
     * comment, both marked as Vectispire's; a person answering one takes it over, and the history keeps
     * both authors apart.
     */
    test('opening a measured checklist answers its lines as Vectispire, and a person answering one takes it over', async ({
        page
    }) => {
        const { name, templateName } = await measuredByCoverage(page, 'automatic');
        await openMeasured(page, name, templateName);

        await expect(page.getByTestId('automatic-count')).toHaveText('2 automatic answer(s)');
        const met = page.getByTestId('line-1');
        await expect(met.getByTestId('answer-value')).toHaveText('Yes');
        await expect(met.getByTestId('answer-automatic')).toHaveText('Automatic — measured by Vectispire');
        await expect(met.getByTestId('answer-author')).toContainText('answered by Vectispire');
        const unmet = page.getByTestId('line-2');
        await expect(unmet.getByTestId('answer-value')).toHaveText('No');
        await expect(unmet.getByTestId('answer-comment')).toContainText('Measured by Vectispire (coverage_threshold)');
        // Nothing left unanswered for the one click to offer.
        await expect(page.getByRole('button', { name: 'Answer every measured line as measured' })).toHaveCount(0);

        await unmet.getByRole('button', { name: 'Answer line 2', exact: true }).click();
        await expect(unmet.getByTestId('takeover-hint')).toHaveText(
            'Answering replaces the automatic answer: the line becomes yours.'
        );
        await unmet.getByLabel('Comment:').fill('Coverage below target on the ledger: tests planned this sprint.');
        await unmet.getByRole('button', { name: 'Save the answer' }).click();
        await expect(unmet.getByTestId('answer-comment')).toContainText('tests planned this sprint');
        await expect(unmet.getByTestId('answer-automatic')).toHaveCount(0);
        await expect(page.getByTestId('automatic-count')).toHaveText('1 automatic answer(s)');

        await unmet.getByRole('button', { name: 'History of line 2' }).click();
        const history = page.getByTestId('history-2');
        await expect(history.getByTestId('history-automatic')).toHaveCount(1);
        await expect(history.locator('li')).toHaveCount(2);
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
