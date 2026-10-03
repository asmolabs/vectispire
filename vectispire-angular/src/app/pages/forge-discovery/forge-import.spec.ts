import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, TestRequest, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { ForgeImportStep, type ImportDone } from './forge-import';
import { useEnglish } from '@/app/core/testing/english';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';
import { CONNECTION_ID, PREVIEW, RESULT } from '@/app/core/testing/forges.fixtures';
import type { ForgeImportPreview } from '@/app/core/api.models';

const TOKEN_ID = '3b1f0c2e-6d4a-4e8b-9f10-2a7c5d9e1b44';
const KEY_ID = '9d0e7c55-1f2a-4b3c-8d4e-5f6a7b8c9d0e';
const HOST = 'gitlab.example.internal';

/**
 * Placement, preview, import and result, through the DOM: what the preview says will happen — created,
 * skipped and why, refused, filed where, cloned how, seen by whom — and that the import sends exactly what was
 * previewed, never a draft the person has not seen.
 */
describe('the import step', () => {
    let fixture: ComponentFixture<ForgeImportStep>;
    let http: HttpTestingController;
    const BASE = `/api/v1/forge-connections/${CONNECTION_ID}/imports`;

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string, root: ParentNode = dom()) =>
        root.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    const all = (selector: string) =>
        Array.from(dom().querySelectorAll(selector)).map((node) => node.textContent?.replace(/\s+/g, ' ').trim() ?? '');
    const button = (testId: string) => dom().querySelector<HTMLButtonElement>(`[data-testid="${testId}"] button`)!;

    async function settle(): Promise<void> {
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
    }

    async function click(testId: string): Promise<void> {
        button(testId).click();
        await settle();
    }

    function previewRequest(): TestRequest {
        return http.expectOne({ method: 'POST', url: `${BASE}/preview` });
    }

    async function open(preview: ForgeImportPreview = PREVIEW, result: object | null = null): Promise<void> {
        fixture = TestBed.createComponent(ForgeImportStep);
        fixture.componentRef.setInput('connectionId', CONNECTION_ID);
        fixture.componentRef.setInput('discoveryId', 12);
        fixture.componentRef.setInput('forgeIds', ['101', '102']);
        fixture.componentRef.setInput('result', result);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne('/api/v1/ssh-keys').flush(
            asSchemaList('SshKeySummary', [
                {
                    id: KEY_ID,
                    name: 'deploy-key',
                    createdAt: '2026-09-01T00:00:00Z',
                    encryptionState: 'current',
                    publicKey: null,
                    usedByRepositories: 0
                }
            ])
        );
        http.expectOne('/api/v1/git-tokens').flush(
            asSchemaList('GitTokenSummary', [
                {
                    id: TOKEN_ID,
                    name: 'gitlab-read',
                    host: HOST,
                    username: null,
                    createdAt: '2026-09-01T00:00:00Z',
                    encryptionState: 'current',
                    usedByRepositories: 0
                }
            ])
        );
        http.expectOne('/api/v1/solutions').flush({
            solutions: [],
            unfiled: { openIssues: {}, repositories: [] }
        });
        if (result === null) {
            const first = previewRequest();
            expect(first.request.body).toEqual({
                discoveryId: 12,
                forgeIds: ['101', '102'],
                mapping: [],
                credentials: [],
                firstScan: false,
                spacingSeconds: 60,
                requiredAgentLabel: undefined
            });
            first.flush(preview);
        }
        await settle();
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [ForgeImportStep],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
    }, 20_000);

    it('previews what will be created, skipped and why, how each is cloned and who will see it', async () => {
        await open();

        const summary = text('[data-testid="preview-summary"]');
        expect(summary).toContain('2 targets created');
        expect(summary).toContain('1 repository skipped');
        expect(summary).toContain('every 7 days');
        expect(summary).toContain('No first scan');
        expect(summary).toContain('No grant is created');
        expect(text('[data-testid="skipped"]')).toBe('acme/frontend/portal — Already a target (targets 7, 8, 9)');
        expect(all('[data-testid="filing"] li')).toEqual([
            'Solution acme: existing, reused',
            'Project acme / backend/payments: existing, reused — 1 target; granted to accounts: 2, teams: 1'
        ]);

        const [api, worker] = Array.from(dom().querySelectorAll('[data-testid="planned-row"]'));
        expect(api.textContent).toContain('HTTPS token — gitlab-read');
        expect(text('[data-testid="visible-to"]', api)).toBe(
            'Administrators and the roles that see the whole estate, plus those granted project acme / backend/payments — accounts: 2, teams: 1.'
        );
        expect(worker.textContent).toContain('None (public repositories)');
        expect(text('[data-testid="warning"]', worker)).toContain('imported with no clone credential');
        expect(text('[data-testid="visible-to"]', worker)).toContain('it is filed into no project');
        expect(button('import').disabled).toBe(false);
    });

    it('says who will see a target filed into a new project, or into any project when nothing is restricted', async () => {
        await open({
            ...PREVIEW,
            projects: [
                { name: 'backend/payments', solution: 'acme', existingId: null, targets: 1, accounts: 0, teams: 0 }
            ]
        });
        expect(text('[data-testid="visible-to"]')).toContain('project acme / backend/payments is new');

        fixture.destroy();
        await open({ ...PREVIEW, visibilityMode: 'everyone' });
        expect(text('[data-testid="visible-to"]')).toContain('Every signed-in account');
    });

    it('writes a placement change as a rule for the namespace, and waits for a fresh preview before importing', async () => {
        await open();

        const rows = Array.from(dom().querySelectorAll<HTMLElement>('[data-testid="placement"]'));
        const payments = rows.find((row) => row.textContent?.includes('acme/backend/payments'))!;
        const solution = payments.querySelector<HTMLInputElement>('[data-testid="placement-solution"]')!;
        solution.value = 'Payments';
        solution.dispatchEvent(new Event('input'));
        await settle();

        expect(text('[data-testid="stale"]')).toContain('preview again before importing');
        expect(button('import').disabled).toBe(true);

        await click('preview');
        const again = previewRequest();
        expect(again.request.body).toMatchObject({
            mapping: [{ namespacePath: 'acme/backend/payments', solution: 'Payments' }]
        });
        again.flush(PREVIEW);
        await settle();
        expect(button('import').disabled).toBe(false);
    });

    it('files one repository into no project when asked, per repository', async () => {
        await open();

        dom().querySelector<HTMLInputElement>('#per-repository')!.click();
        await settle();
        const worker = Array.from(dom().querySelectorAll<HTMLElement>('[data-testid="placement"]')).find((row) =>
            row.textContent?.includes('acme/backend/payments/api')
        )!;
        worker.querySelector<HTMLInputElement>('[data-testid="placement-no-project"]')!.click();
        await settle();

        await click('preview');
        expect(previewRequest().request.body).toMatchObject({ mapping: [{ forgeId: '101', noProject: true }] });
    });

    it('sends the clone credential chosen per host, an SSH key or none', async () => {
        await open();

        const choice = dom().querySelector<HTMLSelectElement>('[data-testid="credential-choice"]')!;
        // The proposal — the one HTTPS token bound to that host — is what the select shows first.
        expect(choice.value).toBe(`https:${TOKEN_ID}`);
        expect(Array.from(choice.options).map((option) => option.textContent?.trim())).toEqual([
            'None (public repositories)',
            'HTTPS token — gitlab-read',
            'SSH key — deploy-key'
        ]);

        choice.value = `ssh:${KEY_ID}`;
        choice.dispatchEvent(new Event('change'));
        await settle();
        await click('preview');
        const ssh = previewRequest();
        expect(ssh.request.body).toMatchObject({ credentials: [{ host: HOST, sshKeyId: KEY_ID }] });
        ssh.flush(PREVIEW);
        await settle();

        const again = dom().querySelector<HTMLSelectElement>('[data-testid="credential-choice"]')!;
        again.value = 'none';
        again.dispatchEvent(new Event('change'));
        await settle();
        await click('preview');
        expect(previewRequest().request.body).toMatchObject({ credentials: [{ host: HOST }] });
    });

    it('queues first scans only when asked, spaced within ten seconds and ten minutes', async () => {
        await open();

        expect(dom().querySelector('#spacing')).toBeNull();
        dom().querySelector<HTMLInputElement>('#first-scan')!.click();
        await settle();
        const spacing = dom().querySelector<HTMLInputElement>('#spacing')!;
        expect(spacing.value).toBe('60');

        spacing.value = '5';
        spacing.dispatchEvent(new Event('input'));
        await settle();
        await click('preview');
        http.expectNone({ method: 'POST', url: `${BASE}/preview` });
        expect(text('[data-testid="spacing-hint"]')).toBe('Between 10 and 600 seconds.');
        expect(button('import').disabled).toBe(true);

        spacing.value = '120';
        spacing.dispatchEvent(new Event('input'));
        await settle();
        await click('preview');
        expect(previewRequest().request.body).toMatchObject({ firstScan: true, spacingSeconds: 120 });
    });

    it('lists what the import would refuse with the reason, and does not offer to import', async () => {
        await open({
            ...PREVIEW,
            refused: [
                {
                    forgeId: '102',
                    fullPath: 'acme/backend/payments/worker',
                    refusal: 'A project belongs to a solution: name the solution of project "worker".'
                }
            ]
        });

        expect(text('[data-testid="preview-summary"]')).toContain('1 repository refused');
        expect(text('[data-testid="refused"]')).toContain('name the solution of project "worker"');
        expect(text('[data-testid="import-blocked"]')).toContain('refused whole');
        expect(button('import').disabled).toBe(true);
    });

    it('imports exactly what was previewed, and hands the batch up', async () => {
        await open();
        const done: ImportDone[] = [];
        fixture.componentInstance.imported.subscribe((value) => done.push(value));

        await click('import');
        const request = http.expectOne({ method: 'POST', url: BASE });
        expect(request.request.body).toEqual(fixture.componentInstance.request());
        expect(request.request.body).toMatchObject({ forgeIds: ['101', '102'], firstScan: false });
        request.flush(RESULT);
        await settle();

        expect(done).toEqual([{ result: RESULT, batch: ['101', '102'] }]);
    });

    it("shows the import's refusal and asks for a fresh preview", async () => {
        await open();
        await click('import');
        http.expectOne({ method: 'POST', url: BASE }).flush(
            { status: 400, detail: '1 of the selected repositories would be refused — acme/x: no.' },
            { status: 400, statusText: 'Bad Request' }
        );
        await settle();

        expect(text('[data-testid="import-error"]')).toContain('would be refused');
        expect(text('[data-testid="stale"]')).toContain('preview again');
        expect(button('import').disabled).toBe(true);
    });

    it('shows the result: the created targets linked, what was skipped, and where the audit entry is', async () => {
        await open(PREVIEW, asSchema('ForgeImportResult', RESULT));

        expect(text('[data-testid="result-summary"]')).toBe('2 targets created. 1 repository skipped.');
        const links = Array.from(dom().querySelectorAll('[data-testid="target-link"]')).map((a) =>
            a.getAttribute('href')
        );
        expect(links).toEqual(['/issues?repository_id=41', '/issues?repository_id=42']);
        expect(dom().querySelector('[data-testid="first-scan-link"]')?.getAttribute('href')).toBe('/scans/900');
        expect(text('[data-testid="result-skipped"]')).toBe('acme/frontend/portal — Already a target');
        expect(text('[data-testid="audit-hint"]')).toContain('"Repositories imported from a forge"');
        http.expectNone({ method: 'POST', url: `${BASE}/preview` });
    });

    it('imports at most a thousand at a time, and says so', async () => {
        fixture = TestBed.createComponent(ForgeImportStep);
        fixture.componentRef.setInput('connectionId', CONNECTION_ID);
        fixture.componentRef.setInput('discoveryId', 12);
        fixture.componentRef.setInput(
            'forgeIds',
            Array.from({ length: 1_200 }, (_, i) => String(i + 1))
        );
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne('/api/v1/ssh-keys').flush([]);
        http.expectOne('/api/v1/git-tokens').flush([]);
        http.expectOne('/api/v1/solutions').flush({ solutions: [], unfiled: { openIssues: {}, repositories: [] } });
        const preview = previewRequest();
        expect((preview.request.body as { forgeIds: string[] }).forgeIds.length).toBe(1_000);
        preview.flush(PREVIEW);
        await settle();
        expect(text('[data-testid="batch-bound"]')).toContain('1200 are selected and an import takes at most 1000');
    });
});
