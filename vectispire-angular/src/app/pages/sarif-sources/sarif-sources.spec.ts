import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { SessionStore } from '@/app/core/session.store';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { SOURCE } from '@/app/core/testing/plugins.fixtures';
import { SarifSources, toolsOf } from './sarif-sources';

/**
 * The declared sources (decisions 0017 §7, 0032 §7).
 *
 * Governance reads them; the platform governor alone declares, enables and removes. What the form
 * must get right is the one invariant the declaration exists for — **exactly one scope**, a project
 * or a repository, never both and never none — the kinds, at least one, and the key: only one
 * holding the scope of every chosen kind (`sarif_import` for SARIF, `report_import` for the others).
 */
describe('the declared sources', () => {
    const REPORTS_KEY = '5f0c3c1e-0000-4000-8000-000000000004';
    const BOTH_KEY = '5f0c3c1e-0000-4000-8000-000000000005';

    let fixture: ComponentFixture<SarifSources>;
    let http: HttpTestingController;

    const KEY = (id: string, name: string, scopes: string[], isExpired = false) =>
        asSchema('ApiKeySummary', {
            id,
            name,
            scopes,
            prefix: 'vsp_1234',
            isExpired,
            targetKind: null,
            targetId: null,
            targetLabel: null,
            createdAt: null,
            lastUsedAt: null,
            expiresAt: null
        });

    async function start(role: string): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [SarifSources],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        TestBed.inject(SessionStore).open('token', {
            username: 'someone',
            displayName: null,
            role,
            mustChangePassword: false,
            mfaEnabled: false
        });
        useEnglish();
        fixture = TestBed.createComponent(SarifSources);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne('/api/v1/sarif-sources').flush([SOURCE]);
        http.expectOne('/api/v1/solutions').flush({
            solutions: [{ id: 1, name: 'Payments', projects: [{ id: 12, name: 'Gateway' }] }],
            unfiled: null
        });
        http.expectOne('/api/v1/repositories').flush([{ id: 42, displayName: 'api-gateway' }]);
        if (role === 'SUPERUSER' || role === 'ADMIN') {
            http.expectOne('/api/v1/api-keys').flush([
                KEY(SOURCE.apiKeyId, 'payments-ci-key', ['read', 'sarif_import']),
                KEY('5f0c3c1e-0000-4000-8000-000000000002', 'read-only', ['read']),
                KEY('5f0c3c1e-0000-4000-8000-000000000003', 'old', ['sarif_import'], true),
                KEY(REPORTS_KEY, 'reports-only', ['read', 'report_import']),
                KEY(BOTH_KEY, 'both', ['sarif_import', 'report_import'])
            ]);
        }
        fixture.detectChanges();
    }

    const dom = () => fixture.nativeElement as HTMLElement;

    it('shows an auditor each source with its scope by name, its kinds, its tools and its key, and no action', async () => {
        await start('AUDITOR');

        const row = dom().querySelector('[data-testid="source-payments-ci"]')?.textContent ?? '';
        expect(
            dom().querySelector('[data-testid="source-payments-ci"] [data-testid="source-kinds"]')?.textContent
        ).toContain('SARIF');
        expect(row).toContain('Payments CI');
        expect(row).toContain('Project Payments / Gateway');
        expect(row).toContain('SonarQube');
        expect(row).toContain(SOURCE.apiKeyId.slice(0, 8));
        expect(dom().querySelector('#declare-source')).toBeNull();
        expect(dom().querySelector('[aria-label="Remove source payments-ci"]')).toBeNull();
    });

    it('offers the governor only the usable keys that hold sarif_import', async () => {
        await start('SUPERUSER');

        expect(dom().querySelector('#declare-source')).not.toBeNull();
        expect(dom().querySelector('[data-testid="source-payments-ci"]')?.textContent).toContain('payments-ci-key');
        expect(fixture.componentInstance.keyOptions().map((option) => option.value)).toEqual([
            SOURCE.apiKeyId,
            BOTH_KEY
        ]);
    });

    it('lists every kind a source delivers, by name, and a kind it does not know as itself', async () => {
        await start('AUDITOR');

        fixture.componentInstance.sources.set([
            { ...SOURCE, kinds: ['sarif', 'coverage', 'test_report'] },
            { ...SOURCE, id: 4, slug: 'future', kinds: ['sbom' as never] }
        ]);
        fixture.detectChanges();
        const kinds = (slug: string) =>
            Array.from(dom().querySelectorAll(`[data-testid="source-${slug}"] [data-testid="source-kinds"] p-tag`)).map(
                (tag) => tag.textContent?.trim()
            );
        expect(kinds('payments-ci')).toEqual(['SARIF', 'Coverage', 'Test reports']);
        expect(kinds('future')).toEqual(['sbom']);
    });

    it('asks for the tools only while SARIF is among the kinds, and sends none without it', async () => {
        await start('SUPERUSER');
        const page = fixture.componentInstance;

        page.openDeclare();
        fixture.detectChanges();
        expect(document.querySelector('#source-tools')).not.toBeNull();

        // Through the checkboxes, as the governor ticks them: the dialog re-renders on their events.
        (document.querySelector('#source-kind-coverage') as HTMLInputElement).click();
        (document.querySelector('#source-kind-sarif') as HTMLInputElement).click();
        fixture.detectChanges();
        expect(page.draft.kinds).toEqual(['coverage']);
        expect(document.querySelector('#source-tools')).toBeNull();
        // Typed while SARIF was ticked, then left behind: not sent.
        Object.assign(page.draft, { slug: 'cov-ci', name: 'Coverage CI', scopeId: 12, tools: 'SonarQube' });
        // Keys are now those holding report_import; the SARIF-only key is no longer offered.
        expect(page.keyOptions().map((option) => option.value)).toEqual([REPORTS_KEY, BOTH_KEY]);
        page.draft.apiKeyId = REPORTS_KEY;
        expect(page.canDeclare()).toBe(true);
        page.declare();

        const body = asSchema(
            'SourceDeclaration',
            http.expectOne({ method: 'POST', url: '/api/v1/sarif-sources' }).request.body
        ) as Record<string, unknown>;
        expect(body['kinds']).toEqual(['coverage']);
        expect(body['tools']).toEqual([]);
    });

    it('will not declare SARIF without tools, nor a source delivering nothing', async () => {
        await start('SUPERUSER');
        const page = fixture.componentInstance;

        page.openDeclare();
        Object.assign(page.draft, { slug: 'x', name: 'x', apiKeyId: BOTH_KEY, scopeId: 12, tools: ' , ' });
        page.setKind('test_report', true);
        expect(page.canDeclare()).toBe(false);
        page.draft.tools = 'SonarQube';
        expect(page.canDeclare()).toBe(true);

        page.setKind('sarif', false);
        page.setKind('test_report', false);
        fixture.detectChanges();
        expect(page.draft.kinds).toEqual([]);
        expect(page.canDeclare()).toBe(false);
        expect(document.querySelector('[data-testid="no-kind"]')?.textContent).toContain('at least one kind');
        page.declare();
        http.expectNone({ method: 'POST', url: '/api/v1/sarif-sources' });
    });

    it('sends the kinds in the form order, and drops a chosen key a new kind no longer fits', async () => {
        await start('SUPERUSER');
        const page = fixture.componentInstance;

        page.openDeclare();
        page.draft.apiKeyId = SOURCE.apiKeyId;
        page.setKind('test_report', true);
        // The SARIF-only key cannot deliver a test report: the server would refuse it.
        expect(page.draft.apiKeyId).toBeNull();
        page.setKind('sarif', false);
        page.setKind('sarif', true);
        expect(page.draft.kinds).toEqual(['sarif', 'test_report']);
    });

    it('declares with exactly one scope, the other one absent from the body', async () => {
        await start('SUPERUSER');

        fixture.componentInstance.openDeclare();
        Object.assign(fixture.componentInstance.draft, {
            slug: 'payments-ci',
            name: 'Payments CI',
            apiKeyId: SOURCE.apiKeyId,
            scopeId: 12,
            tools: 'Semgrep OSS, SonarQube,  sonarqube'
        });
        // A repository chosen then abandoned for a project must not travel with it.
        fixture.componentInstance.setScopeKind('repository');
        expect(fixture.componentInstance.draft.scopeId).toBeNull();
        fixture.componentInstance.setScopeKind('project');
        fixture.componentInstance.draft.scopeId = 12;
        fixture.componentInstance.declare();

        const request = http.expectOne({ method: 'POST', url: '/api/v1/sarif-sources' });
        const body = asSchema('SourceDeclaration', request.request.body) as Record<string, unknown>;
        expect(body['project_id']).toBe(12);
        expect('repository_id' in body).toBe(false);
        expect(body['tools']).toEqual(['Semgrep OSS', 'SonarQube', 'sonarqube']);
        expect(body['kinds']).toEqual(['sarif']);
        request.flush(SOURCE, { status: 201, statusText: 'Created' });
        http.expectOne('/api/v1/sarif-sources').flush([SOURCE]);
    });

    it('declares a repository scope as repository_id alone', async () => {
        await start('SUPERUSER');

        fixture.componentInstance.openDeclare();
        fixture.componentInstance.setScopeKind('repository');
        Object.assign(fixture.componentInstance.draft, {
            slug: 'gw-ci',
            name: 'Gateway CI',
            apiKeyId: SOURCE.apiKeyId,
            scopeId: 42,
            tools: 'Semgrep OSS'
        });
        fixture.componentInstance.declare();

        const body = http.expectOne({ method: 'POST', url: '/api/v1/sarif-sources' }).request.body as Record<
            string,
            unknown
        >;
        expect(body['repository_id']).toBe(42);
        expect('project_id' in body).toBe(false);
    });

    it('will not declare without a scope', async () => {
        await start('SUPERUSER');

        fixture.componentInstance.openDeclare();
        Object.assign(fixture.componentInstance.draft, {
            slug: 'x',
            name: 'x',
            apiKeyId: SOURCE.apiKeyId,
            tools: 'SonarQube'
        });
        expect(fixture.componentInstance.canDeclare()).toBe(false);
        fixture.componentInstance.declare();
        http.expectNone({ method: 'POST', url: '/api/v1/sarif-sources' });
    });

    it("keeps the server's refusal in the dialog", async () => {
        await start('SUPERUSER');

        fixture.componentInstance.openDeclare();
        Object.assign(fixture.componentInstance.draft, {
            slug: 'payments-ci',
            name: 'x',
            apiKeyId: SOURCE.apiKeyId,
            scopeId: 12,
            tools: 'SonarQube'
        });
        fixture.componentInstance.declare();
        http.expectOne({ method: 'POST', url: '/api/v1/sarif-sources' }).flush(
            { detail: 'This key already names a source.' },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();
        expect(document.querySelector('[data-testid="source-form-error"]')?.textContent).toContain('already names');
    });

    it('disables with a PUT, and removes after saying the imported issues stay', async () => {
        await start('SUPERUSER');

        fixture.componentInstance.setEnabled(SOURCE, false);
        const toggle = http.expectOne({ method: 'PUT', url: '/api/v1/sarif-sources/3/enabled' });
        expect(toggle.request.body).toEqual({ enabled: false });
        toggle.flush({ ...SOURCE, enabled: false });

        fixture.componentInstance.askRemove(SOURCE);
        fixture.detectChanges();
        expect(document.querySelector('[data-testid="remove-consequence"]')?.textContent).toContain(
            'What it imported stays'
        );
        fixture.componentInstance.confirmRemove();
        http.expectOne({ method: 'DELETE', url: '/api/v1/sarif-sources/3' }).flush(null);
        http.expectOne('/api/v1/sarif-sources').flush([]);
    });
});

describe('the tools as typed', () => {
    it('splits on commas and lines, trims, and drops blanks and exact repeats', () => {
        expect(toolsOf(' Semgrep OSS ,\nSonarQube,,SonarQube ')).toEqual(['Semgrep OSS', 'SonarQube']);
        expect(toolsOf('  ')).toEqual([]);
    });
});
