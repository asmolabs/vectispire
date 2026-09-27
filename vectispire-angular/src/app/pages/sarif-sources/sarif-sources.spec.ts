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
 * The declared SARIF sources (decision 0017 §7).
 *
 * Governance reads them; the platform governor alone declares, enables and removes. What the form
 * must get right is the one invariant the declaration exists for — **exactly one scope**, a project
 * or a repository, never both and never none — and the key: only one holding `sarif_import`.
 */
describe('the SARIF sources', () => {
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
                KEY('5f0c3c1e-0000-4000-8000-000000000003', 'old', ['sarif_import'], true)
            ]);
        }
        fixture.detectChanges();
    }

    const dom = () => fixture.nativeElement as HTMLElement;

    it('shows an auditor each source with its scope by name, its tools and its key, and no action', async () => {
        await start('AUDITOR');

        const row = dom().querySelector('[data-testid="source-payments-ci"]')?.textContent ?? '';
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
        expect(fixture.componentInstance.keyOptions().map((option) => option.value)).toEqual([SOURCE.apiKeyId]);
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
            'The issues it imported stay'
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
