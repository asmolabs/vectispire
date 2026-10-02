import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { ApiKeys } from './api-keys';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The scopes a new key is offered, and which are ticked before anybody chooses.
 *
 * **`sarif_import` is offered and never ticked by default** (decision 0017 §7): a key holding it can
 * deposit findings into a backlog once declared as a source, and the server's own defaults leave it
 * out. A form that pre-ticked it would issue that right with every CI key.
 */
describe('the API key form', () => {
    let fixture: ComponentFixture<ApiKeys>;
    let http: HttpTestingController;

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [ApiKeys],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();

        fixture = TestBed.createComponent(ApiKeys);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne('/api/v1/api-keys').flush([]);
        http.expectOne('/api/v1/api-keys/targets').flush({ repositories: [], containers: [] });
        fixture.detectChanges();
    });

    function openForm(): void {
        fixture.componentInstance.openForm();
        fixture.detectChanges();
    }

    function issue(): { scopes: string[] } {
        fixture.componentInstance.form.name = 'payments-ci';
        fixture.componentInstance.submit();
        const request = http.expectOne({ method: 'POST', url: '/api/v1/api-keys' });
        const body = asSchema('ApiKeyCreateRequest', request.request.body) as { scopes: string[] };
        request.flush({ key: null, secret: 'vsp_secret' });
        return body;
    }

    it('offers the SARIF import scope, unticked, with what it takes to work', () => {
        openForm();

        // The checkbox itself, in the dialog: a scope listed in the component and never rendered
        // would pass a component test.
        const box = document.querySelector('#sarif_import');
        expect(box).not.toBeNull();
        expect(fixture.componentInstance.form.scopes).not.toContain('sarif_import');
        expect(document.body.textContent).toContain('api_keys.scopes_list.sarif_import_hint');
    });

    it('does not send it unless it is ticked', () => {
        openForm();
        expect(issue().scopes).toEqual(['read', 'scan', 'export']);
    });

    it('sends it once ticked', () => {
        openForm();
        fixture.componentInstance.toggleScope('sarif_import', true);
        expect(issue().scopes).toContain('sarif_import');
    });

    it('offers the report import scope the same way: unticked, explained, sent only once ticked', () => {
        openForm();

        expect(document.querySelector('#report_import')).not.toBeNull();
        expect(fixture.componentInstance.form.scopes).not.toContain('report_import');
        expect(document.body.textContent).toContain('api_keys.scopes_list.report_import_hint');
        fixture.componentInstance.toggleScope('report_import', true);
        expect(issue().scopes).toEqual(['read', 'scan', 'export', 'report_import']);
    });

    it('still does not offer the agent scope', () => {
        openForm();
        expect(document.querySelector('#agent')).toBeNull();
    });
});

/**
 * The keys screen as an operator drives it: the list, the issued secret shown once, a revocation and
 * its refusal — through the buttons and the dialogs, since a component test passed while a field was
 * missing from the page for a month.
 */
describe('the API keys screen', () => {
    let fixture: ComponentFixture<ApiKeys>;
    let http: HttpTestingController;

    const KEY = asSchema('ApiKeySummary', {
        id: '5d0c8e3a-91f2-4b6e-a7d4-3c2b1e0f9a68',
        name: 'payments-ci',
        prefix: 'vsp_3f9a',
        scopes: ['read', 'scan', 'sarif_import'],
        targetKind: 'repository',
        targetId: 5,
        targetLabel: 'Arm Libs Spring',
        owner: 'alice',
        createdAt: '2026-09-01T08:00:00Z',
        lastUsedAt: null,
        expiresAt: null,
        isExpired: false
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [ApiKeys],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();

        fixture = TestBed.createComponent(ApiKeys);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne('/api/v1/api-keys/targets').flush({ repositories: [], containers: [] });
    });

    function list(keys: unknown[] = [KEY]): void {
        http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/api-keys').flush(keys);
        fixture.detectChanges();
    }

    function click(name: string, last = false): void {
        const named = [...document.querySelectorAll<HTMLButtonElement>('button')].filter(
            (candidate) => candidate.getAttribute('aria-label') === name || candidate.textContent.trim() === name
        );
        if (named.length === 0) throw new Error(`no button named ${name}`);
        named[last ? named.length - 1 : 0].click();
        fixture.detectChanges();
    }

    const messages = () => [...document.querySelectorAll('p-message')].map((message) => message.textContent).join(' ');

    it('lists each key with its prefix, scopes, target and owner, and says it was never used', () => {
        list();

        const row = (fixture.nativeElement as HTMLElement).querySelector('tbody tr')!;
        expect(row.textContent).toContain('payments-ci');
        expect(row.textContent).toContain('vsp_3f9a…');
        expect(row.textContent).toContain('api_keys.scopes_list.sarif_import');
        expect(row.textContent).toContain('Arm Libs Spring');
        expect(row.textContent).toContain('alice');
        expect(row.textContent).toContain('api_keys.never');
    });

    it('says the list could not be loaded', () => {
        http.expectOne('/api/v1/api-keys').flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        expect(messages()).toContain('api_keys.error_load');
    });

    it('shows the issued secret once, and forgets it when dismissed', () => {
        list([]);
        click('api_keys.issue_btn');
        const name = document.querySelector<HTMLInputElement>('#name')!;
        name.value = ' payments-ci ';
        name.dispatchEvent(new Event('input'));
        click('common.create');

        const request = http.expectOne({ method: 'POST', url: '/api/v1/api-keys' });
        expect((request.request.body as { name: string }).name).toBe('payments-ci');
        request.flush({ key: KEY, secret: 'vsp_3f9a_the-whole-secret' });
        fixture.detectChanges();
        list();

        expect(document.body.textContent).toContain('vsp_3f9a_the-whole-secret');
        click('common.confirm');
        expect(document.body.textContent).not.toContain('vsp_3f9a_the-whole-secret');
        expect(fixture.componentInstance.issuedSecret()).toBeNull();
    });

    it("keeps the form open on the server's refusal, and shows its reason", () => {
        list([]);
        click('api_keys.issue_btn');
        click('common.create');

        http.expectOne({ method: 'POST', url: '/api/v1/api-keys' }).flush(
            { detail: 'A key needs a name.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        expect(document.querySelector('#name')).not.toBeNull();
        expect(messages()).toContain('A key needs a name.');
    });

    it('revokes a key once confirmed, from its named trash button', () => {
        list();
        click('api_keys.aria_revoke');
        expect(document.body.textContent).toContain('api_keys.delete_confirm');
        click('common.delete', true);

        http.expectOne({ method: 'DELETE', url: '/api/v1/api-keys/5d0c8e3a-91f2-4b6e-a7d4-3c2b1e0f9a68' }).flush(null);
        list([]);

        expect(fixture.nativeElement.textContent).toContain('api_keys.no_keys');
    });

    it('keeps the refusal of a revocation on screen through the reload that follows it', () => {
        list();
        click('api_keys.aria_revoke');
        click('common.delete', true);

        http.expectOne({ method: 'DELETE', url: '/api/v1/api-keys/5d0c8e3a-91f2-4b6e-a7d4-3c2b1e0f9a68' }).flush(
            { detail: 'Only an administrator may revoke a key it does not own.' },
            { status: 403, statusText: 'Forbidden' }
        );
        list();

        expect(messages()).toContain('Only an administrator may revoke a key it does not own.');
    });
});
