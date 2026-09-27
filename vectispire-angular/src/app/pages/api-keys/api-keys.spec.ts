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

    it('still does not offer the agent scope', () => {
        openForm();
        expect(document.querySelector('#agent')).toBeNull();
    });
});
