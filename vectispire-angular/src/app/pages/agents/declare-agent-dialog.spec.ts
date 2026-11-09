import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { mountOnAgents } from './agents-page.testing';
import { DeclareAgentDialog } from './declare-agent-dialog';

/**
 * Declaring an agent, on its own: a form whose required fields say so, a refusal marked on the field
 * it is about, the declaration sent from a submit, and the secret handed to the page to show once.
 */
describe('the declare-agent dialog', () => {
    afterEach(() => TestBed.resetTestingModule());

    function open() {
        const mounted = mountOnAgents(DeclareAgentDialog);
        mounted.page.openForm();
        mounted.fixture.detectChanges();
        return mounted;
    }

    const submit = () => document.querySelector('form#declare-agent')!.dispatchEvent(new Event('submit'));

    it('marks the name required, and invalid with its error when left blank', () => {
        const { fixture, http } = open();
        const name = document.querySelector<HTMLInputElement>('input#name')!;
        expect(name.required).toBe(true);
        expect(name.getAttribute('aria-invalid')).toBe('false');

        submit();
        fixture.detectChanges();
        expect(name.getAttribute('aria-invalid')).toBe('true');
        expect(document.getElementById(name.getAttribute('aria-describedby')!)?.textContent).toContain(
            'Name is required.'
        );
        http.expectNone((request) => request.method === 'POST');
    });

    it('marks the limit, not the name, when the limit is out of bounds', () => {
        const { fixture, page } = open();
        page.formName.set('edge');
        page.formMaxConcurrent.set(17);
        submit();
        fixture.detectChanges();
        expect(document.querySelector('input#name')?.getAttribute('aria-invalid')).toBe('false');
        expect(document.querySelector('input#concurrent')?.getAttribute('aria-describedby')).toContain(
            'declare-agent-error'
        );
    });

    it('says what each credentials mode means as it is chosen', () => {
        const { fixture, page } = open();
        expect(fixture.componentInstance.hint()).toContain('its own git credentials');
        page.formCredentialsMode.set('delegated');
        expect(fixture.componentInstance.hint()).toContain('Requires an encrypted link');
    });

    it('declares on a submit, trimmed, and hands the secret to the page', () => {
        const { fixture, http, page } = open();
        page.formName.set('  edge  ');
        page.formLabels.set(' dmz ');
        page.formCredentialsMode.set('delegated');
        page.formMaxConcurrent.set(2);
        fixture.detectChanges();
        submit();
        const post = http.expectOne((request) => request.method === 'POST' && request.url === '/api/v1/admin/agents');
        expect(post.request.body).toEqual({
            name: 'edge',
            description: undefined,
            credentials_mode: 'delegated',
            labels: 'dmz',
            max_concurrent: 2
        });
        post.flush(asSchema('DeclaredAgent', { id: 'new', name: 'edge', secret: 'SECRET' }));
        expect(page.formVisible()).toBe(false);
        expect(page.issuedSecret()).toBe('SECRET');
        expect(page.secretVisible()).toBe(true);
    });
});
