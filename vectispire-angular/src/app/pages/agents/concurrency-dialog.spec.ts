import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { agentSummary } from '@/app/core/testing/agents.fixtures';
import { mountOnAgents } from './agents-page.testing';
import { ConcurrencyDialog } from './concurrency-dialog';

/** One agent's limit, on its own: a form, sent from a submit, its refusal said on the field. */
describe('the concurrency dialog', () => {
    afterEach(() => TestBed.resetTestingModule());

    const AGENT = agentSummary();
    const submit = () => document.querySelector('form#agent-concurrency')!.dispatchEvent(new Event('submit'));

    it('sends the new limit on a submit and closes', () => {
        const { http, page, fixture } = mountOnAgents(ConcurrencyDialog);
        page.openConcurrency(AGENT);
        page.concurrencyValue.set(6);
        fixture.detectChanges();
        submit();
        const patch = http.expectOne(`/api/v1/admin/agents/${AGENT.id}`);
        expect(patch.request.body).toEqual({ max_concurrent: 6 });
        patch.flush(null);
        expect(page.concurrencyVisible()).toBe(false);
    });

    it('requires the limit and points the field at its error once refused', () => {
        const { page, fixture, http } = mountOnAgents(ConcurrencyDialog);
        page.openConcurrency(AGENT);
        fixture.detectChanges();
        const input = document.querySelector<HTMLInputElement>('input#concurrent-edit')!;
        expect(input.getAttribute('aria-required')).toBe('true');
        expect(input.getAttribute('aria-describedby')).toBe('concurrent-edit-hint');

        page.concurrencyValue.set(null);
        submit();
        fixture.detectChanges();
        expect(input.getAttribute('aria-describedby')).toBe('concurrent-edit-hint concurrent-edit-error');
        expect(document.getElementById('concurrent-edit-error')?.textContent).toContain('between 1 and 16');
        http.expectNone(`/api/v1/admin/agents/${AGENT.id}`);
    });
});
