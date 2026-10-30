import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { agentSummary } from '@/app/core/testing/agents.fixtures';
import { mountOnAgents } from './agents-page.testing';
import { ResetSealingDialog } from './reset-sealing-dialog';

/** Forgetting a sealing key, on its own: the consequence said first, the change said after. */
describe('the reset-sealing dialog', () => {
    afterEach(() => TestBed.resetTestingModule());

    const AGENT = agentSummary({ credentialsMode: 'delegated', sealsCredentials: true });

    it('says what stops before the click, and that the key is forgotten after it', () => {
        const { page, fixture, http } = mountOnAgents(ResetSealingDialog);
        page.askResetSealing(AGENT);
        fixture.detectChanges();
        expect(document.body.textContent).toContain('will stop receiving delegated credentials');

        fixture.componentInstance.confirmResetSealing();
        expect(page.busy()).toBe(AGENT.id);
        http.expectOne(`/api/v1/admin/agents/${AGENT.id}/sealing-key`).flush(null, {
            status: 204,
            statusText: 'No Content'
        });
        expect(page.busy()).toBeNull();
        expect(page.resetSealingVisible()).toBe(false);
        expect(page.notice()).toBe(
            `The sealing key of ${AGENT.name} is forgotten. It receives no delegated credential until it proves a new one.`
        );
    });

    it('says the server’s refusal in its words', () => {
        const { page, http, fixture } = mountOnAgents(ResetSealingDialog);
        page.askResetSealing(AGENT);
        fixture.componentInstance.confirmResetSealing();
        http.expectOne(`/api/v1/admin/agents/${AGENT.id}/sealing-key`).flush(
            { detail: 'Sealing is switched off.' },
            { status: 409, statusText: 'Conflict' }
        );
        expect(page.error()).toBe('Sealing is switched off.');
    });
});
