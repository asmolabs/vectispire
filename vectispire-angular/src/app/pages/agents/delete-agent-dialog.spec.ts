import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { agentSummary } from '@/app/core/testing/agents.fixtures';
import { mountOnAgents } from './agents-page.testing';
import { DeleteAgentDialog } from './delete-agent-dialog';

/** Deleting an agent, on its own: the agent asked about, and a refusal said above the page. */
describe('the delete-agent dialog', () => {
    afterEach(() => TestBed.resetTestingModule());

    const AGENT = agentSummary();

    it('deletes the agent it was opened on and reads the fleet again', () => {
        const { page, fixture, http } = mountOnAgents(DeleteAgentDialog);
        page.askDelete(AGENT);
        fixture.detectChanges();
        expect(document.body.textContent).toContain(`${AGENT.name} — Are you sure`);
        fixture.componentInstance.confirmDelete();
        const call = http.expectOne((request) => request.method === 'DELETE');
        expect(call.request.url).toBe(`/api/v1/admin/agents/${AGENT.id}`);
        call.flush(null);
        expect(page.deleteVisible()).toBe(false);
        http.expectOne('/api/v1/admin/agents');
    });

    it('closes on a refusal and says it in the server’s words', () => {
        const { page, http, fixture } = mountOnAgents(DeleteAgentDialog);
        page.askDelete(AGENT);
        fixture.componentInstance.confirmDelete();
        http.expectOne((request) => request.method === 'DELETE').flush(
            { detail: 'The agent still holds a scan.' },
            { status: 409, statusText: 'Conflict' }
        );
        expect(page.deleteVisible()).toBe(false);
        expect(page.error()).toBe('The agent still holds a scan.');
    });
});
