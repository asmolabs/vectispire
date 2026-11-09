import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { agentActivity, agentSummary, runningScan } from '@/app/core/testing/agents.fixtures';
import { AgentKpis } from './agent-kpis';
import { mountOnAgents } from './agents-page.testing';

/**
 * The agents screen's state, on its own: the scan each agent runs found once, a dialog opened on a
 * clean form, and the two acts made from the row without a dialog.
 */
describe('the state of the agents screen', () => {
    afterEach(() => TestBed.resetTestingModule());

    const AGENT = agentSummary();

    it('finds the scan each agent runs, the first one when it runs several', () => {
        const { page } = mountOnAgents(AgentKpis, {
            activity: agentActivity([
                runningScan({ scanId: 1, targetName: 'first' }),
                runningScan({ scanId: 2, targetName: 'second' }),
                runningScan({ scanId: 3, agentId: null, targetName: 'unassigned' })
            ])
        });
        expect(page.runningByAgent().get(AGENT.id)?.targetName).toBe('first');
        expect(page.runningByAgent().size).toBe(1);
    });

    it('opens the declaration on a clean form and the limit on the agent’s own', () => {
        const { page } = mountOnAgents(AgentKpis);
        page.formName.set('left over');
        page.formMaxConcurrent.set(9);
        page.formError.set('An earlier refusal.');
        page.openForm();
        expect([page.formName(), page.formMaxConcurrent(), page.formCredentialsMode(), page.formError()]).toEqual([
            '',
            1,
            'local',
            null
        ]);
        page.concurrencyError.set('An earlier refusal.');
        page.openConcurrency(AGENT);
        expect([page.concurrencyValue(), page.concurrencyError(), page.concurrencyVisible()]).toEqual([4, null, true]);
    });

    it('disables an enabled agent and reads the fleet again', () => {
        const { page, http } = mountOnAgents(AgentKpis, { agents: [AGENT] });
        page.toggle(AGENT);
        const patch = http.expectOne(`/api/v1/admin/agents/${AGENT.id}`);
        expect(patch.request.body).toEqual({ enabled: false });
        patch.flush(null);
        expect(page.busy()).toBeNull();
        http.expectOne('/api/v1/admin/agents');
    });

    it('shows the private half of a generated signing key once', () => {
        const { page, http } = mountOnAgents(AgentKpis, { agents: [AGENT] });
        page.toggleSigning(AGENT);
        const put = http.expectOne(`/api/v1/admin/agents/${AGENT.id}/signing-key`);
        expect(put.request.body).toEqual({ public_key: 'generate' });
        put.flush(asSchema('PinnedSigningKey', { id: AGENT.id, privateKey: 'PRIVATE', signsResults: true }));
        expect(page.issuedSigningKey()).toBe('PRIVATE');
        expect(page.signingKeyVisible()).toBe(true);
    });
});
