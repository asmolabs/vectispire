import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { agentActivity, agentSummary, executorState, runningScan } from '@/app/core/testing/agents.fixtures';
import { AgentTable } from './agent-table';
import { mountOnAgents } from './agents-page.testing';

/** The registered agents, on their own. */
describe('the agent table', () => {
    afterEach(() => TestBed.resetTestingModule());

    const BUSY = agentSummary({ runningScans: 1, labels: 'dmz,linux' });
    const OFF = agentSummary({ id: '00000000-0000-0000-0000-0000000000cc', name: 'off', enabled: false });

    function rows(dom: HTMLElement): string[] {
        return [...dom.querySelectorAll('tbody tr')].map((row) => row.textContent.replace(/\s+/g, ' '));
    }

    it('says what a busy agent runs and for how long, and splits its labels into tags', () => {
        const { dom } = mountOnAgents(AgentTable, {
            agents: [BUSY, OFF],
            activity: agentActivity([runningScan({ durationSeconds: 90 })])
        });
        expect(rows(dom())[0]).toContain('billing-api (1m 30s)');
        const tags = [...dom().querySelectorAll('tbody tr:first-child p-tag')].map((tag) => tag.textContent.trim());
        expect(tags).toEqual(expect.arrayContaining(['dmz', 'linux']));
        expect(rows(dom())[1]).toContain('Disabled');
        expect(rows(dom())[1]).toContain('Unlabelled targets');
    });

    it('opens the limit dialog on the agent of the row', () => {
        const { dom, page } = mountOnAgents(AgentTable, { agents: [BUSY] });
        dom()
            .querySelector<HTMLButtonElement>(`button[aria-label="Change how many scans ${BUSY.name} runs at once"]`)
            ?.click();
        expect(page.concurrencyAgent()).toBe(BUSY);
        expect(page.concurrencyVisible()).toBe(true);
    });

    it('locks the acts on an agent while one is in flight', () => {
        const { dom, page, fixture } = mountOnAgents(AgentTable, { agents: [BUSY] });
        page.busy.set(BUSY.id);
        fixture.detectChanges();
        const disable = dom().querySelector<HTMLButtonElement>(`button[aria-label="Disable ${BUSY.name}"]`);
        expect(disable?.disabled).toBe(true);
    });

    it('shows each executor, whether it can run anything, what it scans and why not', () => {
        const { dom } = mountOnAgents(AgentTable, {
            agents: [
                agentSummary({ executors: null }),
                agentSummary({
                    id: '00000000-0000-0000-0000-0000000000dd',
                    name: 'down',
                    executors: [
                        executorState({
                            available: false,
                            detail: 'The Docker daemon did not answer a ping: connection refused'
                        })
                    ]
                }),
                agentSummary({
                    id: '00000000-0000-0000-0000-0000000000ee',
                    name: 'cluster',
                    executors: [executorState({ kind: 'kubernetes', targets: ['repository'] })]
                }),
                agentSummary({ id: '00000000-0000-0000-0000-0000000000ff', name: 'bare', executors: [] })
            ]
        });
        const cells = [...dom().querySelectorAll('[data-testid="executors"]')].map((cell) =>
            cell.textContent.replace(/\s+/g, ' ').trim()
        );
        // Never said: an older agent, which claims as before — not a fault to show in red.
        expect(cells[0]).toBe('Not reported');
        expect(cells[1]).toContain('docker');
        expect(cells[1]).toContain('Unavailable');
        expect(cells[1]).toContain('did not answer a ping');
        expect(cells[2]).toContain('kubernetes');
        expect(cells[2]).toContain('Available · repositories');
        expect(cells[2]).not.toContain('images');
        expect(cells[3]).toBe('No executor');
    });
});
