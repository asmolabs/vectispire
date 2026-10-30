import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { agentActivity } from '@/app/core/testing/agents.fixtures';
import { AgentKpis } from './agent-kpis';
import { mountOnAgents } from './agents-page.testing';

/** The four tiles, on their own. */
describe('the agents screen tiles', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('shows nothing until the activity is read', () => {
        const { dom } = mountOnAgents(AgentKpis);
        expect(dom().textContent.trim()).toBe('');
    });

    it('counts the agents online and writes the average duration in minutes', () => {
        const { dom } = mountOnAgents(AgentKpis, {
            activity: agentActivity([], [], {
                onlineAgents: 2,
                totalAgents: 3,
                idleAgents: 1,
                busyAgents: 1,
                avgScanDurationSeconds: 75
            })
        });
        const text = dom().textContent.replace(/\s+/g, ' ');
        expect(text).toContain('2 / 3');
        expect(text).toContain('1 idle');
        expect(text).toContain('1m 15s');
    });
});
