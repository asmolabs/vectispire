import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { agentActivity, runningScan } from '@/app/core/testing/agents.fixtures';
import { mountOnAgents } from './agents-page.testing';
import { RunningScans } from './running-scans';

/** The scans running now, on their own. */
describe('the running scans', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('says none run on an idle fleet', () => {
        const { dom } = mountOnAgents(RunningScans, { activity: agentActivity() });
        expect(dom().textContent).toContain('No scans currently running.');
    });

    it('shows each with its target, its label and how long it has run', () => {
        const { dom } = mountOnAgents(RunningScans, {
            activity: agentActivity([runningScan({ requiredLabel: 'dmz', durationSeconds: 130, branch: '' })])
        });
        const row = dom().querySelector('tbody tr')?.textContent?.replace(/\s+/g, ' ') ?? '';
        expect(row).toContain('billing-api');
        expect(row).toContain('—');
        expect(row).toContain('dmz');
        expect(row).toContain('2m 10s');
        expect(dom().textContent).toContain('1 running');
    });
});
