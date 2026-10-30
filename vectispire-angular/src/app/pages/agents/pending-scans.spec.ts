import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { agentActivity, pendingScan } from '@/app/core/testing/agents.fixtures';
import { mountOnAgents } from './agents-page.testing';
import { PendingScans } from './pending-scans';

/** The queue, on its own. */
describe('the scan queue', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('says the queue is empty', () => {
        const { dom } = mountOnAgents(PendingScans, { activity: agentActivity() });
        expect(dom().textContent).toContain('Queue is empty');
    });

    it('shows each scan in its place, waiting, and routable or blocked', () => {
        const { dom } = mountOnAgents(PendingScans, {
            activity: agentActivity(
                [],
                [
                    pendingScan(),
                    pendingScan({ scanId: 9, positionInQueue: 2, isRoutable: false, waitDurationSeconds: 61 })
                ]
            )
        });
        const rows = [...dom().querySelectorAll('tbody tr')].map((row) => row.textContent.replace(/\s+/g, ' '));
        expect(rows[0]).toContain('#1');
        expect(rows[0]).toContain('12s');
        expect(rows[0]).toContain('Ready for Dispatch');
        expect(rows[1]).toContain('#2');
        expect(rows[1]).toContain('1m 1s');
        expect(rows[1]).toContain('Blocked (no matching agent label)');
    });
});
