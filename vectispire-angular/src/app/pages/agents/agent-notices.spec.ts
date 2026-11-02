import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { executorState } from '@/app/core/testing/agents.fixtures';
import { asSchema } from '@/app/core/testing/contract';
import { AgentNotices } from './agent-notices';
import { mountOnAgents, textOf } from './agents-page.testing';

/** The notices above the figures, on their own. */
describe('the agents screen notices', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('names the labels a credentialed scan waits on, no label in words, and the agents to fix', () => {
        const { dom } = mountOnAgents(AgentNotices, {
            backlog: asSchema('UnservedCredentialedScans', { scans: 2, labels: ['', 'dmz'], keptAgents: ['a', 'b'] })
        });
        const text = textOf(dom(), '[data-testid="credentialed-backlog"]');
        expect(text).toContain('label: none, dmz');
        expect(text).toContain('a, b would take them');
    });

    it('says which label no agent carries', () => {
        const { dom } = mountOnAgents(AgentNotices, {
            unroutable: [asSchema('UnroutableLabel', { label: 'airgap', queued: 1 })]
        });
        expect(dom().textContent).toContain('1 scan requires the label "airgap"');
    });

    it('says the activity could not be read', () => {
        const { dom } = mountOnAgents(AgentNotices);
        expect(textOf(dom(), '[data-testid="activity-error"]')).toBe('Could not load the running and waiting scans.');
    });

    it('says the built-in worker claims nothing while its executor does not answer, in its words', () => {
        const down = asSchema('BuiltInWorkerState', {
            enabled: true,
            runsScans: true,
            executors: [
                executorState({ available: false, detail: 'The Docker daemon did not answer a ping: refused' })
            ],
            checkedAt: '2026-11-01T10:00:00Z'
        });
        const { dom } = mountOnAgents(AgentNotices, { builtIn: down });
        expect(textOf(dom(), '[data-testid="built-in-worker-down"]')).toContain(
            'claims no scan: its executor does not answer (The Docker daemon did not answer a ping: refused)'
        );
    });

    it('says nothing of a built-in worker that answers, or that is not meant to run', () => {
        const up = asSchema('BuiltInWorkerState', {
            enabled: true,
            runsScans: true,
            executors: [executorState()],
            checkedAt: '2026-11-01T10:00:00Z'
        });
        expect(
            mountOnAgents(AgentNotices, { builtIn: up }).dom().querySelector('[data-testid="built-in-worker-down"]')
        ).toBeNull();
        TestBed.resetTestingModule();
        const off = asSchema('BuiltInWorkerState', {
            enabled: false,
            runsScans: false,
            executors: [executorState({ available: false, detail: 'no daemon' })],
            checkedAt: null
        });
        expect(
            mountOnAgents(AgentNotices, { builtIn: off }).dom().querySelector('[data-testid="built-in-worker-down"]')
        ).toBeNull();
    });
});
