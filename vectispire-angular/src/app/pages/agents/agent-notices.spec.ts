import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
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
});
