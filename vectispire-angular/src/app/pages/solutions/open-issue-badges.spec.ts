import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { openIssues } from '@/app/core/testing/solutions.fixtures';
import { OpenIssueBadges } from './open-issue-badges';
import { mountOnSolutions } from './solutions-page.testing';

/**
 * The open-issue badges, on their own: a tag per severity that has any, worst first, each linking to the
 * list it counts with `unsettled` and named for the reader — and none linking where there is no scope.
 */
describe('the open-issue badges of a node', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('links each severity to the unsettled list of its scope, worst first', () => {
        const { dom } = mountOnSolutions(OpenIssueBadges, {
            inputs: { issues: openIssues(2, 1), scope: { project_id: 11 }, name: 'Payments / Gateway' }
        });
        const links = Array.from(dom().querySelectorAll('a'));
        expect(links.map((link) => link.textContent?.trim())).toEqual(['2 Critical', '1 High']);
        expect(links[0].getAttribute('href')).toBe('/issues?project_id=11&severity=critical&unsettled=true');
        expect(links[1].getAttribute('aria-label')).toBe('Open the issues of high severity in Payments / Gateway (1)');
    });

    it('says there is no open issue, and links nothing without a scope', () => {
        expect(
            mountOnSolutions(OpenIssueBadges, { inputs: { issues: openIssues(0, 0) } })
                .dom()
                .textContent?.trim()
        ).toBe('No open issues');
        TestBed.resetTestingModule();
        const unscoped = mountOnSolutions(OpenIssueBadges, { inputs: { issues: openIssues(0, 0, 4) } });
        expect(unscoped.dom().querySelector('a')).toBeNull();
        expect(unscoped.dom().textContent?.trim()).toBe('4 Medium');
    });
});
