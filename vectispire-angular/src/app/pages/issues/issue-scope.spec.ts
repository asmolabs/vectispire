import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { afterEach, describe, expect, it } from 'vitest';
import { IssueScope } from './issue-scope';
import { mountOnIssues, namedButton, textOf } from './issues-page.testing';

/**
 * The scope a link applied, on its own: a project named by its number when the tree does not hold it,
 * taken off in one click; and the OWASP drill-down said in words, with the way back.
 */
describe('the scope of the issue backlog', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('shows the project a link narrowed to, and takes it off', async () => {
        const { dom, fixture, page } = mountOnIssues(IssueScope);
        page.projectId.set(12);
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="scope-project"]')).toBe('Project: #12');

        namedButton(dom(), 'Remove the project filter #12').click();
        await fixture.whenStable();
        expect(page.projectId()).toBeNull();
        expect(TestBed.inject(Router).url).toBe('/');
    });

    it('says the drill-down in words, and offers the way back to the week it came from', () => {
        const { dom, fixture, page } = mountOnIssues(IssueScope);
        page.owaspCategory.set('A06');
        page.openAt.set('2026-09-27');
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="weekly-banner-text"]')).toContain('A06');
        expect(dom().querySelector('[data-testid="weekly-back"]')!.getAttribute('href')).toContain('week=2026-09-21');
    });
});
