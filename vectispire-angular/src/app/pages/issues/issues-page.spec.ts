import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { afterEach, describe, expect, it } from 'vitest';
import { backlogEntry } from '@/app/core/testing/issues.fixtures';
import { IssueScope } from './issue-scope';
import { mountOnIssues } from './issues-page.testing';

/**
 * The issues screen's state on its own: the window it says it shows, the URL it writes — the defaults
 * left out, so a plain visit stays `/issues` — and a selection that never outlives the rows it was made on.
 */
describe('the state of the issues screen', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('names the window of the backlog it shows, and says when there is none', () => {
        const { page } = mountOnIssues(IssueScope, { issues: [backlogEntry(1)], total: 228 });
        expect(page.pageLabel()).toBe('1–50 of 228');
        page.total.set(0);
        expect(page.pageLabel()).toBe('No result');
    });

    it('writes the filters into the URL, leaving the defaults out', async () => {
        const { page, fixture } = mountOnIssues(IssueScope);
        page.severity.set('critical');
        page.onlyKev.set(true);
        page.filtersChanged();
        await fixture.whenStable();
        expect(TestBed.inject(Router).url).toBe('/?severity=critical&is_kev=true');
    });

    it('drops the selection when the list is read again', () => {
        const { page, http } = mountOnIssues(IssueScope, { issues: [backlogEntry(1), backlogEntry(2)] });
        page.selected.set(page.issues());
        page.reload(0);
        expect(page.selected()).toEqual([]);
        http.expectOne((call) => call.url === '/api/v1/issues');
    });
});
