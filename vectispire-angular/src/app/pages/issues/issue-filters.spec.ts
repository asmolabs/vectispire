import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { afterEach, describe, expect, it } from 'vitest';
import { IssueFilters } from './issue-filters';
import { mountOnIssues } from './issues-page.testing';

/**
 * The filters, on its own: a switch shows what the URL asks — including when a link changes it while
 * the screen is open, which a plain field left unseen — and a switch moved writes the URL.
 */
describe('the filters of the issue backlog', () => {
    afterEach(() => TestBed.resetTestingModule());

    const switchOf = (dom: HTMLElement, id: string) => dom.querySelector<HTMLInputElement>(`#${id}`)!;

    it('follows the URL when a link changes it under an open screen', async () => {
        const { dom, fixture, http } = mountOnIssues(IssueFilters);
        expect(switchOf(dom(), 'filter-kev').checked).toBe(false);

        await TestBed.inject(Router).navigateByUrl('/?is_kev=true&overdue=true');
        http.expectOne((call) => call.url === '/api/v1/issues');
        await fixture.whenStable();
        expect(switchOf(dom(), 'filter-kev').checked).toBe(true);
        expect(switchOf(dom(), 'filter-overdue').checked).toBe(true);
    });

    it('writes a switch moved into the URL', async () => {
        const { dom, fixture } = mountOnIssues(IssueFilters);
        switchOf(dom(), 'filter-unsettled').click();
        await fixture.whenStable();
        expect(TestBed.inject(Router).url).toBe('/?unsettled=true');
    });
});
