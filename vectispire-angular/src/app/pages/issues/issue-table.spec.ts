import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { Issue } from '@/app/core/api.models';
import { useFrench } from '@/app/core/testing/english';
import { backlogEntry } from '@/app/core/testing/issues.fixtures';
import { IssueTable } from './issue-table';
import { mountOnIssues, namedButton, textOf } from './issues-page.testing';

/**
 * The table, on its own: each row's type, deadline and triage in words, what a request awaiting
 * approval asks for, the row acts handed to the page, and the bulk act offered to whoever may decide.
 */
describe('the table of the issue backlog', () => {
    afterEach(() => TestBed.resetTestingModule());

    const late = backlogEntry(1, { slaState: 'overdue', slaDays: -3, identifier: 'CVE-2026-0001' });
    const requested = backlogEntry(2, {
        triageStatus: 'pending_approval',
        triageRequestedStatus: 'will_not_fix',
        identifier: 'CVE-2026-0002'
    });
    const rowOf = (dom: HTMLElement, issue: Issue): HTMLElement =>
        Array.from(dom.querySelectorAll<HTMLElement>('tbody tr')).find((row) =>
            row.textContent?.includes(issue.identifier ?? '')
        )!;

    it('states each row: its type, how late it is, and what a pending request asks for', () => {
        const { dom } = mountOnIssues(IssueTable, { issues: [late, requested] });
        expect(rowOf(dom(), late).textContent).toContain('Vulnerability');
        expect(rowOf(dom(), late).textContent).toContain('3 days late');
        expect(textOf(rowOf(dom(), requested), '[data-testid="issue-requested-status"]')).toBe(
            'asks for: Will not fix — risk accepted'
        );
    });

    it('hands a row to the page to triage or to explain', () => {
        const { dom, fixture } = mountOnIssues(IssueTable, { issues: [late] });
        const triaged: Issue[] = [];
        const advised: Issue[] = [];
        fixture.componentInstance.triage.subscribe((issue) => triaged.push(issue));
        fixture.componentInstance.advise.subscribe((issue) => advised.push(issue));
        namedButton(rowOf(dom(), late), 'Triage').click();
        namedButton(rowOf(dom(), late), 'Explain and suggest a fix (AI)').click();
        expect(triaged).toEqual([late]);
        expect(advised).toEqual([late]);
    });

    it('offers the bulk act over a selection to whoever decides, and says so to whoever reads', () => {
        const decides = mountOnIssues(IssueTable, { issues: [late, requested] });
        decides.page.selected.set([late, requested]);
        decides.fixture.detectChanges();
        expect(namedButton(decides.dom(), 'Triage (2)')).toBeTruthy();
        TestBed.resetTestingModule();

        const reads = mountOnIssues(IssueTable, { issues: [late], role: 'AUDITOR' });
        reads.page.selected.set([late]);
        reads.fixture.detectChanges();
        expect(reads.dom().textContent).toContain('This account observes and does not decide');
        expect(Array.from(reads.dom().querySelectorAll('button')).some((b) => b.textContent?.includes('Triage'))).toBe(
            false
        );
    });

    it('rewrites the rows when the language changes', () => {
        const { dom, fixture } = mountOnIssues(IssueTable, { issues: [late] });
        useFrench();
        fixture.detectChanges();
        expect(rowOf(dom(), late).textContent).not.toContain('3 days late');
    });
});
