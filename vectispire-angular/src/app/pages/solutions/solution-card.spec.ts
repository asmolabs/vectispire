import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { SolutionCard } from './solution-card';
import { mountOnSolutions, namedButton } from './solutions-page.testing';

/** One solution, on its own: its projects drawn, the one a link points at ringed, and its acts for an administrator. */
describe('a solution of the tree', () => {
    afterEach(() => TestBed.resetTestingModule());

    const payments = SOLUTION_TREE.solutions[0];

    it('draws its projects, and rings the one the link points at', () => {
        const { dom, fixture, page } = mountOnSolutions(SolutionCard, { inputs: { solution: payments } });
        expect(dom().querySelectorAll('app-project-card').length).toBe(2);
        page.focused.set('project-12');
        fixture.detectChanges();
        expect(dom().querySelector('#project-12')!.classList.contains('ring-2')).toBe(true);
        expect(dom().querySelector('#project-11')!.classList.contains('ring-2')).toBe(false);
    });

    it('opens a new project of this solution for an administrator', () => {
        const { dom, page } = mountOnSolutions(SolutionCard, { inputs: { solution: payments } });
        (dom().querySelector('[data-testid="new-project"] button') as HTMLButtonElement).click();
        expect(page.editing()).toEqual({ kind: 'project', solution: payments, project: null });
        expect(page.editorVisible()).toBe(true);
        namedButton(dom(), 'Delete Payments').click();
        expect(page.pending()?.kind).toBe('delete-solution');
    });
});
