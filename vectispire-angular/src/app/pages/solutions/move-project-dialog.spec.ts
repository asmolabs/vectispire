import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { MoveProjectDialog } from './move-project-dialog';
import { mountOnSolutions, textOf } from './solutions-page.testing';

/**
 * Moving a project, on its own: the other solutions only, the solution required, and a name taken there
 * said beside the name field, the dialog left open on it.
 */
describe('moving a project to another solution', () => {
    afterEach(() => TestBed.resetTestingModule());

    const payments = SOLUTION_TREE.solutions[0];
    const ledger = payments.projects[1];

    it('offers the other solutions, and says a name taken there beside the field', () => {
        const { fixture, http, page } = mountOnSolutions(MoveProjectDialog);
        page.openMoveProject(payments, ledger);
        fixture.detectChanges();
        expect(fixture.componentInstance.solutionChoices()).toEqual([{ label: 'Mobile', value: 2 }]);

        page.targetSolutionId.set(2);
        fixture.detectChanges();
        document.querySelector('[data-testid="move-project-dialog"]')!.dispatchEvent(new Event('submit'));
        const sent = http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/projects/12');
        expect(sent.request.body).toEqual({ solutionId: 2 });
        sent.flush(
            { type: 'urn:vectispire:problem:project-name-taken', title: 'Conflict', status: 409, detail: 'English.' },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();
        expect(page.moveVisible()).toBe(true);
        expect(textOf(document, '[data-testid="move-name-taken"]')).toBe(
            'Mobile already holds a project named Ledger. Give it another name above, or choose another solution.'
        );
    });
});
