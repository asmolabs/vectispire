import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { UnfiledCard } from './unfiled-card';
import { mountOnSolutions } from './solutions-page.testing';

/**
 * The solutions screen's state, on its own: a dialog opened on a clean form, and a reload after a
 * refused change keeping the refusal on screen.
 */
describe('the state of the solutions screen', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('opens each dialog on a clean form', () => {
        const { page } = mountOnSolutions(UnfiledCard);
        page.formError.set('An earlier refusal.');
        page.editSolution(SOLUTION_TREE.solutions[0]);
        expect(page.formName()).toBe('Payments');
        expect(page.formDescription()).toBe('The payments platform');
        expect(page.formError()).toBeNull();
        page.targetSolutionId.set(2);
        page.openMoveProject(SOLUTION_TREE.solutions[0], SOLUTION_TREE.solutions[0].projects[0]);
        expect(page.targetSolutionId()).toBeNull();
    });

    it('keeps a refusal on screen through the reload that follows it', () => {
        const { page, http } = mountOnSolutions(UnfiledCard);
        page.error.set('The solution still holds projects.');
        page.reload(true);
        http.expectOne('/api/v1/solutions').flush(SOLUTION_TREE);
        expect(page.error()).toBe('The solution still holds projects.');
        page.reload();
        http.expectOne('/api/v1/solutions').flush(SOLUTION_TREE);
        expect(page.error()).toBeNull();
    });
});
