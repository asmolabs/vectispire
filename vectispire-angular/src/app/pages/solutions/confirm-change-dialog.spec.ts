import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { ConfirmChangeDialog } from './confirm-change-dialog';
import { mountOnSolutions, namedButton, textOf } from './solutions-page.testing';

/**
 * The confirmation, on its own: what a change takes away from somebody said in full before the click,
 * the change made by its own route — an image unfiled through the images' route, never the repositories'.
 */
describe('the confirmation of a change', () => {
    afterEach(() => TestBed.resetTestingModule());

    const payments = SOLUTION_TREE.solutions[0];
    const ledger = payments.projects[1];

    it('says what deleting a project takes away, and deletes it', () => {
        const { fixture, http, page } = mountOnSolutions(ConfirmChangeDialog);
        page.askDeleteProject(payments, ledger);
        fixture.detectChanges();
        expect(textOf(document, '[data-testid="confirm-text"]')).toContain('Delete the project Payments / Ledger?');
        namedButton(document, 'Confirm').click();
        http.expectOne((call) => call.method === 'DELETE' && call.url === '/api/v1/projects/12').flush(null);
        expect(page.confirmVisible()).toBe(false);
        http.expectOne('/api/v1/solutions');
    });

    it('unfiles an image through the images route, though a repository shares its number', () => {
        const { fixture, http, page } = mountOnSolutions(ConfirmChangeDialog);
        page.askUnfile({ kind: 'container', ref: ledger.containers![0] }, payments, ledger);
        fixture.detectChanges();
        namedButton(document, 'Confirm').click();
        http.expectOne((call) => call.method === 'DELETE' && call.url === '/api/v1/projects/12/containers/9');
    });
});
