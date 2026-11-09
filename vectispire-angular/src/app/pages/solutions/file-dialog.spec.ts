import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { FileDialog } from './file-dialog';
import { mountOnSolutions, textOf } from './solutions-page.testing';

/**
 * The filing dialog, on its own: every project but the one the target is in, the change of access said
 * before the click, and the filing sent from a submit through the target's own route.
 */
describe('the filing dialog', () => {
    afterEach(() => TestBed.resetTestingModule());

    const payments = SOLUTION_TREE.solutions[0];
    const gateway = payments.projects[0];

    it('offers every project but the current one, and says who gains and loses sight', () => {
        const { fixture, page } = mountOnSolutions(FileDialog);
        page.openFile({ kind: 'repository', ref: gateway.repositories[0] }, { solution: payments, project: gateway });
        fixture.detectChanges();
        const dialog = fixture.componentInstance;
        expect(dialog.projectChoices().flatMap((group) => group.items.map((item) => item.value))).toEqual([12, 21]);
        page.targetProjectId.set(21);
        fixture.detectChanges();
        expect(textOf(document, '[data-testid="file-consequence"]')).toContain(
            'those who see it only through a grant on Payments / Gateway lose it, and those granted Mobile / App gain it'
        );
    });

    it('files on a submit, through the route of what is filed', () => {
        const { fixture, http, page } = mountOnSolutions(FileDialog);
        page.openFile({ kind: 'container', ref: { id: 31, name: 'nginx:1.27' } });
        page.targetProjectId.set(11);
        fixture.detectChanges();
        document.querySelector('form#file-target')!.dispatchEvent(new Event('submit'));
        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/projects/11/containers/31').flush(null);
        expect(page.fileVisible()).toBe(false);
    });
});
