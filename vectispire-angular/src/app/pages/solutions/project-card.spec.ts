import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ProjectNode } from '@/app/core/api.models';
import { SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { ProjectCard } from './project-card';
import { mountOnSolutions, namedButton } from './solutions-page.testing';

/**
 * One project, on its own: `partial` said in words, its languages only when counted, a checklist link
 * only when the server says it would open, and an administrator's acts opening their dialogs.
 */
describe('a project of the solutions tree', () => {
    afterEach(() => TestBed.resetTestingModule());

    const payments = SOLUTION_TREE.solutions[0];
    const gateway = payments.projects[0];
    const ledger = payments.projects[1];
    const mount = (project: ProjectNode, role = 'ADMIN') =>
        mountOnSolutions(ProjectCard, { role, inputs: { solution: payments, project } });

    it('says a project seen in part is partial, and offers no checklist the server would refuse', () => {
        const { dom } = mount(gateway);
        expect(dom().querySelector('[data-testid="partial"]')).not.toBeNull();
        expect(dom().querySelector('[data-testid="project-checklist"]')).toBeNull();
        expect(dom().querySelector('[data-testid="project-languages"]')).toBeNull();
    });

    it('shows its languages once counted, and its checklist when it would open', () => {
        const { dom } = mount({ ...ledger, detectedLanguages: ['java', 'python'] });
        expect(dom().querySelector('[data-testid="project-languages"]')).not.toBeNull();
        expect(dom().querySelector('[data-testid="project-checklist"]')).not.toBeNull();
    });

    it("opens an administrator's acts in their dialogs, and offers a reader none", () => {
        const admin = mount(ledger);
        namedButton(admin.dom(), 'Move Ledger to another solution').click();
        expect(admin.page.moving()?.project.id).toBe(ledger.id);
        namedButton(admin.dom(), 'Delete Ledger').click();
        expect(admin.page.pending()).toEqual({ kind: 'delete-project', solution: payments, project: ledger });
        TestBed.resetTestingModule();

        const reader = mount(ledger, 'USER');
        expect(reader.dom().querySelector('[data-testid="move-project"]')).toBeNull();
    });
});
