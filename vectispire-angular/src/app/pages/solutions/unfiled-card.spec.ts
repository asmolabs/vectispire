import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { SolutionTree } from '@/app/core/api.models';
import { openIssues, SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { UnfiledCard } from './unfiled-card';
import { mountOnSolutions, namedButton, textOf } from './solutions-page.testing';

/** "No project", on its own: always there, saying when it is empty, and filing what it holds into a project. */
describe('the "no project" group', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('offers to file what it holds', () => {
        const { dom, page } = mountOnSolutions(UnfiledCard);
        namedButton(dom(), 'File nginx:1.27 into a project').click();
        expect(page.filing()?.target).toEqual({ kind: 'container', ref: { id: 31, name: 'nginx:1.27' } });
        expect(page.fileVisible()).toBe(true);
    });

    it('says everything is filed when it holds nothing, and offers no filing without a project', () => {
        const empty: SolutionTree = {
            solutions: [],
            unfiled: { repositoryCount: 0, containerCount: 0, openIssues: openIssues(0, 0), repositories: [] }
        };
        const { dom } = mountOnSolutions(UnfiledCard, { tree: empty });
        expect(textOf(dom(), '[data-testid="unfiled"]')).toContain(
            'Every repository and image you can see is filed in a project.'
        );
        TestBed.resetTestingModule();
        const noProject: SolutionTree = { ...SOLUTION_TREE, solutions: [] };
        expect(
            namedButton(mountOnSolutions(UnfiledCard, { tree: noProject }).dom(), 'File legacy-batch into a project')
                .disabled
        ).toBe(true);
    });
});
